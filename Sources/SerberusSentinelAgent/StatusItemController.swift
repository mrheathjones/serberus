import AppKit
import SerberusSentinelCore
import SerberusUI
import SwiftUI

/// The Sentinel status item and its dropdown, owned in AppKit.
///
/// This replaces SwiftUI's `MenuBarExtra(.window)`. That scene hosts the
/// dropdown in a PRIVATE window whose frame SwiftUI animates on every content
/// size change and screen fix-up — and on built-in MacBook displays it produced
/// a visible "slide out from the icon and back in" bounce that no content-side
/// change could suppress (the repo has now hit three separate quirks in that
/// host: the `isInserted` scene loop, the `TimelineView` spin, and this).
///
/// Here the agent owns every moving part:
/// - one `NSStatusItem` whose image/tooltip track ``MenubarStateModel/presentation``
///   through Observation, with the prompt blink and grant pulse as
///   cancellation-guarded image swaps (the same discipline the SwiftUI label used);
/// - one borderless, non-activating `NSPanel` per open, sized to the SwiftUI
///   content's fitting size ROUNDED UP TO WHOLE POINTS and placed under the
///   status item in a single, non-animated `setFrame` — later content size
///   changes (the admin request card) resize it once, top edge fixed;
/// - dismissal on outside click (global + local mouse monitors), Escape, an
///   app switch, a Space change, or a display change.
///
/// The SwiftUI content is created on open and torn down on close, so its
/// `.task`s (the on-open refresh, the countdown tick) keep the exact lifetime
/// they had under `MenuBarExtra`.
@MainActor
final class StatusItemController: NSObject {
    private let menubar: MenubarStateModel
    private let makeContent: () -> AnyView
    private let statusItem: NSStatusItem

    private var panel: DropdownPanel?
    private var hosting: FittingHostingView<AnyView>?
    private var iconTask: Task<Void, Never>?
    private var localMonitor: Any?
    private var globalMonitor: Any?
    private var dismissObservers: [NSObjectProtocol] = []
    private var resizeScheduled = false

    /// Gap between the menu bar's bottom edge and the dropdown.
    private static let gap: CGFloat = 6
    /// Minimum distance kept from the screen's visible-frame edges.
    private static let screenInset: CGFloat = 8

    init<Content: View>(menubar: MenubarStateModel, @ViewBuilder content: @escaping () -> Content) {
        self.menubar = menubar
        self.makeContent = { AnyView(content()) }
        self.statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        super.init()

        if let button = statusItem.button {
            button.image = SentinelStatusIcon.image(.template)
            button.imagePosition = .imageOnly
            button.target = self
            button.action = #selector(toggle(_:))
        }
        observePresentation()

        // Reduce Motion flips the blink/pulse into steady images; re-apply live.
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.apply(self.menubar.presentation)
            }
        }
    }

    // MARK: Status-item icon

    /// Re-arms Observation on every change of `presentation` (the tracking is
    /// one-shot). `onChange` fires BEFORE the new value lands, hence the hop.
    private func observePresentation() {
        let presentation = withObservationTracking {
            menubar.presentation
        } onChange: { [weak self] in
            Task { @MainActor [weak self] in self?.observePresentation() }
        }
        apply(presentation)
    }

    private var reduceMotion: Bool { NSWorkspace.shared.accessibilityDisplayShouldReduceMotion }

    /// Sets the image + tooltip for `presentation`, and (re)starts the looping
    /// image swap for the animated states. Every loop is guarded after its
    /// sleep: a cancelled `Task.sleep` returns IMMEDIATELY, and without the
    /// guard the loop becomes a main-thread spin.
    private func apply(_ presentation: MenubarPresentation) {
        iconTask?.cancel()
        iconTask = nil
        guard let button = statusItem.button else { return }
        button.toolTip = presentation.tooltip

        let amber = SentinelStatusIcon.amber
        switch presentation {
        case .idle:
            button.image = SentinelStatusIcon.image(.template)
        case .killSwitch:
            button.image = SentinelStatusIcon.image(.slashed)
        case .pending:
            button.image = SentinelStatusIcon.image(.tinted(amber))
        case .blocked, .degraded:
            button.image = SentinelStatusIcon.image(.tinted(SentinelStatusIcon.red))
        case .offline:
            button.image = SentinelStatusIcon.image(.dashed)
        case .promptWaiting:
            // Design intent: 1.6s pulse, opacity 1 → 0.35; one swap every 800ms.
            button.image = SentinelStatusIcon.image(.tinted(amber))
            guard !reduceMotion else { return }
            iconTask = Task { [weak self] in
                var dimmed = false
                while !Task.isCancelled {
                    try? await Task.sleep(for: .milliseconds(800))
                    guard !Task.isCancelled else { break }
                    dimmed.toggle()
                    let color = dimmed ? amber.withAlphaComponent(0.35) : amber
                    self?.statusItem.button?.image = SentinelStatusIcon.image(.tinted(color))
                }
            }
        case .grantActive(let expiresAt):
            // Green, gently pulsing; amber and faster inside the final minute.
            // Urgency is re-derived every tick so the shift is crisp regardless
            // of the daemon poll cadence.
            let reduceMotion = reduceMotion
            var urgent = Self.isUrgent(expiresAt)
            button.image = SentinelStatusIcon.image(.tinted(urgent ? amber : SentinelStatusIcon.green))
            iconTask = Task { [weak self] in
                var dimmed = false
                while !Task.isCancelled {
                    let interval: Duration = urgent ? .milliseconds(450) : .milliseconds(900)
                    try? await Task.sleep(for: interval)
                    guard !Task.isCancelled else { break }
                    urgent = Self.isUrgent(expiresAt)
                    if !reduceMotion { dimmed.toggle() }
                    let tint = urgent ? amber : SentinelStatusIcon.green
                    let floor: CGFloat = urgent ? 0.3 : 0.55
                    let color = dimmed ? tint.withAlphaComponent(floor) : tint
                    self?.statusItem.button?.image = SentinelStatusIcon.image(.tinted(color))
                }
            }
        }
    }

    /// Whether the soonest grant is within the shared urgency window of expiry.
    private static func isUrgent(_ expiresAt: Date?) -> Bool {
        guard let expiresAt else { return false }
        return expiresAt.timeIntervalSinceNow <= MenubarStateModel.grantUrgentWindow
    }

    // MARK: Dropdown

    var isPresented: Bool { panel != nil }

    @objc private func toggle(_ sender: Any?) {
        if isPresented { dismiss() } else { present() }
    }

    func present() {
        guard panel == nil, let button = statusItem.button, button.window != nil else { return }

        let hosting = FittingHostingView(rootView: makeContent())
        hosting.onContentSizeChange = { [weak self] in self?.scheduleResize() }
        let size = Self.integral(hosting.fittingSize)

        let panel = DropdownPanel(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        panel.backgroundColor = .clear
        panel.isOpaque = false
        panel.hasShadow = true
        panel.isReleasedWhenClosed = false
        panel.hidesOnDeactivate = false
        panel.isMovable = false
        panel.animationBehavior = .none
        panel.level = .popUpMenu
        panel.collectionBehavior = [.canJoinAllSpaces, .transient, .fullScreenAuxiliary, .ignoresCycle]
        panel.appearance = NSAppearance(named: .darkAqua)
        panel.contentView = hosting
        panel.onCancel = { [weak self] in self?.dismiss() }

        self.panel = panel
        self.hosting = hosting
        // ONE non-animated placement: the frame is final before the panel is
        // ever on screen, so there is nothing for the window server to slide.
        panel.setFrame(frame(for: size, anchoredTo: nil), display: false)
        button.highlight(true)
        installDismissTriggers()
        panel.makeKeyAndOrderFront(nil)
    }

    func dismiss() {
        guard let panel else { return }
        removeDismissTriggers()
        panel.orderOut(nil)
        // Detaching the hosting view ends the SwiftUI content's lifetime (its
        // `.task`s cancel), exactly as closing the MenuBarExtra window did.
        panel.contentView = nil
        self.panel = nil
        self.hosting = nil
        statusItem.button?.highlight(false)
    }

    // MARK: Sizing + placement

    /// Whole-point sizes only: a fractional content height is what lets a
    /// window's frame and its content disagree by a pixel and re-layout forever.
    private static func integral(_ size: NSSize) -> NSSize {
        NSSize(width: ceil(size.width), height: ceil(size.height))
    }

    /// The dropdown frame for `size`: horizontally centred under the status
    /// item, top edge just below the menu bar, clamped inside the visible frame
    /// of the screen the status item is on. `anchoredTo` keeps an existing top
    /// edge on a resize so the panel grows downward, not from its centre.
    private func frame(for size: NSSize, anchoredTo current: NSRect?) -> NSRect {
        guard let button = statusItem.button, let window = button.window else {
            return NSRect(origin: .zero, size: size)
        }
        let itemRect = window.convertToScreen(button.convert(button.bounds, to: nil))
        let screen = window.screen ?? NSScreen.main
        let bounds = screen?.visibleFrame ?? itemRect
        let inset = Self.screenInset

        var x = current?.minX ?? (itemRect.midX - size.width / 2).rounded()
        x = min(max(x, bounds.minX + inset), bounds.maxX - size.width - inset)
        let top = current?.maxY ?? min(itemRect.minY - Self.gap, bounds.maxY - Self.gap).rounded(.down)
        var y = top - size.height
        if y < bounds.minY + inset { y = bounds.minY + inset }
        return NSRect(x: x, y: y, width: size.width, height: size.height)
    }

    /// Coalesces content-size invalidations (which can arrive mid-layout) into
    /// one frame update on the next run-loop turn.
    private func scheduleResize() {
        guard !resizeScheduled, panel != nil else { return }
        resizeScheduled = true
        Task { @MainActor [weak self] in
            self?.resizeScheduled = false
            self?.resizeToFit()
        }
    }

    private func resizeToFit() {
        guard let panel, let hosting else { return }
        let size = Self.integral(hosting.fittingSize)
        guard size != panel.frame.size else { return }
        let target = frame(for: size, anchoredTo: panel.frame)
        if reduceMotion {
            panel.setFrame(target, display: true)
        } else {
            // A bounded, one-shot resize (the "Request access…" card sliding
            // in) — never an implicit or repeating animation.
            NSAnimationContext.runAnimationGroup { context in
                context.duration = 0.15
                context.timingFunction = CAMediaTimingFunction(name: .easeOut)
                panel.animator().setFrame(target, display: true)
            }
        }
    }

    // MARK: Dismissal triggers

    private func installDismissTriggers() {
        // Clicks in OTHER apps never reach a local monitor.
        globalMonitor = NSEvent.addGlobalMonitorForEvents(
            matching: [.leftMouseDown, .rightMouseDown, .otherMouseDown]
        ) { [weak self] _ in
            Task { @MainActor [weak self] in self?.dismiss() }
        }
        // Clicks in this app's own windows: anything outside the dropdown
        // dismisses it — EXCEPT the status item itself, whose action toggles
        // (dismissing here too would re-open on the matching mouse-up).
        localMonitor = NSEvent.addLocalMonitorForEvents(
            matching: [.leftMouseDown, .rightMouseDown, .otherMouseDown, .keyDown]
        ) { [weak self] event in
            // Only Sendable facts cross into the isolated block (NSEvent and
            // NSWindow are not Sendable under Swift 6).
            let isKey = event.type == .keyDown
            let isEscape = isKey && event.keyCode == 53
            let windowID = event.window.map(ObjectIdentifier.init)
            let swallow: Bool = MainActor.assumeIsolated {
                guard let self, let panel = self.panel else { return false }
                if isKey {
                    if isEscape { self.dismiss(); return true }
                    return false
                }
                let panelID = ObjectIdentifier(panel)
                let itemWindowID = self.statusItem.button?.window.map(ObjectIdentifier.init)
                if windowID == panelID || (windowID != nil && windowID == itemWindowID) { return false }
                self.dismiss()
                return false
            }
            return swallow ? nil : event
        }
        let center = NotificationCenter.default
        let workspace = NSWorkspace.shared.notificationCenter
        let names: [(NotificationCenter, Notification.Name)] = [
            (workspace, NSWorkspace.didActivateApplicationNotification),
            (workspace, NSWorkspace.activeSpaceDidChangeNotification),
            (center, NSApplication.didChangeScreenParametersNotification),
            (center, NSApplication.didResignActiveNotification),
        ]
        dismissObservers = names.map { center, name in
            center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor [weak self] in self?.dismiss() }
            }
        }
    }

    private func removeDismissTriggers() {
        if let globalMonitor { NSEvent.removeMonitor(globalMonitor) }
        if let localMonitor { NSEvent.removeMonitor(localMonitor) }
        globalMonitor = nil
        localMonitor = nil
        let center = NotificationCenter.default
        let workspace = NSWorkspace.shared.notificationCenter
        for observer in dismissObservers {
            center.removeObserver(observer)
            workspace.removeObserver(observer)
        }
        dismissObservers = []
    }
}

/// Borderless non-activating panel that can still become key, so the admin
/// justification text field takes typing without activating the agent.
private final class DropdownPanel: NSPanel {
    var onCancel: (() -> Void)?
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
    override func cancelOperation(_ sender: Any?) { onCancel?() }
}

/// `NSHostingView` that reports when its SwiftUI content's ideal size changes,
/// so the owning panel can be re-fitted once per change.
private final class FittingHostingView<Content: View>: NSHostingView<Content> {
    var onContentSizeChange: (() -> Void)?

    required init(rootView: Content) {
        super.init(rootView: rootView)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    override func invalidateIntrinsicContentSize() {
        super.invalidateIntrinsicContentSize()
        onContentSizeChange?()
    }
}
