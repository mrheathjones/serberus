import AppKit
import PrivMgrCore
import SerberusSentinelCore
import SwiftUI

/// A borderless panel that can still take keyboard focus — the audit prompt
/// has no title bar but must receive Esc / Return / ⌘↩.
///
/// It is NON-ACTIVATING: it becomes the key window without the agent becoming
/// the active app. macOS refuses to let a background accessory app activate
/// itself when a daemon push, not a user action, asks it to, so an ordinary
/// window would appear but never be key, and Approve would never arm
/// (``PromptArming`` requires key). A non-activating panel is key as soon as it
/// is ordered front, the way Spotlight's is.
private final class PromptPanel: NSPanel {
    override var canBecomeKey: Bool { true }
}

/// Presents a single daemon-driven audit prompt in a floating chromeless
/// window hosting ``PromptWindow``.
///
/// A plain `Window` scene cannot be handed a fresh per-request ``PromptViewModel``
/// on demand, so the daemon-driven prompt uses an AppKit window opened directly.
/// ``present(context:)`` builds the model, shows the window centred on the
/// active display, drives the one-second countdown, and resolves when the user
/// (or the countdown) decides. The window is modal to the requesting action
/// only — it floats but never blocks the rest of the system, and it cannot be
/// dismissed by clicking outside.
///
/// It also feeds the model's arming gate: Approve arms only once the
/// window has been key, visible and uncovered by other apps' windows for a
/// second (``PromptArming``), whatever raised the prompt.
@MainActor
final class PromptWindowController {
    private var window: NSWindow?
    /// Retained so it stays alive to remeasure on the rule disclosure toggle.
    private var hostingController: NSHostingController<PromptWindow>?
    /// Guards the top-anchored resize against re-entrancy (belt-and-suspenders;
    /// the resize is non-animated and fired once per toggle, so it can't storm).
    private var isResizing = false
    private var tickTask: Task<Void, Never>?
    /// Re-reads the window's state every ``armingPollInterval`` while the prompt
    /// is up: another app ordering a window over ours posts us nothing, so the
    /// overlap check has to poll. Cancelled with the window, like the countdown.
    private var armingTask: Task<Void, Never>?
    /// Key, occlusion, move and resize observers on the prompt window, which
    /// report those changes to the arming gate at once. Removed on dismiss.
    private var armingObservers: [NSObjectProtocol] = []
    /// Local monitor for clicks and ⌘↩ on the prompt. Removed on dismiss.
    private var armingEventMonitor: Any?
    /// The app that owned the keyboard focus when the prompt appeared — the
    /// terminal that ran `sudo`. The agent is a menu-bar accessory, so after it
    /// activates to show the prompt macOS will not return focus on its own;
    /// ``dismiss(animated:restoreFocus:)`` reactivates this app so the user lands
    /// back in their terminal. Never our own app (guarded so chained prompts,
    /// which run with the agent already frontmost, don't capture ourselves).
    private var previousApp: NSRunningApplication?
    /// Set while a reentrant `present` is tearing down a displaced prompt to show
    /// another one. Focus must NOT return to the terminal in that window — the
    /// next prompt is about to take the screen — so the intervening dismisses
    /// skip the restore.
    private var isDisplacing = false
    /// The model of the prompt currently on screen. Kept so a reentrant
    /// `present` (daemon reconnect re-push, or a daemon-side timeout racing a
    /// queued next prompt) RESOLVES the displaced prompt instead of merely
    /// closing its window — a bare close would leak the displaced call's
    /// continuation and lose its history entry and XPC reply.
    private var activeModel: PromptViewModel?

    /// Design button labels: cancel is the safe default; approval is explicit.
    static let defaultAllowLabel = "Yes, continue"
    static let defaultDenyLabel = "No, cancel"

    /// How often the arming poll re-reads the window server's list: a window
    /// ordered over an armed prompt disarms it within this long.
    static let armingPollInterval: Duration = .milliseconds(200)

    /// Shows the prompt and suspends until it resolves, returning the verdict.
    func present(context: PromptContext) async -> PromptResponse {
        // Fail the displaced prompt closed. Its onResolve fires exactly once,
        // resuming the displaced continuation (deny), replying over XPC, and
        // tearing down its window via the dismiss below. Focus must not bounce
        // to the terminal between the two prompts, so both dismisses that happen
        // here run with the restore suppressed.
        isDisplacing = true
        activeModel?.deny()
        dismiss(animated: false)
        isDisplacing = false
        // Branding + button labels from the managed prompts profile
        // (`com.herojoneslabs.serberus.prompts`) — world-readable managed
        // prefs, no privilege needed, read fresh so a pushed profile change
        // applies to the very next prompt.
        let prompts = ManagedPreferencesReader().readPrompts().value
        return await withCheckedContinuation { continuation in
            let model = PromptViewModel(context: context) { [weak self] response in
                self?.activeModel = nil
                self?.dismiss(animated: true)
                continuation.resume(returning: response)
            }
            self.activeModel = model

            let host = NSHostingController(
                rootView: PromptWindow(
                    model: model,
                    allowLabel: prompts.allowButtonLabel,
                    denyLabel: prompts.denyButtonLabel,
                    brandTitle: prompts.brandTitle,
                    brandSubtitle: prompts.brandSubtitle,
                    onDisclosureToggled: { [weak self] in self?.refitToContent() }
                )
            )
            self.hostingController = host

            let window = PromptPanel(
                contentRect: NSRect(x: 0, y: 0, width: 470, height: 360),
                styleMask: [.borderless, .nonactivatingPanel],
                backing: .buffered,
                defer: false
            )
            // Key whenever it's in front, and never hidden when another app is
            // active: the prompt must stay up while the terminal keeps focus.
            window.becomesKeyOnlyIfNeeded = false
            window.hidesOnDeactivate = false
            window.backgroundColor = .clear
            window.isOpaque = false
            window.hasShadow = true
            window.isMovableByWindowBackground = true
            window.isReleasedWhenClosed = false
            window.level = .floating
            window.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
            window.contentView = host.view
            // Ideal size for the fixed 470pt width, unclamped by any bounds.
            let ideal = host.sizeThatFits(in: NSSize(width: 470, height: CGFloat.greatestFiniteMagnitude))
            window.setContentSize(NSSize(width: 470, height: ceil(ideal.height)))
            Self.centerOnActiveScreen(window)
            // Remember who had focus (the terminal running sudo) so the prompt
            // can hand it back on dismiss. Ignore ourselves so a chained prompt,
            // presented while the agent is already frontmost, keeps the real
            // previous app rather than capturing the agent.
            if let front = NSWorkspace.shared.frontmostApplication,
               front.bundleIdentifier != Bundle.main.bundleIdentifier {
                self.previousApp = front
            }
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            self.window = window
            self.startArmingObservation(of: window)

            // Drive the countdown until the model resolves (which tears down).
            // The cancellation guard matters: a cancelled Task.sleep returns
            // immediately, and without it this loop would burn through the
            // countdown in a tight spin instead of exiting.
            self.tickTask = Task { @MainActor in
                while model.verdict == nil, !Task.isCancelled {
                    try? await Task.sleep(nanoseconds: 1_000_000_000)
                    guard !Task.isCancelled else { break }
                    if model.verdict == nil { model.tick() }
                }
            }
        }
    }

    /// Feeds the active model's arming gate: on each key, occlusion, move and
    /// resize notification for `window`, every ``armingPollInterval`` for the
    /// overlap check (the poll's first pass runs straight away), and on each
    /// click or ⌘↩ on the prompt, before it's dispatched.
    private func startArmingObservation(of window: NSWindow) {
        let names: [Notification.Name] = [
            NSWindow.didBecomeKeyNotification, NSWindow.didResignKeyNotification,
            NSWindow.didChangeOcclusionStateNotification,
            NSWindow.didMoveNotification, NSWindow.didResizeNotification,
        ]
        armingObservers = names.map { name in
            NotificationCenter.default.addObserver(forName: name, object: window, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.observeArming() }
            }
        }
        armingTask = Task { @MainActor [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                self.observeArming()
                try? await Task.sleep(for: Self.armingPollInterval)
            }
        }
        // A click on the prompt, or ⌘↩ (held or repeated included), is judged on
        // the window's state at that moment, not the last poll, and while Approve
        // is disarmed it restarts the one-second delay, so rapid or held input
        // can't ride the delay out. Other keys don't count. The event always
        // passes through unchanged.
        armingEventMonitor = NSEvent.addLocalMonitorForEvents(
            matching: [.leftMouseDown, .rightMouseDown, .otherMouseDown, .keyDown]
        ) { [weak self] event in
            // Only Sendable facts cross into the isolated block (NSEvent and
            // NSWindow are not Sendable under Swift 6). keyCode is valid only
            // on key events, hence the short-circuit.
            let isApprovalInput = event.type != .keyDown
                || PromptArming.isApproveKey(keyCode: event.keyCode,
                                             commandHeld: event.modifierFlags.contains(.command))
            let windowID = event.window.map(ObjectIdentifier.init)
            MainActor.assumeIsolated {
                guard isApprovalInput, let self, let window = self.window,
                      windowID == ObjectIdentifier(window) else { return }
                self.observeArming()
                self.activeModel?.noteInput()
            }
            return event
        }
    }

    /// Reports the prompt window's state to the active model. Visible means
    /// ordered in and not occluded (another Space, a sleeping display or a
    /// locked screen all clear it); uncovered is the window server's overlap
    /// check, which fails closed when it can't read its lists.
    private func observeArming() {
        guard let window, let model = activeModel else { return }
        model.observeWindow(
            isKey: window.isKeyWindow,
            isVisible: window.isVisible && window.occlusionState.contains(.visible),
            isUncovered: PromptOverlap.isUncovered(
                windowNumber: window.windowNumber,
                ownPID: getpid(),
                windowList: { CGWindowListCopyWindowInfo($0, $1) as? [[String: Any]] },
                isExemptOwner: PromptOverlap.isExemptSystemUI(pid:)
            )
        )
    }

    /// Remeasures the sheet's ideal height after the rule disclosure toggles and
    /// resizes the window to it, TOP edge fixed so it grows DOWNWARD. Deferred to
    /// the next runloop turn so SwiftUI has applied the state change before
    /// `sizeThatFits` reads the new ideal.
    private func refitToContent() {
        DispatchQueue.main.async { [weak self] in
            MainActor.assumeIsolated {
                guard let self, let host = self.hostingController else { return }
                let ideal = host.sizeThatFits(in: NSSize(width: 470, height: CGFloat.greatestFiniteMagnitude))
                self.resizeToContentHeight(ideal.height)
            }
        }
    }

    /// Sets the window to `height`, keeping the TOP edge fixed. NON-animated and
    /// re-entrancy-guarded: an animated `setFrame` runs a blocking nested runloop
    /// that a re-entrant call turns into a hang/crash (the 1.7 regression).
    private func resizeToContentHeight(_ height: CGFloat) {
        guard !isResizing, let window else { return }
        let newHeight = ceil(height)
        let current = window.frame
        guard newHeight > 0, abs(newHeight - current.height) >= 0.5 else { return }
        isResizing = true
        defer { isResizing = false }
        let top = current.maxY  // Cocoa origin is bottom-left; maxY is the top edge.
        window.setFrame(
            NSRect(x: current.origin.x, y: top - newHeight, width: current.width, height: newHeight),
            display: true
        )
    }

    /// Centres the window on the display the user is actually on (design:
    /// "centred on the active display") — the one holding the pointer, which
    /// for a prompt triggered by the user's own action is where their
    /// attention is. `NSWindow.center()` would land on the primary display.
    private static func centerOnActiveScreen(_ window: NSWindow) {
        let mouse = NSEvent.mouseLocation
        let screen = NSScreen.screens.first { NSMouseInRect(mouse, $0.frame, false) }
            ?? NSScreen.main
        guard let frame = screen?.visibleFrame else {
            window.center()
            return
        }
        let size = window.frame.size
        window.setFrameOrigin(NSPoint(
            x: frame.midX - size.width / 2,
            // Slightly above true centre, matching NSWindow.center()'s optical
            // bias — but never with the top above the visible frame: a prompt
            // taller than the screen would sit under the menu bar, and a window
            // over it keeps Approve disarmed.
            y: min(frame.maxY - size.height, frame.minY + (frame.height - size.height) * 0.55)
        ))
    }

    /// Tears down the current window and stops the countdown. The resolution
    /// (XPC reply) has already fired by the time this runs — the fade is
    /// purely cosmetic (design: 120ms fade on dismiss).
    ///
    /// When `restoreFocus` is true and this is not a displacement teardown, the
    /// app that had focus before the prompt (the terminal that ran `sudo`) is
    /// reactivated once the window is gone, so the user lands back where they
    /// were instead of on the desktop with the accessory agent still frontmost.
    func dismiss(animated: Bool, restoreFocus: Bool = true) {
        tickTask?.cancel()
        tickTask = nil
        armingTask?.cancel()
        armingTask = nil
        armingObservers.forEach { NotificationCenter.default.removeObserver($0) }
        armingObservers = []
        if let armingEventMonitor { NSEvent.removeMonitor(armingEventMonitor) }
        armingEventMonitor = nil
        hostingController = nil
        // Resolve who (if anyone) should regain focus after teardown, and clear
        // the stored reference so it can't leak into a later prompt.
        let appToRestore: NSRunningApplication? = (restoreFocus && !isDisplacing) ? previousApp : nil
        previousApp = nil
        let restoreFocusNow: () -> Void = {
            guard let appToRestore,
                  appToRestore.bundleIdentifier != Bundle.main.bundleIdentifier else { return }
            appToRestore.activate()
        }
        guard let window else {
            restoreFocusNow()
            return
        }
        self.window = nil
        let close: () -> Void = {
            window.orderOut(nil)
            window.close()
            restoreFocusNow()
        }
        if animated, !NSWorkspace.shared.accessibilityDisplayShouldReduceMotion {
            NSAnimationContext.runAnimationGroup({ ctx in
                ctx.duration = 0.12
                window.animator().alphaValue = 0
            }, completionHandler: close)
        } else {
            close()
        }
    }
}
