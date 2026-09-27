import AppKit
import PrivMgrCore
import SerberusSentinelCore
import SwiftUI

/// The prompt result toasts (design: "Result toasts"): a transient glass card
/// in the top-right of the main screen, shown for 2.5s after an audit prompt
/// resolves. Purely informational — it ignores mouse events and never takes
/// focus.
@MainActor
final class ToastPresenter {

    enum Kind {
        /// `recipient` is the org's own label for where the audited decision was
        /// sent (managed `auditRecipientLabel`, default "IT"); empty drops the
        /// "sent to …" clause.
        case approved(eventID: String, recipient: String)
        case denied
        case timedOut
        // Install / uninstall with Serberus results.
        case installed(name: String)
        /// `detail` replaces the generic reason when the daemon named one
        /// (``InstallPresentation/refusalDetail(for:uninstall:)``).
        case installRefused(name: String, detail: String?)
        case installFailed(name: String)
        case uninstalled(name: String)
        case uninstallRefused(name: String, detail: String?)
        case uninstallFailed(name: String)
        /// A non-dismissing "Verifying…" toast shown the instant an install is
        /// requested, so the user sees immediate feedback during the (staging +
        /// Gatekeeper-verification) gap before the audit prompt appears — instead
        /// of nothing, which made them click the menu item repeatedly. Cleared
        /// when the next toast replaces it.
        case working(name: String)
        /// A non-dismissing "Installing…" toast shown once the audit prompt is
        /// APPROVED, so the (staging-copy + commit) gap between "approved" and
        /// "installed" shows active work instead of a dead pause. Replaced by the
        /// install-result toast.
        case installing(name: String)

        var title: String {
            switch self {
            case .approved: return "Approved & logged"
            case .denied: return "Denied by you"
            case .timedOut: return "Denied automatically"
            case .installed(let name): return "Installed \(name)"
            case .installRefused: return "Install refused"
            case .installFailed: return "Install failed"
            case .uninstalled(let name): return "Moved \(name) to the Trash"
            case .uninstallRefused: return "Uninstall refused"
            case .uninstallFailed: return "Uninstall failed"
            case .working(let name): return "Verifying \(name)…"
            case .installing(let name): return "Installing \(name)…"
            }
        }

        var meta: String {
            switch self {
            case let .approved(eventID, recipient):
                let to = recipient.trimmingCharacters(in: .whitespacesAndNewlines)
                return to.isEmpty ? "event \(eventID) · logged" : "event \(eventID) · sent to \(to)"
            case .denied: return "nothing was changed"
            case .timedOut: return "no response · nothing was changed"
            case .installed: return "installed with Serberus"
            case let .installRefused(name, detail): return "\(name) — \(detail ?? "not permitted or not notarized")"
            case .installFailed(let name): return "\(name) — see Serberus logs"
            case .uninstalled: return "recoverable from the Trash"
            case let .uninstallRefused(name, detail): return "\(name) — \(detail ?? "not permitted or not in /Applications")"
            case .uninstallFailed(let name): return "\(name) — see Serberus logs"
            case .working: return "verifying app validity…"
            case .installing: return "approved & logged · installing…"
            }
        }

        var symbol: String {
            switch self {
            case .approved: return "checkmark.shield"
            case .denied: return "xmark.shield"
            case .timedOut: return "clock.badge.xmark"
            case .installed: return "arrow.down.app"
            case .installRefused, .uninstallRefused: return "hand.raised"
            case .installFailed, .uninstallFailed: return "exclamationmark.triangle"
            case .uninstalled: return "trash"
            case .working: return "shield.lefthalf.filled"
            case .installing: return "arrow.down.app"
            }
        }

        var color: Color {
            switch self {
            case .approved, .installed, .uninstalled, .installing: return Theme.allow
            case .denied, .installRefused, .installFailed, .uninstallRefused, .uninstallFailed: return Theme.deny
            case .timedOut, .working: return Theme.silent
            }
        }

        var dimColor: Color {
            switch self {
            case .approved, .installed, .uninstalled, .installing: return Theme.allowDim
            case .denied, .installRefused, .installFailed, .uninstallRefused, .uninstallFailed: return Theme.denyDim
            case .timedOut, .working: return Theme.silentDim
            }
        }

        /// The in-progress toasts (verifying / installing) render an indeterminate
        /// progress bar and persist until the next toast replaces them; every
        /// other (terminal) toast auto-dismisses after ``ToastPresenter/duration``.
        var isProgress: Bool {
            switch self {
            case .working, .installing: return true
            default: return false
            }
        }

        var autoDismisses: Bool { !isProgress }
        var showsProgressBar: Bool { isProgress }
    }

    /// Maps a resolved prompt to its toast. `recipient` is the org's audit
    /// recipient label (managed `auditRecipientLabel`, default "IT").
    static func kind(for response: PromptResponse, recipient: String = "IT") -> Kind {
        switch response.verdict {
        case .approved:
            return .approved(
                eventID: String(response.requestID.uuidString.prefix(8)).lowercased(),
                recipient: recipient
            )
        case .denied: return .denied
        case .timedOut: return .timedOut
        }
    }

    /// Maps an install result to its toast (a cancelled prompt shows nothing).
    static func kind(for result: InstallResult, name: String) -> Kind? {
        switch result.status {
        case .installed: return .installed(name: name)
        case .cancelled: return nil
        case .refusedByPolicy, .refusedNotTrusted, .refusedNotEligible:
            return .installRefused(name: name, detail: InstallPresentation.refusalDetail(for: result, uninstall: false))
        case .removed, .failed: return .installFailed(name: name)   // .removed can't occur for install
        }
    }

    /// Maps an uninstall result to its toast (a cancelled prompt shows nothing).
    static func kind(forUninstall result: InstallResult, name: String) -> Kind? {
        switch result.status {
        case .removed: return .uninstalled(name: name)
        case .cancelled: return nil
        case .refusedByPolicy, .refusedNotEligible, .refusedNotTrusted:
            return .uninstallRefused(name: name, detail: InstallPresentation.refusalDetail(for: result, uninstall: true))
        case .installed, .failed: return .uninstallFailed(name: name)   // .installed can't occur for uninstall
        }
    }

    private var panel: NSPanel?
    private var dismissTask: Task<Void, Never>?
    /// Whether the currently-shown toast is a non-dismissing progress toast, so
    /// ``hideIfProgress()`` can clear a stuck "Verifying…"/"Installing…" without
    /// clobbering a terminal toast (e.g. "Denied by you") that already replaced it.
    private var currentIsProgress = false

    /// How long a terminal toast stays up.
    static let duration: TimeInterval = 2.5

    /// Clears the toast ONLY if it is a progress toast — used by the install
    /// result path, so a "Verifying…"/"Installing…" that no result will replace
    /// (e.g. a cancelled install whose "Denied" toast the prompt handler already
    /// showed) is left to the prompt handler, but a truly stuck one is cleared.
    func hideIfProgress() {
        if currentIsProgress { hide() }
    }

    func show(_ kind: Kind) {
        hide()

        let hosting = NSHostingView(rootView: ToastView(kind: kind))
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 10, height: 10),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        panel.backgroundColor = .clear
        panel.isOpaque = false
        panel.hasShadow = true
        // We manage the panel's lifetime from Swift; the default true would
        // over-release on close().
        panel.isReleasedWhenClosed = false
        panel.ignoresMouseEvents = true
        panel.level = .statusBar
        panel.collectionBehavior = [.canJoinAllSpaces, .transient, .fullScreenAuxiliary]
        panel.contentView = hosting
        panel.setContentSize(hosting.fittingSize)

        // Top-right of the main screen, under the menu bar.
        if let screen = NSScreen.main {
            let frame = screen.visibleFrame
            let size = panel.frame.size
            panel.setFrameOrigin(NSPoint(
                x: frame.maxX - size.width - 16,
                y: frame.maxY - size.height - 12
            ))
        }

        // Entry: fade + 8pt upward translate (skipped under Reduce Motion).
        let reduceMotion = NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
        if !reduceMotion {
            panel.alphaValue = 0
            let origin = panel.frame.origin
            panel.setFrameOrigin(NSPoint(x: origin.x, y: origin.y - 8))
            panel.orderFrontRegardless()
            NSAnimationContext.runAnimationGroup { ctx in
                ctx.duration = 0.18
                ctx.timingFunction = CAMediaTimingFunction(name: .easeOut)
                panel.animator().alphaValue = 1
                panel.animator().setFrameOrigin(origin)
            }
        } else {
            panel.orderFrontRegardless()
        }
        self.panel = panel
        currentIsProgress = kind.isProgress

        // A progress toast stays up until the next toast replaces it; every other
        // toast auto-dismisses.
        guard kind.autoDismisses else { return }
        dismissTask = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(Self.duration))
            guard !Task.isCancelled else { return }
            self?.fadeOut()
        }
    }

    private func fadeOut() {
        currentIsProgress = false
        guard let panel else { return }
        self.panel = nil
        NSAnimationContext.runAnimationGroup({ ctx in
            ctx.duration = 0.2
            panel.animator().alphaValue = 0
        }, completionHandler: {
            panel.orderOut(nil)
            panel.close()
        })
    }

    func hide() {
        dismissTask?.cancel()
        dismissTask = nil
        currentIsProgress = false
        guard let panel else { return }
        self.panel = nil
        panel.orderOut(nil)
        panel.close()
    }
}

/// One toast card (design: 14-radius glass, 32×32 radius-10 glyph chip,
/// 13.5/600 title, mono 11px meta).
private struct ToastView: View {
    let kind: ToastPresenter.Kind

    var body: some View {
        HStack(spacing: 11) {
            ZStack {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(kind.dimColor)
                Image(systemName: kind.symbol)
                    .font(.system(size: 15, weight: .medium))
                    .foregroundStyle(kind.color)
            }
            .frame(width: 32, height: 32)
            VStack(alignment: .leading, spacing: kind.showsProgressBar ? 6 : 2) {
                Text(kind.title)
                    .font(.system(size: 13.5, weight: .semibold))
                    .foregroundStyle(Theme.textPrimary)
                    // Take the text's full ideal width so the card grows to fit it
                    // instead of truncating ("installed with Serber…").
                    .fixedSize(horizontal: true, vertical: false)
                if kind.showsProgressBar {
                    // Indeterminate bar — verification/install have no known
                    // duration, so an animated "barber pole" reads as active work.
                    ProgressView()
                        .progressViewStyle(.linear)
                        .controlSize(.small)
                        .tint(kind.color)
                        .frame(width: 212)
                } else {
                    Text(kind.meta)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Theme.textMuted)
                        .fixedSize(horizontal: true, vertical: false)
                }
            }
        }
        .padding(.vertical, 16).padding(.horizontal, 18)
        .background {
            ZStack {
                GlassBackground()
                Theme.glass
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: Radius.toast, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: Radius.toast, style: .continuous)
                .strokeBorder(Theme.glassBorder, lineWidth: 1)
        }
        .overlay(alignment: .top) {
            Theme.glassHighlight.frame(height: 1).padding(.horizontal, Radius.toast)
        }
        .preferredColorScheme(.dark)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(kind.title). \(kind.meta)")
    }
}
