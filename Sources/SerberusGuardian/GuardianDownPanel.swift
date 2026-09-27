import AppKit
import SerberusUI
import SwiftUI

/// Owns the persistent upper-right "Sentinel is down" panel. Unlike the toast
/// (click-through + auto-dismiss) this panel is **clickable** (the Launch button
/// must be hit-testable) and **persistent** — it never auto-dismisses; the
/// watcher calls ``dismiss()`` the moment the Sentinel is back up. It is still
/// non-activating and does not steal focus from the user's frontmost app.
@MainActor
final class GuardianDownPresenter {
    private var panel: NSPanel?

    /// Shows the panel (idempotent). `onLaunch` fires when the user taps
    /// "Launch Serberus".
    func present(onLaunch: @escaping @MainActor () -> Void) {
        guard panel == nil else { return }
        let hosting = NSHostingView(rootView: GuardianDownView(onLaunch: onLaunch))
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 10, height: 10),
            styleMask: [.borderless, .nonactivatingPanel],
            backing: .buffered, defer: false)
        panel.backgroundColor = .clear
        panel.isOpaque = false
        panel.hasShadow = true
        panel.isReleasedWhenClosed = false
        panel.ignoresMouseEvents = false        // the Launch button must be hit-testable
        panel.isFloatingPanel = true
        panel.becomesKeyOnlyIfNeeded = true     // no text field → never becomes key
        panel.hidesOnDeactivate = false         // stays up when another app is frontmost
        panel.level = .floating                 // long-lived → not .statusBar (won't sit over menus)
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.contentView = hosting
        panel.setContentSize(hosting.fittingSize)
        self.panel = panel
        position()

        // Entry: fade + 8pt upward slide (skipped under Reduce Motion). Never
        // NSApp.activate — that is how the button fires without stealing focus.
        let reduceMotion = NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
        if !reduceMotion {
            panel.alphaValue = 0
            let origin = panel.frame.origin
            panel.setFrameOrigin(NSPoint(x: origin.x, y: origin.y - 8))
            panel.orderFrontRegardless()
            NSAnimationContext.runAnimationGroup { ctx in
                ctx.duration = 0.2
                ctx.timingFunction = CAMediaTimingFunction(name: .easeOut)
                panel.animator().alphaValue = 1
                panel.animator().setFrameOrigin(origin)
            }
        } else {
            panel.orderFrontRegardless()
        }
    }

    func dismiss() {
        guard let panel else { return }
        self.panel = nil
        NSAnimationContext.runAnimationGroup({ ctx in
            ctx.duration = 0.18
            panel.animator().alphaValue = 0
        }, completionHandler: {
            panel.orderOut(nil)
            panel.close()
        })
    }

    /// Anchors the card to the top-right of the main screen (same math as the toast).
    private func position() {
        guard let panel, let screen = NSScreen.main else { return }
        let frame = screen.visibleFrame
        let size = panel.frame.size
        panel.setFrameOrigin(NSPoint(x: frame.maxX - size.width - 16, y: frame.maxY - size.height - 12))
    }
}

/// The card content — reads as "protection off" (amber sigil), with the green
/// accent reserved for the single positive action (the Launch button).
private struct GuardianDownView: View {
    let onLaunch: @MainActor () -> Void
    @State private var launching = false

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 10, style: .continuous).fill(GuardianTheme.silentDim)
                SentinelSigilView()
                    .foregroundStyle(GuardianTheme.silent)
                    .frame(width: 18, height: 18)
            }
            .frame(width: 34, height: 34)

            VStack(alignment: .leading, spacing: 3) {
                Text("Serberus Sentinel isn't running")
                    .font(.system(size: 13.5, weight: .semibold))
                    .foregroundStyle(GuardianTheme.textPrimary)
                Text("Your elevation requests won't work until it's relaunched.")
                    .font(.system(size: 11.5))
                    .foregroundStyle(GuardianTheme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)

                Button(action: launch) {
                    HStack(spacing: 6) {
                        if launching { ProgressView().controlSize(.small) }
                        Text(launching ? "Launching…" : "Launch Serberus")
                            .font(.system(size: 12, weight: .semibold))
                    }
                    .foregroundStyle(GuardianTheme.accentInk)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(GuardianTheme.accentGradient,
                               in: RoundedRectangle(cornerRadius: GuardianTheme.Radius.button, style: .continuous))
                }
                .buttonStyle(.plain)
                .disabled(launching)
                .padding(.top, 5)
            }
        }
        .padding(.vertical, 16)
        .padding(.horizontal, 18)
        .frame(width: 300, alignment: .leading)
        .background {
            ZStack {
                GuardianGlassBackground()
                GuardianTheme.glass
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: GuardianTheme.Radius.toast, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: GuardianTheme.Radius.toast, style: .continuous)
                .strokeBorder(GuardianTheme.glassBorder, lineWidth: 1)
        }
        .overlay(alignment: .top) {
            GuardianTheme.glassHighlight.frame(height: 1).padding(.horizontal, GuardianTheme.Radius.toast)
        }
        .preferredColorScheme(.dark)
    }

    private func launch() {
        launching = true
        onLaunch()
        // Guarded auto-revert: if the relaunch didn't take within 6s (panel still
        // up), re-enable the button so it can be retried. A cancelled sleep
        // returns immediately, so guard isCancelled (repo lesson).
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(6))
            guard !Task.isCancelled else { return }
            launching = false
        }
    }
}
