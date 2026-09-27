#if DEBUG
import PrivMgrCore
import SerberusSentinelCore
import SwiftUI

/// A self-driving demo of the elevation prompt (debug builds only). It hosts a
/// real ``PromptViewModel`` with a live countdown so you can approve, deny, let
/// it time out, and exercise the justification gate — no daemon required. The
/// production prompt is driven by the daemon over XPC.
struct PromptDemoView: View {
    @State private var model = PromptDemoView.makeModel()

    var body: some View {
        VStack(spacing: 0) {
            if let verdict = model.verdict {
                resultBanner(verdict)
            } else {
                PromptWindow(
                    model: model,
                    allowLabel: PromptWindowController.defaultAllowLabel,
                    denyLabel: PromptWindowController.defaultDenyLabel,
                    brandTitle: "Acme Inc",
                    brandSubtitle: "IT Security"
                )
                .padding(24)
            }
        }
        .background(Theme.background)
        .preferredColorScheme(.dark)
        .tint(Theme.emerald)
        .task(id: model.context.requestID) {
            // No window-server checks here: the demo reports its window key,
            // visible and uncovered, so Approve arms after the same one-second
            // delay as the real prompt (whose controller feeds the real state).
            model.observeWindow(isKey: true, isVisible: true, isUncovered: true)
            while model.verdict == nil, !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                guard !Task.isCancelled else { break }
                model.observeWindow(isKey: true, isVisible: true, isUncovered: true)
                model.tick()
            }
        }
    }

    private func resultBanner(_ verdict: PromptResponse.Verdict) -> some View {
        VStack(spacing: Spacing.lg) {
            Image(systemName: icon(verdict))
                .font(.system(size: 48))
                .foregroundStyle(color(verdict))
                .shadow(color: color(verdict).opacity(0.5), radius: 12)
            Text(title(verdict)).font(.system(size: 20, weight: .bold)).foregroundStyle(Theme.textPrimary)
            if let justification = model.verdict == .approved && !model.justificationText.isEmpty
                ? model.justificationText : nil {
                Text("“\(justification)”")
                    .font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
            }
            Button("Show Another Prompt") {
                model = PromptDemoView.makeModel()
            }
            .buttonStyle(SentinelGhostButton())
            .frame(width: 200)
            .keyboardShortcut(.defaultAction)
        }
        .padding(32)
        .frame(width: 460, height: 320)
    }

    private func icon(_ verdict: PromptResponse.Verdict) -> String {
        switch verdict {
        case .approved: return "checkmark.circle.fill"
        case .denied: return "xmark.octagon.fill"
        case .timedOut: return "clock.badge.exclamationmark.fill"
        }
    }

    private func color(_ verdict: PromptResponse.Verdict) -> Color {
        switch verdict {
        case .approved: return Theme.success
        case .denied: return Theme.critical
        case .timedOut: return Theme.warning
        }
    }

    private func title(_ verdict: PromptResponse.Verdict) -> String {
        switch verdict {
        case .approved: return "Approved"
        case .denied: return "Denied"
        case .timedOut: return "Timed Out — Denied"
        }
    }

    private static func makeModel() -> PromptViewModel {
        let context = PromptContext(
            user: NSUserName(),
            processName: "brew",
            canonicalPath: "/opt/homebrew/bin/brew",
            teamID: nil,
            signingStatus: .unsigned,
            humanReadableRequest: "sudo /opt/homebrew/bin/brew install wget",
            requireJustification: true,
            justificationMinLength: 10,
            timeoutSeconds: 30,
            ruleName: "rules_sudo_standard · brew-install",
            ruleDescription: "Install software with Homebrew"
        )
        return PromptViewModel(context: context, onResolve: { _ in })
    }
}
#endif
