import Foundation
import Observation
import PrivMgrCore

/// Drives one elevation prompt.
///
/// Enforces the security-relevant rules: the countdown always denies on
/// expiry (never auto-allows), Escape always denies, and Approve is enabled
/// only once the justification requirement is satisfied and the prompt is
/// armed — key, visible and uncovered for a second (``PromptArming``).
/// The resolution callback fires exactly once.
@MainActor
@Observable
public final class PromptViewModel {
    /// Why Approve is disarmed, for the prompt's one-line hint.
    public enum DisarmedReason: Sendable, Equatable {
        /// Another window overlaps the prompt, or the prompt isn't visible.
        case covered
        /// The prompt isn't the key window: another app or window has the focus.
        case notFocused
    }

    public let context: PromptContext
    public private(set) var remainingSeconds: Int
    public var justificationText: String = ""
    /// The verdict once resolved; `nil` while awaiting the user.
    public private(set) var verdict: PromptResponse.Verdict?
    /// Whether Approve is armed (``PromptArming``). Stored, not computed, so the
    /// view re-renders when it flips; only
    /// ``observeWindow(isKey:isVisible:isUncovered:)`` changes it.
    public private(set) var isArmed = false
    /// Why Approve is disarmed, once the prompt has been up for the arming delay
    /// and while the latest observation keeps it from arming. `nil` while armed,
    /// while re-arming after the cause cleared, and during the first second
    /// (a normal arm needs no explanation).
    public private(set) var disarmedReason: DisarmedReason?

    @ObservationIgnored private var arming = PromptArming()
    private let presentedAt: ContinuousClock.Instant
    private let now: @Sendable () -> ContinuousClock.Instant
    private let onResolve: @MainActor (PromptResponse) -> Void

    public init(
        context: PromptContext,
        now: @escaping @Sendable () -> ContinuousClock.Instant = { ContinuousClock.now },
        onResolve: @escaping @MainActor (PromptResponse) -> Void
    ) {
        self.context = context
        self.remainingSeconds = context.timeoutSeconds
        self.now = now
        self.presentedAt = now()
        self.onResolve = onResolve
    }

    /// Whether the justification requirement (if any) is met.
    public var justificationSatisfied: Bool {
        guard context.requireJustification else { return true }
        return justificationText.trimmingCharacters(in: .whitespacesAndNewlines).count >= context.justificationMinLength
    }

    /// Approve is available only while unresolved, justification-satisfied and armed.
    public var canApprove: Bool {
        verdict == nil && justificationSatisfied && isArmed
    }

    /// Fraction of time remaining, for the countdown bar (1 → 0).
    public var progress: Double {
        guard context.timeoutSeconds > 0 else { return 0 }
        return max(0, min(1, Double(remainingSeconds) / Double(context.timeoutSeconds)))
    }

    public func approve() {
        // canApprove includes arming: an unarmed prompt refuses however approval
        // is asked for, never relying on the disabled button alone.
        guard canApprove else { return }
        resolve(.approved, justification: justificationText)
    }

    /// Reports the prompt window's state to the arming gate — the window
    /// controller calls this on every key, occlusion, move or resize change and
    /// on a short poll — and re-evaluates ``isArmed`` and ``disarmedReason``
    /// against the clock, so the poll also arms the prompt once the delay has
    /// passed. A no-op once resolved.
    public func observeWindow(isKey: Bool, isVisible: Bool, isUncovered: Bool) {
        guard verdict == nil else { return }
        let time = now()
        arming.observe(isKey: isKey, isVisible: isVisible, isUncovered: isUncovered, at: time)
        let armed = arming.isArmed(at: time)
        var reason: DisarmedReason?
        if !armed, presentedAt.duration(to: time) >= PromptArming.delay {
            if !isVisible || !isUncovered {
                reason = .covered
            } else if !isKey {
                reason = .notFocused
            }
        }
        // Assign only on change: every set of an observed property re-renders.
        if armed != isArmed { isArmed = armed }
        if reason != disarmedReason { disarmedReason = reason }
    }

    /// Notes a click on the prompt or a ⌘↩ (held or repeated included). The
    /// window controller calls it for each such event, after a fresh
    /// ``observeWindow(isKey:isVisible:isUncovered:)`` and before the event is
    /// dispatched. While Approve is disarmed it restarts the one-second delay
    /// (``PromptArming/noteInput(at:)``); once armed it changes nothing.
    public func noteInput() {
        guard verdict == nil, !isArmed else { return }
        arming.noteInput(at: now())
    }

    /// Deny (the Deny button or Escape).
    public func deny() {
        resolve(.denied, justification: nil)
    }

    /// Advances the countdown one second. On reaching zero it denies via
    /// timeout — elevation is never auto-approved.
    public func tick() {
        guard verdict == nil else { return }
        remainingSeconds -= 1
        if remainingSeconds <= 0 {
            remainingSeconds = 0
            resolve(.timedOut, justification: nil)
        }
    }

    private func resolve(_ verdict: PromptResponse.Verdict, justification: String?) {
        guard self.verdict == nil else { return }
        self.verdict = verdict
        onResolve(PromptResponse(
            requestID: context.requestID,
            verdict: verdict,
            justificationText: justification
        ))
    }
}
