import Foundation
import Testing
import PrivMgrCore
@testable import SerberusSentinelCore

@Suite("MenubarIcon")
struct MenubarIconTests {
    @Test("daemon states map to the four indicators")
    func mapping() {
        #expect(MenubarIcon.from(.healthy) == .healthy)
        #expect(MenubarIcon.from(.pendingPPPC) == .pending)
        #expect(MenubarIcon.from(.pendingProfiles) == .pending)
        #expect(MenubarIcon.from(.degraded) == .degraded)
        #expect(MenubarIcon.from(.killSwitch) == .killSwitch)
    }

    @Test("every icon has a symbol and tooltip")
    func presentation() {
        for icon in MenubarIcon.allCases {
            #expect(!icon.symbolName.isEmpty)
            #expect(icon.tooltip.contains("Serberus"))
        }
    }
}

@MainActor
@Suite("MenubarStateModel")
struct MenubarStateModelTests {
    private let now = Date(timeIntervalSince1970: 1_781_222_400)

    private func grant(user: String = "alice", expiresAt: Date?) -> Grant {
        Grant(user: user, uid: 501, ruleID: "r", profileKey: "rules_sudo_a", teamID: "",
              binaryHash: "aa", canonicalPath: "/bin/x", grantedAt: now, expiresAt: expiresAt, policyVersion: "1.0.0")
    }

    @Test("icon follows the daemon state")
    func icon() {
        let model = MenubarStateModel(daemonState: .healthy, now: { self.now })
        #expect(model.icon == .healthy)
        model.update(state: .degraded)
        #expect(model.icon == .degraded)
    }

    @Test("displayGrants drops expired and sorts soonest-first")
    func displayGrants() {
        let model = MenubarStateModel(now: { self.now })
        model.update(grants: [
            grant(expiresAt: now.addingTimeInterval(600)),
            grant(expiresAt: now.addingTimeInterval(-1)),  // expired
            grant(expiresAt: now.addingTimeInterval(120)),
        ])
        let display = model.displayGrants()
        #expect(display.count == 2)
        #expect(display.first?.expiresAt == now.addingTimeInterval(120))
    }
}

@MainActor
@Suite("MenubarPresentation")
struct MenubarPresentationTests {
    private let now = Date(timeIntervalSince1970: 1_781_222_400)

    private func model(state: DaemonState = .healthy, reachable: Bool = true,
                       at clock: @escaping @Sendable () -> Date) -> MenubarStateModel {
        MenubarStateModel(daemonState: state, daemonReachable: reachable, now: clock)
    }

    @Test("daemon states map to the design's icon states")
    func daemonMapping() {
        let clock: @Sendable () -> Date = { [now] in now }
        #expect(model(state: .healthy, at: clock).presentation == .idle)
        #expect(model(state: .pendingProfiles, at: clock).presentation == .pending)
        // Degraded is its own state — "action blocked" for an enforcement
        // fault would misdirect the user's report.
        #expect(model(state: .degraded, at: clock).presentation == .degraded)
        #expect(model(state: .killSwitch, at: clock).presentation == .killSwitch)
        #expect(model(state: .healthy, reachable: false, at: clock).presentation == .offline)
    }

    @Test("an on-screen prompt pulses regardless of daemon state — except kill switch")
    func promptWaiting() {
        let m = model(at: { self.now })
        m.promptDidBegin()
        #expect(m.presentation == .promptWaiting)

        m.update(state: .killSwitch)
        #expect(m.presentation == .killSwitch)
    }

    @Test("a denial flashes blocked, then decays back to idle")
    func blockedFlash() {
        // Controllable clock: starts at `now`, advanced by the test.
        let offset = ClockOffset()
        let m = model(at: { self.now.addingTimeInterval(offset.value) })
        m.promptDidBegin()
        m.promptDidEnd(verdict: .denied)
        #expect(m.presentation == .blocked)

        offset.value = MenubarStateModel.blockedFlashDuration + 1
        #expect(m.presentation == .idle)
        m.clearExpiredBlockedFlash()
        #expect(m.presentation == .idle)
    }

    @Test("an approval ends the prompt with no flash")
    func approvalNoFlash() {
        let m = model(at: { self.now })
        m.promptDidBegin()
        m.promptDidEnd(verdict: .approved)
        #expect(m.presentation == .idle)
    }

    @Test("a timeout flashes blocked like a denial")
    func timeoutFlash() {
        let m = model(at: { self.now })
        m.promptDidBegin()
        m.promptDidEnd(verdict: .timedOut)
        #expect(m.presentation == .blocked)
    }

    @Test("every presentation has a tooltip")
    func tooltips() {
        let all: [MenubarPresentation] = [.idle, .pending, .promptWaiting, .blocked, .degraded,
                                          .offline, .killSwitch, .grantActive(expiresAt: nil)]
        for presentation in all {
            #expect(presentation.tooltip.contains("Serberus"))
        }
        // The transient denial flash and the persistent fault must not read
        // the same on hover.
        #expect(MenubarPresentation.blocked.tooltip != MenubarPresentation.degraded.tooltip)
    }

    private func grant(expiresAt: Date?) -> Grant {
        Grant(user: "alice", uid: 501, ruleID: "r", profileKey: "rules_sudo_a", teamID: "",
              binaryHash: "aa", canonicalPath: "/bin/x", grantedAt: now, expiresAt: expiresAt,
              policyVersion: "1.0.0")
    }

    @Test("an active grant lights the icon green when the daemon is healthy")
    func grantActiveWhenHealthy() {
        let m = model(at: { self.now })
        // No grant → idle rest state.
        #expect(m.presentation == .idle)
        // Active grant, comfortable time left → grant-active carrying its expiry.
        let expiry = now.addingTimeInterval(600)
        m.update(grants: [grant(expiresAt: expiry)])
        #expect(m.presentation == .grantActive(expiresAt: expiry))
    }

    @Test("the icon carries the SOONEST active grant's expiry for urgency")
    func grantActiveSoonestExpiry() {
        let m = model(at: { self.now })
        let soon = now.addingTimeInterval(30)
        m.update(grants: [
            grant(expiresAt: now.addingTimeInterval(600)),
            grant(expiresAt: soon),
            grant(expiresAt: now.addingTimeInterval(-1)),  // expired — ignored
        ])
        #expect(m.presentation == .grantActive(expiresAt: soon))
    }

    @Test("a grant with no expiry never pulses the icon: nothing is counting down")
    func grantActiveNoExpiry() {
        let m = model(at: { self.now })
        m.update(grants: [grant(expiresAt: nil)])
        #expect(m.presentation == .idle)
        // Alongside a timed grant, only the timed one lights it, with its expiry.
        let expiry = now.addingTimeInterval(300)
        m.update(grants: [grant(expiresAt: nil), grant(expiresAt: expiry)])
        #expect(m.presentation == .grantActive(expiresAt: expiry))
        // The indefinite grant is still listed in the dropdown.
        #expect(m.displayGrants().count == 2)
    }

    @Test("an expired grant returns the icon to its rest state")
    func expiredGrantRests() {
        let m = model(at: { self.now })
        m.update(grants: [grant(expiresAt: now.addingTimeInterval(-1))])
        #expect(m.presentation == .idle)
    }

    @Test("more urgent states outrank the grant-active indicator")
    func moreUrgentStatesWin() {
        // A prompt, a fault, an unreachable daemon, and the kill switch all
        // outrank a benign active-grant indicator.
        let prompting = model(at: { self.now })
        prompting.update(grants: [grant(expiresAt: now.addingTimeInterval(600))])
        prompting.promptDidBegin()
        #expect(prompting.presentation == .promptWaiting)

        let degraded = model(state: .degraded, at: { self.now })
        degraded.update(grants: [grant(expiresAt: now.addingTimeInterval(600))])
        #expect(degraded.presentation == .degraded)

        let offline = model(state: .healthy, reachable: false, at: { self.now })
        offline.update(grants: [grant(expiresAt: now.addingTimeInterval(600))])
        #expect(offline.presentation == .offline)

        let killed = model(state: .killSwitch, at: { self.now })
        killed.update(grants: [grant(expiresAt: now.addingTimeInterval(600))])
        #expect(killed.presentation == .killSwitch)
    }
}

/// A mutable box so the injected clock can be advanced mid-test.
private final class ClockOffset: @unchecked Sendable {
    var value: TimeInterval = 0
}

@MainActor
@Suite("PromptViewModel")
struct PromptViewModelTests {
    private func context(requireJustification: Bool = false, minLength: Int = 0, timeout: Int = 60) -> PromptContext {
        PromptContext(
            user: "alice", processName: "brew", canonicalPath: "/opt/homebrew/bin/brew",
            teamID: nil, signingStatus: .unsigned, humanReadableRequest: "sudo brew install wget",
            requireJustification: requireJustification, justificationMinLength: minLength, timeoutSeconds: timeout
        )
    }

    /// A model on a manual clock: `clock.value` seconds after it was created,
    /// to the millisecond (exact, so boundary checks can't drift).
    private func makeModel(
        _ context: PromptContext, clock: ClockOffset,
        onResolve: @escaping @MainActor (PromptResponse) -> Void = { _ in }
    ) -> PromptViewModel {
        let start = ContinuousClock.now
        return PromptViewModel(
            context: context,
            now: { start.advanced(by: .milliseconds(Int((clock.value * 1000).rounded()))) },
            onResolve: onResolve
        )
    }

    /// A click or ⌘↩ on the prompt, as the window controller's event monitor
    /// reports it: a fresh observation (here, clear), then the input.
    private func input(_ model: PromptViewModel) {
        model.observeWindow(isKey: true, isVisible: true, isUncovered: true)
        model.noteInput()
    }

    private func observeClear(_ model: PromptViewModel) {
        model.observeWindow(isKey: true, isVisible: true, isUncovered: true)
    }

    /// Arms `model` the way the window controller does: the window is reported
    /// key, visible and uncovered, and still is one arming delay later.
    private func arm(_ model: PromptViewModel, clock: ClockOffset) {
        model.observeWindow(isKey: true, isVisible: true, isUncovered: true)
        clock.value += 1
        model.observeWindow(isKey: true, isVisible: true, isUncovered: true)
    }

    @Test("approve produces an approved response with justification")
    func approve() {
        var captured: PromptResponse?
        let clock = ClockOffset()
        let model = makeModel(context(), clock: clock) { captured = $0 }
        model.justificationText = "deploying"
        arm(model, clock: clock)
        model.approve()
        #expect(captured?.verdict == .approved)
        #expect(model.verdict == .approved)
    }

    @Test("countdown reaching zero denies via timeout — never auto-approves")
    func timeoutDenies() {
        var captured: PromptResponse?
        let model = PromptViewModel(context: context(timeout: 3)) { captured = $0 }
        model.tick(); model.tick(); model.tick()
        #expect(captured?.verdict == .timedOut)
        #expect(model.remainingSeconds == 0)
    }

    @Test("Escape/deny produces a denied response")
    func deny() {
        var captured: PromptResponse?
        let model = PromptViewModel(context: context()) { captured = $0 }
        model.deny()
        #expect(captured?.verdict == .denied)
    }

    @Test("justification gate blocks approve until the minimum length is met")
    func justificationGate() {
        let clock = ClockOffset()
        let model = makeModel(context(requireJustification: true, minLength: 5), clock: clock)
        arm(model, clock: clock)
        #expect(!model.canApprove)
        model.justificationText = "abc"
        #expect(!model.canApprove)
        model.justificationText = "abcdef"
        #expect(model.canApprove)
        // Whitespace doesn't count.
        model.justificationText = "  ab  "
        #expect(!model.canApprove)
    }

    @Test("resolution happens exactly once")
    func resolveOnce() {
        var count = 0
        let clock = ClockOffset()
        let model = makeModel(context(), clock: clock) { _ in count += 1 }
        arm(model, clock: clock)
        model.approve()
        model.deny()
        model.tick()
        #expect(count == 1)
        #expect(model.verdict == .approved)
    }

    @Test("progress depletes from 1 toward 0")
    func progress() {
        let model = PromptViewModel(context: context(timeout: 10)) { _ in }
        #expect(model.progress == 1.0)
        for _ in 0..<5 { model.tick() }
        #expect(abs(model.progress - 0.5) < 0.0001)
    }

    // MARK: Arming

    @Test("an unarmed prompt refuses approval, so its first frame can't approve")
    func approveRefusedBeforeArming() {
        // Old API only (no clock, no observations): this is the prompt as it
        // stands the moment it appears, with no justification required.
        var captured: PromptResponse?
        let model = PromptViewModel(context: context()) { captured = $0 }
        #expect(!model.canApprove)
        model.approve()
        #expect(captured == nil)
        #expect(model.verdict == nil)
    }

    @Test("Approve arms after one second of key, visible and uncovered, not before")
    func armsAfterOneSecond() {
        var captured: PromptResponse?
        let clock = ClockOffset()
        let model = makeModel(context(), clock: clock) { captured = $0 }
        model.observeWindow(isKey: true, isVisible: true, isUncovered: true)
        clock.value = 0.999
        model.observeWindow(isKey: true, isVisible: true, isUncovered: true)
        #expect(!model.isArmed)
        #expect(!model.canApprove)
        model.approve()
        #expect(captured == nil)

        clock.value = 1
        model.observeWindow(isKey: true, isVisible: true, isUncovered: true)
        #expect(model.isArmed)
        #expect(model.canApprove)
        model.approve()
        #expect(captured?.verdict == .approved)
    }

    @Test("losing key, becoming not visible, or an overlap each disarm at once")
    func disarmsAtOnce() {
        let blocked: [(isKey: Bool, isVisible: Bool, isUncovered: Bool)] = [
            (false, true, true), (true, false, true), (true, true, false),
        ]
        for state in blocked {
            var captured: PromptResponse?
            let clock = ClockOffset()
            let model = makeModel(context(), clock: clock) { captured = $0 }
            arm(model, clock: clock)
            #expect(model.canApprove)
            // Same instant: no grace period.
            model.observeWindow(isKey: state.isKey, isVisible: state.isVisible, isUncovered: state.isUncovered)
            #expect(!model.isArmed)
            #expect(!model.canApprove)
            model.approve()
            #expect(captured == nil)
            // And it stays disarmed however long the cause lasts.
            clock.value += 30
            model.observeWindow(isKey: state.isKey, isVisible: state.isVisible, isUncovered: state.isUncovered)
            #expect(!model.isArmed)
        }
    }

    @Test("re-arming after a disarm needs another full second")
    func rearmNeedsFullSecond() {
        let clock = ClockOffset()
        let model = makeModel(context(), clock: clock)
        arm(model, clock: clock)
        clock.value = 5
        model.observeWindow(isKey: true, isVisible: true, isUncovered: false)
        clock.value = 5.5
        model.observeWindow(isKey: true, isVisible: true, isUncovered: true)
        clock.value = 6.499
        model.observeWindow(isKey: true, isVisible: true, isUncovered: true)
        #expect(!model.isArmed)
        clock.value = 6.5
        model.observeWindow(isKey: true, isVisible: true, isUncovered: true)
        #expect(model.isArmed)
    }

    @Test("a prompt covered from the start arms one second after it's uncovered")
    func coveredFromStart() {
        let clock = ClockOffset()
        let model = makeModel(context(), clock: clock)
        for second in 0...3 {
            clock.value = Double(second)
            model.observeWindow(isKey: true, isVisible: true, isUncovered: false)
            #expect(!model.isArmed)
        }
        model.observeWindow(isKey: true, isVisible: true, isUncovered: true)
        clock.value = 3.999
        model.observeWindow(isKey: true, isVisible: true, isUncovered: true)
        #expect(!model.isArmed)
        clock.value = 4
        model.observeWindow(isKey: true, isVisible: true, isUncovered: true)
        #expect(model.isArmed)
    }

    @Test("deny, Escape and the timeout work while unarmed")
    func denyAndTimeoutWhileUnarmed() {
        var denied: PromptResponse?
        let covered = makeModel(context(), clock: ClockOffset()) { denied = $0 }
        covered.observeWindow(isKey: false, isVisible: true, isUncovered: false)
        covered.deny()
        #expect(denied?.verdict == .denied)

        var timedOut: PromptResponse?
        let unobserved = makeModel(context(timeout: 2), clock: ClockOffset()) { timedOut = $0 }
        unobserved.tick()
        unobserved.tick()
        #expect(timedOut?.verdict == .timedOut)
    }

    @Test("the hint explains a disarm only after the first second")
    func disarmedReason() {
        let clock = ClockOffset()
        let model = makeModel(context(), clock: clock)
        model.observeWindow(isKey: true, isVisible: true, isUncovered: false)
        #expect(model.disarmedReason == nil)  // the first second: nothing to explain yet
        clock.value = 1
        model.observeWindow(isKey: true, isVisible: true, isUncovered: false)
        #expect(model.disarmedReason == .covered)
        model.observeWindow(isKey: true, isVisible: false, isUncovered: true)
        #expect(model.disarmedReason == .covered)
        model.observeWindow(isKey: false, isVisible: true, isUncovered: true)
        #expect(model.disarmedReason == .notFocused)
        model.observeWindow(isKey: false, isVisible: true, isUncovered: false)
        #expect(model.disarmedReason == .covered)  // moving it also focuses it
        model.observeWindow(isKey: true, isVisible: true, isUncovered: true)
        #expect(model.disarmedReason == nil)  // cause cleared: re-arming, no hint
        clock.value = 2
        model.observeWindow(isKey: true, isVisible: true, isUncovered: true)
        #expect(model.isArmed)
        #expect(model.disarmedReason == nil)
    }

    // MARK: Input while arming

    @Test("a click or ⌘↩ while unarmed restarts the one-second delay")
    func inputRestartsDelay() {
        var captured: PromptResponse?
        let clock = ClockOffset()
        let model = makeModel(context(), clock: clock) { captured = $0 }
        observeClear(model)
        clock.value = 0.95
        input(model)
        clock.value = 1.05
        observeClear(model)
        #expect(!model.isArmed)
        model.approve()
        #expect(captured == nil)
        clock.value = 1.949
        observeClear(model)
        #expect(!model.isArmed)
        clock.value = 1.95
        observeClear(model)
        #expect(model.isArmed)
        model.approve()
        #expect(captured?.verdict == .approved)
    }

    @Test("rapid clicks, one every half second, keep it unarmed indefinitely")
    func rapidClicksKeepUnarmed() {
        var captured: PromptResponse?
        let clock = ClockOffset()
        let model = makeModel(context(), clock: clock) { captured = $0 }
        observeClear(model)
        for step in 1...40 {
            clock.value = Double(step) * 0.5
            observeClear(model)  // the poll that lands just before the click
            #expect(!model.isArmed)
            input(model)
            model.approve()
        }
        #expect(captured == nil)
        // Arms a full second after the last click.
        clock.value = 20.999
        observeClear(model)
        #expect(!model.isArmed)
        clock.value = 21
        observeClear(model)
        #expect(model.isArmed)
    }

    @Test("a held ⌘↩ keeps it unarmed until a second after the last repeat")
    func heldKeyKeepsUnarmed() {
        let clock = ClockOffset()
        let model = makeModel(context(), clock: clock)
        observeClear(model)
        // A key-down, then repeats every 50 ms for three seconds.
        for ms in stride(from: 300, through: 3300, by: 50) {
            clock.value = Double(ms) / 1000
            input(model)
            #expect(!model.isArmed)
        }
        clock.value = 4.299
        observeClear(model)
        #expect(!model.isArmed)
        clock.value = 4.3
        observeClear(model)
        #expect(model.isArmed)
    }

    @Test("typing in the justification field doesn't restart the delay")
    func typingDoesNotRestart() {
        let clock = ClockOffset()
        let model = makeModel(context(requireJustification: true, minLength: 1), clock: clock)
        observeClear(model)
        for (index, character) in "deploying".enumerated() {
            clock.value = 0.1 * Double(index + 1)
            model.justificationText.append(character)
            observeClear(model)
        }
        clock.value = 1
        observeClear(model)
        #expect(model.isArmed)
        #expect(model.canApprove)
    }

    @Test("input while armed neither disarms nor restarts")
    func inputWhileArmed() {
        var captured: PromptResponse?
        let clock = ClockOffset()
        let model = makeModel(context(), clock: clock) { captured = $0 }
        arm(model, clock: clock)
        clock.value = 1.5
        input(model)
        #expect(model.isArmed)
        clock.value = 1.6
        observeClear(model)
        #expect(model.isArmed)
        model.approve()
        #expect(captured?.verdict == .approved)
    }

    @Test("approve() right after an overlap is seen refuses, though the last poll had armed it")
    func approveAfterFreshOverlapRefused() {
        var captured: PromptResponse?
        let clock = ClockOffset()
        let model = makeModel(context(), clock: clock) { captured = $0 }
        arm(model, clock: clock)
        #expect(model.canApprove)  // the last poll armed it
        // The click's fresh read finds an overlay that arrived since that poll;
        // the button may still be drawn enabled when the click lands.
        clock.value += 0.1
        model.observeWindow(isKey: true, isVisible: true, isUncovered: false)
        model.noteInput()
        model.approve()
        #expect(captured == nil)
        #expect(model.verdict == nil)
    }
}
