import AppKit
import Foundation
import OSLog
import PrivMgrCore

/// Watches the Sentinel menu-bar agent and, when it is quit — and the managed
/// `guardianEnabled` gate is on — shows a persistent panel with a relaunch
/// button. The 3s poll is the source of truth; `NSWorkspace` launch/terminate
/// notifications only make it snappier. A debounce absorbs crash/KeepAlive
/// relaunches (the Sentinel returns within its 5s ThrottleInterval), so only a
/// deliberate Quit surfaces the panel.
@MainActor
final class GuardianWatcher {
    private let presenter = GuardianDownPresenter()
    private var pollTimer: Timer?
    private var pendingDown: Task<Void, Never>?
    private var showing = false
    /// Whether the Sentinel has been observed running THIS session. The guardian
    /// only prompts for a Sentinel that was up and THEN went down (a real quit) —
    /// never for one it has simply never seen up yet (cold-login, or the guardian
    /// started first). This encodes the "was up then quit" semantic directly and
    /// removes any dependence on a fixed login-grace guess (which could flash on a
    /// slow boot).
    private var everSeenUp = false

    // nonisolated so the off-actor relaunch ladder can log (Logger is Sendable).
    nonisolated private static let log = Logger(subsystem: BundleConfig.logSubsystem, category: "guardian")
    // A deliberate quit stays down; a crash is relaunched by KeepAlive. A Sentinel
    // that has been up a while relaunches NEAR-INSTANTLY on crash (the 5s
    // ThrottleInterval only delays a relaunch within 5s of the LAST launch — a
    // startup crash-loop), so a short debounce absorbs a normal crash while
    // firing fast after a real quit. Admin-tunable (see runtimeDebounce()).
    private static let runtimeDebounceDefault: TimeInterval = 3
    private static let pollInterval: TimeInterval = 2

    /// Seconds to wait after a Sentinel-down before prompting. Admin-tunable via
    /// the managed config key `guardianDetectionSeconds` (clamped 0…300); absent
    /// ⇒ 3. Lower fires faster but a normal crash-relaunch may briefly flash it.
    private func runtimeDebounce() -> TimeInterval {
        let raw = CFPreferencesSource().managedValue(forKey: "guardianDetectionSeconds",
                                                     domain: BundleConfig.configDomain)
        guard let seconds = (raw as? Int) ?? (raw as? NSNumber)?.intValue else {
            return Self.runtimeDebounceDefault
        }
        return TimeInterval(min(max(seconds, 0), 300))
    }

    func start() {
        let nc = NSWorkspace.shared.notificationCenter
        nc.addObserver(self, selector: #selector(sentinelChanged),
                       name: NSWorkspace.didLaunchApplicationNotification, object: nil)
        nc.addObserver(self, selector: #selector(sentinelChanged),
                       name: NSWorkspace.didTerminateApplicationNotification, object: nil)
        pollTimer = Timer.scheduledTimer(withTimeInterval: Self.pollInterval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.evaluate() }
        }
        Self.log.notice("Guardian watching \(BundleConfig.sentinelBundleID, privacy: .public)")
        evaluate()
    }

    @objc private func sentinelChanged() { evaluate() }

    private func sentinelIsUp() -> Bool {
        !NSRunningApplication.runningApplications(withBundleIdentifier: BundleConfig.sentinelBundleID).isEmpty
    }

    /// Managed-only read of the master gate (config domain). A local `defaults
    /// write` can't forge it (managedValue reads the forced/managed layers only).
    /// Absent ⇒ false — the guardian is opt-in.
    ///
    /// STRICT boolean: only a real plist `<true/>` (a CFBoolean) turns it on. A
    /// bridged `as? Bool` would also accept an integer `1` (or any NSNumber), so
    /// a mistyped `<integer>1</integer>` would silently enable the gate.
    private func guardianEnabled() -> Bool {
        Self.strictManagedBool(CFPreferencesSource().managedValue(forKey: "guardianEnabled",
                                                                  domain: BundleConfig.configDomain))
    }

    /// `true` only for a CFBoolean `true`; every other type (integer, string,
    /// absent) is `false`.
    nonisolated static func strictManagedBool(_ raw: Any?) -> Bool {
        guard let raw, CFGetTypeID(raw as CFTypeRef) == CFBooleanGetTypeID() else { return false }
        return (raw as? Bool) ?? false
    }

    /// Reconciliation, driven by the poll, the workspace notifications, and start.
    private func evaluate() {
        if sentinelIsUp() {
            everSeenUp = true
            pendingDown?.cancel(); pendingDown = nil
            if showing { showing = false; presenter.dismiss() }
            return
        }
        // Sentinel is down. Never prompt for a Sentinel we've never seen up this
        // session — that's cold-login ordering, not a quit.
        guard everSeenUp else { return }
        if showing {
            // Live-hide if an admin turned the gate off while the panel was up.
            if !guardianEnabled() { showing = false; presenter.dismiss() }
            return
        }
        if pendingDown != nil { return }   // already counting down
        // Gate off ⇒ don't even arm the debounce (no prompt, no wakeup/log churn).
        // Re-checked each cycle, so flipping the gate on while down still arms.
        guard guardianEnabled() else { return }
        let debounce = runtimeDebounce()   // read once, on the main actor
        pendingDown = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(debounce))
            guard let self, !Task.isCancelled else { return }
            self.pendingDown = nil
            // Still down after the debounce? (A crash-relaunch would have cancelled
            // us via the up-notification/poll.) Gate still on?
            guard self.sentinelIsUp() == false, self.guardianEnabled() else { return }
            self.showing = true
            self.presenter.present { [weak self] in self?.relaunchSentinel() }
            Self.log.notice("Sentinel down — showing guardian panel")
        }
    }

    /// Relaunch the Sentinel off the main thread (never blocks the panel). Runs on
    /// a GCD worker (which tolerates the blocking `waitUntilExit`), NOT the
    /// cooperative pool. Result is observed by the poll/notification → the panel
    /// auto-dismisses when it's back up.
    private func relaunchSentinel() {
        Self.log.notice("relaunch requested by user")
        DispatchQueue.global(qos: .userInitiated).async { Self.runRelaunchLadder() }
    }

    /// kickstart (primary, re-uses the bootstrapped job) → bootstrap → open.
    nonisolated private static func runRelaunchLadder() {
        let uid = getuid()
        let label = "gui/\(uid)/\(BundleConfig.sentinelBundleID)"
        // kickstart is the correct restart for a quit-but-loaded job; retry a few
        // times to ride out a transient launchctl hiccup before the heavier
        // fallbacks — never drop to an unsupervised `open` over a blip.
        for attempt in 1...3 {
            if run("/bin/launchctl", ["kickstart", label]) == 0 { return }
            if attempt < 3 { usleep(500_000) }
        }
        log.warning("kickstart failed x3; trying bootstrap")
        if run("/bin/launchctl", ["bootstrap", "gui/\(uid)", BundleConfig.sentinelLaunchAgentPath]) == 0 { return }
        log.warning("bootstrap failed; last-resort open (non-launchd instance — degraded)")
        _ = run("/usr/bin/open", [BundleConfig.sentinelAgentAppPath])
    }

    @discardableResult
    nonisolated private static func run(_ path: String, _ arguments: [String]) -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus
        } catch {
            log.error("run \(path, privacy: .public) failed: \(String(describing: error), privacy: .public)")
            return -1
        }
    }
}
