import Foundation
import PrivMgrCore

// MARK: - Sentinels

public enum JITAdmin {
    /// Local group JIT elevation grants membership in.
    public static let adminGroup = "admin"
    /// Grant sentinels shared with the Agent, re-exported for daemon call sites.
    public static let grantCanonicalPath = JITAdminGrant.canonicalPath
    public static let grantProfileKey = JITAdminGrant.profileKey

    /// Whether a grant is a JIT admin grant.
    public static func isJITGrant(_ grant: Grant) -> Bool { JITAdminGrant.isJITGrant(grant) }
}

// MARK: - Injectable system boundaries

/// Reads and mutates local group membership. The real implementation shells
/// out to `dseditgroup`; tests inject a fake so the manager logic is verifiable
/// without root or touching the real admin group.
public protocol GroupMembershipControlling: Sendable {
    /// - Throws: when membership could not be DETERMINED (the directory node is
    ///   unreachable, the check timed out). Callers must never read a failure as
    ///   "not a member": the only caller uses `false` to mean "safe to promote
    ///   and schedule a demotion", which on a permanent admin would strip rights
    ///   Serberus never granted.
    func isMember(user: String, group: String) async throws -> Bool
    func groups(forUser user: String) async -> Set<String>
    func addMember(user: String, group: String) async throws
    func removeMember(user: String, group: String) async throws
}

/// A grant store that can surface JIT admin rows it cannot verify (HMAC
/// failure / undecodable). Separate from `GrantMaintaining` so in-memory fakes
/// and the `NullGrantStore` need not implement it; the manager and the
/// teardown sweep probe for it with `as?`.
public protocol UnverifiedJITRowSource: Sendable {
    /// Unquarantined, (untrusted-)unrevoked JIT rows that fail verification.
    func unverifiedJITCandidates() async throws -> [UnverifiedJITRow]
    /// Quarantines one such row after its user's demotion landed. Returns false
    /// when the store does not stamp rows it cannot verify.
    @discardableResult func retireUnverifiedRow(rowID: Int64) async throws -> Bool
}

extension GrantStore: UnverifiedJITRowSource {}

/// Runs an external command (used to delegate to Jamf Connect). Injectable so
/// the handoff path is testable without Jamf Connect installed.
public protocol CommandRunning: Sendable {
    /// Runs `path` with `arguments`, returning the exit code.
    func run(path: String, arguments: [String]) async throws -> Int32
}

/// Removes what a deleted JIT account leaves behind in the local `admin`
/// group: its short name in `GroupMembership` and its GeneratedUID in
/// `GroupMembers`. Deleting an account does not touch groups, and macOS also
/// resolves local membership by name, so an account created later with the
/// same short name would otherwise be an admin from the start.
public protocol StaleAdminEntryScrubbing: Sendable {
    /// Removes `name` and `generatedUID` from `admin`. Returns one line per
    /// attempt, for the log.
    func scrub(name: String, generatedUID: String?) async -> [String]
}

/// Removes nothing. The default outside the production daemon, so tests never
/// touch the real `admin` group.
public struct NoopStaleAdminEntryScrubber: StaleAdminEntryScrubbing {
    public init() {}
    public func scrub(name: String, generatedUID: String?) async -> [String] { [] }
}

/// Production ``StaleAdminEntryScrubbing``: `/usr/bin/dscl . -delete
/// /Groups/admin <attribute> <value>` against the local node, through a
/// bounded runner (``ProcessCommandRunner``'s timeout).
public struct DSCLStaleAdminEntryScrubber: StaleAdminEntryScrubbing {
    public static let dsclPath = "/usr/bin/dscl"
    private let runner: CommandRunning

    public init(runner: CommandRunning = ProcessCommandRunner()) {
        self.runner = runner
    }

    /// The `dscl` argument vectors for `name` and `generatedUID`; a value that
    /// is not safe as one (empty, a control character, a leading `-`, a
    /// GeneratedUID that is not a UUID) is left out.
    static func commands(name: String, generatedUID: String?) -> [[String]] {
        var commands: [[String]] = []
        if !name.isEmpty, !name.hasPrefix("-"),
           !name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) {
            commands.append([".", "-delete", "/Groups/\(JITAdmin.adminGroup)", "GroupMembership", name])
        }
        if let generatedUID, let uuid = UUID(uuidString: generatedUID) {
            commands.append([".", "-delete", "/Groups/\(JITAdmin.adminGroup)", "GroupMembers", uuid.uuidString])
        }
        return commands
    }

    public func scrub(name: String, generatedUID: String?) async -> [String] {
        var lines: [String] = []
        for arguments in Self.commands(name: name, generatedUID: generatedUID) {
            let what = "\(arguments[3]) \(arguments[4])"
            do {
                let status = try await runner.run(path: Self.dsclPath, arguments: arguments)
                // A value that is not there is reported as an error by dscl;
                // either way it is not in the group afterwards.
                lines.append(status == 0
                    ? "removed \(what) from \(JITAdmin.adminGroup)"
                    : "\(what) not removed from \(JITAdmin.adminGroup) (dscl exit \(status); usually: it was not there)")
            } catch {
                lines.append("\(what) not removed from \(JITAdmin.adminGroup): \(error)")
            }
        }
        return lines
    }
}

// MARK: - Manager

/// Owns the just-in-time local-admin lifecycle.
///
/// Serberus-native flow: verify eligibility + justification against the live
/// ``JITAdminPolicy``, confirm the user is not *already* a permanent admin
/// (never demote someone Serberus did not promote), add them to the admin
/// group, persist a timed grant, schedule auto-demotion, and audit both ends.
/// Jamf Connect flow: run the MDM-configured Jamf Connect command and let it
/// own scope, duration, and audit.
///
/// Every promote/demote is written to the signed decision log. On daemon
/// restart, ``reconcile()`` re-arms timers for still-valid grants and demotes
/// any that expired while the daemon was down. A window lasts only while the
/// JIT provider stays `serberus`: under any other provider the reload tick
/// (``expireOverdue()``) and ``reconcile()`` demote it. Expiry is decided by
/// ``Grant/hasExpired(at:monotonic:)``: the wall clock, the issue time, and —
/// within the boot session a grant was issued in — the continuous clock, so
/// setting the date back cannot stretch a window.
public actor JITAdminManager {
    public typealias PolicyProvider = @Sendable () async -> JITAdminPolicy

    private let policyProvider: PolicyProvider
    private let membership: GroupMembershipControlling
    private let grantStore: GrantMaintaining
    private let decisionLogger: DecisionLogger?
    private let integrityLogger: IntegrityLogger?
    private let deviceSerial: String
    private let version: DaemonVersion
    private let now: @Sendable () -> Date
    /// The continuous clock expiry is also checked against. Injectable for tests.
    private let monotonicNow: @Sendable () -> MonotonicInstant?
    /// True when the daemon is running on a stand-in grant store (the real
    /// SQLite store could not be opened — `degraded(grants_db_error)`). JIT is
    /// then refused outright: a promotion whose grant row cannot be persisted
    /// is invisible to every demotion path and becomes a PERMANENT admin.
    private let grantStoreDegraded: Bool
    /// Decides whether an account `dseditgroup` can no longer find was deleted,
    /// renamed, or is merely unreachable. Injectable for tests.
    private let accountResolver: JITAccountResolving
    /// Whether a promotion may still go ahead (false once the kill switch is
    /// on). Asked again after the request's last await, because the kill switch
    /// can arrive while the request waits on the directory.
    private let promotionPermitted: @Sendable () async -> Bool
    /// Deletes the demoted user's sudo ticket, so a ticket obtained while they
    /// were an admin does not outlive the window. Injectable for tests.
    private let ticketClearer: SudoTicketClearing
    /// The account's GeneratedUID by uid, recorded on the grant at promotion so
    /// a reused uid is never mistaken for a rename. Injectable for tests.
    private let generatedUIDLookup: @Sendable (uid_t) -> String?
    /// Removes a deleted account's name and GeneratedUID from `admin` when its
    /// row is retired. Injectable for tests.
    private let adminGroupScrubber: StaleAdminEntryScrubbing

    /// Live auto-demotion timers, keyed by grant ID.
    private var demotionTasks: [UUID: Task<Void, Never>] = [:]
    /// Users with a self-service request between the active-grant read and the
    /// grant insert. A second concurrent request for the same user would
    /// otherwise pass the "no active grant" check too (actor reentrancy at every
    /// `await`) and stack a second grant + promotion.
    private var requestsInFlight: Set<String> = []
    /// Grants whose demotion is running right now, so the expiry timer, the
    /// reload-tick sweep and a kill switch never demote the same grant twice
    /// concurrently (reentrancy at the membership awaits).
    private var demotionsInProgress: Set<UUID> = []
    /// Callers waiting for a demotion in ``demotionsInProgress`` to finish.
    private var demotionWaiters: [UUID: [CheckedContinuation<Void, Never>]] = [:]
    /// Unverifiable JIT rows whose user this process already demoted (or found
    /// not in `admin`) but which the store could not stamp, because it was
    /// opened without the key and never writes. Skipped by later sweeps so the
    /// user is not demoted again every tick (an admin may have re-added them
    /// on purpose); a restart handles each row once more.
    private var settledUnverifiedRows: Set<Int64> = []

    /// How long to wait before re-attempting a demotion whose group removal
    /// failed. Retries are deliberately unbounded: giving up would leave a user
    /// holding admin that Serberus granted, so the daemon keeps trying (and keeps
    /// logging) until the removal lands or the grant is revoked out from under it.
    /// Short enough to self-heal quickly once a directory node comes back, long
    /// enough not to churn.
    static let demotionRetrySeconds: TimeInterval = 60

    public init(
        policyProvider: @escaping PolicyProvider,
        membership: GroupMembershipControlling,
        grantStore: GrantMaintaining,
        decisionLogger: DecisionLogger?,
        integrityLogger: IntegrityLogger?,
        deviceSerial: String = "UNKNOWN",
        version: DaemonVersion = .current,
        grantStoreDegraded: Bool = false,
        now: @escaping @Sendable () -> Date = { Date() },
        monotonicNow: @escaping @Sendable () -> MonotonicInstant? = { MonotonicClock.now() },
        accountResolver: JITAccountResolving = DirectoryJITAccountResolver(),
        promotionPermitted: @escaping @Sendable () async -> Bool = { true },
        ticketClearer: SudoTicketClearing = NoopSudoTicketClearer(),
        generatedUIDLookup: @escaping @Sendable (uid_t) -> String? = { LocalAccounts.generatedUID(uid: $0) },
        adminGroupScrubber: StaleAdminEntryScrubbing = NoopStaleAdminEntryScrubber()
    ) {
        self.adminGroupScrubber = adminGroupScrubber
        self.ticketClearer = ticketClearer
        self.generatedUIDLookup = generatedUIDLookup
        self.grantStoreDegraded = grantStoreDegraded
        self.accountResolver = accountResolver
        self.promotionPermitted = promotionPermitted
        self.monotonicNow = monotonicNow
        self.policyProvider = policyProvider
        self.membership = membership
        self.grantStore = grantStore
        self.decisionLogger = decisionLogger
        self.integrityLogger = integrityLogger
        self.deviceSerial = deviceSerial
        self.version = version
        self.now = now
    }

    // MARK: Request

    /// Handles a user's self-service admin request.
    public func requestElevation(user: String, uid: uid_t, justification: String) async -> JITAdminResult {
        let policy = await policyProvider()

        switch policy.provider {
        case .disabled:
            return deny(user: user, uid: uid, reason: "Just-in-time admin is not enabled by policy.")

        case .jamfConnect:
            // Jamf Connect elevation runs in the user's GUI session (its own
            // reason prompt), so the *Agent* launches it — never the root daemon.
            // Reaching here means a caller misrouted a JC request.
            return deny(user: user, uid: uid,
                        reason: "Jamf Connect elevation is launched by the Serberus menu bar app, not the daemon.")

        case .serberus:
            guard policy.justificationSatisfied(justification) else {
                return deny(user: user, uid: uid,
                            reason: "A justification of at least \(policy.justificationMinLength) characters is required.")
            }
            // Claimed synchronously (no await between check and insert), so a
            // concurrent request for the same user is refused rather than racing
            // the active-grant check below.
            guard requestsInFlight.insert(user).inserted else {
                return deny(user: user, uid: uid, reason: "An admin request for you is already in progress.")
            }
            defer { requestsInFlight.remove(user) }
            let userGroups = await membership.groups(forUser: user)
            guard policy.isEligible(user: user, groups: userGroups) else {
                return deny(user: user, uid: uid, reason: "You are not eligible for admin elevation.")
            }
            return await grantSerberus(policy: policy, user: user, uid: uid, justification: justification)
        }
    }

    private func grantSerberus(policy: JITAdminPolicy, user: String, uid: uid_t,
                               justification: String) async -> JITAdminResult {
        // A degraded grant store (NullGrantStore / grants_db_error) cannot hold
        // the row every demotion path enumerates, so JIT is refused outright.
        guard !grantStoreDegraded else {
            return deny(user: user, uid: uid,
                        reason: "Just-in-time admin is unavailable: the grant database is degraded.")
        }

        // Idempotency: an existing active JIT grant stands; do not stack. The
        // read must SUCCEED — a store that cannot be read is not "no grants",
        // and promoting on top of an unreadable store is exactly how a
        // Serberus-created admin escapes every recovery path.
        let existing: Grant?
        do {
            existing = try await grantStore.activeGrants(for: user, now: now()).first(where: JITAdmin.isJITGrant)
        } catch {
            await emitIntegrity("JIT admin refused for \(user): grant store unreadable (\(error))")
            return deny(user: user, uid: uid,
                        reason: "Just-in-time admin is unavailable: the grant database could not be read.")
        }
        if let existing {
            return JITAdminResult(outcome: .alreadyActive,
                                  message: "You already have active admin access.",
                                  grantID: existing.grantID, expiresAt: existing.expiresAt)
        }

        // Never demote a permanent admin: if the user is already in the group,
        // do not create a grant (which would schedule a demotion that strips a
        // membership Serberus did not add).
        do {
            if try await membership.isMember(user: user, group: JITAdmin.adminGroup) {
                return JITAdminResult(outcome: .alreadyAdmin,
                                      message: "You are already an administrator.")
            }
        } catch {
            // Membership is UNKNOWN, not "absent" — e.g. the directory node is
            // unreachable and the check timed out. Fail CLOSED: granting here
            // would schedule a demotion against a user who may be a permanent
            // admin, stripping rights Serberus never granted. Refusing costs
            // only a retry once the directory answers again.
            return deny(user: user, uid: uid,
                        reason: "Could not verify your current admin status. Try again in a moment.")
        }

        let issuedAt = now()
        let expiresAt = issuedAt.addingTimeInterval(TimeInterval(policy.effectiveDurationSeconds))
        let grant = Grant(
            user: user, uid: uid,
            ruleID: "jit-self-service",
            profileKey: JITAdmin.grantProfileKey,
            teamID: "", binaryHash: "",
            canonicalPath: JITAdmin.grantCanonicalPath,
            grantedAt: issuedAt, expiresAt: expiresAt,
            policyVersion: "jit",
            // Signed with the row: tells a later rename (same GeneratedUID)
            // apart from a uid reused by a new account (different one).
            generatedUID: generatedUIDLookup(uid)
        )

        // Persist the grant BEFORE touching the admin group. The row is what
        // `expire()`, `reconcile()`, `demoteAll()` and `serberusd --demote-jit`
        // enumerate; a promotion without it can never be undone by Serberus.
        // No row ⇒ no promotion.
        do {
            try await grantStore.insert(grant)
        } catch {
            await emitIntegrity("JIT admin refused for \(user): grant could not be persisted (\(error))")
            return deny(user: user, uid: uid,
                        reason: "Could not record the admin grant, so none was issued. Try again later.")
        }

        // The kill switch may have arrived during any await above; its
        // demote-all then found no row for this request. Ask again right
        // before promoting, and retire the row unpromoted if it did.
        guard await promotionPermitted() else {
            _ = try? await grantStore.revoke(grantID: grant.grantID, now: now())
            await emitIntegrity("JIT admin refused for \(user): Serberus was turned off while the request was in progress")
            return deny(user: user, uid: uid, reason: Self.killSwitchMessage)
        }

        do {
            try await membership.addMember(user: user, group: JITAdmin.adminGroup)
        } catch {
            await rollBackFailedPromotion(grant: grant, error: error)
            return deny(user: user, uid: uid, reason: "Could not grant admin access: \(error.localizedDescription)")
        }

        // A kill switch that landed during `addMember` demoted whatever it
        // found before the promotion finished; undo this one now. The same
        // holds for any demotion of this grant that ran while the add was in
        // flight (the user ended it, an admin revoked it): it may have checked
        // membership before the add landed and retired the row unremoved.
        guard await promotionPermitted() else {
            await undoRacedPromotion(grant: grant, reason: "Serberus was turned off while the promotion was in progress")
            return deny(user: user, uid: uid, reason: Self.killSwitchMessage)
        }
        var endedMeanwhile = demotionsInProgress.contains(grant.grantID)
        if !endedMeanwhile { endedMeanwhile = await rowIsRevoked(grant.grantID) }
        if endedMeanwhile {
            await undoRacedPromotion(grant: grant, reason: "the grant was ended while the promotion was in progress")
            return deny(user: user, uid: uid, reason: "Your admin request was ended while it was being granted.")
        }

        await logDecision(.granted, user: user, uid: uid, grantID: grant.grantID,
                          justification: justification, durationSeconds: policy.effectiveDurationSeconds)
        scheduleDemotion(grantID: grant.grantID, user: user,
                         after: TimeInterval(policy.effectiveDurationSeconds))

        return JITAdminResult(outcome: .granted,
                              message: "Admin access granted until \(Self.timeString(expiresAt)).",
                              grantID: grant.grantID, expiresAt: expiresAt)
    }

    /// Whether the store holds `grantID` as revoked. false when it cannot be
    /// read (the ordinary paths then keep watching the unrevoked row).
    private func rowIsRevoked(_ grantID: UUID) async -> Bool {
        guard let all = try? await grantStore.allGrants() else { return false }
        return all.first { $0.grantID == grantID }?.revokedAt != nil
    }

    /// Undoes a promotion whose add landed after a demotion of the same grant
    /// had already started (kill switch, ended early, revoked).
    ///
    /// That demotion may have checked membership before the add landed, found
    /// the user not in `admin`, and retired the row: the user would then be an
    /// admin with a revoked row, which no recovery path looks at. So: wait for
    /// a demotion still in progress, then demote the row if it is still live,
    /// or, if it was retired, make sure the user is not in `admin` after all
    /// (``removeStrandedMembership(of:reason:)``).
    private func undoRacedPromotion(grant: Grant, reason: String) async {
        await waitForDemotion(of: grant.grantID)
        let current: Grant?
        do {
            current = try await grantStore.allGrants().first { $0.grantID == grant.grantID }
        } catch {
            current = nil
        }
        if current == nil || current?.revokedAt == nil {
            // Still live (or unreadable): the ordinary demotion, which keeps the
            // row active until the removal is confirmed.
            if await demote(grant: current ?? grant, reason: reason) { return }
            await waitForDemotion(of: grant.grantID)
            if !(await rowIsRevoked(grant.grantID)) { return } // a retry is scheduled
        }
        await removeStrandedMembership(of: grant, reason: reason)
    }

    /// Suspends until no demotion of `grantID` is in progress.
    private func waitForDemotion(of grantID: UUID) async {
        while demotionsInProgress.contains(grantID) {
            await withCheckedContinuation { demotionWaiters[grantID, default: []].append($0) }
        }
    }

    private func finishDemotion(of grantID: UUID) {
        demotionsInProgress.remove(grantID)
        for waiter in demotionWaiters.removeValue(forKey: grantID) ?? [] { waiter.resume() }
    }

    /// For a user whose JIT row is already retired: when they are in `admin`
    /// anyway (a promotion that landed after the demotion checked), records a
    /// replacement JIT row that is already over and demotes it. The row makes
    /// the removal durable: until it lands, every recovery path (the reload
    /// tick, `reconcile()` after a restart, `--demote-jit`) sees an unrevoked
    /// JIT row and retries. An unknown membership is treated as "in admin";
    /// a user record that no longer exists is not (nothing of ours landed).
    private func removeStrandedMembership(of grant: Grant, reason: String) async {
        let stillMember: Bool
        do {
            stillMember = try await membership.isMember(user: grant.user, group: JITAdmin.adminGroup)
        } catch JITAdminError.userRecordNotFound {
            stillMember = false
        } catch {
            stillMember = true
        }
        guard stillMember else { return }
        await emitIntegrity("JIT admin \(grant.user) is in \(JITAdmin.adminGroup) although grant \(grant.grantID.uuidString) "
                            + "was retired (the promotion landed after the demotion checked membership; \(reason)); "
                            + "demoting again")
        let issued = now()
        let replacement = Grant(
            user: grant.user, uid: grant.uid, ruleID: grant.ruleID, profileKey: JITAdmin.grantProfileKey,
            teamID: "", binaryHash: "", canonicalPath: JITAdmin.grantCanonicalPath,
            grantedAt: issued, expiresAt: issued, policyVersion: grant.policyVersion,
            generatedUID: grant.generatedUID)
        do {
            try await grantStore.insert(replacement)
        } catch {
            // No durable row: remove directly and say so loudly.
            await emitIntegrity("JIT admin \(grant.user): replacement grant row could not be recorded (\(error)); "
                                + "removing from \(JITAdmin.adminGroup) directly")
            do {
                try await membership.removeMember(user: grant.user, group: JITAdmin.adminGroup)
            } catch {
                await emitIntegrity("JIT admin demotion FAILED for \(grant.user) with no grant row to retry from "
                                    + "(\(error)); check the \(JITAdmin.adminGroup) group by hand")
            }
            return
        }
        _ = await demote(grant: replacement, reason: reason)
    }

    /// Undoes a promotion whose `addMember` threw. The add may still have
    /// LANDED (a timed-out `dseditgroup` is killed mid-mutation), so the grant
    /// row is only retired once the user is confirmed NOT in `admin`; otherwise
    /// the ordinary demotion path runs, which keeps the row ACTIVE (and retries)
    /// until the removal is confirmed.
    private func rollBackFailedPromotion(grant: Grant, error: Error) async {
        let stillMember: Bool
        do {
            stillMember = try await membership.isMember(user: grant.user, group: JITAdmin.adminGroup)
        } catch {
            stillMember = true // unknown ⇒ assume the add landed; demote() retries safely
        }
        if stillMember {
            _ = await demote(grant: grant, reason: "rollback of failed promotion (\(error))")
            return
        }
        do {
            _ = try await grantStore.revoke(grantID: grant.grantID, now: now())
        } catch {
            // Harmless leftover: the user is not an admin, and a later demotion
            // of a non-member simply retires the row.
            await emitIntegrity("JIT rollback for \(grant.user): could not retire grant row (\(error))")
        }
    }

    // MARK: End / revoke

    /// Ends the current user's JIT admin window early (user-initiated).
    @discardableResult
    public func endElevation(user: String) async -> Bool {
        guard let grant = await activeJITGrant(for: user) else { return false }
        return await demote(grant: grant, reason: "ended early by user")
    }

    /// Revokes a JIT grant by ID (admin-console / expiry path). Demotes the
    /// user from the admin group. No-op for a non-JIT grant ID.
    @discardableResult
    public func revoke(grantID: UUID) async -> Bool {
        guard let all = await readAllGrants(context: "revoke") else { return false }
        guard let grant = all.first(where: { $0.grantID == grantID && JITAdmin.isJITGrant($0) }) else {
            return false
        }
        return await demote(grant: grant, reason: "revoked")
    }

    /// Demotes every active JIT admin (kill switch / revoke-all, or the first
    /// start after an upgrade). Returns the number demoted.
    @discardableResult
    public func demoteAll(reason: String = "kill switch / revoke-all") async -> Int {
        var count = await demoteUnverifiedJITRows(reason: reason)
        guard let all = await readAllGrants(context: "demote-all (\(reason))") else { return count }
        for grant in all where JITAdmin.isJITGrant(grant) && grant.revokedAt == nil {
            if await demote(grant: grant, reason: reason) { count += 1 }
        }
        return count
    }

    /// Re-arms timers and cleans up after a daemon restart: any JIT grant that
    /// expired while the daemon was down is demoted now; still-valid grants get
    /// a fresh demotion timer, unless the JIT provider is no longer `serberus`,
    /// in which case they are demoted now too (``providerEndReason(context:)``).
    ///
    /// The timer is re-armed for what is left of the window by BOTH clocks
    /// (``Grant/remainingSeconds(at:monotonic:)``): within the boot session the
    /// grant was issued in, the continuous clock bounds it however far the wall
    /// clock was set back; after a reboot, the wall clock and the issue-time
    /// check are all there is.
    public func reconcile() async {
        await demoteUnverifiedJITRows(reason: "unverifiable JIT grant found at startup")
        guard let all = await readAllGrants(context: "reconcile") else { return }
        let current = now()
        let monotonic = monotonicNow()
        let providerEnded = await providerEndReason(context: "startup")
        for grant in all where JITAdmin.isJITGrant(grant) && grant.revokedAt == nil {
            guard let remaining = grant.remainingSeconds(at: current, monotonic: monotonic) else { continue }
            if remaining <= 0 {
                _ = await demote(grant: grant, reason: "expired while daemon was down")
            } else if let providerEnded {
                _ = await demote(grant: grant, reason: providerEnded)
            } else {
                scheduleDemotion(grantID: grant.grantID, user: grant.user, after: remaining)
            }
        }
    }

    /// Expiry backstop, run on every policy-reload tick (and on wake): demotes
    /// every unrevoked JIT grant whose window is over by
    /// ``Grant/hasExpired(at:monotonic:)`` — past `expiresAt`, past its
    /// continuous-clock deadline, or with the clock set back before it was
    /// issued — plus any unverifiable JIT row. A clock change, a dropped timer,
    /// or a demotion whose retry is pending must never extend a window past its
    /// expiry by more than one tick. Returns the number demoted.
    ///
    /// While the JIT provider is not `serberus`, every open window is demoted
    /// too (``providerEndReason(context:)``): the tick runs right after the
    /// reload pass, so a policy that turns Serberus JIT off ends its windows
    /// within one tick, and a demotion that fails is tried again on the next.
    ///
    /// On a degraded store (``grantStoreDegraded``) only the unverifiable-row
    /// sweep runs: nothing else can be read, and reporting that every tick
    /// would only repeat what startup already reported.
    @discardableResult
    public func expireOverdue() async -> Int {
        var count = await demoteUnverifiedJITRows(reason: "unverifiable JIT grant found on reload tick")
        guard !grantStoreDegraded else { return count }
        guard let all = await readAllGrants(context: "overdue-expiry tick") else { return count }
        let current = now()
        let monotonic = monotonicNow()
        let providerEnded = await providerEndReason(context: "reload tick")
        for grant in all where JITAdmin.isJITGrant(grant) && grant.revokedAt == nil {
            let reason: String
            if grant.hasExpired(at: current, monotonic: monotonic) {
                reason = "window expired (reload tick)"
            } else if let providerEnded {
                reason = providerEnded
            } else {
                continue
            }
            if await demote(grant: grant, reason: reason) { count += 1 }
        }
        return count
    }

    /// Why open Serberus JIT windows end, when the live policy's provider is
    /// not `serberus` (`disabled`, which is also what a missing JIT profile
    /// reads as, or `jamf_connect`); nil while it is. A window is only ever
    /// issued under `serberus`, so under any other provider it is one the
    /// policy no longer allows. Observed Jamf Connect windows are not grant
    /// rows and are never touched here.
    private func providerEndReason(context: String) async -> String? {
        let provider = await policyProvider().provider
        guard provider != .serberus else { return nil }
        return "JIT provider is now \(provider.rawValue), not serberus (\(context))"
    }

    /// Cancels all pending demotion timers (daemon shutdown). Does not demote —
    /// membership persists across restart and `reconcile()` re-arms it.
    public func stop() {
        for task in demotionTasks.values { task.cancel() }
        demotionTasks.removeAll()
    }

    // MARK: Internals

    private func activeJITGrant(for user: String) async -> Grant? {
        let grants = (try? await grantStore.activeGrants(for: user, now: now())) ?? []
        return grants.first(where: JITAdmin.isJITGrant)
    }

    /// Every grant row, or nil (after an integrity event) when the store cannot
    /// be read. Callers must treat nil as UNKNOWN, never as "no JIT admins".
    private func readAllGrants(context: String) async -> [Grant]? {
        do {
            return try await grantStore.allGrants()
        } catch {
            await emitIntegrity("JIT \(context): grant store unreadable (\(error)); JIT admins NOT enumerated")
            return nil
        }
    }

    private func demote(grant: Grant, reason: String) async -> Bool {
        demotionTasks[grant.grantID]?.cancel()
        demotionTasks[grant.grantID] = nil
        // Another path (timer / tick / kill switch) is already demoting this
        // grant; it owns the outcome and any retry.
        guard demotionsInProgress.insert(grant.grantID).inserted else { return false }
        defer { finishDemotion(of: grant.grantID) }

        // Membership FIRST: a user who already left `admin` (removed by hand, or
        // an earlier removal that landed but whose row write failed) is a
        // SUCCESS — `dseditgroup -d` on a non-member fails, and treating that as
        // a failed demotion would retry forever and never retire the row.
        // Unknown membership (directory unreachable) falls through to the
        // removal attempt; its failure keeps the grant active for retry.
        //
        // A user record `dseditgroup` cannot find is resolved by the row's uid:
        // a renamed account is demoted under its new name; only an account
        // confirmed gone retires the row unremoved; anything undecided keeps
        // the grant active and retries.
        var member = grant.user
        let stillMember: Bool
        var accountGone = false
        // Whether the row's uid still stands for the account Serberus promoted
        // (false once another account has it).
        var uidIsTheAccount = true
        do {
            stillMember = try await membership.isMember(user: grant.user, group: JITAdmin.adminGroup)
        } catch JITAdminError.userRecordNotFound {
            switch await accountResolver.identify(user: grant.user, uid: grant.uid, generatedUID: grant.generatedUID) {
            case .gone:
                stillMember = false
                accountGone = true
            case let .uidReused(by: newAccount):
                // The uid now belongs to a DIFFERENT account (its GeneratedUID
                // differs from the one recorded at promotion). That account was
                // never promoted by Serberus and must not be demoted; the one
                // Serberus promoted is gone.
                stillMember = false
                accountGone = true
                uidIsTheAccount = false
                await emitIntegrity(
                    "JIT admin account \(grant.user) (uid \(grant.uid)) is gone and its uid now belongs to a "
                    + "different account, \(newAccount) (GeneratedUID differs); \(newAccount) is NOT demoted (\(reason))")
            case let .renamed(newName):
                member = newName
                await emitIntegrity(
                    "JIT admin account RENAMED: \(grant.user) (uid \(grant.uid)) is now \(newName); "
                    + "demoting \(newName) (\(reason))")
                stillMember = (try? await membership.isMember(user: newName, group: JITAdmin.adminGroup)) ?? true
            case .present:
                stillMember = true
            case let .undetermined(why):
                await emitIntegrity(
                    "JIT admin demotion of \(grant.user) (\(reason)): user record not found and the account "
                    + "could not be confirmed deleted (\(why)); grant kept ACTIVE and retried")
                scheduleDemotion(grantID: grant.grantID, user: grant.user, after: Self.demotionRetrySeconds)
                return false
            }
        } catch {
            stillMember = true
        }

        // Remove from the admin group. A JIT grant exists only for users
        // Serberus itself promoted, so demotion never strips a permanent admin.
        if stillMember {
            do {
                try await membership.removeMember(user: member, group: JITAdmin.adminGroup)
            } catch {
                // The removal did NOT land, and a timed-out `dseditgroup` is killed
                // mid-mutation — so the user may well still be in `admin`.
                //
                // Do NOT stamp `revokedAt` here. Every recovery path (``demoteAll``,
                // ``reconcile``, ``expire``, ``expireOverdue``) filters on
                // `revokedAt == nil`, so a grant marked revoked while its membership
                // survives is invisible to all of them, FOREVER: a permanent admin
                // that Serberus created and then lost track of, while the decision
                // log claims a clean demotion. Leaving the grant ACTIVE keeps it
                // retryable — by the timer below, by the reload tick, and by
                // `reconcile()` on the next daemon start.
                await emitIntegrity(
                    "JIT admin demotion FAILED for \(member) (\(reason)): \(error) — "
                    + "grant left ACTIVE and will be retried; user may still hold admin")
                scheduleDemotion(grantID: grant.grantID, user: grant.user, after: Self.demotionRetrySeconds)
                return false
            }
        }
        _ = try? await grantStore.revoke(grantID: grant.grantID, now: now())
        if !stillMember && !accountGone && member == grant.user {
            // "Not a member" was read before the row was retired. A promotion of
            // this grant still in flight can land in between; look again, now
            // that the row is retired, and demote what landed.
            await removeStrandedMembership(of: grant, reason: reason)
        }
        // The window is over: a sudo ticket from inside it must not let the
        // user skip the gate. sudo 1.9.15+ names the ticket after the uid, which
        // the row records (and which survives a rename); older sudo used the
        // name, so the account's current name and the row's are cleared too.
        // A uid now held by a different account is left alone.
        if uidIsTheAccount {
            ticketClearer.clearTicket(uid: grant.uid, user: member)
            if member != grant.user { ticketClearer.clearTicket(uid: grant.uid, user: grant.user) }
        } else {
            ticketClearer.clearTicket(user: grant.user)
        }
        await logDecision(.denied, user: member, uid: grant.uid, grantID: grant.grantID,
                          justification: nil, durationSeconds: 0, eventType: "jit_admin_demotion")
        if accountGone {
            await emitIntegrity("JIT admin grant for \(grant.user) retired (\(reason)); the account (uid \(grant.uid)) "
                                + "no longer exists by name, by uid, or in the local directory node")
            for line in await adminGroupScrubber.scrub(name: grant.user, generatedUID: grant.generatedUID) {
                await emitIntegrity("JIT admin account \(grant.user) is gone: \(line)")
            }
        } else {
            await emitIntegrity(stillMember
                ? "JIT admin demoted \(member) (\(reason))"
                : "JIT admin grant for \(member) retired (\(reason)); user was already not in \(JITAdmin.adminGroup)")
        }
        return true
    }

    /// Demotes every user named by an UNVERIFIABLE JIT row (HMAC failure or
    /// undecodable — see ``GrantStore/unverifiedJITCandidates()``), then
    /// quarantines those rows. Conservative by owner decision: a JIT row the
    /// store cannot vouch for may stand for a real promotion, and quarantining
    /// it without demoting would strand that admin forever. A row whose user
    /// cannot be read is reported loudly and left for a human. Returns the
    /// number of users demoted.
    @discardableResult
    private func demoteUnverifiedJITRows(reason: String) async -> Int {
        guard let source = grantStore as? UnverifiedJITRowSource else { return 0 }
        let candidates: [UnverifiedJITRow]
        do {
            candidates = try await source.unverifiedJITCandidates()
        } catch {
            await emitIntegrity("JIT \(reason): unverifiable-row scan failed (\(error))")
            return 0
        }
        let pending = candidates.filter { !settledUnverifiedRows.contains($0.rowID) }
        guard !pending.isEmpty else { return 0 }
        var demoted = 0
        let byUser = Dictionary(grouping: pending) { $0.user ?? "" }
        for user in byUser.keys.sorted() {
            let rows = byUser[user] ?? []
            guard !user.isEmpty else {
                await emitIntegrity("JIT \(reason): \(rows.count) unverifiable JIT row(s) name no readable user — "
                                    + "check the admin group by hand")
                continue
            }
            let isMember: Bool
            do {
                isMember = try await membership.isMember(user: user, group: JITAdmin.adminGroup)
            } catch JITAdminError.userRecordNotFound {
                // The row's uid is untrusted, so only a name-based absence the
                // local node confirms retires it; otherwise it is retried.
                if await accountResolver.identify(user: user, uid: nil) == .gone {
                    isMember = false
                } else {
                    await emitIntegrity("JIT \(reason): \(user)'s record was not found and the account could not "
                                        + "be confirmed deleted; unverifiable row(s) left in place and retried next tick")
                    continue
                }
            } catch {
                isMember = true // unknown ⇒ attempt the removal (fail toward demotion)
            }
            if isMember {
                do {
                    try await membership.removeMember(user: user, group: JITAdmin.adminGroup)
                } catch {
                    await emitIntegrity("JIT \(reason): demotion of \(user) FAILED (\(error)); "
                                        + "unverifiable row(s) left in place and retried next tick")
                    continue
                }
                demoted += 1
                await logDecision(.denied, user: user, uid: getpwnam(user)?.pointee.pw_uid ?? uid_t.max, grantID: nil,
                                  justification: nil, durationSeconds: 0, eventType: "jit_admin_demotion")
            }
            ticketClearer.clearTicket(user: user)
            for row in rows {
                // A store that never writes (opened without the key) answers
                // false: remember the row here instead, so the next tick does
                // not demote this user again.
                if (try? await source.retireUnverifiedRow(rowID: row.rowID)) == false {
                    settledUnverifiedRows.insert(row.rowID)
                }
            }
            await emitIntegrity("JIT \(reason): \(isMember ? "demoted" : "retired (already not admin)") \(user) "
                                + "for \(rows.count) unverifiable JIT row(s) (\(rows.map(\.reason).joined(separator: ", ")))")
        }
        return demoted
    }

    /// Arms the demotion timer `seconds` from now, on the continuous clock.
    private func scheduleDemotion(grantID: UUID, user: String, after seconds: TimeInterval) {
        demotionTasks[grantID]?.cancel()
        let interval = max(0, seconds)
        demotionTasks[grantID] = Task { [weak self] in
            if interval > 0 {
                // CONTINUOUS clock: keeps counting while the Mac sleeps. The
                // uptime clock behind `Task.sleep(nanoseconds:)` pauses in sleep,
                // which silently extended every window by the time slept.
                try? await Task.sleep(until: ContinuousClock.now.advanced(by: .seconds(interval)),
                                      clock: .continuous)
            }
            guard !Task.isCancelled, let self else { return }
            await self.expire(grantID: grantID)
        }
    }

    private func expire(grantID: UUID) async {
        await demoteUnverifiedJITRows(reason: "unverifiable JIT grant found at expiry")
        guard let all = await readAllGrants(context: "expiry") else {
            // A transient read failure must not drop the timer: that would
            // leave the user in `admin` until the next daemon restart. Retry.
            demotionTasks[grantID] = nil
            scheduleRetry(grantID: grantID)
            return
        }
        guard let grant = all.first(where: { $0.grantID == grantID && JITAdmin.isJITGrant($0) }),
              grant.revokedAt == nil else {
            demotionTasks[grantID] = nil
            return
        }
        _ = await demote(grant: grant, reason: "window expired")
    }

    /// Re-arms an expiry check for `grantID` after ``demotionRetrySeconds``.
    private func scheduleRetry(grantID: UUID) {
        let retry = Self.demotionRetrySeconds
        demotionTasks[grantID] = Task { [weak self] in
            try? await Task.sleep(until: ContinuousClock.now.advanced(by: .seconds(retry)), clock: .continuous)
            guard !Task.isCancelled, let self else { return }
            await self.expire(grantID: grantID)
        }
    }

    static let killSwitchMessage = "Just-in-time admin is unavailable while Serberus is turned off on this Mac."

    private func deny(user: String, uid: uid_t, reason: String) -> JITAdminResult {
        Task { await logDecision(.denied, user: user, uid: uid, grantID: nil,
                                 justification: nil, durationSeconds: 0) }
        return JITAdminResult(outcome: .denied, message: reason)
    }

    // MARK: Audit

    private func logDecision(_ outcome: DecisionEvent.Outcome, user: String, uid: uid_t,
                             grantID: UUID?, justification: String?, durationSeconds: Int,
                             eventType: String = "jit_admin_elevation") async {
        guard let decisionLogger else { return }
        let event = DecisionEvent(
            timestamp: now(), eventType: eventType, outcome: outcome,
            enforcementMode: .enforce, authURI: nil, sudoCommand: nil, arguments: nil,
            processPath: JITAdmin.grantCanonicalPath, processTeamID: "", processHash: "",
            userName: user, userUID: Int(uid),
            ruleID: "jit-self-service", profileKey: JITAdmin.grantProfileKey,
            grantID: grantID, justification: justification,
            grantDurationSeconds: durationSeconds, cacheHit: false,
            deviceSerial: deviceSerial, daemonVersion: version.daemonVersion,
            pamModuleVersion: version.pamModuleVersion, policyVersion: "jit"
        )
        try? await decisionLogger.log(event)
    }

    private func emitIntegrity(_ detail: String) async {
        guard let integrityLogger else { return }
        let event = IntegrityEvent(timestamp: now(), kind: .grantRevocation, detail: detail,
                                   daemonVersion: version.daemonVersion)
        try? await integrityLogger.log(event)
    }

    private static func timeString(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm"
        return formatter.string(from: date)
    }
}

// MARK: - One-shot teardown sweep (`serberusd --demote-jit`)

/// Outcome of a ``JITDemotionSweep`` pass.
public struct JITDemotionReport: Sendable, Equatable {
    /// Users removed from `admin` by this pass.
    public var demoted: [String] = []
    /// Users with a qualifying JIT grant who were already NOT in `admin`; their
    /// grant rows were still retired.
    public var alreadyNotAdmin: [String] = []
    /// Grant rows this pass stamped revoked.
    public var revokedGrantIDs: [UUID] = []
    /// Users named ONLY by unverifiable JIT rows (HMAC failure / undecodable)
    /// that this pass handled as demotion candidates. Their rows are never
    /// stamped — the teardown does not write rows it cannot verify.
    public var unverifiedCandidates: [String] = []
    /// Per-user (or `"<store>"`) failure descriptions. Empty ⇒ success.
    public var failures: [String: String] = [:]

    public init() {}

    /// True when every qualifying user was demoted (or confirmed not an admin)
    /// and every grant row was retired.
    public var succeeded: Bool { failures.isEmpty }
}

/// Removes every Serberus-created JIT admin, independent of a running daemon.
///
/// Used by the uninstall / teardown path (`serberusd --demote-jit`) after the
/// daemon has been booted out: the daemon's own timers are gone, so without this
/// a user inside a JIT window (or one whose demotion failed and is still being
/// retried) would keep `admin` forever once Serberus is removed.
///
/// A grant QUALIFIES when it is a VERIFIED JIT grant that is unrevoked
/// (demotion never confirmed — a live window, or an expired one whose demotion
/// failed). A revoked row never qualifies, even when unexpired: a user who
/// ended JIT early and was later made a real admin must not be demoted.
/// Unverifiable JIT rows (``UnverifiedJITRowSource``) add their (untrusted)
/// users as DEMOTION CANDIDATES — conservative by owner decision — but those
/// rows are never written. For each user the sweep checks membership, removes
/// the user from `admin` when present (or when membership cannot be
/// determined), and only then stamps that user's unrevoked verified JIT rows
/// revoked. Every user is attempted even after an earlier failure.
public enum JITDemotionSweep {
    public static func run(
        grantStore: GrantMaintaining,
        membership: GroupMembershipControlling,
        accountResolver: JITAccountResolving = DirectoryJITAccountResolver(),
        ticketClearer: SudoTicketClearing = NoopSudoTicketClearer(),
        adminGroupScrubber: StaleAdminEntryScrubbing = NoopStaleAdminEntryScrubber(),
        now: Date = Date(),
        log: @Sendable (String) async -> Void = { _ in }
    ) async -> JITDemotionReport {
        var report = JITDemotionReport()
        let all: [Grant]
        do {
            all = try await grantStore.allGrants()
        } catch {
            report.failures["<store>"] = "grant store unreadable: \(error)"
            await log("demote-jit: FAILED — grant store unreadable (\(error)); JIT admins could not be enumerated")
            return report
        }

        let qualifying = all.filter { JITAdmin.isJITGrant($0) && $0.revokedAt == nil }

        // Unverifiable JIT rows: demotion candidates, never stamped.
        var unverifiedUsers: Set<String> = []
        if let source = grantStore as? UnverifiedJITRowSource {
            do {
                for row in try await source.unverifiedJITCandidates() {
                    if let user = row.user {
                        unverifiedUsers.insert(user)
                        await log("demote-jit: unverifiable JIT row (\(row.reason)) names \(user); "
                                  + "treating as a demotion candidate")
                    } else {
                        report.failures["<row \(row.rowID)>"] = "unverifiable JIT row names no readable user"
                        await log("demote-jit: FAILED — unverifiable JIT row \(row.rowID) names no readable user; "
                                  + "check the admin group by hand")
                    }
                }
            } catch {
                report.failures["<store>"] = "unverifiable-row scan failed: \(error)"
                await log("demote-jit: FAILED — could not scan for unverifiable JIT rows (\(error))")
            }
        }

        // Stable per-user order so the log (and tests) are deterministic.
        let byUser = Dictionary(grouping: qualifying, by: \.user)
        let verifiedUsers = Set(byUser.keys)
        report.unverifiedCandidates = unverifiedUsers.subtracting(verifiedUsers).sorted()
        for user in verifiedUsers.union(unverifiedUsers).sorted() {
            let grants = byUser[user] ?? []
            // The account to act on: the row's name, or its new name when the
            // row's uid shows the account was renamed.
            var member = user
            // The account's uid, when the rows agree on one and it was not
            // reused by another account: sudo names tickets by uid.
            var ticketUID: uid_t? = Set(grants.map(\.uid)).count == 1 ? grants.first?.uid : nil
            // Set when the account is gone (deleted, or its uid now another's):
            // its leftovers in `admin` are removed once the rows are retired.
            var goneGeneratedUID: String??
            let isMember: Bool?
            do {
                isMember = try await membership.isMember(user: user, group: JITAdmin.adminGroup)
            } catch JITAdminError.userRecordNotFound {
                // Same rule as the daemon: retire only an account confirmed
                // gone; demote a renamed one under its new name; otherwise fail
                // (the row stays active and the teardown reports it).
                let uids = Set(grants.map(\.uid))
                let guids = Set(grants.map(\.generatedUID))
                switch await accountResolver.identify(user: user, uid: uids.count == 1 ? uids.first : nil,
                                                      generatedUID: guids.count == 1 ? guids.first ?? nil : nil) {
                case .gone:
                    isMember = false
                    goneGeneratedUID = .some(guids.count == 1 ? guids.first ?? nil : nil)
                    await log("demote-jit: \(user)'s account no longer exists (by name, by uid, or in the local node)")
                case let .uidReused(by: newAccount):
                    isMember = false
                    ticketUID = nil
                    goneGeneratedUID = .some(guids.count == 1 ? guids.first ?? nil : nil)
                    await log("demote-jit: \(user)'s account is gone and its uid now belongs to a different account, "
                              + "\(newAccount) (GeneratedUID differs); \(newAccount) is NOT demoted")
                case let .renamed(newName):
                    member = newName
                    await log("demote-jit: account \(user) was RENAMED to \(newName); demoting \(newName)")
                    isMember = try? await membership.isMember(user: newName, group: JITAdmin.adminGroup)
                case .present:
                    isMember = nil
                case let .undetermined(why):
                    report.failures[user] = "user record not found and the account could not be confirmed deleted: \(why)"
                    await log("demote-jit: FAILED — \(user)'s record was not found and the account could not be "
                              + "confirmed deleted (\(why)); grant left active")
                    continue
                }
            } catch {
                isMember = nil // unknown: attempt the removal anyway (teardown fails toward demotion)
            }

            if isMember == false {
                report.alreadyNotAdmin.append(member)
                clearTicket(ticketClearer, uid: ticketUID, user: member)
                await log("demote-jit: \(member) already not in \(JITAdmin.adminGroup); retiring JIT grant row(s)")
            } else {
                do {
                    try await membership.removeMember(user: member, group: JITAdmin.adminGroup)
                    report.demoted.append(member)
                    clearTicket(ticketClearer, uid: ticketUID, user: member)
                    await log("demote-jit: removed \(member) from \(JITAdmin.adminGroup)")
                } catch {
                    report.failures[user] = "removal of \(member) from \(JITAdmin.adminGroup) failed: \(error)"
                    await log("demote-jit: FAILED to remove \(member) from \(JITAdmin.adminGroup): \(error) — grant left active")
                    continue // never stamp a grant revoked while the membership may survive
                }
            }

            for grant in grants where grant.revokedAt == nil {
                do {
                    _ = try await grantStore.revoke(grantID: grant.grantID, now: now)
                    report.revokedGrantIDs.append(grant.grantID)
                } catch {
                    report.failures[user] = "grant \(grant.grantID.uuidString) could not be marked revoked: \(error)"
                    await log("demote-jit: \(user) demoted but grant \(grant.grantID.uuidString) could not be marked revoked: \(error)")
                }
            }
            if case let .some(generatedUID) = goneGeneratedUID {
                for line in await adminGroupScrubber.scrub(name: user, generatedUID: generatedUID) {
                    await log("demote-jit: \(user)'s account is gone: \(line)")
                }
            }
        }
        if qualifying.isEmpty && unverifiedUsers.isEmpty {
            await log("demote-jit: no JIT admin grants to demote")
        }
        return report
    }

    /// Clears the uid ticket (and the name one) when the uid is known, else by
    /// name alone (the unverifiable rows, whose uid is not trusted).
    private static func clearTicket(_ clearer: SudoTicketClearing, uid: uid_t?, user: String) {
        if let uid {
            clearer.clearTicket(uid: uid, user: user)
        } else {
            clearer.clearTicket(user: user)
        }
    }
}
