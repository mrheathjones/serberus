import Foundation
import Testing
@testable import PrivMgrCore

@Suite("GrantStore — persistence and integrity", .serialized)
struct GrantStoreTests {
    let keyProvider = InMemoryKeyProvider.random()

    private func makeGrant(
        user: String = "alice",
        ruleID: String = "allow-brew",
        profileKey: String = "rules_sudo_test",
        expiresAt: Date? = Fixtures.now.addingTimeInterval(600)
    ) -> Grant {
        Grant(
            user: user,
            uid: 501,
            ruleID: ruleID,
            profileKey: profileKey,
            teamID: "",
            binaryHash: Fixtures.brewIdentity.sha256,
            canonicalPath: "/opt/homebrew/bin/brew",
            grantedAt: Fixtures.now,
            expiresAt: expiresAt,
            policyVersion: "1.0.0"
        )
    }

    @Test("grants survive store close and reopen")
    func persistence() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { try? FileManager.default.removeItem(atPath: path) }

        let grant = makeGrant()
        // A fixed continuous clock, so the stamp insert() adds is known.
        let clock = MonotonicInstant(bootSessionID: "boot-a", nanoseconds: 1_000_000_000)
        do {
            let store = try GrantStore(path: path, keyProvider: keyProvider, monotonicNow: { clock })
            try await store.insert(grant)
            await store.close()
        }
        let reopened = try GrantStore(path: path, keyProvider: keyProvider, monotonicNow: { clock })
        let active = try await reopened.activeGrants(now: Fixtures.now)
        #expect(active == [grant.stampingContinuousDeadline(at: clock)])
        #expect(active.first?.continuousDeadlineNanos == 1_000_000_000 + 600_000_000_000)
        await reopened.close()
    }

    @Test("startup re-stamp: a row from another boot gets a same-boot deadline from what is left, shortening only")
    func restampFromAnotherBoot() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let grant = makeGrant()                                   // 600 s window from Fixtures.now
        let revoked = makeGrant(user: "bob")
        let untimed = makeGrant(user: "carol", expiresAt: nil)
        let bootA = MonotonicInstant(bootSessionID: "boot-a", nanoseconds: 5_000_000_000_000)
        do {
            let store = try GrantStore(path: path, keyProvider: keyProvider, monotonicNow: { bootA })
            for row in [grant, revoked, untimed] { try await store.insert(row) }
            try await store.revoke(grantID: revoked.grantID, now: Fixtures.now)
            await store.close()
        }

        // After a reboot, 100 s into the window by the wall clock.
        let bootB = MonotonicInstant(bootSessionID: "boot-b", nanoseconds: 2_000_000_000)
        let store = try GrantStore(path: path, keyProvider: keyProvider, monotonicNow: { bootB })
        let wall = Fixtures.now.addingTimeInterval(100)
        #expect(try await store.restampContinuousDeadlines(now: wall) == 1)   // only the live timed row
        let stamped = try #require(try await store.allGrants().first { $0.grantID == grant.grantID })
        #expect(stamped.bootSessionID == "boot-b")
        #expect(stamped.continuousDeadlineNanos == bootB.nanoseconds + 500_000_000_000)
        // Still verifies (the columns are outside the row HMAC), and a second
        // pass in the same boot changes nothing.
        #expect(try await store.activeGrants(now: wall).map(\.grantID).contains(grant.grantID))
        #expect(try await store.restampContinuousDeadlines(now: wall) == 0)
        // Setting the wall clock back in this boot no longer stretches it.
        let later = MonotonicInstant(bootSessionID: "boot-b", nanoseconds: bootB.nanoseconds + 501_000_000_000)
        #expect(stamped.hasExpired(at: Fixtures.now.addingTimeInterval(1), monotonic: later))
        await store.close()
    }

    @Test("re-stamp clamps to the original window and never lengthens it")
    func restampClamps() {
        let grant = makeGrant()                                   // 600 s window
        let boot = MonotonicInstant(bootSessionID: "boot-b", nanoseconds: 1_000)
        // A wall clock before issue would give more than the window: clamped.
        let early = grant.restampingContinuousDeadline(at: boot, now: Fixtures.now.addingTimeInterval(-3600))
        #expect(early?.continuousDeadlineNanos == 1_000 + 600_000_000_000)
        // Past expiry: a deadline of now.
        let late = grant.restampingContinuousDeadline(at: boot, now: Fixtures.now.addingTimeInterval(900))
        #expect(late?.continuousDeadlineNanos == 1_000)
        // Already stamped in this boot, or untimed: nothing to do.
        #expect(grant.stampingContinuousDeadline(at: boot).restampingContinuousDeadline(at: boot, now: Fixtures.now) == nil)
        #expect(makeGrant(expiresAt: nil).restampingContinuousDeadline(at: boot, now: Fixtures.now) == nil)
    }

    @Test("expired grants are removed by cleanup")
    func expiry() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try GrantStore(path: path, keyProvider: keyProvider)

        try await store.insert(makeGrant(expiresAt: Fixtures.now.addingTimeInterval(-60)))
        try await store.insert(makeGrant(user: "bob"))

        let removed = try await store.cleanupExpired(now: Fixtures.now)
        #expect(removed == 1)
        let remaining = try await store.allGrants()
        #expect(remaining.count == 1)
        #expect(remaining.first?.user == "bob")
        await store.close()
    }

    @Test("revocation path: revokeAll (kill switch)")
    func revokeAllPath() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try GrantStore(path: path, keyProvider: keyProvider)
        try await store.insert(makeGrant())
        try await store.insert(makeGrant(user: "bob"))

        let count = try await store.revokeAll(now: Fixtures.now)
        #expect(count == 2)
        #expect(try await store.activeGrants(now: Fixtures.now).isEmpty)
        // Revoked rows remain for audit, with revokedAt set.
        #expect(try await store.allGrants().allSatisfy { $0.revokedAt != nil })
        await store.close()
    }

    @Test("revocation path: per-user")
    func revokeUserPath() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try GrantStore(path: path, keyProvider: keyProvider)
        try await store.insert(makeGrant())
        try await store.insert(makeGrant(user: "bob"))

        let count = try await store.revokeAll(for: "alice", now: Fixtures.now)
        #expect(count == 1)
        let active = try await store.activeGrants(now: Fixtures.now)
        #expect(active.map(\.user) == ["bob"])
        await store.close()
    }

    @Test("revocation path: per-grant")
    func revokeGrantPath() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try GrantStore(path: path, keyProvider: keyProvider)
        let target = makeGrant()
        try await store.insert(target)
        try await store.insert(makeGrant(user: "bob"))

        let count = try await store.revoke(grantID: target.grantID, now: Fixtures.now)
        #expect(count == 1)
        #expect(try await store.activeGrants(now: Fixtures.now).map(\.user) == ["bob"])
        await store.close()
    }

    @Test("revocation path: per-profile (policy reload)")
    func revokeProfilePath() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try GrantStore(path: path, keyProvider: keyProvider)
        try await store.insert(makeGrant(profileKey: "rules_sudo_removed"))
        try await store.insert(makeGrant(user: "bob", profileKey: "rules_sudo_kept"))

        let count = try await store.revokeAll(forProfileKey: "rules_sudo_removed", now: Fixtures.now)
        #expect(count == 1)
        #expect(try await store.activeGrants(now: Fixtures.now).map(\.profileKey) == ["rules_sudo_kept"])
        await store.close()
    }

    @Test("tampered rows are excluded, quarantined, and reported")
    func tamperDetection() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { try? FileManager.default.removeItem(atPath: path) }

        let grant = makeGrant()
        do {
            let store = try GrantStore(path: path, keyProvider: keyProvider)
            try await store.insert(grant)
            await store.close()
        }

        // Attacker flips the user column directly in SQLite.
        let tamper = Process()
        tamper.executableURL = URL(fileURLWithPath: "/usr/bin/sqlite3")
        tamper.arguments = [path, "UPDATE grants SET user='mallory'"]
        try tamper.run()
        tamper.waitUntilExit()
        #expect(tamper.terminationStatus == 0)

        let store = try GrantStore(path: path, keyProvider: keyProvider)
        let active = try await store.activeGrants(now: Fixtures.now)
        #expect(active.isEmpty)
        let violations = await store.drainIntegrityViolations()
        #expect(violations.contains(.integrityViolation(grantID: grant.grantID.uuidString)))
        // Quarantined: tampered row may never satisfy a later query either.
        let again = try await store.activeGrants(now: Fixtures.now)
        #expect(again.isEmpty)
        await store.close()
    }

    private func jitGrant(_ user: String) -> Grant {
        Grant(user: user, uid: 501, ruleID: "jit-self-service", profileKey: JITAdminGrant.profileKey,
              teamID: "", binaryHash: "", canonicalPath: JITAdminGrant.canonicalPath,
              grantedAt: Fixtures.now, expiresAt: Fixtures.now.addingTimeInterval(600), policyVersion: "jit")
    }

    private func sqlite(_ path: String, _ sql: String) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/sqlite3")
        process.arguments = [path, sql]
        try process.run()
        process.waitUntilExit()
    }

    @Test("a tampered JIT row is NOT quarantined on read: it surfaces as a demotion candidate until retired")
    func tamperedJITRowIsCandidateNotQuarantined() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let jit = jitGrant("alice")
        let binary = makeGrant(user: "bob")
        do {
            let store = try GrantStore(path: path, keyProvider: keyProvider)
            try await store.insert(jit)
            try await store.insert(binary)
            await store.close()
        }
        try sqlite(path, "UPDATE grants SET user='mallory'")

        let store = try GrantStore(path: path, keyProvider: keyProvider)
        #expect(try await store.allGrants().isEmpty)          // neither row verifies
        let candidates = try await store.unverifiedJITCandidates()
        #expect(candidates.map(\.user) == ["mallory"])       // the JIT row only, NOT quarantined
        #expect(candidates.first?.reason == "HMAC verification failed")
        let summary = try await store.integritySummary()
        #expect(summary.quarantined == 1 && summary.unverifiable == 1 && summary.verified == 0)

        // Retired once the demotion landed → no longer a candidate.
        #expect(try await store.retireUnverifiedRow(rowID: candidates[0].rowID))
        #expect(try await store.unverifiedJITCandidates().isEmpty)
        await store.close()
    }

    @Test("existing-only open: never creates a missing store")
    func existingOnlyDoesNotCreate() {
        let path = Fixtures.tempDatabasePath()
        #expect(throws: GrantStoreError.self) {
            _ = try GrantStore(path: path, integrityKeys: [HMACSHA256.generateKey()], options: .existingNoQuarantine)
        }
        #expect(!FileManager.default.fileExists(atPath: path))
    }

    @Test("existing-only open with a fallback key: verifies with whichever key matches, never quarantines")
    func multiKeyNoQuarantine() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let realKey = try keyProvider.key(account: BundleConfig.grantsHMACKeyAccount)
        let grant = makeGrant()
        let tampered = makeGrant(user: "carol")
        do {
            let store = try GrantStore(path: path, keyProvider: keyProvider, monotonicNow: { nil })
            try await store.insert(grant)
            try await store.insert(tampered)
            await store.close()
        }
        try sqlite(path, "UPDATE grants SET ruleID='evil' WHERE grantID='\(tampered.grantID.uuidString)'")

        let store = try GrantStore(path: path, integrityKeys: [HMACSHA256.generateKey(), realKey],
                                   options: .existingNoQuarantine)
        #expect(try await store.allGrants() == [grant])
        // Revocation re-signs with the key that verified the row.
        #expect(try await store.revoke(grantID: grant.grantID, now: Fixtures.now) == 1)
        await store.close()

        // Nothing was quarantined: the standard store still reports the tampered
        // row as a fresh violation (not already-quarantined), and the revoked row verifies.
        let standard = try GrantStore(path: path, keyProvider: keyProvider)
        let all = try await standard.allGrants()
        #expect(all.count == 1 && all[0].revokedAt != nil)
        #expect(await standard.drainIntegrityViolations().contains(.integrityViolation(grantID: tampered.grantID.uuidString)))
        await standard.close()
    }

    @Test("existingRowCount: absent 0, empty 0, rows counted, read-only")
    func existingRowCount() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        #expect(GrantStore.existingRowCount(atPath: path) == 0)
        #expect(!FileManager.default.fileExists(atPath: path))
        let store = try GrantStore(path: path, keyProvider: keyProvider)
        #expect(GrantStore.existingRowCount(atPath: path) == 0)
        try await store.insert(makeGrant())
        try await store.insert(makeGrant(user: "bob"))
        #expect(GrantStore.existingRowCount(atPath: path) == 2)
        await store.close()
    }

    @Test("a read-only file key provider never mints a key")
    func readOnlyFileKeyNeverMints() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("serberus-key-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let account = BundleConfig.grantsHMACKeyAccount
        #expect(throws: LoggingError.self) {
            _ = try FileKeyProvider(directory: directory, creation: .readOnly).key(account: account)
        }
        #expect(throws: LoggingError.self) {
            _ = try FileKeyProvider(directory: directory, creation: .createIf { _ in false }).key(account: account)
        }
        #expect(!FileManager.default.fileExists(atPath: FileKeyProvider.keyURL(directory: directory, account: account).path))
        // An existing key is still READ in read-only mode.
        let minted = try FileKeyProvider(directory: directory).key(account: account)
        #expect(try FileKeyProvider(directory: directory, creation: .readOnly).key(account: account) == minted)
    }

    @Test("schema newer than supported fails open with explicit error")
    func schemaTooNew() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        do {
            let store = try GrantStore(path: path, keyProvider: keyProvider)
            await store.close()
        }
        let bump = Process()
        bump.executableURL = URL(fileURLWithPath: "/usr/bin/sqlite3")
        bump.arguments = [path, "PRAGMA user_version = 99"]
        try bump.run()
        bump.waitUntilExit()

        #expect(throws: GrantStoreError.schemaTooNew(found: 99, supported: GrantStoreSchema.currentVersion)) {
            _ = try GrantStore(path: path, keyProvider: keyProvider)
        }
    }

    @Test("fresh database lands on the current schema version")
    func freshSchema() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try GrantStore(path: path, keyProvider: keyProvider)
        try await store.insert(makeGrant())
        let stored = try await store.allGrants()
        #expect(stored.first?.schemaVersion == GrantStoreSchema.currentVersion)
        await store.close()
    }
}

/// Grant expiry that setting the date and time cannot defeat: the issue-time
/// check, the continuous-clock deadline (same boot session), the per-tick
/// revocation, and the schema migration that added the columns.
@Suite("GrantStore — clock changes", .serialized)
struct GrantClockTests {
    let keyProvider = InMemoryKeyProvider.random()
    private static let boot = "boot-a"
    private static let issuedAt = MonotonicInstant(bootSessionID: boot, nanoseconds: 5_000_000_000)

    private static func later(_ seconds: UInt64, boot: String = boot) -> MonotonicInstant {
        MonotonicInstant(bootSessionID: boot, nanoseconds: issuedAt.nanoseconds + seconds * 1_000_000_000)
    }

    private func grant(user: String = "alice", jit: Bool = false, expiresIn seconds: TimeInterval? = 600) -> Grant {
        Grant(
            user: user, uid: 501, ruleID: jit ? "jit-self-service" : "allow-brew",
            profileKey: jit ? JITAdminGrant.profileKey : "rules_sudo_test",
            teamID: "", binaryHash: Fixtures.brewIdentity.sha256,
            canonicalPath: jit ? JITAdminGrant.canonicalPath : "/opt/homebrew/bin/brew",
            grantedAt: Fixtures.now, expiresAt: seconds.map { Fixtures.now.addingTimeInterval($0) },
            policyVersion: "1.0.0"
        )
    }

    /// A clock the test moves.
    private final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var value: MonotonicInstant?
        init(_ value: MonotonicInstant?) { self.value = value }
        var now: MonotonicInstant? { lock.lock(); defer { lock.unlock() }; return value }
        func set(_ newValue: MonotonicInstant?) { lock.lock(); value = newValue; lock.unlock() }
    }

    private func runSQLite(_ path: String, _ sql: String) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/sqlite3")
        process.arguments = [path, sql]
        try process.run()
        process.waitUntilExit()
    }

    @Test("a wall clock set back before issue time counts as expired")
    func clockBeforeIssueIsExpired() {
        let g = grant()
        #expect(g.isActive(at: Fixtures.now, monotonic: nil))
        #expect(!g.isActive(at: Fixtures.now.addingTimeInterval(-1), monotonic: nil))
        #expect(g.hasExpired(at: Fixtures.now.addingTimeInterval(-3600), monotonic: nil))
        // An indefinite grant too: a clock before its issue time is not "within" it.
        #expect(!grant(expiresIn: nil).isActive(at: Fixtures.now.addingTimeInterval(-1), monotonic: nil))
    }

    @Test("same boot session: the continuous clock expires the grant however the wall clock is set")
    func continuousClockExpiresInSameBoot() {
        let g = grant().stampingContinuousDeadline(at: Self.issuedAt)
        // Wall clock held at issue time (set back again and again); continuous time runs on.
        #expect(g.isActive(at: Fixtures.now, monotonic: Self.later(599)))
        #expect(!g.isActive(at: Fixtures.now, monotonic: Self.later(600)))
        #expect(!g.isActive(at: Fixtures.now.addingTimeInterval(1), monotonic: Self.later(3600)))
        #expect(g.remainingSeconds(at: Fixtures.now, monotonic: Self.later(500)) == 100)
        // The wall clock still expires it on its own.
        #expect(!g.isActive(at: Fixtures.now.addingTimeInterval(600), monotonic: Self.later(1)))
    }

    @Test("another boot session falls back to the wall clock plus the issue-time check")
    func otherBootUsesWallClock() {
        let g = grant().stampingContinuousDeadline(at: Self.issuedAt)
        let afterReboot = Self.later(1, boot: "boot-b")
        #expect(g.isActive(at: Fixtures.now.addingTimeInterval(300), monotonic: afterReboot))
        #expect(!g.isActive(at: Fixtures.now.addingTimeInterval(600), monotonic: afterReboot))
        #expect(!g.isActive(at: Fixtures.now.addingTimeInterval(-1), monotonic: afterReboot))
        #expect(g.remainingSeconds(at: Fixtures.now.addingTimeInterval(500), monotonic: afterReboot) == 100)
    }

    @Test("insert stamps the deadline; queries apply both clocks")
    func storeAppliesBothClocks() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let clock = Clock(Self.issuedAt)
        let store = try GrantStore(path: path, keyProvider: keyProvider, monotonicNow: { clock.now })
        let g = grant()
        try await store.insert(g)
        let stored = try #require(try await store.allGrants().first)
        #expect(stored.bootSessionID == Self.boot)
        #expect(stored.continuousDeadlineNanos == Self.later(600).nanoseconds)

        #expect(try await store.activeGrants(now: Fixtures.now).count == 1)
        clock.set(Self.later(601))  // ten minutes pass; the wall clock was set back to issue time
        #expect(try await store.activeGrants(now: Fixtures.now).isEmpty)
        #expect(try await store.activeGrants(for: "alice", now: Fixtures.now).isEmpty)
        #expect(await store.hasExpired(stored, now: Fixtures.now))
        await store.close()
    }

    @Test("revokeExpired revokes clock-expired non-JIT rows for good; JIT rows are left to the JIT manager")
    func revokeExpiredIsPermanent() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let clock = Clock(Self.issuedAt)
        let store = try GrantStore(path: path, keyProvider: keyProvider, monotonicNow: { clock.now })
        let sudo = grant()
        let jit = grant(user: "bob", jit: true)
        let live = grant(user: "carol", expiresIn: 3600)
        try await store.insert(sudo)
        try await store.insert(jit)
        try await store.insert(live)

        #expect(try await store.revokeExpired(now: Fixtures.now) == 0)
        clock.set(Self.later(700))
        #expect(try await store.revokeExpired(now: Fixtures.now) == 1)   // sudo only
        let rows = try await store.allGrants()
        #expect(rows.first { $0.grantID == sudo.grantID }?.revokedAt != nil)
        #expect(rows.first { $0.grantID == jit.grantID }?.revokedAt == nil)
        #expect(rows.first { $0.grantID == live.grantID }?.revokedAt == nil)

        // Moving the clocks back cannot revive it: the revocation is signed.
        clock.set(Self.later(1))
        #expect(try await store.activeGrants(now: Fixtures.now).map(\.grantID).contains(sudo.grantID) == false)
        // A clock set back before issue is expiry too.
        #expect(try await store.revokeExpired(now: Fixtures.now.addingTimeInterval(-60)) == 1) // carol
        await store.close()
    }

    @Test("a version-1 database migrates in place: old rows still verify and use the wall clock only")
    func migratesVersionOneRows() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let old = grant()
        do {
            let store = try GrantStore(path: path, keyProvider: keyProvider, monotonicNow: { nil })
            try await store.insert(old)
            await store.close()
        }
        // Turn it back into what a version-1 build left on disk.
        try runSQLite(path, "ALTER TABLE grants DROP COLUMN bootSessionID")
        try runSQLite(path, "ALTER TABLE grants DROP COLUMN continuousDeadline")
        try runSQLite(path, "ALTER TABLE grants DROP COLUMN generatedUID")
        try runSQLite(path, "UPDATE grants SET schemaVersion = 1")
        try runSQLite(path, "PRAGMA user_version = 1")
        let v1Row = Grant(
            grantID: old.grantID, user: old.user, uid: old.uid, ruleID: old.ruleID, profileKey: old.profileKey,
            teamID: old.teamID, binaryHash: old.binaryHash, canonicalPath: old.canonicalPath,
            grantedAt: old.grantedAt, expiresAt: old.expiresAt, policyVersion: old.policyVersion, schemaVersion: 1
        )
        // Re-sign the row as a version-1 build would have (schemaVersion is signed).
        let key = try keyProvider.key(account: BundleConfig.grantsHMACKeyAccount)
        let hmac = HMACSHA256.hexSignature(message: v1Row.integrityMessage(), key: key)
        try runSQLite(path, "UPDATE grants SET rowHMAC = '\(hmac)'")

        // The read-only teardown view reads a version-1 table as it is.
        let view = try GrantStore(path: path, integrityKeys: [key], options: .existingNoQuarantine)
        #expect(try await view.allGrants() == [v1Row])
        await view.close()

        let clock = Clock(Self.issuedAt)
        let store = try GrantStore(path: path, keyProvider: keyProvider, monotonicNow: { clock.now })
        let rows = try await store.allGrants()
        #expect(rows == [v1Row])                      // verified, not quarantined
        #expect(rows.first?.continuousDeadlineNanos == nil)
        clock.set(Self.later(10_000))                 // no deadline: the continuous clock does not apply
        #expect(try await store.activeGrants(now: Fixtures.now).count == 1)
        #expect(try await store.activeGrants(now: Fixtures.now.addingTimeInterval(600)).isEmpty)
        // New rows land on the current schema, stamped.
        try await store.insert(grant(user: "dave"))
        let dave = try #require(try await store.allGrants().first { $0.user == "dave" })
        #expect(dave.schemaVersion == GrantStoreSchema.currentVersion)
        #expect(dave.bootSessionID == Self.boot)
        await store.close()
    }

    @Test("a version-2 database migrates to 3: old rows still verify, and a recorded GeneratedUID is signed")
    func migratesVersionTwoRowsAndSignsGeneratedUID() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let old = grant(jit: true)
        do {
            let store = try GrantStore(path: path, keyProvider: keyProvider, monotonicNow: { nil })
            try await store.insert(old)
            await store.close()
        }
        // What a version-2 build left on disk: no generatedUID column, schemaVersion 2.
        try runSQLite(path, "ALTER TABLE grants DROP COLUMN generatedUID")
        try runSQLite(path, "UPDATE grants SET schemaVersion = 2")
        try runSQLite(path, "PRAGMA user_version = 2")
        let v2Row = Grant(
            grantID: old.grantID, user: old.user, uid: old.uid, ruleID: old.ruleID, profileKey: old.profileKey,
            teamID: old.teamID, binaryHash: old.binaryHash, canonicalPath: old.canonicalPath,
            grantedAt: old.grantedAt, expiresAt: old.expiresAt, policyVersion: old.policyVersion, schemaVersion: 2
        )
        let key = try keyProvider.key(account: BundleConfig.grantsHMACKeyAccount)
        let hmac = HMACSHA256.hexSignature(message: v2Row.integrityMessage(), key: key)
        try runSQLite(path, "UPDATE grants SET rowHMAC = '\(hmac)'")

        // The read-only teardown view reads a version-2 table as it is.
        let view = try GrantStore(path: path, integrityKeys: [key], options: .existingNoQuarantine)
        #expect(try await view.allGrants() == [v2Row])
        await view.close()

        let store = try GrantStore(path: path, keyProvider: keyProvider, monotonicNow: { nil })
        #expect(try await store.allGrants() == [v2Row])         // verified after migration
        #expect(try await store.unverifiedJITCandidates().isEmpty)

        let guid = "0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9"
        let recorded = Grant(
            user: "erin", uid: 502, ruleID: "jit-self-service", profileKey: JITAdminGrant.profileKey,
            teamID: "", binaryHash: "", canonicalPath: JITAdminGrant.canonicalPath,
            grantedAt: Fixtures.now, expiresAt: Fixtures.now.addingTimeInterval(600), policyVersion: "jit",
            generatedUID: guid
        )
        try await store.insert(recorded)
        let erin = try #require(try await store.allGrants().first { $0.user == "erin" })
        #expect(erin.generatedUID == guid)
        #expect(erin.schemaVersion == 3)
        await store.close()

        // The GeneratedUID is inside the row HMAC: clearing or changing it on the
        // signed row makes the row unverifiable (a demotion candidate), never a
        // silently trusted "different account".
        try runSQLite(path, "UPDATE grants SET generatedUID = 'FFFFFFFF-0000-0000-0000-000000000000' WHERE user = 'erin'")
        let reopened = try GrantStore(path: path, keyProvider: keyProvider, monotonicNow: { nil })
        #expect(try await reopened.allGrants().map(\.user) == ["alice"])
        #expect(try await reopened.unverifiedJITCandidates().map(\.user) == ["erin"])
        await reopened.close()
    }

    @Test("a grant without a GeneratedUID signs exactly the pre-3 message")
    func generatedUIDAbsentKeepsMessage() {
        let base = grant(jit: true)
        let withEmpty = Grant(
            grantID: base.grantID, user: base.user, uid: base.uid, ruleID: base.ruleID, profileKey: base.profileKey,
            teamID: base.teamID, binaryHash: base.binaryHash, canonicalPath: base.canonicalPath,
            grantedAt: base.grantedAt, expiresAt: base.expiresAt, policyVersion: base.policyVersion,
            generatedUID: ""
        )
        #expect(withEmpty.generatedUID == nil)
        #expect(withEmpty.integrityMessage() == base.integrityMessage())
        let withGUID = Grant(
            grantID: base.grantID, user: base.user, uid: base.uid, ruleID: base.ruleID, profileKey: base.profileKey,
            teamID: base.teamID, binaryHash: base.binaryHash, canonicalPath: base.canonicalPath,
            grantedAt: base.grantedAt, expiresAt: base.expiresAt, policyVersion: base.policyVersion,
            generatedUID: "0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9"
        )
        #expect(withGUID.integrityMessage() != base.integrityMessage())
    }

    @Test("the live clock reads a boot session and moves forward")
    func liveClock() throws {
        let first = try #require(MonotonicClock.now())
        #expect(!first.bootSessionID.isEmpty)
        let second = try #require(MonotonicClock.now())
        #expect(second.bootSessionID == first.bootSessionID)
        #expect(second.nanoseconds >= first.nanoseconds)
    }
}

@Suite("SessionGrantCache")
struct SessionGrantCacheTests {
    private let key = SessionGrantCache.Key(
        user: "alice",
        ruleID: "allow-brew",
        binaryHash: Fixtures.brewIdentity.sha256
    )

    @Test("allow decisions are cached within TTL")
    func cachesAllow() async {
        let cache = SessionGrantCache()
        await cache.store(decision: .allow, key: key, ttlSeconds: 300, now: Fixtures.now)
        let hit = await cache.lookup(key: key, now: Fixtures.now.addingTimeInterval(299))
        #expect(hit == .allow)
        let miss = await cache.lookup(key: key, now: Fixtures.now.addingTimeInterval(301))
        #expect(miss == nil)
    }

    @Test("a clock set back before the store time never reads a cached allow")
    func clockSetBackMisses() async {
        let cache = SessionGrantCache()
        await cache.store(decision: .allow, key: key, ttlSeconds: 300, now: Fixtures.now)
        #expect(await cache.lookup(key: key, now: Fixtures.now.addingTimeInterval(-1)) == nil)
        // The miss evicted it: moving the clock forward again does not revive it.
        #expect(await cache.lookup(key: key, now: Fixtures.now.addingTimeInterval(10)) == nil)
    }

    @Test("deny decisions are never cached")
    func neverCachesDeny() async {
        let cache = SessionGrantCache()
        await cache.store(decision: .deny, key: key, ttlSeconds: 300, now: Fixtures.now)
        #expect(await cache.lookup(key: key, now: Fixtures.now) == nil)
    }

    @Test("zero TTL is never cached")
    func zeroTTL() async {
        let cache = SessionGrantCache()
        await cache.store(decision: .allow, key: key, ttlSeconds: 0, now: Fixtures.now)
        #expect(await cache.lookup(key: key, now: Fixtures.now) == nil)
    }

    @Test("targeted removals")
    func removals() async {
        let cache = SessionGrantCache()
        let bobKey = SessionGrantCache.Key(user: "bob", ruleID: "other", binaryHash: "ff00")
        await cache.store(decision: .allow, key: key, ttlSeconds: 300, now: Fixtures.now)
        await cache.store(decision: .allow, key: bobKey, ttlSeconds: 300, now: Fixtures.now)

        await cache.removeAll(for: "alice")
        #expect(await cache.lookup(key: key, now: Fixtures.now) == nil)
        #expect(await cache.lookup(key: bobKey, now: Fixtures.now) == .allow)

        await cache.removeAll(forRuleID: "other")
        #expect(await cache.lookup(key: bobKey, now: Fixtures.now) == nil)
    }
}
