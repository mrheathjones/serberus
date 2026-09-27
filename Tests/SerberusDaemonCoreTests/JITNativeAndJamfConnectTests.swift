import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

// MARK: - Fakes

/// Local `admin` membership the test controls.
private actor AdminMembership: GroupMembershipControlling {
    private var admins: Set<String>
    private var failing = false
    private var missingRecords: Set<String> = []
    private(set) var removed: [String] = []

    init(admins: Set<String> = []) { self.admins = admins }

    func set(admin user: String, _ isAdmin: Bool) {
        if isAdmin { admins.insert(user) } else { admins.remove(user) }
    }
    func setFailing(_ value: Bool) { failing = value }
    func setMissingRecord(_ user: String) { missingRecords.insert(user) }

    func isMember(user: String, group: String) async throws -> Bool {
        if failing { throw JITAdminError.commandTimedOut(path: "/usr/sbin/dseditgroup", seconds: 10) }
        if missingRecords.contains(user) { throw JITAdminError.userRecordNotFound(user: user) }
        return group == "admin" && admins.contains(user)
    }
    func groups(forUser user: String) async -> Set<String> { admins.contains(user) ? ["admin", "developers"] : ["developers"] }
    func addMember(user: String, group: String) async throws { admins.insert(user) }
    func removeMember(user: String, group: String) async throws {
        removed.append(user)
        admins.remove(user)
    }
}

/// Records which tickets were cleared: the names passed by either call, and the
/// uids passed to ``SudoTicketClearing/clearTicket(uid:user:)``.
private final class TicketSpy: SudoTicketClearing, @unchecked Sendable {
    private let lock = NSLock()
    private var users: [String] = []
    private var uids: [uid_t] = []
    private var allCount = 0
    func clearTicket(uid: uid_t, user: String?) -> Bool {
        lock.lock(); defer { lock.unlock() }
        uids.append(uid)
        if let user { users.append(user) }
        return true
    }
    func clearTicket(user: String) -> Bool { lock.lock(); users.append(user); lock.unlock(); return true }
    func clearAllTickets() -> Int { lock.lock(); allCount += 1; lock.unlock(); return 0 }
    var clearedUsers: [String] { lock.lock(); defer { lock.unlock() }; return users }
    var clearedUIDs: [uid_t] { lock.lock(); defer { lock.unlock() }; return uids }
    var clearAllCalls: Int { lock.lock(); defer { lock.unlock() }; return allCount }
}

/// A grant store holding whatever the test put there.
private actor ListGrantStore: GrantMaintaining {
    private var grants: [Grant]
    init(_ grants: [Grant] = []) { self.grants = grants }
    func insert(_ grant: Grant) async throws { grants.append(grant) }
    func cleanupExpired(now: Date) async throws -> Int { 0 }
    func activeGrants(now: Date) async throws -> [Grant] { grants.filter { $0.isActive(at: now, monotonic: nil) } }
    func activeGrants(for user: String, now: Date) async throws -> [Grant] {
        grants.filter { $0.user == user && $0.isActive(at: now, monotonic: nil) }
    }
    func allGrants() async throws -> [Grant] { grants }
    func revokeAll(now: Date) async throws -> Int { 0 }
    func revoke(grantID: UUID, now: Date) async throws -> Int {
        guard let index = grants.firstIndex(where: { $0.grantID == grantID && $0.revokedAt == nil }) else { return 0 }
        let g = grants[index]
        grants[index] = Grant(grantID: g.grantID, user: g.user, uid: g.uid, ruleID: g.ruleID, profileKey: g.profileKey,
                              teamID: g.teamID, binaryHash: g.binaryHash, canonicalPath: g.canonicalPath,
                              grantedAt: g.grantedAt, expiresAt: g.expiresAt, revokedAt: now,
                              policyVersion: g.policyVersion, generatedUID: g.generatedUID)
        return 1
    }
    func all() -> [Grant] { grants }
}

/// Fixture log lines instead of a `log` child.
private final class FixtureLogSource: JamfConnectLogStreaming, @unchecked Sendable {
    private let historyLines: [String]
    init(history: [String] = []) { historyLines = history }
    func liveLines() -> AsyncStream<String> { AsyncStream { _ in } } // stays open, yields nothing
    func history(seconds: Int) async -> [String] { historyLines }
}

private enum Fixture {
    static let now = CoordinatorFixtures.now
    static let jcDaemon = "/Library/Application Support/JamfConnect/JamfConnectDaemon"
    static let sspDaemon = "/Applications/Self Service+.app/Contents/MacOS/Self Service+ Daemon"

    static func stamp(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: -7 * 3600)
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSSSSSZ"
        return formatter.string(from: date)
    }

    /// One `log stream --style ndjson` line.
    static func line(_ message: String, at date: Date = now, subsystem: String = "com.jamf.connect.daemon.ssp",
                     category: String = "PrivilegeElevation", image: String = jcDaemon) -> String {
        let object: [String: Any] = [
            "timestamp": stamp(date), "eventType": "logEvent", "messageType": "Default",
            "subsystem": subsystem, "category": category,
            "processImagePath": image, "senderImagePath": image,
            "processID": 812, "eventMessage": message,
        ]
        let data = try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }

    static func jitGrant(user: String = "root", uid: uid_t = 0, expiresIn: TimeInterval = 900,
                         generatedUID: String? = nil) -> Grant {
        Grant(user: user, uid: uid, ruleID: "jit-self-service", profileKey: JITAdminGrant.profileKey,
              teamID: "", binaryHash: "", canonicalPath: JITAdminGrant.canonicalPath,
              grantedAt: now.addingTimeInterval(-60), expiresAt: now.addingTimeInterval(expiresIn),
              policyVersion: "jit", generatedUID: generatedUID)
    }
}

// MARK: - Log parsing

@Suite("Jamf Connect log parsing")
struct JamfConnectLogParserTests {
    @Test("an elevation from the Jamf Connect daemon parses with user, minutes and time")
    func elevated() throws {
        let event = try #require(JamfConnectLogParser.parse(
            line: Fixture.line("jdoe elevated to admin for 30 minutes"), fallbackDate: nil))
        #expect(event.kind == .elevated(user: "jdoe", minutes: 30))
        #expect(abs(event.date.timeIntervalSince(Fixture.now)) < 1)
        #expect(event.processImagePath == Fixture.jcDaemon)
    }

    @Test("message variants Jamf may write are recognized", arguments: [
        ("User jdoe elevated to admin for 15 minutes", JamfConnectElevationEvent.Kind.elevated(user: "jdoe", minutes: 15)),
        ("\"j.doe\" elevated to administrator for 1 minute", .elevated(user: "j.doe", minutes: 1)),
        ("Removed user jdoe from admin group", .removed(user: "jdoe")),
        ("Removed user jdoe from the admin group.", .removed(user: "jdoe")),
        ("User elevation time remaining: 04:59", .remaining(seconds: 299)),
        ("User elevation time remaining: 1:02:03", .remaining(seconds: 3723)),
    ])
    func variants(message: String, expected: JamfConnectElevationEvent.Kind) {
        #expect(JamfConnectLogParser.parseMessage(message) == expected)
    }

    @Test("unrelated, redacted or malformed messages are ignored", arguments: [
        "<private> elevated to admin for 30 minutes",
        "jdoe elevated to admin for 0 minutes",
        "jdoe requested elevation",
        "User elevation time remaining: 04:75",
        "",
    ])
    func ignored(message: String) {
        #expect(JamfConnectLogParser.parseMessage(message) == nil)
    }

    @Test("both documented subsystems and the Self Service+ bundle are accepted")
    func acceptedSenders() {
        #expect(JamfConnectLogParser.parse(line: Fixture.line("a elevated to admin for 5 minutes",
                                                               subsystem: "com.jamf.connect"), fallbackDate: nil) != nil)
        #expect(JamfConnectLogParser.parse(line: Fixture.line("a elevated to admin for 5 minutes",
                                                               image: Fixture.sspDaemon), fallbackDate: nil) != nil)
        #expect(JamfConnectLogParser.parse(line: Fixture.line(
            "a elevated to admin for 5 minutes",
            image: "/Applications/Jamf Connect.app/Contents/MacOS/Jamf Connect"), fallbackDate: nil) != nil)
    }

    @Test("an entry from another process, subsystem or category is refused, however it reads", arguments: [
        ("com.jamf.connect.daemon.ssp", "PrivilegeElevation", "/Users/mallory/Downloads/fake"),
        ("com.jamf.connect.daemon.ssp", "PrivilegeElevation", "/tmp/Jamf Connect.app/Contents/MacOS/x"),
        ("com.jamf.connect.daemon.ssp", "PrivilegeElevation", "/Applications/Jamf Connect.app/../../tmp/x"),
        ("com.jamf.connect.daemon.ssp", "PrivilegeElevation", "/Applications/Jamf Connect.app.evil/x"),
        ("com.jamf.connect.daemon.ssp", "PrivilegeElevation", "/Applications/Jamf Connect.app/"),
        ("com.jamf.connect.evil", "PrivilegeElevation", Fixture.jcDaemon),
        ("com.jamf.connect", "Login", Fixture.jcDaemon),
    ])
    func refusedSenders(subsystem: String, category: String, image: String) {
        let line = Fixture.line("mallory elevated to admin for 480 minutes",
                                subsystem: subsystem, category: category, image: image)
        #expect(JamfConnectLogParser.parse(line: line, fallbackDate: Fixture.now) == nil)
    }

    @Test("non-JSON lines (the tool's banner) and entries without an image path are ignored")
    func nonJSON() {
        #expect(JamfConnectLogParser.parse(line: "Filtering the log data using \"subsystem == ...\"",
                                           fallbackDate: Fixture.now) == nil)
        #expect(JamfConnectLogParser.parse(line: #"{"subsystem":"com.jamf.connect","category":"PrivilegeElevation","eventMessage":"a elevated to admin for 5 minutes"}"#,
                                           fallbackDate: Fixture.now) == nil)
    }

    @Test("an unparseable timestamp uses the fallback, or drops the entry without one")
    func timestampFallback() {
        let line = Fixture.line("a elevated to admin for 5 minutes")
            .replacingOccurrences(of: Fixture.stamp(Fixture.now), with: "not a date")
        #expect(JamfConnectLogParser.parse(line: line, fallbackDate: Fixture.now)?.date == Fixture.now)
        #expect(JamfConnectLogParser.parse(line: line, fallbackDate: nil) == nil)
    }
}

// MARK: - Windows

@Suite("Jamf Connect elevation windows")
struct JamfConnectWindowTests {
    private let now = Fixture.now
    private func event(_ kind: JamfConnectElevationEvent.Kind, at offset: TimeInterval = 0) -> JamfConnectElevationEvent {
        JamfConnectElevationEvent(kind: kind, date: now.addingTimeInterval(offset), processImagePath: Fixture.jcDaemon)
    }

    @Test("an elevation opens a window for the logged duration")
    func opens() {
        var windows = JamfConnectElevationWindows()
        let changes = windows.apply(event(.elevated(user: "jdoe", minutes: 30)), now: now)
        #expect(changes.count == 1)
        #expect(windows.active(for: "jdoe", at: now.addingTimeInterval(29 * 60))?.end == now.addingTimeInterval(1800))
        #expect(windows.active(for: "jdoe", at: now.addingTimeInterval(1800)) == nil)
        #expect(windows.active(for: "someone", at: now) == nil)
    }

    @Test("the logged duration is capped at the 8-hour JIT ceiling")
    func ceiling() {
        var windows = JamfConnectElevationWindows()
        _ = windows.apply(event(.elevated(user: "jdoe", minutes: 10_000)), now: now)
        #expect(windows.byUser["jdoe"]?.end == now.addingTimeInterval(8 * 3600))
        _ = windows.apply(event(.elevated(user: "big", minutes: Int.max)), now: now)
        #expect(windows.byUser["big"]?.end == now.addingTimeInterval(8 * 3600))
    }

    @Test("a removal entry closes the window; an older removal does not")
    func removal() {
        var windows = JamfConnectElevationWindows()
        _ = windows.apply(event(.elevated(user: "jdoe", minutes: 30), at: 0), now: now)
        #expect(windows.apply(event(.removed(user: "jdoe"), at: -10), now: now).isEmpty)
        let changes = windows.apply(event(.removed(user: "jdoe"), at: 60), now: now)
        guard case .closed(let window, _)? = changes.first else { Issue.record("not closed"); return }
        #expect(window.user == "jdoe")
        #expect(windows.byUser.isEmpty)
    }

    @Test("time remaining only shortens the sole open window")
    func remaining() {
        var windows = JamfConnectElevationWindows()
        _ = windows.apply(event(.elevated(user: "jdoe", minutes: 30)), now: now)
        _ = windows.apply(event(.remaining(seconds: 300), at: 60), now: now)
        #expect(windows.byUser["jdoe"]?.end == now.addingTimeInterval(360))
        _ = windows.apply(event(.remaining(seconds: 3000), at: 120), now: now) // never lengthens
        #expect(windows.byUser["jdoe"]?.end == now.addingTimeInterval(360))
        _ = windows.apply(event(.elevated(user: "other", minutes: 30)), now: now)
        _ = windows.apply(event(.remaining(seconds: 5), at: 130), now: now) // ambiguous: ignored
        #expect(windows.byUser["jdoe"]?.end == now.addingTimeInterval(360))
        #expect(windows.byUser["other"]?.end == now.addingTimeInterval(1800))
    }

    @Test("an elevation already over when it arrives opens nothing; an older event never replaces a newer window")
    func stale() {
        var windows = JamfConnectElevationWindows()
        #expect(windows.apply(event(.elevated(user: "jdoe", minutes: 5), at: -3600), now: now).isEmpty)
        #expect(windows.byUser.isEmpty)
        _ = windows.apply(event(.elevated(user: "jdoe", minutes: 30), at: 0), now: now)
        #expect(windows.apply(event(.elevated(user: "jdoe", minutes: 60), at: -60), now: now).isEmpty)
        #expect(windows.byUser["jdoe"]?.end == now.addingTimeInterval(1800))
    }

    @Test("expire closes elapsed windows only")
    func expire() {
        var windows = JamfConnectElevationWindows()
        _ = windows.apply(event(.elevated(user: "a", minutes: 1)), now: now)
        _ = windows.apply(event(.elevated(user: "b", minutes: 10)), now: now)
        let closed = windows.expire(now: now.addingTimeInterval(120))
        #expect(closed.count == 1)
        #expect(windows.byUser.keys.sorted() == ["b"])
    }
}

// MARK: - Observer

@Suite("Jamf Connect elevation observer", .serialized)
struct JamfConnectObserverTests {
    private final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var value = Fixture.now
        var now: Date { lock.lock(); defer { lock.unlock() }; return value }
        func advance(_ seconds: TimeInterval) { lock.lock(); value = value.addingTimeInterval(seconds); lock.unlock() }
    }

    private func logDirectory() throws -> URL { try CoordinatorFixtures.tempDirectory() }

    private func loggedText(in directory: URL) -> String {
        let files = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
        return files.filter { $0.lastPathComponent.hasPrefix("decisions") }
            .compactMap { try? String(contentsOf: $0, encoding: .utf8) }.joined()
    }

    @Test("a live elevation opens a window, is logged, and its removal clears the user's ticket")
    func liveFlow() async throws {
        let dir = try logDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let clock = Clock()
        let tickets = TicketSpy()
        let observer = JamfConnectElevationObserver(
            source: FixtureLogSource(), membership: AdminMembership(admins: ["jdoe"]), ticketClearer: tickets,
            decisionLogger: try DecisionLogger(directory: dir, keyProvider: InMemoryKeyProvider.random()),
            now: { clock.now })
        await observer.start()
        await observer.ingest(line: Fixture.line("jdoe elevated to admin for 30 minutes"))
        #expect(await observer.activeWindow(for: "jdoe")?.user == "jdoe")
        #expect(await observer.activeWindow(for: "other") == nil)
        #expect(tickets.clearedUsers.isEmpty)

        await observer.ingest(line: Fixture.line("Removed user jdoe from admin group", at: Fixture.now.addingTimeInterval(60)))
        #expect(await observer.activeWindow(for: "jdoe") == nil)
        #expect(tickets.clearedUsers == ["jdoe"])

        let logged = loggedText(in: dir)
        #expect(logged.contains("jit_admin_elevation"))
        #expect(logged.contains("jit_admin_demotion"))
        #expect(logged.contains(JamfConnectElevationObserver.ruleID))
        await observer.stop()
    }

    @Test("a spoofed entry from outside the Jamf bundles opens nothing")
    func spoofIgnored() async {
        let observer = JamfConnectElevationObserver(
            source: FixtureLogSource(), membership: AdminMembership(), ticketClearer: TicketSpy(),
            decisionLogger: nil, now: { Fixture.now })
        await observer.start()
        await observer.ingest(line: Fixture.line("mallory elevated to admin for 480 minutes", image: "/tmp/fake"))
        #expect(await observer.activeWindow(for: "mallory") == nil)
        await observer.stop()
    }

    @Test("sweep ends a window that elapsed or whose user left admin, clearing each ticket")
    func sweep() async {
        let clock = Clock()
        let tickets = TicketSpy()
        let membership = AdminMembership(admins: ["a", "b", "c"])
        let observer = JamfConnectElevationObserver(
            source: FixtureLogSource(), membership: membership, ticketClearer: tickets,
            decisionLogger: nil, now: { clock.now })
        await observer.start()
        await observer.ingest(line: Fixture.line("a elevated to admin for 1 minutes"))
        await observer.ingest(line: Fixture.line("b elevated to admin for 30 minutes"))
        await observer.ingest(line: Fixture.line("c elevated to admin for 30 minutes"))
        await membership.set(admin: "b", false)
        clock.advance(120)
        await observer.sweep()
        #expect(tickets.clearedUsers.sorted() == ["a", "b"])
        #expect(await observer.activeWindow(for: "c") != nil)

        // Unknown membership never ends a window by itself.
        await membership.setFailing(true)
        await observer.sweep()
        #expect(await observer.activeWindow(for: "c") != nil)
        await observer.stop()
        #expect(tickets.clearedUsers.sorted() == ["a", "b", "c"]) // stop ends every window
    }

    @Test("history restores an open window silently; stop ignores later lines")
    func history() async throws {
        let dir = try logDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let history = [
            Fixture.line("old elevated to admin for 5 minutes", at: Fixture.now.addingTimeInterval(-7200)),
            Fixture.line("jdoe elevated to admin for 60 minutes", at: Fixture.now.addingTimeInterval(-600)),
        ]
        let observer = JamfConnectElevationObserver(
            source: FixtureLogSource(history: history), membership: AdminMembership(), ticketClearer: TicketSpy(),
            decisionLogger: try DecisionLogger(directory: dir, keyProvider: InMemoryKeyProvider.random()),
            now: { Fixture.now })
        await observer.start()
        await observer.restore(fromHistory: history)
        #expect(await observer.activeWindow(for: "jdoe")?.end == Fixture.now.addingTimeInterval(3000))
        #expect(await observer.activeWindow(for: "old") == nil)
        #expect(!loggedText(in: dir).contains("jit_admin_elevation"))
        await observer.stop()
        await observer.ingest(line: Fixture.line("late elevated to admin for 5 minutes"))
        #expect(await observer.activeWindow(for: "late") == nil)
    }
}

// MARK: - Self Service's Jamf Connect (JCDaemon)

/// Entries as Self Service's bundled Jamf Connect writes them (macOS 26), with
/// the names replaced.
private enum SelfServiceFixture {
    static let jcDaemon = "/Applications/Self Service.app/Contents/MacOS/JCDaemon.app/Contents/MacOS/JCDaemon"
    static let menuApp = "/Applications/Self Service.app/Contents/MacOS/Jamf Connect.app/Contents/MacOS/Jamf Connect"

    /// A JCDaemon entry (subsystem com.jamf.connect.daemon.ssp).
    static func daemon(_ message: String, at offset: TimeInterval = 0) -> String {
        Fixture.line(message, at: Fixture.now.addingTimeInterval(offset), image: jcDaemon)
    }

    /// One elevation of `user` for 44:59, started `offset` seconds from now.
    static func grant(_ user: String, at offset: TimeInterval) -> [String] {
        [
            daemon("Attempting to grant privilege elevation for: \(user)", at: offset),
            daemon("Added user \(user) to admin group.", at: offset + 0.031),
            daemon("\(user)'s elevations this month: 7", at: offset + 0.033),
            daemon("User \(user) elevated to admin for stated reason: SPECIAL REQUESTS", at: offset + 0.033),
            daemon("Privilege elevation time remaining: 44:59", at: offset + 0.034),
        ]
    }

    /// The user ending `user`'s elevation early, `offset` seconds from now.
    static func end(_ user: String, at offset: TimeInterval) -> [String] {
        [
            daemon("User elevation timer was canceled for \(user)", at: offset),
            daemon("Removed user \(user) from admin group.", at: offset + 0.020),
            daemon("Session for \(user) ended, removing entry from UserDefaults and notifying menubar", at: offset + 0.020),
        ]
    }
}

@Suite("Jamf Connect in Self Service: log parsing")
struct SelfServiceJamfConnectParserTests {
    @Test("the JCDaemon lines that start, time and end an elevation parse")
    func realLines() throws {
        let added = try #require(JamfConnectLogParser.parse(
            line: SelfServiceFixture.daemon("Added user jdoe to admin group."), fallbackDate: nil))
        #expect(added.kind == .added(user: "jdoe"))
        #expect(added.processImagePath == SelfServiceFixture.jcDaemon)
        #expect(JamfConnectLogParser.parse(line: SelfServiceFixture.daemon("Privilege elevation time remaining: 44:59"),
                                           fallbackDate: nil)?.kind == .remaining(seconds: 2699))
        #expect(JamfConnectLogParser.parse(line: SelfServiceFixture.daemon("Removed user jdoe from admin group."),
                                           fallbackDate: nil)?.kind == .removed(user: "jdoe"))
    }

    @Test("variants of the new forms are recognized", arguments: [
        ("added user \"j.doe\" to the admin group", JamfConnectElevationEvent.Kind.added(user: "j.doe")),
        ("ADDED USER jdoe TO ADMIN GROUP", .added(user: "jdoe")),
        ("  Added user jdoe to admin group.\n", .added(user: "jdoe")),
        ("PRIVILEGE ELEVATION TIME REMAINING: 1:00:00.", .remaining(seconds: 3600)),
        ("Privilege elevation time remaining: 00:05", .remaining(seconds: 5)),
    ])
    func variants(message: String, expected: JamfConnectElevationEvent.Kind) {
        #expect(JamfConnectLogParser.parseMessage(message) == expected)
    }

    @Test("the other JCDaemon and menu app lines are not elevation entries", arguments: [
        "Attempting to grant privilege elevation for: jdoe",
        "jdoe's elevations this month: 7",
        "User jdoe elevated to admin for stated reason: SPECIAL REQUESTS",
        "User elevation timer was canceled for jdoe",
        "Session for jdoe ended, removing entry from UserDefaults and notifying menubar",
        "duration specified by role Mac-Local-Administrator: 45 minutes",
        "Contents: Elevation Granted for UPN: first.last@example.org, Role: Mac-Local-Administrator, Duration: 45.000000 minutes (ends: <private>), authentication method: identityProvider",
        "This user is not in the admin group",
        "User account can request for admin privilege session",
        "Validating privilege elevation sessions at daemon startup.",
        "No active sessions for 'jdoe'",
        "Added user <private> to admin group.",
        "Removed user <private> from admin group.",
        "Added user jdoe bob to admin group.",
        "Added user jdoe to admin group. Added user bob to admin group.",
        "Other elevation time remaining: 44:59",
    ])
    func noise(message: String) {
        #expect(JamfConnectLogParser.parseMessage(message) == nil)
    }

    @Test("a reason the user typed never reads as an elevation entry", arguments: [
        "Added user bob to admin group.",
        "bob elevated to admin for 480 minutes",
        "Removed user jdoe from admin group.",
        "Privilege elevation time remaining: 7:59:59",
        "x\nAdded user bob to admin group.",
        "\nbob elevated to admin for 480 minutes\n",
        "\n\nRemoved user jdoe from admin group.",
        "SPECIAL REQUESTS",
        "",
    ])
    func hostileReason(reason: String) {
        let message = "User jdoe elevated to admin for stated reason: \(reason)"
        #expect(JamfConnectLogParser.parseMessage(message) == nil)
        #expect(JamfConnectLogParser.parse(line: SelfServiceFixture.daemon(message), fallbackDate: nil) == nil)
    }

    @Test("the reason text alone is not an elevation entry")
    func reasonAlone() {
        #expect(JamfConnectLogParser.parseMessage("SPECIAL REQUESTS") == nil)
        #expect(JamfConnectLogParser.parseMessage("stated reason: SPECIAL REQUESTS") == nil)
    }

    @Test("Self Service's JCDaemon is a trusted sender")
    func daemonTrusted() {
        #expect(JamfConnectLogParser.isTrustedImagePath(SelfServiceFixture.jcDaemon))
        #expect(JamfConnectLogParser.parse(line: Fixture.line("Added user jdoe to admin group.", subsystem: "com.jamf.connect",
                                                               image: SelfServiceFixture.jcDaemon), fallbackDate: nil) != nil)
    }

    @Test("the rest of Self Service, including its Jamf Connect menu app, is not trusted", arguments: [
        SelfServiceFixture.menuApp,
        "/Applications/Self Service.app/Contents/MacOS/Other",
        "/Applications/Self Service.app/Contents/MacOS/Self Service",
        "/Applications/Self Service.app/Contents/Resources/JCDaemon",
        "/Applications/Self Service.app/Contents/MacOS/JCDaemon.app/",
        "/Applications/Self Service.app/Contents/MacOS/JCDaemon.app.evil/JCDaemon",
        "/Applications/Self Service.app/Contents/MacOS/JCDaemonX.app/Contents/MacOS/JCDaemon",
        "/Applications/Self Service.app/Contents/MacOS/JCDaemon.app/../Other",
        "/Applications/Self Service.app/Contents/MacOS/JCDaemon.app/Contents/../../Jamf Connect.app/Contents/MacOS/Jamf Connect",
        "/Applications/Self Service.app/Contents/MacOS/JCDaemon.app/./JCDaemon",
        "/Applications/Self Service.app/Contents/MacOS/JCDaemon.app/Contents/MacOS/../../../../../../../tmp/x",
        "/tmp/Applications/Self Service.app/Contents/MacOS/JCDaemon.app/Contents/MacOS/JCDaemon",
        "Applications/Self Service.app/Contents/MacOS/JCDaemon.app/Contents/MacOS/JCDaemon",
        "/Users/mallory/Applications/Self Service.app/Contents/MacOS/JCDaemon.app/Contents/MacOS/JCDaemon",
    ])
    func untrusted(image: String) {
        #expect(!JamfConnectLogParser.isTrustedImagePath(image))
        #expect(JamfConnectLogParser.parse(line: Fixture.line("Added user mallory to admin group.", image: image),
                                           fallbackDate: Fixture.now) == nil)
    }
}

@Suite("Jamf Connect in Self Service: windows")
struct SelfServiceJamfConnectWindowTests {
    private let now = Fixture.now
    private func event(_ kind: JamfConnectElevationEvent.Kind, at offset: TimeInterval = 0) -> JamfConnectElevationEvent {
        JamfConnectElevationEvent(kind: kind, date: now.addingTimeInterval(offset),
                                  processImagePath: SelfServiceFixture.jcDaemon)
    }

    @Test("Added opens a default-length window; the time remaining after it sets the end; Removed closes it")
    func addedRemainingRemoved() {
        var windows = JamfConnectElevationWindows()
        guard case .opened(let opened)? = windows.apply(event(.added(user: "jdoe")), now: now).first else {
            Issue.record("not opened"); return
        }
        #expect(opened.end == now.addingTimeInterval(JamfConnectElevationWindows.addedDefaultSeconds))
        let resized = windows.apply(event(.remaining(seconds: 2699), at: 0.003), now: now)
        guard case .resized(let window)? = resized.first else { Issue.record("not resized"); return }
        #expect(abs(window.end.timeIntervalSince(now) - 2699.003) < 0.001)
        #expect(windows.active(for: "jdoe", at: now.addingTimeInterval(2690)) != nil)
        let closed = windows.apply(event(.removed(user: "jdoe"), at: 36), now: now.addingTimeInterval(36))
        guard case .closed(let ended, _)? = closed.first else { Issue.record("not closed"); return }
        #expect(ended.user == "jdoe")
        #expect(windows.byUser.isEmpty)
    }

    @Test("Added then time remaining ends by expiry")
    func addedRemainingExpiry() {
        var windows = JamfConnectElevationWindows()
        _ = windows.apply(event(.added(user: "jdoe")), now: now)
        _ = windows.apply(event(.remaining(seconds: 2699), at: 0.003), now: now)
        #expect(windows.expire(now: now.addingTimeInterval(2690)).isEmpty)
        #expect(windows.expire(now: now.addingTimeInterval(2700)).count == 1)
        #expect(windows.active(for: "jdoe", at: now.addingTimeInterval(2700)) == nil)
    }

    @Test("Added with no time remaining stays bounded to the default length")
    func addedWithoutRemaining() {
        var windows = JamfConnectElevationWindows()
        _ = windows.apply(event(.added(user: "jdoe")), now: now)
        let limit = JamfConnectElevationWindows.addedDefaultSeconds
        #expect(limit == 15 * 60)
        #expect(windows.active(for: "jdoe", at: now.addingTimeInterval(limit - 1)) != nil)
        #expect(windows.active(for: "jdoe", at: now.addingTimeInterval(limit)) == nil)
        #expect(windows.expire(now: now.addingTimeInterval(limit)).count == 1)
    }

    @Test("a time remaining after the grace period only shortens, as before")
    func lateRemaining() {
        var windows = JamfConnectElevationWindows()
        _ = windows.apply(event(.added(user: "jdoe")), now: now)
        _ = windows.apply(event(.remaining(seconds: 2699), at: 120), now: now.addingTimeInterval(120))
        #expect(windows.byUser["jdoe"]?.end == now.addingTimeInterval(900))
        _ = windows.apply(event(.remaining(seconds: 60), at: 130), now: now.addingTimeInterval(130))
        #expect(windows.byUser["jdoe"]?.end == now.addingTimeInterval(190))
    }

    @Test("only the first time remaining sets the length; later ones only shorten")
    func onlyFirstRemaining() {
        var windows = JamfConnectElevationWindows()
        _ = windows.apply(event(.added(user: "jdoe")), now: now)
        _ = windows.apply(event(.remaining(seconds: 600), at: 0.003), now: now)
        _ = windows.apply(event(.remaining(seconds: 2699), at: 0.004), now: now)
        #expect(abs((windows.byUser["jdoe"]?.end.timeIntervalSince(now) ?? 0) - 600.003) < 0.001)
    }

    @Test("the length from time remaining is capped at the 8-hour ceiling")
    func capped() {
        var windows = JamfConnectElevationWindows()
        _ = windows.apply(event(.added(user: "jdoe")), now: now)
        _ = windows.apply(event(.remaining(seconds: 30 * 3600), at: 1), now: now)
        #expect(windows.byUser["jdoe"]?.end == now.addingTimeInterval(JamfConnectElevationWindows.ceilingSeconds))
    }

    @Test("time remaining with another window open is ambiguous: the default length stays")
    func ambiguous() {
        var windows = JamfConnectElevationWindows()
        _ = windows.apply(event(.elevated(user: "other", minutes: 30), at: -60), now: now)
        _ = windows.apply(event(.added(user: "jdoe")), now: now)
        _ = windows.apply(event(.remaining(seconds: 5), at: 0.003), now: now)
        #expect(windows.byUser["jdoe"]?.end == now.addingTimeInterval(900))
        #expect(windows.byUser["other"]?.end == now.addingTimeInterval(1740))
    }

    @Test("an older time remaining does not set the length; zero remaining closes the window")
    func olderAndZero() {
        var windows = JamfConnectElevationWindows()
        _ = windows.apply(event(.added(user: "jdoe")), now: now)
        #expect(windows.apply(event(.remaining(seconds: 2699), at: -5), now: now).isEmpty)
        #expect(windows.byUser["jdoe"]?.end == now.addingTimeInterval(900))
        let changes = windows.apply(event(.remaining(seconds: 0), at: 0.003), now: now.addingTimeInterval(0.003))
        guard case .closed? = changes.first else { Issue.record("not closed"); return }
        #expect(windows.byUser.isEmpty)
    }

    @Test("a closed window does not come back from a time remaining")
    func closedStaysClosed() {
        var windows = JamfConnectElevationWindows()
        _ = windows.apply(event(.added(user: "jdoe")), now: now)
        _ = windows.close(user: "jdoe", reason: "left admin")
        #expect(windows.apply(event(.remaining(seconds: 2699), at: 0.003), now: now).isEmpty)
        #expect(windows.byUser.isEmpty)
        _ = windows.apply(event(.added(user: "bob"), at: 1), now: now.addingTimeInterval(1))
        _ = windows.apply(event(.removed(user: "bob"), at: 1.001), now: now.addingTimeInterval(1.001))
        #expect(windows.apply(event(.remaining(seconds: 2699), at: 1.002), now: now.addingTimeInterval(1.002)).isEmpty)
        #expect(windows.byUser.isEmpty)
    }

    @Test("the older forms still work next to the new ones")
    func oldForms() {
        var windows = JamfConnectElevationWindows()
        _ = windows.apply(event(.elevated(user: "alice", minutes: 30)), now: now)
        _ = windows.apply(event(.remaining(seconds: 3000), at: 1), now: now) // never lengthens
        #expect(windows.byUser["alice"]?.end == now.addingTimeInterval(1800))
        _ = windows.apply(event(.remaining(seconds: 300), at: 1), now: now)
        #expect(windows.byUser["alice"]?.end == now.addingTimeInterval(301))
        _ = windows.apply(event(.removed(user: "alice"), at: 2), now: now)
        #expect(windows.byUser.isEmpty)
    }
}

@Suite("Jamf Connect in Self Service: observer", .serialized)
struct SelfServiceJamfConnectObserverTests {
    private final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var value = Fixture.now
        var now: Date { lock.lock(); defer { lock.unlock() }; return value }
        func advance(_ seconds: TimeInterval) { lock.lock(); value = value.addingTimeInterval(seconds); lock.unlock() }
    }

    @Test("the live JCDaemon lines open a window for the time remaining, and the removal ends it")
    func live() async {
        let clock = Clock()
        let tickets = TicketSpy()
        let observer = JamfConnectElevationObserver(
            source: FixtureLogSource(), membership: AdminMembership(admins: ["jdoe"]), ticketClearer: tickets,
            decisionLogger: nil, now: { clock.now })
        await observer.start()
        clock.advance(1) // the entries are logged just before they are read
        for line in SelfServiceFixture.grant("jdoe", at: 0) { await observer.ingest(line: line) }
        let window = await observer.activeWindow(for: "jdoe")
        #expect(abs((window?.end.timeIntervalSince(Fixture.now) ?? 0) - 2699.034) < 0.01)
        clock.advance(36)
        for line in SelfServiceFixture.end("jdoe", at: 36) { await observer.ingest(line: line) }
        #expect(await observer.activeWindow(for: "jdoe") == nil)
        #expect(tickets.clearedUsers == ["jdoe"])
        await observer.stop()
    }

    @Test("the menu app's lines open nothing")
    func menuApp() async {
        let observer = JamfConnectElevationObserver(
            source: FixtureLogSource(), membership: AdminMembership(admins: ["jdoe"]), ticketClearer: TicketSpy(),
            decisionLogger: nil, now: { Fixture.now })
        await observer.start()
        for message in ["Added user jdoe to admin group.", "jdoe elevated to admin for 45 minutes"] {
            await observer.ingest(line: Fixture.line(message, subsystem: "com.jamf.connect", image: SelfServiceFixture.menuApp))
        }
        #expect(await observer.activeWindow(for: "jdoe") == nil)
        await observer.stop()
    }

    @Test("startup restores a window from a history of the new forms, including one past the default length")
    func restore() async {
        let history = SelfServiceFixture.grant("done", at: -3 * 3600) + SelfServiceFixture.end("done", at: -3 * 3600 + 60)
            + SelfServiceFixture.grant("jdoe", at: -1200)
            + [SelfServiceFixture.daemon("Added user fresh to admin group.", at: -120)]
            + [SelfServiceFixture.daemon("Added user gone to admin group.", at: -1800)]
            + [Fixture.line("old elevated to admin for 60 minutes", at: Fixture.now.addingTimeInterval(-600))]
        // The history is replayed once, here (the source's own read is empty).
        let observer = JamfConnectElevationObserver(
            source: FixtureLogSource(), membership: AdminMembership(), ticketClearer: TicketSpy(),
            decisionLogger: nil, now: { Fixture.now })
        await observer.start()
        await observer.restore(fromHistory: history)
        let jdoe = await observer.activeWindow(for: "jdoe")
        #expect(abs((jdoe?.end.timeIntervalSince(Fixture.now) ?? 0) - (2699.034 - 1200)) < 0.01)
        #expect(await observer.activeWindow(for: "done") == nil)
        // No time remaining followed: the default length from the entry.
        #expect(abs((await observer.activeWindow(for: "fresh")?.end.timeIntervalSince(Fixture.now) ?? 0) - 780) < 0.01)
        #expect(await observer.activeWindow(for: "gone") == nil)
        #expect(await observer.activeWindow(for: "old")?.end == Fixture.now.addingTimeInterval(3000))
        // Reading the same history again leaves the restored windows as they are.
        await observer.restore(fromHistory: history)
        #expect(await observer.activeWindow(for: "jdoe")?.end == jdoe?.end)
        #expect(await observer.activeWindow(for: "fresh") != nil)
        await observer.stop()
    }
}

// MARK: - Sudo tickets

@Suite("Sudo timestamp directory", .serialized)
struct SudoTimestampDirectoryTests {
    /// sudo 1.9.15+ tickets (`501`, `502`), older name tickets, and a sub-directory.
    private func makeDirectory() throws -> String {
        let dir = try CoordinatorFixtures.tempDirectory().path
        for name in ["501", "502", "alice", "bob", ".hidden"] {
            FileManager.default.createFile(atPath: dir + "/" + name, contents: Data("t".utf8))
        }
        try FileManager.default.createDirectory(atPath: dir + "/subdir", withIntermediateDirectories: false)
        return dir
    }

    private func exists(_ dir: String, _ name: String) -> Bool {
        FileManager.default.fileExists(atPath: dir + "/" + name)
    }

    /// A lookup that knows alice (501) and bob (502), by exact name only.
    private let fixtureUIDs: @Sendable (String) -> uid_t? = { ["alice": 501, "bob": 502][$0] }

    @Test("clearing by uid removes the uid-named ticket sudo 1.9.15+ writes, and the name ticket when given")
    func clearByUID() throws {
        let dir = try makeDirectory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let tickets = SudoTimestampDirectory(path: dir, uidForName: { _ in nil })
        #expect(tickets.clearTicket(uid: 501))
        #expect(!exists(dir, "501"))
        #expect(exists(dir, "alice"), "no name given: the name ticket stays")
        #expect(tickets.clearTicket(uid: 502, user: "bob"))
        #expect(!exists(dir, "502") && !exists(dir, "bob"))
        // Only a name file left (older sudo): still removed.
        #expect(tickets.clearTicket(uid: 503, user: "alice"))
        #expect(!exists(dir, "alice"))
        #expect(!tickets.clearTicket(uid: 504, user: "nobody"))
        // An unsafe name is never used as a path; the uid file still is.
        FileManager.default.createFile(atPath: dir + "/505", contents: Data("t".utf8))
        #expect(tickets.clearTicket(uid: 505, user: "../505"))
        #expect(!exists(dir, "505") && exists(dir, "subdir"))
    }

    @Test("clearing by name resolves the exact account to its uid and removes both tickets")
    func clearByNameResolvesUID() throws {
        let dir = try makeDirectory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let tickets = SudoTimestampDirectory(path: dir, uidForName: fixtureUIDs)
        #expect(tickets.clearTicket(user: "alice"))
        #expect(!exists(dir, "501") && !exists(dir, "alice"))
        #expect(exists(dir, "502") && exists(dir, "bob"))
        for name in ["", ".", "..", "../alice", "a/b", "subdir"] {
            #expect(!tickets.clearTicket(user: name))
        }
        #expect(exists(dir, "subdir"))
        #expect(!tickets.clearTicket(user: "nobody"))
    }

    @Test("a name that does not resolve still removes its name ticket")
    func clearByUnresolvedName() throws {
        let dir = try makeDirectory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        #expect(SudoTimestampDirectory(path: dir, uidForName: { _ in nil }).clearTicket(user: "bob"))
        #expect(!exists(dir, "bob") && exists(dir, "502"))
    }

    @Test("the production lookup requires the exact canonical name")
    func exactUIDLookup() {
        #expect(SudoTimestampDirectory.exactUID("root") == 0)
        #expect(SudoTimestampDirectory.exactUID("ROOT") == nil)
        #expect(SudoTimestampDirectory.exactUID("root\0x") == nil)
        #expect(SudoTimestampDirectory.exactUID("") == nil)
        #expect(SudoTimestampDirectory.exactUID("serberus-no-such-user-7f3a") == nil)
        #expect(SudoTimestampDirectory.ticketName(uid: 501) == "501")
    }

    @Test("a symlink is removed itself, never followed")
    func symlinkNotFollowed() throws {
        let dir = try makeDirectory()
        let outside = try CoordinatorFixtures.tempDirectory().path + "/target"
        defer {
            try? FileManager.default.removeItem(atPath: dir)
            try? FileManager.default.removeItem(atPath: (outside as NSString).deletingLastPathComponent)
        }
        FileManager.default.createFile(atPath: outside, contents: Data("keep".utf8))
        try FileManager.default.createSymbolicLink(atPath: dir + "/507", withDestinationPath: outside)
        try FileManager.default.createSymbolicLink(atPath: dir + "/carol", withDestinationPath: outside)
        #expect(SudoTimestampDirectory(path: dir, uidForName: { _ in nil }).clearTicket(uid: 507))
        #expect(SudoTimestampDirectory(path: dir, uidForName: { _ in nil }).clearTicket(user: "carol"))
        #expect(FileManager.default.fileExists(atPath: outside))
    }

    @Test("clearing all removes every ticket file and leaves directories")
    func clearAll() throws {
        let dir = try makeDirectory()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        #expect(SudoTimestampDirectory(path: dir).clearAllTickets() == 5)
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir) == ["subdir"])
        #expect(SudoTimestampDirectory(path: dir + "/missing").clearAllTickets() == 0)
    }

    @Test("the safe-name rule matches pam_serberus")
    func safeNames() {
        #expect(SudoTimestampDirectory.isSafeName("alice"))
        #expect(SudoTimestampDirectory.isSafeName("..."))
        #expect(SudoTimestampDirectory.isSafeName("501"))
        #expect(!SudoTimestampDirectory.isSafeName(".."))
        #expect(!SudoTimestampDirectory.isSafeName("a/b"))
        #expect(SudoTimestampDirectory.defaultPath == "/var/db/sudo/ts")
    }
}

// MARK: - Native gate

@Suite("Native sudo for JIT admins")
struct NativeAdminGateTests {
    private let window = JamfConnectElevationWindow(user: "jdoe", start: Fixture.now,
                                                    end: Fixture.now.addingTimeInterval(600),
                                                    processImagePath: Fixture.jcDaemon)

    @Test("an active Serberus JIT grant for this user and uid is a source")
    func serberusGrant() {
        let grant = Fixture.jitGrant(user: "alice", uid: 501)
        #expect(NativeAdminGate.source(user: "alice", uid: 501, provider: .serberus, activeGrants: [grant],
                                       jamfConnectWindow: nil) == .serberusJIT(grantID: grant.grantID))
        // Another uid (a reused name) or another user never counts.
        #expect(NativeAdminGate.source(user: "alice", uid: 502, provider: .serberus, activeGrants: [grant],
                                       jamfConnectWindow: nil) == nil)
        #expect(NativeAdminGate.source(user: "bob", uid: 501, provider: .serberus, activeGrants: [grant],
                                       jamfConnectWindow: nil) == nil)
    }

    @Test("a binary grant is not a source; a Jamf Connect window for the user is")
    func otherSources() {
        let binary = Grant(user: "jdoe", uid: 501, ruleID: "r", profileKey: "p", teamID: "", binaryHash: "h",
                           canonicalPath: "/bin/echo", grantedAt: Fixture.now, expiresAt: nil, policyVersion: "1")
        #expect(NativeAdminGate.source(user: "jdoe", uid: 501, provider: .jamfConnect, activeGrants: [binary],
                                       jamfConnectWindow: nil) == nil)
        #expect(NativeAdminGate.source(user: "jdoe", uid: 501, provider: .jamfConnect, activeGrants: [binary],
                                       jamfConnectWindow: window) == .jamfConnect(window))
        #expect(NativeAdminGate.source(user: "other", uid: 501, provider: .jamfConnect, activeGrants: [],
                                       jamfConnectWindow: window) == nil)
    }

    @Test("each source counts only under its own provider: a Serberus grant under serberus, a Jamf Connect window under jamf_connect")
    func sourceNeedsItsProvider() {
        let grant = Fixture.jitGrant(user: "jdoe", uid: 501)
        for provider in [JITAdminProvider.disabled, .jamfConnect] {
            #expect(NativeAdminGate.source(user: "jdoe", uid: 501, provider: provider, activeGrants: [grant],
                                           jamfConnectWindow: nil) == nil)
        }
        for provider in [JITAdminProvider.disabled, .serberus] {
            #expect(NativeAdminGate.source(user: "jdoe", uid: 501, provider: provider, activeGrants: [],
                                           jamfConnectWindow: window) == nil)
        }
    }

    @Test("a source counts only with a definite, live admin membership")
    func membershipRequired() async {
        let membership = AdminMembership(admins: ["jdoe"])
        #expect(await NativeAdminGate.evaluate(user: "jdoe", uid: 501, provider: .jamfConnect, activeGrants: [],
                                               jamfConnectWindow: window, membership: membership) == .jamfConnect(window))
        await membership.set(admin: "jdoe", false)
        #expect(await NativeAdminGate.evaluate(user: "jdoe", uid: 501, provider: .jamfConnect, activeGrants: [],
                                               jamfConnectWindow: window, membership: membership) == nil)
        await membership.set(admin: "jdoe", true)
        await membership.setFailing(true)
        #expect(await NativeAdminGate.evaluate(user: "jdoe", uid: 501, provider: .jamfConnect, activeGrants: [],
                                               jamfConnectWindow: window, membership: membership) == nil)
    }
}

// MARK: - JIT manager: tickets and GeneratedUID

@Suite("JIT demotion clears tickets and honours GeneratedUID", .serialized)
struct JITTicketAndGeneratedUIDTests {
    private let guid = "11111111-2222-3333-4444-555555555555"

    @Test("a promotion records the account's GeneratedUID; a demotion clears the ticket")
    func recordAndClear() async throws {
        let store = ListGrantStore()
        let membership = AdminMembership()
        let tickets = TicketSpy()
        let manager = JITAdminManager(
            policyProvider: { JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"]) },
            membership: membership, grantStore: store, decisionLogger: nil, integrityLogger: nil,
            now: { Fixture.now }, monotonicNow: { nil }, ticketClearer: tickets,
            generatedUIDLookup: { _ in self.guid })
        let result = await manager.requestElevation(user: "alice", uid: 501, justification: "a long enough reason")
        #expect(result.outcome == .granted)
        #expect(await store.all().first?.generatedUID == guid)
        #expect(tickets.clearedUsers.isEmpty)

        #expect(await manager.endElevation(user: "alice"))
        #expect(tickets.clearedUsers == ["alice"])
        #expect(tickets.clearedUIDs == [501])
    }

    @Test("kill-switch demote-all and the teardown sweep clear tickets")
    func demoteAllAndSweep() async {
        let store = ListGrantStore([Fixture.jitGrant(user: "alice", uid: 501), Fixture.jitGrant(user: "bob", uid: 502)])
        let membership = AdminMembership(admins: ["alice", "bob"])
        let tickets = TicketSpy()
        let manager = JITAdminManager(
            policyProvider: { .disabledDefault }, membership: membership, grantStore: store,
            decisionLogger: nil, integrityLogger: nil, now: { Fixture.now }, monotonicNow: { nil },
            ticketClearer: tickets)
        #expect(await manager.demoteAll() == 2)
        #expect(tickets.clearedUsers.sorted() == ["alice", "bob"])
        #expect(tickets.clearedUIDs.sorted() == [501, 502])

        let sweepStore = ListGrantStore([Fixture.jitGrant(user: "carol", uid: 503)])
        let sweepTickets = TicketSpy()
        let report = await JITDemotionSweep.run(grantStore: sweepStore, membership: AdminMembership(admins: ["carol"]),
                                                ticketClearer: sweepTickets, now: Fixture.now)
        #expect(report.demoted == ["carol"])
        #expect(sweepTickets.clearedUsers == ["carol"])
        #expect(sweepTickets.clearedUIDs == [503])
    }

    @Test("a uid reused by a NEW account (different GeneratedUID) is not demoted; the original is retired")
    func uidReusedNotDemoted() async {
        let grant = Fixture.jitGrant(user: "alice", uid: 501, generatedUID: guid)
        let store = ListGrantStore([grant])
        let membership = AdminMembership(admins: ["newhire"])
        await membership.setMissingRecord("alice")
        let tickets = TicketSpy()
        let resolver = DirectoryJITAccountResolver(
            byName: { _ in .notFound }, byUID: { _ in .found("newhire") },
            localNode: AbsentLocalNode(), generatedUIDForUID: { _ in "99999999-8888-7777-6666-555555555555" })
        let manager = JITAdminManager(
            policyProvider: { .disabledDefault }, membership: membership, grantStore: store,
            decisionLogger: nil, integrityLogger: nil, now: { Fixture.now }, monotonicNow: { nil },
            accountResolver: resolver, ticketClearer: tickets)
        #expect(await manager.demoteAll() == 1)                      // the row is retired…
        #expect(await membership.removed.isEmpty)                    // …and nobody was removed from admin
        #expect(await store.all().first?.revokedAt != nil)
        // The uid now belongs to newhire: only the old name's ticket is cleared.
        #expect(tickets.clearedUIDs.isEmpty)
        #expect(tickets.clearedUsers == ["alice"])
    }

    @Test("the same GeneratedUID under a new name is a rename and is demoted")
    func renameDemoted() async {
        let grant = Fixture.jitGrant(user: "alice", uid: 501, generatedUID: guid)
        let store = ListGrantStore([grant])
        let membership = AdminMembership(admins: ["alice2"])
        await membership.setMissingRecord("alice")
        let resolver = DirectoryJITAccountResolver(
            byName: { _ in .notFound }, byUID: { _ in .found("alice2") },
            localNode: AbsentLocalNode(), generatedUIDForUID: { _ in self.guid.lowercased() })
        let manager = JITAdminManager(
            policyProvider: { .disabledDefault }, membership: membership, grantStore: store,
            decisionLogger: nil, integrityLogger: nil, now: { Fixture.now }, monotonicNow: { nil },
            accountResolver: resolver, ticketClearer: TicketSpy())
        #expect(await manager.demoteAll() == 1)
        #expect(await membership.removed == ["alice2"])
    }

    @Test("the resolver: rename, reuse, unreadable GeneratedUID, and rows without one")
    func resolver() async {
        func resolver(current: String?) -> DirectoryJITAccountResolver {
            DirectoryJITAccountResolver(byName: { _ in .notFound }, byUID: { _ in .found("other") },
                                        localNode: AbsentLocalNode(), generatedUIDForUID: { _ in current })
        }
        #expect(await resolver(current: guid).identify(user: "alice", uid: 501, generatedUID: guid) == .renamed(to: "other"))
        #expect(await resolver(current: "AAAA").identify(user: "alice", uid: 501, generatedUID: guid) == .uidReused(by: "other"))
        guard case .undetermined = await resolver(current: nil).identify(user: "alice", uid: 501, generatedUID: guid) else {
            Issue.record("an unreadable GeneratedUID must not decide"); return
        }
        // No GeneratedUID recorded (a row from before schema 3): a rename, as before.
        #expect(await resolver(current: "AAAA").identify(user: "alice", uid: 501, generatedUID: nil) == .renamed(to: "other"))
        #expect(await resolver(current: "AAAA").identify(user: "alice", uid: 501) == .renamed(to: "other"))
    }

    @Test("the synthesized GeneratedUID for a uid with no record is not an account's")
    func synthesized() {
        #expect(LocalAccounts.isSynthesizedGeneratedUID("FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F5"))
        #expect(!LocalAccounts.isSynthesizedGeneratedUID(guid))
        // System accounts carry the fixed FFFFEEEE… form, derived from the uid
        // alone, so it cannot tell a reused uid apart: reported as none.
        #expect(LocalAccounts.generatedUID(uid: 0) == nil)
        if getuid() >= 501 { #expect(LocalAccounts.generatedUID(uid: getuid()) != nil) }
    }
}

private struct AbsentLocalNode: LocalDirectoryProbing {
    func userRecord(named name: String) async -> LocalNodeLookup { .absent }
    func userRecord(uid: uid_t) async -> LocalNodeLookup { .absent }
    func networkDirectoryConfigured() async -> Bool? { false }
}

// MARK: - Daemon: native reply, gating transition, kill switch

@Suite("Daemon — native sudo, ticket clearing, kill switch", .serialized)
struct DaemonNativeTests {
    private func config(enabled: Bool = true, mode: EnforcementMode = .enforce) -> SerberusConfig {
        SerberusConfig(
            jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil,
            daemonEnabled: enabled, enforcementMode: mode, sudoCacheSeconds: 0,
            promptTimeoutSeconds: 60, pamBypass: PAMBypass(groups: ["admin"], users: [])
        )
    }

    private func makeController(store: GrantMaintaining, membership: GroupMembershipControlling,
                                tickets: SudoTicketClearing = TicketSpy(),
                                observer: JamfConnectElevationObserving? = nil,
                                decisionLogger: DecisionLogger? = nil,
                                paths: DaemonPaths) -> DaemonController {
        DaemonController(
            paths: paths, machServiceName: "test.unused",
            prefsReader: ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [:])),
            grantStore: store,
            stateController: DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil),
            integrityLogger: nil, decisionLogger: decisionLogger,
            pppc: StaticPPPCStatus(ready: true), authDB: NoopAuthorizationDBApplier(),
            membership: membership, sudoTickets: tickets, jamfConnectObserver: observer,
            lastKnownGood: InMemoryLastKnownGoodConfigStore(initial: CoordinatorFixtures.lastKnownGoodConfig()),
            inspector: StaticBinaryIdentityInspector(identity: BinaryIdentity(
                canonicalPath: "", teamID: nil, sha256: "", signingStatus: .unsigned)),
            deviceSerial: "TESTSERIAL", now: { Fixture.now })
    }

    private let sudo = PAMRequest(user: "root", kind: .sudo(command: "/bin/echo", argv: ["hi"], tty: nil))

    @Test("a JIT admin with an active grant who is in admin right now gets the native reply, logged")
    func nativeForJITAdmin() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let paths = DaemonPaths.ephemeral(in: dir)
        let membership = AdminMembership(admins: ["root"])
        let logger = try DecisionLogger(directory: paths.logDirectory, keyProvider: InMemoryKeyProvider.random())
        let controller = makeController(store: ListGrantStore([Fixture.jitGrant()]), membership: membership,
                                        decisionLogger: logger, paths: paths)
        await controller.loadPolicyForTesting(profiles: [], config: config())
        await controller.loadJITPolicyForTesting(JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"]))

        let response = await controller.handlePAM(sudo)
        #expect(response.native)
        #expect(response.ruleID == "jit-native")
        let files = try FileManager.default.contentsOfDirectory(at: paths.logDirectory, includingPropertiesForKeys: nil)
        let logged = files.compactMap { try? String(contentsOf: $0, encoding: .utf8) }.joined()
        #expect(logged.contains("jit-native"))

        // Out of admin (demoted, or removed by hand): gated again — no rule, so denied.
        await membership.set(admin: "root", false)
        let gated = await controller.handlePAM(sudo)
        #expect(!gated.native)
        #expect(gated.decision == .deny)
    }

    @Test("an admin without a JIT grant or window is gated as before")
    func noSourceNoNative() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let controller = makeController(store: ListGrantStore(), membership: AdminMembership(admins: ["root"]),
                                        paths: DaemonPaths.ephemeral(in: dir))
        await controller.loadPolicyForTesting(profiles: [], config: config())
        #expect(!(await controller.handlePAM(sudo)).native)
    }

    @Test("an observed Jamf Connect window plus live admin membership is native, only for the jamf_connect provider")
    func nativeForJamfConnect() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let observer = JamfConnectElevationObserver(
            source: FixtureLogSource(), membership: AdminMembership(admins: ["root"]), ticketClearer: TicketSpy(),
            decisionLogger: nil, now: { Fixture.now })
        let controller = makeController(store: ListGrantStore(), membership: AdminMembership(admins: ["root"]),
                                        observer: observer, paths: DaemonPaths.ephemeral(in: dir))
        await controller.loadPolicyForTesting(profiles: [], config: config())
        await controller.loadJITPolicyForTesting(JITAdminPolicy(provider: .jamfConnect))
        await observer.ingest(line: Fixture.line("root elevated to admin for 30 minutes"))

        let response = await controller.handlePAM(sudo)
        #expect(response.native)
        #expect(response.ruleID == "jit-native-jamf-connect")

        // Switching the provider away stops the observer (and ends its windows).
        await controller.loadJITPolicyForTesting(JITAdminPolicy(provider: .serberus, eligibleGroups: ["x"]))
        #expect(await observer.activeWindow(for: "root") == nil)
        #expect(!(await controller.handlePAM(sudo)).native)
    }

    @Test("moving into enforce from any other state clears every sudo ticket, once")
    func enforceTransitionClearsTickets() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let tickets = TicketSpy()
        let controller = makeController(store: ListGrantStore(), membership: AdminMembership(), tickets: tickets,
                                        paths: DaemonPaths.ephemeral(in: dir))
        await controller.adoptConfigForTesting(config(mode: .audit))
        #expect(tickets.clearAllCalls == 0)
        await controller.adoptConfigForTesting(config(mode: .enforce))
        #expect(tickets.clearAllCalls == 1)
        await controller.adoptConfigForTesting(config(mode: .enforce))
        #expect(tickets.clearAllCalls == 1)                           // no transition, no clear
        await controller.adoptConfigForTesting(config(enabled: false))
        await controller.adoptConfigForTesting(config(mode: .enforce))
        #expect(tickets.clearAllCalls == 2)                           // back from the kill switch
        await controller.adoptConfigForTesting(config(), awaitingConfig: true)
        await controller.adoptConfigForTesting(config())
        #expect(tickets.clearAllCalls == 3)                           // back from bootstrap
    }

    @Test("kill switch: no native reply; the Jamf Connect hand-off stays described and is not refused as 'turned off'")
    func killSwitch() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let controller = makeController(store: ListGrantStore([Fixture.jitGrant()]),
                                        membership: AdminMembership(admins: ["root"]),
                                        paths: DaemonPaths.ephemeral(in: dir))
        await controller.loadPolicyForTesting(profiles: [], config: config(enabled: false))
        #expect(!(await controller.handlePAM(sudo)).native)

        await controller.loadJITPolicyForTesting(JITAdminPolicy(provider: .jamfConnect))
        let info = await controller.jitAdminInfo()
        #expect(info.available)
        #expect(info.provider == .jamfConnect)
        #expect(info.jamfConnectCommand == JamfConnectCommand.jamfConnectDefault)
        // Serberus JIT stays refused under the kill switch.
        await controller.loadJITPolicyForTesting(JITAdminPolicy(provider: .serberus, eligibleGroups: ["developers"]))
        let refused = await controller.requestAdminElevation(user: "root", justification: "a long enough reason")
        #expect(refused.outcome == .denied)
        #expect(refused.message.contains("turned off"))
    }
}

// MARK: - Daemon: a JIT policy that turns Serberus JIT off

/// What MDM does to a JIT profile whose provider was `serberus`.
enum JITProfileChange: String, CaseIterable, Sendable {
    case disabled
    case jamfConnect = "jamf_connect"
    case removed = "profile removed"

    /// The provider the profile now delivers; nil once there is no profile.
    var provider: String? { self == .removed ? nil : rawValue }
}

@Suite("Daemon — a provider other than serberus ends open Serberus JIT windows", .serialized)
struct DaemonJITProviderOffTests {
    private let sudo = PAMRequest(user: "root", kind: .sudo(command: "/bin/echo", argv: ["hi"], tty: nil))

    /// Managed preferences: an enforcing config, and a JIT profile with
    /// `provider`, or none.
    private func domains(jit provider: String?) -> [String: [String: any Sendable]] {
        var domains: [String: [String: any Sendable]] = [BundleConfig.configDomain: CoordinatorFixtures.enforceableConfig]
        if let provider {
            domains[BundleConfig.jitDomain] = ["provider": provider, "eligibleGroups": ["developers"]]
        }
        return domains
    }

    private func makeController(source: MutablePreferencesSource, store: GrantMaintaining,
                                membership: GroupMembershipControlling, tickets: SudoTicketClearing,
                                observer: JamfConnectElevationObserving? = nil, paths: DaemonPaths) -> DaemonController {
        DaemonController(
            paths: paths, machServiceName: "test.unused",
            prefsReader: ManagedPreferencesReader(source: source),
            grantStore: store,
            stateController: DaemonStateController(statePlist: paths.statePlist, integrityLogger: nil),
            integrityLogger: nil,
            pppc: StaticPPPCStatus(ready: true), authDB: NoopAuthorizationDBApplier(),
            membership: membership, sudoTickets: tickets, jamfConnectObserver: observer,
            lastKnownGood: InMemoryLastKnownGoodConfigStore(initial: CoordinatorFixtures.lastKnownGoodConfig()),
            inspector: StaticBinaryIdentityInspector(identity: BinaryIdentity(
                canonicalPath: "", teamID: nil, sha256: "", signingStatus: .unsigned)),
            deviceSerial: "TESTSERIAL", now: { Fixture.now })
    }

    /// Installs the JIT manager as `start()` builds it, reading the daemon's live policy.
    private func installManager(in controller: DaemonController, store: GrantMaintaining,
                                membership: GroupMembershipControlling,
                                tickets: SudoTicketClearing) async -> JITAdminManager {
        let manager = JITAdminManager(
            policyProvider: { [weak controller] in await controller?.liveJITPolicy() ?? .disabledDefault },
            membership: membership, grantStore: store, decisionLogger: nil, integrityLogger: nil,
            now: { Fixture.now }, monotonicNow: { nil }, ticketClearer: tickets)
        await controller.setJITManagerForTesting(manager)
        return manager
    }

    @Test("a reload that turns Serberus JIT off ends jit-native at once, and the tick right after it demotes the window",
          arguments: JITProfileChange.allCases)
    func reloadEndsWindow(change: JITProfileChange) async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let source = MutablePreferencesSource(domains: domains(jit: "serberus"))
        let store = ListGrantStore()
        let membership = AdminMembership()
        let tickets = TicketSpy()
        let controller = makeController(source: source, store: store, membership: membership, tickets: tickets,
                                        paths: DaemonPaths.ephemeral(in: dir))
        await controller.reloadPolicyIfChanged()
        let manager = await installManager(in: controller, store: store, membership: membership, tickets: tickets)

        // A window under serberus: root is promoted and gets native sudo.
        let granted = await controller.requestAdminElevation(user: "root", justification: "a long enough reason")
        #expect(granted.outcome == .granted)
        #expect(await controller.handlePAM(sudo).ruleID == "jit-native")
        #expect(await controller.expireOverdueJITForTesting() == 0)

        // MDM turns Serberus JIT off, and the reload pass adopts it.
        source.set(domains(jit: change.provider))
        await controller.reloadPolicyIfChanged()
        #expect(await controller.liveJITPolicy().provider != .serberus)
        // root is still in admin until the sweep, but sudo is gated again at once.
        #expect(try await membership.isMember(user: "root", group: "admin"))
        #expect(!(await controller.handlePAM(sudo)).native)

        // The tick's sweep, which runs right after the reload pass, ends the window.
        #expect(await controller.expireOverdueJITForTesting() == 1)
        #expect(await membership.removed == ["root"])
        #expect(await store.all().allSatisfy { $0.revokedAt != nil })
        #expect(tickets.clearedUIDs == [0])
        #expect(await controller.expireOverdueJITForTesting() == 0)
        await manager.stop()
    }

    @Test("a daemon that starts under a provider other than serberus demotes the open window instead of re-arming it",
          arguments: JITProfileChange.allCases)
    func startupEndsWindow(change: JITProfileChange) async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let source = MutablePreferencesSource(domains: domains(jit: change.provider))
        let store = ListGrantStore([Fixture.jitGrant()])            // root's window, still open
        let membership = AdminMembership(admins: ["root"])
        let tickets = TicketSpy()
        let controller = makeController(source: source, store: store, membership: membership, tickets: tickets,
                                        paths: DaemonPaths.ephemeral(in: dir))
        await controller.reloadPolicyIfChanged()                    // the policy the daemon starts with
        let manager = await installManager(in: controller, store: store, membership: membership, tickets: tickets)

        await controller.settleJITAdminsAtStartup(manager)
        #expect(await membership.removed == ["root"])
        #expect(await store.all().allSatisfy { $0.revokedAt != nil })
        #expect(tickets.clearedUIDs == [0])
        #expect(!(await controller.handlePAM(sudo)).native)
        await manager.stop()
    }

    @Test("under serberus nothing changes: startup re-arms the window, native sudo works, and a reload that only changes eligibility keeps it")
    func serberusKeepsWindow() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let source = MutablePreferencesSource(domains: domains(jit: "serberus"))
        let store = ListGrantStore([Fixture.jitGrant()])
        let membership = AdminMembership(admins: ["root"])
        let tickets = TicketSpy()
        let controller = makeController(source: source, store: store, membership: membership, tickets: tickets,
                                        paths: DaemonPaths.ephemeral(in: dir))
        await controller.reloadPolicyIfChanged()
        let manager = await installManager(in: controller, store: store, membership: membership, tickets: tickets)

        await controller.settleJITAdminsAtStartup(manager)
        #expect(await store.all().allSatisfy { $0.revokedAt == nil })
        #expect(await controller.handlePAM(sudo).ruleID == "jit-native")
        #expect(await controller.expireOverdueJITForTesting() == 0)

        // Eligibility is checked when a window is requested, not while it is open.
        var changed = domains(jit: "serberus")
        changed[BundleConfig.jitDomain]?["eligibleGroups"] = ["someone-else"]
        source.set(changed)
        await controller.reloadPolicyIfChanged()
        #expect(await controller.handlePAM(sudo).ruleID == "jit-native")
        #expect(await controller.expireOverdueJITForTesting() == 0)
        #expect(await membership.removed.isEmpty)
        #expect(tickets.clearedUIDs.isEmpty)
        await manager.stop()
    }

    @Test("serberus → jamf_connect ends the Serberus window and leaves an observed Jamf Connect window alone")
    func jamfConnectWindowUntouched() async throws {
        let dir = try CoordinatorFixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let source = MutablePreferencesSource(domains: domains(jit: "serberus"))
        let store = ListGrantStore([Fixture.jitGrant(user: "alice", uid: 501)])   // alice: a Serberus window
        let membership = AdminMembership(admins: ["alice", "root"])               // root: elevated by Jamf Connect
        let tickets = TicketSpy()
        let observerTickets = TicketSpy()
        let observer = JamfConnectElevationObserver(
            source: FixtureLogSource(), membership: membership, ticketClearer: observerTickets,
            decisionLogger: nil, now: { Fixture.now })
        let controller = makeController(source: source, store: store, membership: membership, tickets: tickets,
                                        observer: observer, paths: DaemonPaths.ephemeral(in: dir))
        await controller.reloadPolicyIfChanged()
        let manager = await installManager(in: controller, store: store, membership: membership, tickets: tickets)

        source.set(domains(jit: "jamf_connect"))
        await controller.reloadPolicyIfChanged()                                  // starts the observer
        await observer.ingest(line: Fixture.line("root elevated to admin for 30 minutes"))

        #expect(await controller.expireOverdueJITForTesting() == 1)              // alice's window ends…
        #expect(await membership.removed == ["alice"])
        #expect(await observer.activeWindow(for: "root") != nil)                  // …root's Jamf Connect one does not
        #expect(observerTickets.clearedUsers.isEmpty)
        let response = await controller.handlePAM(sudo)
        #expect(response.native)
        #expect(response.ruleID == "jit-native-jamf-connect")
        await observer.stop()
        await manager.stop()
    }
}

// MARK: - Jamf Connect: anchored messages, two clocks, history, uid, child process

@Suite("Jamf Connect observation hardening", .serialized)
struct JamfConnectHardeningTests {
    private let now = Fixture.now
    private let boot = "boot-A"

    private func event(_ kind: JamfConnectElevationEvent.Kind, at offset: TimeInterval = 0) -> JamfConnectElevationEvent {
        JamfConnectElevationEvent(kind: kind, date: now.addingTimeInterval(offset), processImagePath: Fixture.jcDaemon)
    }

    @Test("a known message inside a longer one is not an elevation entry", arguments: [
        "Reason: jdoe elevated to admin for 30 minutes",
        "jdoe elevated to admin for 30 minutes because mallory said so",
        "mallory wrote: \"jdoe\" elevated to admin for 480 minutes",
        "Note: Removed user bob from admin group",
        "Removed user bob from admin group and more",
        "Removed user bob from administrators",
        "User elevation time remaining: 04:59 (spoofed)",
        "prefix User elevation time remaining: 04:59",
    ])
    func unanchoredRefused(message: String) {
        #expect(JamfConnectLogParser.parseMessage(message) == nil)
    }

    @Test("surrounding white space is tolerated")
    func whitespaceTolerated() {
        #expect(JamfConnectLogParser.parseMessage("  jdoe elevated to admin for 30 minutes\n")
                == .elevated(user: "jdoe", minutes: 30))
    }

    @Test("a window ends on the continuous clock even if the wall clock is set back")
    func continuousDeadline() {
        var windows = JamfConnectElevationWindows()
        let opened = MonotonicInstant(bootSessionID: boot, nanoseconds: 1_000_000_000_000)
        _ = windows.apply(event(.elevated(user: "jdoe", minutes: 30)), now: now, monotonic: opened)
        #expect(windows.byUser["jdoe"]?.continuousDeadline == MonotonicInstant(bootSessionID: boot,
                                                               nanoseconds: 1_000_000_000_000 + 1800 * 1_000_000_000))
        // 31 minutes later on the continuous clock, with the wall clock set back
        // to 10 minutes after the start: over.
        let later = MonotonicInstant(bootSessionID: boot, nanoseconds: 1_000_000_000_000 + 1860 * 1_000_000_000)
        #expect(windows.active(for: "jdoe", at: now.addingTimeInterval(600), monotonic: later) == nil)
        #expect(windows.expire(now: now.addingTimeInterval(600), monotonic: later).count == 1)
        #expect(windows.byUser.isEmpty)
    }

    @Test("a deadline from another boot session falls back to the wall clock")
    func otherBootSession() {
        var windows = JamfConnectElevationWindows()
        _ = windows.apply(event(.elevated(user: "jdoe", minutes: 30)), now: now,
                          monotonic: MonotonicInstant(bootSessionID: boot, nanoseconds: 5))
        let other = MonotonicInstant(bootSessionID: "boot-B", nanoseconds: 0)
        #expect(windows.active(for: "jdoe", at: now.addingTimeInterval(60), monotonic: other) != nil)
        #expect(windows.active(for: "jdoe", at: now.addingTimeInterval(1800), monotonic: other) == nil)
    }

    @Test("a wall clock before the window's start counts as over")
    func clockBeforeStart() {
        var windows = JamfConnectElevationWindows()
        _ = windows.apply(event(.elevated(user: "jdoe", minutes: 30)), now: now)
        #expect(windows.active(for: "jdoe", at: now.addingTimeInterval(-1)) == nil)
        #expect(windows.expire(now: now.addingTimeInterval(-1)).count == 1)
        // An entry dated after "now" opens nothing.
        var fresh = JamfConnectElevationWindows()
        #expect(fresh.apply(event(.elevated(user: "jdoe", minutes: 30), at: 60), now: now).isEmpty)
    }

    @Test("a history read that lands late does not re-open a window a live removal closed")
    func historyAfterLiveRemoval() async {
        let tickets = TicketSpy()
        let observer = JamfConnectElevationObserver(
            source: FixtureLogSource(), membership: AdminMembership(admins: ["jdoe", "kim"]), ticketClearer: tickets,
            decisionLogger: nil, now: { Fixture.now }, monotonicNow: { nil })
        await observer.start()
        // Live: the removal arrives while the history read is still running.
        await observer.ingest(line: Fixture.line("Removed user jdoe from admin group", at: Fixture.now.addingTimeInterval(-30)))
        await observer.restore(fromHistory: [
            Fixture.line("jdoe elevated to admin for 60 minutes", at: Fixture.now.addingTimeInterval(-600)),
            Fixture.line("kim elevated to admin for 60 minutes", at: Fixture.now.addingTimeInterval(-600)),
        ])
        #expect(await observer.activeWindow(for: "jdoe") == nil)
        #expect(await observer.activeWindow(for: "kim") != nil)  // no live entry for kim: restored
        await observer.stop()
    }

    @Test("the window records the account's uid, and its end clears the uid ticket")
    func uidTicket() async {
        let tickets = TicketSpy()
        let observer = JamfConnectElevationObserver(
            source: FixtureLogSource(), membership: AdminMembership(admins: ["jdoe"]), ticketClearer: tickets,
            decisionLogger: nil, now: { Fixture.now }, monotonicNow: { nil },
            uidForUser: { $0 == "jdoe" ? 501 : nil })
        await observer.start()
        await observer.ingest(line: Fixture.line("jdoe elevated to admin for 30 minutes"))
        #expect(await observer.activeWindow(for: "jdoe")?.uid == 501)
        await observer.ingest(line: Fixture.line("Removed user jdoe from admin group", at: Fixture.now.addingTimeInterval(60)))
        #expect(tickets.clearedUIDs == [501])
        #expect(tickets.clearedUsers == ["jdoe"])
        await observer.stop()
    }

    private final class ExitFlag: @unchecked Sendable {
        private let lock = NSLock()
        private var value = false
        func set() { lock.lock(); value = true; lock.unlock() }
        var isSet: Bool { lock.lock(); defer { lock.unlock() }; return value }
    }

    private func waitFor(_ flag: ExitFlag, seconds: Double) async -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if flag.isSet { return true }
            try? await Task.sleep(for: .milliseconds(50))
        }
        return flag.isSet
    }

    @Test("stopping the reader ends the child's whole process group")
    func stopKillsGroup() async throws {
        let exited = ExitFlag()
        let reader = ChildReader(path: "/bin/sleep", arguments: ["300"], onLine: { _ in }, onExit: { exited.set() })
        #expect(reader.start())
        let group = try #require(reader.processGroup)
        try? await Task.sleep(for: .milliseconds(200))
        reader.stop()
        #expect(await waitFor(exited, seconds: 5))
        try? await Task.sleep(for: .milliseconds(100))
        #expect(kill(-group, 0) == -1 && errno == ESRCH)
    }

    @Test("the child exits by itself when the parent's lifeline closes (the parent died)")
    func lifelineEndsChild() async throws {
        let exited = ExitFlag()
        let reader = ChildReader(path: "/bin/sleep", arguments: ["300"], onLine: { _ in }, onExit: { exited.set() })
        #expect(reader.start())
        let group = try #require(reader.processGroup)
        try? await Task.sleep(for: .milliseconds(200))
        reader.closeLifeline() // what the kernel does when this process dies
        #expect(await waitFor(exited, seconds: 5))
        try? await Task.sleep(for: .milliseconds(100))
        #expect(kill(-group, 0) == -1 && errno == ESRCH)
    }

    @Test("the reader still delivers the command's output line by line")
    func deliversLines() async {
        let exited = ExitFlag()
        let lines = LineBox()
        let reader = ChildReader(path: "/bin/echo", arguments: ["one"], onLine: { lines.append($0) },
                                 onExit: { exited.set() })
        #expect(reader.start())
        #expect(await waitFor(exited, seconds: 5))
        #expect(lines.all == ["one"])
    }

    private final class LineBox: @unchecked Sendable {
        private let lock = NSLock()
        private var lines: [String] = []
        func append(_ line: String) { lock.lock(); lines.append(line); lock.unlock() }
        var all: [String] { lock.lock(); defer { lock.unlock() }; return lines }
    }
}
