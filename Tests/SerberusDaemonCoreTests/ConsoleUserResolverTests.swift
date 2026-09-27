import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

/// P3-daemon-sources: the pure trust core of ``ConsoleUserResolver``. Each case
/// pins the invariant that the emitted name/home come only from the injected
/// passwd entry and that every off-path yields a rejection (no console user
/// downstream ⇒ no enrollment).
@Suite("Console user resolver")
struct ConsoleUserResolverTests {

    /// A passwd lookup that returns a fixed entry for a specific uid, else nil.
    private func passwd(uid: uid_t, name: String, home: String) -> (uid_t) -> PasswdEntry? {
        { queried in queried == uid ? PasswdEntry(name: name, homeDir: home) : nil }
    }

    @Test("valid console pair resolves to the passwd name and home")
    func resolvesValid() {
        let result = ConsoleUserResolver.evaluate(
            scName: "alice", scUID: 501, minimumUID: 501,
            passwd: passwd(uid: 501, name: "alice", home: "/Users/alice"))
        #expect(result == .resolved(ConsoleUser(uid: 501, name: "alice", homeDir: "/Users/alice")))
    }

    @Test("uid at the minimum boundary is accepted")
    func minimumBoundaryAccepted() {
        let result = ConsoleUserResolver.evaluate(
            scName: "edge", scUID: 501, minimumUID: 501,
            passwd: passwd(uid: 501, name: "edge", home: "/Users/edge"))
        if case .resolved = result {} else { Issue.record("expected resolved at boundary") }
    }

    @Test("nil console name is rejected")
    func nilNameRejected() {
        let result = ConsoleUserResolver.evaluate(
            scName: nil, scUID: 501, minimumUID: 501,
            passwd: passwd(uid: 501, name: "alice", home: "/Users/alice"))
        #expect(result == .rejected(.noConsoleUser))
    }

    @Test("empty console name is rejected")
    func emptyNameRejected() {
        let result = ConsoleUserResolver.evaluate(
            scName: "", scUID: 501, minimumUID: 501,
            passwd: passwd(uid: 501, name: "alice", home: "/Users/alice"))
        #expect(result == .rejected(.noConsoleUser))
    }

    @Test("loginwindow is rejected")
    func loginWindowRejected() {
        let result = ConsoleUserResolver.evaluate(
            scName: "loginwindow", scUID: 0, minimumUID: 501,
            passwd: passwd(uid: 0, name: "root", home: "/var/root"))
        #expect(result == .rejected(.loginWindow))
    }

    @Test("root uid is rejected as a system user")
    func rootRejected() {
        let result = ConsoleUserResolver.evaluate(
            scName: "root", scUID: 0, minimumUID: 501,
            passwd: passwd(uid: 0, name: "root", home: "/var/root"))
        #expect(result == .rejected(.systemUser(uid: 0)))
    }

    @Test("sub-minimum uid is rejected as a system user")
    func subMinimumRejected() {
        let result = ConsoleUserResolver.evaluate(
            scName: "_svc", scUID: 200, minimumUID: 501,
            passwd: passwd(uid: 200, name: "_svc", home: "/var/empty"))
        #expect(result == .rejected(.systemUser(uid: 200)))
    }

    @Test("unknown uid (no passwd record) is rejected")
    func unknownUIDRejected() {
        let result = ConsoleUserResolver.evaluate(
            scName: "ghost", scUID: 777, minimumUID: 501,
            passwd: { _ in nil })
        #expect(result == .rejected(.unknownUID(uid: 777)))
    }

    @Test("passwd name disagreeing with the console name is refused")
    func nameMismatchRejected() {
        let result = ConsoleUserResolver.evaluate(
            scName: "alice", scUID: 501, minimumUID: 501,
            passwd: passwd(uid: 501, name: "bob", home: "/Users/bob"))
        #expect(result == .rejected(.nameMismatch(scName: "alice", pwName: "bob")))
    }

    @Test("non-absolute passwd home is refused")
    func nonAbsoluteHomeRejected() {
        let result = ConsoleUserResolver.evaluate(
            scName: "alice", scUID: 501, minimumUID: 501,
            passwd: passwd(uid: 501, name: "alice", home: "Users/alice"))
        #expect(result == .rejected(.nameMismatch(scName: "alice", pwName: "alice")))
    }

    @Test("emitted identity comes from passwd, not the console name string")
    func identityFromPasswd() {
        // Same name in both, but the home can only come from passwd.
        let result = ConsoleUserResolver.evaluate(
            scName: "carol", scUID: 502, minimumUID: 501,
            passwd: passwd(uid: 502, name: "carol", home: "/Users/carol-real"))
        #expect(result == .resolved(ConsoleUser(uid: 502, name: "carol", homeDir: "/Users/carol-real")))
    }
}
