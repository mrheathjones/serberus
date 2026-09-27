import Foundation
import Testing
@testable import PrivMgrCore

/// P2-resolver-core: the pure ``IDPGroupResolver``. Every case pins the
/// containment invariant (output is only `[]` or `[consoleUser.name]`) and the
/// fail-safe direction (disabled / no-config / no-console-user / missing-source
/// / refusal / no-match all enroll no one).
@Suite("IDP group resolver")
struct IDPGroupResolverTests {

    // MARK: Test doubles

    /// A source that returns a fixed claim, nil, or throws a fixed refusal.
    private struct StubSource: IDPGroupSourceProviding {
        enum Behavior {
            case claim(IDPGroupClaim)
            case missing
            case refuse(IDPSourceRefusal)
            case throwOther
        }
        struct OtherError: Error {}
        let behavior: Behavior
        func readClaim(
            for user: ConsoleUser,
            config: SerberusConfig.SudoEnrollment
        ) throws -> IDPGroupClaim? {
            switch behavior {
            case let .claim(c): return c
            case .missing: return nil
            case let .refuse(r): throw r
            case .throwOther: throw OtherError()
            }
        }
    }

    private let alice = ConsoleUser(uid: 501, name: "alice", homeDir: "/Users/alice")

    private func config(
        idpGroups: [String],
        source: IDPGroupSource = .jamfConnectState,
        requireRootOwnedState: Bool = false
    ) -> SerberusConfig.SudoEnrollment {
        SerberusConfig.SudoEnrollment(
            idpGroups: idpGroups,
            idpSource: source,
            requireRootOwnedState: requireRootOwnedState
        )
    }

    private func resolver(_ behavior: StubSource.Behavior) -> IDPGroupResolver {
        IDPGroupResolver(source: StubSource(behavior: behavior))
    }

    // MARK: Gates (fail-safe, no source read)

    @Test("disabled source enrolls no one")
    func disabled() {
        let out = resolver(.claim(IDPGroupClaim(groups: ["Test-Name"], ownerWritable: true)))
            .resolve(consoleUser: alice, config: config(idpGroups: ["Test-Name"], source: .disabled))
        #expect(out.resolvedUsers.isEmpty)
        #expect(out.matchedGroups.isEmpty)
        #expect(out.event == .disabled)
    }

    @Test("empty configured groups enrolls no one")
    func noConfiguredGroups() {
        let out = resolver(.claim(IDPGroupClaim(groups: ["Test-Name"], ownerWritable: true)))
            .resolve(consoleUser: alice, config: config(idpGroups: []))
        #expect(out.resolvedUsers.isEmpty)
        #expect(out.event == .noConfiguredGroups)
    }

    @Test("nil console user enrolls no one")
    func noConsoleUser() {
        let out = resolver(.claim(IDPGroupClaim(groups: ["Test-Name"], ownerWritable: true)))
            .resolve(consoleUser: nil, config: config(idpGroups: ["Test-Name"]))
        #expect(out.resolvedUsers.isEmpty)
        #expect(out.event == .noConsoleUser)
    }

    // MARK: Matching

    @Test("matching group name enrolls exactly the console-user name")
    func matchByName() {
        let out = resolver(.claim(IDPGroupClaim(groups: ["Engineering", "Test-Name"], ownerWritable: true)))
            .resolve(consoleUser: alice, config: config(idpGroups: ["Test-Name"]))
        #expect(out.resolvedUsers == ["alice"])
        #expect(out.matchedGroups == ["Test-Name"])
        #expect(out.event == .granted(user: "alice", matched: ["Test-Name"]))
    }

    @Test("GUID with braces on one side matches bare GUID on the other")
    func matchByGuidBraces() {
        let guid = "6C8FA2B0-1111-2222-3333-444455556666"
        // Configured with braces, claim carries bare GUID.
        let out = resolver(.claim(IDPGroupClaim(groups: [guid], ownerWritable: true)))
            .resolve(consoleUser: alice, config: config(idpGroups: ["{\(guid)}"]))
        #expect(out.resolvedUsers == ["alice"])
        #expect(out.matchedGroups == ["{\(guid)}"])  // original configured form preserved
    }

    @Test("match is case- and whitespace-insensitive")
    func matchNormalized() {
        let out = resolver(.claim(IDPGroupClaim(groups: ["  test-NAME  "], ownerWritable: true)))
            .resolve(consoleUser: alice, config: config(idpGroups: ["Test-Name"]))
        #expect(out.resolvedUsers == ["alice"])
        #expect(out.matchedGroups == ["Test-Name"])
    }

    @Test("non-matching claim enrolls no one")
    func noMatch() {
        let out = resolver(.claim(IDPGroupClaim(groups: ["Interns", "Everyone"], ownerWritable: true)))
            .resolve(consoleUser: alice, config: config(idpGroups: ["Test-Name"]))
        #expect(out.resolvedUsers.isEmpty)
        #expect(out.matchedGroups.isEmpty)
        #expect(out.event == .noMatch)
    }

    @Test("multiple matches are sorted and de-duplicated")
    func multipleMatchesSorted() {
        let out = resolver(.claim(IDPGroupClaim(groups: ["zebra", "alpha", "alpha"], ownerWritable: true)))
            .resolve(consoleUser: alice, config: config(idpGroups: ["Zebra", "Alpha", "Zebra"]))
        #expect(out.resolvedUsers == ["alice"])
        #expect(out.matchedGroups == ["Alpha", "Zebra"])
    }

    // MARK: Source nil / refusals (all fail-safe)

    @Test("missing/nil source is stale and enrolls no one")
    func missingSource() {
        let out = resolver(.missing)
            .resolve(consoleUser: alice, config: config(idpGroups: ["Test-Name"]))
        #expect(out.resolvedUsers.isEmpty)
        #expect(out.event == .staleOrMissingSource)
    }

    @Test("ownership refusal maps to refusedOwnership, no enrollment")
    func refusedOwnership() {
        let out = resolver(.refuse(.ownership(uid: 501, mode: 0o622)))
            .resolve(consoleUser: alice, config: config(idpGroups: ["Test-Name"]))
        #expect(out.resolvedUsers.isEmpty)
        #expect(out.event == .refusedOwnership(uid: 501, mode: 0o622))
    }

    @Test("symlink refusal maps to refusedSymlink, no enrollment")
    func refusedSymlink() {
        let out = resolver(.refuse(.symlink))
            .resolve(consoleUser: alice, config: config(idpGroups: ["Test-Name"]))
        #expect(out.resolvedUsers.isEmpty)
        #expect(out.event == .refusedSymlink)
    }

    @Test("strict refusal maps to strictReject, no enrollment")
    func strictReject() {
        let out = resolver(.refuse(.strictReject))
            .resolve(consoleUser: alice, config: config(idpGroups: ["Test-Name"], requireRootOwnedState: true))
        #expect(out.resolvedUsers.isEmpty)
        #expect(out.event == .strictReject)
    }

    @Test("an unexpected source error degrades to stale, no enrollment")
    func otherErrorFailsSafe() {
        let out = resolver(.throwOther)
            .resolve(consoleUser: alice, config: config(idpGroups: ["Test-Name"]))
        #expect(out.resolvedUsers.isEmpty)
        #expect(out.event == .staleOrMissingSource)
    }

    // MARK: Containment invariant

    @Test("resolved name is the console user's, never a plist-supplied name")
    func neverEmitsPlistName() {
        // The claim's group tokens include what looks like another username;
        // the output must still be exactly the console-user name.
        let out = resolver(.claim(IDPGroupClaim(groups: ["Test-Name", "root", "victim"], ownerWritable: true)))
            .resolve(consoleUser: alice, config: config(idpGroups: ["Test-Name"]))
        #expect(out.resolvedUsers == ["alice"])
        if case let .granted(user, _) = out.event {
            #expect(user == "alice")
        } else {
            Issue.record("expected .granted")
        }
    }
}
