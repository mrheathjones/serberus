import Foundation
import Testing
import PrivMgrCore
@testable import SerberusDaemonCore

/// Integration: the IdP-group enrollment pipeline composed **end to end** the
/// way the daemon composes it — a verified ``ConsoleUser`` →
/// ``IDPGroupResolver`` over an in-memory ``IDPGroupSourceProviding`` →
/// the FROZEN ``SudoersGenerator``. No `DaemonController` internals are touched;
/// the resolver's `resolvedUsers` are fed verbatim into the generator as
/// `enrollmentUsers`, exactly as the daemon does.
///
/// Every test pins the **fail-safe direction**, not just the happy path:
/// - (a) a matching claim enrolls *exactly* the one verified console user;
/// - (b) a tampered claim naming other users can never enroll them
///       (output ⊆ `{consoleUser.name}`);
/// - (c) no console user / refusal / no-intersection / logout removes the drop-in;
/// - (d) a verified-but-unsafe console name is still dropped by the generator's
///       principal validation (defense in depth over the resolver).
@Suite("IDP resolve end-to-end (console user → resolver → generator)")
struct IDPResolveEndToEndTests {

    // MARK: - Composition fixtures

    /// Header used for byte-exact body assertions.
    static let header = "# test-header"
    /// A curated command path that does not exist on disk. `PathCanonicalizer`
    /// under `.allowMissing` keeps it verbatim, so the generated Cmnd spec is
    /// deterministic and the body is byte-stable across machines.
    static let curatedSpec = "/opt/serberus-test/bin/tool"

    /// The full expected body for a single enrolled `alice` — header + the
    /// generator's per-principal `Defaults` block + the curated User_Spec.
    /// Built from `SudoersGenerator`'s own constants so it tracks the generator.
    static let aliceCuratedBody: String = {
        let defaults = """
        Defaults:alice timestamp_timeout=0
        Defaults:alice !env_keep
        Defaults:alice passwd_tries=1
        Defaults:alice authfail_message="\(SudoersGenerator.authFailMessage)"
        Defaults:alice badpass_message="\(SudoersGenerator.badPassMessage)"
        """
        return "\(header)\n\(defaults)\nalice ALL = \(curatedSpec)\n"
    }()

    /// The single trust anchor for the matching cases: a standard console user.
    static let alice = ConsoleUser(uid: 501, name: "alice", homeDir: "/Users/alice")

    /// An in-memory source: returns a fixed claim, `nil` (stale/missing), or
    /// throws a fixed refusal. Stands in for `JamfConnectStateSource` so the
    /// pipeline is exercised without touching the filesystem.
    struct StubSource: IDPGroupSourceProviding {
        enum Behavior: Sendable {
            case claim(IDPGroupClaim)
            case missing
            case refuse(IDPSourceRefusal)
        }
        let behavior: Behavior
        func readClaim(
            for user: ConsoleUser,
            config: SerberusConfig.SudoEnrollment
        ) throws -> IDPGroupClaim? {
            switch behavior {
            case let .claim(claim): return claim
            case .missing: return nil
            case let .refuse(refusal): throw refusal
            }
        }
    }

    /// A curated, `pam_serberus`-gated prompt allow rule (the generator emits
    /// prompt and silent allows identically — no `NOPASSWD`).
    private func curatedRule() -> Rule {
        Rule(
            id: "curated",
            type: .sudo,
            action: .allow,
            description: "curated tool",
            priority: 0,
            match: MatchCriteria(commandPattern: Self.curatedSpec, matchType: .exact),
            elevation: ElevationBehavior(type: .prompt)
        )
    }

    private func profile(_ rules: [Rule]) -> RuleProfile {
        RuleProfile(
            policyVersion: "1.0.0",
            profileKey: "rules_sudo_e2e",
            profilePriority: 0,
            rules: rules
        )
    }

    private func enrollmentConfig(
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

    /// Drive the whole pipeline: resolve, then feed the resolver's output
    /// straight into the generator as `enrollmentUsers` (no enrollment group).
    private func run(
        consoleUser: ConsoleUser?,
        idpGroups: [String],
        source: StubSource.Behavior,
        requireRootOwnedState: Bool = false,
        rules: [Rule]? = nil
    ) -> (outcome: IDPResolveOutcome, result: SudoersGenerator.Result) {
        let config = enrollmentConfig(
            idpGroups: idpGroups,
            requireRootOwnedState: requireRootOwnedState
        )
        let resolver = IDPGroupResolver(source: StubSource(behavior: source))
        let outcome = resolver.resolve(consoleUser: consoleUser, config: config)
        let result = SudoersGenerator.generate(
            profiles: [profile(rules ?? [curatedRule()])],
            enrollmentGroup: nil,
            enrollmentUsers: outcome.resolvedUsers,
            header: Self.header
        )
        return (outcome, result)
    }

    /// The leading principal token of every non-header body line
    /// (`"<principal> ALL = ..."`).
    private func principals(in body: String) -> [String] {
        body.split(separator: "\n")
            .filter { !$0.hasPrefix("#") && !$0.hasPrefix("Defaults") }
            .compactMap { $0.split(separator: " ").first.map(String.init) }
    }

    // MARK: - (a) Matching claim enrolls exactly the one console user

    @Test("a matching IdP claim enrolls exactly the verified console user as '<user> ALL = <curated>'")
    func matchingClaimEnrollsConsoleUser() {
        let (outcome, result) = run(
            consoleUser: Self.alice,
            idpGroups: ["Test-Name"],
            source: .claim(IDPGroupClaim(groups: ["Engineering", "Test-Name"], ownerWritable: true))
        )
        // The resolver emitted exactly the one verified name…
        #expect(outcome.resolvedUsers == ["alice"])
        #expect(outcome.matchedGroups == ["Test-Name"])
        #expect(outcome.event == .granted(user: "alice", matched: ["Test-Name"]))
        // …and the FROZEN generator rendered it as the single curated User_Spec,
        // preceded by the per-principal timestamp_timeout=0 (forces the fine gate
        // on every curated command, not just the first in a tty).
        #expect(result.body == Self.aliceCuratedBody)
        #expect(result.excluded.isEmpty)
        #expect(principals(in: result.body) == ["alice"])
        // Crucially: no NOPASSWD, no ALL-commands token leaked into the grant.
        #expect(!result.body.contains("NOPASSWD"))
        #expect(!result.body.contains("ALL = ALL"))
    }

    @Test("full daemon path: ConsoleUserResolver.evaluate → resolver → generator")
    func fullDaemonPathHappy() {
        // Drive the real ConsoleUserResolver pure core with an injected passwd lookup so the
        // ConsoleUser is produced the way the live daemon produces it.
        let passwd: (uid_t) -> PasswdEntry? = { uid in
            uid == 501 ? PasswdEntry(name: "alice", homeDir: "/Users/alice") : nil
        }
        let resolution = ConsoleUserResolver.evaluate(
            scName: "alice", scUID: 501, minimumUID: 501, passwd: passwd)
        guard case let .resolved(user) = resolution else {
            Issue.record("expected a resolved console user, got \(resolution)")
            return
        }
        let (outcome, result) = run(
            consoleUser: user,
            idpGroups: ["Test-Name"],
            source: .claim(IDPGroupClaim(groups: ["Test-Name"], ownerWritable: true))
        )
        #expect(outcome.resolvedUsers == ["alice"])
        #expect(result.body == Self.aliceCuratedBody)
    }

    // MARK: - (b) Tampered claim can never enroll a DIFFERENT user

    @Test("a tampered claim naming other users/injection tokens still enrolls only the console user")
    func tamperedClaimContainsToConsoleUser() {
        // The console user owns this file, so she can write anything into the
        // group array — including tokens shaped like privileged usernames and a
        // full sudoers-injection string. None of it can name a different user.
        let hostile = IDPGroupClaim(
            groups: [
                "Test-Name",                       // the one real match
                "root", "wheel", "victim", "%admin", // decoy "usernames"/groups
                "attacker ALL=(ALL) NOPASSWD: ALL",  // decoy injection payload
            ],
            ownerWritable: true
        )
        let (outcome, result) = run(
            consoleUser: Self.alice,
            idpGroups: ["Test-Name"],
            source: .claim(hostile)
        )
        // Containment invariant: output ⊆ { consoleUser.name }.
        #expect(outcome.resolvedUsers == ["alice"])
        #expect(Set(outcome.resolvedUsers).isSubset(of: [Self.alice.name]))
        #expect(principals(in: result.body) == ["alice"])
        // The decoy names/payload never reach the sudoers body.
        #expect(!result.body.contains("root"))
        #expect(!result.body.contains("victim"))
        #expect(!result.body.contains("wheel"))
        #expect(!result.body.contains("attacker"))
        #expect(!result.body.contains("NOPASSWD"))
        #expect(!result.body.contains("%admin"))
    }

    /// A matrix of fully attacker-controlled claims. Whatever the claim asserts,
    /// the generated body's principal set must be a subset of `{alice}`.
    static let hostileClaims: [IDPGroupClaim] = [
        IDPGroupClaim(groups: ["Test-Name", "bob"], ownerWritable: true),
        IDPGroupClaim(groups: ["Test-Name", "root ALL = (ALL) ALL"], ownerWritable: true),
        IDPGroupClaim(groups: ["Test-Name", "\nmallory ALL = ALL"], ownerWritable: true),
        IDPGroupClaim(groups: ["Test-Name", "ALL"], ownerWritable: true),
    ]

    @Test("no attacker-controlled claim can widen the principal set beyond the console user",
          arguments: hostileClaims)
    func containmentUnderHostileClaims(_ claim: IDPGroupClaim) {
        let (outcome, result) = run(
            consoleUser: Self.alice,
            idpGroups: ["Test-Name"],
            source: .claim(claim)
        )
        #expect(Set(outcome.resolvedUsers).isSubset(of: [Self.alice.name]))
        #expect(Set(principals(in: result.body)).isSubset(of: [Self.alice.name]))
    }

    // MARK: - (c) Fail-safe: every off-path input removes the drop-in

    /// One off-path scenario and a human-readable label for test output.
    struct OffPathCase: Sendable, CustomStringConvertible {
        let label: String
        let consoleUser: ConsoleUser?
        let idpGroups: [String]
        let behavior: StubSource.Behavior
        let requireRootOwnedState: Bool
        var description: String { label }
    }

    /// A matching claim used by the off-path cases where the claim itself is not
    /// the reason enrollment is denied (proves the OTHER gate is what drops it).
    private static let matchingClaim = StubSource.Behavior.claim(
        IDPGroupClaim(groups: ["Test-Name"], ownerWritable: true))

    static let offPathCases: [OffPathCase] = [
        // No one at the console (also the logout case): the still-matching state
        // file on disk is never consulted — resolver stops at Gate 3.
        OffPathCase(label: "no console user (logout) despite a matching file",
                    consoleUser: nil, idpGroups: ["Test-Name"],
                    behavior: matchingClaim, requireRootOwnedState: false),
        // Source refused on ownership (someone else owns / group-writable file).
        OffPathCase(label: "source refusal: ownership",
                    consoleUser: alice, idpGroups: ["Test-Name"],
                    behavior: .refuse(.ownership(uid: 501, mode: 0o622)),
                    requireRootOwnedState: false),
        // Source refused because the path went through a symlink.
        OffPathCase(label: "source refusal: symlink",
                    consoleUser: alice, idpGroups: ["Test-Name"],
                    behavior: .refuse(.symlink), requireRootOwnedState: false),
        // Strict mode rejected a non-root-owned file.
        OffPathCase(label: "source refusal: strictReject",
                    consoleUser: alice, idpGroups: ["Test-Name"],
                    behavior: .refuse(.strictReject), requireRootOwnedState: true),
        // Jamf Connect never signed in / file gone: stale, no claim.
        OffPathCase(label: "stale/missing source",
                    consoleUser: alice, idpGroups: ["Test-Name"],
                    behavior: .missing, requireRootOwnedState: false),
        // A valid claim, but no configured group intersects it.
        OffPathCase(label: "no intersection",
                    consoleUser: alice, idpGroups: ["Test-Name"],
                    behavior: .claim(IDPGroupClaim(groups: ["Interns"], ownerWritable: true)),
                    requireRootOwnedState: false),
        // Feature-shaped but nothing configured to match: no one ever enrolls.
        OffPathCase(label: "no configured groups",
                    consoleUser: alice, idpGroups: [],
                    behavior: matchingClaim, requireRootOwnedState: false),
    ]

    @Test("every off-path input enrolls no one and removes the drop-in (empty body)",
          arguments: offPathCases)
    func offPathRemovesDropIn(_ scenario: OffPathCase) {
        let (outcome, result) = run(
            consoleUser: scenario.consoleUser,
            idpGroups: scenario.idpGroups,
            source: scenario.behavior,
            requireRootOwnedState: scenario.requireRootOwnedState
        )
        // The resolver enrolled no one…
        #expect(outcome.resolvedUsers.isEmpty, "\(scenario.label): expected no resolved users")
        // …so the generator returns an empty body (caller REMOVES the drop-in),
        // never a header-only or partial file.
        #expect(result.body == "", "\(scenario.label): expected an empty (remove) body")
    }

    // MARK: - (d) A verified-but-unsafe console name is dropped by the generator

    /// Console usernames that pass the resolver's containment (they ARE the verified name)
    /// but must be rejected by the generator's `isSafePrincipalName` guard.
    static let unsafeConsoleNames: [String] = [
        "ALL",                              // reserved sudoers token
        "user,root",                        // comma → spec injection
        "evil ALL=(ALL) NOPASSWD: ALL",     // whitespace + full injection
        "%wheel",                           // leading '%'
    ]

    @Test("a verified console user with an unsafe name is dropped by the generator (defense in depth)",
          arguments: unsafeConsoleNames)
    func unsafeConsoleNameDroppedByGenerator(_ unsafeName: String) {
        // The resolver does NOT vet the name — it faithfully emits the verified
        // console-user name (containment holds). The FROZEN generator is the
        // authoritative last gate that refuses to render an unsafe principal.
        let hostileUser = ConsoleUser(uid: 501, name: unsafeName, homeDir: "/Users/x")
        let (outcome, result) = run(
            consoleUser: hostileUser,
            idpGroups: ["Test-Name"],
            source: .claim(IDPGroupClaim(groups: ["Test-Name"], ownerWritable: true))
        )
        // The resolver emitted the (unsafe) verified name unchanged…
        #expect(outcome.resolvedUsers == [unsafeName])
        // …and the generator dropped it, yielding an empty (remove) body plus a
        // typed principal exclusion for loud logging.
        #expect(result.body == "")
        #expect(result.excluded.contains { $0.matchType == "principal" && $0.principal == unsafeName })
    }

    // MARK: - Feature is opt-in / off by default

    @Test("with idpSource disabled the drop-in stays empty even for a matching claim")
    func disabledSourceEnrollsNoOne() {
        let config = SerberusConfig.SudoEnrollment(
            idpGroups: ["Test-Name"],
            idpSource: .disabled)
        let resolver = IDPGroupResolver(
            source: StubSource(behavior: .claim(
                IDPGroupClaim(groups: ["Test-Name"], ownerWritable: true))))
        let outcome = resolver.resolve(consoleUser: Self.alice, config: config)
        let result = SudoersGenerator.generate(
            profiles: [profile([curatedRule()])],
            enrollmentGroup: nil,
            enrollmentUsers: outcome.resolvedUsers,
            header: Self.header)
        #expect(outcome.event == .disabled)
        #expect(outcome.resolvedUsers.isEmpty)
        #expect(result.body == "")
    }
}
