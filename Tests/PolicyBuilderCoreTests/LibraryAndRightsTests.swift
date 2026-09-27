import Foundation
import Testing
import PrivMgrCore
@testable import PolicyBuilderCore

@MainActor
@Suite("AuthRightsCatalog — live authorization database")
struct AuthRightsCatalogTests {
    @Test("enumerates rights from the live system authorization database")
    func enumeratesLiveRights() {
        let catalog = AuthRightsCatalog()
        catalog.loadIfNeeded()
        #expect(catalog.loaded)
        #expect(catalog.loadError == nil)
        // The system template ships ~149 rights; assert a healthy lower bound.
        #expect(catalog.rightsCount > 100)
        // A well-known right must be present with metadata.
        let admin = catalog.rights.first { $0.name == "system.privilege.admin" }
        #expect(admin != nil)
    }

    @Test("search filters by name and comment, case-insensitively")
    func searchFilters() {
        let catalog = AuthRightsCatalog()
        catalog.loadIfNeeded()
        let prefs = catalog.search("preferences")
        #expect(!prefs.isEmpty)
        #expect(prefs.allSatisfy { $0.name.lowercased().contains("preferences") || ($0.comment?.lowercased().contains("preferences") ?? false) })
        // Empty query returns the full right set (rules excluded by default).
        #expect(catalog.search("").count == catalog.rightsCount)
        // Rule templates are only included when asked for.
        #expect(catalog.search("", includeRules: true).count >= catalog.search("").count)
    }

    @Test("rights the daemon refuses are marked with the reason")
    func refusalsMarked() {
        let rights: [String: Any] = [
            "system.preferences.printing": ["class": "rule", "rule": ["authenticate-admin"]],
            "system.preferences.location": ["class": "rule", "k-of-n": 1, "rule": ["on-console", "authenticate-admin"]],
            "com.example.keychain": ["class": "rule", "rule": "kcunlock"],
            "system.privilege.admin": ["class": "rule", "rule": ["authenticate-admin"]],
            "system.login.console": ["class": "evaluate-mechanisms", "mechanisms": ["builtin:login"]],
        ]
        let rules: [String: Any] = [
            "authenticate-admin": ["class": "user", "group": "admin", "timeout": 0],
            "on-console": ["class": "evaluate-mechanisms", "mechanisms": ["builtin:on-console"]],
            "kcunlock": ["class": "evaluate-mechanisms", "mechanisms": ["builtin:unlock-keychain"]],
        ]
        func refusals(_ name: String) -> (allow: String?, deny: String?) {
            AuthorizationRight.refusals(for: name, rights: rights, rules: rules)
        }
        // A plain admin gate: both accepted.
        #expect(refusals("system.preferences.printing").allow == nil)
        #expect(refusals("system.preferences.printing").deny == nil)
        // Not a plain admin gate: deny only.
        #expect(refusals("system.preferences.location").allow != nil)
        #expect(refusals("system.preferences.location").deny == nil)
        // A mechanism chain: neither.
        #expect(refusals("com.example.keychain").allow?.contains("mechanism chain") == true)
        #expect(refusals("com.example.keychain").deny != nil)
        // Root-equivalent: a plain allow is refused.
        #expect(refusals("system.privilege.admin").allow?.contains("root") == true)
        // Protected: neither.
        #expect(refusals("system.login.console").allow != nil && refusals("system.login.console").deny != nil)

        let catalog = AuthRightsCatalog()
        catalog.loadIfNeeded()
        let ruleClassesRefused = catalog.rights.filter { $0.kind == .rule }.allSatisfy { $0.refusedForEveryRule }
        #expect(ruleClassesRefused)
        #expect(catalog.rights.contains { $0.kind == .right && $0.allowRefusal == nil })
    }
}

@MainActor
@Suite("ProfileLibraryStore — persistence")
struct ProfileLibraryStoreTests {
    private func tempStore() -> ProfileLibraryStore {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-test-\(UUID().uuidString)")
            .appendingPathComponent("policies.json")
        return ProfileLibraryStore(url: url)
    }

    /// A temp store that already holds ``LibraryFixture``, as if an admin had
    /// authored it in an earlier session.
    private func fixtureStore() -> ProfileLibraryStore {
        let store = tempStore()
        #expect(store.save(LibraryFixture.default))
        return store
    }

    @Test("v2 three-tier library file round-trips through disk")
    func roundTrip() throws {
        let store = tempStore()
        let file = LibraryFixture.default
        #expect(store.save(file))
        let loaded = try #require(store.load())
        #expect(loaded.schemaVersion == PolicyLibraryFile.currentSchemaVersion)
        // Fixture timestamps are fixed whole seconds, so iso8601 round-trips to
        // full value equality (not just id/count equality) across all tiers.
        #expect(loaded.definitions == file.definitions)
        #expect(loaded.rules == file.rules)
        #expect(loaded.policies == file.policies)
        try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent())
    }

    @Test("first run starts an empty library and writes it, so nothing is authored for the admin")
    func firstRunStartsEmpty() throws {
        let store = tempStore()
        defer { try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent()) }
        #expect(store.load() == nil)

        let model = PolicyBuilderModel.persistent(store: store)
        #expect(model.policies.isEmpty)
        #expect(model.rules.isEmpty)
        #expect(model.definitions.isEmpty)

        let written = try #require(store.load())
        #expect(written.schemaVersion == PolicyLibraryFile.currentSchemaVersion)
        #expect(written.policies.isEmpty && written.rules.isEmpty && written.definitions.isEmpty)
    }

    @Test("an authored library and new policies survive a fresh store-backed model")
    func persistsAcrossModels() throws {
        let store = fixtureStore()

        let first = PolicyBuilderModel.persistent(store: store)   // loads the stored library
        // Identities load verbatim: compiled profile keys derive from policy
        // ids, and grants/logs reference the compiled rule ids built from
        // these slugs.
        #expect(first.policies.map(\.id) == ["developer_tools", "admin_settings", "network_diag"])
        #expect(first.rules.map(\.id) == [
            "allow_xcode_select", "deny_rm_system",
            "prompt_network_prefs", "prompt_print_prefs",
            "allow_dscacheutil",
        ])
        #expect(first.definitions.map(\.id) == [
            "xcode_select", "rm_system_paths",
            "network_preferences", "printing_preferences",
            "dscacheutil_flush",
        ])

        let newID = first.newPolicy(name: "Unit Test")
        #expect(newID == "unit_test")
        first.addRule("allow_xcode_select", toPolicy: newID)

        let second = PolicyBuilderModel.persistent(store: store)  // reloads from disk
        #expect(second.policies.count == 4)
        let reloaded = try #require(second.policy(id: "unit_test"))
        #expect(reloaded.name == "Unit Test")
        // The assignment references the shared library rule by id.
        #expect(reloaded.rules.map(\.ruleID) == ["allow_xcode_select"])

        try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent())
    }

    @Test("deleting a policy persists the removal but keeps the shared rules")
    func deleteRemoves() throws {
        let store = fixtureStore()
        let model = PolicyBuilderModel.persistent(store: store)
        let id = try #require(model.policies.first).id
        model.deletePolicy(id: id)
        #expect(model.policy(id: id) == nil)
        // The rules a policy referenced are shared library entries, not owned
        // by the policy — deleting the policy must not cascade downward.
        #expect(model.rule(id: "allow_xcode_select") != nil)

        let fresh = PolicyBuilderModel.persistent(store: store)
        #expect(fresh.policy(id: id) == nil)
        #expect(fresh.rule(id: "allow_xcode_select") != nil)
        try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent())
    }

    @Test("rule upsert, per-policy toggle, and cascade delete persist across fresh store-backed models")
    func ruleMutationsPersist() throws {
        let store = fixtureStore()

        let first = PolicyBuilderModel.persistent(store: store)
        first.upsertRule(PolicyRule(id: "persist_check", name: "Persist Check",
                                    definitionIDs: ["xcode_select"]))
        first.addRule("persist_check", toPolicy: "developer_tools")
        first.setRule("persist_check", enabled: false, inPolicy: "developer_tools")

        let second = PolicyBuilderModel.persistent(store: store)
        #expect(second.rule(id: "persist_check") != nil)
        let assignment = try #require(second.policy(id: "developer_tools")?
            .rules.first { $0.ruleID == "persist_check" })
        #expect(assignment.enabled == false)

        second.deleteRule(id: "persist_check")

        let third = PolicyBuilderModel.persistent(store: store)
        #expect(third.rule(id: "persist_check") == nil)
        // The cascade removed the assignment too, not just the library rule —
        // no dangling references survive a reload.
        #expect(third.policy(id: "developer_tools")?
            .rules.contains { $0.ruleID == "persist_check" } == false)

        try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent())
    }

    @Test("a stored library, including rules Commander once shipped as starters, loads unchanged")
    func storedLibraryKeepsRetiredStarterEntries() throws {
        let store = tempStore()
        defer { try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent()) }
        var file = LibraryFixture.default
        file.definitions.append(RuleDefinition(
            id: "tcpdump", name: "tcpdump", kind: .sudo,
            commandPattern: "/usr/sbin/tcpdump", matchType: .prefixRegex))
        file.rules.append(PolicyRule(
            id: "prompt_tcpdump", name: "Packet capture", definitionIDs: ["tcpdump"],
            action: .allow, elevationType: .prompt))
        #expect(store.save(file))

        let model = PolicyBuilderModel.persistent(store: store)
        #expect(model.definition(id: "tcpdump")?.commandPattern == "/usr/sbin/tcpdump")
        #expect(model.rule(id: "prompt_tcpdump")?.definitionIDs == ["tcpdump"])
    }

    @Test("definition edits and cascade deletes persist across fresh store-backed models")
    func definitionMutationsPersist() throws {
        let store = fixtureStore()

        let first = PolicyBuilderModel.persistent(store: store)
        var definition = try #require(first.definition(id: "dscacheutil_flush"))
        definition.commandPattern = "/usr/local/bin/dscacheutil"
        first.upsertDefinition(definition)

        let second = PolicyBuilderModel.persistent(store: store)
        #expect(second.definition(id: "dscacheutil_flush")?.commandPattern == "/usr/local/bin/dscacheutil")

        second.deleteDefinition(id: "dscacheutil_flush")

        let third = PolicyBuilderModel.persistent(store: store)
        #expect(third.definition(id: "dscacheutil_flush") == nil)
        // The cascade removed the reference from the rule that used it.
        #expect(third.rule(id: "allow_dscacheutil")?.definitionIDs.isEmpty == true)

        try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent())
    }
}

// MARK: - Library fixture

/// A three-tier library used as test data: several policies over shared rules
/// and definitions (sudo allow + deny, authuri allows, a silent grant). This
/// is the former Commander starter library, kept only so the persistence,
/// migration, compiler and risk-signal tests have a realistic library to work
/// on. Commander no longer ships a starter library (it starts empty), and
/// nothing here is a policy recommendation.
enum LibraryFixture {
    /// Fixed whole-second timestamp so the fixture round-trips through ISO8601 exactly.
    static let fixtureDate = Date(timeIntervalSince1970: 1_781_222_400) // 2026-06-12 UTC

    static var `default`: PolicyLibraryFile {
        PolicyLibraryFile(definitions: definitions, rules: rules, policies: policies)
    }

    // MARK: Tier 3 — definitions (pure matchers)

    static let definitions: [RuleDefinition] = [
        RuleDefinition(
            id: "xcode_select", name: "xcode-select --reset",
            detail: "Test fixture: an argument-constrained sudo allow.",
            kind: .sudo,
            commandPattern: "/usr/bin/xcode-select",
            argPattern: "^(-r|--reset)$",
            matchType: .exact,
            createdAt: fixtureDate, updatedAt: fixtureDate),
        RuleDefinition(
            id: "rm_system_paths", name: "rm -rf on /System or /Library",
            detail: "Recursive removal targeting /System or /Library.",
            kind: .sudo,
            commandPattern: "/bin/rm",
            argPattern: "-rf?\\s+/(System|Library)",
            matchType: .prefixRegex,
            createdAt: fixtureDate, updatedAt: fixtureDate),
        RuleDefinition(
            id: "network_preferences", name: "Network preferences",
            detail: "The system.preferences.network authorization right.",
            kind: .authuri,
            authURI: "system.preferences.network",
            createdAt: fixtureDate, updatedAt: fixtureDate),
        RuleDefinition(
            id: "printing_preferences", name: "Printing preferences",
            detail: "The system.preferences.printing authorization right.",
            kind: .authuri,
            authURI: "system.preferences.printing",
            createdAt: fixtureDate, updatedAt: fixtureDate),
        RuleDefinition(
            id: "dscacheutil_flush", name: "dscacheutil -flushcache",
            detail: "DNS cache flush via /usr/bin/dscacheutil.",
            kind: .sudo,
            commandPattern: "/usr/bin/dscacheutil",
            argPattern: "-flushcache",
            matchType: .prefixRegex,
            createdAt: fixtureDate, updatedAt: fixtureDate),
    ]

    // MARK: Tier 2 — rules (decision bundles)

    static let rules: [PolicyRule] = [
        PolicyRule(
            id: "allow_xcode_select", name: "Reset the active Xcode toolchain",
            definitionIDs: ["xcode_select"],
            action: .allow, elevationType: .silent,
            priority: 20,
            maxGrantDurationSeconds: 900,
            logArguments: false,
            createdAt: fixtureDate, updatedAt: fixtureDate),
        PolicyRule(
            id: "deny_rm_system", name: "Never allow recursive removal under /System or /Library",
            definitionIDs: ["rm_system_paths"],
            action: .deny,
            priority: 1,
            createdAt: fixtureDate, updatedAt: fixtureDate),
        PolicyRule(
            id: "prompt_network_prefs", name: "Change network settings",
            definitionIDs: ["network_preferences"],
            action: .allow, elevationType: .silent,
            priority: 10,
            logArguments: false,
            createdAt: fixtureDate, updatedAt: fixtureDate),
        PolicyRule(
            id: "prompt_print_prefs", name: "Add or remove printers",
            definitionIDs: ["printing_preferences"],
            action: .allow, elevationType: .silent,
            priority: 20,
            logArguments: false,
            createdAt: fixtureDate, updatedAt: fixtureDate),
        PolicyRule(
            id: "allow_dscacheutil", name: "Flush DNS cache",
            definitionIDs: ["dscacheutil_flush"],
            action: .allow, elevationType: .silent,
            priority: 10,
            logArguments: false,
            createdAt: fixtureDate, updatedAt: fixtureDate),
    ]

    // MARK: Tier 1 — policies

    static let policies: [Policy] = [
        Policy(
            id: "developer_tools", name: "Developer Tools",
            summary: "Silent toolchain elevation for engineers, with a hard block on destructive removals.",
            scope: PolicyScope(userGroups: ["Developers"], devices: "Developer workstations",
                               schedule: "All times", network: "Any network"),
            policyVersion: "1.2.0", profilePriority: 40,
            rules: [
                PolicyRuleAssignment(ruleID: "allow_xcode_select"),
                PolicyRuleAssignment(ruleID: "deny_rm_system"),
            ],
            createdAt: fixtureDate, updatedAt: fixtureDate),
        Policy(
            id: "admin_settings", name: "Admin Settings (Prompted)",
            summary: "Lets standard users change network and printer settings after an approval prompt with justification.",
            scope: PolicyScope(userGroups: ["Standard Users"], devices: "All managed devices",
                               schedule: "Business hours (9–17)", network: "Corporate network"),
            policyVersion: "1.0.0", profilePriority: 50,
            rules: [
                PolicyRuleAssignment(ruleID: "prompt_network_prefs"),
                PolicyRuleAssignment(ruleID: "prompt_print_prefs"),
            ],
            createdAt: fixtureDate, updatedAt: fixtureDate),
        Policy(
            id: "network_diag", name: "Network Diagnostics",
            summary: "Help Desk can flush the DNS cache silently.",
            scope: PolicyScope(userGroups: ["Help Desk", "IT Administrators"], devices: "All managed devices",
                               schedule: "All times", network: "Any network"),
            policyVersion: "0.9.0", profilePriority: 60,
            rules: [
                PolicyRuleAssignment(ruleID: "allow_dscacheutil"),
            ],
            createdAt: fixtureDate, updatedAt: fixtureDate),
    ]
}
