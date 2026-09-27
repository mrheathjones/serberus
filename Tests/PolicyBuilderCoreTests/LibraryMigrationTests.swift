import Foundation
import Testing
import PrivMgrCore
@testable import PolicyBuilderCore

// MARK: - Fixtures

/// v1 library fixtures, hand-written against the OLD on-disk shape
/// (`schemaVersion` 1, `profiles`, `metadata`, `unassignedRules`) so the
/// migration is tested against real legacy bytes rather than round-tripped
/// current types. Dates use the shared test epoch (2026-06-12 UTC).
private enum MigrationFixtures {
    static let epoch = Date(timeIntervalSince1970: 1_781_222_400) // 2026-06-12 UTC
    static let isoDate = "2026-06-12T00:00:00Z"

    static func tempStore() -> ProfileLibraryStore {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-migration-\(UUID().uuidString)")
            .appendingPathComponent("policies.json")
        return ProfileLibraryStore(url: url)
    }

    /// Writes raw JSON to the store's path (the store only creates directories
    /// on `save`, so raw fixture writes must create them explicitly).
    static func write(_ json: String, to store: ProfileLibraryStore) throws {
        try FileManager.default.createDirectory(
            at: store.url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(json.utf8).write(to: store.url)
    }

    static func rawTopLevel(of store: ProfileLibraryStore) throws -> [String: Any] {
        let object = try JSONSerialization.jsonObject(with: Data(contentsOf: store.url))
        return (object as? [String: Any]) ?? [:]
    }

    /// A representative v1 library: a sudo profile with metadata (disabled,
    /// custom scope), an authuri profile WITHOUT metadata (derived fields),
    /// and one unassigned rule.
    static let v1Library = """
    {
      "schemaVersion": 1,
      "profiles": [
        {
          "schemaVersion": "1.0",
          "policyVersion": "1.2.0",
          "profileKey": "rules_sudo_developer_tools",
          "profilePriority": 40,
          "rules": [
            {
              "id": "allow-brew",
              "type": "sudo",
              "action": "allow",
              "description": "Homebrew install / upgrade",
              "priority": 10,
              "cacheSeconds": 300,
              "match": {
                "commandPattern": "/opt/homebrew/bin/brew",
                "argPattern": "install|upgrade",
                "matchType": "prefix-regex",
                "requiredTeamID": "TEAM123456"
              },
              "conditions": { "requireJustification": false, "maxGrantDurationSeconds": 0 },
              "elevation": { "type": "silent", "notify": false, "logArguments": true }
            },
            {
              "id": "deny-rm-system",
              "type": "sudo",
              "action": "deny",
              "description": "Block recursive removal",
              "priority": 1,
              "match": { "commandPattern": "/bin/rm", "matchType": "exact" },
              "conditions": { "requireJustification": false, "maxGrantDurationSeconds": 0 },
              "elevation": { "type": "silent", "notify": false, "logArguments": true }
            }
          ]
        },
        {
          "schemaVersion": "1.0",
          "policyVersion": "1.0.0",
          "profileKey": "rules_authuri_admin_settings",
          "profilePriority": 50,
          "rules": [
            {
              "id": "prompt-network",
              "type": "authuri",
              "action": "allow",
              "description": "Change network settings with approval",
              "priority": 10,
              "match": { "authURI": "system.preferences.network" },
              "conditions": { "requireJustification": true, "maxGrantDurationSeconds": 600 },
              "elevation": { "type": "prompt", "notify": true, "logArguments": true }
            }
          ]
        }
      ],
      "metadata": {
        "rules_sudo_developer_tools": {
          "displayName": "Developer Tools",
          "summary": "Engineer elevation",
          "scope": {
            "userGroups": ["Developers"],
            "devices": "Developer workstations",
            "schedule": "All times",
            "network": "Any network"
          },
          "enabled": false,
          "createdAt": "\(isoDate)",
          "updatedAt": "\(isoDate)"
        }
      },
      "unassignedRules": [
        {
          "id": "orphan-tcpdump",
          "type": "sudo",
          "action": "allow",
          "description": "Packet capture",
          "priority": 20,
          "match": { "commandPattern": "/usr/sbin/tcpdump", "matchType": "prefix-regex" },
          "conditions": { "requireJustification": true, "maxGrantDurationSeconds": 1800 },
          "elevation": { "type": "prompt", "notify": true, "logArguments": true }
        }
      ]
    }
    """

    /// Two v1 sudo profiles whose rules share BOTH the id `allow-brew` and an
    /// identical matcher — exercises matcher dedupe and rule-id suffixing at
    /// once. Profiles migrate in profileKey order: alpha before beta.
    static let v1CollidingLibrary = """
    {
      "schemaVersion": 1,
      "profiles": [
        {
          "schemaVersion": "1.0",
          "policyVersion": "1.0.0",
          "profileKey": "rules_sudo_beta",
          "profilePriority": 50,
          "rules": [
            {
              "id": "allow-brew",
              "type": "sudo",
              "action": "allow",
              "description": "Homebrew for beta",
              "priority": 10,
              "match": { "commandPattern": "/opt/homebrew/bin/brew", "matchType": "exact" },
              "conditions": { "requireJustification": false, "maxGrantDurationSeconds": 0 },
              "elevation": { "type": "silent", "notify": false, "logArguments": true }
            }
          ]
        },
        {
          "schemaVersion": "1.0",
          "policyVersion": "1.0.0",
          "profileKey": "rules_sudo_alpha",
          "profilePriority": 40,
          "rules": [
            {
              "id": "allow-brew",
              "type": "sudo",
              "action": "allow",
              "description": "Homebrew for alpha",
              "priority": 10,
              "match": { "commandPattern": "/opt/homebrew/bin/brew", "matchType": "exact" },
              "conditions": { "requireJustification": false, "maxGrantDurationSeconds": 0 },
              "elevation": { "type": "silent", "notify": false, "logArguments": true }
            }
          ]
        }
      ]
    }
    """

    /// Two v1 profiles of different mechanisms sharing the slug `shared` —
    /// exercises policy-id collision suffixing (authuri sorts first).
    static let v1SharedSlugLibrary = """
    {
      "schemaVersion": 1,
      "profiles": [
        {
          "schemaVersion": "1.0",
          "policyVersion": "3.0.0",
          "profileKey": "rules_sudo_shared",
          "profilePriority": 50,
          "rules": [
            {
              "id": "allow-tool",
              "type": "sudo",
              "action": "allow",
              "description": "Some tool",
              "priority": 10,
              "match": { "commandPattern": "/usr/bin/tool", "matchType": "exact" },
              "conditions": { "requireJustification": false, "maxGrantDurationSeconds": 0 },
              "elevation": { "type": "silent", "notify": false, "logArguments": true }
            }
          ]
        },
        {
          "schemaVersion": "1.0",
          "policyVersion": "2.0.0",
          "profileKey": "rules_authuri_shared",
          "profilePriority": 40,
          "rules": [
            {
              "id": "prompt-printers",
              "type": "authuri",
              "action": "allow",
              "description": "Printer settings",
              "priority": 10,
              "match": { "authURI": "system.preferences.printing" },
              "conditions": { "requireJustification": false, "maxGrantDurationSeconds": 0 },
              "elevation": { "type": "prompt", "notify": false, "logArguments": true }
            }
          ]
        }
      ]
    }
    """
}

// MARK: - v1 → v2 migration

@MainActor
@Suite("PolicyLibraryFile — v1 → v2 migration")
struct LibraryMigrationTests {
    @Test("a v1 file decodes into the three tiers with the expected counts and ids")
    func v1CountsAndShapes() throws {
        let store = MigrationFixtures.tempStore()
        defer { try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent()) }
        try MigrationFixtures.write(MigrationFixtures.v1Library, to: store)

        let loaded = try #require(store.load())
        #expect(loaded.schemaVersion == PolicyLibraryFile.currentSchemaVersion)
        // Profiles migrate in profileKey order: authuri_admin_settings first.
        #expect(loaded.policies.map(\.id) == ["admin_settings", "developer_tools"])
        // 3 profile rules + 1 unassigned rule, each split into rule + definition.
        #expect(loaded.rules.map(\.id) == ["prompt_network", "allow_brew",
                                           "deny_rm_system", "orphan_tcpdump"])
        #expect(loaded.definitions.map(\.id) == ["prompt_network", "allow_brew",
                                                 "deny_rm_system", "orphan_tcpdump"])
        // Every migrated assignment starts enabled and references a real rule.
        for policy in loaded.policies {
            #expect(policy.rules.allSatisfy { $0.enabled })
            #expect(policy.rules.allSatisfy { assignment in
                loaded.rules.contains { $0.id == assignment.ruleID }
            })
        }
    }

    @Test("metadata, wire settings, and matchers survive the split")
    func settingsPreserved() throws {
        let store = MigrationFixtures.tempStore()
        defer { try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent()) }
        try MigrationFixtures.write(MigrationFixtures.v1Library, to: store)
        let loaded = try #require(store.load())

        // Policy with v1 metadata: every field carries over.
        let dev = try #require(loaded.policies.first { $0.id == "developer_tools" })
        #expect(dev.name == "Developer Tools")
        #expect(dev.summary == "Engineer elevation")
        #expect(dev.scope.userGroups == ["Developers"])
        #expect(dev.scope.devices == "Developer workstations")
        #expect(dev.enabled == false)
        #expect(dev.policyVersion == "1.2.0")
        #expect(dev.profilePriority == 40)
        #expect(dev.createdAt == MigrationFixtures.epoch)
        #expect(dev.rules.map(\.ruleID) == ["allow_brew", "deny_rm_system"])

        // Policy without v1 metadata: name derived from the key, enabled.
        let admin = try #require(loaded.policies.first { $0.id == "admin_settings" })
        #expect(admin.name == "Admin Settings")
        #expect(admin.enabled == true)
        #expect(admin.policyVersion == "1.0.0")
        #expect(admin.profilePriority == 50)

        // Rule tier: decision + advanced settings from the wire rule.
        let brew = try #require(loaded.rules.first { $0.id == "allow_brew" })
        #expect(brew.name == "Homebrew install / upgrade")
        #expect(brew.detail == "Homebrew install / upgrade")
        #expect(brew.definitionIDs == ["allow_brew"])
        #expect(brew.action == .allow)
        #expect(brew.elevationType == .silent)
        #expect(brew.priority == 10)
        #expect(brew.useGlobalCache == false) // explicit cacheSeconds in v1
        #expect(brew.cacheSeconds == 300)

        let deny = try #require(loaded.rules.first { $0.id == "deny_rm_system" })
        #expect(deny.action == .deny)
        #expect(deny.useGlobalCache == true) // nil cacheSeconds in v1

        let network = try #require(loaded.rules.first { $0.id == "prompt_network" })
        #expect(network.elevationType == .prompt)
        #expect(network.requireJustification)
        #expect(network.maxGrantDurationSeconds == 600)

        // Definition tier: matchers and pins land unchanged.
        let brewDefinition = try #require(loaded.definitions.first { $0.id == "allow_brew" })
        #expect(brewDefinition.kind == .sudo)
        #expect(brewDefinition.commandPattern == "/opt/homebrew/bin/brew")
        #expect(brewDefinition.argPattern == "install|upgrade")
        #expect(brewDefinition.matchType == .prefixRegex)
        #expect(brewDefinition.requiredTeamID == "TEAM123456")
        #expect(brewDefinition.authURI == nil)

        let networkDefinition = try #require(loaded.definitions.first { $0.id == "prompt_network" })
        #expect(networkDefinition.kind == .authuri)
        #expect(networkDefinition.authURI == "system.preferences.network")
        #expect(networkDefinition.commandPattern == nil)
    }

    @Test("identical matchers dedupe into one shared definition; rule ids suffix")
    func dedupeAndRuleIDCollisions() throws {
        let store = MigrationFixtures.tempStore()
        defer { try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent()) }
        try MigrationFixtures.write(MigrationFixtures.v1CollidingLibrary, to: store)
        let loaded = try #require(store.load())

        // One shared definition for the identical (kind, matcher) pair.
        #expect(loaded.definitions.map(\.id) == ["allow_brew"])
        // Rules are never deduped — each wire rule migrates, suffixed in
        // profileKey order (alpha claims the base slug, beta gets _2).
        #expect(loaded.rules.map(\.id) == ["allow_brew", "allow_brew_2"])
        #expect(loaded.rules.allSatisfy { $0.definitionIDs == ["allow_brew"] })

        let alpha = try #require(loaded.policies.first { $0.id == "alpha" })
        let beta = try #require(loaded.policies.first { $0.id == "beta" })
        #expect(alpha.rules.map(\.ruleID) == ["allow_brew"])
        #expect(beta.rules.map(\.ruleID) == ["allow_brew_2"])
        // The suffixed rule keeps its own wire settings.
        #expect(loaded.rules.first { $0.id == "allow_brew_2" }?.name == "Homebrew for beta")
    }

    @Test("policy-id collisions across mechanisms suffix in profileKey order")
    func policyIDCollisions() throws {
        let store = MigrationFixtures.tempStore()
        defer { try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent()) }
        try MigrationFixtures.write(MigrationFixtures.v1SharedSlugLibrary, to: store)
        let loaded = try #require(store.load())

        #expect(loaded.policies.map(\.id) == ["shared", "shared_2"])
        // rules_authuri_shared sorts first, so it claims the base slug.
        #expect(loaded.policies.first { $0.id == "shared" }?.policyVersion == "2.0.0")
        #expect(loaded.policies.first { $0.id == "shared_2" }?.policyVersion == "3.0.0")
        // Distinct matchers do NOT dedupe.
        #expect(loaded.definitions.count == 2)
    }

    @Test("v1 unassignedRules land as policy-less library rules")
    func unassignedRulesBecomePolicyless() throws {
        let store = MigrationFixtures.tempStore()
        defer { try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent()) }
        try MigrationFixtures.write(MigrationFixtures.v1Library, to: store)
        let loaded = try #require(store.load())

        let orphan = try #require(loaded.rules.first { $0.id == "orphan_tcpdump" })
        #expect(orphan.definitionIDs == ["orphan_tcpdump"])
        #expect(orphan.elevationType == .prompt)
        #expect(orphan.requireJustification)
        #expect(orphan.maxGrantDurationSeconds == 1800)
        // No policy references it — it lives in the library, unassigned.
        #expect(loaded.policies.allSatisfy { policy in
            !policy.rules.contains { $0.ruleID == "orphan_tcpdump" }
        })
    }

    @Test("a v1 file without a top-level schemaVersion key still migrates")
    func missingSchemaVersionMigrates() throws {
        let store = MigrationFixtures.tempStore()
        defer { try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent()) }
        try MigrationFixtures.write(MigrationFixtures.v1Library, to: store)

        // Real pre-versioning files carried no top-level schemaVersion at all;
        // strip it via JSONSerialization surgery and decode again.
        var json = try MigrationFixtures.rawTopLevel(of: store)
        json.removeValue(forKey: "schemaVersion")
        try JSONSerialization.data(withJSONObject: json).write(to: store.url)

        let loaded = try #require(store.load())
        #expect(loaded.schemaVersion == PolicyLibraryFile.currentSchemaVersion)
        #expect(loaded.policies.count == 2)
        #expect(loaded.rules.count == 4)
    }

    @Test("loadOrCreate persists the migration, making it durable on disk")
    func migrationDurableThroughLoadOrCreate() throws {
        let store = MigrationFixtures.tempStore()
        defer { try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent()) }
        try MigrationFixtures.write(MigrationFixtures.v1Library, to: store)

        let model = PolicyBuilderModel.persistent(store: store)
        #expect(model.policies.count == 2)
        #expect(model.rules.count == 4)
        #expect(model.definitions.count == 4)

        // The file on disk is now v2 — the next launch decodes directly.
        let raw = try MigrationFixtures.rawTopLevel(of: store)
        #expect(raw["schemaVersion"] as? Int == PolicyLibraryFile.currentSchemaVersion)
        #expect(raw["policies"] != nil)
        #expect(raw["profiles"] == nil)
        #expect(raw["metadata"] == nil)
    }
}

// MARK: - v2 persistence

@MainActor
@Suite("PolicyLibraryFile — v2 round-trip")
struct LibraryV2RoundTripTests {
    @Test("a v2 file round-trips through disk value- and byte-stably")
    func v2RoundTrip() throws {
        let store = MigrationFixtures.tempStore()
        defer { try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent()) }

        // Fixture dates are fixed whole seconds, so ISO8601 encoding is
        // lossless and the loaded value compares equal to the in-memory fixture.
        let fixture = LibraryFixture.default
        #expect(store.save(fixture))
        let loaded = try #require(store.load())
        #expect(loaded.schemaVersion == PolicyLibraryFile.currentSchemaVersion)
        #expect(loaded.definitions == fixture.definitions)
        #expect(loaded.rules == fixture.rules)
        #expect(loaded.policies == fixture.policies)

        // Re-encoding the loaded file writes identical bytes (sorted keys,
        // stable date encoding) — the same guarantee export relies on.
        let firstBytes = try Data(contentsOf: store.url)
        #expect(store.save(loaded))
        let secondBytes = try Data(contentsOf: store.url)
        #expect(firstBytes == secondBytes)
    }

    @Test("a v2 file decodes as v2 — the migration path never touches it")
    func v2FileDecodesAsV2() throws {
        let store = MigrationFixtures.tempStore()
        defer { try? FileManager.default.removeItem(at: store.url.deletingLastPathComponent()) }
        let fixture = LibraryFixture.default
        #expect(store.save(fixture))

        // On-disk shape is the v2 contract: three tier arrays + version 2,
        // none of the legacy keys.
        let raw = try MigrationFixtures.rawTopLevel(of: store)
        #expect(raw["schemaVersion"] as? Int == 2)
        #expect(raw["definitions"] != nil)
        #expect(raw["rules"] != nil)
        #expect(raw["policies"] != nil)
        #expect(raw["profiles"] == nil)
        #expect(raw["metadata"] == nil)
        #expect(raw["unassignedRules"] == nil)

        // Ids come back verbatim — untouched by collision suffixing or
        // slug re-derivation (which only run during v1 migration).
        let loaded = try #require(store.load())
        #expect(loaded.definitions.map(\.id) == fixture.definitions.map(\.id))
        #expect(loaded.rules.map(\.id) == fixture.rules.map(\.id))
        #expect(loaded.policies.map(\.id) == fixture.policies.map(\.id))
    }
}
