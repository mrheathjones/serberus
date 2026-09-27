import Foundation
import Testing
@testable import PrivMgrCore

/// Validates the deployable sample artifacts in `Support/sample-profiles/`
/// against the same decoders the daemon runs, so a drifted sample can never
/// reach a test Mac.
@Suite("Sample deployment artifacts")
struct SampleArtifactTests {
    // MARK: Repo locations (resolved relative to this source file)

    private static let repoRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // SampleArtifactTests.swift
        .deletingLastPathComponent() // PrivMgrCoreTests
        .deletingLastPathComponent() // Tests
    private static let profilesDirectory = repoRoot.appendingPathComponent("Support/sample-profiles")
    private static let ruleSourcesDirectory = repoRoot.appendingPathComponent("Support/sample-rules")

    private static let bareRulesPlist = profilesDirectory
        .appendingPathComponent("\(BundleConfig.rulesDomain).plist")
    private static let bareConfigPlist = profilesDirectory
        .appendingPathComponent("\(BundleConfig.configDomain).plist")
    private static let sudoRulesMobileconfig = profilesDirectory
        .appendingPathComponent("rules_sudo_test.mobileconfig")
    private static let authURIRulesMobileconfig = profilesDirectory
        .appendingPathComponent("rules_authuri_test.mobileconfig")
    private static let breakGlassMobileconfig = profilesDirectory
        .appendingPathComponent("serberus-config-breakglass.mobileconfig")

    /// The exact `rules_*` key set each rules-bearing artifact is pinned to
    /// carry. Tests FAIL — never skip — when a pinned key is absent, so a
    /// renamed key can never ship undetected.
    private static let pinnedRuleKeys: [String: Set<String>] = [
        bareRulesPlist.lastPathComponent: ["rules_sudo_test", "rules_authuri_test"],
        sudoRulesMobileconfig.lastPathComponent: ["rules_sudo_test"],
        authURIRulesMobileconfig.lastPathComponent: ["rules_authuri_test"],
    ]

    // MARK: Plist helpers

    private func loadPlist(_ url: URL) throws -> [String: Any] {
        let data = try Data(contentsOf: url)
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        return try #require(plist as? [String: Any],
                            "\(url.lastPathComponent) root must be a dictionary")
    }

    /// The forced MCX settings for `domain` inside a Configuration profile —
    /// the flat dict that lands in `/Library/Managed Preferences/<domain>.plist`
    /// — asserting the wrapper shape every sample ships with (System scope,
    /// removal disallowed, `com.apple.ManagedClient.preferences` payload).
    private func payload(inMobileconfig url: URL, domain: String) throws -> [String: Any] {
        let root = try loadPlist(url)
        #expect(root["PayloadType"] as? String == "Configuration", "\(url.lastPathComponent)")
        #expect(root["PayloadScope"] as? String == "System", "\(url.lastPathComponent)")
        #expect(root["PayloadRemovalDisallowed"] as? Bool == true, "\(url.lastPathComponent)")
        let contents = try #require(root["PayloadContent"] as? [[String: Any]],
                                    "\(url.lastPathComponent)")
        let mcx = try #require(
            contents.first { $0["PayloadType"] as? String == "com.apple.ManagedClient.preferences" },
            "\(url.lastPathComponent) has no com.apple.ManagedClient.preferences payload"
        )
        let inner = try #require(mcx["PayloadContent"] as? [String: Any],
                                 "\(url.lastPathComponent) MCX payload has no PayloadContent")
        let domainDict = try #require(inner[domain] as? [String: Any],
                                      "\(url.lastPathComponent) has no \(domain) MCX entry")
        let forced = try #require(domainDict["Forced"] as? [[String: Any]],
                                  "\(url.lastPathComponent) \(domain) has no Forced array")
        return try #require(forced.first?["mcx_preference_settings"] as? [String: Any],
                            "\(url.lastPathComponent) \(domain) has no mcx_preference_settings")
    }

    /// Every `rules_*` entry in an artifact dictionary, requiring each to be
    /// the JSON *string* shape the rules domain is delivered as.
    private func ruleStrings(in dictionary: [String: Any], from name: String) throws -> [String: String] {
        var profiles: [String: String] = [:]
        for (key, value) in dictionary where key.hasPrefix(RuleSchemaConstants.profileKeyPrefix) {
            profiles[key] = try #require(value as? String,
                                         "\(name)/\(key) must be a JSON string value")
        }
        return profiles
    }

    /// All rules-bearing sample artifacts as (artifact name, key → JSON string).
    private func allRulesArtifacts() throws -> [(name: String, profiles: [String: String])] {
        var artifacts: [(name: String, profiles: [String: String])] = []
        let bare = try loadPlist(Self.bareRulesPlist)
        artifacts.append((Self.bareRulesPlist.lastPathComponent,
                          try ruleStrings(in: bare, from: Self.bareRulesPlist.lastPathComponent)))
        for url in [Self.sudoRulesMobileconfig, Self.authURIRulesMobileconfig] {
            let inner = try payload(inMobileconfig: url, domain: BundleConfig.rulesDomain)
            artifacts.append((url.lastPathComponent,
                              try ruleStrings(in: inner, from: url.lastPathComponent)))
        }
        return artifacts
    }

    /// A `Support/sample-rules/*.json` source decoded as the canonical profile.
    private func canonicalProfile(_ key: String) throws -> RuleProfile {
        let url = Self.ruleSourcesDirectory.appendingPathComponent("\(key).json")
        return try RuleProfile.decode(jsonData: Data(contentsOf: url), expectedKey: key)
    }

    /// Converts a config-domain plist dictionary into the Sendable shape
    /// ``DictionaryPreferencesSource`` requires, rejecting any value that is
    /// not one of the native types the sample is allowed to carry.
    private func sendableConfigDomain(_ dictionary: [String: Any]) -> [String: any Sendable] {
        var domain: [String: any Sendable] = [:]
        for (key, value) in dictionary {
            // Bool must precede the numeric branch: an NSNumber bridges to both
            // Bool and Int, so distinguish the true CFBoolean first, else a
            // daemonEnabled flag would be stored as an Int.
            if CFGetTypeID(value as CFTypeRef) == CFBooleanGetTypeID() {
                domain[key] = (value as? Bool) ?? false
            } else if let int = value as? Int {
                domain[key] = int
            } else if let string = value as? String {
                domain[key] = string
            } else if let arr = value as? [String] {
                domain[key] = arr
            } else if let nested = value as? [String: [String]] {
                domain[key] = nested
            } else {
                Issue.record("config key '\(key)' has non-native type \(type(of: value)) — samples must ship native plist values")
            }
        }
        return domain
    }

    /// Runs a config-domain dictionary through the production reader and
    /// asserts the break-glass invariants: clean parse, pass-through mode,
    /// admin group bypass, at least one named break-glass user.
    private func assertBreakGlassConfig(_ dictionary: [String: Any], from name: String) throws {
        // Native types, never a JSON string (a JSON string here silently
        // yields enforce + no bypass — the sudo-bricking hazard).
        let mode = try #require(dictionary["enforcementMode"] as? String,
                                "\(name): enforcementMode must be a native string")
        #expect(EnforcementMode(rawValue: mode) == .monitor,
                "\(name): break-glass sample must ship monitor, never enforce")
        #expect(!(dictionary["pamBypass"] is String),
                "\(name): pamBypass must be a native dict, not a JSON string")
        let bypass = try #require(dictionary["pamBypass"] as? [String: Any],
                                  "\(name): pamBypass must be a dictionary")
        let groups = try #require(bypass["groups"] as? [String], "\(name)")
        let users = try #require(bypass["users"] as? [String], "\(name)")
        #expect(groups.contains("admin"), "\(name): admin group is the recovery path")
        #expect(!users.isEmpty, "\(name): must name at least one break-glass user")

        let reader = ManagedPreferencesReader(source: DictionaryPreferencesSource(
            domains: [BundleConfig.configDomain: sendableConfigDomain(dictionary)]))
        let result = reader.readConfig()
        #expect(result.findings.isEmpty, "\(name): \(result.findings)")
        #expect(result.value.enforcementMode == .monitor, "\(name)")
        #expect(result.value.pamBypass == PAMBypass(groups: groups, users: users), "\(name)")
    }

    // MARK: Rules artifacts

    @Test("every rules_* value decodes as wire schema v1.0 and passes validation")
    func rulesArtifactsDecodeAndValidate() throws {
        let artifacts = try allRulesArtifacts()
        #expect(artifacts.count == 3)
        for artifact in artifacts {
            #expect(!artifact.profiles.isEmpty, "\(artifact.name) carries no rules_* keys")
            for (key, json) in artifact.profiles {
                let profile = try RuleProfile.decode(jsonString: json, expectedKey: key)
                #expect(profile.schemaVersion == RuleSchemaConstants.currentSchemaVersion,
                        "\(artifact.name)/\(key)")
                #expect(profile.profileKey == key, "\(artifact.name)/\(key)")
                let report = PolicyValidator().validate(profile)
                #expect(report.errors.isEmpty, "\(artifact.name)/\(key): \(report.errors)")
            }
        }
    }

    @Test("every rules artifact carries exactly its pinned rules_* keys")
    func artifactsCarryExactlyPinnedKeys() throws {
        let artifacts = try allRulesArtifacts()
        #expect(Set(artifacts.map { $0.name }) == Set(Self.pinnedRuleKeys.keys),
                "rules artifacts and pinnedRuleKeys must list the same files")
        for artifact in artifacts {
            let pinned = try #require(Self.pinnedRuleKeys[artifact.name],
                                      "\(artifact.name) has no pinned key set — add it to pinnedRuleKeys")
            #expect(Set(artifact.profiles.keys) == pinned,
                    "\(artifact.name) must carry exactly \(pinned.sorted()), found \(artifact.profiles.keys.sorted())")
        }
    }

    @Test("embedded profiles are semantically equal to their Support/sample-rules sources",
          arguments: ["rules_sudo_test", "rules_authuri_test"])
    func embeddedProfilesMatchSources(key: String) throws {
        let canonical = try canonicalProfile(key)
        for artifact in try allRulesArtifacts() {
            let pinned = try #require(Self.pinnedRuleKeys[artifact.name],
                                      "\(artifact.name) has no pinned key set — add it to pinnedRuleKeys")
            guard pinned.contains(key) else { continue }
            // A pinned key that is absent must FAIL, never skip: a renamed
            // key in the shipped artifact would otherwise go undetected.
            let json = try #require(artifact.profiles[key],
                                    "\(artifact.name) is pinned to carry \(key) but does not")
            let embedded = try RuleProfile.decode(jsonString: json, expectedKey: key)
            #expect(embedded == canonical, "\(artifact.name)/\(key) drifted from sample-rules source")
        }
    }

    @Test("embedded rules_* values parse identically through the production reader")
    func readerRoundTrip() throws {
        for artifact in try allRulesArtifacts() {
            let reader = ManagedPreferencesReader(source: DictionaryPreferencesSource(
                domains: [BundleConfig.rulesDomain: artifact.profiles]))
            let result = reader.readRuleProfiles()
            #expect(result.findings.isEmpty, "\(artifact.name): \(result.findings)")
            #expect(result.value.count == artifact.profiles.count, "\(artifact.name)")
        }
    }

    // MARK: Break-glass config artifacts

    @Test("break-glass bare config plist ships native values the reader accepts")
    func breakGlassBarePlist() throws {
        let root = try loadPlist(Self.bareConfigPlist)
        try assertBreakGlassConfig(root, from: Self.bareConfigPlist.lastPathComponent)
    }

    @Test("break-glass mobileconfig payload is the config domain with native values")
    func breakGlassMobileconfig() throws {
        // `payload(...)` returns exactly the forced MCX settings that land in
        // /Library/Managed Preferences/<configDomain>.plist.
        let settings = try payload(inMobileconfig: Self.breakGlassMobileconfig,
                                   domain: BundleConfig.configDomain)
        try assertBreakGlassConfig(settings, from: Self.breakGlassMobileconfig.lastPathComponent)
    }

    // MARK: Hygiene across the whole directory

    @Test("no sample artifact still carries the stale authenticate-admin description")
    func noStaleAuthenticateAdminText() throws {
        let files = try FileManager.default.contentsOfDirectory(
            at: Self.profilesDirectory, includingPropertiesForKeys: nil)
            .filter { ["plist", "mobileconfig"].contains($0.pathExtension) }
        #expect(files.count >= 5)
        for file in files {
            let content = try String(contentsOf: file, encoding: .utf8)
            // "authenticate-session-owner-or-admin" (2026-07-11 semantics)
            // does not contain this substring, so any hit is stale text.
            #expect(!content.contains("authenticate-admin"), "\(file.lastPathComponent)")
        }
    }

    /// The single MCX payload's `(domain, forced settings)` for any sample
    /// mobileconfig — the flat dict that lands in
    /// `/Library/Managed Preferences/<domain>.plist`.
    private func mcxDomainAndSettings(_ url: URL) throws -> (domain: String, settings: [String: Any]) {
        let root = try loadPlist(url)
        #expect(root["PayloadType"] as? String == "Configuration", "\(url.lastPathComponent)")
        #expect(root["PayloadScope"] as? String == "System", "\(url.lastPathComponent)")
        #expect(root["PayloadRemovalDisallowed"] as? Bool == true, "\(url.lastPathComponent)")
        let contents = try #require(root["PayloadContent"] as? [[String: Any]], "\(url.lastPathComponent)")
        let mcx = try #require(
            contents.first { $0["PayloadType"] as? String == "com.apple.ManagedClient.preferences" },
            "\(url.lastPathComponent) is not the com.apple.ManagedClient.preferences (MCX) shape Jamf renders")
        let inner = try #require(mcx["PayloadContent"] as? [String: Any], "\(url.lastPathComponent)")
        // Every Serberus profile targets exactly one domain.
        #expect(inner.count == 1, "\(url.lastPathComponent) MCX payload targets \(inner.count) domains")
        let domain = try #require(inner.keys.first, "\(url.lastPathComponent)")
        let domainDict = try #require(inner[domain] as? [String: Any], "\(url.lastPathComponent)")
        let forced = try #require(domainDict["Forced"] as? [[String: Any]],
                                  "\(url.lastPathComponent) \(domain) has no Forced array")
        let settings = try #require(forced.first?["mcx_preference_settings"] as? [String: Any],
                                    "\(url.lastPathComponent) \(domain) has no mcx_preference_settings")
        return (domain, settings)
    }

    /// EVERY sample `.mobileconfig` — not just the pinned canonical ones — must
    /// be sound MCX whose forced settings parse cleanly through the production
    /// reader for its domain. This closes the gap where a regenerated sample
    /// (e.g. the 1:1 rules/config profiles) could ship broken MCX nesting or a
    /// JSON-string value in the config domain (the "silently ignored → enforce
    /// + no bypass" brick) undetected.
    @Test("native Apple sample profiles are well-formed Configuration profiles")
    func nativeAppleProfilesAreSound() throws {
        // Managed background items (com.apple.servicemanagement) and any other
        // non-MCX Apple payloads still ship in sample-profiles/ and must be
        // valid Configuration profiles, even though the MCX assertions don't
        // apply to them.
        let files = try FileManager.default.contentsOfDirectory(
            at: Self.profilesDirectory, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "mobileconfig" }
            .filter { !isSerberusMCXProfile($0) }
        for url in files {
            let root = try loadPlist(url)
            #expect(root["PayloadType"] as? String == "Configuration", "\(url.lastPathComponent)")
            #expect(root["PayloadScope"] as? String == "System", "\(url.lastPathComponent)")
            let contents = try #require(root["PayloadContent"] as? [[String: Any]], "\(url.lastPathComponent)")
            #expect(!contents.isEmpty, "\(url.lastPathComponent) has no payloads")
            for payload in contents {
                #expect(payload["PayloadType"] as? String != nil, "\(url.lastPathComponent) payload missing PayloadType")
            }
        }
    }

    /// True when a profile carries a Serberus MCX (`com.apple.ManagedClient.preferences`)
    /// payload. Native Apple profiles (e.g. `com.apple.servicemanagement`
    /// managed background items) live in the same directory but are a different
    /// shape — they are validated as well-formed plists by `plutil`, not by the
    /// Serberus-MCX assertions here.
    private func isSerberusMCXProfile(_ url: URL) -> Bool {
        guard let root = try? loadPlist(url),
              let contents = root["PayloadContent"] as? [[String: Any]] else { return false }
        return contents.contains { $0["PayloadType"] as? String == "com.apple.ManagedClient.preferences" }
    }

    @Test("every sample .mobileconfig is sound MCX and parses through the production reader")
    func everyMobileconfigIsSoundMCX() throws {
        let files = try FileManager.default.contentsOfDirectory(
            at: Self.profilesDirectory, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "mobileconfig" }
            // Serberus MCX profiles only; native Apple payloads are a different
            // shape and are covered by the plist-soundness check below.
            .filter(isSerberusMCXProfile)
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        #expect(files.count >= 5)

        for url in files {
            let name = url.lastPathComponent
            let (domain, settings) = try mcxDomainAndSettings(url)
            // The rules domain and any of its sibling sub-domains
            // (com.herojoneslabs.serberus.rules.<suffix>) are all rule profiles —
            // the daemon composes native arrays across them.
            let isRulesDomain = domain == BundleConfig.rulesDomain
                || domain.hasPrefix(BundleConfig.rulesDomain + ".")
            switch domain {
            case _ where isRulesDomain:
                // A rules-domain sample may carry EITHER `rules_*` JSON-string
                // keys (app publish / .mobileconfig export) OR a native `rules`
                // array (Jamf Custom Schema) — or both. Validate whichever the
                // sample uses; require at least one.
                let stringRules = try ruleStrings(in: settings, from: name)
                let nativeRules = settings[RuleSchemaConstants.nativeRulesKey] as? [[String: Any]]
                #expect(!stringRules.isEmpty || !(nativeRules ?? []).isEmpty,
                        "\(name) carries neither rules_* keys nor a native rules array")

                for (key, json) in stringRules {
                    let profile = try RuleProfile.decode(jsonString: json, expectedKey: key)
                    #expect(profile.schemaVersion == RuleSchemaConstants.currentSchemaVersion, "\(name)/\(key)")
                    #expect(PolicyValidator().validate(profile).errors.isEmpty, "\(name)/\(key)")
                }
                // Every native rule must decode through the daemon's converter.
                for (index, dict) in (nativeRules ?? []).enumerated() {
                    if case .invalid(let reason) = Rule.fromManagedDictionary(dict) {
                        Issue.record("\(name) native rule[\(index)] rejected by the reader: \(reason)")
                    }
                }
                // The rules_* keys still parse clean through the production reader.
                let reader = ManagedPreferencesReader(source: DictionaryPreferencesSource(
                    domains: [domain: stringRules]))
                #expect(reader.readRuleProfiles().findings.isEmpty, "\(name): \(reader.readRuleProfiles().findings)")

            case BundleConfig.configDomain:
                // Native plist types only — a JSON-string value here is
                // config_invalid and the config is not adopted, so the reader
                // must parse clean.
                let reader = ManagedPreferencesReader(source: DictionaryPreferencesSource(
                    domains: [domain: sendableConfigDomain(settings)]))
                let result = reader.readConfig()
                #expect(result.findings.isEmpty, "\(name): \(result.findings)")

            default:
                Issue.record("\(name) has unexpected MCX domain '\(domain)' — add reader coverage for it")
            }
        }
    }

    /// The shipped Jamf Custom Schema for the rules domain must parse, target
    /// the rules domain, and its per-rule fields must exactly match the keys
    /// ``Rule/fromManagedDictionary(_:)`` reads — so the in-Jamf authoring form
    /// and the daemon's native reader can never silently drift.
    @Test("rules Custom Schema parses, targets the rules domain, and matches the native reader")
    func rulesCustomSchemaMatchesReader() throws {
        let url = Self.repoRoot
            .appendingPathComponent("Support/jamf-schemas/\(BundleConfig.rulesDomain).json")
        let data = try Data(contentsOf: url)
        let root = try #require(
            try JSONSerialization.jsonObject(with: data) as? [String: Any],
            "schema root must be an object")
        #expect(root["__preferencedomain"] as? String == BundleConfig.rulesDomain)

        let properties = try #require(root["properties"] as? [String: Any])
        #expect(properties[RuleSchemaConstants.nativePolicyVersionKey] != nil)
        #expect(properties[RuleSchemaConstants.nativeProfilePriorityKey] != nil)

        let rules = try #require(properties[RuleSchemaConstants.nativeRulesKey] as? [String: Any])
        #expect(rules["type"] as? String == "array")
        let items = try #require(rules["items"] as? [String: Any])
        let itemProps = try #require(items["properties"] as? [String: Any])

        // The exact field set the daemon's native converter reads.
        let expected: Set<String> = [
            "id", "type", "action", "description", "priority",
            "commandPattern", "matchType", "argPattern", "authURI",
            "elevationType", "logArguments",
            "requireJustification", "maxGrantDurationSeconds",
            "cacheSeconds", "requiredTeamID", "requiredBinaryHash",
            "appTeamID", "appBundleID",
        ]
        #expect(Set(itemProps.keys) == expected,
                "schema rule fields \(Set(itemProps.keys).sorted()) drifted from the reader's \(expected.sorted())")

        // A rule built to the schema's enum values must decode cleanly.
        let sample: [String: Any] = [
            "id": "schema-check", "type": "sudo", "action": "allow",
            "commandPattern": "/usr/bin/true", "matchType": "exact",
        ]
        guard case .rule = Rule.fromManagedDictionary(sample) else {
            Issue.record("schema-shaped rule failed to decode"); return
        }
    }

    /// Multi-purpose binaries whose verbs include a way to root or to
    /// changing the Mac for every user (`jamf createAccount`/`policy`,
    /// `xcode-select -s`, `dscl`/`dseditgroup` edits, `launchctl` loads…). An
    /// allow or prompt rule on one must name the verb with `argPattern`.
    private static let multiVerbBinaries: Set<String> = [
        "/usr/local/bin/jamf", "/usr/local/jamf/bin/jamf", "/usr/local/bin/jamfconnect",
        "/usr/bin/xcode-select", "/usr/bin/dscl", "/usr/sbin/dseditgroup", "/bin/launchctl",
        "/usr/bin/defaults", "/usr/bin/security", "/usr/sbin/systemsetup", "/usr/sbin/softwareupdate",
        "/usr/bin/profiles", "/usr/bin/sqlite3", "/usr/bin/env", "/bin/sh", "/bin/bash", "/bin/zsh",
    ]

    /// Every rule in every sample rules source and profile: the
    /// `Support/sample-rules` JSON, `rules_*` JSON strings, and native `rules`
    /// arrays, in every `.mobileconfig` and bare `.plist`.
    private func allSampleRules() throws -> [(source: String, rule: Rule)] {
        var found: [(source: String, rule: Rule)] = []
        let sources = try FileManager.default.contentsOfDirectory(at: Self.ruleSourcesDirectory,
                                                                  includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" }
        for url in sources {
            let key = url.deletingPathExtension().lastPathComponent
            for rule in try canonicalProfile(key).rules { found.append((url.lastPathComponent, rule)) }
        }
        func walk(_ value: Any, _ name: String) {
            if let dict = value as? [String: Any] {
                for (key, inner) in dict {
                    if key.hasPrefix(RuleSchemaConstants.profileKeyPrefix), let json = inner as? String,
                       let profile = try? RuleProfile.decode(jsonString: json, expectedKey: key) {
                        for rule in profile.rules { found.append((name, rule)) }
                    } else if key == RuleSchemaConstants.nativeRulesKey, let natives = inner as? [[String: Any]] {
                        for native in natives {
                            if case .rule(let rule) = Rule.fromManagedDictionary(native) { found.append((name, rule)) }
                        }
                    } else {
                        walk(inner, name)
                    }
                }
            } else if let array = value as? [Any] {
                for inner in array { walk(inner, name) }
            }
        }
        let profiles = try FileManager.default.contentsOfDirectory(at: Self.profilesDirectory,
                                                                   includingPropertiesForKeys: nil)
            .filter { ["mobileconfig", "plist"].contains($0.pathExtension) }
        for url in profiles {
            walk(try loadPlist(url), url.lastPathComponent)
        }
        return found
    }

    @Test("no sample allow or prompt rule on a multi-verb binary (jamf, xcode-select, dscl, …) lacks an argPattern")
    func multiVerbRulesNameTheVerb() throws {
        let rules = try allSampleRules()
        // The walk must actually reach the jamf samples, or this proves nothing.
        #expect(rules.contains { $0.rule.match.commandPattern == "/usr/local/bin/jamf" })
        for (source, rule) in rules where rule.type == .sudo && rule.action == .allow {
            guard let command = rule.match.commandPattern, Self.multiVerbBinaries.contains(command) else { continue }
            let pattern = rule.match.argPattern ?? ""
            #expect(!pattern.isEmpty, "\(source): rule '\(rule.id)' allows every \(command) verb; add an argPattern")
        }
    }

    /// Folders a standard user can own or write to. That user can swap a binary
    /// in one, so an allow or prompt rule on it hands them root.
    private static let userOwnableFolders = [
        "/opt/homebrew/", "/usr/local/", "/Users/", "~", "/tmp/", "/private/tmp/", "/private/var/tmp/",
    ]

    /// The root-owned Jamf binaries, the only `/usr/local` paths a rule may target.
    private static let rootOwnedJamfBinaries: Set<String> = [
        "/usr/local/bin/jamf", "/usr/local/jamf/bin/jamf", "/usr/local/bin/jamfconnect",
    ]

    @Test("no sample allow or prompt rule targets a binary in a folder a standard user can own")
    func rulesAvoidUserOwnedFolders() throws {
        let rules = try allSampleRules()
        // The walk must reach the /usr/local jamf samples, or the exception goes untested.
        #expect(rules.contains { $0.rule.match.commandPattern == "/usr/local/bin/jamf" })
        for (source, rule) in rules where rule.type == .sudo && rule.action == .allow {
            let command = rule.match.commandPattern ?? ""
            guard !Self.rootOwnedJamfBinaries.contains(command) else { continue }
            // The trailing slash also catches a prefix rule on the folder itself.
            let inUserFolder = Self.userOwnableFolders.contains { (command + "/").hasPrefix($0) }
            #expect(!inUserFolder, "\(source): rule '\(rule.id)' runs \(command) as root, and whoever owns its folder can swap it")
        }
    }

    @Test("payload UUIDs are unique across all sample mobileconfigs")
    func payloadUUIDsAreUnique() throws {
        let files = try FileManager.default.contentsOfDirectory(
            at: Self.profilesDirectory, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "mobileconfig" }
        var seen: Set<String> = []
        for file in files {
            let root = try loadPlist(file)
            var uuids = [try #require(root["PayloadUUID"] as? String, "\(file.lastPathComponent)")]
            let contents = try #require(root["PayloadContent"] as? [[String: Any]],
                                        "\(file.lastPathComponent)")
            for inner in contents {
                uuids.append(try #require(inner["PayloadUUID"] as? String,
                                          "\(file.lastPathComponent)"))
            }
            for uuid in uuids {
                #expect(seen.insert(uuid).inserted,
                        "\(file.lastPathComponent): PayloadUUID \(uuid) reused — copy-paste hazard")
            }
        }
    }
}
