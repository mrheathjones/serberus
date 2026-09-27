import Foundation
import Testing
@testable import PrivMgrCore

@Suite("PolicyValidator — pre-export pipeline")
struct PolicyValidatorTests {
    @Test("a well-formed profile passes")
    func validProfile() {
        let report = PolicyValidator().validate(Fixtures.profile(rules: [Fixtures.sudoRule()]))
        #expect(report.isExportable)
        #expect(report.errors.isEmpty)
    }

    @Test("grant duration: -1 (never grant), 0 (org default) and seconds pass; other negatives are refused everywhere")
    func grantDuration() {
        func rule(_ seconds: Int) -> Rule {
            var rule = Fixtures.sudoRule()
            rule.conditions.maxGrantDurationSeconds = seconds
            return rule
        }
        for ok in [-1, 0, 300, RuleSchemaConstants.maxGrantSeconds] {
            let report = PolicyValidator().validate(Fixtures.profile(rules: [rule(ok)]))
            #expect(!report.errors.contains { $0.check == "grant-duration" }, "\(ok)")
            #expect(rule(ok).runtimeRejectionReason == nil, "\(ok)")
        }
        let tooLong = PolicyValidator().validate(Fixtures.profile(rules: [rule(RuleSchemaConstants.maxGrantSeconds + 1)]))
        #expect(tooLong.warnings.contains { $0.check == "grant-duration" })
        for bad in [-2, -300] {
            let report = PolicyValidator().validate(Fixtures.profile(rules: [rule(bad)]))
            #expect(report.errors.contains { $0.check == "grant-duration" }, "\(bad)")
            #expect(rule(bad).runtimeRejectionReason != nil, "\(bad)")
        }
        // The native reader applies the same gate.
        let native: [String: Any] = ["id": "g", "type": "sudo", "action": "allow",
                                     "commandPattern": "/usr/bin/true", "matchType": "exact"]
        var never = native; never["maxGrantDurationSeconds"] = -1
        guard case .rule(let parsed) = Rule.fromManagedDictionary(never) else {
            Issue.record("-1 was refused by the native reader"); return
        }
        #expect(parsed.conditions.maxGrantDurationSeconds == RuleSchemaConstants.neverGrantSeconds)
        var negative = native; negative["maxGrantDurationSeconds"] = -5
        if case .rule = Rule.fromManagedDictionary(negative) { Issue.record("-5 was accepted by the native reader") }
    }

    @Test("unrecognized schemaVersion blocks")
    func schemaVersion() {
        var profile = Fixtures.profile(rules: [Fixtures.sudoRule()])
        profile.schemaVersion = "9.9"
        let report = PolicyValidator().validate(profile)
        #expect(!report.isExportable)
        #expect(report.errors.contains { $0.check == "schema-version" })
    }

    @Test("non-semver policyVersion blocks")
    func semver() {
        for bad in ["1.0", "v1.0.0", "1.0.0-beta", "", "1.a.0"] {
            let report = PolicyValidator().validate(
                Fixtures.profile(policyVersion: bad, rules: [Fixtures.sudoRule()])
            )
            #expect(!report.isExportable, "expected '\(bad)' to be rejected")
        }
        #expect(PolicyValidator.isSemver("1.0.0"))
        #expect(PolicyValidator.isSemver("12.34.56"))
    }

    @Test("profileKey naming convention enforced")
    func profileKey() {
        for bad in ["rules_", "rules_other_x", "authuri_x", "rules_sudo_", "rules_sudo_UPPER"] {
            let report = PolicyValidator().validate(Fixtures.profile(key: bad, rules: [Fixtures.sudoRule()]))
            #expect(report.errors.contains { $0.check == "profile-key" }, "expected '\(bad)' rejected")
        }
        #expect(PolicyValidator.isValidProfileKey("rules_authuri_keychain_modify"))
        #expect(PolicyValidator.isValidProfileKey("rules_sudo_homebrew2"))
    }

    @Test("profilePriority must be positive")
    func profilePriority() {
        let report = PolicyValidator().validate(Fixtures.profile(priority: 0, rules: [Fixtures.sudoRule()]))
        #expect(report.errors.contains { $0.check == "profile-priority" })
    }

    @Test("invalid auth URI blocks")
    func authURIFormat() {
        let rule = Fixtures.authURIRule(authURI: "system keychain modify")
        let report = PolicyValidator().validate(
            Fixtures.profile(key: "rules_authuri_test", rules: [rule])
        )
        #expect(report.errors.contains { $0.check == "auth-uri" })
    }

    @Test("uncompilable regex blocks")
    func regexSyntax() {
        let rule = Fixtures.sudoRule(commandPattern: "([unclosed", matchType: .regex)
        let report = PolicyValidator().validate(Fixtures.profile(rules: [rule]))
        #expect(report.errors.contains { $0.check == "regex-syntax" })

        let argRule = Fixtures.sudoRule(argPattern: "(bad", matchType: .exact)
        let argReport = PolicyValidator().validate(Fixtures.profile(rules: [argRule]))
        #expect(argReport.errors.contains { $0.check == "regex-syntax" })
    }

    @Test("invalid glob blocks")
    func globSyntax() {
        let rule = Fixtures.sudoRule(commandPattern: "/opt/[unclosed", matchType: .glob)
        let report = PolicyValidator().validate(Fixtures.profile(rules: [rule]))
        #expect(report.errors.contains { $0.check == "glob-syntax" })
    }

    @Test("cacheSeconds out of range blocks")
    func cacheRange() {
        for bad in [-1, 86_401] {
            let report = PolicyValidator().validate(
                Fixtures.profile(rules: [Fixtures.sudoRule(cacheSeconds: bad)])
            )
            #expect(report.errors.contains { $0.check == "cache-seconds" }, "expected \(bad) rejected")
        }
    }

    @Test("duplicate rule IDs block")
    func duplicateIDs() {
        let report = PolicyValidator().validate(
            Fixtures.profile(rules: [Fixtures.sudoRule(id: "dup"), Fixtures.sudoRule(id: "dup", priority: 20)])
        )
        #expect(report.errors.contains { $0.check == "duplicate-rule-id" })
    }

    @Test("equal-priority allow/deny on the same target blocks")
    func priorityConflict() {
        let report = PolicyValidator().validate(Fixtures.profile(rules: [
            Fixtures.sudoRule(id: "a", action: .allow, priority: 5),
            Fixtures.sudoRule(id: "b", action: .deny, priority: 5),
        ]))
        #expect(report.errors.contains { $0.check == "priority-conflict" })
    }

    @Test("rule type mismatched with profile key blocks")
    func typeCoherence() {
        let report = PolicyValidator().validate(
            Fixtures.profile(key: "rules_authuri_test", rules: [Fixtures.sudoRule()])
        )
        #expect(report.errors.contains { $0.check == "rule-type" })
    }

    @Test("broad any-allow without identity pin warns but does not block")
    func broadMatchWarning() {
        let rule = Fixtures.sudoRule(commandPattern: nil, matchType: .any)
        let report = PolicyValidator().validate(Fixtures.profile(rules: [rule]))
        #expect(report.isExportable)
        #expect(report.warnings.contains { $0.check == "broad-match" })
    }

    @Test("public single-rule validation flags relative paths and type mismatches")
    func publicRuleValidation() {
        let relative = Fixtures.sudoRule(commandPattern: "relative/path")
        let issues = PolicyValidator.validate(rule: relative, expectedType: .sudo)
        #expect(issues.contains { $0.check == "command-pattern" && $0.severity == .error })

        let mismatched = PolicyValidator.validate(rule: Fixtures.sudoRule(), expectedType: .authuri)
        #expect(mismatched.contains { $0.check == "rule-type" })
    }
}

@Suite("ConflictDetector — cross-profile")
struct ConflictDetectorTests {
    @Test("opposing actions on the same target across profiles are reported")
    func opposingActions() {
        let mine = Fixtures.profile(key: "rules_sudo_mine",
                                    rules: [Fixtures.sudoRule(id: "allow-brew", action: .allow)])
        let published = Fixtures.profile(key: "rules_sudo_published",
                                         rules: [Fixtures.sudoRule(id: "deny-brew", action: .deny)])
        let conflicts = ConflictDetector().crossProfileConflicts(mine, against: [published])
        #expect(conflicts.count == 1)
        #expect(conflicts.first?.detail.contains("opposing actions") == true)
    }

    @Test("duplicate coverage is reported as a distinct detail")
    func duplicateCoverage() {
        let mine = Fixtures.profile(key: "rules_sudo_mine", rules: [Fixtures.sudoRule()])
        let published = Fixtures.profile(key: "rules_sudo_published", rules: [Fixtures.sudoRule(id: "other")])
        let conflicts = ConflictDetector().crossProfileConflicts(mine, against: [published])
        #expect(conflicts.first?.detail.contains("duplicate") == true)
    }

    @Test("different targets do not conflict")
    func noConflict() {
        let mine = Fixtures.profile(key: "rules_sudo_mine", rules: [Fixtures.sudoRule()])
        let published = Fixtures.profile(
            key: "rules_sudo_published",
            rules: [Fixtures.sudoRule(id: "other", commandPattern: "/usr/bin/say")]
        )
        #expect(ConflictDetector().crossProfileConflicts(mine, against: [published]).isEmpty)
    }

    @Test("a profile never conflicts with itself")
    func selfExcluded() {
        let mine = Fixtures.profile(key: "rules_sudo_mine", rules: [Fixtures.sudoRule()])
        #expect(ConflictDetector().crossProfileConflicts(mine, against: [mine]).isEmpty)
    }

    @Test("identity-scoped rules pinning different apps on the same right do not conflict")
    func differentAppsSameRightNoConflict() {
        let gitkraken = Fixtures.profile(key: "rules_authuri_app_identity_gitkraken", rules: [
            Fixtures.authURIRule(
                id: "gitkraken__gitkraken",
                authURI: "com.apple.ServiceManagement.daemons.modify",
                appIdentity: AppIdentityBranch(teamID: "TEAM1", bundleID: "com.axosoft.gitkraken")
            ),
        ])
        let devin = Fixtures.profile(key: "rules_authuri_windsurf_devin", rules: [
            Fixtures.authURIRule(
                id: "windsurf_devin__devin",
                authURI: "com.apple.ServiceManagement.daemons.modify",
                appIdentity: AppIdentityBranch(teamID: "TEAM2", bundleID: "com.windsurf.devin")
            ),
        ])
        #expect(ConflictDetector().crossProfileConflicts(gitkraken, against: [devin]).isEmpty)
    }

    @Test("the same app pinned twice across profiles still conflicts")
    func samePinTwiceStillConflicts() {
        let branch = AppIdentityBranch(teamID: "TEAM1", bundleID: "com.axosoft.gitkraken")
        let mine = Fixtures.profile(key: "rules_authuri_app_identity_gitkraken", rules: [
            Fixtures.authURIRule(
                id: "gitkraken__gitkraken",
                authURI: "com.apple.ServiceManagement.daemons.modify",
                appIdentity: branch
            ),
        ])
        let published = Fixtures.profile(key: "rules_authuri_app_identity_gitkraken_dup", rules: [
            Fixtures.authURIRule(
                id: "gitkraken__gitkraken2",
                authURI: "com.apple.ServiceManagement.daemons.modify",
                appIdentity: branch
            ),
        ])
        #expect(ConflictDetector().crossProfileConflicts(mine, against: [published]).count == 1)
    }

    @Test("an identity-scoped rule alongside a plain rewrite of the same right still conflicts")
    func identityVersusPlainStillConflicts() {
        let identity = Fixtures.profile(key: "rules_authuri_app_identity_gitkraken", rules: [
            Fixtures.authURIRule(
                id: "gitkraken__gitkraken",
                authURI: "com.apple.ServiceManagement.daemons.modify",
                appIdentity: AppIdentityBranch(teamID: "TEAM1", bundleID: "com.axosoft.gitkraken")
            ),
        ])
        let plain = Fixtures.profile(key: "rules_authuri_daemons_modify", rules: [
            Fixtures.authURIRule(id: "allow-all", authURI: "com.apple.ServiceManagement.daemons.modify"),
        ])
        #expect(ConflictDetector().crossProfileConflicts(identity, against: [plain]).count == 1)
    }
}

@Suite("MobileConfigGenerator")
struct MobileConfigGeneratorTests {
    @Test("export embeds the profile JSON under the rules domain")
    func roundTrip() throws {
        let profile = Fixtures.profile(rules: [Fixtures.sudoRule()])
        let export = try MobileConfigGenerator().export(profile, organization: "Test Org")

        let plist = try PropertyListSerialization.propertyList(from: export.data, format: nil)
        let root = try #require(plist as? [String: Any])
        #expect(root["PayloadType"] as? String == "Configuration")
        #expect(root["PayloadScope"] as? String == "System")

        let envelope = try mcxPayloadEnvelope(inMobileconfig: export.data)
        #expect(envelope["PayloadType"] as? String == "com.apple.ManagedClient.preferences")

        let settings = try mcxSettings(inMobileconfig: export.data, domain: BundleConfig.rulesDomain)
        let embedded = try #require(settings[profile.profileKey] as? String)
        let decoded = try RuleProfile.decode(jsonString: embedded, expectedKey: profile.profileKey)
        #expect(decoded == profile)
    }

    @Test("validation errors block export")
    func blockedExport() {
        let bad = Fixtures.profile(policyVersion: "not-semver", rules: [Fixtures.sudoRule()])
        #expect(throws: ExportError.self) {
            try MobileConfigGenerator().export(bad, organization: "Test Org")
        }
    }

    @Test("re-export of the same version is byte-identical (deterministic)")
    func deterministicExport() throws {
        let profile = Fixtures.profile(rules: [Fixtures.sudoRule()])
        let first = try MobileConfigGenerator().export(profile, organization: "Test Org")
        let second = try MobileConfigGenerator().export(profile, organization: "Test Org")
        #expect(first.data == second.data)
        #expect(first.payloadUUID == second.payloadUUID)
    }

    @Test("different versions get different payload UUIDs")
    func versionedUUIDs() throws {
        let v1 = Fixtures.profile(policyVersion: "1.0.0", rules: [Fixtures.sudoRule()])
        let v2 = Fixtures.profile(policyVersion: "1.0.1", rules: [Fixtures.sudoRule()])
        let exportV1 = try MobileConfigGenerator().export(v1, organization: "Test Org")
        let exportV2 = try MobileConfigGenerator().export(v2, organization: "Test Org")
        #expect(exportV1.payloadUUID != exportV2.payloadUUID)
    }
}

@Suite("PolicyValidator — authuri target gate (shared with the runtime parser)")
struct PolicyValidatorTargetGateTests {
    private func issues(_ right: String, _ action: RuleAction) -> [ValidationIssue] {
        PolicyValidator.validate(rule: Fixtures.authURIRule(action: action, authURI: right), expectedType: .authuri)
    }

    @Test("rule-class names and trailing-dot wildcards are errors for any action", arguments: [
        "is-root", "entitled", "default", "authenticate-admin", "use-login-window-ui",
        "system.privilege.", "config.", "sys.openfile.", "system.preferences.",
    ])
    func targetErrors(right: String) {
        for action in RuleAction.allCases {
            #expect(issues(right, action).contains { $0.check == "auth-uri-target" && $0.severity == .error },
                    "\(right) \(action)")
        }
    }

    @Test("a deny on a login/unlock right is an error; an allow is not caught by that check")
    func denyForbidden() {
        for right in ["system.disk.unlock", "system.platformsso.login", "system.login.screensaver"] {
            #expect(issues(right, .deny).contains { $0.check == "auth-uri-deny" }, "\(right)")
            #expect(!issues(right, .allow).contains { $0.check == "auth-uri-deny" }, "\(right)")
        }
    }

    @Test("an allow on FileVault unlock / Platform SSO is an error too (auth-uri-allow)")
    func allowForbidden() {
        for right in ["system.disk.unlock", "system.platformsso.login", "system.platformsso.register"] {
            #expect(issues(right, .allow).contains { $0.check == "auth-uri-allow" }, "\(right)")
            #expect(!issues(right, .deny).contains { $0.check == "auth-uri-allow" }, "\(right)")
        }
        #expect(!issues("system.preferences.datetime", .allow).contains { $0.check == "auth-uri-allow" })
    }

    @Test("names outside ^[A-Za-z0-9][A-Za-z0-9._-]*$ are refused (NUL, whitespace, non-ASCII, leading dot)")
    func invalidCharacters() {
        for right in ["com.apple.\u{0}x", "system.preferences.date time", "system.préférences", ".system.x",
                      "system/preferences", "system.preferences\n", "-system.x", ""] {
            #expect(AuthRightTargetPolicy.targetRejectionReason(right) != nil, "\(right.debugDescription)")
            #expect(issues(right, .allow).contains { $0.check == "auth-uri" }, "\(right.debugDescription)")
            #expect(Fixtures.authURIRule(action: .deny, authURI: right).runtimeRejectionReason != nil)
        }
        for right in ["system.preferences.datetime", "com.apple.ServiceManagement.daemons.modify",
                      "com.example.third_party-right", "system.volume.external.adopt"] {
            #expect(AuthRightTargetPolicy.targetRejectionReason(right) == nil, "\(right)")
        }
    }

    @Test("Serberus's own composition rows are never rule targets")
    func ownRowsRefused() {
        let row = AuthURICompositionNaming.nativeDefaultRow(for: "system.preferences.datetime")
        #expect(AuthRightTargetPolicy.targetRejectionReason(row) != nil)
        #expect(issues(row, .allow).contains { $0.check == "auth-uri-target" })
    }

    @Test("ordinary rights pass the gate")
    func ordinaryRightsPass() {
        for right in ["system.preferences.datetime", "system.install.software", "system.keychain-modify"] {
            for action in RuleAction.allCases {
                #expect(!issues(right, action).contains { $0.check == "auth-uri-target" || $0.check == "auth-uri-deny" })
            }
        }
    }

    @Test("the validator and the runtime parser agree")
    func agreesWithRuntime() {
        for right in ["is-root", "system.privilege.", "system.privilege", "system.disk.unlock", "system.preferences.datetime"] {
            for action in RuleAction.allCases {
                let rule = Fixtures.authURIRule(action: action, authURI: right)
                let validatorRefuses = PolicyValidator.validate(rule: rule, expectedType: .authuri)
                    .contains { $0.check == "auth-uri-target" || $0.check == "auth-uri-deny" || $0.check == "auth-uri-allow" }
                #expect(validatorRefuses == (rule.runtimeRejectionReason != nil), "\(right) \(action)")
            }
        }
    }
}

/// Keeps the root-equivalent DENY-list honest against the rights macOS
/// actually ships: every admin-gated right in this Mac's
/// `/System/Library/Security/authorization.plist` must be protected,
/// root-equivalent, or explicitly reviewed as safe. A new macOS that adds an
/// admin-gated right fails here until someone classifies it.
///
/// "Admin-gated" is the daemon's own reading (``AuthRightNativeGate``): a
/// definition with a `rule` key and no `class` is a rule delegation, rule
/// chains are resolved through the plist's `rules`, and only a plain admin
/// gate counts. A plain allow on any other right is refused at apply time
/// from the live definition, so it needs no entry here.
@Suite("AuthRightTargetPolicy sweep")
struct AuthRightTargetPolicySweepTests {
    static let plistPath = "/System/Library/Security/authorization.plist"
    static let hasShippedDatabase = FileManager.default.isReadableFile(atPath: plistPath)

    /// The plist's rights and rules. A reference resolves to a rule first,
    /// then to a right (authd keeps both in one table).
    static func shippedDatabase() throws -> (rights: [String: Any], lookup: AuthRightNativeGate.Lookup) {
        let data = try #require(FileManager.default.contents(atPath: plistPath))
        let plist = try #require(try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any])
        let rights = try #require(plist["rights"] as? [String: Any])
        let rules = plist["rules"] as? [String: Any] ?? [:]
        return (rights, { (rules[$0] ?? rights[$0]) as? [String: Any] })
    }

    /// A right no rule may ever target (the empty default right, a no-dot
    /// rule class) needs no classification. Trailing-dot wildcards DO: a
    /// rule can name (and so create) any child under them.
    static func needsClassification(_ name: String) -> Bool {
        name.hasSuffix(".") || AuthRightTargetPolicy.targetRejectionReason(name) == nil
    }

    @Test("every admin-gated right on this Mac is protected, root-equivalent, or reviewed as safe",
          .enabled(if: hasShippedDatabase, "no readable /System/Library/Security/authorization.plist on this host"))
    func sweep() throws {
        let (rights, lookup) = try Self.shippedDatabase()
        var unclassified: [String] = []
        var gated = 0
        for (name, value) in rights {
            guard let definition = value as? [String: Any], Self.needsClassification(name),
                  AuthRightNativeGate.isAdminGated(definition, lookup: lookup) else { continue }
            gated += 1
            if AuthRightTargetPolicy.isProtected(name) || AuthRightTargetPolicy.isRootEquivalent(name)
                || AuthRightTargetPolicy.knownNonRootEquivalentRights.contains(name) { continue }
            unclassified.append(name)
        }
        #expect(gated > 0, "no admin-gated rights found — has the plist format changed?")
        #expect(unclassified.isEmpty, """
            Unclassified admin-gated rights (add each to AuthRightTargetPolicy.rootEquivalentRightPrefixes \
            — the default when in doubt — or, after review, to knownNonRootEquivalentRights): \
            \(unclassified.sorted().joined(separator: ", "))
            """)
    }

    @Test("every right on this Mac that delegates to a mechanism chain is detected as one",
          .enabled(if: hasShippedDatabase, "no readable /System/Library/Security/authorization.plist on this host"))
    func mechanismChainsReported() throws {
        let (rights, lookup) = try Self.shippedDatabase()
        var chains: [String: String] = [:]
        for (name, value) in rights {
            guard let definition = value as? [String: Any],
                  let chain = AuthRightNativeGate.mechanismChain(definition, lookup: lookup) else { continue }
            chains[name] = chain
            // A mechanism chain is never a plain admin gate.
            #expect(!AuthRightNativeGate.isAdminGated(definition, lookup: lookup), "\(name)")
        }
        #expect(!chains.isEmpty)
        // The rights that reach a mechanism rule only THROUGH a rule
        // reference, which a class-only check misses.
        for name in ["com.apple.ctk.pair", "system.preferences.continuity"] where rights[name] != nil {
            #expect(chains[name] != nil, "\(name) should reach a mechanism chain")
        }
    }

    @Test("every reviewed-safe right this Mac defines is a plain admin gate (so the entry is reachable)",
          .enabled(if: hasShippedDatabase, "no readable /System/Library/Security/authorization.plist on this host"))
    func reviewedSafeRightsAreAdminGated() throws {
        let (rights, lookup) = try Self.shippedDatabase()
        for name in AuthRightTargetPolicy.knownNonRootEquivalentRights {
            guard let definition = rights[name] as? [String: Any] else { continue }
            #expect(AuthRightNativeGate.isAdminGated(definition, lookup: lookup),
                    "\(name): \(AuthRightNativeGate.plainAllowRefusal(definition, lookup: lookup) ?? "")")
        }
    }

    @Test("every real right name on this Mac passes the character gate",
          .enabled(if: hasShippedDatabase, "no readable /System/Library/Security/authorization.plist on this host"))
    func realNamesPassCharacterGate() throws {
        let (rights, _) = try Self.shippedDatabase()
        let rejected = rights.keys.filter { !$0.isEmpty && !AuthRightTargetPolicy.hasValidCharacters($0) }
        #expect(rejected.isEmpty, "\(rejected.sorted())")
    }

    @Test("the reviewed-safe set never overlaps protected or root-equivalent")
    func classificationsAreDisjoint() {
        for name in AuthRightTargetPolicy.knownNonRootEquivalentRights {
            #expect(!AuthRightTargetPolicy.isProtected(name), "\(name)")
            #expect(!AuthRightTargetPolicy.isRootEquivalent(name), "\(name)")
        }
    }

    @Test("the shipped samples, library and docs rights stay allowable")
    func shippedRightsAllowable() {
        for name in ["system.preferences", "system.preferences.datetime", "system.preferences.printing",
                     "system.preferences.network", "system.preferences.dateandtime.changetimezone",
                     "system.install.software"] {
            #expect(AuthRightTargetPolicy.knownNonRootEquivalentRights.contains(name), "\(name)")
            #expect(Fixtures.authURIRule(action: .allow, authURI: name).runtimeRejectionReason == nil, "\(name)")
        }
    }

    @Test("review additions: write-anywhere, debugger, smart-card binding, startup disk are root-equivalent",
          arguments: ["com.apple.desktopservices", "com.apple.desktopservices.scripted",
                      "com.apple.app-sandbox.replace-file", "com.apple.app-sandbox.set-attributes",
                      "com.apple.app-sandbox.create-symlink", "com.apple.lldb.LaunchUsingXPC",
                      "com.apple.ctkbind.admin", "system.preferences.startupdisk",
                      "com.apple.dt.instruments.process.analysis", "com.apple.dt.anything"])
    func reviewAdditionsRootEquivalent(right: String) {
        #expect(AuthRightTargetPolicy.isRootEquivalent(right))
    }

    @Test("review additions: built-ins, login keychain, Kerberos, restart and shutdown are protected",
          arguments: ["com.apple.builtin.authenticate", "system.keychain.create.loginkc",
                      "com.apple.KerberosAgent", "system.restart", "system.shutdown"])
    func reviewAdditionsProtected(right: String) {
        #expect(AuthRightTargetPolicy.isProtected(right))
    }
}

/// The daemon's reading of a right's native gate, on synthetic definitions
/// shaped like the ones macOS ships.
@Suite("AuthRightNativeGate")
struct AuthRightNativeGateTests {
    static var rules: [String: [String: Any]] { [
        "admin": ["class": "user", "group": "admin", "shared": true],
        "authenticate-admin": ["class": "user", "group": "admin", "timeout": 0],
        "authenticate-admin-30": ["class": "user", "group": "admin", "timeout": 30],
        "is-admin": ["class": "user", "group": "admin", "authenticate-user": false],
        "is-root": ["class": "user", "authenticate-user": false, "allow-root": true],
        "entitled": ["class": "evaluate-mechanisms", "mechanisms": ["builtin:entitled,privileged"]],
        "on-console": ["class": "evaluate-mechanisms", "mechanisms": ["builtin:on-console"]],
        "entitled-admin": ["class": "rule", "k-of-n": 2, "rule": ["is-admin", "entitled"]],
        "entitled-admin-or-authenticate-admin": ["class": "rule", "k-of-n": 1, "rule": ["entitled-admin", "authenticate-admin-30"]],
        "root-or-entitled-admin-or-authenticate-admin": ["class": "rule", "k-of-n": 1, "rule": ["is-root", "entitled-admin-or-authenticate-admin"]],
        "authenticate-session-owner": ["class": "user", "session-owner": true],
        "kcunlock": ["class": "evaluate-mechanisms", "extract-password": true,
                     "mechanisms": ["builtin:unlock-keychain", "builtin:kc-verify,privileged"]],
        "lpadmin": ["class": "user", "group": "_lpadmin"],
        "default": ["class": "user", "group": "admin", "shared": true],
        "loop-a": ["class": "rule", "rule": "loop-b"],
        "loop-b": ["class": "rule", "rule": "loop-a"],
    ] }
    static var lookup: AuthRightNativeGate.Lookup { { rules[$0] } }

    private func refusal(_ definition: [String: Any]) -> String? {
        AuthRightNativeGate.plainAllowRefusal(definition, lookup: Self.lookup)
    }

    @Test("plain admin gates are admin-gated, directly or through rule chains")
    func adminGated() {
        #expect(refusal(["class": "user", "group": "admin", "allow-root": true]) == nil)
        #expect(refusal(["class": "rule", "rule": "authenticate-admin"]) == nil)
        #expect(refusal(["class": "rule", "rule": ["authenticate-admin"]]) == nil)
        // An any-of array whose other branches admit only admins or root.
        #expect(refusal(["class": "rule", "rule": "root-or-entitled-admin-or-authenticate-admin"]) == nil)
        #expect(refusal(["class": "rule", "k-of-n": 1, "rule": ["is-root", "is-admin", "authenticate-admin-30"]]) == nil)
    }

    @Test("a definition with a rule key but no class is a rule delegation")
    func classlessRule() {
        #expect(refusal(["rule": "default"]) == nil)
        #expect(refusal(["rule": "authenticate-session-owner"]) != nil)
    }

    @Test("session owner only, other groups, entitlements and requirements are not admin gates")
    func narrowerGates() {
        #expect(refusal(["class": "user", "session-owner": true])?.contains("session owner alone") == true)
        #expect(refusal(["class": "user", "group": "_lpoperator"])?.contains("_lpoperator") == true)
        #expect(refusal(["class": "rule", "rule": "entitled"]) != nil)
        #expect(refusal(["class": "user", "group": "admin", "entitled": true])?.contains("entitled") == true)
        #expect(refusal(["class": "user", "group": "admin", "entitled-group": true]) != nil)
        #expect(refusal(["class": "user", "group": "admin", "require-apple-signed": true]) != nil)
        #expect(refusal(["class": "user", "group": "admin", "requirement": "anchor apple"]) != nil)
        // entitled-admin on its own: the entitlement is part of the gate.
        #expect(refusal(["class": "rule", "rule": "entitled-admin"]) != nil)
    }

    @Test("an any-of branch that admits non-admins (on-console, a bare entitlement, another group) is refused")
    func widerAlternatives() {
        #expect(refusal(["class": "rule", "k-of-n": 1, "rule": ["on-console", "is-admin", "is-root"]]) != nil)
        #expect(refusal(["class": "rule", "k-of-n": 1, "rule": ["entitled", "admin"]]) != nil)
        #expect(refusal(["class": "rule", "k-of-n": 1, "rule": ["lpadmin", "admin"]]) != nil)
    }

    @Test("class=allow is reported as already open; class=deny as denied")
    func openAndDenied() {
        #expect(refusal(["class": "allow"])?.contains("already open") == true)
        #expect(refusal(["class": "deny"])?.contains("denied") == true)
    }

    @Test("unknown shapes are refused: undefined rules, loops, partial k-of-n, unknown classes")
    func unsure() {
        #expect(refusal(["class": "rule", "rule": "no-such-rule"])?.contains("not defined") == true)
        #expect(refusal(["class": "rule", "rule": "loop-a"]) != nil)
        #expect(refusal(["class": "rule", "k-of-n": 2, "rule": ["admin", "authenticate-admin", "is-admin"]]) != nil)
        #expect(refusal(["class": "future-class"]) != nil)
        #expect(refusal([:]) != nil)
    }

    @Test("mechanism chains are found through rule references; entitlement and console predicates are not chains")
    func mechanismChains() {
        let chain = AuthRightNativeGate.mechanismChain(["class": "rule", "rule": "kcunlock"], lookup: Self.lookup)
        #expect(chain?.contains("kcunlock") == true)
        #expect(AuthRightNativeGate.mechanismChain(["class": "evaluate-mechanisms", "mechanisms": ["x:y"]], lookup: Self.lookup) != nil)
        #expect(AuthRightNativeGate.mechanismChain(["class": "rule", "rule": "root-or-entitled-admin-or-authenticate-admin"],
                                                   lookup: Self.lookup) == nil)
        #expect(AuthRightNativeGate.mechanismChain(["class": "rule", "k-of-n": 1, "rule": ["on-console", "admin"]],
                                                   lookup: Self.lookup) == nil)
        #expect(AuthRightNativeGate.mechanismChain(["class": "rule", "rule": "loop-a"], lookup: Self.lookup) == nil)
    }

    /// `levels` layers of `width` rights; every right in a layer is a
    /// `k-of-n: 1` over every right in the next, and the last layer is the
    /// admin rule. The shape a user can pre-create with `config.add.`.
    private static func layeredGraph(levels: Int, width: Int) -> [String: [String: Any]] {
        var graph: [String: [String: Any]] = ["admin": ["class": "user", "group": "admin"]]
        for level in 0..<levels {
            let next = level + 1 < levels ? (0..<width).map { "n\(level + 1).\($0)" } : ["admin"]
            for index in 0..<width {
                graph["n\(level).\(index)"] = ["class": "rule", "k-of-n": 1, "rule": next]
            }
        }
        return graph
    }

    @Test("a wide reference graph is classified with each rule looked up once, and a graph over the budget is refused")
    func boundedLookups() {
        final class Counter: @unchecked Sendable { var lookups = 0 }
        let top: [String: Any] = ["class": "rule", "k-of-n": 1, "rule": (0..<3).map { "n0.\($0)" }]

        // 15 layers of 3 (inside the depth limit): about 3^15 paths, 46
        // distinct rules.
        let small = Self.layeredGraph(levels: 15, width: 3)
        let counter = Counter()
        let verdict = AuthRightNativeGate.plainAllowRefusal(top, lookup: { counter.lookups += 1; return small[$0] })
        #expect(verdict == nil)
        #expect(counter.lookups <= small.count, "\(counter.lookups)")

        // 17 layers of 20: more distinct rules than the budget.
        let wide = Self.layeredGraph(levels: 17, width: 20)
        let wideTop: [String: Any] = ["class": "rule", "k-of-n": 1, "rule": (0..<20).map { "n0.\($0)" }]
        let wideCounter = Counter()
        let refusal = AuthRightNativeGate.plainAllowRefusal(wideTop, lookup: { wideCounter.lookups += 1; return wide[$0] })
        #expect(refusal?.contains("more than \(AuthRightNativeGate.maxLookups)") == true, "\(refusal ?? "nil")")
        #expect(wideCounter.lookups <= AuthRightNativeGate.maxLookups, "\(wideCounter.lookups)")

        // The mechanism search is bounded the same way, and reports the
        // unfinished search instead of "no chain".
        let chainCounter = Counter()
        let chain = AuthRightNativeGate.mechanismChain(wideTop, lookup: { chainCounter.lookups += 1; return wide[$0] })
        #expect(chain?.contains("more than") == true, "\(chain ?? "nil")")
        #expect(chainCounter.lookups <= AuthRightNativeGate.maxLookups)
    }

    @Test("an unsatisfiable or malformed k-of-n is refused, even over a single rule")
    func impossibleKofN() {
        #expect(refusal(["class": "rule", "k-of-n": 3, "rule": ["admin", "authenticate-admin"]])?.contains("k-of-n") == true)
        #expect(refusal(["class": "rule", "k-of-n": 2, "rule": ["admin"]])?.contains("k-of-n") == true)
        #expect(refusal(["class": "rule", "k-of-n": 2, "rule": "admin"])?.contains("k-of-n") == true)
        #expect(refusal(["class": "rule", "k-of-n": 0, "rule": ["admin", "authenticate-admin"]])?.contains("k-of-n") == true)
        #expect(refusal(["class": "rule", "k-of-n": "1", "rule": ["admin", "authenticate-admin"]])?.contains("k-of-n") == true)
        // k equal to the count is an all-of; 1 is an any-of.
        #expect(refusal(["class": "rule", "k-of-n": 2, "rule": ["admin", "authenticate-admin"]]) == nil)
        #expect(refusal(["class": "rule", "k-of-n": 1, "rule": ["admin"]]) == nil)
    }

    @Test("a definition that runs its own mechanisms is not a plain admin gate, and is a mechanism chain")
    func ownMechanisms() {
        let mfa: [String: Any] = ["class": "user", "group": "admin",
                                  "mechanisms": ["VendorMFA:check", "builtin:authenticate,privileged"]]
        #expect(refusal(mfa)?.contains("runs its own mechanisms") == true)
        #expect(AuthRightNativeGate.mechanismChain(mfa, lookup: Self.lookup)?.contains("VendorMFA:check") == true)
        // Reached through a rule reference.
        let lookup: AuthRightNativeGate.Lookup = { $0 == "admin-mfa" ? mfa : Self.rules[$0] }
        #expect(AuthRightNativeGate.plainAllowRefusal(["class": "rule", "rule": "admin-mfa"], lookup: lookup) != nil)
        #expect(AuthRightNativeGate.mechanismChain(["class": "rule", "rule": "admin-mfa"], lookup: lookup)?.contains("admin-mfa") == true)
        // Even predicate-only mechanisms on a class=user rule are not the plain shape.
        #expect(refusal(["class": "user", "group": "admin", "mechanisms": ["builtin:on-console"]]) != nil)
    }

    @Test("credential settings come from the class=user rule a single-reference chain reaches")
    func credentialSettings() {
        let direct = AuthRightNativeGate.credentialSettings(["class": "user", "group": "admin", "timeout": 900, "shared": false],
                                                            lookup: Self.lookup)
        #expect(direct.timeout == 900 && direct.shared == false)
        let delegated = AuthRightNativeGate.credentialSettings(["class": "rule", "rule": "authenticate-admin-30"], lookup: Self.lookup)
        #expect(delegated.timeout == 30 && delegated.shared == nil)
        // The is-root branch authenticates nobody, so only the admin branch counts.
        let anyOf = AuthRightNativeGate.credentialSettings(["class": "rule", "k-of-n": 1, "rule": ["is-root", "admin"]],
                                                           lookup: Self.lookup)
        #expect(anyOf.timeout == nil && anyOf.shared == true && anyOf.passwordOnly == nil)
    }

    @Test("an any-of native carries the shortest admin-branch timeout, shared only when all are, and password-only when any is")
    func credentialSettingsAnyOf() {
        // system.printingmanager: is-admin (no timeout) or authenticate-admin (timeout 0).
        let printing = AuthRightNativeGate.credentialSettings(
            ["class": "rule", "k-of-n": 1, "rule": ["is-admin", "authenticate-admin"]], lookup: Self.lookup)
        #expect(printing.timeout == 0)
        // Neither branch sets `shared` in these fixtures, so none is carried.
        #expect(printing.shared == nil)
        #expect(printing.passwordOnly == nil)

        let lookup: AuthRightNativeGate.Lookup = {
            switch $0 {
            case "admin-120-shared": return ["class": "user", "group": "admin", "timeout": 120, "shared": true]
            case "admin-30-shared-password": return ["class": "user", "group": "admin", "timeout": 30, "shared": true,
                                                     "password-only": true]
            default: return Self.rules[$0]
            }
        }
        let mixed = AuthRightNativeGate.credentialSettings(
            ["class": "rule", "k-of-n": 1, "rule": ["is-root", "admin-120-shared", "admin-30-shared-password"]], lookup: lookup)
        #expect(mixed.timeout == 30)
        #expect(mixed.shared == true)
        #expect(mixed.passwordOnly == true)

        // A nested any-of is read through.
        let nested = AuthRightNativeGate.credentialSettings(
            ["class": "rule", "rule": "root-or-entitled-admin-or-authenticate-admin"], lookup: Self.lookup)
        #expect(nested.timeout == 30)

        // A single class=user rule carries password-only as it is.
        let direct = AuthRightNativeGate.credentialSettings(
            ["class": "user", "group": "admin", "password-only": true], lookup: Self.lookup)
        #expect(direct.passwordOnly == true)
    }

    @Test("an undefined right is read through the wildcard that governs it")
    func governingWildcard() {
        let rights: [String: Any] = [
            "system.": ["class": "rule", "rule": ["default"]],
            "system.volume.external.": ["class": "rule", "k-of-n": 1, "rule": ["on-console", "admin"]],
            "": ["class": "rule", "rule": ["default"]],
        ]
        let rules: [String: Any] = Self.rules
        #expect(AuthRightNativeGate.plainAllowRefusal("system.preferences.dateandtime.changetimezone", rights: rights, rules: rules) == nil)
        #expect(AuthRightNativeGate.plainAllowRefusal("system.volume.external.x", rights: rights, rules: rules)?
            .contains("system.volume.external.") == true)
        #expect(AuthRightNativeGate.plainAllowRefusal("com.vendor.right", rights: rights, rules: rules) == nil)
        #expect(AuthRightNativeGate.plainAllowRefusal("com.vendor.right", rights: [:], rules: rules) == nil)
    }
}

/// Authoring-time warnings for rules the daemon will not enforce.
@Suite("PolicyValidator: allows the Mac drops")
struct DroppedAllowWarningTests {
    private func warnings(_ action: RuleAction, _ right: String, app: AppIdentityBranch? = nil) -> [String] {
        let rule = Fixtures.authURIRule(action: action, authURI: right, appIdentity: app)
        return PolicyValidator.validate(rule: rule, expectedType: .authuri)
            .filter { $0.severity == .warning }.map(\.check)
    }

    @Test("a rule on a protected right warns, whatever its action")
    func protectedWarns() {
        #expect(warnings(.allow, "com.apple.security.sudo").contains("auth-uri-protected"))
        #expect(warnings(.deny, "system.restart").contains("auth-uri-protected"))
    }

    @Test("a plain allow on a root-equivalent right warns; a deny or an identity-scoped allow does not")
    func rootEquivalentWarns() {
        #expect(warnings(.allow, "system.privilege.admin").contains("auth-uri-root-equivalent"))
        #expect(!warnings(.deny, "system.privilege.admin").contains("auth-uri-root-equivalent"))
        let app = AppIdentityBranch(teamID: "ABCDE12345", bundleID: "com.example.app")
        #expect(!warnings(.allow, "system.privilege.admin", app: app).contains("auth-uri-root-equivalent"))
    }

    @Test("the shipped sample rights raise no drop warning")
    func samplesClean() {
        for right in ["system.preferences", "system.preferences.datetime", "system.preferences.printing",
                      "system.install.software", "system.preferences.dateandtime.changetimezone"] {
            #expect(warnings(.allow, right).isEmpty, "\(right): \(warnings(.allow, right))")
        }
    }

    @Test("a plain allow on a right this Mac's macOS does not gate with an admin password warns",
          .enabled(if: AuthRightTargetPolicySweepTests.hasShippedDatabase, "no readable authorization.plist"))
    func nativeGateWarns() throws {
        let (rights, _) = try AuthRightTargetPolicySweepTests.shippedDatabase()
        // `system.print.admin` is gated to _lpadmin wherever macOS ships it.
        guard rights["system.print.admin"] != nil else { return }
        #expect(warnings(.allow, "system.print.admin").contains("auth-uri-native-gate"))
        #expect(!warnings(.deny, "system.print.admin").contains("auth-uri-native-gate"))
    }
}
