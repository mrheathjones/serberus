import Foundation

/// Generates `.mobileconfig` configuration profiles that deliver rule
/// profiles into the `com.herojoneslabs.serberus.rules` managed preference domain.
///
/// Export is gated by the full ``PolicyValidator`` pipeline — a profile with
/// any blocking error cannot be exported. Cross-profile conflicts are
/// surfaced separately by ``ConflictDetector`` and require acknowledgement
/// in the Policy Builder UI before this generator is invoked.
///
/// ## Payload shape — why `com.apple.ManagedClient.preferences`
///
/// Every payload is wrapped in the `com.apple.ManagedClient.preferences`
/// (MCX `Forced` → `mcx_preference_settings`) format — the exact shape Jamf
/// Pro emits for its "Application & Custom Settings" payload. A bare
/// custom-domain `PayloadType` (e.g. `com.herojoneslabs.serberus.rules`) has
/// no renderer in the Jamf console: an uploaded profile deploys correctly but
/// shows *no payloads* in the GUI. The MCX wrapper is one Jamf recognizes, so
/// the same uploaded `.mobileconfig` now renders its payloads.
///
/// This changes only how the profile is *authored*, never what it *delivers*:
/// macOS composes both forms into an identical
/// `/Library/Managed Preferences/<domain>.plist`, which is what
/// ``ManagedPreferencesReader`` reads — so the daemon sees exactly the same
/// values either way.
public struct MobileConfigGenerator: Sendable {
    public init() {}

    /// Result of a successful export.
    public struct Export: Sendable, Equatable {
        /// Serialized XML plist payload, ready to write as `.mobileconfig`.
        public let data: Data
        /// Top-level PayloadUUID (stable per profileKey + policyVersion).
        public let payloadUUID: UUID
        /// Suggested filename, e.g. `rules_sudo_homebrew-1.0.0.mobileconfig`.
        public let suggestedFilename: String
    }

    /// Result of a settings-plist export — the flat preference-domain plist for
    /// Jamf's "Application & Custom Settings → Upload File" flow, where the
    /// operator uploads just the settings dict and names the preference domain.
    public struct SettingsPlist: Sendable, Equatable {
        /// Serialized XML plist of the flat forced settings, ready to write as
        /// `<domain>.plist`. This is byte-for-byte what lands in
        /// `/Library/Managed Preferences/<domain>.plist` on a managed Mac.
        public let data: Data
        /// The preference domain the operator enters in Jamf (e.g.
        /// `com.herojoneslabs.serberus.rules`).
        public let domain: String
        /// Suggested filename, `<domain>.plist`.
        public let suggestedFilename: String
    }

    /// Validates `profile` and generates a `.mobileconfig` delivering it as
    /// a single `rules_*` key in the rules domain.
    ///
    /// - Parameters:
    ///   - profile: The rule profile to export.
    ///   - organization: PayloadOrganization shown in System Settings.
    /// - Throws: ``ExportError/validationFailed(issues:)`` when any blocking
    ///   validation error exists; ``ExportError/serializationFailed(reason:)``
    ///   on plist encoding failure.
    public func export(_ profile: RuleProfile, organization: String) throws -> Export {
        let report = PolicyValidator().validate(profile)
        guard report.isExportable else {
            throw ExportError.validationFailed(issues: report.errors.map(\.description))
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys] // deterministic output
        let ruleJSON: String
        do {
            ruleJSON = String(decoding: try encoder.encode(profile), as: UTF8.self)
        } catch {
            throw ExportError.serializationFailed(reason: String(describing: error))
        }

        // UUIDs are derived deterministically from profileKey + policyVersion
        // so re-exporting the same version produces an identical profile and
        // Jamf updates rather than duplicates.
        let payloadUUID = Self.stableUUID(seed: "\(profile.profileKey)|\(profile.policyVersion)|payload")
        let contentUUID = Self.stableUUID(seed: "\(profile.profileKey)|\(profile.policyVersion)|content")

        let payload = Self.managedPreferencesPayload(
            domain: BundleConfig.rulesDomain,
            settings: [profile.profileKey: ruleJSON],
            identifier: "\(BundleConfig.rulesDomain).\(profile.profileKey)",
            uuid: contentUUID,
            displayName: "Serberus Rules — \(profile.profileKey)"
        )
        let root = Self.configurationRoot(
            identifier: "\(BundleConfig.rulesDomain).\(profile.profileKey)",
            uuid: payloadUUID,
            displayName: "Serberus — \(profile.profileKey) (\(profile.policyVersion))",
            description: "Serberus rule profile \(profile.profileKey), policy version \(profile.policyVersion).",
            organization: organization,
            payload: payload
        )

        return Export(
            data: try Self.serialize(root),
            payloadUUID: payloadUUID,
            suggestedFilename: "\(profile.profileKey)-\(profile.policyVersion).mobileconfig"
        )
    }

    /// Validates every profile and generates ONE `.mobileconfig` whose single
    /// rules-domain payload carries N `rules_*` keys — one JSON string per
    /// profile, exactly the shape ``ManagedPreferencesReader`` already reads.
    ///
    /// The Policy Builder's three-tier model can compile one authored policy
    /// into both a sudo and an authuri profile; delivering them in one
    /// configuration profile keeps install/remove atomic on the device.
    /// The single-profile ``export(_:organization:)`` is unchanged.
    ///
    /// Determinism mirrors the single-profile path exactly: profiles are
    /// sorted by `profileKey`, each is JSON-encoded with sorted keys, and the
    /// payload UUIDs derive from the joined `profileKey|policyVersion` pairs —
    /// so re-exporting the same versions produces an identical profile and
    /// Jamf updates rather than duplicates.
    ///
    /// - Throws: ``ExportError/validationFailed(issues:)`` when `profiles` is
    ///   empty, contains a duplicate `profileKey`, or any profile has a
    ///   blocking validation error (all offending profiles are reported at
    ///   once); ``ExportError/serializationFailed(reason:)`` on encoding
    ///   failure.
    public func export(profiles: [RuleProfile], organization: String) throws -> Export {
        let (sorted, settings) = try Self.validatedRulesSettings(profiles)

        // Seeded from every key+version pair so any member's version bump
        // yields a new identity, matching the single-profile convention.
        let seedBody = sorted.map { "\($0.profileKey)|\($0.policyVersion)" }.joined(separator: ",")
        let payloadUUID = Self.stableUUID(seed: "\(seedBody)|payload")
        let contentUUID = Self.stableUUID(seed: "\(seedBody)|content")

        let joinedKeys = sorted.map(\.profileKey).joined(separator: "+")
        let identifier = "\(BundleConfig.rulesDomain).\(joinedKeys)"
        let described = sorted.map { "\($0.profileKey) (\($0.policyVersion))" }.joined(separator: ", ")

        let payload = Self.managedPreferencesPayload(
            domain: BundleConfig.rulesDomain,
            settings: settings,
            identifier: identifier,
            uuid: contentUUID,
            displayName: "Serberus Rules — \(sorted.map(\.profileKey).joined(separator: ", "))"
        )
        let root = Self.configurationRoot(
            identifier: identifier,
            uuid: payloadUUID,
            displayName: "Serberus — \(described)",
            description: "Serberus rule profiles: \(described).",
            organization: organization,
            payload: payload
        )

        // One profile degrades to the single-profile filename convention so
        // sudo-only or authuri-only policies keep familiar names.
        let suggestedFilename = sorted.count == 1
            ? "\(sorted[0].profileKey)-\(sorted[0].policyVersion).mobileconfig"
            : "\(joinedKeys)-\(sorted[0].policyVersion).mobileconfig"

        return Export(data: try Self.serialize(root), payloadUUID: payloadUUID,
                      suggestedFilename: suggestedFilename)
    }

    /// Emits the flat rules-domain plist for every compiled profile — the exact
    /// dict `/Library/Managed Preferences/\(BundleConfig.rulesDomain).plist`
    /// resolves to on a managed Mac, ready to upload through Jamf's
    /// "Application & Custom Settings → Upload File" flow (enter the rules
    /// domain as the preference domain).
    ///
    /// Validation, sorting, and JSON encoding are shared with
    /// ``export(profiles:organization:)`` so the settings plist and the
    /// `.mobileconfig` always carry byte-identical rule payloads.
    ///
    /// - Throws: ``ExportError/validationFailed(issues:)`` when `profiles` is
    ///   empty, has a duplicate `profileKey`, or any profile has a blocking
    ///   validation error; ``ExportError/serializationFailed(reason:)`` on
    ///   plist encoding failure.
    public func rulesSettingsPlist(profiles: [RuleProfile]) throws -> SettingsPlist {
        let (_, settings) = try Self.validatedRulesSettings(profiles)
        return SettingsPlist(
            data: try Self.serialize(settings),
            domain: BundleConfig.rulesDomain,
            suggestedFilename: "\(BundleConfig.rulesDomain).plist"
        )
    }

    /// Generates a `.mobileconfig` delivering the JIT local-admin policy into
    /// the `com.herojoneslabs.serberus.jit` managed domain.
    ///
    /// Unlike rule export there is no per-profile validation gate; the schema is
    /// small and every field has a fail-safe default, but a `jamfConnect`
    /// provider with no command is rejected so an operator can't ship a policy
    /// that can never elevate.
    public func exportJITAdmin(_ policy: JITAdminPolicy, organization: String) throws -> Export {
        let payloadUUID = Self.stableUUID(seed: "jit|\(policy.provider.rawValue)|payload")
        let contentUUID = Self.stableUUID(seed: "jit|\(policy.provider.rawValue)|content")

        var settings: [String: Any] = [
            "provider": policy.provider.rawValue,
            "eligibleGroups": policy.eligibleGroups,
            "maxDurationSeconds": policy.effectiveDurationSeconds,
            "requireJustification": policy.requireJustification,
            "justificationMinLength": policy.justificationMinLength,
        ]
        if policy.provider == .jamfConnect {
            let command = policy.effectiveJamfConnectCommand
            settings["jamfConnectCommand"] = [
                "path": command.path,
                "arguments": command.arguments,
            ]
        }

        let payload = Self.managedPreferencesPayload(
            domain: BundleConfig.jitDomain,
            settings: settings,
            identifier: "\(BundleConfig.jitDomain).policy",
            uuid: contentUUID,
            displayName: "Serberus JIT Admin"
        )
        let root = Self.configurationRoot(
            identifier: "\(BundleConfig.jitDomain).policy",
            uuid: payloadUUID,
            displayName: "Serberus — JIT Admin Policy",
            description: "Serberus just-in-time local-admin elevation policy.",
            organization: organization,
            payload: payload
        )
        return Export(data: try Self.serialize(root), payloadUUID: payloadUUID,
                      suggestedFilename: "serberus-jit-admin.mobileconfig")
    }

    /// Generates a `.mobileconfig` delivering daemon behavior + break-glass
    /// settings into the `com.herojoneslabs.serberus.config` managed domain.
    ///
    /// Every value is emitted as its native plist type — `pamBypass` and
    /// `sudoEnrollment` are dictionaries of string arrays, NOT JSON strings —
    /// exactly the shapes ``ManagedPreferencesReader/readConfig()`` expects.
    ///
    /// The Jamf connection keys (`jamfProURL`, `jamfAPIClientID`,
    /// `jamfAPIClientSecret`) are deliberately never emitted: they remain a
    /// separately delivered profile in the same domain. Managed preferences
    /// union across profiles per domain, so both payloads compose on-device.
    public func exportDaemonConfig(_ config: SerberusConfig, organization: String) throws -> Export {
        // Seeded on the enforcement mode only (the JIT convention: identity
        // stable across setting tweaks), so re-exporting updates the existing
        // MDM profile rather than duplicating it.
        let payloadUUID = Self.stableUUID(seed: "config|\(config.enforcementMode.rawValue)|payload")
        let contentUUID = Self.stableUUID(seed: "config|\(config.enforcementMode.rawValue)|content")

        // Native dict-of-arrays, parity with pamBypass — NOT a JSON string, so
        // ManagedPreferencesReader.readConfig() decodes it. `group` is inserted
        // only when non-nil because PropertyListSerialization rejects an
        // NSNull/nil value. The IdP-group enrollment keys are carried whenever IdP
        // enrollment is on, so a round trip through Commander never silently
        // drops them.
        //
        // An EMPTY enrollment (no users, no group, IdP off) is left out
        // entirely: absence already means "enroll nobody", and emitting
        // `{ users: [] }` would collide with a separately delivered enrollment
        // profile (the enrollment schema allows only one profile to set it).
        let enrollment = config.sudoEnrollment
        var sudoEnrollment: [String: Any]? = nil
        if !enrollment.users.isEmpty || enrollment.group != nil || enrollment.idpSource != .disabled {
            var dict: [String: Any] = ["users": enrollment.users]
            if let group = enrollment.group {
                dict["group"] = group
            }
            if enrollment.idpSource != .disabled {
                dict["idpSource"] = enrollment.idpSource.rawValue
                dict["idpGroups"] = enrollment.idpGroups
                dict["idpStatePath"] = enrollment.idpStatePath
                dict["idpGroupsKey"] = enrollment.idpGroupsKey
                dict["requireRootOwnedState"] = enrollment.requireRootOwnedState
            }
            sudoEnrollment = dict
        }

        var settings: [String: Any] = [
            "daemonEnabled": config.daemonEnabled,
            "enforcementMode": config.enforcementMode.rawValue,
            "sudoCacheSeconds": config.sudoCacheSeconds,
            "promptTimeoutSeconds": config.promptTimeoutSeconds,
            "pamBypass": [
                "groups": config.pamBypass.groups,
                "users": config.pamBypass.users,
            ],
            // Admin-console gate (Commander reads it; the daemon ignores it).
            "commanderPublishEnabled": config.commanderPublishEnabled,
        ]
        if let sudoEnrollment {
            settings["sudoEnrollment"] = sudoEnrollment
        }
        // Touch ID toggle for identity-scoped app branches. Emitted only when
        // turned ON (the default is off), so an unchanged policy still
        // produces a byte-identical profile.
        if config.enableBiometrics {
            settings["enableBiometrics"] = true
        }
        // Org-wide default timed-grant duration (minutes). Emitted only when set
        // so profiles are byte-identical to before when the feature is unused.
        if config.defaultGrantDurationMinutes > 0 {
            settings["defaultGrantDurationMinutes"] = config.defaultGrantDurationMinutes
        }
        // Time-bound master switch. Always emitted: the daemon's default is ON,
        // so leaving the key out when it's switched off would silently turn it
        // back on.
        settings["timeBoundGrantsEnabled"] = config.timeBoundGrantsEnabled

        let payload = Self.managedPreferencesPayload(
            domain: BundleConfig.configDomain,
            settings: settings,
            identifier: "\(BundleConfig.configDomain).settings",
            uuid: contentUUID,
            displayName: "Serberus Daemon Config"
        )
        let root = Self.configurationRoot(
            identifier: "\(BundleConfig.configDomain).settings",
            uuid: payloadUUID,
            displayName: "Serberus — Daemon Config",
            description: "Serberus daemon enforcement mode, PAM break-glass bypass, prompt behavior, and the Commander direct-publish gate.",
            organization: organization,
            payload: payload
        )
        return Export(data: try Self.serialize(root), payloadUUID: payloadUUID,
                      suggestedFilename: "serberus-config.mobileconfig")
    }

    // MARK: Payload construction

    /// Wraps `settings` — the flat forced key/values for `domain` — in the
    /// `com.apple.ManagedClient.preferences` payload Jamf Pro renders as an
    /// "Application & Custom Settings" payload.
    ///
    /// The `Forced` → `mcx_preference_settings` nesting is the MCX shape macOS
    /// composes into `/Library/Managed Preferences/<domain>.plist`, so the
    /// on-device managed preferences (and therefore everything
    /// ``ManagedPreferencesReader`` reads) are identical to a bare-domain
    /// payload — only the Jamf console rendering differs.
    static func managedPreferencesPayload(
        domain: String,
        settings: [String: Any],
        identifier: String,
        uuid: UUID,
        displayName: String
    ) -> [String: Any] {
        [
            "PayloadType": "com.apple.ManagedClient.preferences",
            "PayloadVersion": 1,
            "PayloadIdentifier": identifier,
            "PayloadUUID": uuid.uuidString,
            "PayloadDisplayName": displayName,
            "PayloadEnabled": true,
            "PayloadContent": [
                domain: [
                    "Forced": [
                        ["mcx_preference_settings": settings],
                    ],
                ],
            ],
        ]
    }

    /// The top-level `Configuration` dictionary wrapping a single delivered
    /// `payload` — System scope, removal disallowed, the envelope every
    /// Serberus profile ships with.
    static func configurationRoot(
        identifier: String,
        uuid: UUID,
        displayName: String,
        description: String,
        organization: String,
        payload: [String: Any]
    ) -> [String: Any] {
        [
            "PayloadType": "Configuration",
            "PayloadVersion": 1,
            "PayloadIdentifier": identifier,
            "PayloadUUID": uuid.uuidString,
            "PayloadDisplayName": displayName,
            "PayloadDescription": description,
            "PayloadOrganization": organization,
            "PayloadScope": "System",
            "PayloadRemovalDisallowed": true,
            "PayloadContent": [payload],
        ]
    }

    /// XML-plist serialization, mapping any failure to
    /// ``ExportError/serializationFailed(reason:)``.
    static func serialize(_ plist: [String: Any]) throws -> Data {
        do {
            return try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        } catch {
            throw ExportError.serializationFailed(reason: String(describing: error))
        }
    }

    /// Validates `profiles` (non-empty, unique `profileKey`s, each passing the
    /// full ``PolicyValidator`` pipeline) and returns them sorted by key
    /// alongside the flat rules-domain settings dict they deliver — one
    /// JSON string per profile under its `profileKey`, the exact shape
    /// ``ManagedPreferencesReader/readRuleProfiles()`` reads. Shared by
    /// ``export(profiles:organization:)`` and
    /// ``rulesSettingsPlist(profiles:)`` so the `.mobileconfig` and the
    /// settings plist can never drift.
    static func validatedRulesSettings(
        _ profiles: [RuleProfile]
    ) throws -> (sorted: [RuleProfile], settings: [String: Any]) {
        guard !profiles.isEmpty else {
            throw ExportError.validationFailed(issues: ["No profiles to export"])
        }
        let sorted = profiles.sorted { $0.profileKey < $1.profileKey }

        var issues: [String] = []
        var seenKeys: Set<String> = []
        for profile in sorted {
            if !seenKeys.insert(profile.profileKey).inserted {
                issues.append("Duplicate profileKey '\(profile.profileKey)' in export set")
            }
            let report = PolicyValidator().validate(profile)
            issues.append(contentsOf: report.errors.map(\.description))
        }
        guard issues.isEmpty else {
            throw ExportError.validationFailed(issues: issues)
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys] // deterministic output

        var settings: [String: Any] = [:]
        for profile in sorted {
            do {
                settings[profile.profileKey] = String(decoding: try encoder.encode(profile), as: UTF8.self)
            } catch {
                throw ExportError.serializationFailed(reason: String(describing: error))
            }
        }
        return (sorted, settings)
    }

    /// Deterministic UUID derived from a seed string (UUIDv8-style fold of
    /// the seed's SHA-256). Stable across processes and platforms.
    static func stableUUID(seed: String) -> UUID {
        var digest = SHA256Hasher.hash(Data(seed.utf8))
        // Set RFC 4122 version (4) and variant bits so the result is a
        // structurally valid UUID.
        digest[6] = (digest[6] & 0x0F) | 0x40
        digest[8] = (digest[8] & 0x3F) | 0x80
        let bytes = (digest[0], digest[1], digest[2], digest[3],
                     digest[4], digest[5], digest[6], digest[7],
                     digest[8], digest[9], digest[10], digest[11],
                     digest[12], digest[13], digest[14], digest[15])
        return UUID(uuid: bytes)
    }
}
