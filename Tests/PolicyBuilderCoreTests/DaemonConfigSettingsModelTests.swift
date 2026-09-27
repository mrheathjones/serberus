import Foundation
import Testing
import PrivMgrCore
@testable import PolicyBuilderCore

@MainActor
@Suite("DaemonConfigSettingsModel")
struct DaemonConfigSettingsModelTests {
    /// Isolated defaults per test so drafts never leak between tests or into
    /// the developer's real preferences.
    private func freshDefaults() -> UserDefaults {
        let name = "DaemonConfigSettingsModelTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defaults.removePersistentDomain(forName: name)
        return defaults
    }

    @Test("defaults match ManagedPreferencesReader's fail-safe defaults")
    func readerAlignedDefaults() {
        let model = DaemonConfigSettingsModel(defaults: freshDefaults())
        #expect(model.enforcementMode == .enforce)
        #expect(model.sudoCacheSeconds == 0)
        #expect(model.promptTimeoutSeconds == 60)
        #expect(model.daemonEnabled)
        #expect(model.pamBypassUsers.isEmpty)
        #expect(model.pamBypassGroups.isEmpty)
        // Sudo enrollment defaults to empty (fail-safe: the coarse drop-in
        // enrolls nobody until an admin authors it).
        #expect(model.sudoEnrollmentGroup == nil)
        #expect(model.sudoEnrollmentUsers.isEmpty)
        #expect(model.sudoEnrollmentValidationError == nil)
        #expect(model.config.sudoEnrollment.group == nil)
        #expect(model.config.sudoEnrollment.users.isEmpty)
        // Direct publish is an opt-in gate: off until an admin turns it on.
        #expect(!model.commanderPublishEnabled)
        #expect(!model.config.commanderPublishEnabled)
        // Time-bound grants are on by default, with no global default duration
        // until an admin sets one.
        #expect(model.timeBoundGrantsEnabled)
        #expect(model.config.timeBoundGrantsEnabled)
        #expect(model.defaultGrantDurationMinutes == 0)
        #expect(model.config.defaultGrantDurationMinutes == 0)
    }

    @Test("the time-bound switch and default duration flow into the config, persist, and export")
    func timeBoundGrantsAuthoring() throws {
        let defaults = freshDefaults()
        let model = DaemonConfigSettingsModel(defaults: defaults)
        model.timeBoundGrantsEnabled = true
        model.defaultGrantDurationMinutes = 15
        #expect(model.config.timeBoundGrantsEnabled)
        #expect(model.config.defaultGrantDurationMinutes == 15)
        #expect(model.config.defaultGrantDurationSeconds == 900)
        model.save()
        let reloaded = DaemonConfigSettingsModel(defaults: defaults)
        #expect(reloaded.timeBoundGrantsEnabled)
        #expect(reloaded.defaultGrantDurationMinutes == 15)

        // Both keys land in the exported profile payload.
        model.pamBypassUsersText = "breakglass"
        let export = try #require(model.export())
        let plist = try PropertyListSerialization.propertyList(from: export.data, format: nil) as? [String: Any]
        let payloads = plist?["PayloadContent"] as? [[String: Any]]
        let forced = ((payloads?.first?["PayloadContent"] as? [String: Any])?[BundleConfig.configDomain] as? [String: Any])?["Forced"] as? [[String: Any]]
        let settings = forced?.first?["mcx_preference_settings"] as? [String: Any]
        #expect(settings?["timeBoundGrantsEnabled"] as? Bool == true)
        #expect(settings?["defaultGrantDurationMinutes"] as? Int == 15)
    }

    @Test("switching time-bound grants off is exported explicitly, not left to the ON default")
    func timeBoundOffIsExported() throws {
        let model = DaemonConfigSettingsModel(defaults: freshDefaults())
        model.timeBoundGrantsEnabled = false
        model.pamBypassUsersText = "breakglass"
        let export = try #require(model.export())
        let plist = try PropertyListSerialization.propertyList(from: export.data, format: nil) as? [String: Any]
        let payloads = plist?["PayloadContent"] as? [[String: Any]]
        let forced = ((payloads?.first?["PayloadContent"] as? [String: Any])?[BundleConfig.configDomain] as? [String: Any])?["Forced"] as? [[String: Any]]
        let settings = forced?.first?["mcx_preference_settings"] as? [String: Any]
        #expect(settings?["timeBoundGrantsEnabled"] as? Bool == false)
    }

    @Test("an out-of-range default duration is clamped in the produced config")
    func defaultDurationClamped() {
        let model = DaemonConfigSettingsModel(defaults: freshDefaults())
        model.timeBoundGrantsEnabled = true
        model.defaultGrantDurationMinutes = 100_000
        #expect(model.config.defaultGrantDurationMinutes == RuleSchemaConstants.maxGrantDurationMinutes)
    }

    @Test("the Commander direct-publish gate flows into the config and persists across relaunch")
    func commanderPublishGatePersists() throws {
        let defaults = freshDefaults()
        let model = DaemonConfigSettingsModel(defaults: defaults)
        model.commanderPublishEnabled = true
        #expect(model.config.commanderPublishEnabled)
        model.save()
        #expect(DaemonConfigSettingsModel(defaults: defaults).commanderPublishEnabled)

        // And it lands in the exported profile payload.
        model.pamBypassUsersText = "breakglass"
        let export = try #require(model.export())
        let plist = try PropertyListSerialization.propertyList(from: export.data, format: nil) as? [String: Any]
        let payloads = plist?["PayloadContent"] as? [[String: Any]]
        let forced = ((payloads?.first?["PayloadContent"] as? [String: Any])?[BundleConfig.configDomain] as? [String: Any])?["Forced"] as? [[String: Any]]
        let settings = forced?.first?["mcx_preference_settings"] as? [String: Any]
        #expect(settings?["commanderPublishEnabled"] as? Bool == true)
    }

    @Test("users and groups parse comma, newline, and whitespace separators")
    func listParsing() {
        let model = DaemonConfigSettingsModel(defaults: freshDefaults())
        model.pamBypassUsersText = " alice ,bob\n  carol\n,, "
        #expect(model.pamBypassUsers == ["alice", "bob", "carol"])
        model.pamBypassGroupsText = "admin,\nserberus-breakglass"
        #expect(model.pamBypassGroups == ["admin", "serberus-breakglass"])
        model.pamBypassUsersText = "   \n , "
        #expect(model.pamBypassUsers.isEmpty)
    }

    /// Regression: `"\r\n"` is a single Swift `Character`, so the old
    /// `split(whereSeparator: { $0 == "\n" })` never matched it and a
    /// spreadsheet paste became ONE garbage entry ("alice\r\nbob") that
    /// lifted the brick-risk gate while matching no real account.
    @Test("CRLF pastes split into separate entries")
    func crlfParsing() {
        let model = DaemonConfigSettingsModel(defaults: freshDefaults())
        model.pamBypassUsersText = "alice\r\nbob"
        #expect(model.pamBypassUsers == ["alice", "bob"])
        #expect(model.invalidPamBypassUserEntries.isEmpty)
        #expect(model.bypassValidationError == nil)

        // Bare CR and other Unicode newlines split too.
        model.pamBypassUsersText = "alice\rbob\u{2028}carol"
        #expect(model.pamBypassUsers == ["alice", "bob", "carol"])

        model.pamBypassGroupsText = "admins\r\nserberus-breakglass\r\n"
        #expect(model.pamBypassGroups == ["admins", "serberus-breakglass"])
    }

    /// Regression: `"helpdesk breakglass"` parsed as ONE entry — a non-empty
    /// bypass array that lifted the enforce+no-bypass acknowledgement gate
    /// while exporting a username that can never match. It must be flagged,
    /// excluded from the parsed list, and block export until fixed.
    @Test("space-separated entries are invalid, never lift the guardrail, and block export")
    func spaceSeparatedEntriesBlockExport() {
        let model = DaemonConfigSettingsModel(defaults: freshDefaults())
        model.enforcementMode = .enforce
        model.pamBypassUsersText = "helpdesk breakglass"

        #expect(model.pamBypassUsers.isEmpty)
        #expect(model.invalidPamBypassUserEntries == ["helpdesk breakglass"])
        // The malformed entry is NOT a break-glass population.
        #expect(model.requiresBrickRiskAcknowledgement)
        #expect(model.bypassValidationError != nil)
        #expect(!model.canExport)
        #expect(model.export() == nil)
        #expect(model.lastExportError != nil)

        // No acknowledgement escape hatch for typos: still blocked.
        model.brickRiskAcknowledged = true
        #expect(!model.canExport)
        #expect(model.exportBlocker == model.bypassValidationError)
        #expect(model.export() == nil)

        // Fixing the separator clears the error and unblocks export.
        model.pamBypassUsersText = "helpdesk, breakglass"
        #expect(model.pamBypassUsers == ["helpdesk", "breakglass"])
        #expect(model.bypassValidationError == nil)
        #expect(!model.requiresBrickRiskAcknowledgement)
        #expect(model.canExport)
        #expect(model.export() != nil)
        #expect(model.lastExportError == nil)
    }

    @Test("invalid entries block export even alongside valid ones, in either field")
    func mixedValidAndInvalidEntries() {
        let model = DaemonConfigSettingsModel(defaults: freshDefaults())
        model.pamBypassUsersText = "alice, help desk"
        model.pamBypassGroupsText = "admin\ttier2, ops"

        #expect(model.pamBypassUsers == ["alice"])
        #expect(model.invalidPamBypassUserEntries == ["help desk"])
        #expect(model.pamBypassGroups == ["ops"])
        #expect(model.invalidPamBypassGroupEntries == ["admin\ttier2"])
        // Valid entries lift the brick gate, but validation still blocks.
        #expect(!model.requiresBrickRiskAcknowledgement)
        let error = model.bypassValidationError
        #expect(error != nil)
        #expect(error?.contains("help desk") == true)
        #expect(error?.contains("admin\ttier2") == true)
        #expect(!model.canExport)
        #expect(model.export() == nil)

        // Only well-formed names reach the assembled config.
        #expect(model.config.pamBypass.users == ["alice"])
        #expect(model.config.pamBypass.groups == ["ops"])
    }

    @Test("draft persists across model instances")
    func draftPersistence() {
        let defaults = freshDefaults()
        let first = DaemonConfigSettingsModel(defaults: defaults)
        first.enforcementMode = .audit
        first.pamBypassUsersText = "breakglass-admin"
        first.pamBypassGroupsText = "admin, ops"
        first.sudoEnrollmentUsersText = "jane, sam"
        first.sudoEnrollmentGroupText = "serberus-sudoers"
        first.sudoCacheSeconds = 300
        first.promptTimeoutSeconds = 120
        first.daemonEnabled = false
        first.save()

        let second = DaemonConfigSettingsModel(defaults: defaults)
        #expect(second.enforcementMode == .audit)
        #expect(second.pamBypassUsersText == "breakglass-admin")
        #expect(second.pamBypassGroups == ["admin", "ops"])
        #expect(second.sudoEnrollmentUsersText == "jane, sam")
        #expect(second.sudoEnrollmentUsers == ["jane", "sam"])
        #expect(second.sudoEnrollmentGroupText == "serberus-sudoers")
        #expect(second.sudoEnrollmentGroup == "serberus-sudoers")
        #expect(second.sudoCacheSeconds == 300)
        #expect(second.promptTimeoutSeconds == 120)
        #expect(!second.daemonEnabled)
    }

    @Test("enforce with empty bypass blocks export until acknowledged")
    func brickGuardrail() {
        let model = DaemonConfigSettingsModel(defaults: freshDefaults())
        // Default draft IS the bricking shape: enforce + nobody bypasses.
        #expect(model.requiresBrickRiskAcknowledgement)
        #expect(!model.canExport)
        #expect(model.exportBlocker != nil)
        #expect(model.export() == nil)
        #expect(model.lastExportError != nil)

        model.brickRiskAcknowledged = true
        #expect(model.canExport)
        #expect(model.exportBlocker == nil)
        #expect(model.export() != nil)
        #expect(model.lastExportError == nil)
    }

    @Test("any bypass population or non-enforce mode lifts the guardrail")
    func guardrailLifts() {
        let withUser = DaemonConfigSettingsModel(defaults: freshDefaults())
        withUser.pamBypassUsersText = "breakglass-admin"
        #expect(!withUser.requiresBrickRiskAcknowledgement)
        #expect(withUser.canExport)

        let withGroup = DaemonConfigSettingsModel(defaults: freshDefaults())
        withGroup.pamBypassGroupsText = "admin"
        #expect(!withGroup.requiresBrickRiskAcknowledgement)
        #expect(withGroup.canExport)

        let audit = DaemonConfigSettingsModel(defaults: freshDefaults())
        audit.enforcementMode = .audit
        #expect(!audit.requiresBrickRiskAcknowledgement)
        #expect(audit.canExport)
    }

    @Test("cache and timeout clamp to the documented ranges")
    func clamping() {
        let model = DaemonConfigSettingsModel(defaults: freshDefaults())
        model.sudoCacheSeconds = 999_999
        #expect(model.config.sudoCacheSeconds == 86_400)
        model.sudoCacheSeconds = -5
        #expect(model.config.sudoCacheSeconds == 0)
        model.promptTimeoutSeconds = 0
        #expect(model.config.promptTimeoutSeconds == 1)
        model.promptTimeoutSeconds = 999_999
        #expect(model.config.promptTimeoutSeconds == 60)
    }

    @Test("export emits the draft into the config domain")
    func exportsDraft() throws {
        let model = DaemonConfigSettingsModel(defaults: freshDefaults())
        model.enforcementMode = .enforce
        model.pamBypassUsersText = "breakglass-admin"
        model.pamBypassGroupsText = "admin"
        model.sudoCacheSeconds = 300

        let export = try #require(model.export(organization: "Acme"))
        #expect(export.suggestedFilename == "serberus-config.mobileconfig")

        // Delivered through the MCX wrapper Jamf renders; settings live under
        // Forced/mcx_preference_settings for the config domain.
        let envelope = try mcxPayloadEnvelope(inMobileconfig: export.data)
        #expect(envelope["PayloadType"] as? String == "com.apple.ManagedClient.preferences")
        let content = try mcxSettings(inMobileconfig: export.data, domain: BundleConfig.configDomain)
        #expect(content["enforcementMode"] as? String == "enforce")
        #expect(content["sudoCacheSeconds"] as? Int == 300)
        let bypass = content["pamBypass"] as? [String: Any]
        #expect(bypass?["users"] as? [String] == ["breakglass-admin"])
        #expect(bypass?["groups"] as? [String] == ["admin"])
        // The Jamf connection keys are a separately delivered profile.
        #expect(content["jamfProURL"] == nil)
        #expect(content["jamfAPIClientID"] == nil)
        #expect(content["jamfAPIClientSecret"] == nil)
    }

    // MARK: sudo enrollment (curated-sudo standard-user grant)

    @Test("sudo enrollment users parse commas, CRLF, and Unicode newlines")
    func sudoEnrollmentUsersParsing() {
        let model = DaemonConfigSettingsModel(defaults: freshDefaults())
        model.sudoEnrollmentUsersText = " jane ,sam\r\ncarol\u{2028}\n,, "
        #expect(model.sudoEnrollmentUsers == ["jane", "sam", "carol"])
        #expect(model.invalidSudoEnrollmentUserEntries.isEmpty)
        #expect(model.sudoEnrollmentValidationError == nil)

        // Empty-ish input -> empty enrollment, no group.
        model.sudoEnrollmentUsersText = "   \n , "
        model.sudoEnrollmentGroupText = ""
        #expect(model.sudoEnrollmentUsers.isEmpty)
        #expect(model.sudoEnrollmentGroup == nil)
    }

    /// A whitespace-malformed principal in either sudo-enrollment field matches
    /// no real account, so it must block export — independent of the PAM
    /// brick-risk gate (which is lifted here by a valid bypass user).
    @Test("internal-whitespace sudo-enrollment entries block export until fixed")
    func sudoEnrollmentWhitespaceBlocksExport() {
        let model = DaemonConfigSettingsModel(defaults: freshDefaults())
        // Lift the PAM brick-risk gate so only sudo-enrollment validation is
        // under test.
        model.pamBypassUsersText = "breakglass-admin"
        #expect(!model.requiresBrickRiskAcknowledgement)

        model.sudoEnrollmentUsersText = "jane doe"
        model.sudoEnrollmentGroupText = "sudo group"
        #expect(model.sudoEnrollmentUsers.isEmpty)
        #expect(model.sudoEnrollmentGroup == nil)
        #expect(model.invalidSudoEnrollmentUserEntries == ["jane doe"])
        #expect(model.invalidSudoEnrollmentGroupEntries == ["sudo group"])
        let error = model.sudoEnrollmentValidationError
        #expect(error != nil)
        #expect(error?.contains("jane doe") == true)
        #expect(error?.contains("sudo group") == true)
        #expect(!model.canExport)
        #expect(model.exportBlocker == error)
        #expect(model.export() == nil)
        #expect(model.lastExportError != nil)

        // Fixing the separators clears the error and unblocks export.
        model.sudoEnrollmentUsersText = "jane, doe"
        model.sudoEnrollmentGroupText = "serberus-sudoers"
        #expect(model.sudoEnrollmentUsers == ["jane", "doe"])
        #expect(model.sudoEnrollmentGroup == "serberus-sudoers")
        #expect(model.sudoEnrollmentValidationError == nil)
        #expect(model.canExport)
        #expect(model.export() != nil)
        #expect(model.lastExportError == nil)
    }

    /// F5: the sudo-enrollment fields feed a generated `sudoers` User_Spec, so a
    /// principal must be a strict, safe local name. `ALL` and any sudoers-sigil
    /// entry (`%group`, `#0`, `+netgroup`) must be flagged, excluded from the
    /// parsed list, and block export — even though they contain no whitespace and
    /// so pass the looser PAM-bypass parser.
    @Test("sudo-enrollment reserved 'ALL' and sigil entries are rejected and block export")
    func sudoEnrollmentReservedAndSigilBlockExport() {
        let model = DaemonConfigSettingsModel(defaults: freshDefaults())
        // Lift the PAM brick-risk gate so only sudo-enrollment validation is under test.
        model.pamBypassUsersText = "breakglass-admin"
        #expect(!model.requiresBrickRiskAcknowledgement)

        model.sudoEnrollmentUsersText = "alice, ALL, #0, +netgroup"
        model.sudoEnrollmentGroupText = "%staff"
        // Only the safe name survives parsing.
        #expect(model.sudoEnrollmentUsers == ["alice"])
        #expect(model.invalidSudoEnrollmentUserEntries == ["ALL", "#0", "+netgroup"])
        // A `%`-prefixed group is invalid (the generator owns the `%`).
        #expect(model.sudoEnrollmentGroup == nil)
        #expect(model.invalidSudoEnrollmentGroupEntries == ["%staff"])

        let error = model.sudoEnrollmentValidationError
        #expect(error != nil)
        #expect(error?.contains("ALL") == true)
        #expect(error?.contains("%staff") == true)
        #expect(!model.canExport)
        #expect(model.exportBlocker == error)
        #expect(model.export() == nil)
        #expect(model.lastExportError != nil)

        // Fixing to safe names clears the error and unblocks export.
        model.sudoEnrollmentUsersText = "alice, bob_1"
        model.sudoEnrollmentGroupText = "staff"
        #expect(model.sudoEnrollmentUsers == ["alice", "bob_1"])
        #expect(model.sudoEnrollmentGroup == "staff")
        #expect(model.sudoEnrollmentValidationError == nil)
        #expect(model.canExport)
        #expect(model.export() != nil)
        #expect(model.lastExportError == nil)
    }

    /// F5 is scoped to sudo-enrollment only: the PAM-bypass parser semantics must
    /// NOT change. `ALL` (and other whitespace-free sigils) remain valid bypass
    /// entries — the daemon's fail-closed backstops handle bypass differently, and
    /// this test pins that the fix did not bleed into pamBypass.
    @Test("PAM-bypass parsing is unchanged: 'ALL' remains a valid bypass entry")
    func pamBypassUnaffectedBySudoEnrollmentTightening() {
        let model = DaemonConfigSettingsModel(defaults: freshDefaults())
        model.pamBypassUsersText = "ALL, admin.user"
        model.pamBypassGroupsText = "wheel"
        #expect(model.pamBypassUsers == ["ALL", "admin.user"])
        #expect(model.invalidPamBypassUserEntries.isEmpty)
        #expect(model.pamBypassGroups == ["wheel"])
        #expect(model.bypassValidationError == nil)
    }

    /// Empty enrollment is a valid, exportable state ("no grant / drop-in
    /// removed"). It must NOT be coupled to the PAM brick-risk gate: with the
    /// brick risk acknowledged (the only remaining blocker), empty enrollment
    /// exports cleanly and the config carries nil group / empty users.
    @Test("empty sudo enrollment is a valid exportable state, not brick-gated")
    func emptySudoEnrollmentIsExportable() {
        let model = DaemonConfigSettingsModel(defaults: freshDefaults())
        // Default draft is the PAM bricking shape; acknowledge it so the ONLY
        // thing that could still block is sudo-enrollment validation.
        model.brickRiskAcknowledged = true
        #expect(model.sudoEnrollmentUsers.isEmpty)
        #expect(model.sudoEnrollmentGroup == nil)
        #expect(model.sudoEnrollmentValidationError == nil)
        #expect(model.canExport)
        #expect(model.export() != nil)
        #expect(model.config.sudoEnrollment.group == nil)
        #expect(model.config.sudoEnrollment.users.isEmpty)
    }
}
