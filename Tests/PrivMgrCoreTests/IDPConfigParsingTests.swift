import Foundation
import Testing
@testable import PrivMgrCore

/// P1-config-model: parsing of the additive `sudoEnrollment` IdP-enrollment
/// sub-config (IdP-group enrollment). Every case asserts the fail-safe direction — malformed
/// input degrades to `.disabled` / empty and never widens enrollment.
@Suite("IDP enrollment config parsing")
struct IDPConfigParsingTests {
    private func reader(config: [String: any Sendable]) -> ManagedPreferencesReader {
        ManagedPreferencesReader(source: DictionaryPreferencesSource(domains: [
            BundleConfig.configDomain: config,
        ]))
    }

    @Test("absent sudoEnrollment yields default (disabled/empty) IdP config")
    func defaultsWhenAbsent() {
        let result = reader(config: [:]).readConfig()
        let enrollment = result.value.sudoEnrollment
        #expect(enrollment.idpSource == .disabled)
        #expect(enrollment.idpGroups.isEmpty)
        #expect(enrollment.idpStatePath == "Library/Preferences/com.jamf.connect.state.plist")
        #expect(enrollment.idpGroupsKey == "UserGroups")
        #expect(enrollment.requireRootOwnedState == true)   // strict by default
        #expect(result.findings.isEmpty)
    }

    @Test("full valid IdP config parses")
    func fullValid() {
        let result = reader(config: [
            "sudoEnrollment": [
                "group": "serberus-sudoers",
                "users": ["alice", "bob"],
                "idpGroups": ["Test-Name", "{6C8F...GUID}"],
                "idpSource": "jamf_connect_state",
                "idpStatePath": "Library/Preferences/com.example.state.plist",
                "idpGroupsKey": "Groups",
                "requireRootOwnedState": true,
            ] as [String: any Sendable],
        ]).readConfig()
        let enrollment = result.value.sudoEnrollment
        #expect(enrollment.group == "serberus-sudoers")
        #expect(enrollment.users == ["alice", "bob"])
        #expect(enrollment.idpGroups == ["Test-Name", "{6C8F...GUID}"])
        #expect(enrollment.idpSource == .jamfConnectState)
        #expect(enrollment.idpStatePath == "Library/Preferences/com.example.state.plist")
        #expect(enrollment.idpGroupsKey == "Groups")
        #expect(enrollment.requireRootOwnedState == true)
        #expect(result.findings.isEmpty)
    }

    @Test("missing IdP keys default to disabled/empty even when other enrollment keys present")
    func missingKeysDefault() {
        let result = reader(config: [
            "sudoEnrollment": [
                "users": ["carol"],
            ] as [String: any Sendable],
        ]).readConfig()
        let enrollment = result.value.sudoEnrollment
        #expect(enrollment.users == ["carol"])
        #expect(enrollment.idpSource == .disabled)
        #expect(enrollment.idpGroups.isEmpty)
        #expect(enrollment.idpStatePath == "Library/Preferences/com.jamf.connect.state.plist")
        #expect(enrollment.idpGroupsKey == "UserGroups")
        #expect(enrollment.requireRootOwnedState == true)   // strict by default
        #expect(result.findings.isEmpty)
    }

    @Test("unknown idpSource string falls back to disabled with a finding")
    func unknownIDPSourceFailsClosed() {
        let result = reader(config: [
            "sudoEnrollment": [
                "idpGroups": ["Test-Name"],
                "idpSource": "some_future_provider",
            ] as [String: any Sendable],
        ]).readConfig()
        #expect(result.value.sudoEnrollment.idpSource == .disabled)
        // idpGroups still parse — the source, not the group list, is invalid.
        #expect(result.value.sudoEnrollment.idpGroups == ["Test-Name"])
        #expect(result.findings.contains(.invalidValue(
            domain: BundleConfig.configDomain,
            key: "sudoEnrollment.idpSource",
            reason: "unknown source 'some_future_provider'; defaulting to disabled")))
    }

    @Test("non-string idpSource yields invalidValue finding and stays disabled")
    func nonStringIDPSource() {
        let result = reader(config: [
            "sudoEnrollment": [
                "idpSource": 42,
            ] as [String: any Sendable],
        ]).readConfig()
        #expect(result.value.sudoEnrollment.idpSource == .disabled)
        #expect(result.findings.contains(.invalidValue(
            domain: BundleConfig.configDomain,
            key: "sudoEnrollment.idpSource",
            reason: "expected a string source name")))
    }

    @Test("idpGroups filters per element: one mistyped entry never drops the whole list")
    func idpGroupsPerElementFilter() {
        let result = reader(config: [
            "sudoEnrollment": [
                "idpGroups": ["Test-Name", 7, "Test-Name-2"] as [any Sendable],
            ] as [String: any Sendable],
        ]).readConfig()
        #expect(result.value.sudoEnrollment.idpGroups == ["Test-Name", "Test-Name-2"])
        #expect(result.findings.count == 1)
    }

    @Test("non-array idpGroups yields empty list with a finding")
    func nonArrayIDPGroups() {
        let result = reader(config: [
            "sudoEnrollment": [
                "idpGroups": "Test-Name",
            ] as [String: any Sendable],
        ]).readConfig()
        #expect(result.value.sudoEnrollment.idpGroups.isEmpty)
        #expect(result.findings.contains(.invalidValue(
            domain: BundleConfig.configDomain,
            key: "sudoEnrollment.idpGroups",
            reason: "expected an array of strings")))
    }

    @Test("mistyped idpStatePath / idpGroupsKey keep defaults with findings")
    func mistypedStringOverrides() {
        let result = reader(config: [
            "sudoEnrollment": [
                "idpStatePath": 123,
                "idpGroupsKey": ["not", "a", "string"],
            ] as [String: any Sendable],
        ]).readConfig()
        let enrollment = result.value.sudoEnrollment
        #expect(enrollment.idpStatePath == "Library/Preferences/com.jamf.connect.state.plist")
        #expect(enrollment.idpGroupsKey == "UserGroups")
        #expect(result.findings.contains(.invalidValue(
            domain: BundleConfig.configDomain,
            key: "sudoEnrollment.idpStatePath",
            reason: "expected a string path")))
        #expect(result.findings.contains(.invalidValue(
            domain: BundleConfig.configDomain,
            key: "sudoEnrollment.idpGroupsKey",
            reason: "expected a string key name")))
    }

    @Test("requireRootOwnedState bool round-trips; mistyped keeps the strict default with a finding")
    func requireRootOwnedStateParsing() {
        let falseResult = reader(config: [
            "sudoEnrollment": ["requireRootOwnedState": false] as [String: any Sendable],
        ]).readConfig()
        #expect(falseResult.value.sudoEnrollment.requireRootOwnedState == false)
        #expect(falseResult.findings.isEmpty)

        let badResult = reader(config: [
            "sudoEnrollment": ["requireRootOwnedState": "no"] as [String: any Sendable],
        ]).readConfig()
        #expect(badResult.value.sudoEnrollment.requireRootOwnedState == true)
        #expect(badResult.findings.contains(.invalidValue(
            domain: BundleConfig.configDomain,
            key: "sudoEnrollment.requireRootOwnedState",
            reason: "expected a boolean")))
    }

    @Test("non-dictionary sudoEnrollment yields inert IdP config with a finding")
    func nonDictSudoEnrollment() {
        let result = reader(config: [
            "sudoEnrollment": "not-a-dict",
        ]).readConfig()
        let enrollment = result.value.sudoEnrollment
        #expect(enrollment.idpSource == .disabled)
        #expect(enrollment.idpGroups.isEmpty)
        #expect(result.findings.contains(.invalidValue(
            domain: BundleConfig.configDomain,
            key: "sudoEnrollment",
            reason: "expected a dictionary with 'group' and 'users'")))
    }

    @Test("IDPGroupSource fail-closed rawValue parse mirrors JITAdminProvider")
    func idpGroupSourceRawValues() {
        #expect(IDPGroupSource(rawValue: "disabled") == .disabled)
        #expect(IDPGroupSource(rawValue: "jamf_connect_state") == .jamfConnectState)
        #expect(IDPGroupSource(rawValue: "bogus") == nil)
        #expect(IDPGroupSource.disabled.rawValue == "disabled")
        #expect(IDPGroupSource.jamfConnectState.rawValue == "jamf_connect_state")
    }
}
