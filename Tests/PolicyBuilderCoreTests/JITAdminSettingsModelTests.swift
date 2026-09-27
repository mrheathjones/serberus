import Foundation
import Testing
import PrivMgrCore
@testable import PolicyBuilderCore

@MainActor
@Suite("JITAdminSettingsModel — Jamf Connect command")
struct JITAdminSettingsModelTests {
    private func freshDefaults() -> UserDefaults {
        let name = "JITAdminSettingsModelTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: name)!
        defaults.removePersistentDomain(forName: name)
        return defaults
    }

    @Test("a blank command path exports the default command")
    func blankPathUsesDefault() throws {
        let model = JITAdminSettingsModel(defaults: freshDefaults())
        model.provider = .jamfConnect
        model.jamfConnectPath = ""
        #expect(model.canExport)
        #expect(model.exportBlocker == nil)
        #expect(model.policy.effectiveJamfConnectCommand == JamfConnectCommand.jamfConnectDefault)
    }

    @Test("an absolute command path exports as given")
    func absolutePathExports() {
        let model = JITAdminSettingsModel(defaults: freshDefaults())
        model.provider = .jamfConnect
        model.jamfConnectPath = "/usr/local/bin/jamfconnect"
        model.jamfConnectArgsText = "acc-promo --elevate"
        #expect(model.canExport)
        #expect(model.exportBlocker == nil)
        #expect(model.policy.jamfConnectCommand.arguments == ["acc-promo", "--elevate"])
    }

    @Test("a relative command path blocks export with a clear reason")
    func relativePathBlocks() {
        let model = JITAdminSettingsModel(defaults: freshDefaults())
        model.provider = .jamfConnect
        model.jamfConnectPath = "jamfconnect"
        #expect(!model.canExport)
        #expect(model.exportBlocker?.contains("full path") == true)
    }
}
