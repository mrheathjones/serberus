import Foundation
import Testing
import PrivMgrCore
@testable import PolicyBuilderCore

/// The bundle inspector behind drag & drop / "Add App…" in the Definition
/// composer: reads what PPPC Utility reads from an app's code signature.
@Suite("AppBundleInspector")
struct AppBundleInspectorTests {
    @Test("an Apple platform app yields its signing identifier and designated requirement, but no Team ID")
    func appleApp() {
        let info = AppBundleInspector.inspect(url: URL(fileURLWithPath: "/System/Applications/Calculator.app"))
        #expect(info.signingIdentifier == "com.apple.calculator")
        #expect(info.infoBundleID == "com.apple.calculator")
        #expect(info.pinIdentifier == "com.apple.calculator")
        #expect(info.teamID == nil)              // Apple's own apps carry no OU team
        #expect(!info.isPinnable)
        #expect(info.signingStatus == .valid)
        #expect(info.designatedRequirement?.contains("com.apple.calculator") == true)
        #expect(!info.name.isEmpty)
    }

    @Test("a path that is not a bundle yields nothing pinnable and reads as unsigned")
    func notABundle() {
        let info = AppBundleInspector.inspect(url: URL(fileURLWithPath: "/nonexistent/Nope.app"))
        #expect(info.signingIdentifier == nil)
        #expect(info.teamID == nil)
        #expect(info.signingStatus == .unsigned)
        #expect(info.name == "Nope")
        #expect(!info.isPinnable)
    }

    @Test("pinIdentifier prefers the signing identifier over the Info.plist bundle ID")
    func pinIdentifierPreference() {
        let info = AppSignatureInfo(path: "/x", name: "X", infoBundleID: "com.example.plist", signingIdentifier: "com.example.signed",
                                    teamID: "ABCDEFGHIJ", designatedRequirement: nil, version: nil, signingStatus: .valid)
        #expect(info.pinIdentifier == "com.example.signed")
        #expect(info.isPinnable)
    }
}
