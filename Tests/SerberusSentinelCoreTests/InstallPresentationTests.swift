import Foundation
import Testing
import PrivMgrCore
@testable import SerberusSentinelCore

@Suite("Install / uninstall presentation")
struct InstallPresentationTests {
    @Test("the toast name drops control, bidi and other invisible format characters")
    func sanitizedName() {
        // U+202E RIGHT-TO-LEFT OVERRIDE would make "evil\u{202E}ppa.pkg" read as "evilgkp.app".
        #expect(InstallPresentation.displayName(forPath: "/Users/a/Downloads/evil\u{202E}gkp.app") == "evilgkp.app")
        #expect(InstallPresentation.displayName(forPath: "/tmp/Tool\u{200B}\u{0007}.pkg") == "Tool.pkg")
        #expect(InstallPresentation.displayName(forPath: "/tmp/Plain App.app") == "Plain App.app")
        #expect(InstallPresentation.displayName(forPath: "/tmp/\u{2066}\u{2069}") == "the selected item")
    }

    @Test("the Sentinel and the daemon clean names the same way")
    func sharedSanitizer() {
        let raw = "A\u{202A}B\u{0085}C\u{FEFF}D"
        #expect(DisplayText.sanitized(raw) == "ABCD")
    }

    @Test("requiresIT names IT; other refusals keep the generic wording")
    func requiresIT() {
        let refused = InstallResult(status: .refusedByPolicy, message: "x", reason: .requiresIT)
        #expect(InstallPresentation.refusalDetail(for: refused, uninstall: false) == "This needs to be deployed by IT.")
        #expect(InstallPresentation.refusalDetail(for: refused, uninstall: true) == "This needs to be removed by IT.")
        let plain = InstallResult(status: .refusedByPolicy, message: "x")
        #expect(InstallPresentation.refusalDetail(for: plain, uninstall: false) == nil)
    }

    @Test("install and uninstall prompts label the request row 'Item'")
    func itemRowLabel() {
        func context(_ processName: String, _ request: String) -> PromptContext {
            PromptContext(user: "alice", processName: processName, canonicalPath: "/tmp/x.pkg", teamID: nil,
                          signingStatus: .unsigned, humanReadableRequest: request, requireJustification: false,
                          justificationMinLength: 0, timeoutSeconds: 30)
        }
        #expect(context(PromptContext.installProcessName, "Install “X”").requestRowLabel == "Item")
        #expect(context(PromptContext.uninstallProcessName, "Move “X” to the Trash").requestRowLabel == "Item")
        #expect(context("brew", "sudo /opt/homebrew/bin/brew").requestRowLabel == "Command")
        #expect(context("x", PromptContext.authURIRequestPrefix + "system.preferences").requestRowLabel == "Right")
    }

    @Test("the escape pass leaves install and uninstall prompt text as the daemon cleaned it")
    func escapeLeavesInstallTextAlone() {
        // Built as the daemon builds them: every name through DisplayText.sanitized,
        // which strips every control and format character.
        let headline = DisplayText.sanitized("Evil\u{202E}ppa Café 日本 🍺\u{200B}\u{0007}")
        let version = DisplayText.sanitized("1.2\u{FEFF}", maxLength: 32)
            + " (" + DisplayText.sanitized("34\u{2066}", maxLength: 32) + ")"
        let source = DisplayText.sanitized("/Users/a/Downloads/Tool\u{2028}\u{0085}.pkg", maxLength: 300)
        let capped = DisplayText.sanitized(String(repeating: "Long Name ", count: 20))
        let cases = [
            (PromptContext.installProcessName, "Install “\(headline)” \(version) from \(source)"),
            (PromptContext.installProcessName, "Install “\(capped)” from \(source)"),
            (PromptContext.uninstallProcessName, "Move “\(headline)” to the Trash"),
        ]
        for (processName, request) in cases {
            let context = PromptContext(
                user: "alice", processName: processName, canonicalPath: "/tmp/x.pkg", teamID: nil,
                signingStatus: .unsigned, humanReadableRequest: request, requireJustification: false,
                justificationMinLength: 0, timeoutSeconds: 30
            )
            #expect(context.requestRowValue == request)
            let response = PromptResponse(requestID: context.requestID, verdict: .approved, justificationText: nil)
            #expect(ElevationHistoryEntry(context: context, response: response, date: Date()).displayRequest == request)
        }

        // What sanitized keeps, such as an NBSP in a name, shows as an escape.
        let spaced = PromptContext(
            user: "alice", processName: PromptContext.installProcessName, canonicalPath: "/tmp/x.pkg", teamID: nil,
            signingStatus: .unsigned, humanReadableRequest: "Install “\(DisplayText.sanitized("Foo\u{00A0}Bar"))”",
            requireJustification: false, justificationMinLength: 0, timeoutSeconds: 30
        )
        #expect(spaced.requestRowValue == #"Install “Foo\u{00A0}Bar”"#)
    }
}
