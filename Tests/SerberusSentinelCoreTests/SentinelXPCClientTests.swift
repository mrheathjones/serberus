import Foundation
import Testing
import PrivMgrCore
@testable import SerberusSentinelCore

/// The Sentinel client carries `PromptContext`/`PromptResponse` across the libxpc
/// boundary via `SerberusXPCCoding`. A live connection needs a signed daemon, so
/// these unit tests pin the wire round-trip the client depends on.
@Suite("SentinelXPCClient payloads")
struct SentinelXPCClientTests {
    @Test("PromptContext round-trips through the XPC coder")
    func promptContextRoundTrips() throws {
        let context = PromptContext(
            user: "alice",
            processName: "brew",
            canonicalPath: "/opt/homebrew/bin/brew",
            teamID: "ABCDE12345",
            signingStatus: .valid,
            humanReadableRequest: "sudo brew install wget",
            requireJustification: true,
            justificationMinLength: 10,
            timeoutSeconds: 60
        )
        let data = try SerberusXPCCoding.encode(context)
        let decoded = try SerberusXPCCoding.decode(PromptContext.self, from: data)
        #expect(decoded == context)
    }

    @Test("PromptResponse round-trips through the XPC coder")
    func promptResponseRoundTrips() throws {
        let response = PromptResponse(
            requestID: UUID(),
            verdict: .approved,
            justificationText: "deploying release"
        )
        let data = try SerberusXPCCoding.encode(response)
        let decoded = try SerberusXPCCoding.decode(PromptResponse.self, from: data)
        #expect(decoded == response)
        #expect(decoded.verdict == .approved)
    }
}
