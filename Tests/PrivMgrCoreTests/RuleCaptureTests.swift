import Foundation
import Testing
@testable import PrivMgrCore

/// `RuleCapture` is untrusted input to Commander (a user-supplied file or a
/// Jamf attachment any local user on the recording Mac could have written),
/// so its decoder refuses rather than trims.
@Suite("RuleCapture decoding guards")
struct RuleCaptureTests {
    private static let base = Date(timeIntervalSince1970: 1_784_000_000)

    private func capture(attempts: Int = 1, schema: String = RuleCapture.currentSchemaVersion,
                         start: Date = base, end: Date = base.addingTimeInterval(10)) -> RuleCapture {
        RuleCapture(
            schemaVersion: schema,
            host: CaptureHost(serialNumber: "SER1", computerName: "mac", osVersion: "26.4", userName: "u"),
            startedAt: start, endedAt: end,
            attempts: (0..<attempts).map { i in
                CapturedAttempt(id: "a\(i)", kind: .sudo, timestamp: Self.base, user: "u",
                                sudoCommand: "/usr/bin/true", argv: [], outcome: .granted, rawLines: ["x"])
            }
        )
    }

    @Test("a well-formed capture decodes and compares equal")
    func decodes() throws {
        let original = capture(attempts: 3)
        let decoded = try RuleCapture.decode(from: try original.encoded())
        #expect(decoded == original)
    }

    @Test("oversize data is refused before any decoding")
    func tooLarge() {
        let data = Data(count: RuleCapture.maxEncodedBytes + 1)
        #expect(throws: CaptureDecodeError.tooLarge(bytes: RuleCapture.maxEncodedBytes + 1)) {
            try RuleCapture.decode(from: data)
        }
    }

    @Test("malformed JSON is refused with a malformed error")
    func malformed() {
        #expect(throws: CaptureDecodeError.self) { try RuleCapture.decode(from: Data("{}".utf8)) }
        #expect(throws: CaptureDecodeError.self) { try RuleCapture.decode(from: Data("not json".utf8)) }
    }

    @Test("an unknown schema major is refused, a newer minor is accepted")
    func schema() throws {
        #expect(throws: CaptureDecodeError.unsupportedSchema("2.0")) {
            try RuleCapture.decode(from: try capture(schema: "2.0").encoded())
        }
        let minor = try RuleCapture.decode(from: try capture(schema: "1.7").encoded())
        #expect(minor.schemaVersion == "1.7")
    }

    @Test("more attempts than the cap is refused, not truncated")
    func tooManyAttempts() throws {
        let data = try capture(attempts: RuleCapture.maxAttempts + 1).encoded()
        #expect(throws: CaptureDecodeError.tooManyAttempts(RuleCapture.maxAttempts + 1)) {
            try RuleCapture.decode(from: data)
        }
    }

    @Test("an end before the start is malformed")
    func endBeforeStart() throws {
        let data = try capture(start: Self.base, end: Self.base.addingTimeInterval(-1)).encoded()
        #expect(throws: CaptureDecodeError.self) { try RuleCapture.decode(from: data) }
    }

    @Test("per-attempt invariants: empty or duplicate ids and kind/target mismatches are refused")
    func attemptInvariants() throws {
        func capture(with attempts: [CapturedAttempt]) -> RuleCapture {
            RuleCapture(host: CaptureHost(serialNumber: nil, computerName: "m", osVersion: "26", userName: "u"),
                        startedAt: Self.base, endedAt: Self.base, attempts: attempts)
        }
        let ok = CapturedAttempt(id: "a", kind: .sudo, timestamp: Self.base, user: "u",
                                 sudoCommand: "/bin/ls", outcome: .granted, rawLines: [])
        let emptyID = CapturedAttempt(id: "", kind: .sudo, timestamp: Self.base, user: "u",
                                      sudoCommand: "/bin/ls", outcome: .granted, rawLines: [])
        let noCommand = CapturedAttempt(id: "b", kind: .sudo, timestamp: Self.base, user: "u",
                                        sudoCommand: "", outcome: .granted, rawLines: [])
        let noRight = CapturedAttempt(id: "c", kind: .authuri, timestamp: Self.base, user: "u",
                                      authURI: nil, outcome: .granted, rawLines: [])
        #expect(throws: Never.self) { try RuleCapture.decode(from: try capture(with: [ok]).encoded()) }
        #expect(throws: CaptureDecodeError.self) { try RuleCapture.decode(from: try capture(with: [ok, ok]).encoded()) }
        #expect(throws: CaptureDecodeError.self) { try RuleCapture.decode(from: try capture(with: [emptyID]).encoded()) }
        #expect(throws: CaptureDecodeError.self) { try RuleCapture.decode(from: try capture(with: [noCommand]).encoded()) }
        #expect(throws: CaptureDecodeError.self) { try RuleCapture.decode(from: try capture(with: [noRight]).encoded()) }
    }

    @Test("attempt convenience: target and binaryPath follow the kind")
    func attemptConveniences() {
        let sudo = CapturedAttempt(id: "s", kind: .sudo, timestamp: Self.base, user: "u",
                                   sudoCommand: "/usr/local/bin/jamf", argv: ["policy"], outcome: .granted, rawLines: [])
        #expect(sudo.target == "/usr/local/bin/jamf policy")
        #expect(sudo.binaryPath == "/usr/local/bin/jamf")
        let auth = CapturedAttempt(id: "a", kind: .authuri, timestamp: Self.base, user: "u",
                                   authURI: "system.print.admin", clientPath: "/usr/bin/x", outcome: .denied, rawLines: [])
        #expect(auth.target == "system.print.admin")
        #expect(auth.binaryPath == "/usr/bin/x")
    }

    @Test("the suggested file name is safe and carries the serial and extension")
    func fileName() {
        let c = RuleCapture(
            host: CaptureHost(serialNumber: "C02 X/Y", computerName: "mac", osVersion: "26", userName: "u"),
            startedAt: Self.base, endedAt: Self.base, attempts: []
        )
        #expect(c.suggestedFileName.hasPrefix("Serberus-Capture-C02_X_Y-"))
        #expect(c.suggestedFileName.hasSuffix(".serberuscapture"))
        #expect(!c.suggestedFileName.contains("/"))
    }
}
