import Foundation
import Testing
@testable import SerberusIntelCore

@Suite("MultipartBody")
struct MultipartBodyTests {
    private func render(_ data: Data) -> String { String(decoding: data, as: UTF8.self) }

    @Test("encodes a well-formed single-file part")
    func encodesPart() {
        let body = MultipartBody(boundary: "BOUNDARY").encode(
            fieldName: "file",
            fileName: "capture.zip",
            mimeType: "application/zip",
            payload: Data("PK".utf8)
        )
        let text = render(body)
        #expect(text.hasPrefix("--BOUNDARY\r\n"))
        #expect(text.contains(#"Content-Disposition: form-data; name="file"; filename="capture.zip""#))
        #expect(text.contains("Content-Type: application/zip\r\n\r\n"))
        // The closing delimiter must carry the trailing `--`, or Jamf reads
        // the part as unterminated.
        #expect(text.hasSuffix("\r\n--BOUNDARY--\r\n"))
    }

    @Test("CRLF in a filename cannot inject MIME headers")
    func rejectsHeaderInjection() {
        // The filename derives from the Mac's computer name and serial —
        // values Serberus does not control. A CRLF would otherwise terminate
        // Content-Disposition early and let the remainder be parsed as
        // attacker-chosen headers.
        let body = MultipartBody(boundary: "B").encode(
            fieldName: "file",
            fileName: "eek\r\nX-Injected: yes\r\n\r\nmalicious",
            mimeType: "application/zip",
            payload: Data()
        )
        let text = render(body)
        #expect(!text.contains("X-Injected: yes"))
        #expect(!text.contains("eek\r\n"))
    }

    @Test("a quote in a filename cannot break out of the quoted value")
    func rejectsQuoteBreakout() {
        let body = MultipartBody(boundary: "B").encode(
            fieldName: "file",
            fileName: #"a" ; name="evil"#,
            mimeType: "application/zip",
            payload: Data()
        )
        // Exactly two quote pairs survive: name="file" and filename="…".
        #expect(render(body).filter { $0 == "\"" }.count == 4)
    }

    @Test("sanitize keeps ordinary capture filenames intact")
    func sanitizePreservesRealNames() {
        #expect(MultipartBody.sanitize("Serberus-Intel-C02XY-20260716-193000Z.zip")
            == "Serberus-Intel-C02XY-20260716-193000Z.zip")
    }

    @Test("sanitize never yields an empty filename")
    func sanitizeNeverEmpty() {
        #expect(MultipartBody.sanitize("") == "unnamed")
        #expect(MultipartBody.sanitize("///") == "___")
    }

    @Test("payload bytes survive verbatim")
    func payloadIsUntouched() {
        // Binary zip bytes, including a NUL and a byte that is not valid UTF-8.
        let payload = Data([0x50, 0x4B, 0x03, 0x04, 0x00, 0xFF])
        let body = MultipartBody(boundary: "B").encode(
            fieldName: "file", fileName: "a.zip", mimeType: "application/zip", payload: payload
        )
        #expect(body.range(of: payload) != nil)
    }

    @Test("content type advertises the boundary")
    func contentType() {
        #expect(MultipartBody(boundary: "XYZ").contentType == "multipart/form-data; boundary=XYZ")
    }

    @Test("random boundaries are unique per call")
    func randomBoundary() {
        #expect(MultipartBody.randomBoundary() != MultipartBody.randomBoundary())
    }
}
