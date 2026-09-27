import Foundation

/// Builds `multipart/form-data` bodies.
///
/// Pure and deterministic (the boundary is injected, never generated
/// internally) so the exact bytes on the wire are unit-testable.
public struct MultipartBody: Sendable, Equatable {
    public let boundary: String

    public init(boundary: String) {
        self.boundary = boundary
    }

    /// Value for the `Content-Type` header.
    public var contentType: String {
        "multipart/form-data; boundary=\(boundary)"
    }

    /// Encodes a single file part.
    ///
    /// - Parameters:
    ///   - fieldName: Form field name (Jamf's attachment endpoints expect
    ///     `file` on the Jamf Pro API and `name` on Classic `fileuploads`).
    ///   - fileName: Advertised filename; sanitized before it reaches the header.
    public func encode(fieldName: String, fileName: String, mimeType: String, payload: Data) -> Data {
        let disposition = "Content-Disposition: form-data; name=\"\(Self.sanitize(fieldName))\";"
            + " filename=\"\(Self.sanitize(fileName))\""

        var body = Data()
        body.append(Data("--\(boundary)\r\n".utf8))
        body.append(Data("\(disposition)\r\n".utf8))
        body.append(Data("Content-Type: \(mimeType)\r\n\r\n".utf8))
        body.append(payload)
        body.append(Data("\r\n--\(boundary)--\r\n".utf8))
        return body
    }

    /// Strips anything that could break out of a quoted MIME header value.
    ///
    /// The filename is derived from the Mac's computer name and serial —
    /// values Serberus does not control. A computer name containing a quote,
    /// CR, or LF would otherwise terminate the `Content-Disposition` header
    /// early and let the rest be read as attacker-chosen MIME headers. Since
    /// this is a security tool uploading to the MDM of record, the filename
    /// is reduced to an unambiguously safe character set rather than escaped.
    static func sanitize(_ value: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_. "))
        let cleaned = String(value.unicodeScalars.map { allowed.contains($0) ? Character($0) : "_" })
        return cleaned.isEmpty ? "unnamed" : cleaned
    }

    /// A fresh, collision-resistant boundary.
    public static func randomBoundary() -> String {
        "Boundary-\(UUID().uuidString)"
    }
}
