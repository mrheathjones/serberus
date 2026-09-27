import Foundation

/// Checks whether the daemon has the privacy approvals it needs (startup
/// step 1). Endpoint Security requires Full Disk Access via a PPPC profile; if
/// it is absent the daemon runs in `pending_pppc` — every other enforcement
/// layer is active, only ESF is held back.
public protocol PPPCStatusChecking: Sendable {
    /// True when the daemon can read FDA-protected locations, which is the
    /// prerequisite for the ESF client.
    func fullDiskAccessReady() -> Bool
}

/// Production check: attempts to read a TCC-protected location. Success means
/// Full Disk Access has been granted to this binary.
public struct PPPCPreflight: PPPCStatusChecking {
    /// A location only readable with Full Disk Access.
    private let probePath: String

    public init(probePath: String = "/Library/Application Support/com.apple.TCC/TCC.db") {
        self.probePath = probePath
    }

    public func fullDiskAccessReady() -> Bool {
        // Opening the protected file for reading succeeds only with FDA.
        let descriptor = open(probePath, O_RDONLY)
        if descriptor >= 0 {
            close(descriptor)
            return true
        }
        return false
    }
}

/// Test/dry-run check with a fixed answer.
public struct StaticPPPCStatus: PPPCStatusChecking {
    public let ready: Bool
    public init(ready: Bool) { self.ready = ready }
    public func fullDiskAccessReady() -> Bool { ready }
}
