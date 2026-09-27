import Foundation
import IOKit
import PrivMgrCore

/// Gathers the host context stamped into every bundle.
///
/// Everything here is readable by a standard user. Nothing probes the
/// root-only grant database — that gap is recorded as an unavailable
/// artifact instead (see ``IntelCollector``).
public struct HostProbe: Sendable {
    /// `FileManager` is not `Sendable` and so cannot be stored here.
    private var fileManager: FileManager { .default }

    public init() {}

    public func current() -> HostContext {
        let state = NSDictionary(contentsOfFile: BundleConfig.statePlistPath)
        return HostContext(
            serialNumber: Self.serialNumber(),
            computerName: Host.current().localizedName ?? ProcessInfo.processInfo.hostName,
            osVersion: ProcessInfo.processInfo.operatingSystemVersionString,
            userName: NSUserName(),
            componentVersions: componentVersions(),
            // Key names match the daemon's own state.plist schema as read by
            // the `serberus status` CLI — kept identical so the two tools
            // never disagree about what this Mac is doing.
            daemonState: state?["state"] as? String,
            enforcementMode: state?["enforcementMode"] as? String,
            degradedReason: state?["degradedReason"] as? String,
            stateUpdatedAt: state?["updatedAt"] as? String,
            hasConfiguration: fileManager.fileExists(atPath: BundleConfig.lastKnownGoodConfigPath)
        )
    }

    /// Hardware serial via IOKit.
    ///
    /// Read from the IORegistry rather than shelling out to
    /// `system_profiler`, which takes seconds and would stall the UI. The
    /// serial is also what Jamf's computer lookup filters on.
    static func serialNumber() -> String? {
        let matching = IOServiceMatching("IOPlatformExpertDevice")
        let service = IOServiceGetMatchingService(kIOMainPortDefault, matching)
        guard service != 0 else { return nil }
        defer { IOObjectRelease(service) }

        guard let property = IORegistryEntryCreateCFProperty(
            service,
            kIOPlatformSerialNumberKey as CFString,
            kCFAllocatorDefault,
            0
        )?.takeRetainedValue() as? String else {
            return nil
        }
        let trimmed = property.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    private func componentVersions() -> [String: String] {
        guard let plist = NSDictionary(contentsOfFile: BundleConfig.versionPlistPath) else {
            return [:]
        }
        var versions: [String: String] = [:]
        for (key, value) in plist {
            if let key = key as? String, let value = value as? String {
                versions[key] = value
            }
        }
        return versions
    }

}
