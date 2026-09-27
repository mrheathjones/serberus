import Foundation
import IOKit

/// Hardware serial number for decision-log events. Read once via
/// IOKit; `"UNKNOWN"` when unavailable.
public enum DeviceInfo {
    public static func serialNumber() -> String {
        let platformExpert = IOServiceGetMatchingService(
            kIOMainPortDefault,
            IOServiceMatching("IOPlatformExpertDevice")
        )
        guard platformExpert != 0 else { return "UNKNOWN" }
        defer { IOObjectRelease(platformExpert) }

        guard let property = IORegistryEntryCreateCFProperty(
            platformExpert,
            kIOPlatformSerialNumberKey as CFString,
            kCFAllocatorDefault,
            0
        )?.takeRetainedValue() as? String, !property.isEmpty else {
            return "UNKNOWN"
        }
        return property
    }
}
