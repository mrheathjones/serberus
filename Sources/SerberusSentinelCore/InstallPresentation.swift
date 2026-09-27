import Foundation
import PrivMgrCore

/// Display helpers for the "Install / Uninstall with Serberus" toasts. Pure, so
/// the Sentinel's wording is unit-tested without AppKit.
public enum InstallPresentation {
    /// The item's file name, cleaned exactly as the daemon cleans names
    /// (``DisplayText/sanitized(_:maxLength:)``: no control, bidi or other
    /// invisible format characters), so a crafted file name cannot make the
    /// toast read differently from what is really being installed.
    public static func displayName(forPath path: String) -> String {
        let name = DisplayText.sanitized((path as NSString).lastPathComponent)
        return name.isEmpty ? "the selected item" : name
    }

    /// The refusal detail to show for `result`, when its ``InstallResult/Reason``
    /// names one the user should act on; nil to keep the generic wording.
    public static func refusalDetail(for result: InstallResult, uninstall: Bool) -> String? {
        switch result.reason {
        case .requiresIT?:
            return uninstall ? "This needs to be removed by IT." : "This needs to be deployed by IT."
        case nil:
            return nil
        }
    }
}
