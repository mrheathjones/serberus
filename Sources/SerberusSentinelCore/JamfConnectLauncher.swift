import Foundation
import PrivMgrCore
import Security

/// Whether the Jamf Connect elevation command can be offered, and if not, why.
public enum JamfConnectAvailability: Sendable, Equatable {
    /// The binary exists, is a regular file, and is signed by Jamf.
    case ready
    /// Nothing runnable at the configured path.
    case notInstalled
    /// The binary is there but does not pass the Jamf signature check.
    case failedSignatureCheck

    /// The reason shown on the disabled menu item; nil when ready.
    public var unavailableReason: String? {
        switch self {
        case .ready: return nil
        case .notInstalled: return "Jamf Connect isn't installed."
        case .failedSignatureCheck: return "Jamf Connect failed its signature check."
        }
    }
}

/// Checks the Jamf Connect command before the Sentinel runs it: the path is
/// absolute, names an existing regular file (after resolving symlinks, since
/// `/usr/local/bin/jamfconnect` may link into the app bundle), and that file
/// passes a strict static code-signature check against
/// `anchor apple generic and certificate leaf[subject.OU] = "483DWKW443"` —
/// the equivalent of `codesign --verify --strict -R=<requirement>`. The team
/// is fixed (``JamfConnectCommand/expectedTeamID``); no MDM key changes it.
public struct JamfConnectVerifier: Sendable {
    /// Code-signing check of the file at a path. Injectable for tests.
    private let signatureCheck: @Sendable (String) -> Bool

    public init(signatureCheck: @escaping @Sendable (String) -> Bool = JamfConnectVerifier.isSignedByJamf) {
        self.signatureCheck = signatureCheck
    }

    public func availability(of command: JamfConnectCommand) -> JamfConnectAvailability {
        check(command).availability
    }

    /// The resolved path that passed the check, or nil. This is the path to
    /// run: running `command.path` instead would follow the symlink again, and
    /// the link could have been re-pointed since the check.
    public func verifiedExecutable(of command: JamfConnectCommand) -> String? {
        let result = check(command)
        return result.availability == .ready ? result.resolved : nil
    }

    private func check(_ command: JamfConnectCommand) -> (availability: JamfConnectAvailability, resolved: String?) {
        guard command.hasAbsolutePath else { return (.notInstalled, nil) }
        let resolved = (command.path as NSString).resolvingSymlinksInPath
        var info = stat()
        guard stat(resolved, &info) == 0 else { return (.notInstalled, nil) }
        guard (info.st_mode & S_IFMT) == S_IFREG else { return (.notInstalled, nil) }
        return signatureCheck(resolved) ? (.ready, resolved) : (.failedSignatureCheck, nil)
    }

    /// The code requirement the binary must satisfy.
    public static let requirement =
        "anchor apple generic and certificate leaf[subject.OU] = \"\(JamfConnectCommand.expectedTeamID)\""

    /// Strict static validation of `path` against ``requirement``.
    ///
    /// No `kSecCSEnforceRevocationChecks`: it makes the check ask Apple's OCSP
    /// service, so offline (or behind a filtering proxy) a genuine Jamf binary
    /// would fail or stall the menu. The check is there to catch a binary that
    /// is not Jamf's; a revoked Jamf certificate is left to the system's own
    /// revocation handling. The command runs as the user, from a path only root
    /// or an admin can write.
    public static let isSignedByJamf: @Sendable (String) -> Bool = { path in
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess,
              let code else { return false }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(Self.requirement as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return false }
        let flags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures)
        return SecStaticCodeCheckValidity(code, flags, requirement) == errSecSuccess
    }
}

/// Launches the Jamf Connect elevation command **in the logged-in user's
/// session** — which is where it belongs, because Jamf Connect shows its own
/// reason prompt in the user's GUI. The Sentinel is a user-context LaunchAgent, so
/// running it here (rather than routing through the root daemon) gives Jamf
/// Connect the session it needs. Serberus is a pure launcher: it fires the
/// command and reports whether it started; JC owns everything after that.
public struct JamfConnectLauncher: Sendable {
    private let verifier: JamfConnectVerifier

    public init(verifier: JamfConnectVerifier = JamfConnectVerifier()) {
        self.verifier = verifier
    }

    /// Runs the command, returning whether it launched. Only an absolute path
    /// that passes ``JamfConnectVerifier`` is run — checked again here, right
    /// before the launch, not only when the menu was drawn. Fire-and-forget:
    /// success means "launched", not "elevated" — JC drives the rest and shows
    /// its own success/failure UI.
    public func run(_ command: JamfConnectCommand) async -> Bool {
        // Runs the file that was checked, not the configured (possibly
        // symlinked) path.
        guard let executable = verifier.verifiedExecutable(of: command) else { return false }
        return await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: executable)
                process.arguments = command.arguments
                do {
                    try process.run()
                    continuation.resume(returning: true)
                } catch {
                    continuation.resume(returning: false)
                }
            }
        }
    }
}
