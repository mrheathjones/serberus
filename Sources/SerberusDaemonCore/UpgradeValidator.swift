import Foundation

/// The seven upgrade-validation criteria. An upgrade may proceed
/// to daemon bootstrap only if ALL pass; otherwise the installer restores the
/// AuthorizationDB from backup, aborts bootstrap, and writes `state=degraded`.
///
/// The criteria are expressed as facts so the all-must-pass logic is pure and
/// unit-testable. The probe that gathers the facts from disk (file modes, code
/// signatures, plist keys, snapshot checksums) is platform-bound and used by
/// the PKG flow.
public struct UpgradeValidator: Sendable {
    public struct Facts: Sendable, Equatable {
        /// 1. New daemon binary present at install path with mode 755.
        public var daemonBinaryPresentAndExecutable: Bool
        /// 2. New daemon binary passes code-signature verification.
        public var daemonSignatureValid: Bool
        /// 3. PAM module present at /usr/local/lib/pam/pam_serberus.so with
        ///    mode 444 (/usr/lib/pam is on the sealed system snapshot).
        public var pamModulePresentAndCorrectMode: Bool
        /// 4. PAM module passes code-signature verification.
        public var pamSignatureValid: Bool
        /// 5. LaunchDaemon plist present and parses without error.
        public var launchDaemonPlistParses: Bool
        /// 6. Plist contains the required KeepAlive and ThrottleInterval keys.
        public var launchDaemonPlistHasRequiredKeys: Bool
        /// 7. An AuthorizationDB backup for every modified right exists with a
        ///    valid checksum.
        public var authDBBackupsValid: Bool

        public init(
            daemonBinaryPresentAndExecutable: Bool = false,
            daemonSignatureValid: Bool = false,
            pamModulePresentAndCorrectMode: Bool = false,
            pamSignatureValid: Bool = false,
            launchDaemonPlistParses: Bool = false,
            launchDaemonPlistHasRequiredKeys: Bool = false,
            authDBBackupsValid: Bool = false
        ) {
            self.daemonBinaryPresentAndExecutable = daemonBinaryPresentAndExecutable
            self.daemonSignatureValid = daemonSignatureValid
            self.pamModulePresentAndCorrectMode = pamModulePresentAndCorrectMode
            self.pamSignatureValid = pamSignatureValid
            self.launchDaemonPlistParses = launchDaemonPlistParses
            self.launchDaemonPlistHasRequiredKeys = launchDaemonPlistHasRequiredKeys
            self.authDBBackupsValid = authDBBackupsValid
        }

        /// All seven criteria satisfied.
        public static let allPassing = Facts(
            daemonBinaryPresentAndExecutable: true,
            daemonSignatureValid: true,
            pamModulePresentAndCorrectMode: true,
            pamSignatureValid: true,
            launchDaemonPlistParses: true,
            launchDaemonPlistHasRequiredKeys: true,
            authDBBackupsValid: true
        )
    }

    public init() {}

    /// Returns the list of failed criteria descriptions. Empty = the upgrade
    /// may proceed to bootstrap.
    public func failures(_ facts: Facts) -> [String] {
        var failures: [String] = []
        if !facts.daemonBinaryPresentAndExecutable {
            failures.append("daemon binary missing or not mode 755")
        }
        if !facts.daemonSignatureValid {
            failures.append("daemon binary failed code-signature verification")
        }
        if !facts.pamModulePresentAndCorrectMode {
            failures.append("PAM module missing or not mode 444")
        }
        if !facts.pamSignatureValid {
            failures.append("PAM module failed code-signature verification")
        }
        if !facts.launchDaemonPlistParses {
            failures.append("LaunchDaemon plist missing or does not parse")
        }
        if !facts.launchDaemonPlistHasRequiredKeys {
            failures.append("LaunchDaemon plist missing KeepAlive/ThrottleInterval")
        }
        if !facts.authDBBackupsValid {
            failures.append("AuthorizationDB backups missing or checksum invalid")
        }
        return failures
    }

    /// Whether the upgrade may proceed.
    public func mayProceed(_ facts: Facts) -> Bool {
        failures(facts).isEmpty
    }
}
