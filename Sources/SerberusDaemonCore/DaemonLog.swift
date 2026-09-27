import Foundation
import os
import PrivMgrCore

/// OSLog mirror for the three Serberus categories.
///
/// On-disk JSONL is written by PrivMgrCore's ``DecisionLogger`` /
/// ``IntegrityLogger``; this adds the live `os.Logger` streams the daemon
/// emits alongside them. Kept here (not in PrivMgrCore) so the core package
/// stays OS-framework light.
public enum DaemonLog {
    public static let decisions = Logger(subsystem: BundleConfig.logSubsystem, category: "decisions")
    public static let integrity = Logger(subsystem: BundleConfig.logSubsystem, category: "integrity")
    public static let telemetry = Logger(subsystem: BundleConfig.logSubsystem, category: "telemetry")
}
