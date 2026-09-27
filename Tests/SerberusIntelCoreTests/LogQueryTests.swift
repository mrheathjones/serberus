import Foundation
import PrivMgrCore
import Testing
@testable import SerberusIntelCore

@Suite("LogQuery argv + predicate")
struct LogQueryTests {
    @Test("predicate matches the daemon subsystem and every child subsystem")
    func predicateShape() {
        // The Sentinel logs under `…serberus.sentinel`, so an equality-only
        // predicate (the one pam_serberus.c's comment suggests) would drop it.
        // This is the regression that would silently produce a log export with
        // a whole component missing.
        #expect(LogQuery.predicate.contains(#"subsystem == "com.herojoneslabs.serberus""#))
        #expect(LogQuery.predicate.contains(#"subsystem BEGINSWITH "com.herojoneslabs.serberus.""#))
    }

    @Test("root subsystem is sourced from BundleConfig, not a copy")
    func subsystemNotDuplicated() {
        #expect(LogQuery.rootSubsystem == BundleConfig.logSubsystem)
    }

    @Test("BEGINSWITH is dot-anchored so a sibling prefix cannot match")
    func predicateIsDotAnchored() {
        // Guards against `com.herojoneslabs.serberusEvil` satisfying the
        // prefix clause.
        #expect(!LogQuery.predicate.contains(#"BEGINSWITH "com.herojoneslabs.serberus""#))
    }

    @Test("show argv carries the window and ndjson style")
    func showArguments() {
        let arguments = LogQuery().showArguments(window: .sixHours)
        #expect(arguments.first == "show")
        #expect(arguments.contains("--last"))
        #expect(arguments.contains("6h"))
        #expect(arguments.contains("ndjson"))
        #expect(arguments.contains(LogQuery.predicate))
    }

    @Test("info/debug flags are opt-in")
    func levelFlags() {
        let quiet = LogQuery().showArguments(window: .oneHour)
        #expect(!quiet.contains("--info"))
        #expect(!quiet.contains("--debug"))

        let loud = LogQuery(includeInfoAndDebug: true).showArguments(window: .oneHour)
        #expect(loud.contains("--info"))
        #expect(loud.contains("--debug"))
    }

    @Test("stream argv has no --last")
    func streamArguments() {
        let arguments = LogQuery().streamArguments()
        #expect(arguments.first == "stream")
        #expect(!arguments.contains("--last"))
        #expect(arguments.contains("ndjson"))
    }

    @Test("log tool is invoked by absolute path")
    func absolutePath() {
        // `log` is a common shell alias; resolving via PATH would let the
        // user's environment choose the binary a security tool runs.
        #expect(LogQuery.logToolPath == "/usr/bin/log")
    }

    @Test("every window is a literal log(1) accepts")
    func windowsAreLogArguments() {
        for window in LogWindow.allCases {
            #expect(window.rawValue.range(of: #"^\d+[mhd]$"#, options: .regularExpression) != nil)
        }
    }
}
