import Foundation
import SerberusDaemonCore

// serberusd — the Serberus root LaunchDaemon entry point.
//
// launchd starts this binary on demand for the Mach service
// `com.herojoneslabs.serberus.daemon`. All behavior lives in SerberusDaemonCore; this
// file only constructs the production daemon and hands control to the XPC /
// dispatch run loop, which `dispatchMain()` services for the process lifetime.

// One-shot installer/uninstaller sub-commands exit immediately; the default
// (no arguments — how launchd starts it) is the long-running service driven by
// the XPC / dispatch run loop.
//
// Any OTHER `--flag`, or a stray positional argument, is rejected with exit 2 +
// usage on stderr: starting the full service for an unknown (e.g. misspelled)
// one-shot command never returns, and hangs the installer script that ran it.
switch DaemonCommandLine.parse(Array(CommandLine.arguments.dropFirst())) {
case .service:
    break

case .restoreAuthDB:
    let success = await DaemonMode.restoreAuthorizationDB()
    exit(success ? 0 : 1)

case .removeSudoers:
    let success = await DaemonMode.removeSudoersDropIn()
    exit(success ? 0 : 1)

case .demoteJIT:
    // Teardown: demote every Serberus-created JIT admin (unrevoked JIT grant, or
    // an unverifiable JIT row) and mark the verified grants revoked. Root only;
    // never creates a key or the store. Exit 0 on success; 3 when there is no
    // grant store (nothing to demote — informational); 1 on any failure (not
    // root, unopenable/unverifiable store, a failed demotion). Run AFTER the
    // daemon is booted out.
    let outcome = await DaemonMode.demoteJITAdmins()
    exit(outcome.exitCode)

case let .usageError(message):
    FileHandle.standardError.write(Data("serberusd: \(message)\n\(DaemonCommandLine.usage)\n".utf8))
    exit(DaemonCommandLine.usageExitCode)
}

let controller = DaemonController.makeProduction()

// launchd stops the daemon with SIGTERM (shutdown, restart, bootout). Record
// the wall-clock high-water mark first, so a clock set back while the daemon is
// not running is caught at the next start, stop any `log` child (it runs in
// its own process group, which launchd's teardown of this job does not
// reach), then exit as SIGTERM would have.
signal(SIGTERM, SIG_IGN)
let terminationSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global(qos: .userInitiated))
terminationSource.setEventHandler {
    controller.recordClockHighWaterMarkAtShutdown()
    UnifiedLogStream.terminateAllChildren()
    exit(0)
}
terminationSource.resume()

Task {
    await controller.start()
}

dispatchMain()
