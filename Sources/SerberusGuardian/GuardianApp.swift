import AppKit

/// Serberus Guardian — a tiny invisible `LSUIElement` agent (no Dock, no menu
/// bar, no window of its own) that watches the Sentinel and shows a persistent
/// "relaunch me" panel when it is quit. A plain AppKit app owning one watcher;
/// deliberately NOT a SwiftUI `App`/`MenuBarExtra` scene (an earlier SwiftUI
/// scene-based build spun at launch).
@main
@MainActor
final class GuardianApp: NSObject, NSApplicationDelegate {
    private let watcher = GuardianWatcher()

    static func main() {
        let app = NSApplication.shared
        let delegate = GuardianApp()
        app.delegate = delegate
        app.setActivationPolicy(.accessory)   // no Dock icon; belt-and-suspenders with LSUIElement
        app.run()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        watcher.start()
    }
}
