import PolicyBuilderCore
import PrivMgrCore
import SwiftUI

/// Serberus Commander app / Policy Builder (bundle `com.herojoneslabs.serberus.commander`).
///
/// Distributed separately from the endpoint PKG — not installed on managed
/// Macs. Native SwiftUI, no web views. Core logic lives in PrivMgrCore via
/// PolicyBuilderCore, so a future console app can reuse it.
@main
struct SerberusCommanderApp: App {
    /// Store-backed: loads the persisted policy library (or seeds it on first
    /// run) so authored policies survive restarts. Constructed in init() AFTER
    /// the folder migration, since `.persistent()` reads from disk.
    @State private var model: PolicyBuilderModel
    /// Whether the launch page has revealed the app. App-level so the window's
    /// later re-opens never re-show the splash — only the first launch does.
    @State private var launchComplete = false

    init() {
        // Move any pre-rename per-user data into ~/Library/Application Support/Serberus
        // BEFORE the disk-reading policy library is loaded below.
        AppSupportMigration.migrateUserSupportDirectory()
        _model = State(initialValue: PolicyBuilderModel.persistent())
    }

    var body: some Scene {
        Window("Serberus Commander", id: "serberus") {
            RootView(model: model, launchComplete: $launchComplete)
                .frame(minWidth: 1040, minHeight: 680)
                .toolbarBackground(.hidden, for: .windowToolbar)
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 1280, height: 820)
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(after: .newItem) {
                // Capture (Rule Recorder) hand-off from Sentinel: a
                // .serberuscapture file → Definitions → Import Capture.
                Button("Import Capture…") { model.requestCaptureImport() }
                    .keyboardShortcut("i", modifiers: [.command, .shift])
            }
        }

        // Fleet at a glance from the menu bar — Serberus device count, check-in
        // / daemon-state breakdown, Macs with uploads waiting — each row a deep
        // link into the Fleet Observer. Same design language as the Sentinel
        // agent's popover; amber sigil while uploads wait.
        //
        // ⚠️ Deliberately UNCONDITIONAL, and NOT `MenuBarExtra(isInserted:)`.
        // On macOS 26 the `isInserted:` initializer with `.window` style drives
        // an infinite scenesDidChange / main-menu update loop (the status
        // item's visibility KVO re-fires every run-loop pass → 100% main-thread
        // CPU, app launches "not responding"). Gating the scene with `if`
        // instead crashes the result-builder type-checker ("failed to produce
        // diagnostic"). An always-inserted extra is the only form that both
        // compiles and runs cleanly — so the menu-bar item has no hide toggle.
        MenuBarExtra {
            CommanderMenuBarView(model: model)
        } label: {
            CommanderStatusItemLabel(model: model)
        }
        .menuBarExtraStyle(.window)
    }
}
