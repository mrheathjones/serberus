import SwiftUI

struct AuthURIBrowserApp: App {
    @State private var catalog = Catalog()

    var body: some Scene {
        WindowGroup("Auth URI Browser") {
            ContentView(catalog: catalog)
                .frame(minWidth: 1040, minHeight: 620)
                .task {
                    await catalog.load()
                    // `--select <name>` opens straight onto a right (deep link / scripting).
                    let arguments = CommandLine.arguments
                    if let index = arguments.firstIndex(of: "--select"), arguments.indices.contains(index + 1) {
                        let name = arguments[index + 1]
                        if let entry = catalog.entry(named: name) {
                            catalog.filter = entry.kind == .rule ? .rules : .rights
                            catalog.selectedID = entry.id
                        }
                    }
                }
        }
        .defaultSize(width: 1280, height: 780)
        .commands {
            CommandGroup(after: .toolbar) {
                Button("Reload Authorization Database") {
                    Task { await catalog.load() }
                }
                .keyboardShortcut("r", modifiers: .command)
                Button("Discover Custom Rights…") {
                    Task { await catalog.discoverCustomRights() }
                }
                .keyboardShortcut("d", modifiers: [.command, .shift])
            }
        }
    }
}

/// Entry point. `AuthURIBrowser --dump [--rules]` prints every entry with its
/// badges as tab-separated text and exits, for scripting and for checking the
/// resolver from a terminal; anything else launches the GUI.
@main
enum Entry {
    static func main() {
        let arguments = CommandLine.arguments.dropFirst()
        guard arguments.contains("--dump") else {
            AuthURIBrowserApp.main()
            return
        }
        do {
            let entries = try Catalog.loadEntries(extra: [])
            let includeRules = arguments.contains("--rules")
            print(["name", "kind", "badges", "modified", "overridden", "description"].joined(separator: "\t"))
            for entry in entries where includeRules || entry.kind == .right {
                let badges = entry.badges.map { $0.label + ($0.password ? " (password)" : "") }.joined(separator: ", ")
                print([entry.name, entry.kind.rawValue, badges, entry.isModified ? "yes" : "no", entry.isDrifted ? "yes" : "no", entry.summary ?? ""].joined(separator: "\t"))
            }
        } catch {
            FileHandle.standardError.write(Data("\(error.localizedDescription)\n".utf8))
            exit(1)
        }
    }
}
