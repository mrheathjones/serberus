import Foundation
import Testing
import PrivMgrCore
@testable import SerberusCLICore

@Suite("CLICommand parsing")
struct CLICommandParsingTests {
    @Test("commands parse")
    func commands() {
        #expect(CLICommand.parse(["list"]) == .list(json: false))
        #expect(CLICommand.parse(["list", "--json"]) == .list(json: true))
        #expect(CLICommand.parse(["status"]) == .status)
        #expect(CLICommand.parse(["grants"]) == .grants)
        #expect(CLICommand.parse(["version"]) == .version)
        #expect(CLICommand.parse([]) == .help)
        #expect(CLICommand.parse(["bogus"]) == .unknown("bogus"))
    }

    @Test("simulate flags parse, including repeated --arg")
    func simulateFlags() {
        let command = CLICommand.parse([
            "simulate", "--user", "alice", "--command", "/opt/homebrew/bin/brew",
            "--arg", "install", "--arg", "wget", "--team-id", "ABCDE12345", "--json",
        ])
        guard case let .simulate(args) = command else {
            Issue.record("expected simulate"); return
        }
        #expect(args.user == "alice")
        #expect(args.command == "/opt/homebrew/bin/brew")
        #expect(args.argv == ["install", "wget"])
        #expect(args.teamID == "ABCDE12345")
        #expect(args.json)
    }
}

@Suite("CLIRunner")
struct CLIRunnerTests {
    private let now = Date(timeIntervalSince1970: 1_781_222_400)

    private func runner(
        rules: [String: any Sendable] = [:],
        config: [String: any Sendable] = [:],
        stateDir: URL? = nil,
        isRoot: Bool = false
    ) -> CLIRunner {
        let dir = stateDir ?? FileManager.default.temporaryDirectory
        return CLIRunner(
            preferences: DictionaryPreferencesSource(domains: [
                BundleConfig.rulesDomain: rules,
                BundleConfig.configDomain: config,
            ]),
            statePlistURL: dir.appendingPathComponent("state.plist"),
            versionPlistURL: dir.appendingPathComponent("version.plist"),
            username: "alice",
            isRoot: isRoot,
            now: { self.now }
        )
    }

    private func profileJSON(key: String = "rules_sudo_brew") -> String {
        let profile = RuleProfile(
            policyVersion: "1.0.0", profileKey: key, profilePriority: 50,
            rules: [Rule(id: "allow-brew", type: .sudo, action: .allow, description: "d", priority: 10,
                         match: MatchCriteria(commandPattern: "/opt/homebrew/bin/brew", matchType: .exact))]
        )
        return String(decoding: try! JSONEncoder().encode(profile), as: UTF8.self)
    }

    @Test("list shows capabilities and the no-policy case")
    func list() {
        let empty = runner().run(.list(json: false))
        #expect(empty.text.contains("No rules_* profiles"))

        let withRules = runner(rules: ["rules_sudo_brew": profileJSON()]).run(.list(json: false))
        #expect(withRules.text.contains("/opt/homebrew/bin/brew"))
        #expect(withRules.text.contains("alice"))
    }

    @Test("list --json emits structured capabilities")
    func listJSON() throws {
        let output = runner(rules: ["rules_sudo_brew": profileJSON()]).run(.list(json: true))
        let json = try JSONSerialization.jsonObject(with: Data(output.text.utf8)) as? [String: Any]
        #expect(json?["user"] as? String == "alice")
        let capabilities = json?["capabilities"] as? [[String: Any]]
        #expect(capabilities?.first?["target"] as? String == "/opt/homebrew/bin/brew")
    }

    @Test("status reports state and freshness; STALE past the threshold")
    func status() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        try writePlist([
            "state": "healthy", "enforcementMode": "enforce", "daemonVersion": "1.0.0",
            "updatedAt": ISO8601.string(from: now.addingTimeInterval(-30)),
        ], to: dir.appendingPathComponent("state.plist"))

        let fresh = runner(stateDir: dir).run(.status)
        #expect(fresh.text.contains("healthy"))
        #expect(fresh.text.contains("30s ago"))
        #expect(!fresh.text.contains("STALE"))

        try writePlist([
            "state": "healthy", "enforcementMode": "enforce", "daemonVersion": "1.0.0",
            "updatedAt": ISO8601.string(from: now.addingTimeInterval(-3600)),
        ], to: dir.appendingPathComponent("state.plist"))
        let stale = runner(stateDir: dir).run(.status)
        #expect(stale.text.contains("STALE"))
    }

    @Test("status shows the exec gate state from state.plist")
    func statusExecGate() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let statePlist = dir.appendingPathComponent("state.plist")
        func status(_ extra: [String: Any]) throws -> String {
            var state: [String: Any] = [
                "state": "healthy", "enforcementMode": "enforce", "daemonVersion": "1.0.0",
                "updatedAt": ISO8601.string(from: now.addingTimeInterval(-30)),
            ]
            state.merge(extra) { $1 }
            try writePlist(state, to: statePlist)
            return runner(stateDir: dir).run(.status).text
        }

        #expect(try status(["execGate": "active"]).contains("Exec gate        on"))
        #expect(try status([
            "execGate": "off_not_entitled",
            "execGateDetail": "This build has no Endpoint Security entitlement, so the exec gate is off.",
        ]).contains("Exec gate        off (no Endpoint Security entitlement)"))
        #expect(try status(["execGate": "unavailable", "execGateDetail": "Full Disk Access missing"])
            .contains("Exec gate        off, unavailable (Full Disk Access missing)"))
        #expect(try status(["execGate": "not_started", "execGateDetail": "daemon degraded"])
            .contains("Exec gate        off, not started (daemon degraded)"))
        // A daemon that predates the key.
        #expect(try status([:]).contains("Exec gate        not reported"))
    }

    @Test("status reports not-installed when state.plist is absent")
    func statusMissing() {
        let output = runner().run(.status)
        #expect(output.exitCode == 1)
        #expect(output.text.contains("not be installed"))
    }

    @Test("version reads version.plist")
    func version() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        try writePlist([
            "daemonVersion": "1.2.3", "pamModuleVersion": "1.2.3", "cliVersion": "1.2.3",
            "installedAt": "2026-06-13T00:00:00Z",
        ], to: dir.appendingPathComponent("version.plist"))
        let output = runner(stateDir: dir).run(.version)
        #expect(output.text.contains("1.2.3"))
    }

    @Test("grants is explicit about unavailable vs live data")
    func grants() {
        let unavailable = runner().run(.grants, grants: nil)
        #expect(unavailable.text.contains("sudo serberus grants"))

        let live = runner(isRoot: true).run(.grants, grants: [
            Grant(user: "alice", uid: 501, ruleID: "allow-brew", profileKey: "rules_sudo_brew",
                  teamID: "", binaryHash: "aa", canonicalPath: "/opt/homebrew/bin/brew",
                  grantedAt: now, expiresAt: now.addingTimeInterval(600), policyVersion: "1.0.0"),
        ])
        #expect(live.text.contains("read live"))
        #expect(live.text.contains("/opt/homebrew/bin/brew"))
    }

    @Test("simulate runs the engine and shows the trace")
    func simulate() {
        let args = SimulateArguments(command: "/opt/homebrew/bin/brew", executablePath: "/opt/homebrew/bin/brew")
        let output = runner(rules: ["rules_sudo_brew": profileJSON()]).run(.simulate(args))
        #expect(output.text.contains("ALLOW"))
        #expect(output.text.contains("Trace:"))
    }

    @Test("simulate --json emits a structured decision")
    func simulateJSON() throws {
        var args = SimulateArguments(command: "/opt/homebrew/bin/brew", executablePath: "/opt/homebrew/bin/brew")
        args.json = true
        let output = runner(rules: ["rules_sudo_brew": profileJSON()]).run(.simulate(args))
        let json = try JSONSerialization.jsonObject(with: Data(output.text.utf8)) as? [String: Any]
        #expect(json?["decision"] as? String == "allow")
        #expect(json?["matchedRule"] as? String == "allow-brew")
    }

    @Test("unknown command exits non-zero with help")
    func unknown() {
        let output = runner().run(.unknown("frobnicate"))
        #expect(output.exitCode == 2)
        #expect(output.text.contains("Usage:"))
    }

    // MARK: helpers

    private func makeTempDir() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("serberus-cli-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private func writePlist(_ dict: [String: Any], to url: URL) throws {
        let data = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        try data.write(to: url)
    }
}
