import Foundation
import PrivMgrCore

/// Captured CLI result: text for stdout and a process exit code.
public struct CLIOutput: Equatable, Sendable {
    public let text: String
    public let exitCode: Int32

    public init(text: String, exitCode: Int32 = 0) {
        self.text = text
        self.exitCode = exitCode
    }
}

/// Runs CLI commands against injected sources so every command is testable
/// without the real `/Library` files or a running daemon.
///
/// Data-freshness rule: the CLI never presents stale data as
/// live. `status` reports the age of `state.plist`; `grants` is explicit about
/// whether it read the live database or could not.
public struct CLIRunner: Sendable {
    private let preferences: PreferencesSource
    private let statePlistURL: URL
    private let versionPlistURL: URL
    private let username: String
    private let isRoot: Bool
    private let stalenessThreshold: TimeInterval
    private let now: @Sendable () -> Date

    public init(
        preferences: PreferencesSource,
        statePlistURL: URL,
        versionPlistURL: URL,
        username: String,
        isRoot: Bool,
        stalenessThreshold: TimeInterval = 15 * 60,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.preferences = preferences
        self.statePlistURL = statePlistURL
        self.versionPlistURL = versionPlistURL
        self.username = username
        self.isRoot = isRoot
        self.stalenessThreshold = stalenessThreshold
        self.now = now
    }

    /// Runs `command`. For `.grants`, the executable supplies live grants when
    /// it could read them (root); `nil` means unavailable.
    public func run(_ command: CLICommand, grants: [Grant]? = nil) -> CLIOutput {
        switch command {
        case let .list(json): return listOutput(json: json)
        case .status: return statusOutput()
        case .grants: return grantsOutput(grants)
        case .version: return versionOutput()
        case let .simulate(args): return simulateOutput(args)
        case .help: return CLIOutput(text: Self.helpText)
        case let .unknown(name):
            return CLIOutput(text: "Unknown command '\(name)'.\n\n\(Self.helpText)", exitCode: 2)
        }
    }

    // MARK: list

    private func listOutput(json: Bool) -> CLIOutput {
        let profiles = ManagedPreferencesReader(source: preferences).readRuleProfiles().value
        let capabilities = Self.capabilities(in: profiles)

        if json {
            let payload = CapabilitiesJSON(
                user: username,
                profileCount: profiles.count,
                capabilities: capabilities
            )
            return CLIOutput(text: Self.encodeJSON(payload))
        }

        var lines = ["Effective Serberus capabilities for \(username):"]
        if profiles.isEmpty {
            lines.append("  No rules_* profiles are deployed — native macOS behavior applies.")
        } else if capabilities.isEmpty {
            lines.append("  \(profiles.count) profile(s) deployed, no allow/prompt capabilities.")
        } else {
            for capability in capabilities {
                lines.append("  • [\(capability.action)] \(capability.target)  (\(capability.profileKey) · \(capability.ruleID))")
            }
        }
        return CLIOutput(text: lines.joined(separator: "\n"))
    }

    // MARK: status

    private func statusOutput() -> CLIOutput {
        guard let state = Self.readPlist(statePlistURL) else {
            return CLIOutput(
                text: "Serberus daemon: state.plist not found — daemon may not be installed.",
                exitCode: 1
            )
        }
        let version = Self.readPlist(versionPlistURL)

        var lines = ["Serberus daemon status:"]
        lines.append("  State            \(state["state"] as? String ?? "unknown")")
        if let reason = state["degradedReason"] as? String {
            lines.append("  Degraded reason  \(reason)")
        }
        lines.append("  Enforcement      \(state["enforcementMode"] as? String ?? "unknown")")
        lines.append("  Daemon version   \(state["daemonVersion"] as? String ?? version?["daemonVersion"] as? String ?? "unknown")")
        lines.append("  Exec gate        \(Self.execGateDescription(state))")

        if let updatedAt = state["updatedAt"] as? String, let date = ISO8601.date(from: updatedAt) {
            let age = now().timeIntervalSince(date)
            let stale = age > stalenessThreshold
            lines.append("  Updated          \(updatedAt) (\(Self.ageString(age))\(stale ? " — STALE" : ""))")
        } else {
            lines.append("  Updated          unknown")
        }
        return CLIOutput(text: lines.joined(separator: "\n"))
    }

    /// The exec gate line, from `state.plist`'s `execGate` / `execGateDetail`.
    static func execGateDescription(_ state: [String: Any]) -> String {
        let detail = (state["execGateDetail"] as? String)?
            .split(separator: "\n").first.map(String.init)
        switch state["execGate"] as? String {
        case "active": return "on"
        case "off_not_entitled": return "off (no Endpoint Security entitlement)"
        case "unavailable": return "off, unavailable" + (detail.map { " (\($0))" } ?? "")
        case "not_started": return "off, not started" + (detail.map { " (\($0))" } ?? "")
        case let other?: return other
        case nil: return "not reported"
        }
    }

    // MARK: grants

    private func grantsOutput(_ grants: [Grant]?) -> CLIOutput {
        guard let grants else {
            return CLIOutput(text: """
                Active grants are stored in a root-only database and are not \
                readable here.
                Run `sudo serberus grants`, or view them in the Serberus menubar.
                """, exitCode: 0)
        }
        let active = grants.filter { $0.isActive(at: now()) }
        if active.isEmpty {
            return CLIOutput(text: "No active grants (read live from the grant database).")
        }
        var lines = ["Active grants (read live from the grant database):"]
        for grant in active.sorted(by: { $0.grantedAt < $1.grantedAt }) {
            let expiry = grant.expiresAt.map(ISO8601.string(from:)) ?? "no expiry"
            lines.append("  • \(grant.user) · \(grant.ruleID) · \(grant.canonicalPath) · expires \(expiry)")
        }
        return CLIOutput(text: lines.joined(separator: "\n"))
    }

    // MARK: version

    private func versionOutput() -> CLIOutput {
        guard let version = Self.readPlist(versionPlistURL) else {
            return CLIOutput(text: "Serberus is not installed (version.plist not found).", exitCode: 1)
        }
        var lines = ["Serberus component versions:"]
        lines.append("  Daemon  \(version["daemonVersion"] as? String ?? "unknown")")
        lines.append("  PAM     \(version["pamModuleVersion"] as? String ?? "unknown")")
        lines.append("  CLI     \(version["cliVersion"] as? String ?? "unknown")")
        if let installedAt = version["installedAt"] as? String {
            lines.append("  Installed \(installedAt)")
        }
        return CLIOutput(text: lines.joined(separator: "\n"))
    }

    // MARK: simulate

    private func simulateOutput(_ args: SimulateArguments) -> CLIOutput {
        let profiles = ManagedPreferencesReader(source: preferences).readRuleProfiles().value
        let config = ManagedPreferencesReader(source: preferences).readConfig().value

        let executable = args.executablePath ?? args.command ?? "/usr/bin/true"
        let context = SimulationContext(
            user: args.user ?? username,
            uid: 0,
            authURI: args.authURI,
            sudoCommand: args.authURI == nil ? (args.command ?? executable) : nil,
            argv: args.argv,
            executablePath: executable,
            teamID: args.teamID,
            binaryHash: args.binaryHash,
            signingStatus: args.teamID.isEmpty ? .unsigned : .valid,
            activeGrants: [],
            currentTime: now()
        )

        let result: SimulationResult
        do {
            result = try DecisionSimulator().simulate(
                context: context, profiles: profiles,
                globalCacheSeconds: config.sudoCacheSeconds,
                globalGrantDurationSeconds: config.defaultGrantDurationSeconds,
                timeBoundGrantsEnabled: config.timeBoundGrantsEnabled
            )
        } catch {
            return CLIOutput(text: "Cannot simulate: \(error.localizedDescription)", exitCode: 2)
        }

        if args.json {
            return CLIOutput(text: Self.encodeJSON(SimulateResultJSON(result: result)))
        }

        var lines = ["Decision: \(result.decision.rawValue.uppercased())"]
        lines.append("  Reason   \(result.reason)")
        if let rule = result.matchedRule { lines.append("  Rule     \(rule)") }
        if let profile = result.matchedProfile { lines.append("  Profile  \(profile)") }
        lines.append("  Cache    \(result.cacheBehavior)")
        for warning in result.warnings { lines.append("  ⚠ \(warning)") }
        lines.append("  Trace:")
        for step in result.evaluationTrace {
            lines.append("    \(step.description)")
        }
        return CLIOutput(text: lines.joined(separator: "\n"))
    }

    // MARK: Helpers

    /// Allow/prompt capabilities across all profiles, deterministically ordered.
    static func capabilities(in profiles: [RuleProfile]) -> [Capability] {
        var result: [Capability] = []
        for profile in profiles.sorted(by: { $0.profileKey < $1.profileKey }) {
            for rule in profile.rules where rule.action == .allow {
                let target: String
                switch rule.type {
                case .authuri: target = rule.match.authURI ?? "(unspecified right)"
                case .sudo: target = rule.match.commandPattern ?? "(any command)"
                }
                result.append(Capability(
                    profileKey: profile.profileKey,
                    ruleID: rule.id,
                    action: rule.elevation.type == .prompt ? "prompt" : "allow",
                    target: target
                ))
            }
        }
        return result
    }

    static func readPlist(_ url: URL) -> [String: Any]? {
        guard let data = try? Data(contentsOf: url),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let dict = plist as? [String: Any] else {
            return nil
        }
        return dict
    }

    static func ageString(_ seconds: TimeInterval) -> String {
        let whole = Int(seconds.rounded())
        if whole < 60 { return "\(whole)s ago" }
        if whole < 3600 { return "\(whole / 60)m ago" }
        return "\(whole / 3600)h ago"
    }

    static func encodeJSON(_ value: some Encodable) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]
        guard let data = try? encoder.encode(value) else { return "{}" }
        return String(decoding: data, as: UTF8.self)
    }

    public static let helpText = """
        serberus — Serberus privilege management CLI

        Usage:
          serberus list [--json]     Effective capabilities for the current user
          serberus status            Daemon health, version, policy version
          serberus grants            Active timed grants (sudo serberus grants for live data)
          serberus version           Installed component versions
          serberus simulate ...      Run the Decision Simulator
            --user <name>  --command <path>  --arg <a> [--arg <b> ...]
            --auth-uri <right>  --executable <path>  --team-id <id>  --hash <sha256>  --json
        """
}

/// One effective capability for `list`.
public struct Capability: Codable, Equatable, Sendable {
    public let profileKey: String
    public let ruleID: String
    public let action: String
    public let target: String
}

struct CapabilitiesJSON: Encodable {
    let user: String
    let profileCount: Int
    let capabilities: [Capability]
}

struct SimulateResultJSON: Encodable {
    let decision: String
    let reason: String
    let matchedRule: String?
    let matchedProfile: String?
    let cacheBehavior: String
    let warnings: [String]
    let trace: [String]

    init(result: SimulationResult) {
        decision = result.decision.rawValue
        reason = result.reason
        matchedRule = result.matchedRule
        matchedProfile = result.matchedProfile
        cacheBehavior = result.cacheBehavior
        warnings = result.warnings
        trace = result.evaluationTrace.map(\.description)
    }
}
