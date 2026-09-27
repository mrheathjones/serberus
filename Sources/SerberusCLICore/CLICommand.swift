import Foundation

/// The parsed CLI invocation.
public enum CLICommand: Equatable, Sendable {
    case list(json: Bool)
    case status
    case grants
    case version
    case simulate(SimulateArguments)
    case help
    case unknown(String)

    /// Parses `argv` (excluding the program name).
    public static func parse(_ arguments: [String]) -> CLICommand {
        guard let first = arguments.first else { return .help }
        let rest = Array(arguments.dropFirst())
        switch first {
        case "list":
            return .list(json: rest.contains("--json"))
        case "status":
            return .status
        case "grants":
            return .grants
        case "version":
            return .version
        case "simulate":
            return .simulate(SimulateArguments.parse(rest))
        case "help", "--help", "-h":
            return .help
        default:
            return .unknown(first)
        }
    }
}

/// `serberus simulate` flags.
public struct SimulateArguments: Equatable, Sendable {
    public var user: String?
    public var command: String?
    public var argv: [String]
    public var authURI: String?
    public var executablePath: String?
    public var teamID: String
    public var binaryHash: String
    public var json: Bool

    public init(
        user: String? = nil,
        command: String? = nil,
        argv: [String] = [],
        authURI: String? = nil,
        executablePath: String? = nil,
        teamID: String = "",
        binaryHash: String = "",
        json: Bool = false
    ) {
        self.user = user
        self.command = command
        self.argv = argv
        self.authURI = authURI
        self.executablePath = executablePath
        self.teamID = teamID
        self.binaryHash = binaryHash
        self.json = json
    }

    /// Parses `--key value` flags. `--arg` may repeat to build argv.
    public static func parse(_ tokens: [String]) -> SimulateArguments {
        var args = SimulateArguments()
        var index = 0
        func nextValue() -> String? {
            guard index + 1 < tokens.count else { return nil }
            index += 1
            return tokens[index]
        }
        while index < tokens.count {
            switch tokens[index] {
            case "--user": args.user = nextValue()
            case "--command": args.command = nextValue()
            case "--auth-uri": args.authURI = nextValue()
            case "--executable": args.executablePath = nextValue()
            case "--team-id": args.teamID = nextValue() ?? ""
            case "--hash": args.binaryHash = nextValue() ?? ""
            case "--arg": if let value = nextValue() { args.argv.append(value) }
            case "--json": args.json = true
            default: break
            }
            index += 1
        }
        return args
    }
}
