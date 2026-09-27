import Foundation
import PrivMgrCore

/// Tier 2 of the authoring model: a named decision bundle over a set of
/// definitions.
///
/// A rule holds the WHAT-HAPPENS half of the old wire `Rule` — allow/deny,
/// silent/prompt, and every advanced setting — and references its matchers
/// (``RuleDefinition``) by id instead of embedding them. One rule can cover
/// several definitions (e.g. "Allow developer package managers" over both a
/// Homebrew and a MacPorts definition); ``PolicyCompiler`` expands each
/// (rule, definition) pair into one wire rule at compile time. Rules are
/// library-owned and shared: assigning a rule to several policies references
/// the same value, so an edit propagates everywhere it is assigned.
public struct PolicyRule: Codable, Sendable, Equatable, Identifiable {
    /// Stable slug (`[a-z0-9_]+` by convention), unique across the rule
    /// library. Ids never change after creation — compiled wire rule ids and
    /// policy assignments embed them.
    public var id: String
    /// Display name shown in the Rules screen and policy assignment lists.
    public var name: String
    /// Free-text description. When non-empty it becomes the compiled wire
    /// rule's `description`; otherwise `name` is used.
    public var detail: String
    /// Ordered references into the definition library. Unknown ids are
    /// skipped at compile time and reported by authoring validation.
    public var definitionIDs: [String]
    /// Allow or deny. Deny wins at equal priority and is never cached.
    public var action: RuleAction
    /// Silent grant or user-approved prompt (meaningful for allow).
    public var elevationType: ElevationType

    // Advanced settings — applied to every wire rule this rule compiles to.
    /// Wire evaluation order within the compiled profile. Lower runs first.
    public var priority: Int
    /// When true the wire `cacheSeconds` is `nil` (use the global
    /// `sudoCacheSeconds`); when false, `cacheSeconds` below is emitted.
    public var useGlobalCache: Bool
    /// Per-rule cache TTL in seconds (`0` = never cache). Only emitted when
    /// `useGlobalCache` is false.
    public var cacheSeconds: Int
    /// When true, the user must supply justification text before approval.
    public var requireJustification: Bool
    /// Duration of the grant created on allow: -1 = evaluate every time
    /// (never grant), 0 = use the org default, N = N seconds.
    public var maxGrantDurationSeconds: Int
    /// When true, redacted argv is included in decision log events.
    public var logArguments: Bool

    public var createdAt: Date
    public var updatedAt: Date

    public init(
        id: String,
        name: String,
        detail: String = "",
        definitionIDs: [String] = [],
        action: RuleAction = .allow,
        elevationType: ElevationType = .silent,
        priority: Int = 50,
        useGlobalCache: Bool = true,
        cacheSeconds: Int = 0,
        requireJustification: Bool = false,
        maxGrantDurationSeconds: Int = 0,
        logArguments: Bool = false,
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.detail = detail
        self.definitionIDs = definitionIDs
        self.action = action
        self.elevationType = elevationType
        self.priority = priority
        self.useGlobalCache = useGlobalCache
        self.cacheSeconds = cacheSeconds
        self.requireJustification = requireJustification
        self.maxGrantDurationSeconds = maxGrantDurationSeconds
        self.logArguments = logArguments
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}
