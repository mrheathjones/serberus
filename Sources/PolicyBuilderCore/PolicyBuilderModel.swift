import Foundation
import Observation
import PrivMgrCore

/// Sidebar destinations. The Fleet section surfaces V1.1 data; the Policy
/// section drives the live V1 rule engine.
public enum SidebarSection: String, CaseIterable, Identifiable, Sendable {
    case dashboard
    case policies
    case rules
    case definitions
    case decisionSimulator
    case fleetObserver
    case settings

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .dashboard: return "Dashboard"
        case .policies: return "Policies"
        case .rules: return "Rules"
        case .definitions: return "Definitions"
        case .decisionSimulator: return "Decision Simulator"
        case .fleetObserver: return "Fleet Observer"
        case .settings: return "Settings"
        }
    }

    public var group: SidebarGroup {
        switch self {
        case .dashboard: return .overview
        case .policies, .rules, .definitions, .decisionSimulator: return .policy
        case .fleetObserver: return .fleet
        case .settings: return .system
        }
    }
}

/// Sidebar grouping for section headers.
public enum SidebarGroup: String, CaseIterable, Identifiable, Sendable {
    case overview
    case policy
    case fleet
    case system

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .overview: return "Overview"
        case .policy: return "Policy"
        case .fleet: return "Fleet"
        case .system: return "System"
        }
    }

    public var sections: [SidebarSection] {
        SidebarSection.allCases.filter { $0.group == self }
    }
}

/// A cross-screen deep link into one of the three authoring tiers. The target
/// screen consumes it on appear (scroll/flash the row, or open its editor).
public enum PendingFocus: Equatable, Sendable {
    case policy(id: String)
    case rule(id: String)
    case definition(id: String)
}

/// Top-level app state shared across the Policy Builder panes.
///
/// Holds the three-tier authoring library — ``Policy`` → ``PolicyRule`` →
/// ``RuleDefinition`` — as the single source of truth. Every mutation goes
/// through a model method that persists atomically. The daemon-facing wire
/// profiles are never stored: ``compiledProfiles()`` derives them on demand
/// via ``PolicyCompiler``, so validation, simulation, export, and publish all
/// see exactly what the fleet would enforce.
@MainActor
@Observable
public final class PolicyBuilderModel {
    public var selectedSection: SidebarSection = .dashboard
    /// Set by the app-level "Import Capture…" command; the Definitions screen
    /// consumes it — on appear AND on change, because the screen may not
    /// exist yet when the command fires from another section — and opens the
    /// file importer.
    public var captureImportPending = false

    /// File ▸ Import Capture…: jump to Definitions and open the importer.
    public func requestCaptureImport() {
        selectedSection = .definitions
        captureImportPending = true
    }
    /// When another screen deep-links into a tier's screen, the target screen
    /// consumes this on appear. Set via ``openPolicyEditor(policyID:)`` /
    /// ``openRuleEditor(ruleID:)`` / ``openDefinitionEditor(definitionID:)``.
    public var pendingFocus: PendingFocus?

    /// Tier 1 — deliverable policies referencing rules by id.
    public var policies: [Policy]
    /// Tier 2 — the shared rule library (decision + advanced settings).
    public var rules: [PolicyRule]
    /// Tier 3 — the shared definition library (pure matchers).
    public var definitions: [RuleDefinition]

    public var simulator: DecisionSimulatorModel
    public var patternTester = PatternTesterModel()
    public var export = ExportModel()
    public var publish: PublishModel
    /// Live authorization-rights catalog read from this Mac (for the definition builder).
    public var authRights = AuthRightsCatalog()
    /// Editable MDM connection (vendor, URL, credentials) for the Settings pane.
    public var mdm = MDMSettingsModel()
    /// Editable just-in-time local-admin policy for the Settings pane.
    public var jitAdmin = JITAdminSettingsModel()
    /// Editable daemon behavior / break-glass config for the Settings pane.
    public var daemonConfig = DaemonConfigSettingsModel()
    /// The Fleet Observer's Jamf-backed device list + captures.
    public var fleet: FleetObserverModel
    /// A single capture attempt the operator chose to author on the Definitions
    /// screen — the Fleet Observer reviews a capture in place and, only when
    /// "Create Definition" is pressed, hands the draft here and navigates to
    /// Definitions, where the composer opens pre-filled and the review ledger /
    /// harvest completes on save. `nil` outside that hand-off.
    public var pendingComposerPrefill: PendingComposerPrefill?
    /// A BATCH of definitions the Review Capture sheet just created directly (no
    /// composer). The Fleet Observer navigates to Definitions and hands the
    /// completion here so the review ledger record + harvest delete (and any
    /// "couldn't delete from Jamf" notice) happen on the destination screen the
    /// operator lands on — never silently on the unmounted Fleet Observer.
    public var pendingImportCompletion: PendingImportCompletion?
    /// A deep link into the Fleet Observer (tab + filters) waiting for the
    /// screen to consume it — set by the Dashboard cards, the risk signals
    /// and the menu bar through ``openFleetObserver(_:)``.
    public var pendingFleetRoute: FleetRoute?

    /// Dashboard risk signals the operator switched off (Settings → Dashboard
    /// & fleet posture). Persisted in `UserDefaults` when one was given.
    public var disabledRiskSignals: Set<RiskSignal.Kind> {
        didSet {
            guard disabledRiskSignals != oldValue else { return }
            defaults?.set(disabledRiskSignals.map(\.rawValue).sorted(), forKey: Self.kDisabledRiskSignals)
        }
    }
    @ObservationIgnored private let defaults: UserDefaults?
    private static let kDisabledRiskSignals = "serberus.dashboard.disabledRiskSignals"

    /// Read-only Jamf connection state for the Settings pane.
    private let credentialStore: JamfCredentialStore
    /// The admin Mac's managed preferences — source of the direct-publish gate.
    private let preferencesReader: ManagedPreferencesReader
    /// On-disk persistence; `nil` keeps the library in-memory only (tests).
    private let store: ProfileLibraryStore?

    /// Whether Commander may publish RULE profiles straight to the MDM API —
    /// the `commanderPublishEnabled` key of the `com.herojoneslabs.serberus.config`
    /// profile delivered to THIS Mac (managed layer only — a user's
    /// `defaults write` never counts). False hides every "Publish to Jamf"
    /// affordance for policies (card, editor, export sheet) — the file paths
    /// (console-editable Jamf schema / `.plist`, plus `.mobileconfig`)
    /// remain. Refreshed by ``refreshDirectPublishGate()`` (cheap; screens
    /// call it on appear).
    public private(set) var directPublishEnabled: Bool

    /// Policies with a direct publish in flight — owned by the model (not a
    /// screen's @State) so spinners survive navigation and no surface can
    /// start a second publish of the same policy while one is running.
    public private(set) var publishingPolicyIDs: Set<String> = []
    /// Outcome of the most recent direct-publish run (single or batch). Kept
    /// here so a batch that finishes while the operator is on another screen
    /// still reports when they come back; the presenting screen clears it.
    public var lastPublishSummary: PublishSummary?

    public init(
        policies: [Policy] = [],
        rules: [PolicyRule] = [],
        definitions: [RuleDefinition] = [],
        simulator: DecisionSimulatorModel = DecisionSimulatorModel(defaults: nil),
        publish: PublishModel = PublishModel(),
        credentialStore: JamfCredentialStore = JamfCredentialStore(),
        preferencesReader: ManagedPreferencesReader = ManagedPreferencesReader(),
        store: ProfileLibraryStore? = nil,
        fleet: FleetObserverModel = FleetObserverModel(),
        defaults: UserDefaults? = nil
    ) {
        self.policies = policies
        self.rules = rules
        self.definitions = definitions
        self.simulator = simulator
        self.publish = publish
        self.credentialStore = credentialStore
        self.preferencesReader = preferencesReader
        self.store = store
        self.fleet = fleet
        self.defaults = defaults
        self.disabledRiskSignals = Set((defaults?.stringArray(forKey: Self.kDisabledRiskSignals) ?? [])
            .compactMap(RiskSignal.Kind.init(rawValue:)))
        self.directPublishEnabled = preferencesReader.readConfig().value.commanderPublishEnabled
    }

    /// Re-reads the direct-publish gate from managed preferences (an MDM push
    /// can flip it while Commander is open). Safe to call from `onAppear`.
    public func refreshDirectPublishGate() {
        let enabled = preferencesReader.readConfig().value.commanderPublishEnabled
        if enabled != directPublishEnabled { directPublishEnabled = enabled }
    }

    /// Builds a store-backed model: loads the persisted library, or starts an
    /// empty one on first run. The Policy Builder uses this at launch.
    @MainActor
    public static func persistent(store: ProfileLibraryStore = ProfileLibraryStore()) -> PolicyBuilderModel {
        // The app's model remembers the simulator's builder layout, the
        // fleet check-in thresholds, the risk-signal switches and the upload
        // review ledger across launches; the in-memory (test) default does
        // not touch UserDefaults or disk.
        let model = PolicyBuilderModel(
            simulator: DecisionSimulatorModel(defaults: .standard),
            store: store,
            fleet: FleetObserverModel(defaults: .standard, reviews: CaptureReviewLedger(url: CaptureReviewLedger.defaultURL())),
            defaults: .standard)
        model.loadOrCreate()
        return model
    }

    /// Loads the library from disk, or starts an empty one on first run.
    /// Commander ships no starter policies: every rule is one the admin wrote.
    /// A loaded v1 file is migrated by ``PolicyLibraryFile/init(from:)``;
    /// persisting right after load makes that migration durable so the next
    /// launch reads v2 directly.
    public func loadOrCreate() {
        if let file = store?.load() {
            policies = file.policies
            rules = file.rules
            definitions = file.definitions
        } else {
            policies = []
            rules = []
            definitions = []
        }
        persist()
    }

    /// Writes the current library to disk (no-op without a store).
    public func persist() {
        store?.save(PolicyLibraryFile(definitions: definitions, rules: rules, policies: policies))
    }

    /// Re-reads the persisted library (picking up external changes) without
    /// disturbing navigation. No-op without a store.
    public func reloadLibrary() {
        guard let file = store?.load() else { return }
        policies = file.policies
        rules = file.rules
        definitions = file.definitions
    }

    // MARK: Lookups

    public func policy(id: String) -> Policy? {
        policies.first { $0.id == id }
    }

    public func rule(id: String) -> PolicyRule? {
        rules.first { $0.id == id }
    }

    public func definition(id: String) -> RuleDefinition? {
        definitions.first { $0.id == id }
    }

    /// The policy's assignments joined with their library rules, in
    /// assignment order. `rule` is `nil` for dangling references (deleted
    /// rules) so the UI can surface them instead of hiding them.
    public func rules(in policy: Policy) -> [(assignment: PolicyRuleAssignment, rule: PolicyRule?)] {
        policy.rules.map { ($0, rule(id: $0.ruleID)) }
    }

    /// The rule's definitions in reference order. Dangling references are
    /// dropped (authoring validation reports them separately).
    public func definitions(in rule: PolicyRule) -> [RuleDefinition] {
        rule.definitionIDs.compactMap { definition(id: $0) }
    }

    /// Policies with an assignment (enabled or not) referencing `ruleID` —
    /// drives "used by N policies" counts and delete warnings.
    public func policiesUsing(ruleID: String) -> [Policy] {
        policies.filter { $0.rules.contains { $0.ruleID == ruleID } }
    }

    /// Rules referencing `definitionID` — drives "used by N rules" counts and
    /// delete warnings.
    public func rulesUsing(definitionID: String) -> [PolicyRule] {
        rules.filter { $0.definitionIDs.contains(definitionID) }
    }

    // MARK: Policy CRUD

    /// Creates an empty policy (id slugged from `name`, uniquified), persists,
    /// and returns the new id. Does not navigate — callers pair with
    /// ``openPolicyEditor(policyID:)`` when they want the editor.
    @discardableResult
    public func newPolicy(name: String = "New Policy") -> String {
        let base = Self.slugify(name)
        let id = AuthoringID.uniqueID(base: base.isEmpty ? "policy" : base,
                                      existing: Set(policies.map(\.id)))
        policies.append(Policy(id: id, name: name, profilePriority: nextPolicyPriority()))
        persist()
        return id
    }

    /// Upserts a policy by id, bumps `updatedAt`, and persists. On replace
    /// the stored `createdAt` is preserved so editors don't have to carry it.
    public func updatePolicy(_ policy: Policy) {
        var updated = policy
        updated.updatedAt = Date()
        if let index = policies.firstIndex(where: { $0.id == policy.id }) {
            updated.createdAt = policies[index].createdAt
            policies[index] = updated
        } else {
            policies.append(updated)
        }
        persist()
    }

    /// Removes a policy and persists. The rules it referenced stay in the
    /// library (they are shared, not owned).
    public func deletePolicy(id: String) {
        deletePolicies(ids: [id])
    }

    /// Removes several policies and persists ONCE — the Policies list view's
    /// checkbox multi-delete must not rewrite the library per row.
    public func deletePolicies(ids: Set<String>) {
        guard !ids.isEmpty else { return }
        policies.removeAll { ids.contains($0.id) }
        persist()
    }

    /// Duplicates a policy under `<id>_copy` (uniquified) with " (Copy)"
    /// appended to the name and a fresh priority. Rule assignments are
    /// copied by reference — both policies share the same library rules.
    @discardableResult
    public func duplicatePolicy(id: String) -> String? {
        guard let source = policy(id: id) else { return nil }
        var copy = source
        copy.id = AuthoringID.uniqueID(base: "\(id)_copy", existing: Set(policies.map(\.id)))
        copy.name = source.name + " (Copy)"
        copy.profilePriority = nextPolicyPriority()
        copy.createdAt = Date()
        copy.updatedAt = Date()
        policies.append(copy)
        persist()
        return copy.id
    }

    /// Toggles one rule assignment inside a policy — the functional per-rule
    /// per-policy gate: disabled assignments are never compiled. No-op when
    /// the policy or assignment doesn't exist.
    public func setRule(_ ruleID: String, enabled: Bool, inPolicy policyID: String) {
        guard let policyIndex = policies.firstIndex(where: { $0.id == policyID }),
              let ruleIndex = policies[policyIndex].rules.firstIndex(where: { $0.ruleID == ruleID })
        else { return }
        policies[policyIndex].rules[ruleIndex].enabled = enabled
        policies[policyIndex].updatedAt = Date()
        persist()
    }

    /// Appends an enabled assignment for `ruleID`. No-op when the policy
    /// doesn't exist, the rule isn't in the library (no dangling refs by
    /// construction), or the policy already has the assignment.
    public func addRule(_ ruleID: String, toPolicy policyID: String) {
        guard let policyIndex = policies.firstIndex(where: { $0.id == policyID }),
              rule(id: ruleID) != nil,
              !policies[policyIndex].rules.contains(where: { $0.ruleID == ruleID })
        else { return }
        policies[policyIndex].rules.append(PolicyRuleAssignment(ruleID: ruleID))
        policies[policyIndex].updatedAt = Date()
        persist()
    }

    /// Removes `ruleID`'s assignment from a policy. The rule itself stays in
    /// the library. No-op when the policy or assignment doesn't exist.
    public func removeRule(_ ruleID: String, fromPolicy policyID: String) {
        guard let policyIndex = policies.firstIndex(where: { $0.id == policyID }),
              policies[policyIndex].rules.contains(where: { $0.ruleID == ruleID })
        else { return }
        policies[policyIndex].rules.removeAll { $0.ruleID == ruleID }
        policies[policyIndex].updatedAt = Date()
        persist()
    }

    /// Patch-bumps a policy's semver ("1.0.0" → "1.0.1") and persists.
    /// No-op when ``nextPatchVersion(of:)`` can't produce a successor.
    public func bumpPolicyVersion(id: String) {
        guard let index = policies.firstIndex(where: { $0.id == id }),
              let next = Self.nextPatchVersion(of: policies[index].policyVersion) else { return }
        policies[index].policyVersion = next
        policies[index].updatedAt = Date()
        persist()
    }

    /// The patch successor of a strict MAJOR.MINOR.PATCH version ("1.0.0" →
    /// "1.0.1"), or `nil` when the version isn't strictly numeric semver or the
    /// patch component would overflow. The single parser shared by
    /// ``bumpPolicyVersion(id:)`` and the Export sheet's bump button,
    /// so the UI never offers a bump the model would reject.
    nonisolated public static func nextPatchVersion(of version: String) -> String? {
        let parts = version.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              parts.allSatisfy({ !$0.isEmpty && $0.allSatisfy(\.isNumber) }),
              let patch = Int(parts[2]) else { return nil }
        let (next, overflow) = patch.addingReportingOverflow(1)
        guard !overflow else { return nil }
        return "\(parts[0]).\(parts[1]).\(next)"
    }

    // MARK: Rule CRUD

    /// Creates a library rule (id slugged from `name`, uniquified) with the
    /// standard defaults (allow, silent, priority 50, global cache), persists,
    /// and returns the new id. Does not navigate or assign to any policy.
    @discardableResult
    public func newRule(name: String = "New Rule") -> String {
        let base = Self.slugify(name)
        let id = AuthoringID.uniqueID(base: base.isEmpty ? "rule" : base,
                                      existing: Set(rules.map(\.id)))
        rules.append(PolicyRule(id: id, name: name))
        persist()
        return id
    }

    /// Upserts a rule by id, bumps `updatedAt`, and persists. On replace the
    /// stored `createdAt` is preserved. Because policies reference rules by
    /// id, the edit is visible in every policy the rule is assigned to.
    public func upsertRule(_ rule: PolicyRule) {
        var updated = rule
        updated.updatedAt = Date()
        if let index = rules.firstIndex(where: { $0.id == rule.id }) {
            updated.createdAt = rules[index].createdAt
            rules[index] = updated
        } else {
            rules.append(updated)
        }
        persist()
    }

    /// Removes a rule from the library AND its assignments from every policy
    /// (referential-integrity cascade), bumping `updatedAt` on each policy
    /// that actually changed. Persists once.
    public func deleteRule(id: String) {
        deleteRules(ids: [id])
    }

    /// Removes several rules with the same cascade as ``deleteRule(id:)`` and
    /// persists ONCE — the Rules screen's checkbox multi-delete must not
    /// rewrite the library per row.
    public func deleteRules(ids: Set<String>) {
        guard !ids.isEmpty else { return }
        rules.removeAll { ids.contains($0.id) }
        let now = Date()
        for index in policies.indices where policies[index].rules.contains(where: { ids.contains($0.ruleID) }) {
            policies[index].rules.removeAll { ids.contains($0.ruleID) }
            policies[index].updatedAt = now
        }
        persist()
    }

    /// Duplicates a rule under `<id>_copy` (uniquified) with " (Copy)"
    /// appended to the name. Definition references are copied; policy
    /// assignments are not (the copy starts unassigned).
    @discardableResult
    public func duplicateRule(id: String) -> String? {
        guard let source = rule(id: id) else { return nil }
        var copy = source
        copy.id = AuthoringID.uniqueID(base: "\(id)_copy", existing: Set(rules.map(\.id)))
        copy.name = source.name + " (Copy)"
        copy.createdAt = Date()
        copy.updatedAt = Date()
        rules.append(copy)
        persist()
        return copy.id
    }

    // MARK: Definition CRUD

    /// Creates a definition of `kind` (id slugged from `name`, uniquified)
    /// with kind-appropriate empty matcher fields, persists, and returns the
    /// new id. Does not navigate.
    @discardableResult
    public func newDefinition(kind: RuleType, name: String = "New Definition") -> String {
        let base = Self.slugify(name)
        let id = AuthoringID.uniqueID(base: base.isEmpty ? "definition" : base,
                                      existing: Set(definitions.map(\.id)))
        definitions.append(RuleDefinition(
            id: id, name: name, kind: kind,
            matchType: kind == .sudo ? .exact : nil
        ))
        persist()
        return id
    }

    /// Upserts a definition by id, bumps `updatedAt`, and persists. On
    /// replace the stored `createdAt` is preserved. Rules reference
    /// definitions by id, so the edit propagates to every rule using it.
    public func upsertDefinition(_ definition: RuleDefinition) {
        upsertDefinitions([definition])
    }

    /// Upserts several definitions with the same rules as
    /// ``upsertDefinition(_:)`` and persists ONCE — a batch import must not
    /// rewrite the whole library once per row.
    public func upsertDefinitions(_ batch: [RuleDefinition]) {
        guard !batch.isEmpty else { return }
        let now = Date()
        for definition in batch {
            var updated = definition
            updated.updatedAt = now
            if let index = definitions.firstIndex(where: { $0.id == definition.id }) {
                updated.createdAt = definitions[index].createdAt
                definitions[index] = updated
            } else {
                definitions.append(updated)
            }
        }
        persist()
    }

    /// Removes a definition from the library AND its references from every
    /// rule (referential-integrity cascade), bumping `updatedAt` on each rule
    /// that actually changed. Persists once.
    public func deleteDefinition(id: String) {
        deleteDefinitions(ids: [id])
    }

    /// Removes several definitions with the same cascade as
    /// ``deleteDefinition(id:)`` and persists ONCE — the Definitions screen's
    /// checkbox multi-delete must not rewrite the library per row.
    public func deleteDefinitions(ids: Set<String>) {
        guard !ids.isEmpty else { return }
        definitions.removeAll { ids.contains($0.id) }
        let now = Date()
        for index in rules.indices where rules[index].definitionIDs.contains(where: { ids.contains($0) }) {
            rules[index].definitionIDs.removeAll { ids.contains($0) }
            rules[index].updatedAt = now
        }
        persist()
    }

    /// Duplicates a definition under `<id>_copy` (uniquified) with " (Copy)"
    /// appended to the name. Rule references are not copied — the duplicate
    /// starts unused.
    @discardableResult
    public func duplicateDefinition(id: String) -> String? {
        guard let source = definition(id: id) else { return nil }
        var copy = source
        copy.id = AuthoringID.uniqueID(base: "\(id)_copy", existing: Set(definitions.map(\.id)))
        copy.name = source.name + " (Copy)"
        copy.createdAt = Date()
        copy.updatedAt = Date()
        definitions.append(copy)
        persist()
        return copy.id
    }

    // MARK: App Identity definitions (identity-scoped authorization rights)

    /// Commander's authoring-side scope guard for one right (fast feedback
    /// with the specific rejection reason). The daemon re-checks at compose
    /// time, so this is the FIRST gate, not the only one.
    public func appIdentityScopeDecision(forRight right: String) -> AuthURIIdentityScopeDecision {
        AuthURIIdentityScopeRegistry.current.authoringDecision(for: right)
    }

    /// App Identity definitions (per-app pins on a right), in stable id order.
    public var appIdentityDefinitions: [RuleDefinition] {
        definitions.filter(\.isAppIdentity).sorted { $0.id < $1.id }
    }

    /// Compiled identity-scoped wire rules in `policyID` whose right is
    /// provisional (testing — not verified) — for warnings only; publishing
    /// is never blocked on it (the profile's Jamf scope is the operator's).
    public func provisionalAppIdentityRules(inPolicy policyID: String) -> [Rule] {
        compiledProfiles(forPolicy: policyID).flatMap(\.rules).filter { rule in
            guard rule.isIdentityScoped, let right = rule.match.authURI else { return false }
            return AuthURIIdentityScopeRegistry.current.state(for: right) == .provisional
        }
    }

    /// Fleet Macs whose macOS major is newer than a right's verified range —
    /// the "warn loudly" input. Uses the Fleet Observer's loaded devices
    /// (never invented); empty until the fleet has loaded.
    public func unverifiedOSWarnings() -> [(right: String, message: String, devices: Int)] {
        let rights = Set(appIdentityDefinitions.compactMap(\.authURI)).sorted()
        guard !rights.isEmpty, case .loaded = fleet.state else { return [] }
        let majors = fleet.devices.compactMap { $0.osVersion.flatMap(MacOSVersion.major(from:)) }
        guard let newest = majors.max() else { return [] }
        var warnings: [(String, String, Int)] = []
        for right in rights {
            if let message = AuthURIIdentityScopeRegistry.current.osVersionWarning(for: right, fleetMajor: newest) {
                let entry = AuthURIIdentityScopeRegistry.current.entry(for: right)
                let bound = entry?.verifiedMacOSMajors?.upperBound ?? newest
                let count = majors.filter { $0 > bound }.count
                warnings.append((right, message, count))
            }
        }
        return warnings
    }

    // MARK: Compile-facing

    /// The wire profiles the whole library compiles to — every policy (which
    /// of them is live on a given Mac is MDM scoping's call, not an authoring
    /// toggle's). Feeds the Decision Simulator and cross-policy conflict
    /// checks.
    public func compiledProfiles() -> [RuleProfile] {
        PolicyCompiler().compileLibrary(policies: policies, rules: rules, definitions: definitions)
    }

    /// The wire profiles ONE policy compiles to (zero, one, or two — sudo
    /// and/or authuri).
    public func compiledProfiles(forPolicy id: String) -> [RuleProfile] {
        guard let policy = policy(id: id) else { return [] }
        return PolicyCompiler().compile(policy, rules: rules, definitions: definitions)
    }

    /// Full validation of a policy's compiled output — one report per
    /// compiled profile (empty when the policy compiles to nothing, i.e. no
    /// enabled assignments resolve to a definition). Drives the Policies
    /// screen's validation badges.
    public func validationReport(forPolicy id: String) -> [ValidationReport] {
        compiledProfiles(forPolicy: id).map { PolicyValidator().validate($0) }
    }

    /// Prepares the export model for one policy: aggregate validation over
    /// ALL of its compiled profiles, plus cross-profile conflicts against the
    /// rest of the compiled library (every other policy).
    public func prepareExport(forPolicy id: String) {
        let profiles = compiledProfiles(forPolicy: id)
        let rest = PolicyCompiler().compileLibrary(
            policies: policies.filter { $0.id != id },
            rules: rules, definitions: definitions
        )
        export.prepare(profiles: profiles, library: rest)
    }

    /// Runs the simulator against the compiled library — exactly the profiles
    /// the fleet would enforce (disabled rule assignments excluded).
    public func runSimulation(currentTime: Date = Date()) {
        simulator.run(profiles: compiledProfiles(), currentTime: currentTime)
    }

    /// Whether a policy is publishable right now: the direct-publish gate
    /// (``directPublishEnabled``) is on, it compiles to at least one profile,
    /// every compiled profile is free of blocking validation errors, and the
    /// MDM connection is complete. Drives enable/disable of the direct
    /// "Publish to MDM" buttons on the policy card and details editor (which
    /// are not shown at all while the gate is off).
    public func canPublishToMDM(id: String) -> Bool {
        publishBlocker(id: id) == nil
    }

    /// Why direct publish is unavailable for a policy right now, in the order
    /// the checks run — nil when it can publish. Drives the disabled Publish
    /// controls' tooltips so a dead button always says why.
    public func publishBlocker(id: String) -> String? {
        guard directPublishEnabled else {
            return "Direct publish is off on this Mac (commanderPublishEnabled is not set by the config profile)."
        }
        // Publishes are serialized: one run (single or batch) at a time, so
        // outcomes never race for the same summary.
        guard publishingPolicyIDs.isEmpty else {
            return publishingPolicyIDs.contains(id)
                ? "This policy is being published right now."
                : "A publish is already in progress — wait for it to finish."
        }
        guard mdm.connection.isComplete else {
            return "Configure a complete \(mdm.vendor.displayName) connection in Settings to publish."
        }
        let profiles = compiledProfiles(forPolicy: id)
        guard !profiles.isEmpty else {
            return "Compiles to no profiles — enable at least one rule with a definition."
        }
        let errors = profiles.reduce(0) { $0 + PolicyValidator().validate($1).errors.count }
        guard errors == 0 else {
            return "Fix \(errors) validation \(errors == 1 ? "error" : "errors") before publishing — see Export."
        }
        return nil
    }

    /// One-click publish of a policy to the configured MDM: compiles the
    /// policy, gates on blocking validation errors and cross-profile conflicts
    /// (mirroring the Export sheet), generates the combined MCX `.mobileconfig`,
    /// and creates/updates the profile under the policy's STABLE id (so a
    /// display-name rename never orphans it). Returns the outcome for the
    /// caller to surface; also reflected in ``MDMSettingsModel/publishState``.
    ///
    /// Conflicts are refused here rather than published silently — the Export
    /// sheet is the place to review and acknowledge them.
    @MainActor
    @discardableResult
    public func publishPolicyToMDM(id: String, organization: String = "Serberus") async -> MDMResult {
        // Defense in depth behind the hidden buttons: the gate is policy, not
        // just chrome.
        guard directPublishEnabled else {
            return .misconfigured(detail: "Direct publish is off on this Mac — the com.herojoneslabs.serberus.config profile does not set commanderPublishEnabled. Deliver this policy with Save Jamf Schema or Save .plist (console-editable) instead.")
        }
        // One publish per policy at a time. This runs on the main actor before
        // the first await, so two callers cannot both pass.
        guard !publishingPolicyIDs.contains(id) else {
            return .misconfigured(detail: "“\(policy(id: id)?.name ?? id)” is already being published — wait for it to finish.")
        }
        publishingPolicyIDs.insert(id)
        defer { publishingPolicyIDs.remove(id) }
        let profiles = compiledProfiles(forPolicy: id)
        guard !profiles.isEmpty else {
            return .misconfigured(detail: "“\(policy(id: id)?.name ?? id)” compiles to no profiles — enable at least one rule with a definition.")
        }
        let errorCount = profiles.reduce(0) { $0 + PolicyValidator().validate($1).errors.count }
        guard errorCount == 0 else {
            return .misconfigured(detail: "Fix \(errorCount) validation error(s) before publishing — see the Export sheet.")
        }
        let others = PolicyCompiler().compileLibrary(
            policies: policies.filter { $0.id != id }, rules: rules, definitions: definitions)
        let conflicts = profiles.flatMap { ConflictDetector().crossProfileConflicts($0, against: others) }
        guard conflicts.isEmpty else {
            return .misconfigured(detail: "\(conflicts.count) cross-profile conflict(s) — review and publish from the Export sheet.")
        }
        do {
            let export = try MobileConfigGenerator().export(profiles: profiles, organization: organization)
            return await mdm.publish(name: "Serberus — \(id)", mobileconfig: export.data)
        } catch {
            return .misconfigured(detail: error.localizedDescription)
        }
    }

    /// Publishes several policies SEQUENTIALLY through ``publishPolicyToMDM``
    /// — the same gated, validated path — and records one ``PublishSummary``
    /// in ``lastPublishSummary`` (also returned). Every direct-publish surface
    /// (card, list batch bar, Edit Policy footer) goes through here so the
    /// in-flight tracking and the reporting live in one place.
    @MainActor
    @discardableResult
    public func publishPolicies(ids: [String], organization: String = "Serberus") async -> PublishSummary {
        var published: [String] = []
        var failed: [String] = []
        var lastHeadline = ""
        for id in ids {
            let name = policy(id: id).map { $0.name.isEmpty ? $0.id : $0.name } ?? id
            let result = await publishPolicyToMDM(id: id, organization: organization)
            lastHeadline = result.headline
            if result.isSuccess { published.append(name) } else { failed.append("\(name): \(result.headline)") }
        }
        let summary: PublishSummary
        if ids.count == 1 {
            // A single publish reads like it always did: the outcome headline.
            summary = PublishSummary(title: failed.isEmpty ? "Published" : "Publish failed",
                                     message: lastHeadline, published: published, failed: failed)
        } else {
            var lines: [String] = []
            if !published.isEmpty {
                lines.append("Published \(published.count) \(published.count == 1 ? "policy" : "policies"): \(published.joined(separator: ", ")).")
            }
            if !failed.isEmpty {
                lines.append("Failed \(failed.count): " + failed.joined(separator: " · "))
            }
            summary = PublishSummary(
                title: failed.isEmpty ? "Published \(published.count) policies"
                                      : (published.isEmpty ? "Publish failed" : "Published with failures"),
                message: lines.joined(separator: "\n"), published: published, failed: failed)
        }
        lastPublishSummary = summary
        return summary
    }

    // MARK: Navigation

    /// Navigates to the Fleet Observer at `route` (tab + filters). The screen
    /// consumes the route on appear / on change, so this works whether or not
    /// it is currently showing.
    public func openFleetObserver(_ route: FleetRoute = .allDevices) {
        pendingFleetRoute = route
        selectedSection = .fleetObserver
    }

    /// Navigates to the Policies screen focused on one policy (open its editor).
    public func openPolicyEditor(policyID: String) {
        pendingFocus = .policy(id: policyID)
        selectedSection = .policies
    }

    /// Navigates to the Rules screen, focused on `ruleID` when given
    /// (`nil` just switches screens, e.g. for a create-new flow).
    public func openRuleEditor(ruleID: String?) {
        pendingFocus = ruleID.map { .rule(id: $0) }
        selectedSection = .rules
    }

    /// Navigates to the Definitions screen, focused on `definitionID` when
    /// given (`nil` just switches screens).
    public func openDefinitionEditor(definitionID: String?) {
        pendingFocus = definitionID.map { .definition(id: $0) }
        selectedSection = .definitions
    }

    // MARK: Shared helpers

    public func jamfConnectionState() -> JamfCredentialStore.ConnectionState {
        credentialStore.connectionState()
    }

    /// The Jamf connection Fleet Observer should use: the connection typed into
    /// Settings when it is complete, otherwise the credentials delivered by the
    /// `com.herojoneslabs.serberus.config` profile (the same ones the Settings
    /// "Endpoint connection (MDM-delivered)" card shows). So on a managed admin
    /// Mac the operator need not re-type the URL/client/secret — the profile
    /// already carries them. Falls back to the (incomplete) entered connection
    /// when neither source is configured, so the callers' "connect Jamf"
    /// guidance still fires.
    public var effectiveJamfConnection: MDMConnection {
        let entered = mdm.connection
        if entered.isComplete { return entered }
        if case let .configured(credentials) = jamfConnectionState() {
            return MDMConnection(vendor: .jamf,
                                 instanceURL: credentials.serverURL.absoluteString,
                                 clientID: credentials.clientID,
                                 clientSecret: credentials.clientSecret)
        }
        return entered
    }

    /// The next free policy priority (max + 10) — every creation path uses
    /// this so new policies never tie with existing ones.
    public func nextPolicyPriority() -> Int { (policies.map(\.profilePriority).max() ?? 40) + 10 }

    /// "New Policy" → "new_policy". Forwards to ``AuthoringID/slugify(_:)``
    /// (kept here because every existing caller reaches it via the model).
    nonisolated public static func slugify(_ name: String) -> String {
        AuthoringID.slugify(name)
    }
}

/// Outcome of one direct-publish run (one or several policies). Kept on the
/// model (``PolicyBuilderModel/lastPublishSummary``) so a run that finishes
/// while the operator is on another screen still gets reported.
public struct PublishSummary: Identifiable, Sendable, Equatable {
    public let id: UUID
    public let title: String
    public let message: String
    /// Display names of the policies that published.
    public let published: [String]
    /// "<name>: <reason>" for each policy that did not.
    public let failed: [String]

    public var isSuccess: Bool { failed.isEmpty }

    public init(id: UUID = UUID(), title: String, message: String, published: [String], failed: [String]) {
        self.id = id
        self.title = title
        self.message = message
        self.published = published
        self.failed = failed
    }
}

/// One capture attempt handed from the Fleet Observer's Review Capture sheet to
/// the Definitions composer (``PolicyBuilderModel/pendingComposerPrefill``). It
/// carries the review-ledger identity (`fileName`/`origin`) and the harvest
/// target so the import commits — ledger recorded, record cleared — only when
/// the pre-filled composer is saved.
public struct PendingComposerPrefill: Identifiable, Equatable, Sendable {
    public let id: UUID
    public let draft: DefinitionDraft
    public let fileName: String
    public let origin: FleetUpload?
    public let harvestFrom: FleetUpload?

    public init(id: UUID = UUID(), draft: DefinitionDraft, fileName: String,
                origin: FleetUpload? = nil, harvestFrom: FleetUpload? = nil) {
        self.id = id
        self.draft = draft
        self.fileName = fileName
        self.origin = origin
        self.harvestFrom = harvestFrom
    }
}

/// A batch import to complete on the Definitions screen (see
/// ``PolicyBuilderModel/pendingImportCompletion``): the definitions are already
/// persisted; Definitions records the review ledger and performs the harvest
/// delete (surfacing any failure where the operator lands), then flashes the
/// newest row.
public struct PendingImportCompletion: Identifiable, Equatable, Sendable {
    public let id: UUID
    public let definitionIDs: [String]
    public let fileName: String
    public let origin: FleetUpload?
    public let harvestFrom: FleetUpload?

    public init(id: UUID = UUID(), definitionIDs: [String], fileName: String,
                origin: FleetUpload? = nil, harvestFrom: FleetUpload? = nil) {
        self.id = id
        self.definitionIDs = definitionIDs
        self.fileName = fileName
        self.origin = origin
        self.harvestFrom = harvestFrom
    }
}

/// One risk heuristic surfaced on the Dashboard — computed from the authored
/// policy library (and, when loaded, the live fleet), never from sample data.
///
/// **The score is a 0–100 severity heuristic, not a measurement**: each
/// ``Kind`` has a base weight plus a per-occurrence step (capped), so a signal
/// that touches more rules / more Macs scores higher, and the Dashboard sorts
/// by it. `level` buckets the score (low < 35 ≤ medium < 65 ≤ high). The
/// per-kind ``Kind/explanation`` spells the formula out for the tooltip.
public struct RiskSignal: Identifiable, Sendable, Equatable, Hashable {
    public enum Level: Sendable, Equatable, Hashable {
        case low, medium, high

        public var label: String {
            switch self {
            case .low: return "Low"
            case .medium: return "Medium"
            case .high: return "High"
            }
        }

        public static func bucket(_ score: Int) -> Level {
            score >= 65 ? .high : (score >= 35 ? .medium : .low)
        }
    }

    /// The heuristics the Dashboard knows. Each can be switched off in
    /// Settings (``PolicyBuilderModel/disabledRiskSignals``); `nominal` is the
    /// "nothing to report" placeholder and is never listed as a switch.
    public enum Kind: String, CaseIterable, Sendable, Codable, Hashable, Identifiable {
        case silent, unpinned, longGrants = "long_grants", broad, noDeny = "no_deny", offline,
             unverifiedOS = "unverified_os", nominal

        public var id: String { rawValue }

        /// The kinds an operator can toggle (everything but the placeholder).
        public static let configurable: [Kind] = allCases.filter { $0 != .nominal }

        /// Whether the signal reads the live fleet (vs the policy library).
        public var isFleetDerived: Bool { self == .offline || self == .unverifiedOS }

        public var title: String {
            switch self {
            case .silent: return "Silent elevations"
            case .unpinned: return "Unpinned allow rules"
            case .longGrants: return "Long-lived grants"
            case .broad: return "Broad command patterns"
            case .noDeny: return "No deny carve-outs"
            case .offline: return "Offline Serberus Macs"
            case .unverifiedOS: return "App identity rights unverified on fleet macOS"
            case .nominal: return "Posture nominal"
            }
        }

        /// What the signal looks for and how its 0–100 score is built —
        /// the Dashboard tooltip and the Settings row description.
        public var explanation: String {
            switch self {
            case .silent:
                return "Compiled allow rules that elevate without any prompt. Score = 30 + 8 per silent rule, capped at 95."
            case .unpinned:
                return "Compiled allow rules with neither a Team ID nor a binary-hash pin — any binary at that path is trusted. Score = 25 + 7 per unpinned rule, capped at 92."
            case .longGrants:
                return "Rules whose maximum grant duration exceeds one hour. Score = 30 + 10 per rule, capped at 70."
            case .broad:
                return "Rules matching any command, or a command pattern containing a wildcard. Score = 40 + 9 per rule, capped at 88."
            case .noDeny:
                return "The library compiles rules but not a single explicit deny — nothing carves out what must never elevate. Score = 52 (fixed)."
            case .offline:
                return "Serberus Macs whose last Jamf contact is older than the offline threshold (Settings → Dashboard & fleet posture) — Commander cannot know their enforcement state. Score = 40 + 4 per Mac, capped at 90. Shown only once the fleet has loaded; never invented."
            case .unverifiedOS:
                return "Fleet Macs run a macOS MAJOR newer than any version an authored app-identity right was verified on. Apple can rewire how a right resolves its caller across majors, so the composed branches may silently stop matching. Score = 60 + 5 per unverified Mac, capped at 95. Shown only once the fleet has loaded; never invented."
            case .nominal:
                return "No elevated risk signals from the current policies."
            }
        }
    }

    public let id: String
    public let kind: Kind
    public let title: String
    public let detail: String
    /// 0–100 severity heuristic (see the type doc).
    public let score: Int
    public let level: Level
    /// How this score was built — ``Kind/explanation``.
    public var explanation: String { kind.explanation }

    public init(kind: Kind, detail: String, score: Int) {
        self.id = kind.rawValue
        self.kind = kind
        self.title = kind.title
        self.detail = detail
        self.score = score
        // The level is ALWAYS the score's bucket, so the badge can never
        // contradict the Low/Medium/High legend shown on the Dashboard.
        self.level = Level.bucket(score)
    }

    /// Legacy shape (id/title given explicitly) — kept for call sites that
    /// built signals by hand; `kind` is inferred from `id` when it matches.
    public init(id: String, title: String, detail: String, score: Int, level: Level) {
        self.id = id
        self.kind = Kind(rawValue: id) ?? .nominal
        self.title = title
        self.detail = detail
        self.score = score
        self.level = level
    }
}

public extension PolicyBuilderModel {
    /// Risk heuristics for the Dashboard, wire-level (they inspect the compiled
    /// rules exactly as the daemon would). Computed over EVERY policy's enabled
    /// assignments — a toggled-off policy's rules are still authored risk. The
    /// one fleet-derived signal (offline devices) is included only when the
    /// fleet has actually been loaded, so nothing here is invented. Signals the
    /// operator switched off (``disabledRiskSignals``) are skipped; the
    /// offline window is ``FleetObserverModel/thresholds``.
    func riskSignals(now: Date = Date()) -> [RiskSignal] {
        let compiler = PolicyCompiler()
        let wireRules = policies
            .flatMap { compiler.compile($0, rules: rules, definitions: definitions) }
            .flatMap(\.rules)
        var signals: [RiskSignal] = []
        let enabled: (RiskSignal.Kind) -> Bool = { !self.disabledRiskSignals.contains($0) }

        let silent = wireRules.filter { $0.action == .allow && $0.elevation.type == .silent }.count
        if enabled(.silent), silent > 0 {
            let score = min(95, 30 + silent * 8)
            signals.append(.init(kind: .silent,
                                 detail: "\(silent) allow rule\(silent == 1 ? "" : "s") grant without a prompt",
                                 score: score))
        }
        // Identity-scoped rules are pinned by their compiled code requirement.
        let unpinned = wireRules.filter { $0.action == .allow && $0.appIdentity == nil && $0.match.requiredTeamID == nil && $0.match.requiredBinaryHash == nil }.count
        if enabled(.unpinned), unpinned > 0 {
            let score = min(92, 25 + unpinned * 7)
            signals.append(.init(kind: .unpinned,
                                 detail: "\(unpinned) allow rule\(unpinned == 1 ? "" : "s") lack a Team ID / hash pin",
                                 score: score))
        }
        let longGrants = wireRules.filter { $0.conditions.maxGrantDurationSeconds > 3600 }.count
        if enabled(.longGrants), longGrants > 0 {
            signals.append(.init(kind: .longGrants,
                                 detail: "\(longGrants) rule\(longGrants == 1 ? "" : "s") grant for over 1 hour",
                                 score: min(70, 30 + longGrants * 10)))
        }
        let broad = wireRules.filter { ($0.match.matchType == .any) || ($0.match.commandPattern?.contains("*") ?? false) }.count
        if enabled(.broad), broad > 0 {
            signals.append(.init(kind: .broad,
                                 detail: "\(broad) rule\(broad == 1 ? "" : "s") use wildcard / any matching",
                                 score: min(88, 40 + broad * 9)))
        }
        let denies = wireRules.filter { $0.action == .deny }.count
        if enabled(.noDeny), denies == 0, !wireRules.isEmpty {
            signals.append(.init(kind: .noDeny,
                                 detail: "No policy defines an explicit deny exception",
                                 score: 52))
        }
        // Fleet-derived — only when the fleet has been loaded (never invented).
        if enabled(.offline), case .loaded = fleet.state {
            let offline = fleet.serberusDevices.filter { fleet.freshness(of: $0, now: now) == .offline }.count
            if offline > 0 {
                let days = fleet.thresholds.offlineAfterDays
                let score = min(90, 40 + offline * 4)
                signals.append(.init(kind: .offline,
                                     detail: "\(offline) Serberus Mac\(offline == 1 ? "" : "s") \(offline == 1 ? "hasn't" : "haven't") checked into Jamf in over \(days == 7 ? "a week" : "\(days) days")",
                                     score: score))
            }
        }
        if enabled(.unverifiedOS) {
            let warnings = unverifiedOSWarnings()
            if !warnings.isEmpty {
                let macs = warnings.map(\.devices).max() ?? 0
                let rights = warnings.map(\.right).joined(separator: ", ")
                signals.append(.init(kind: .unverifiedOS,
                                     detail: "\(macs) fleet Mac\(macs == 1 ? "" : "s") run a macOS newer than \(rights) \(warnings.count == 1 ? "was" : "were") verified on — re-verify before trusting the per-app branches",
                                     score: min(95, 60 + macs * 5)))
            }
        }
        if signals.isEmpty {
            signals.append(.init(kind: .nominal,
                                 detail: wireRules.isEmpty ? "No rules compiled yet — author policies to enforce elevation."
                                                           : "No elevated risk signals from the current policies.",
                                 score: wireRules.isEmpty ? 0 : 12))
        }
        return signals.sorted { $0.score > $1.score }
    }
}
