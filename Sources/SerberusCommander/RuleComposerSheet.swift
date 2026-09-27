import PolicyBuilderCore
import PrivMgrCore
import SwiftUI

// MARK: - Intent

/// How the Rule composer was opened. Drives `.sheet(item:)`. Rules live in
/// exactly one place now — the shared library — so the old destination/home
/// plumbing is gone: policies reference rules by id, assignment happens on
/// the Policies screen (or the Rules screen's "Add to Policy" menu).
enum RuleComposerIntent: Identifiable, Equatable {
    /// New library rule.
    case create
    /// Edit an existing library rule; the change propagates to every policy
    /// that assigned it.
    case edit(ruleID: String)

    var id: String {
        switch self {
        case .create: return "create"
        case .edit(let ruleID): return "edit::\(ruleID)"
        }
    }
}

// MARK: - Readback

/// Composes the live plain-English summary shown above the composer footer,
/// so the author reads back what the rule actually does before saving.
/// Multi-definition aware: a rule now bundles N matchers under one decision,
/// so the sentence names one or two definitions and counts the rest.
enum RuleReadback {
    /// - Parameters:
    ///   - definitions: the draft's RESOLVED definitions (dangling ids dropped).
    ///   - policyCount: how many policies currently assign the rule (0 for
    ///     new rules — they start unassigned and unenforced).
    static func sentence(for draft: RuleDraft, definitions: [RuleDefinition], policyCount: Int) -> String {
        guard !definitions.isEmpty else {
            return "This rule has no definitions yet — it matches nothing and compiles to nothing until one is added."
        }
        let covered = policyCount > 0
            ? "anyone covered by its \(policyCount == 1 ? "policy" : "\(policyCount) policies")"
            : "anyone it covers"
        var sentence: String
        switch draft.action {
        case .deny:
            sentence = "Blocks \(targetPhrase(definitions)) for \(covered)."
        case .allow:
            let base = "allows \(covered) to use \(targetPhrase(definitions))"
            sentence = draft.elevationType == .silent
                ? "\(base) silently — no prompt."
                : "\(base) after approving a prompt."
            sentence = sentence.prefix(1).uppercased() + sentence.dropFirst()
            if draft.maxGrantDurationSeconds > 0 {
                sentence += " Admin rights last \(DurationFormat.humanize(draft.maxGrantDurationSeconds, zero: ""))."
            } else if draft.maxGrantDurationSeconds < 0 {
                sentence += " Every use is checked again."
            }
        }
        if policyCount == 0 {
            sentence += " Not assigned to any policy yet, so it isn't enforced."
        }
        return sentence
    }

    /// "“Homebrew CLI”", "“A” and “B”", or "all 5 of its definitions".
    private static func targetPhrase(_ definitions: [RuleDefinition]) -> String {
        switch definitions.count {
        case 1: return "“\(definitions[0].name)”"
        case 2: return "“\(definitions[0].name)” and “\(definitions[1].name)”"
        default: return "all \(definitions.count) of its definitions"
        }
    }
}

// MARK: - Composer sheet

/// The single authoring surface for library rules (tier 2): one modal sheet
/// covering create and edit. A rule is a decision bundle — Allow/Deny,
/// Silent/Prompt, and the advanced settings — over a multi-select of
/// definitions (tier 3, the matchers). Matcher fields are NOT edited here:
/// definitions have their own screen, and this sheet only picks from the
/// definition library. Nothing touches the model until Save, so Cancel is a
/// true discard.
struct RuleComposerSheet: View {
    @Bindable var model: PolicyBuilderModel
    let intent: RuleComposerIntent
    /// Called after a successful save with the rule's id, so the hosting
    /// screen can select/flash the row.
    var onSaved: ((String) -> Void)? = nil
    let dismiss: () -> Void

    /// Where a "create/edit in Definitions" jump should land after the
    /// composer confirms discarding its unsaved changes.
    private enum DefinitionsLink: Equatable {
        case create
        case edit(String)
    }

    @State private var draft = RuleDraft()
    /// Baseline for the dirty check (the loaded rule in edit mode, the
    /// defaults in create mode).
    @State private var baseline = RuleDraft()
    @State private var loaded = false
    @State private var showingPicker = false
    @State private var confirmDiscard = false
    @State private var confirmSilentBroad = false
    @State private var confirmDelete = false
    /// Pending jump to the Definitions screen, held while the discard
    /// confirmation is up (jumping abandons the composer).
    @State private var pendingDefinitionsLink: DefinitionsLink?
    @State private var confirmLeaveForDefinitions = false

    private var isEdit: Bool {
        if case .edit = intent { return true }
        return false
    }

    private var originalRuleID: String? {
        if case .edit(let ruleID) = intent { return ruleID }
        return nil
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(Theme.hairline)
            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.lg) {
                    nameCard
                    definitionsCard
                    whenMatchedCard
                    advancedCard
                }
                .padding(Spacing.xl)
            }
            .scrollIndicators(.never)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            Divider().overlay(Theme.hairline)
            readbackLine
            footer
        }
        .frame(width: 720, height: 680)
        .background(Theme.background)
        .preferredColorScheme(.dark)
        .tint(Theme.emerald)
        .onAppear(perform: loadOnce)
        .interactiveDismissDisabled(isDirty)
        .sheet(isPresented: $showingPicker) {
            DefinitionPickerSheet(model: model, selectedIDs: $draft.definitionIDs) {
                showingPicker = false
            }
        }
        .confirmationDialog("Discard changes to “\(displayName)”?",
                            isPresented: $confirmDiscard, titleVisibility: .visible) {
            Button("Discard Changes", role: .destructive) { dismiss() }
            Button("Keep Editing", role: .cancel) {}
        }
        .confirmationDialog("Discard changes and open Definitions?",
                            isPresented: $confirmLeaveForDefinitions, titleVisibility: .visible) {
            Button("Discard & Open Definitions", role: .destructive) {
                if let link = pendingDefinitionsLink { navigateToDefinitions(link) }
            }
            Button("Keep Editing", role: .cancel) { pendingDefinitionsLink = nil }
        } message: {
            Text("The composer closes and unsaved changes to this rule are lost. Definitions are authored in their own screen.")
        }
        .confirmationDialog("Silently allow a pattern?",
                            isPresented: $confirmSilentBroad, titleVisibility: .visible) {
            Button("Save Anyway", role: .destructive) { save() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This rule grants admin rights with no prompt, and at least one of its sudo definitions matches a non-exact pattern. Anyone a covering policy applies to can run any matching command silently.")
        }
        .alert("Delete “\(displayName)”?", isPresented: $confirmDelete) {
            Button("Cancel", role: .cancel) {}
            Button("Delete", role: .destructive) { deleteEditedRule() }
        } message: {
            Text(deleteMessage)
        }
    }

    // MARK: Setup

    private func loadOnce() {
        guard !loaded else { return }
        loaded = true
        switch intent {
        case .create:
            // New rules land after everything existing when priorities tie-break,
            // so adding a rule never silently jumps the evaluation queue.
            draft.priority = (model.rules.map(\.priority).max() ?? 40) + 10
            baseline = draft
        case .edit(let ruleID):
            // A rule deleted while the intent was in flight still opens under
            // its id — saving recreates it rather than silently minting a new one.
            draft = model.rule(id: ruleID).map(RuleDraft.init(rule:)) ?? RuleDraft(ruleID: ruleID)
            baseline = draft
        }
    }

    /// Best display string for dialogs: the name, falling back to the id.
    private var displayName: String {
        let name = draft.name.trimmingCharacters(in: .whitespaces)
        if !name.isEmpty { return name }
        return draft.ruleID.isEmpty ? "this rule" : draft.ruleID
    }

    /// The draft's definitions that still resolve in the library — the ones
    /// that would actually compile.
    private var resolvedDefinitions: [RuleDefinition] {
        draft.definitionIDs.compactMap { model.definition(id: $0) }
    }

    /// Policies currently assigning this rule (edit mode only — new rules
    /// always start unassigned).
    private var assignedPolicyCount: Int {
        guard let originalRuleID else { return 0 }
        return model.policiesUsing(ruleID: originalRuleID).count
    }

    // MARK: Header

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 1) {
                Text(isEdit ? "Edit Rule" : "New Rule")
                    .font(.system(size: 17, weight: .bold)).foregroundStyle(Theme.textPrimary)
                Text(subtitle).font(.system(size: 12)).foregroundStyle(Theme.textMuted)
            }
            Spacer()
        }
        .padding(Spacing.lg)
    }

    private var subtitle: String {
        if isEdit {
            let count = assignedPolicyCount
            let usage = count == 0 ? "not in any policy"
                : "in \(count) \(count == 1 ? "policy" : "policies")"
            return "\(originalRuleID ?? "") · \(usage)"
        }
        let name = draft.name.trimmingCharacters(in: .whitespaces)
        return name.isEmpty ? "A rule bundles definitions with one decision" : name
    }

    // MARK: Name & purpose

    private var nameCard: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            RuleFormStyle.eyebrow("Name & purpose", "number")
            VStack(alignment: .leading, spacing: 5) {
                LabeledField(label: "Rule name") {
                    TextField("Allow developer package managers", text: $draft.name)
                }
                RuleFormStyle.caption("A display name — shown in the Rules screen and in policies' rule lists.")
            }
            LabeledField(label: "What does this rule do?") {
                TextField("Lets developers run package managers without a password prompt", text: $draft.detail)
            }
            identifierRow
            VStack(alignment: .leading, spacing: 5) {
                RuleFormStyle.labeled("Action") {
                    SegmentedControl(selection: $draft.action, options: [.allow: "Allow", .deny: "Deny"], label: "Action")
                }
                RuleFormStyle.caption("Deny rules always win over Allow rules when both match.")
            }
        }
        .card()
    }

    /// The stable slug: read-only after create (policies and compiled wire
    /// rules embed it), previewed live before.
    @ViewBuilder
    private var identifierRow: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: Spacing.sm) {
                Text("Identifier").font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textMuted)
                Text(isEdit ? draft.ruleID : derivedRuleID)
                    .font(.mono(11)).foregroundStyle(Theme.textSecondary)
            }
            RuleFormStyle.caption(isEdit
                ? "Fixed at creation — policies and compiled wire rules reference it, so renaming the rule never rewrites it."
                : "Derived from the name when the rule is created, then never changes.")
        }
    }

    /// Live preview of the id ``save()`` would mint (same slug + uniquify).
    private var derivedRuleID: String {
        let base = AuthoringID.slugify(draft.name)
        return AuthoringID.uniqueID(base: base.isEmpty ? "rule" : base,
                                    existing: Set(model.rules.map(\.id)))
    }

    // MARK: Definitions

    private var definitionsCard: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            HStack {
                RuleFormStyle.eyebrow("Definitions", "books.vertical")
                Spacer()
                if !draft.definitionIDs.isEmpty {
                    Button { showingPicker = true } label: {
                        Label("Add Definition…", systemImage: "plus.circle").font(.system(size: 11))
                    }
                    .buttonStyle(.plain).foregroundStyle(Theme.emerald)
                }
            }
            RuleFormStyle.caption("Definitions are the matchers this rule decides on — every definition below gets this rule's action and settings.")
            if draft.definitionIDs.isEmpty {
                emptyDefinitionsState
            } else {
                VStack(spacing: 6) {
                    ForEach(draft.definitionIDs, id: \.self) { id in
                        definitionRow(id)
                    }
                }
            }
            newDefinitionHint
        }
        .card()
    }

    private func definitionRow(_ id: String) -> some View {
        let definition = model.definition(id: id)
        let glyph = definitionGlyph(for: definition?.authoringKind)
        let index = draft.definitionIDs.firstIndex(of: id)

        return HStack(spacing: Spacing.md) {
            Image(systemName: glyph.symbol)
                .font(.system(size: 12))
                .foregroundStyle(glyph.tint)
                .frame(width: 28, height: 28)
                .background(glyph.tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 7, style: .continuous))
            VStack(alignment: .leading, spacing: 1) {
                Text(definition?.name ?? "Missing definition")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(definition == nil ? Theme.warning : Theme.textPrimary)
                    .lineLimit(1)
                Text(definition.map(definitionTarget) ?? id)
                    .font(.mono(10)).foregroundStyle(Theme.textMuted).lineLimit(1)
            }
            Spacer()
            if definition == nil {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 10)).foregroundStyle(Theme.warning)
                    .help("This definition was deleted — remove the reference, or recreate it in Definitions.")
            }
            Button { removeDefinition(id) } label: {
                Image(systemName: "xmark.circle.fill").font(.system(size: 13))
            }
            .buttonStyle(.plain).foregroundStyle(Theme.textMuted)
            .help("Remove from this rule")
        }
        .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
        .background(Theme.elevated.opacity(0.5), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous)
            .strokeBorder(Theme.hairline, lineWidth: 1))
        .contextMenu {
            Button("Move Up") { moveDefinition(id, by: -1) }
                .disabled(index == draft.definitionIDs.startIndex)
            Button("Move Down") { moveDefinition(id, by: 1) }
                .disabled(index == draft.definitionIDs.index(before: draft.definitionIDs.endIndex))
            Divider()
            if definition != nil {
                Button("Edit in Definitions…") { openDefinitions(.edit(id)) }
            }
            Button("Remove from Rule", role: .destructive) { removeDefinition(id) }
        }
    }

    private var emptyDefinitionsState: some View {
        VStack(spacing: Spacing.sm) {
            Image(systemName: "square.dashed").font(.system(size: 24)).foregroundStyle(Theme.textMuted)
            Text("No definitions yet")
                .font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            Text("This rule matches nothing — and compiles to nothing — until you add at least one definition.")
                .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
                .multilineTextAlignment(.center)
            Button { showingPicker = true } label: { Label("Add Definition…", systemImage: "plus") }
                .buttonStyle(.ghost).padding(.top, Spacing.xs)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, Spacing.lg)
        .background(Theme.elevated.opacity(0.4), in: RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.md, style: .continuous)
            .strokeBorder(Theme.hairline, style: StrokeStyle(lineWidth: 1, dash: [4])))
    }

    /// New matchers are authored in the Definitions screen, not inline — the
    /// hint jumps there (after confirming the discard, since the composer
    /// can't survive the navigation).
    private var newDefinitionHint: some View {
        HStack(spacing: Spacing.xs) {
            Text("Need a matcher that doesn't exist yet?")
                .font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
            Button("Create it in Definitions") { openDefinitions(.create) }
                .buttonStyle(.plain)
                .font(.system(size: 10.5, weight: .medium)).foregroundStyle(Theme.emerald)
        }
    }

    private func removeDefinition(_ id: String) {
        draft.definitionIDs.removeAll { $0 == id }
    }

    private func moveDefinition(_ id: String, by offset: Int) {
        guard let index = draft.definitionIDs.firstIndex(of: id) else { return }
        let target = index + offset
        guard draft.definitionIDs.indices.contains(target) else { return }
        draft.definitionIDs.swapAt(index, target)
    }

    /// Jumping to Definitions abandons the composer — never silently: when
    /// dirty, an explicit discard confirmation runs first (discard is safer
    /// than auto-saving a half-edited rule the user never reviewed).
    private func openDefinitions(_ link: DefinitionsLink) {
        if isDirty {
            pendingDefinitionsLink = link
            confirmLeaveForDefinitions = true
        } else {
            navigateToDefinitions(link)
        }
    }

    private func navigateToDefinitions(_ link: DefinitionsLink) {
        pendingDefinitionsLink = nil
        dismiss()
        switch link {
        case .create: model.openDefinitionEditor(definitionID: nil)
        case .edit(let id): model.openDefinitionEditor(definitionID: id)
        }
    }

    // MARK: When matched + Advanced

    private var whenMatchedCard: some View {
        RuleWhenMatchedGroup(draft: $draft, definitionKinds: selectedDefinitionKinds).card()
    }

    /// The kinds of the definitions currently picked for this rule.
    private var selectedDefinitionKinds: Set<RuleType> {
        let picked = Set(draft.definitionIDs)
        return Set(model.definitions.filter { picked.contains($0.id) }.map(\.kind))
    }

    private var advancedCard: some View {
        RuleAdvancedSettingsGroup(draft: $draft).card()
    }

    // MARK: Validation

    /// Issues from compiling a scratch policy containing just this draft —
    /// exactly what the validator will say about the rule's wire output.
    /// Definition-level fixes belong in the Definitions screen; the composer
    /// only surfaces the aggregate so a broken save is never a surprise.
    private var scratchIssues: [ValidationIssue] {
        var rule = draft.toPolicyRule()
        if rule.id.isEmpty { rule.id = "draft_rule" }
        let scratch = Policy(id: "draft_preview", name: "Preview",
                             rules: [PolicyRuleAssignment(ruleID: rule.id)])
        return PolicyCompiler().compile(scratch, rules: [rule], definitions: model.definitions)
            .flatMap { PolicyValidator().validate($0).issues }
    }

    // MARK: Readback + footer

    private var readbackLine: some View {
        Text(RuleReadback.sentence(for: draft,
                                   definitions: resolvedDefinitions,
                                   policyCount: assignedPolicyCount))
            .font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Spacing.lg)
            .padding(.top, Spacing.md)
    }

    private var footer: some View {
        let issues = scratchIssues
        let errors = issues.filter { $0.severity == .error }
        let warnings = issues.filter { $0.severity == .warning }
        return VStack(alignment: .leading, spacing: Spacing.sm) {
            HStack(spacing: Spacing.sm) {
                if isEdit {
                    Button { confirmDelete = true } label: { Label("Delete Rule…", systemImage: "trash") }
                        .buttonStyle(.ghost).foregroundStyle(Theme.critical)
                }
                Button("Cancel") { cancel() }.buttonStyle(.ghost)
                    .keyboardShortcut(.cancelAction)
                Spacer()
                if resolvedDefinitions.isEmpty {
                    StatusBadge("No definitions", tone: .pending, symbol: "questionmark.circle")
                        .help("The rule compiles to nothing until a definition is added.")
                } else if errors.isEmpty && warnings.isEmpty {
                    StatusBadge("Valid", tone: .healthy, symbol: "checkmark.seal.fill")
                } else {
                    if !errors.isEmpty {
                        StatusBadge("\(errors.count) \(errors.count == 1 ? "error" : "errors")",
                                    tone: .degraded, symbol: "xmark.octagon.fill")
                            .help(errors.map(\.message).joined(separator: "\n"))
                    }
                    if !warnings.isEmpty {
                        StatusBadge("\(warnings.count)", tone: .pending, symbol: "exclamationmark.triangle.fill")
                            .help(warnings.map(\.message).joined(separator: "\n"))
                    }
                }
                Button { attemptSave() } label: {
                    Label(isEdit ? "Save Changes" : "Create Rule", systemImage: "checkmark")
                }
                .buttonStyle(.emerald)
                .keyboardShortcut(.defaultAction)
                .disabled(!canSave)
            }
            if !errors.isEmpty || !warnings.isEmpty {
                Text("You can save with warnings or errors — they only block exporting to MDM.")
                    .font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
            }
        }
        .padding(Spacing.lg)
    }

    // MARK: Actions

    private var isDirty: Bool { draft != baseline }

    /// Save-with-errors is the philosophy; the one hard gate is a usable
    /// name (the id is minted from it, and a nameless rule is unfindable in
    /// every list). Duplicate ids can't happen: create mode uniquifies, edit
    /// mode never changes the id.
    private var canSave: Bool {
        !draft.name.trimmingCharacters(in: .whitespaces).isEmpty
    }

    private func cancel() {
        if isDirty { confirmDiscard = true } else { dismiss() }
    }

    /// A broad silent allow is the one-click footgun — confirm before
    /// committing whenever any selected sudo definition matches a non-exact
    /// pattern (nil matchType means exact on the wire, so it doesn't trip this).
    private var needsHardConfirm: Bool {
        draft.action == .allow && draft.elevationType == .silent
            && resolvedDefinitions.contains { $0.kind == .sudo && ($0.matchType ?? .exact) != .exact }
    }

    private func attemptSave() {
        if needsHardConfirm { confirmSilentBroad = true } else { save() }
    }

    private func save() {
        // Commit the trimmed name so lists never render padded strings, and
        // mint the id before the upsert (new drafts carry an empty ruleID).
        draft.name = draft.name.trimmingCharacters(in: .whitespaces)
        if draft.ruleID.isEmpty {
            draft.ruleID = derivedRuleID
        }
        model.upsertRule(draft.toPolicyRule())
        onSaved?(draft.ruleID)
        dismiss()
    }

    private var deleteMessage: String {
        let count = assignedPolicyCount
        if count == 0 {
            return "This removes the rule from the library. It isn't assigned to any policy, so enforcement is unchanged."
        }
        return "This removes the rule from the library and withdraws it from \(count) \(count == 1 ? "policy" : "policies"). Devices keep enforcing the old versions until those policies are re-exported and republished."
    }

    private func deleteEditedRule() {
        if let originalRuleID {
            model.deleteRule(id: originalRuleID)
        }
        dismiss()
    }
}

// MARK: - Definition picker

/// Modal multi-select over the definition library: search + kind filter, tap
/// a row to add or remove it. Mutates the composer's draft ids directly, so
/// the selection is live behind the sheet and "Done" is just a close.
private struct DefinitionPickerSheet: View {
    @Bindable var model: PolicyBuilderModel
    @Binding var selectedIDs: [String]
    let dismiss: () -> Void

    @State private var query = ""
    @State private var kindFilter: KindFilter = .all

    private enum KindFilter: String, CaseIterable, Identifiable {
        case all = "All kinds", sudo = "Sudo", authuri = "Auth right", appIdentity = "App identity"
        var id: String { rawValue }
    }

    private var visibleDefinitions: [RuleDefinition] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        return model.definitions
            .filter { matchesKind($0.authoringKind) }
            .filter {
                q.isEmpty
                    || $0.name.lowercased().contains(q)
                    || $0.id.lowercased().contains(q)
                    || ($0.authURI ?? "").lowercased().contains(q)
                    || ($0.commandPattern ?? "").lowercased().contains(q)
            }
            .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    private func matchesKind(_ kind: DefinitionKind) -> Bool {
        switch kindFilter {
        case .all: return true
        case .sudo: return kind == .sudo
        case .authuri: return kind == .authuri
        case .appIdentity: return kind == .appIdentity
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(Theme.hairline)
            VStack(alignment: .leading, spacing: Spacing.md) {
                filterBar
                if model.definitions.isEmpty {
                    emptyLibraryState
                } else if visibleDefinitions.isEmpty {
                    noMatchState
                } else {
                    ScrollView {
                        LazyVStack(spacing: 6) {
                            ForEach(visibleDefinitions) { definition in
                                row(definition)
                            }
                        }
                        .padding(.bottom, Spacing.md)
                    }
                    .scrollIndicators(.never)
                }
            }
            .padding(Spacing.lg)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            Divider().overlay(Theme.hairline)
            footer
        }
        .frame(width: 560, height: 540)
        .background(Theme.background)
        .preferredColorScheme(.dark)
        .tint(Theme.emerald)
        .onExitCommand { dismiss() }
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 1) {
                Text("Add Definitions")
                    .font(.system(size: 15, weight: .bold)).foregroundStyle(Theme.textPrimary)
                Text("Pick the matchers this rule decides on")
                    .font(.system(size: 12)).foregroundStyle(Theme.textMuted)
            }
            Spacer()
        }
        .padding(Spacing.lg)
    }

    private var filterBar: some View {
        HStack(spacing: Spacing.md) {
            HStack(spacing: Spacing.sm) {
                Image(systemName: "magnifyingglass").font(.system(size: 12)).foregroundStyle(Theme.textMuted)
                TextField("Search definitions…", text: $query)
                    .textFieldStyle(.plain).font(.system(size: 13)).foregroundStyle(Theme.textPrimary)
                if !query.isEmpty {
                    Button { query = "" } label: { Image(systemName: "xmark.circle.fill") }
                        .buttonStyle(.plain).foregroundStyle(Theme.textMuted)
                }
            }
            .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
            .background(Theme.elevated.opacity(0.7), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))

            Picker("", selection: $kindFilter) {
                ForEach(KindFilter.allCases) { Text($0.rawValue).tag($0) }
            }.labelsHidden().fixedSize()
        }
    }

    private func row(_ definition: RuleDefinition) -> some View {
        let isSelected = selectedIDs.contains(definition.id)
        let glyph = definitionGlyph(for: definition.authoringKind)

        return Button {
            if isSelected {
                selectedIDs.removeAll { $0 == definition.id }
            } else {
                selectedIDs.append(definition.id)
            }
        } label: {
            HStack(spacing: Spacing.md) {
                Image(systemName: glyph.symbol)
                    .font(.system(size: 12))
                    .foregroundStyle(glyph.tint)
                    .frame(width: 28, height: 28)
                    .background(glyph.tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                VStack(alignment: .leading, spacing: 1) {
                    Text(definition.name.isEmpty ? definition.id : definition.name)
                        .font(.system(size: 12.5, weight: .semibold)).foregroundStyle(Theme.textPrimary)
                        .lineLimit(1)
                    Text(definitionTarget(definition))
                        .font(.mono(10)).foregroundStyle(Theme.textMuted).lineLimit(1)
                }
                Spacer()
                Image(systemName: isSelected ? "checkmark.circle.fill" : "plus.circle")
                    .font(.system(size: 15))
                    .foregroundStyle(isSelected ? Theme.emerald : Theme.textMuted)
            }
            .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(isSelected ? Theme.accentDim : Theme.surface,
                        in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous)
                .strokeBorder(isSelected ? Theme.emerald.opacity(0.35) : Theme.hairline, lineWidth: 1))
        }
        .buttonStyle(.plain)
    }

    private var emptyLibraryState: some View {
        VStack(spacing: Spacing.md) {
            Image(systemName: "books.vertical").font(.system(size: 32)).foregroundStyle(Theme.textMuted)
            Text("No definitions yet").font(.system(size: 14, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            Text("Definitions are authored in the Definitions screen — create the matchers there first, then pick them here.")
                .font(.system(size: 12)).foregroundStyle(Theme.textMuted)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .card()
    }

    private var noMatchState: some View {
        VStack(spacing: Spacing.md) {
            Image(systemName: "line.3.horizontal.decrease.circle").font(.system(size: 32)).foregroundStyle(Theme.textMuted)
            Text("No definitions match").font(.system(size: 14, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            Text("Adjust the search or kind filter above.").font(.system(size: 12)).foregroundStyle(Theme.textMuted)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .card()
    }

    private var footer: some View {
        HStack {
            Text("\(selectedIDs.count) selected")
                .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
            Spacer()
            // Picks commit live, so Done is the one exit (Return; Esc via
            // onExitCommand on the sheet root).
            Button("Done") { dismiss() }
                .buttonStyle(.emerald)
                .keyboardShortcut(.defaultAction)
        }
        .padding(Spacing.lg)
    }
}

// MARK: - Definition presentation helpers

/// Icon + tint for a definition kind. `nil` means a dangling reference (the
/// definition was deleted while a rule still pointed at it) — rendered as a
/// warning, never hidden.
private func definitionGlyph(for kind: DefinitionKind?) -> (symbol: String, tint: Color) {
    switch kind {
    case .authuri: return ("lock.fill", Theme.info)
    case .appIdentity: return ("app.badge.checkmark", Theme.info)
    case .sudo: return ("terminal.fill", Theme.emerald)
    case nil: return ("questionmark.circle", Theme.warning)
    }
}

/// One-line mono target for a definition row ("system.preferences.network",
/// "/opt/homebrew/bin/brew", "any command").
private func definitionTarget(_ definition: RuleDefinition) -> String {
    switch definition.kind {
    case .authuri:
        if definition.isAppIdentity {
            return "\(definition.appBundleID?.isEmpty == false ? definition.appBundleID! : "(no bundle ID)") → \(definition.authURI ?? "(no right set)")"
        }
        return definition.authURI ?? "(no right set)"
    case .sudo:
        if (definition.matchType ?? .exact) == .any { return "any command" }
        return definition.commandPattern ?? "(no command set)"
    }
}
