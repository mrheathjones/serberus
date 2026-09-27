import PolicyBuilderCore
import PrivMgrCore
import SwiftUI

/// Edit an existing policy after creation: identity (name + stable
/// identifier), versioning, and the rule-assignment manager with per-policy
/// enable toggles. (No scope/conditions and no on/off switch: a policy is
/// delivered and scoped by MDM.)
///
/// Two commit models coexist deliberately. Detail fields (identity,
/// versioning) are staged and land on Save via
/// ``PolicyBuilderModel/updatePolicy(_:)`` — they are text a user may want to
/// abandon. Rule assignment changes (add / remove / per-rule toggles) go
/// through the model immediately — they are references into the shared rule
/// library, and the Policies grid should reflect them live.
struct PolicyDetailsEditorView: View {
    @Bindable var model: PolicyBuilderModel
    /// The policy's CURRENT id. Assignment mutations keep targeting this id
    /// even while the identifier field holds an unsaved rename.
    let policyID: String
    /// When true the editor opens scrolled to the rules section — the
    /// Policies grid's "Manage Rules" path into this one editing surface.
    var focusRules = false
    var onClose: () -> Void

    @State private var name = ""
    @State private var idText = ""
    @State private var summary = ""
    @State private var version = "1.0.0"
    @State private var priority = 50
    @State private var loaded = false
    @State private var baseline: Snapshot?
    @State private var confirmDiscard = false
    @State private var showingAddRules = false
    @State private var publishMessage: String?
    @State private var publishSuccess = false
    /// "Open Rules Screen" from the add-rules picker abandons this editor —
    /// confirmed first when there are unsaved edits, never silently.
    @State private var confirmLeaveForRules = false

    /// In flight for THIS policy — owned by the model so a publish started
    /// from the Policies screen shows (and blocks) here too.
    private var publishing: Bool { model.publishingPolicyIDs.contains(policyID) }

    /// The staged detail fields, snapshot at load for dirty tracking. Rule
    /// assignments are intentionally absent — they commit live.
    private struct Snapshot: Equatable {
        var name: String
        var idText: String
        var summary: String
        var version: String
        var priority: Int
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(Theme.hairline)
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: Spacing.lg) {
                        identitySection
                        versioningSection
                        rulesSection
                    }
                    .padding(Spacing.xl)
                }
                .scrollIndicators(.never)
                .onAppear {
                    loadOnce()
                    model.refreshDirectPublishGate()
                    if focusRules {
                        // Let the sheet lay out before jumping, or scrollTo
                        // lands on stale geometry.
                        Task {
                            try? await Task.sleep(for: .milliseconds(80))
                            withAnimation { proxy.scrollTo("rules", anchor: .top) }
                        }
                    }
                }
            }
            Divider().overlay(Theme.hairline)
            footer
        }
        .frame(width: 760, height: 720)
        .background(Theme.background)
        .preferredColorScheme(.dark)
        .tint(Theme.emerald)
        .interactiveDismissDisabled(isDirty)
        .sheet(isPresented: $showingAddRules) {
            AddRulesSheet(model: model,
                          policyID: policyID,
                          dismiss: { showingAddRules = false },
                          onOpenRulesScreen: {
                              showingAddRules = false
                              if isDirty { confirmLeaveForRules = true } else { openRulesScreen() }
                          })
        }
        .confirmationDialog("Discard changes to “\(name.isEmpty ? policyID : name)”?",
                            isPresented: $confirmDiscard, titleVisibility: .visible) {
            Button("Discard Changes", role: .destructive) { onClose() }
            Button("Keep Editing", role: .cancel) {}
        }
        .confirmationDialog("Discard changes to “\(name.isEmpty ? policyID : name)” and open Rules?",
                            isPresented: $confirmLeaveForRules, titleVisibility: .visible) {
            Button("Discard and Open Rules", role: .destructive) { openRulesScreen() }
            Button("Keep Editing", role: .cancel) {}
        }
        .alert(publishSuccess ? "Published" : "Publish failed",
               isPresented: Binding(get: { publishMessage != nil }, set: { if !$0 { publishMessage = nil } })) {
            Button("OK", role: .cancel) { publishMessage = nil }
        } message: {
            Text(publishMessage ?? "")
        }
    }

    private func loadOnce() {
        guard !loaded else { return }
        guard let policy = model.policy(id: policyID) else {
            // Deleted out from under the sheet (deep link raced a delete).
            onClose()
            return
        }
        name = policy.name
        idText = policy.id
        summary = policy.summary
        version = policy.policyVersion
        priority = policy.profilePriority
        baseline = currentSnapshot
        loaded = true
    }

    // MARK: Header / footer

    /// Title only — closing is the footer's Cancel (one way out, not two).
    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 1) {
                Text("Edit Policy").font(.system(size: 17, weight: .bold)).foregroundStyle(Theme.textPrimary)
                Text(name.isEmpty ? policyID : name).font(.system(size: 12)).foregroundStyle(Theme.textMuted)
            }
            Spacer()
        }
        .padding(Spacing.lg)
    }

    private var footer: some View {
        HStack {
            Button("Cancel") { requestClose() }.buttonStyle(.ghost)
                .keyboardShortcut(.cancelAction)
            Spacer()
            // Direct publish exists only where the admin Mac's config profile
            // turns it on (`commanderPublishEnabled`) — otherwise the policy is
            // delivered via the Export sheet's file paths.
            if model.directPublishEnabled {
                Button { runPublish() } label: {
                    if publishing {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Publish to \(model.mdm.vendor.displayName)", systemImage: "antenna.radiowaves.left.and.right")
                    }
                }
                .buttonStyle(.ghost)
                .disabled(publishing || isDirty || !model.canPublishToMDM(id: policyID))
                .help(publishHelp)
            }
            Button { save() } label: { Label("Save Changes", systemImage: "checkmark") }
                .buttonStyle(.emerald).disabled(!canSave)
        }
        .padding(Spacing.lg)
    }

    /// Why the publish button is (or isn't) available — publish targets the
    /// SAVED policy, so unsaved edits must be saved first.
    private var publishHelp: String {
        if let blocker = model.publishBlocker(id: policyID) { return blocker }
        if isDirty {
            return "Save changes before publishing — publish uses the saved policy."
        }
        return "Create or update this policy's profile in \(model.mdm.vendor.displayName) via the API (the console shows its rules blank; prefer Export → Save Jamf Schema for console-editable rules)."
    }

    private func openRulesScreen() {
        onClose()
        model.openRuleEditor(ruleID: nil)
    }

    private func runPublish() {
        guard model.publishBlocker(id: policyID) == nil else { return }
        Task {
            // Same gated, serialized path as the Policies screen; this sheet
            // shows the outcome itself and consumes the model's copy so the
            // Policies screen does not repeat it.
            let summary = await model.publishPolicies(ids: [policyID])
            publishSuccess = summary.isSuccess
            publishMessage = summary.message
            model.lastPublishSummary = nil
        }
    }

    // MARK: Identity

    private var identitySection: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            Label("Identity", systemImage: "number").font(.eyebrow).tracking(0.8).foregroundStyle(Theme.textMuted)
            LabeledField(label: "Policy name") { TextField("e.g. Developer Tools", text: $name) }
            LabeledField(label: "Identifier") {
                TextField("developer_tools", text: $idText).font(.mono(12))
            }
            Text("Compiled profile keys derive from this — rules_sudo_\(trimmedID.isEmpty ? "…" : trimmedID) and/or rules_authuri_\(trimmedID.isEmpty ? "…" : trimmedID), depending on the mechanisms this policy's enabled rules cover.")
                .font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            if !idValid {
                warn("Identifier must be lowercase letters, digits, or underscores (a–z, 0–9, _).")
            } else if idChanged {
                if model.policy(id: trimmedID) != nil {
                    warn("A different policy already uses this identifier — saving will overwrite it.")
                }
                warn("Renaming the identifier changes the compiled profile keys — anything already deployed under “\(policyID)” loses continuity, and managed Macs will treat this as a brand-new policy.")
            }
            VStack(alignment: .leading, spacing: 5) {
                Text("Summary").font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textMuted)
                TextEditor(text: $summary)
                    .font(.system(size: 13)).foregroundStyle(Theme.textPrimary)
                    .scrollContentBackground(.hidden)
                    .frame(height: 64).padding(Spacing.sm)
                    .background(Theme.background.opacity(0.55), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
            }
        }
        .card()
    }

    // MARK: Versioning

    private var versioningSection: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            Label("Versioning", systemImage: "number.circle").font(.eyebrow).tracking(0.8).foregroundStyle(Theme.textMuted)
            HStack(alignment: .top, spacing: Spacing.lg) {
                VStack(alignment: .leading, spacing: 5) {
                    LabeledField(label: "Version") { TextField("1.0.0", text: $version) }
                    Text("Bump this (e.g. 1.0.0 → 1.0.1) whenever rules change so managed Macs pick up the update.")
                        .font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(width: 180)
                VStack(alignment: .leading, spacing: 5) {
                    Text("Policy priority").font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textMuted)
                    Stepper("\(priority)", value: $priority, in: 1...1000, step: 10)
                        .font(.system(size: 13)).foregroundStyle(Theme.textPrimary)
                    Text("When two policies both match, the lower number wins.")
                        .font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(width: 220)
                Spacer()
            }
            if !versionValid {
                warn("Version must be MAJOR.MINOR.PATCH (e.g. 1.0.0). You can still save — it blocks exporting, not saving.")
            }
        }
        .card()
    }

    private var versionValid: Bool {
        let parts = version.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 3 && parts.allSatisfy { !$0.isEmpty && $0.allSatisfy(\.isNumber) }
    }

    // MARK: Rules (assignment manager)

    private var rulesSection: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            HStack {
                Label("Rules", systemImage: "list.bullet.rectangle").font(.eyebrow).tracking(0.8).foregroundStyle(Theme.textMuted)
                Spacer()
                Button { showingAddRules = true } label: { Label("Add Rules…", systemImage: "plus") }
                    .buttonStyle(.ghost)
            }
            Text("Assignments reference the shared rule library and apply immediately. A rule switched off here is skipped when this policy compiles, but keeps working in every other policy that uses it.")
                .font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)

            if let policy = model.policy(id: policyID) {
                if policy.rules.isEmpty {
                    emptyRules
                } else {
                    VStack(spacing: 4) {
                        ForEach(policy.rules) { assignment in
                            assignedRow(assignment)
                        }
                    }
                }
            }
        }
        .card()
        .id("rules")
    }

    private var emptyRules: some View {
        VStack(spacing: Spacing.sm) {
            Image(systemName: "tray").font(.system(size: 24)).foregroundStyle(Theme.textMuted)
            Text("No rules assigned").font(.system(size: 12, weight: .medium)).foregroundStyle(Theme.textMuted)
            Text("This policy compiles to nothing until at least one enabled rule is assigned.")
                .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
            Button { showingAddRules = true } label: { Label("Add Rules…", systemImage: "plus") }
                .buttonStyle(.ghost).padding(.top, Spacing.xxs)
        }
        .frame(maxWidth: .infinity, minHeight: 110)
    }

    @ViewBuilder
    private func assignedRow(_ assignment: PolicyRuleAssignment) -> some View {
        HStack(spacing: Spacing.md) {
            if let rule = model.rule(id: assignment.ruleID) {
                AssignmentRuleSummary(rule: rule, resolvedDefinitions: model.definitions(in: rule).count)
                    .opacity(assignment.enabled ? 1 : 0.55)
                Spacer()
                Toggle("", isOn: assignmentBinding(assignment.ruleID))
                    .labelsHidden().toggleStyle(.switch).tint(Theme.emerald).scaleEffect(0.75)
                    .help(assignment.enabled
                          ? "Enabled — compiles into this policy"
                          : "Disabled — skipped when this policy compiles")
            } else {
                // Dangling reference (rule deleted from the library) —
                // surfaced instead of hidden so it can be cleaned up.
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 12)).foregroundStyle(Theme.warning)
                VStack(alignment: .leading, spacing: 2) {
                    Text(assignment.ruleID).font(.mono(11)).foregroundStyle(Theme.textPrimary)
                    Text("Missing from the rule library — never compiles.")
                        .font(.system(size: 10.5)).foregroundStyle(Theme.warning)
                }
                Spacer()
            }
            Button { model.removeRule(assignment.ruleID, fromPolicy: policyID) } label: {
                Image(systemName: "minus.circle")
            }
            .buttonStyle(.plain).foregroundStyle(Theme.textMuted)
            .help("Remove from this policy (the rule stays in the library)")
        }
        .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
        .background(Theme.background.opacity(0.4), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
    }

    /// Per-rule per-policy toggle — the functional compile gate, committed
    /// immediately via ``PolicyBuilderModel/setRule(_:enabled:inPolicy:)``.
    private func assignmentBinding(_ ruleID: String) -> Binding<Bool> {
        Binding(
            get: { model.policy(id: policyID)?.rules.first(where: { $0.ruleID == ruleID })?.enabled ?? true },
            set: { model.setRule(ruleID, enabled: $0, inPolicy: policyID) }
        )
    }

    private func warn(_ message: String) -> some View {
        Label(message, systemImage: "exclamationmark.triangle.fill")
            .font(.system(size: 11)).foregroundStyle(Theme.warning)
            .fixedSize(horizontal: false, vertical: true)
    }

    // MARK: Validation & save

    private var trimmedID: String { idText.trimmingCharacters(in: .whitespaces) }

    private var idChanged: Bool { trimmedID != policyID }

    /// `[a-z0-9_]+` — the identifier lands inside compiled profile keys,
    /// which `PolicyValidator.isValidProfileKey` constrains to this charset.
    private var idValid: Bool {
        !trimmedID.isEmpty && trimmedID.allSatisfy { ($0.isLetter && $0.isLowercase) || $0.isNumber || $0 == "_" }
    }

    private var canSave: Bool {
        !name.trimmingCharacters(in: .whitespaces).isEmpty && idValid
    }

    private var currentSnapshot: Snapshot {
        Snapshot(name: name, idText: idText, summary: summary, version: version, priority: priority)
    }

    private var isDirty: Bool { loaded && baseline != currentSnapshot }

    private func requestClose() {
        if isDirty { confirmDiscard = true } else { onClose() }
    }

    private func save() {
        // Re-read the live policy so rule changes made in this sheet (they
        // commit immediately) are never clobbered by the staged details.
        guard var updated = model.policy(id: policyID) else {
            onClose()
            return
        }
        updated.name = name.trimmingCharacters(in: .whitespaces)
        updated.summary = summary
        updated.policyVersion = version.trimmingCharacters(in: .whitespaces)
        updated.profilePriority = priority
        if idChanged {
            // Rename = re-home under the new id: drop the old record, then
            // upsert (which overwrites any collision — the warning said so).
            updated.id = trimmedID
            model.deletePolicy(id: policyID)
        }
        model.updatePolicy(updated)
        onClose()
    }
}

// MARK: - Shared rule-row anatomy

/// Row anatomy for a library rule shown in assignment contexts — the details
/// editor's rules list, the Add Rules picker, and the create wizard's rules
/// step: name, allow/deny + silent/prompt chips, mono id, definition count.
/// Trailing controls (enable toggles, add/remove buttons) belong to the host
/// row, so this stays a pure value view.
struct AssignmentRuleSummary: View {
    let rule: PolicyRule
    /// Resolved definition count (`model.definitions(in:).count`) — passed in
    /// so the view needs no model access to flag dangling references.
    let resolvedDefinitions: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: Spacing.sm) {
                Text(rule.name.isEmpty ? rule.id : rule.name)
                    .font(.system(size: 13, weight: .medium)).foregroundStyle(Theme.textPrimary)
                    .lineLimit(1)
                RuleDecisionBadge(rule.action == .allow ? "allow" : "deny",
                                  color: rule.action == .allow ? Theme.success : Theme.critical)
                if rule.action == .allow {
                    RuleDecisionBadge(rule.elevationType == .silent ? "silent" : "prompt",
                                      color: rule.elevationType == .silent ? Theme.warning : Theme.info)
                }
            }
            HStack(spacing: Spacing.sm) {
                Text(rule.id).font(.mono(10)).foregroundStyle(Theme.textMuted).lineLimit(1)
                Text(definitionCountText)
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(definitionsHealthy ? Theme.textMuted : Theme.warning)
            }
        }
    }

    private var definitionsHealthy: Bool {
        !rule.definitionIDs.isEmpty && resolvedDefinitions == rule.definitionIDs.count
    }

    private var definitionCountText: String {
        let referenced = rule.definitionIDs.count
        if referenced == 0 { return "no definitions — compiles to nothing" }
        if resolvedDefinitions < referenced { return "\(resolvedDefinitions) of \(referenced) definitions resolve" }
        return referenced == 1 ? "1 definition" : "\(referenced) definitions"
    }
}

// MARK: - Add Rules picker

/// Picker over the shared rule library. Adding assigns immediately (the sheet
/// stays up for multi-add, and the row flips to "Added"); already-assigned
/// rules are disabled. Rules themselves are authored in the Rules screen —
/// this sheet only references them.
private struct AddRulesSheet: View {
    @Bindable var model: PolicyBuilderModel
    let policyID: String
    let dismiss: () -> Void
    /// Escape hatch when the library is empty: close the editor stack and
    /// jump to the Rules screen where rules are authored.
    var onOpenRulesScreen: () -> Void

    @State private var query = ""

    private var assignedIDs: Set<String> {
        Set(model.policy(id: policyID)?.rules.map(\.ruleID) ?? [])
    }

    private var results: [PolicyRule] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return model.rules }
        return model.rules.filter {
            $0.name.lowercased().contains(q)
                || $0.id.lowercased().contains(q)
                || $0.detail.lowercased().contains(q)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Add Rules").font(.system(size: 17, weight: .bold)).foregroundStyle(Theme.textPrimary)
                    Text("\(model.rules.count) \(model.rules.count == 1 ? "rule" : "rules") in the shared library")
                        .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
                }
                Spacer()
            }

            if model.rules.isEmpty {
                emptyLibrary
            } else {
                searchField
                if results.isEmpty {
                    VStack(spacing: Spacing.sm) {
                        Image(systemName: "magnifyingglass").font(.system(size: 26)).foregroundStyle(Theme.textMuted)
                        Text("No matching rules").font(.system(size: 12)).foregroundStyle(Theme.textMuted)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    ScrollView {
                        LazyVStack(spacing: 4) {
                            ForEach(results) { rule in
                                ruleRow(rule)
                            }
                        }
                        .padding(.vertical, 2)
                    }
                    .scrollIndicators(.visible)
                    .frame(maxHeight: .infinity)
                }
            }

            Divider().overlay(Theme.hairline)
            HStack {
                Text("New rules are authored in the Rules screen.")
                    .font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
                Spacer()
                Button("Done", action: dismiss).buttonStyle(.emerald).keyboardShortcut(.defaultAction)
            }
        }
        .padding(Spacing.lg)
        .frame(width: 580, height: 540)
        .background(Theme.background)
        .preferredColorScheme(.dark)
        .tint(Theme.emerald)
        // Picks commit live, so Done is the one exit (Return; Esc here).
        .onExitCommand { dismiss() }
    }

    private var searchField: some View {
        HStack(spacing: Spacing.sm) {
            Image(systemName: "magnifyingglass").font(.system(size: 12)).foregroundStyle(Theme.textMuted)
            TextField("Search rules by name, id, or description…", text: $query)
                .textFieldStyle(.plain).font(.system(size: 13)).foregroundStyle(Theme.textPrimary)
            if !query.isEmpty {
                Button { query = "" } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain).foregroundStyle(Theme.textMuted)
            }
        }
        .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
        .background(Theme.elevated.opacity(0.7), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
    }

    private func ruleRow(_ rule: PolicyRule) -> some View {
        let assigned = assignedIDs.contains(rule.id)
        return HStack(spacing: Spacing.md) {
            AssignmentRuleSummary(rule: rule, resolvedDefinitions: model.definitions(in: rule).count)
            Spacer()
            if assigned {
                StatusBadge("Added", tone: .healthy, symbol: "checkmark")
            } else {
                Button("Add") { model.addRule(rule.id, toPolicy: policyID) }
                    .buttonStyle(.ghost)
            }
        }
        .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
        .opacity(assigned ? 0.6 : 1)
    }

    private var emptyLibrary: some View {
        VStack(spacing: Spacing.sm) {
            Image(systemName: "list.bullet.rectangle").font(.system(size: 30)).foregroundStyle(Theme.textMuted)
            Text("The rule library is empty").font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            Text("Author rules in the Rules screen, then attach them to policies here.")
                .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
            Button { onOpenRulesScreen() } label: { Label("Open Rules Screen", systemImage: "arrow.up.forward") }
                .buttonStyle(.emerald).padding(.top, Spacing.xs)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
