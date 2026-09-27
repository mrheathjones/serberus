import PolicyBuilderCore
import PrivMgrCore
import SwiftUI

/// The Create-Policy wizard: Details → Rules → Review.
///
/// Policies are mechanism-agnostic containers now, so there is no type
/// picker: the wizard authors the deliverable (identity, versioning) and
/// ATTACHES existing library rules with per-policy enable toggles. There is
/// no scope / conditions step either — a policy is delivered and scoped by
/// MDM (the group the profile is assigned to), not by authoring metadata.
/// Rules and definitions themselves are authored in their own screens;
/// ``PolicyCompiler`` splits the result into sudo/authuri wire profiles at
/// compile time.
struct CreatePolicyWizardView: View {
    @Bindable var model: PolicyBuilderModel
    var onClose: () -> Void
    /// Fired with the new policy id right before `onClose`, so the Policies
    /// grid can scroll-and-flash the created card.
    var onCreated: ((String) -> Void)? = nil

    @State private var step = 0
    @State private var name = ""
    @State private var idText = ""
    /// The last auto-slugged identifier; while the field still equals this,
    /// name edits keep regenerating it (same convention as the composer's
    /// generated rule names).
    @State private var lastGeneratedID = ""
    @State private var idEdited = false
    @State private var version = "1.0.0"
    @State private var priority = 50
    @State private var summary = ""
    /// Staged rule references — nothing touches the model until Create.
    @State private var assignments: [PolicyRuleAssignment] = []
    @State private var initialized = false
    /// The priority the wizard opened with — typed input is measured against it.
    @State private var basePriority = 50
    @State private var confirmDiscard = false
    @State private var confirmLeaveForRules = false

    private let steps = ["Details", "Rules", "Review"]

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(Theme.hairline)
            StepperHeader(steps: steps, current: step)
                .padding(.horizontal, Spacing.xl).padding(.vertical, Spacing.lg)
            Divider().overlay(Theme.hairline)
            ScrollView {
                stepContent.padding(Spacing.xl)
            }
            .scrollIndicators(.never)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            Divider().overlay(Theme.hairline)
            footer
        }
        .frame(width: 780, height: 640)
        .background(Theme.background)
        .preferredColorScheme(.dark)
        .tint(Theme.emerald)
        // Typed input is never lost to a stray Esc / swipe: mirror Edit
        // Policy's discard confirmation once there is anything to lose.
        .interactiveDismissDisabled(hasInput)
        .confirmationDialog("Discard this new policy?", isPresented: $confirmDiscard, titleVisibility: .visible) {
            Button("Discard", role: .destructive) { onClose() }
            Button("Keep Editing", role: .cancel) {}
        }
        .confirmationDialog("Discard this new policy and open Rules?", isPresented: $confirmLeaveForRules, titleVisibility: .visible) {
            Button("Discard and Open Rules", role: .destructive) { openRulesScreen() }
            Button("Keep Editing", role: .cancel) {}
        }
        .onAppear {
            guard !initialized else { return }
            priority = model.nextPolicyPriority()
            basePriority = priority
            initialized = true
        }
    }

    /// Anything the operator has typed or picked beyond the wizard's defaults.
    private var hasInput: Bool {
        !name.isEmpty || !idText.isEmpty || !summary.isEmpty
            || version != "1.0.0" || priority != basePriority || !assignments.isEmpty
    }

    private func requestClose() {
        if hasInput { confirmDiscard = true } else { onClose() }
    }

    /// Jumping to the Rules screen abandons the wizard — never silently.
    private func requestOpenRulesScreen() {
        if hasInput { confirmLeaveForRules = true } else { openRulesScreen() }
    }

    private func openRulesScreen() {
        onClose()
        model.openRuleEditor(ruleID: nil)
    }

    /// Title only — closing is the footer's Cancel (same as Edit Policy).
    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 1) {
                Text("Create Policy").font(.system(size: 17, weight: .bold)).foregroundStyle(Theme.textPrimary)
                Text(name.isEmpty ? "New policy" : name).font(.system(size: 12)).foregroundStyle(Theme.textMuted)
            }
            Spacer()
        }
        .padding(Spacing.lg)
    }

    @ViewBuilder
    private var stepContent: some View {
        switch step {
        case 0: detailsStep
        case 1: WizardRulesStep(model: model,
                                assignments: $assignments,
                                onOpenRulesScreen: { requestOpenRulesScreen() })
        default: reviewStep
        }
    }

    // MARK: Details

    private var detailsStep: some View {
        VStack(alignment: .leading, spacing: Spacing.lg) {
            stepIntro("Details", "Name the policy. Rules from the shared library are attached in the next step; scoping happens in your MDM.")
            LabeledField(label: "Policy name") {
                TextField("e.g. Developer Tools", text: $name)
                    .onChange(of: name) { _, newValue in
                        guard !idEdited else { return }
                        let slug = PolicyBuilderModel.slugify(newValue)
                        lastGeneratedID = slug
                        idText = slug
                    }
            }
            HStack(spacing: Spacing.lg) {
                LabeledField(label: "Policy version") { TextField("1.0.0", text: $version) }.frame(width: 130)
                VStack(alignment: .leading, spacing: 5) {
                    Text("Priority").font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textMuted)
                    Stepper("\(priority)", value: $priority, in: 1...1000, step: 10)
                        .font(.system(size: 13)).foregroundStyle(Theme.textPrimary)
                }.frame(width: 140)
                Spacer()
            }
            LabeledField(label: "Identifier") {
                TextField("developer_tools", text: $idText)
                    .font(.mono(12))
                    .onChange(of: idText) { _, newValue in
                        // Only a HAND edit locks the field — programmatic
                        // regeneration writes lastGeneratedID first.
                        if newValue != lastGeneratedID { idEdited = true }
                    }
            }
            Text("Compiled profile keys derive from this — rules_sudo_\(trimmedID.isEmpty ? "…" : trimmedID) and/or rules_authuri_\(trimmedID.isEmpty ? "…" : trimmedID), depending on the mechanisms the attached rules cover.")
                .font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            if !trimmedID.isEmpty && !idValid {
                warn("Identifier must be lowercase letters, digits, or underscores (a–z, 0–9, _).")
            } else if idCollides {
                warn("A policy with this identifier already exists — choose another.")
            }
            if !versionValid {
                warn("Version should be MAJOR.MINOR.PATCH (e.g. 1.0.0). It blocks exporting, not creating.")
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
    }

    // MARK: Review

    private var reviewStep: some View {
        // Compile the draft exactly the way export/publish will, so the
        // review shows the real wire profiles (and their validation) before
        // anything lands in the library.
        let policy = draftPolicy()
        let profiles = PolicyCompiler().compile(policy, rules: model.rules, definitions: model.definitions)
        let reports = profiles.map { PolicyValidator().validate($0) }
        let errorCount = reports.reduce(0) { $0 + $1.errors.count }
        let warningCount = reports.reduce(0) { $0 + $1.warnings.count }
        let enabledRules = assignments.filter(\.enabled).compactMap { model.rule(id: $0.ruleID) }
        let allow = enabledRules.filter { $0.action == .allow }.count
        let deny = enabledRules.count - allow

        return VStack(alignment: .leading, spacing: Spacing.lg) {
            stepIntro("Review", "Confirm the policy before adding it to the library.")
            VStack(alignment: .leading, spacing: Spacing.md) {
                DetailRow(label: "Name", value: finalName)
                DetailRow(label: "Identifier", value: trimmedID, mono: true)
                DetailRow(label: "Version", value: "v\(version.trimmingCharacters(in: .whitespaces)) · priority \(priority)")
                DetailRow(label: "Rules", value: "\(assignments.count) attached · \(enabledRules.count) enabled (\(allow) allow · \(deny) deny)")
            }
            .card()

            VStack(alignment: .leading, spacing: Spacing.sm) {
                Label("Compiled profiles", systemImage: "shippingbox").font(.eyebrow).tracking(0.8).foregroundStyle(Theme.textMuted)
                if profiles.isEmpty {
                    Label("Compiles to no profiles yet — attach at least one enabled rule whose definitions exist. You can still create the policy and add rules later.",
                          systemImage: "info.circle")
                        .font(.system(size: 11)).foregroundStyle(Theme.info)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    ForEach(profiles.indices, id: \.self) { index in
                        let profile = profiles[index]
                        let report = reports[index]
                        HStack(spacing: Spacing.sm) {
                            Text(profile.profileKey).font(.mono(11)).foregroundStyle(Theme.textPrimary)
                            Text("\(profile.rules.count) wire \(profile.rules.count == 1 ? "rule" : "rules")")
                                .font(.system(size: 10)).foregroundStyle(Theme.textMuted)
                            Spacer()
                            if report.isExportable {
                                StatusBadge("Valid", tone: .healthy, symbol: "checkmark.seal.fill")
                            } else {
                                StatusBadge("\(report.errors.count) \(report.errors.count == 1 ? "error" : "errors")",
                                            tone: .degraded, symbol: "xmark.octagon.fill")
                            }
                        }
                    }
                }
            }
            .card()

            HStack(spacing: Spacing.sm) {
                if errorCount > 0 {
                    StatusBadge("\(errorCount) \(errorCount == 1 ? "error" : "errors")", tone: .degraded, symbol: "xmark.octagon.fill")
                } else if !profiles.isEmpty {
                    StatusBadge("Valid", tone: .healthy, symbol: "checkmark.seal.fill")
                }
                if warningCount > 0 {
                    StatusBadge("\(warningCount) \(warningCount == 1 ? "warning" : "warnings")", tone: .pending, symbol: "exclamationmark.triangle.fill")
                }
                Spacer()
            }
            if errorCount > 0 {
                Text("You can still create the policy locally; resolve errors before publishing to MDM.")
                    .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
            }
        }
    }

    // MARK: Footer

    private var footer: some View {
        HStack {
            Button("Cancel") { requestClose() }.buttonStyle(.ghost)
                .keyboardShortcut(.cancelAction)
            Spacer()
            if step > 0 {
                Button { withAnimation { step -= 1 } } label: { Label("Back", systemImage: "chevron.left") }
                    .buttonStyle(.ghost)
            }
            if step < steps.count - 1 {
                Button { withAnimation { step += 1 } } label: { Label("Next", systemImage: "chevron.right").labelStyle(TrailingIcon()) }
                    .buttonStyle(.emerald).disabled(step == 0 && !detailsValid)
            } else {
                Button { create() } label: { Label("Create Policy", systemImage: "checkmark") }
                    .buttonStyle(.emerald).disabled(!detailsValid)
            }
        }
        .padding(Spacing.lg)
    }

    // MARK: Validation & create

    private var trimmedID: String { idText.trimmingCharacters(in: .whitespaces) }

    /// `[a-z0-9_]+` — the identifier lands inside compiled profile keys,
    /// which `PolicyValidator.isValidProfileKey` constrains to this charset.
    private var idValid: Bool {
        !trimmedID.isEmpty && trimmedID.allSatisfy { ($0.isLetter && $0.isLowercase) || $0.isNumber || $0 == "_" }
    }

    /// Creating over an existing id would silently overwrite that policy
    /// (``PolicyBuilderModel/updatePolicy(_:)`` upserts by id), so a
    /// collision blocks Next instead of merely warning.
    private var idCollides: Bool { model.policy(id: trimmedID) != nil }

    private var detailsValid: Bool {
        !name.trimmingCharacters(in: .whitespaces).isEmpty && idValid && !idCollides
    }

    private var versionValid: Bool {
        let parts = version.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 3 && parts.allSatisfy { !$0.isEmpty && $0.allSatisfy(\.isNumber) }
    }

    private var finalName: String {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty ? Policy.humanize(trimmedID) : trimmed
    }

    private func draftPolicy() -> Policy {
        Policy(
            id: trimmedID,
            name: finalName,
            summary: summary,
            enabled: true,
            policyVersion: version.trimmingCharacters(in: .whitespaces),
            profilePriority: priority,
            rules: assignments
        )
    }

    private func create() {
        let policy = draftPolicy()
        model.updatePolicy(policy)
        onCreated?(policy.id)
        onClose()
    }

    private func stepIntro(_ title: String, _ subtitle: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.system(size: 16, weight: .bold)).foregroundStyle(Theme.textPrimary)
            Text(subtitle).font(.system(size: 12)).foregroundStyle(Theme.textMuted)
        }
    }

    private func warn(_ message: String) -> some View {
        Label(message, systemImage: "exclamationmark.triangle.fill")
            .font(.system(size: 11)).foregroundStyle(Theme.warning)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// Trailing-icon label style for "Next →".
private struct TrailingIcon: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 5) { configuration.title; configuration.icon }
    }
}

// MARK: - Rules step

/// Pick rules from the shared library and stage per-policy enable toggles.
/// Same row anatomy as the details editor's assignment manager
/// (``AssignmentRuleSummary``) — inclusion is the checkmark, enablement is
/// the switch that appears once a rule is attached.
private struct WizardRulesStep: View {
    @Bindable var model: PolicyBuilderModel
    @Binding var assignments: [PolicyRuleAssignment]
    /// The library is empty — bail out of the wizard and go author rules.
    var onOpenRulesScreen: () -> Void

    @State private var query = ""

    private var filtered: [PolicyRule] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return model.rules }
        return model.rules.filter {
            $0.name.lowercased().contains(q)
                || $0.id.lowercased().contains(q)
                || $0.detail.lowercased().contains(q)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.lg) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Rules").font(.system(size: 16, weight: .bold)).foregroundStyle(Theme.textPrimary)
                    Text("Attach rules from the shared library. The switch sets per-policy enablement — everything else about a rule is edited in the Rules screen.")
                        .font(.system(size: 12)).foregroundStyle(Theme.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                Text("\(assignments.count) of \(model.rules.count) attached")
                    .font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textMuted)
                    .fixedSize()
            }

            if model.rules.isEmpty {
                emptyLibrary
            } else {
                searchField
                if filtered.isEmpty {
                    VStack(spacing: Spacing.sm) {
                        Image(systemName: "magnifyingglass").font(.system(size: 26)).foregroundStyle(Theme.textMuted)
                        Text("No matching rules").font(.system(size: 12)).foregroundStyle(Theme.textMuted)
                    }
                    .frame(maxWidth: .infinity, minHeight: 120).card()
                } else {
                    VStack(spacing: 4) {
                        ForEach(filtered) { rule in
                            ruleRow(rule)
                        }
                    }
                    .card(padding: Spacing.sm)
                }
            }
        }
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
        let included = assignments.contains { $0.ruleID == rule.id }
        return HStack(spacing: Spacing.md) {
            Button { toggleInclusion(rule) } label: {
                HStack(spacing: Spacing.md) {
                    Image(systemName: included ? "checkmark.circle.fill" : "circle")
                        .font(.system(size: 16))
                        .foregroundStyle(included ? Theme.emerald : Theme.textMuted)
                    AssignmentRuleSummary(rule: rule, resolvedDefinitions: model.definitions(in: rule).count)
                }
            }
            .buttonStyle(.plain)
            Spacer()
            if included {
                Toggle("", isOn: enabledBinding(rule.id))
                    .labelsHidden().toggleStyle(.switch).tint(Theme.emerald).scaleEffect(0.75)
                    .help("Attached but switched off — kept in the policy without being enforced.")
            }
        }
        .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
        .background(included ? Theme.accentDim : Theme.background.opacity(0.4),
                    in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous)
            .strokeBorder(included ? Theme.emerald.opacity(0.35) : Theme.hairline, lineWidth: 1))
    }

    private var emptyLibrary: some View {
        VStack(spacing: Spacing.sm) {
            Image(systemName: "list.bullet.rectangle").font(.system(size: 30)).foregroundStyle(Theme.textMuted)
            Text("The rule library is empty").font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            Text("Author rules in the Rules screen first, then attach them to policies here. You can also create this policy empty and add rules later.")
                .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
                .multilineTextAlignment(.center)
            Button { onOpenRulesScreen() } label: { Label("Open Rules Screen", systemImage: "arrow.up.forward") }
                .buttonStyle(.ghost).padding(.top, Spacing.xs)
        }
        .frame(maxWidth: .infinity, minHeight: 160).card()
    }

    private func toggleInclusion(_ rule: PolicyRule) {
        if let index = assignments.firstIndex(where: { $0.ruleID == rule.id }) {
            assignments.remove(at: index)
        } else {
            assignments.append(PolicyRuleAssignment(ruleID: rule.id))
        }
    }

    private func enabledBinding(_ ruleID: String) -> Binding<Bool> {
        Binding(
            get: { assignments.first(where: { $0.ruleID == ruleID })?.enabled ?? true },
            set: { newValue in
                guard let index = assignments.firstIndex(where: { $0.ruleID == ruleID }) else { return }
                assignments[index].enabled = newValue
            }
        )
    }
}
