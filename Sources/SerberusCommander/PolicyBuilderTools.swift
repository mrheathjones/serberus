import PolicyBuilderCore
import PrivMgrCore
import SwiftUI

/// Live Glob/Regex tester sheet. Matching uses the shared
/// PatternMatcher, so the preview agrees with real evaluation.
struct PatternTesterSheet: View {
    @Bindable var tester: PatternTesterModel
    let dismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading) {
            Text("Glob / Regex Tester").font(.title2.bold())
            Form {
                Picker("Match type", selection: $tester.matchType) {
                    ForEach(MatchType.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }
                TextField("Command pattern", text: $tester.commandPattern)
                TextField("Sample path", text: $tester.samplePath)
                TextField("Arg pattern (regex)", text: $tester.argPattern)
                TextField("Sample argument", text: $tester.sampleArgument)
            }
            .formStyle(.grouped)
            verdictLabel
            HStack {
                Spacer()
                Button("Done", action: dismiss).keyboardShortcut(.defaultAction)
            }
        }
        .padding()
        .frame(width: 460, height: 420)
        // Nothing to commit, so Done is the one exit (Return; Esc here).
        .onExitCommand(perform: dismiss)
    }

    @ViewBuilder
    private var verdictLabel: some View {
        switch tester.verdict {
        case .match:
            Label("Matches", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
        case .noMatch:
            Label("No match", systemImage: "minus.circle").foregroundStyle(.secondary)
        case .invalidCommandPattern:
            Label("Invalid command pattern", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
        case .invalidArgPattern:
            Label("Invalid arg pattern", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
        }
    }
}

/// MobileConfig export sheet: blocking validation errors and a
/// mandatory acknowledgement of cross-profile conflicts before export.
/// Exports one library policy identified by `policyID`. A policy can compile
/// to up to two wire profiles (sudo + authuri); both land in ONE combined
/// `.mobileconfig`, and errors in either block the export.
struct ExportSheet: View {
    @Bindable var model: PolicyBuilderModel
    let policyID: String
    let dismiss: () -> Void
    @State private var savedTo: URL?
    @State private var saveError: String?
    @State private var publishing = false
    @State private var publishResult: MDMResult?

    private var export: ExportModel { model.export }
    private var policy: Policy? { model.policy(id: policyID) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Export \(policy?.name ?? Policy.humanize(policyID))").font(.title2.bold())
                Text(policyID).font(.mono(11)).foregroundStyle(.secondary)
            }

            versionRow

            compiledProfilesBox

            let errors = export.reports.flatMap(\.errors)
            if !errors.isEmpty {
                GroupBox("Validation errors (blocking)") {
                    ForEach(errors, id: \.description) { issue in
                        Label(issue.message, systemImage: "xmark.octagon")
                            .foregroundStyle(.red)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }

            if !export.conflicts.isEmpty {
                GroupBox("Cross-profile conflicts") {
                    ForEach(export.conflicts, id: \.description) { conflict in
                        Text(conflict.description).font(.caption)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    Toggle("I acknowledge these conflicts", isOn: $model.export.conflictsAcknowledged)
                }
            }

            if export.canExport() { deliveryGuide }

            if let savedTo {
                HStack(spacing: 6) {
                    Label("Saved \(savedTo.lastPathComponent)", systemImage: "checkmark.seal")
                        .foregroundStyle(.green)
                    Button("Reveal in Finder") {
                        NSWorkspace.shared.activateFileViewerSelecting([savedTo])
                    }
                    .buttonStyle(.link)
                }
            }
            if let publishResult {
                Label(publishResult.headline,
                      systemImage: publishResult.isSuccess ? "checkmark.seal" : "exclamationmark.triangle")
                    .foregroundStyle(publishResult.isSuccess ? .green : .orange)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            if let error = saveError ?? export.lastError {
                Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange)
            }

            HStack(spacing: 8) {
                Button("Cancel", action: dismiss)
                    .buttonStyle(.ghost)
                    .keyboardShortcut(.cancelAction)
                Spacer()
                // The delivery actions as one segmented group (the Intel bar's
                // button-picker idiom): full titles. Publish (primary) exists
                // only where the admin Mac's config profile turns direct
                // publish on (`commanderPublishEnabled`); otherwise the file
                // paths are the whole menu and Save Jamf Schema leads.
                SegmentedActionBar(actions: deliveryActions)
            }
        }
        .padding()
        .frame(width: 680, height: 660)
        .onAppear {
            model.refreshDirectPublishGate()
            model.prepareExport(forPolicy: policyID)
        }
    }

    private var deliveryActions: [SegmentedActionBar.Action] {
        var actions: [SegmentedActionBar.Action] = [
            .init(id: "schema", title: "Save Jamf Schema",
                  isPrimary: !model.directPublishEnabled,
                  isDisabled: !export.canExport(),
                  help: "Jamf Custom Schema JSON with this policy's rules pre-filled — Jamf → Application & Custom Settings → External Applications → Custom Schema. Renders as an editable form in the console.") { runExportSchema() },
            .init(id: "plist", title: "Save .plist",
                  isDisabled: !export.canExport(),
                  help: "Flat \(BundleConfig.rulesDomain) settings plist for Jamf → Application & Custom Settings → Upload File") { runExportPlist() },
            .init(id: "mobileconfig", title: "Save .mobileconfig",
                  isDisabled: !export.canExport(),
                  help: "Whole configuration profile for Jamf → Configuration Profiles → Upload (deploys; the console shows its payload blank — same importer as Publish)") { runExport() },
        ]
        if model.directPublishEnabled {
            actions.append(.init(id: "publish", title: "Publish to Jamf",
                                 isPrimary: true,
                                 isDisabled: !export.canExport() || publishing || !model.mdm.connection.isComplete,
                                 isBusy: publishing,
                                 help: model.mdm.connection.isComplete
                                     ? "Create or update this profile in Jamf via the API (renders blank in the console — prefer Save Jamf Schema for console-editable rules)"
                                     : "Configure a complete Jamf connection in Settings to enable direct publish") { runPublish() })
        }
        return actions
    }

    /// The three delivery paths this sheet produces, so the operator picks the
    /// right artifact for the right Jamf flow. Only shown once the policy is
    /// exportable (an empty/invalid policy gets the blocking reason above).
    private var deliveryGuide: some View {
        GroupBox("Deliver to Jamf") {
            VStack(alignment: .leading, spacing: 6) {
                guideRow("list.bullet.clipboard", "Save Jamf Schema",
                         "Console-EDITABLE. Jamf → new profile → Application & Custom Settings → External Applications → Add → Custom Schema → paste/upload this JSON. The preference domain (\(JamfRulesSchema.subdomain(forPolicyID: policyID))) and the rules are pre-filled, and the form shows only the fields this policy's rule type uses; anyone can modify them in the form afterwards. Use this INSTEAD of Publish for a policy Jamf admins own.")
                guideRow("doc.badge.gearshape", "Save .mobileconfig",
                         "Jamf → Configuration Profiles → Upload. The whole profile. Deploys correctly but the console shows its payload blank (same importer as Publish) — use Save Jamf Schema or Save .plist if anyone must read or edit it in Jamf.")
                guideRow("list.bullet.rectangle", "Save .plist",
                         "Jamf → new profile → Application & Custom Settings → Upload File, preference domain \(BundleConfig.rulesDomain). Renders + editable in the console (Jamf builds the payload).")
                if model.directPublishEnabled {
                    guideRow("antenna.radiowaves.left.and.right", "Publish to Jamf",
                             model.mdm.connection.isComplete
                                ? "Create or update this profile directly through the Jamf API. Enforces correctly, but the console shows its payload BLANK — pick 'Save Jamf Schema' if others need to edit it in Jamf."
                                : "Needs a complete Jamf connection — set one up in Settings.")
                } else {
                    guideRow("antenna.radiowaves.left.and.right", "Publish to Jamf (off on this Mac)",
                             "Direct API publish is hidden because this Mac's com.herojoneslabs.serberus.config profile does not set commanderPublishEnabled. Deliver with Save Jamf Schema (console-editable form) or Save .plist (renders in the console); Save .mobileconfig deploys but shows blank, exactly like Publish.")
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func guideRow(_ symbol: String, _ title: String, _ detail: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: symbol).foregroundStyle(.secondary).frame(width: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.system(size: 12, weight: .semibold))
                Text(detail).font(.system(size: 11)).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// The wire profile keys this export will emit — the operator's proof of
    /// the mechanism split before anything is written. Empty compilation gets
    /// the model's blocking reason instead of a bare empty box.
    @ViewBuilder
    private var compiledProfilesBox: some View {
        if export.preparedProfiles.isEmpty {
            Label(export.blockingReason() ?? "This policy compiles to no profiles.",
                  systemImage: "exclamationmark.triangle")
                .foregroundStyle(.orange)
                .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            GroupBox("Compiled profiles (one combined .mobileconfig)") {
                ForEach(export.preparedProfiles, id: \.profileKey) { profile in
                    HStack(spacing: 8) {
                        Image(systemName: "doc.badge.gearshape").foregroundStyle(.secondary)
                        Text(profile.profileKey).font(.mono(11))
                        Spacer()
                        Text("\(profile.rules.count) rule(s)")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
    }

    /// Version chip + one-click patch bump — the nudge to re-version a policy
    /// whose rules changed since the last export.
    @ViewBuilder
    private var versionRow: some View {
        if let policy {
            HStack(spacing: 8) {
                Label("Version \(policy.policyVersion)", systemImage: "number.circle")
                    .font(.system(size: 12, weight: .medium))
                if let next = PolicyBuilderModel.nextPatchVersion(of: policy.policyVersion) {
                    Button("Bump to \(next)") {
                        model.bumpPolicyVersion(id: policyID)
                        model.prepareExport(forPolicy: policyID)
                    }
                    .buttonStyle(.link).font(.system(size: 12))
                } else {
                    Text("Fix the version in Policy Settings to enable one-click bumps.")
                        .font(.system(size: 10)).foregroundStyle(.orange)
                }
                Spacer()
                Text("Bump the version whenever rules change so managed Macs pick up the update.")
                    .font(.system(size: 10)).foregroundStyle(.secondary)
            }
        }
    }

    /// Generates one combined profile for every compiled key and writes it
    /// where the admin chooses. The suggested filename is derived from the
    /// compiled profile keys, which embed the policy id.
    private func runExport() {
        saveError = nil
        publishResult = nil
        guard let result = export.export(profiles: model.compiledProfiles(forPolicy: policyID)) else { return }

        let panel = NSSavePanel()
        panel.nameFieldStringValue = result.suggestedFilename
        panel.canCreateDirectories = true
        panel.title = "Export .mobileconfig"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try result.data.write(to: url, options: .atomic)
            savedTo = url
        } catch {
            saveError = "Could not save: \(error.localizedDescription)"
        }
    }

    /// Saves the flat rules-domain settings plist for Jamf's "Application &
    /// Custom Settings → Upload File" flow (same validation gate as the
    /// `.mobileconfig` export — the two never carry different rules).
    private func runExportPlist() {
        saveError = nil
        publishResult = nil
        guard let result = export.exportSettingsPlist(profiles: model.compiledProfiles(forPolicy: policyID)) else { return }

        let panel = NSSavePanel()
        panel.nameFieldStringValue = result.suggestedFilename
        panel.canCreateDirectories = true
        panel.title = "Save settings .plist"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try result.data.write(to: url, options: .atomic)
            savedTo = url
        } catch {
            saveError = "Could not save: \(error.localizedDescription)"
        }
    }

    /// Saves the Jamf Custom Schema JSON — the console-editable path: the
    /// shipped rules schema on a per-policy sub-domain, pre-filled with this
    /// policy's compiled rules as the form's defaults.
    private func runExportSchema() {
        saveError = nil
        publishResult = nil
        guard let result = export.exportJamfSchema(
            profiles: model.compiledProfiles(forPolicy: policyID),
            policyID: policyID,
            policyName: policy?.name ?? Policy.humanize(policyID)
        ) else { return }

        let panel = NSSavePanel()
        panel.nameFieldStringValue = result.suggestedFilename
        panel.allowedContentTypes = [.json]
        panel.canCreateDirectories = true
        panel.title = "Save Jamf Custom Schema"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try result.data.write(to: url, options: .atomic)
            savedTo = url
        } catch {
            saveError = "Could not save: \(error.localizedDescription)"
        }
    }

    /// Publishes the combined `.mobileconfig` to the configured MDM via the
    /// API, creating a new profile or updating the one that already carries
    /// this policy's name.
    ///
    /// The profile name is derived from the raw, stable policy id — never the
    /// editable display name (renaming would orphan the Jamf profile and make
    /// an unscoped duplicate) and never `Policy.humanize` (which strips
    /// `rules_*` prefixes, so distinct ids like `rules_x` and `x` would collide
    /// onto one Jamf name and silently overwrite each other). The raw id is
    /// unique and rename-stable, so create-vs-update always resolves the same
    /// profile. (Create-vs-update is matched by name in the MDM.)
    private func runPublish() {
        saveError = nil
        savedTo = nil
        publishResult = nil
        // The segment is hidden while the gate is off; guard anyway so the
        // gate is policy, not just chrome.
        guard model.directPublishEnabled else {
            saveError = "Direct publish is off on this Mac (commanderPublishEnabled) — use Save Jamf Schema or Save .plist."
            return
        }
        guard let result = export.export(profiles: model.compiledProfiles(forPolicy: policyID)) else { return }
        let name = "Serberus — \(policyID)"
        publishing = true
        Task {
            publishResult = await model.mdm.publish(name: name, mobileconfig: result.data)
            publishing = false
        }
    }
}

/// Auth URI browser. Enumerates **all** authorization rights live
/// from this Mac's authorization database (`/System/Library/Security/authorization.plist`),
/// searchable, with class/group/comment metadata. The chosen right is delivered
/// through `onPick`. Manual entry remains for custom rights.
struct AuthURIBrowserSheet: View {
    /// Which rights the browser offers.
    enum Mode {
        /// Every right on this Mac EXCEPT the identity-only ones (those can
        /// only be authored as App Identity definitions). While per-app rules
        /// are disabled nothing is hidden: the identity-only rights
        /// list with their "deny only" badge instead of pointing at a feature
        /// that is off.
        case authorizationRights
        /// ONLY the rights identity scoping may target, from the scope-guard
        /// table (verified + provisional), with their state.
        case appIdentity
    }

    @Bindable var model: PolicyBuilderModel
    /// Receives the chosen right name (rule composer, wizard, simulator, or
    /// browse-only exploration from the Rules screen's Tools menu).
    let onPick: (String) -> Void
    var mode: Mode = .authorizationRights
    let dismiss: () -> Void

    @State private var query = ""
    @State private var manual = ""
    @State private var includeRules = false
    @State private var selected: String?
    /// A manually-typed right that isn't in the catalog, awaiting confirmation.
    @State private var pendingCustom: String?

    private var catalog: AuthRightsCatalog { model.authRights }
    private var registry: AuthURIIdentityScopeRegistry { .current }

    private var results: [AuthorizationRight] {
        switch mode {
        case .authorizationRights:
            // Identity-only rights are authored as App Identity definitions;
            // a plain allow on one would rewrite it for every caller.
            let hidden = AppIdentityAvailability.enabled ? Set(registry.identityOnlyRights) : []
            return catalog.search(query, includeRules: includeRules).filter { !hidden.contains($0.name) }
        case .appIdentity:
            let q = query.trimmingCharacters(in: .whitespaces).lowercased()
            return registry.identityOnlyRights
                .filter { q.isEmpty || $0.lowercased().contains(q) }
                .map { name in
                    // Prefer the live catalog entry (class/group/comment); a
                    // right absent from this Mac's template still lists, since
                    // the daemon captures the TARGET Mac's definition.
                    catalog.rights.first { $0.name == name }
                        ?? AuthorizationRight(name: name, ruleClass: nil, group: nil,
                                              comment: registry.entry(for: name)?.notes, kind: .right)
                }
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            header

            if let error = catalog.loadError {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 12)).foregroundStyle(Theme.warning)
            }

            searchField

            if results.isEmpty {
                VStack(spacing: Spacing.sm) {
                    Image(systemName: "magnifyingglass").font(.system(size: 26)).foregroundStyle(Theme.textMuted)
                    Text(catalog.loaded ? "No matching rights" : "Loading rights…")
                        .font(.system(size: 12)).foregroundStyle(Theme.textMuted)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 4) {
                        ForEach(results) { right in
                            rightRow(right)
                        }
                    }
                    .padding(.vertical, 2)
                }
                .scrollIndicators(.visible)
                .frame(maxHeight: .infinity)
            }

            Divider().overlay(Theme.hairline)
            HStack(spacing: Spacing.sm) {
                if mode == .appIdentity {
                    Text(AppIdentityAvailability.enabled
                         ? "Other rights can still be typed; they compose as authored but are warned as unverified."
                         : AppIdentityAvailability.unavailableNote)
                        .font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
                    Spacer()
                    Button("Cancel", action: dismiss).buttonStyle(.ghost).keyboardShortcut(.cancelAction)
                } else {
                TextField("Custom right name…", text: $manual)
                    .textFieldStyle(.plain).font(.mono(11))
                    .padding(.horizontal, Spacing.md).padding(.vertical, 7)
                    .background(Theme.background.opacity(0.55), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
                Button("Use") { useCustom() }.buttonStyle(.ghost).disabled(manual.isEmpty)
                Spacer()
                Button("Cancel", action: dismiss).buttonStyle(.ghost).keyboardShortcut(.cancelAction)
                }
            }
        }
        .padding(Spacing.lg)
        .frame(width: 580, height: 560)
        .background(Theme.background)
        .preferredColorScheme(.dark)
        .tint(Theme.emerald)
        .onAppear { catalog.loadIfNeeded() }
        .alert("Unknown authorization right", isPresented: Binding(
            get: { pendingCustom != nil }, set: { if !$0 { pendingCustom = nil } })) {
            Button("Add anyway") { if let name = pendingCustom { apply(name) } }
            Button("Cancel", role: .cancel) { pendingCustom = nil }
        } message: {
            Text("No right named “\(pendingCustom ?? "")” exists on this Mac. You can still add it — the rule stays inert until the right is created.")
        }
    }

    private var header: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text(mode == .appIdentity ? "App Identity Rights" : "Authorization Rights")
                    .font(.system(size: 17, weight: .bold)).foregroundStyle(Theme.textPrimary)
                Text(mode == .appIdentity
                     ? (AppIdentityAvailability.enabled
                        ? "Only rights verified for per-app identity scoping (Serberus's engineering table)"
                        : "Per-app rules are disabled in Serberus 0.9.0; reference only")
                     : "\(catalog.rightsCount) rights read live from this Mac")
                    .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
            }
            Spacer()
            if mode == .authorizationRights {
                Toggle(isOn: $includeRules) {
                    Text("Include rule templates").font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                }
                .toggleStyle(.switch).tint(Theme.emerald).scaleEffect(0.85).fixedSize()
            }
        }
    }

    private var searchField: some View {
        HStack(spacing: Spacing.sm) {
            Image(systemName: "magnifyingglass").font(.system(size: 12)).foregroundStyle(Theme.textMuted)
            TextField("Search rights (e.g. preferences, admin, software)…", text: $query)
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

    private func rightRow(_ right: AuthorizationRight) -> some View {
        Button { apply(right.name) } label: {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: Spacing.sm) {
                    Text(right.name).font(.mono(11)).foregroundStyle(Theme.textPrimary).lineLimit(1)
                    if right.isWildcard {
                        Text("wildcard").font(.system(size: 9, weight: .semibold)).foregroundStyle(Theme.info)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Theme.info.opacity(0.14), in: Capsule())
                    }
                    if mode == .appIdentity {
                        let state = registry.state(for: right.name)
                        Text(state.label).font(.system(size: 9, weight: .semibold))
                            .foregroundStyle(state == .provisional ? Theme.warning : Theme.success)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background((state == .provisional ? Theme.warning : Theme.success).opacity(0.14), in: Capsule())
                    }
                    if mode == .authorizationRights, let badge = refusalBadge(right) {
                        Text(badge).font(.system(size: 9, weight: .semibold)).foregroundStyle(Theme.warning)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Theme.warning.opacity(0.14), in: Capsule())
                    }
                    Spacer()
                    if let cls = right.ruleClass {
                        Text(cls).font(.system(size: 9, weight: .semibold)).foregroundStyle(Theme.textMuted)
                    }
                    if let group = right.group {
                        Text(group).font(.system(size: 9, weight: .semibold)).foregroundStyle(Theme.emerald)
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Theme.accentDim, in: Capsule())
                    }
                }
                if let comment = right.comment, !comment.isEmpty {
                    Text(comment).font(.system(size: 11)).foregroundStyle(Theme.textMuted).lineLimit(2)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                if mode == .authorizationRights, let note = refusalNote(right) {
                    Label(note, systemImage: "exclamationmark.triangle")
                        .font(.system(size: 10.5)).foregroundStyle(Theme.warning).lineLimit(3)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.surface, in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
        }
        .buttonStyle(.plain)
    }

    /// A short badge for a right the daemon refuses some rules on (judged
    /// against this Mac's shipped database), or nil.
    private func refusalBadge(_ right: AuthorizationRight) -> String? {
        if right.refusedForEveryRule { return "not enforced" }
        if right.allowRefusal != nil { return "deny only" }
        if right.denyRefusal != nil { return "allow only" }
        return nil
    }

    /// Why, for ``refusalBadge(_:)``.
    private func refusalNote(_ right: AuthorizationRight) -> String? {
        if right.refusedForEveryRule, let reason = right.allowRefusal {
            return "The Mac does not enforce a rule on this right: \(reason)."
        }
        if let reason = right.allowRefusal { return "An allow rule is not enforced: \(reason)." }
        if let reason = right.denyRefusal { return "A deny rule is not enforced: \(reason)." }
        return nil
    }

    /// Manual-entry path: warn-then-allow if the typed right isn't a known one.
    private func useCustom() {
        let trimmed = manual.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        if catalog.existence(of: trimmed) == false {
            pendingCustom = trimmed
        } else {
            apply(trimmed)
        }
    }

    private func apply(_ right: String) {
        let trimmed = right.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return }
        onPick(trimmed)
        dismiss()
    }
}
