import AppKit
import PolicyBuilderCore
import PrivMgrCore
import SwiftUI
import UniformTypeIdentifiers

// MARK: - Intent

/// How the Definition composer was opened. Drives `.sheet(item:)`.
enum DefinitionComposerIntent: Identifiable, Equatable {
    /// New definition. `kind` presets the kind tile (the New Definition menu
    /// picks it up front so the form opens already shaped).
    case create(kind: DefinitionKind)
    /// New definition pre-filled from a captured attempt (Import Capture):
    /// the form opens with the command/right, pins and a generated id already
    /// in place, still unsaved until the admin clicks Save.
    case createPrefilled(DefinitionDraft)
    /// Edit an existing definition by its stable id.
    case edit(definitionID: String)

    var id: String {
        switch self {
        case .create(let kind): return "create::\(kind.rawValue)"
        case .createPrefilled(let draft): return "prefilled::\(draft.id.uuidString)"
        case .edit(let definitionID): return "edit::\(definitionID)"
        }
    }
}

// MARK: - App Identity availability

/// Per-app (App Identity) rules are disabled in Serberus 0.9.0
/// (``AuthURIIdentityScope/perAppPinsEnabled``). Commander keeps
/// the kind visible so existing definitions still open and show the
/// validator's `app-identity-disabled` error, but never offers it for a new
/// definition.
enum AppIdentityAvailability {
    static var enabled: Bool { AuthURIIdentityScope.perAppPinsEnabled }
    /// One line shown wherever the kind would otherwise be offered.
    static let unavailableNote =
        "Unavailable in Serberus 0.9.0: the app's identity comes from a value the caller can forge. See docs/authuri-identity-scoped-rules.md."

    /// Capture import drafts an identity-only right as App Identity; while
    /// per-app rules are disabled the draft becomes a plain authorization-right
    /// definition instead (the validator then says the right has no per-app
    /// allow path in this release).
    static func available(_ draft: DefinitionDraft) -> DefinitionDraft {
        guard !enabled, draft.appIdentity else { return draft }
        var plain = draft
        plain.authoringKind = .authuri
        plain.appTeamID = ""
        plain.appBundleID = ""
        return plain
    }
}

// MARK: - Readback

/// Composes the live plain-English summary shown above the composer footer.
/// Definitions only describe WHAT is matched — the sentence deliberately ends
/// by pointing at the Rules tier, where allow/deny is decided, so the split
/// between the tiers stays legible while authoring.
enum DefinitionReadback {
    static func sentence(for draft: DefinitionDraft) -> String {
        switch draft.kind {
        case .authuri:
            let right = draft.authURI.trimmingCharacters(in: .whitespaces)
            if draft.appIdentity {
                let app = draft.appBundleID.trimmingCharacters(in: .whitespaces)
                if !AppIdentityAvailability.enabled {
                    return "Would match the “\(right.isEmpty ? "…" : right)” permission only from \(app.isEmpty ? "the pinned app" : app). Per-app rules are disabled in Serberus 0.9.0: the daemon ignores this definition and the right keeps its native definition for every caller."
                }
                return "Matches requests for the “\(right.isEmpty ? "…" : right)” permission ONLY from \(app.isEmpty ? "the pinned app" : app) (verified by its code signature). The app authenticates as the session owner or an admin (the user's own password, or an admin's); every other caller keeps the right's native behaviour. Rules referencing this definition decide allow/deny like any other definition."
            }
            return "Matches requests to unlock the “\(right.isEmpty ? "…" : right)” permission. Rules referencing this definition decide what happens on a match."
        case .sudo:
            let command = draft.commandPattern.trimmingCharacters(in: .whitespaces)
            let shown = draft.matchType == .any || command.isEmpty ? "any command" : command
            var base = "Matches \(shown) run with sudo"
            let args = draft.argPattern.trimmingCharacters(in: .whitespaces)
            if !args.isEmpty {
                base += " with arguments matching “\(args)”"
            }
            base += ". Rules referencing this definition decide what happens on a match."
            return base
        }
    }
}

// MARK: - Composer sheet

/// The single authoring surface for definitions (tier 3): one modal sheet
/// covering create and edit. A definition is a pure matcher — a sudo command
/// pattern or an authorization right, plus optional identity pins — so the
/// form carries no decision settings (those live on rules). Nothing touches
/// the model until Save, so Cancel is a true discard.
struct DefinitionComposerSheet: View {
    @Bindable var model: PolicyBuilderModel
    let intent: DefinitionComposerIntent
    /// Called after a successful save with the definition's stable id, so the
    /// hosting screen can select/flash it (or a rule composer can reference it).
    var onSaved: ((String) -> Void)? = nil
    let dismiss: () -> Void

    @State private var draft = DefinitionDraft()
    /// Baseline for the dirty check (the loaded definition in edit mode, the
    /// kind-preset defaults in create mode).
    @State private var baseline = DefinitionDraft()
    @State private var loaded = false
    @State private var showingBrowser = false
    @State private var showingTester = false
    @State private var confirmDiscard = false
    @State private var confirmDelete = false

    /// Matcher checks mirrored from ``PolicyValidator`` — the exact set a
    /// compiled rule using this definition would be flagged on (empty pattern
    /// for a non-any match style, regex/glob syntax, right-name format).
    private static let matcherChecks: Set<String> = [
        "auth-uri", "match-shape", "command-pattern", "regex-syntax", "glob-syntax",
        "app-identity", "app-identity-scope", "app-identity-required", "app-identity-disabled",
    ]
    /// Whether the typed right was auto-converted to App Identity (shown once).
    @State private var convertedToAppIdentity = false
    /// The app whose signature filled the App Identity fields (drag & drop or
    /// "Add App…"), for the read-only code-signing block.
    @State private var inspectedApp: AppSignatureInfo?
    @State private var dropTargeted = false
    @State private var appNotice: String?

    private var isEdit: Bool {
        if case .edit = intent { return true }
        return false
    }

    /// Whether dropping/adding an app may fill an App Identity pin: always
    /// while per-app rules are enabled; otherwise only on an existing App
    /// Identity definition.
    private var acceptsAppDrop: Bool {
        AppIdentityAvailability.enabled || (isEdit && draft.authoringKind == .appIdentity)
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(Theme.hairline)
            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.lg) {
                    kindCard
                    formCard
                }
                .padding(Spacing.xl)
            }
            .scrollIndicators(.never)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            Divider().overlay(Theme.hairline)
            readbackLine
            footer
        }
        .frame(width: 720, height: 640)
        .background(Theme.background)
        .overlay {
            if dropTargeted && acceptsAppDrop {
                RoundedRectangle(cornerRadius: Radius.md, style: .continuous)
                    .strokeBorder(Theme.emerald, style: StrokeStyle(lineWidth: 2, dash: [8, 6]))
                    .padding(6)
                    .overlay {
                        Label("Drop the app to pin it", systemImage: "app.badge.checkmark")
                            .font(.system(size: 14, weight: .semibold)).foregroundStyle(Theme.emerald)
                            .padding(Spacing.md)
                            .background(Theme.background.opacity(0.9), in: Capsule())
                    }
                    .allowsHitTesting(false)
            }
        }
        // PPPC-Utility style: drop an .app anywhere on the sheet — whatever
        // kind is selected — to switch to App Identity and fill the pin from
        // the bundle's code signature. Off while per-app rules are disabled,
        // except on an existing App Identity definition.
        .onDrop(of: [UTType.fileURL], isTargeted: $dropTargeted) { providers in
            guard acceptsAppDrop else { return false }
            guard let provider = providers.first(where: { $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) }) else {
                return false
            }
            provider.loadDataRepresentation(forTypeIdentifier: UTType.fileURL.identifier) { data, _ in
                guard let data, let url = URL(dataRepresentation: data, relativeTo: nil) else { return }
                DispatchQueue.main.async { adoptApp(at: url) }
            }
            return true
        }
        .preferredColorScheme(.dark)
        .tint(Theme.emerald)
        .onAppear(perform: loadOnce)
        .interactiveDismissDisabled(isDirty)
        .sheet(isPresented: $showingBrowser) {
            AuthURIBrowserSheet(model: model,
                                onPick: { right in draft.authURI = right },
                                mode: draft.appIdentity ? .appIdentity : .authorizationRights,
                                dismiss: { showingBrowser = false })
        }
        // An identity-only right typed into the plain Authorization-right form
        // is migrated to App Identity on the spot: a plain allow on it would
        // rewrite the right for every caller, which is what per-app scoping
        // exists to avoid. Not while per-app rules are disabled: the
        // plain form then shows the validator's "no per-app allow path" note.
        .onChange(of: draft.authURI) { _, right in
            guard AppIdentityAvailability.enabled,
                  !isEdit, draft.kind == .authuri, !draft.appIdentity,
                  AuthURIIdentityScopeRegistry.current.isIdentityOnly(right.trimmingCharacters(in: .whitespaces))
            else { return }
            draft.authoringKind = .appIdentity
            convertedToAppIdentity = true
        }
        .sheet(isPresented: $showingTester) {
            PatternTesterSheet(tester: model.patternTester) { showingTester = false }
        }
        .confirmationDialog("Discard changes to “\(draft.name.isEmpty ? "this definition" : draft.name)”?",
                            isPresented: $confirmDiscard, titleVisibility: .visible) {
            Button("Discard Changes", role: .destructive) { dismiss() }
            Button("Keep Editing", role: .cancel) {}
        }
        .alert("Delete “\(draft.definitionID)”?", isPresented: $confirmDelete) {
            Button("Cancel", role: .cancel) {}
            Button("Delete", role: .destructive) { deleteEditedDefinition() }
        } message: {
            Text(deleteMessage)
        }
    }

    // MARK: Setup

    private func loadOnce() {
        guard !loaded else { return }
        loaded = true
        model.authRights.loadIfNeeded()
        switch intent {
        case .create(let kind):
            // A new App Identity definition is not offered while per-app
            // rules are disabled; open the plain right form instead.
            draft.authoringKind = kind == .appIdentity && !AppIdentityAvailability.enabled ? .authuri : kind
            baseline = draft
        case .createPrefilled(let prefilled):
            draft = AppIdentityAvailability.available(prefilled)
            // Baseline = an empty draft of the same kind, so the pre-filled
            // content counts as unsaved work: closing the sheet asks first.
            baseline = DefinitionDraft(kind: draft.kind, appIdentity: draft.appIdentity)
        case .edit(let definitionID):
            if let definition = model.definition(id: definitionID) {
                draft = DefinitionDraft(definition: definition)
            }
            baseline = draft
        }
    }

    // MARK: Header

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 1) {
                Text(isEdit ? "Edit Definition" : "New Definition")
                    .font(.system(size: 17, weight: .bold)).foregroundStyle(Theme.textPrimary)
                Text(subtitle).font(.system(size: 12)).foregroundStyle(Theme.textMuted)
            }
            Spacer()
        }
        .padding(Spacing.lg)
    }

    private var subtitle: String {
        if isEdit {
            let count = usedByRules.count
            return "\(draft.definitionID) · used by \(count) \(count == 1 ? "rule" : "rules")"
        }
        return draft.name.isEmpty ? "A definition describes what rules match against" : draft.name
    }

    /// Rules currently referencing this definition — drives the header count
    /// and the delete warning.
    private var usedByRules: [PolicyRule] {
        guard isEdit else { return [] }
        return model.rulesUsing(definitionID: draft.definitionID)
    }

    // MARK: Kind card

    /// Two mechanism tiles at creation; a locked row afterwards. The kind can
    /// never change on an existing definition — compiled wire rules and the
    /// matcher shape both hang off it, so a flip would silently re-target
    /// every rule referencing it.
    private var kindCard: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            Label("Definition kind", systemImage: "square.grid.2x2")
                .font(.eyebrow).tracking(0.8).foregroundStyle(Theme.textMuted)
            if isEdit {
                lockedKindRow
            } else {
                HStack(spacing: Spacing.md) {
                    kindTile(.sudo, symbol: "terminal.fill", tint: Theme.emerald,
                             title: "Sudo command",
                             detail: "Matches a command run with sudo in Terminal — exact path, wildcard, or regex.")
                    kindTile(.authuri, symbol: "lock.fill", tint: Theme.info,
                             title: "Authorization right",
                             detail: "Matches a macOS privileged action, like unlocking a System Settings pane.")
                    if AppIdentityAvailability.enabled {
                        kindTile(.appIdentity, symbol: "app.badge.checkmark", tint: Theme.info,
                                 title: "App Identity",
                                 detail: "Matches a verified authorization right only when ONE app (Team ID + bundle ID) asks for it.")
                    } else {
                        kindTile(.appIdentity, symbol: "app.badge.checkmark", tint: Theme.textMuted,
                                 title: "App Identity (unavailable)",
                                 detail: AppIdentityAvailability.unavailableNote,
                                 enabled: false)
                    }
                }
            }
        }
        .card()
    }

    private var lockedKindRow: some View {
        let kind = draft.authoringKind
        let tint = kind == .sudo ? Theme.emerald : Theme.info
        return HStack(spacing: Spacing.md) {
            Image(systemName: kind.symbol)
                .font(.system(size: 13))
                .foregroundStyle(tint)
                .frame(width: 30, height: 30)
                .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            VStack(alignment: .leading, spacing: 1) {
                Text(kind.title)
                    .font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.textPrimary)
                Text("The mechanism is fixed after creation — duplicate into a new definition to switch it.")
                    .font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
            }
        }
    }

    private func kindTile(_ kind: DefinitionKind, symbol: String, tint: Color, title: String, detail: String,
                          enabled: Bool = true) -> some View {
        let selected = draft.authoringKind == kind
        return Button { draft.authoringKind = kind } label: {
            VStack(alignment: .leading, spacing: Spacing.sm) {
                Image(systemName: symbol)
                    .font(.system(size: 14))
                    .foregroundStyle(tint)
                    .frame(width: 30, height: 30)
                    .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                Text(title).font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.textPrimary)
                Text(detail).font(.system(size: 11)).foregroundStyle(Theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
                    .multilineTextAlignment(.leading)
            }
            .padding(Spacing.md)
            .frame(maxWidth: .infinity, alignment: .topLeading)
            .background(selected ? tint.opacity(0.10) : Theme.elevated.opacity(0.5),
                        in: RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.md, style: .continuous)
                .strokeBorder(selected ? tint.opacity(0.55) : Theme.hairline, lineWidth: selected ? 1.5 : 1))
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
        .opacity(enabled ? 1 : 0.6)
    }

    // MARK: Form card

    private var formCard: some View {
        VStack(alignment: .leading, spacing: Spacing.xl) {
            namePurposeGroup
            switch draft.authoringKind {
            case .authuri:
                authURIGroup
                identityPinsGroup
            case .appIdentity:
                appIdentityGroup
            case .sudo:
                commandGroup
                identityPinsGroup
            }
        }
        .card()
    }

    private var namePurposeGroup: some View {
        group("Name & purpose", "number") {
            VStack(alignment: .leading, spacing: 5) {
                LabeledField(label: "Definition name") { TextField("Homebrew CLI", text: $draft.name) }
                caption("Shown in the Definitions list and in rule pickers.")
            }
            LabeledField(label: "What does it match?") {
                TextField("brew install / upgrade / uninstall run with sudo", text: $draft.detail)
            }
            identifierRow
        }
    }

    /// The stable id: derived from the name at creation, read-only forever
    /// after — compiled wire rule ids and rule references embed it, so a
    /// rename must never rewrite it.
    @ViewBuilder
    private var identifierRow: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: Spacing.sm) {
                Text("Identifier:").font(.system(size: 11)).foregroundStyle(Theme.textMuted)
                Text(isEdit ? draft.definitionID : derivedID)
                    .font(.mono(11)).foregroundStyle(Theme.textSecondary)
                    .textSelection(.enabled)
            }
            caption(isEdit
                ? "Permanent — rules and compiled profiles reference this definition by it."
                : "Generated from the name when you create the definition, permanent afterwards.")
        }
    }

    private var authURIGroup: some View {
        group("Authorization right", "lock.doc") {
            VStack(alignment: .leading, spacing: 5) {
                HStack {
                    Text("Right name").font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textMuted)
                    Spacer()
                    Button { showingBrowser = true } label: {
                        Label("Browse rights", systemImage: "magnifyingglass").font(.system(size: 10))
                    }
                    .buttonStyle(.plain).foregroundStyle(Theme.emerald)
                }
                TextField("system.preferences.datetime", text: $draft.authURI)
                    .textFieldStyle(.plain).font(.mono(12)).foregroundStyle(Theme.textPrimary)
                    .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
                    .background(Theme.background.opacity(0.55), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
                caption("The macOS permission this definition matches (e.g. system.preferences.datetime unlocks Date & Time). Click Browse rights to pick from this Mac's real list.")
                if unknownRight {
                    warn("No authorization right named this exists on this Mac. You can still save it — the definition stays inert until the right is created.")
                }
            }
            inlineIssues(["auth-uri", "match-shape", "app-identity-required"])
        }
    }

    /// App Identity: the authorization-right form plus the app pin. Only the
    /// rights in Serberus's verified table can be browsed or typed; the Team
    /// ID + bundle ID compile to a code requirement that must parse before
    /// the definition is worth saving. No posture anywhere: every app branch
    /// is session-owner-or-admin.
    private var appIdentityGroup: some View {
        let right = draft.authURI.trimmingCharacters(in: .whitespaces)
        let decision: AuthURIIdentityScopeDecision? = right.isEmpty ? nil : model.appIdentityScopeDecision(forRight: right)
        return group("Authorization right (per-app)", "app.badge.checkmark") {
            // Shown first so an existing definition says up front that
            // it does nothing in this release.
            inlineIssues(["app-identity-disabled"])
            appPicker
            VStack(alignment: .leading, spacing: 5) {
                HStack {
                    Text("Right name").font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textMuted)
                    Spacer()
                    if let decision { scopeBadge(decision.state) }
                    Button { showingBrowser = true } label: {
                        Label("Browse rights", systemImage: "magnifyingglass").font(.system(size: 10))
                    }
                    .buttonStyle(.plain).foregroundStyle(Theme.emerald)
                }
                TextField("e.g. com.apple.ServiceManagement.daemons.modify", text: $draft.authURI)
                    .textFieldStyle(.plain).font(.mono(12)).foregroundStyle(Theme.textPrimary)
                    .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
                    .background(Theme.background.opacity(0.55), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
                caption(AppIdentityAvailability.enabled
                    ? "The daemon composes the right on the Mac: this app gets its own branch, everyone else keeps the native definition. Rights outside Serberus's verified table are enforced as authored but warned about."
                    : "In Serberus 0.9.0 the daemon composes nothing for this definition: the right keeps its native definition for every caller.")
                if convertedToAppIdentity {
                    Label("Switched to App Identity: this right can only be allowed per app.", systemImage: "arrow.triangle.2.circlepath")
                        .font(.system(size: 11)).foregroundStyle(Theme.info)
                }
                if let decision {
                    if let reason = decision.rejectionReason {
                        warn(reason)
                    } else if let entry = decision.entry {
                        caption(entry.notes)
                        if decision.state == .provisional {
                            warn("\(AuthURIIdentityEligibility.provisional.label): the daemon enforces this rule wherever the profile lands. Scope the Jamf profile to the test Mac(s) \(entry.allowedSerials.sorted().joined(separator: ", ")) until a capture confirms the branch matches.")
                        }
                        if let confirm = entry.authorMustConfirm {
                            warn("Condition: \(confirm)")
                        }
                    }
                }
            }
            VStack(alignment: .leading, spacing: 5) {
                LabeledField(label: "Apple Developer Team ID") { TextField("e.g. M5RQTPC7A2", text: $draft.appTeamID) }
                caption("10 characters — filled from the app's signature when you drop or add the app, or from codesign -dv --verbose=2 /Applications/App.app (TeamIdentifier).")
            }
            VStack(alignment: .leading, spacing: 5) {
                LabeledField(label: "Bundle ID (code-signing identifier)") { TextField("e.g. com.postmanlabs.mac", text: $draft.appBundleID) }
                caption("The app's signing identifier — its bundle ID for a bundled app. Compiled with the Team ID into the code requirement authd matches against the caller.")
            }
            requirementPreview
            signatureBlock
            inlineIssues(["auth-uri", "match-shape", "app-identity", "app-identity-scope", "app-identity-required"])
        }
    }

    /// Drop zone + "Add App…" (an open panel filtered to app bundles). Either
    /// reads the bundle's code signature and fills Team ID + identifier.
    private var appPicker: some View {
        HStack(spacing: Spacing.md) {
            Image(systemName: "arrow.down.app").font(.system(size: 18)).foregroundStyle(Theme.emerald)
            VStack(alignment: .leading, spacing: 2) {
                Text("Drag the app here, or choose it").font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.textPrimary)
                Text("Reads the Team ID, signing identifier and designated requirement straight from the bundle's code signature.")
                    .font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            Button { chooseApp() } label: { Label("Add App…", systemImage: "plus.app") }
                .buttonStyle(.emerald)
        }
        .padding(Spacing.md)
        .background(Theme.elevated.opacity(0.5), in: RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.md, style: .continuous)
            .strokeBorder(Theme.emerald.opacity(0.45), style: StrokeStyle(lineWidth: 1, dash: [6, 4])))
    }

    /// Read-only code-signing facts for the app that filled the form.
    @ViewBuilder
    private var signatureBlock: some View {
        if let notice = appNotice {
            warn(notice)
        }
        if let app = inspectedApp {
            VStack(alignment: .leading, spacing: 5) {
                Text("Code signature of \(app.name)").font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textMuted)
                DetailRow(label: "Path", value: app.path, mono: true)
                if let identifier = app.signingIdentifier { DetailRow(label: "Identifier", value: identifier, mono: true) }
                if let bundleID = app.infoBundleID, bundleID != app.signingIdentifier {
                    DetailRow(label: "Info.plist bundle ID", value: bundleID, mono: true)
                }
                DetailRow(label: "Team ID", value: app.teamID ?? "none (Apple platform app, ad-hoc, or unsigned)", mono: true)
                if let version = app.version { DetailRow(label: "Version", value: version) }
                DetailRow(label: "Signature", value: app.signingStatus.rawValue)
                if let requirement = app.designatedRequirement {
                    Text("Designated requirement").font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textMuted)
                    CodeBlock {
                        Text(requirement).font(.mono(10.5)).foregroundStyle(Theme.textSecondary).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    caption("Serberus pins the identifier + anchor + Team ID core of this requirement (above), not the full certificate-field chain, so the pin survives a re-sign under the same team.")
                }
            }
        }
    }

    // MARK: App adoption (drag & drop / Add App…)

    private func chooseApp() {
        let panel = NSOpenPanel()
        panel.title = "Choose the app to pin"
        panel.prompt = "Pin App"
        panel.allowedContentTypes = [.applicationBundle]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.treatsFilePackagesAsDirectories = false
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        if panel.runModal() == .OK, let url = panel.url {
            adoptApp(at: url)
        }
    }

    /// Switches the draft to App Identity (create mode) and fills the pin
    /// from the bundle's signature. In edit mode the kind is locked, so only
    /// an existing App Identity definition takes the values.
    private func adoptApp(at url: URL) {
        let info = AppBundleInspector.inspect(url: url)
        appNotice = nil
        guard acceptsAppDrop else { return }
        if isEdit, draft.authoringKind != .appIdentity {
            appNotice = "\(info.name) was not applied: this definition's kind is fixed after creation. Create a new App Identity definition for it."
            return
        }
        if !isEdit { draft.authoringKind = .appIdentity }
        inspectedApp = info
        if let team = info.teamID { draft.appTeamID = team }
        if let identifier = info.pinIdentifier { draft.appBundleID = identifier }
        if draft.name.trimmingCharacters(in: .whitespaces).isEmpty { draft.name = info.name }
        if draft.detail.isEmpty { draft.detail = "\(info.name) (\(info.pinIdentifier ?? "?"))" }
        if info.teamID == nil {
            appNotice = "\(info.name) has no Team ID in its signature (\(info.signingStatus.rawValue)). An App Identity pin needs a team-signed app — Apple platform apps and ad-hoc builds cannot be pinned this way."
        } else if info.signingStatus != .valid {
            appNotice = "\(info.name)'s signature is \(info.signingStatus.rawValue) on this Mac; the pin was filled from it anyway."
        }
    }

    @ViewBuilder
    private var requirementPreview: some View {
        let team = draft.appTeamID.trimmingCharacters(in: .whitespaces).uppercased()
        let bundle = draft.appBundleID.trimmingCharacters(in: .whitespaces)
        if !team.isEmpty || !bundle.isEmpty {
            VStack(alignment: .leading, spacing: 5) {
                Text("Compiled code requirement").font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textMuted)
                switch Result(catching: { () throws -> String in
                    let compiled = try CodeRequirementCompiler.compile(teamID: team, bundleID: bundle)
                    try CodeRequirementCompiler.validate(compiled)
                    return compiled
                }) {
                case let .success(compiled):
                    CodeBlock {
                        Text(compiled).font(.mono(11)).foregroundStyle(Theme.textSecondary).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    caption("Accepted by SecRequirementCreateWithString — syntax only. Whether the live caller's signature matches is authd's decision at request time.")
                case let .failure(error):
                    Label(error.localizedDescription, systemImage: "xmark.octagon.fill")
                        .font(.system(size: 11)).foregroundStyle(Theme.critical)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private func scopeBadge(_ state: AuthURIIdentityEligibility) -> some View {
        let tone: StatusTone = switch state {
        case .verifiedEligible: .healthy
        case .provisional: .pending
        case .confirmedIneligible: .degraded
        case .unknown: .offline
        }
        return StatusBadge(state.label, tone: tone, symbol: state == .provisional ? "flask.fill" : nil)
    }

    private var commandGroup: some View {
        group("Command", "terminal") {
            labeled("Match style") {
                Picker("", selection: $draft.matchType) {
                    Text("Exact path").tag(MatchType.exact)
                    Text("Wildcard (*)").tag(MatchType.glob)
                    Text("Regex").tag(MatchType.regex)
                    Text("Path prefix + argument regex").tag(MatchType.prefixRegex)
                    Text("Any command").tag(MatchType.any)
                }.labelsHidden().fixedSize()
            }
            if draft.matchType != .any {
                VStack(alignment: .leading, spacing: 5) {
                    LabeledField(label: "Command path") { TextField("/usr/sbin/installer", text: $draft.commandPattern) }
                    caption("The full path of the command being run with sudo.")
                }
            }
            if draft.matchType == .exact {
                VStack(alignment: .leading, spacing: 5) {
                    LabeledField(label: "Resolved path (symlinked binaries — optional)") {
                        TextField("/usr/local/jamf/bin/jamf", text: $draft.resolvedCommandPattern)
                    }
                    caption("If the command above is a symlink, set this to the real path it resolves to (e.g. /usr/local/bin/jamf → /usr/local/jamf/bin/jamf). One definition then covers BOTH paths — the sudoers layer matches the symlink users type, the daemon matches the resolved binary. Leave blank for a normal command.")
                }
            }
            VStack(alignment: .leading, spacing: 5) {
                LabeledField(label: "Argument filter (optional)") { TextField("install|upgrade", text: $draft.argPattern) }
                caption("A regular expression tested against the command's first argument. Leave blank to match any arguments.")
            }
            Button {
                // Seed the tester with the draft so it tests THIS pattern,
                // not whatever was last typed in it.
                model.patternTester.matchType = draft.matchType
                model.patternTester.commandPattern = draft.commandPattern
                model.patternTester.argPattern = draft.argPattern
                showingTester = true
            } label: {
                Label("Test this pattern…", systemImage: "checkmark.circle.badge.questionmark")
                    .font(.system(size: 11))
            }
            .buttonStyle(.plain).foregroundStyle(Theme.emerald)
            if broadMatcher {
                warn("Matches every sudo command. Pin a Team ID or SHA-256 below so an allow rule using this definition isn't a blanket grant.")
            }
            inlineIssues(["command-pattern", "regex-syntax", "glob-syntax", "match-shape"])
        }
    }

    private var identityPinsGroup: some View {
        group("Verify the binary (optional)", "checkmark.shield") {
            caption("Stops impostor copies of the program from matching this definition.")
            VStack(alignment: .leading, spacing: 5) {
                LabeledField(label: "Apple Developer Team ID") { TextField("M5RQTPC7A2", text: $draft.requiredTeamID) }
                caption("Only match if the binary is signed by this 10-character team (from codesign -dv).")
            }
            VStack(alignment: .leading, spacing: 5) {
                LabeledField(label: "Exact binary fingerprint (SHA-256)") { TextField("", text: $draft.requiredBinaryHash) }
                caption("Only match this exact file. Get it with: shasum -a 256 /path/to/binary.")
            }
        }
    }

    // MARK: Validation

    /// Wraps the draft's compiled matcher in a scratch wire rule and runs the
    /// shared ``PolicyValidator`` per-rule checks — the exact validation any
    /// rule using this definition would face at export time, so the composer
    /// can never disagree with the export gate. Filtered to matcher-scoped
    /// checks (rule-tier checks like cache/grant bounds don't apply here).
    private var matcherIssues: [ValidationIssue] {
        let definition = draft.toDefinition()
        // An App Identity draft validates as the identity-scoped wire rule it
        // compiles to.
        let scratch = Rule(id: "draft", type: definition.kind, action: .allow,
                           description: "", priority: 50, match: definition.matchCriteria(),
                           appIdentity: definition.appIdentityBranch())
        return PolicyValidator.validate(rule: scratch, expectedType: nil)
            .filter { Self.matcherChecks.contains($0.check) }
    }

    /// True only when the catalog is loaded and the entered right is genuinely
    /// absent — an unknown/blank existence result never warns.
    private var unknownRight: Bool {
        guard draft.kind == .authuri else { return false }
        let uri = draft.authURI.trimmingCharacters(in: .whitespaces)
        guard !uri.isEmpty else { return false }
        return model.authRights.existence(of: uri) == false
    }

    /// An any-command matcher with no identity pin — worth a caution at the
    /// definition tier even though allow/deny is decided on rules.
    private var broadMatcher: Bool {
        draft.kind == .sudo && draft.matchType == .any
            && draft.requiredTeamID.trimmingCharacters(in: .whitespaces).isEmpty
            && draft.requiredBinaryHash.trimmingCharacters(in: .whitespaces).isEmpty
    }

    // MARK: Readback + footer

    private var readbackLine: some View {
        Text(DefinitionReadback.sentence(for: draft))
            .font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Spacing.lg)
            .padding(.top, Spacing.md)
    }

    private var footer: some View {
        let issues = matcherIssues
        let errors = issues.filter { $0.severity == .error }
        let warnings = issues.filter { $0.severity == .warning }
        return VStack(alignment: .leading, spacing: Spacing.sm) {
            HStack(spacing: Spacing.sm) {
                if isEdit {
                    Button { confirmDelete = true } label: { Label("Delete Definition…", systemImage: "trash") }
                        .buttonStyle(.ghost).foregroundStyle(Theme.critical)
                }
                Button("Cancel") { cancel() }.buttonStyle(.ghost)
                    .keyboardShortcut(.cancelAction)
                Spacer()
                if errors.isEmpty && warnings.isEmpty {
                    StatusBadge("Valid", tone: .healthy, symbol: "checkmark.seal.fill")
                } else {
                    if !errors.isEmpty {
                        StatusBadge("\(errors.count) \(errors.count == 1 ? "error" : "errors")",
                                    tone: .degraded, symbol: "xmark.octagon.fill")
                    }
                    if !warnings.isEmpty {
                        StatusBadge("\(warnings.count)", tone: .pending, symbol: "exclamationmark.triangle.fill")
                    }
                }
                Button { save() } label: {
                    Label(isEdit ? "Save Changes" : "Create Definition", systemImage: "checkmark")
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

    /// Save-with-errors is the philosophy (matcher problems only block MDM
    /// export), with one exception that corrupts identity rather than merely
    /// failing validation: a definition with no name would generate a
    /// meaningless id and be unfindable in every picker.
    private var canSave: Bool {
        !draft.name.trimmingCharacters(in: .whitespaces).isEmpty
    }

    /// The id a brand-new definition will be created under: the name's slug,
    /// uniquified against the library — same derivation as
    /// ``PolicyBuilderModel/newDefinition(kind:name:)``.
    private var derivedID: String {
        let base = PolicyBuilderModel.slugify(draft.name)
        return AuthoringID.uniqueID(base: base.isEmpty ? "definition" : base,
                                    existing: Set(model.definitions.map(\.id)))
    }

    private func cancel() {
        if isDirty { confirmDiscard = true } else { dismiss() }
    }

    private func save() {
        // Commit the trimmed name so the derived id always agrees with what
        // the identifier row previewed (a padded name would slug differently).
        draft.name = draft.name.trimmingCharacters(in: .whitespaces)
        if !isEdit {
            draft.definitionID = derivedID
        }
        model.upsertDefinition(draft.toDefinition())
        onSaved?(draft.definitionID)
        dismiss()
    }

    private var deleteMessage: String {
        let users = usedByRules
        guard !users.isEmpty else {
            return "No rules reference this definition, so enforcement is unchanged."
        }
        let names = users.map { $0.name.isEmpty ? $0.id : $0.name }.joined(separator: ", ")
        return "Deleting also removes this matcher from \(users.count == 1 ? "1 rule" : "\(users.count) rules"): \(names). A rule left with no definitions matches nothing and compiles to nothing."
    }

    private func deleteEditedDefinition() {
        if case .edit(let definitionID) = intent {
            model.deleteDefinition(id: definitionID)
        }
        dismiss()
    }

    // MARK: Layout helpers

    private func caption(_ text: String) -> some View {
        Text(text).font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func group(_ title: String, _ symbol: String, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            Label(title, systemImage: symbol).font(.eyebrow).tracking(0.8).foregroundStyle(Theme.textMuted)
            content()
        }
    }

    private func labeled(_ label: String, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label).font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textMuted)
            content()
        }
    }

    private func warn(_ message: String) -> some View {
        Label(message, systemImage: "exclamationmark.triangle.fill")
            .font(.system(size: 11)).foregroundStyle(Theme.warning)
            .fixedSize(horizontal: false, vertical: true)
    }

    /// Issues whose check belongs to the given group, rendered as inline
    /// warnings under the fields they concern (same routing as the rule form).
    @ViewBuilder
    private func inlineIssues(_ checks: [String]) -> some View {
        let matching = matcherIssues.filter { checks.contains($0.check) }
        if !matching.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(Array(matching.enumerated()), id: \.offset) { _, issue in
                    Label(issue.message, systemImage: issue.severity == .error
                          ? "xmark.octagon.fill" : "exclamationmark.triangle.fill")
                        .font(.system(size: 11))
                        .foregroundStyle(issue.severity == .error ? Theme.critical : Theme.warning)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}
