import PolicyBuilderCore
import PrivMgrCore
import SwiftUI
import UniformTypeIdentifiers

/// Definitions — the shared matcher library (tier 3): every sudo command
/// pattern and authorization right in one flat, searchable list. Definitions
/// carry no allow/deny — rules reference them by id and add the decision —
/// so this screen is pure "what can be matched", with create/edit/delete in
/// place via the ``DefinitionComposerSheet``, **Import Capture** (the Rule
/// Recorder hand-off from Sentinel) feeding pre-filled definitions in, and a
/// checkbox multi-selection for batch delete / single duplicate.
struct DefinitionsView: View {
    @Bindable var model: PolicyBuilderModel

    @State private var query = ""
    @State private var kindFilter: KindFilter = .all
    @State private var selectedRowID: String?
    /// Briefly highlights a just-saved definition's row.
    @State private var flashRowID: String?
    @State private var composerIntent: DefinitionComposerIntent?
    /// Definitions awaiting the delete confirmation (one from a row / the
    /// keyboard, several from the checkbox selection).
    @State private var deleteCandidates: [RuleDefinition] = []
    /// Checkbox multi-selection — distinct from the keyboard focus row
    /// (`selectedRowID`). Drives the batch bar (delete N / duplicate one).
    @State private var checkedIDs: Set<String> = []

    // Import Capture
    @State private var importingCapture = false
    @State private var importedCapture: ImportedCapture?
    @State private var importError: String?
    /// A draft handed back by the import sheet; the composer opens with it
    /// once the import sheet has actually dismissed (two sheets cannot swap in
    /// one transaction).
    @State private var pendingPrefill: DefinitionDraft?
    /// Fleet Observer harvest: the Jamf attachment to delete once the import
    /// it came from COMMITS (batch created, or the prefilled composer saved).
    /// Cancel anywhere leaves the file on the record.
    @State private var harvestAfterImport: FleetUpload?
    /// The capture being imported right now (file name + the Jamf upload it
    /// is, when known) — the review ledger records the outcome against it
    /// when the import commits or the capture is rejected. `nil` outside an
    /// import flow, so a plain New Definition never touches the ledger.
    @State private var importInFlight: (fileName: String, origin: FleetUpload?)?
    /// Outcome of the post-import delete, when it failed.
    @State private var harvestNotice: String?
    /// The Fleet Observer's harvest switch (shared key): a reject also clears
    /// the Jamf record when it is on.
    @AppStorage("fleet.deleteAfterDownload") private var deleteAfterDownload = false

    private static let captureType = UTType(filenameExtension: RuleCapture.fileExtension) ?? .json

    private enum KindFilter: String, CaseIterable, Identifiable {
        case all = "All kinds", sudo = "Sudo", authuri = "Auth right", appIdentity = "App identity"
        var id: String { rawValue }
    }

    // MARK: Derived state

    /// Name-sorted, filtered definitions. Row identity is the definition's
    /// stable slug — unique across the library by construction.
    private var rows: [RuleDefinition] {
        model.definitions
            .filter { matchesKind($0.authoringKind) && matchesQuery($0) }
            .sorted {
                let byName = $0.name.localizedCaseInsensitiveCompare($1.name)
                if byName != .orderedSame { return byName == .orderedAscending }
                return $0.id < $1.id
            }
    }

    private func matchesKind(_ kind: DefinitionKind) -> Bool {
        switch kindFilter {
        case .all: return true
        case .sudo: return kind == .sudo
        case .authuri: return kind == .authuri
        case .appIdentity: return kind == .appIdentity
        }
    }

    private func matchesQuery(_ definition: RuleDefinition) -> Bool {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return true }
        return definition.name.lowercased().contains(q)
            || definition.id.lowercased().contains(q)
            || target(for: definition).lowercased().contains(q)
            || definition.detail.lowercased().contains(q)
    }

    /// The mono target line: the right name or the command pattern — what the
    /// definition actually matches.
    private func target(for definition: RuleDefinition) -> String {
        switch definition.kind {
        case .authuri:
            if definition.isAppIdentity {
                let app = (definition.appBundleID?.isEmpty == false) ? definition.appBundleID! : "(no bundle ID)"
                return "\(app) → \(definition.authURI ?? "(no right)")"
            }
            return definition.authURI ?? "(no right)"
        case .sudo:
            if let pattern = definition.commandPattern { return pattern }
            return (definition.matchType ?? .exact) == .any ? "any command" : "(no command)"
        }
    }

    private var headerSubtitle: String {
        let total = model.definitions.count
        let sudo = model.definitions.filter { $0.kind == .sudo }.count
        let apps = model.definitions.filter(\.isAppIdentity).count
        let auth = total - sudo - apps
        var subtitle = "\(total) \(total == 1 ? "definition" : "definitions")"
        if total > 0 {
            subtitle += " · \(sudo) sudo · \(auth) auth \(auth == 1 ? "right" : "rights")"
            if apps > 0 { subtitle += " · \(apps) app \(apps == 1 ? "identity" : "identities")" }
        }
        return subtitle
    }

    // MARK: Body

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.lg) {
            ScreenHeader("Definitions", subtitle: headerSubtitle) {
                HStack(spacing: Spacing.sm) {
                    Button {
                        importingCapture = true
                    } label: {
                        Label("Import Capture", systemImage: "square.and.arrow.down")
                    }
                    .buttonStyle(.ghost)
                    .help("Import a .serberuscapture recorded in Serberus Sentinel and create definitions from what the user actually did")
                    newDefinitionMenu
                }
            }

            if model.definitions.isEmpty {
                emptyLibraryState
            } else {
                filterBar
                if !checkedIDs.isEmpty {
                    selectionBar
                }
                listArea
            }
        }
        .padding(Spacing.xl)
        .animation(.easeOut(duration: 0.15), value: checkedIDs.isEmpty)
        .onAppear {
            model.authRights.loadIfNeeded()
            consumeCaptureImportRequest()
            consumePendingComposerPrefill()
            consumePendingImportCompletion()
        }
        .onChange(of: model.definitions) { _, _ in pruneStaleSelection() }
        // File ▸ Import Capture… lands here — on appear too, because the
        // command may have fired while another section was showing.
        .onChange(of: model.captureImportPending) { _, _ in consumeCaptureImportRequest() }
        // The Fleet Observer's Review Capture sheet chose one attempt and pressed
        // Create Definition — open the pre-filled composer here.
        .onChange(of: model.pendingComposerPrefill) { _, _ in consumePendingComposerPrefill() }
        // A batch Create N Definitions from Review Capture — complete the ledger
        // + harvest here so any delete failure surfaces on this screen.
        .onChange(of: model.pendingImportCompletion) { _, _ in consumePendingImportCompletion() }
        // `.data` too: a capture pulled back down from a Jamf computer record
        // can arrive with its extension mangled (observed in testing: the "." before
        // `serberuscapture` dropped). The decoder validates the contents, so
        // restricting by extension would only lock out real captures.
        .fileImporter(isPresented: $importingCapture,
                      allowedContentTypes: [Self.captureType, .json, .data],
                      allowsMultipleSelection: false) { result in
            switch result {
            case let .success(urls):
                guard let url = urls.first else { return }
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                do {
                    let capture = try CaptureImporter.load(url: url)
                    // A file saved from the Fleet Observer (or from Sentinel
                    // with the same name as its upload) is still that upload.
                    let key = CaptureReviewLedger.key(forFileName: url.lastPathComponent)
                    let origin = model.fleet.uploads.first { CaptureReviewLedger.key(forFileName: $0.fileName) == key }
                    importInFlight = (url.lastPathComponent, origin)
                    harvestAfterImport = nil
                    importedCapture = ImportedCapture(capture: capture, fileName: url.lastPathComponent, origin: origin)
                } catch {
                    importError = error.localizedDescription
                }
            case let .failure(error):
                importError = error.localizedDescription
            }
        }
        .sheet(item: $importedCapture, onDismiss: {
            // The composer may only open once the import sheet is actually
            // gone — `onDismiss` is the hook that guarantees that ordering.
            guard let draft = pendingPrefill else {
                // Closed without creating anything and without handing a draft
                // on (Cancel, or a Reject already recorded): a Fleet harvest
                // stays on the record and the ledger is untouched.
                harvestAfterImport = nil
                importInFlight = nil
                return
            }
            pendingPrefill = nil
            composerIntent = .createPrefilled(draft)
        }) { imported in
            ImportCaptureSheet(
                model: model,
                imported: imported,
                onCreateOne: { draft in
                    pendingPrefill = draft
                    importedCapture = nil
                },
                onCreated: { ids in
                    // Record BEFORE the sheet goes away: onDismiss clears the
                    // in-flight import state.
                    completeImport(definitionIDs: ids)
                    importedCapture = nil
                    if let last = ids.last { flash(last) }
                },
                onReject: {
                    rejectImport()
                    importedCapture = nil
                },
                deletesFromJamfOnReject: deleteAfterDownload,
                dismiss: { importedCapture = nil }
            )
        }
        .alert("Reviewed, but not deleted from Jamf",
               isPresented: Binding(get: { harvestNotice != nil }, set: { if !$0 { harvestNotice = nil } })) {
            Button("OK") { harvestNotice = nil }
        } message: {
            Text(harvestNotice ?? "")
        }
        .alert("Couldn't import capture",
               isPresented: Binding(get: { importError != nil }, set: { if !$0 { importError = nil } })) {
            Button("OK") { importError = nil }
        } message: {
            Text(importError ?? "")
        }
        .sheet(item: $composerIntent, onDismiss: {
            // A prefilled composer that closed without saving keeps the
            // harvested file on the record and the capture waiting.
            harvestAfterImport = nil
            importInFlight = nil
        }) { intent in
            DefinitionComposerSheet(model: model, intent: intent,
                                    onSaved: { definitionID in
                                        flash(definitionID)
                                        completeImport(definitionIDs: [definitionID])
                                    },
                                    dismiss: { composerIntent = nil })
        }
        .alert(deleteTitle,
               isPresented: Binding(get: { !deleteCandidates.isEmpty }, set: { if !$0 { deleteCandidates = [] } })) {
            Button("Cancel", role: .cancel) { deleteCandidates = [] }
            Button(deleteCandidates.count > 1 ? "Delete \(deleteCandidates.count)" : "Delete", role: .destructive) { confirmDelete() }
        } message: {
            Text(deleteMessage)
        }
    }

    /// The Fleet Observer reviewed a capture in place and pressed Create
    /// Definition on a single attempt: open the pre-filled composer here. The
    /// in-flight identity + harvest target come along so the review ledger
    /// records `.imported` (and the Jamf record is cleared) when the composer
    /// saves — exactly as the file-import path does.
    private func consumePendingComposerPrefill() {
        guard let prefill = model.pendingComposerPrefill else { return }
        model.pendingComposerPrefill = nil
        importInFlight = (prefill.fileName, prefill.origin)
        harvestAfterImport = prefill.harvestFrom
        Task { @MainActor in
            composerIntent = .createPrefilled(prefill.draft)
        }
    }

    /// The Fleet Observer's Review Capture sheet created a BATCH of definitions
    /// directly (no composer). They are already persisted; here we record the
    /// review ledger as `.imported` and run the harvest delete — so a failed
    /// delete surfaces its notice on THIS screen — then flash the newest row.
    private func consumePendingImportCompletion() {
        guard let completion = model.pendingImportCompletion else { return }
        model.pendingImportCompletion = nil
        importInFlight = (completion.fileName, completion.origin)
        harvestAfterImport = completion.harvestFrom
        completeImport(definitionIDs: completion.definitionIDs)
        if let last = completion.definitionIDs.last { flash(last) }
    }

    /// The import committed (a definition exists): record it in the review
    /// ledger — it stops counting as an upload waiting, whatever happens to
    /// the Jamf record — and only now remove the harvested capture from the
    /// device's record (harvest switch).
    private func completeImport(definitionIDs: [String]) {
        guard let inFlight = importInFlight else { return }
        importInFlight = nil
        if let origin = inFlight.origin {
            model.fleet.reviews.record(origin, decision: .imported, definitionIDs: definitionIDs)
        } else {
            model.fleet.reviews.record(fileName: inFlight.fileName, decision: .imported, definitionIDs: definitionIDs)
        }
        guard let upload = harvestAfterImport else { return }
        harvestAfterImport = nil
        Task { await deleteFromRecord(upload, verb: "imported") }
    }

    /// Reject (Import Capture sheet): reviewed, no definition. Recorded in the
    /// ledger against the upload it came from (or the file name), and — with
    /// the Fleet Observer harvest switch on — removed from the Jamf record.
    private func rejectImport() {
        guard let inFlight = importInFlight else { return }
        importInFlight = nil
        harvestAfterImport = nil
        if let origin = inFlight.origin {
            model.fleet.reviews.record(origin, decision: .rejected)
            if deleteAfterDownload {
                Task { await deleteFromRecord(origin, verb: "rejected") }
            }
        } else {
            model.fleet.reviews.record(fileName: inFlight.fileName, decision: .rejected)
        }
    }

    /// Post-import / post-reject delete. Uses the same connection the Fleet
    /// Observer loads with (Settings, else the config-profile credentials).
    private func deleteFromRecord(_ upload: FleetUpload, verb: String) async {
        do {
            try await model.fleet.deleteUpload(upload, connection: model.effectiveJamfConnection)
        } catch {
            if error is CancellationError { return }
            harvestNotice = "\(upload.fileName) was \(verb), but removing it from \(upload.deviceName)'s record failed: \(FleetObserverModel.describe(error)) It is marked \(verb) here; delete it from Fleet Observer → Uploads later."
        }
    }

    /// Opens the file importer if File ▸ Import Capture… asked for it. On the
    /// next run-loop turn so a freshly appeared view is attached to its window
    /// before it presents.
    private func consumeCaptureImportRequest() {
        guard model.captureImportPending else { return }
        model.captureImportPending = false
        Task { @MainActor in importingCapture = true }
    }

    /// New Definition (⌘N): the kind is picked up front so the composer opens
    /// already shaped — mirroring the ⊕ menu vocabulary on the Rules screen.
    private var newDefinitionMenu: some View {
        Menu {
            Button {
                composerIntent = .create(kind: .sudo)
            } label: { Label("Sudo command", systemImage: "terminal") }
                .keyboardShortcut("n", modifiers: .command)
            Button {
                composerIntent = .create(kind: .authuri)
            } label: { Label("Authorization right", systemImage: "lock") }
            // Per-app rules are disabled in 0.9.0: listed, not offered.
            Button {
                composerIntent = .create(kind: .appIdentity)
            } label: {
                Label(AppIdentityAvailability.enabled ? "App Identity" : "App Identity (unavailable in 0.9.0)",
                      systemImage: "app.badge.checkmark")
            }
            .disabled(!AppIdentityAvailability.enabled)
            .help(AppIdentityAvailability.enabled ? "" : AppIdentityAvailability.unavailableNote)
        } label: {
            // Colour set ON the label: the borderless menu style paints its
            // label in its own tint otherwise, which read as light text on the
            // accent fill ("entirely too bright").
            Label("New Definition", systemImage: "plus")
                .foregroundStyle(Theme.emerald)
        }
        .menuStyle(.borderlessButton).fixedSize()
        // Same tinted chrome as the "New Rule" / "New Policy" buttons on the
        // sibling screens (a ButtonStyle can't be applied to a Menu).
        .tintedControlChrome()
    }

    // MARK: Filter bar

    private var filterBar: some View {
        HStack(spacing: Spacing.md) {
            selectAllCheckbox
            HStack(spacing: Spacing.sm) {
                Image(systemName: "magnifyingglass").font(.system(size: 12)).foregroundStyle(Theme.textMuted)
                TextField("Search definitions, commands, rights…", text: $query)
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

    /// Header checkbox over the VISIBLE rows: checks them all, or clears
    /// them when every visible row is already checked. Shows a dash while
    /// only some are checked.
    private var selectAllCheckbox: some View {
        let visible = rows.map(\.id)
        let checkedVisible = visible.filter(checkedIDs.contains).count
        let all = !visible.isEmpty && checkedVisible == visible.count
        let symbol = all ? "checkmark.square.fill" : (checkedVisible > 0 ? "minus.square.fill" : "square")
        return Button {
            if all { checkedIDs.subtract(visible) } else { checkedIDs.formUnion(visible) }
        } label: {
            Image(systemName: symbol)
                .font(.system(size: 16))
                .foregroundStyle(checkedVisible > 0 ? Theme.emerald : Theme.textMuted)
                .frame(width: 20, height: 20)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(visible.isEmpty)
        .help(all ? "Deselect all" : "Select all \(visible.count) visible \(visible.count == 1 ? "definition" : "definitions")")
        .accessibilityLabel(all ? "Deselect all definitions" : "Select all visible definitions")
    }

    // MARK: Selection bar

    /// Batch actions for the checkbox selection, in the Intel-bar segmented
    /// idiom. Duplicate is single-target only (it opens the copy for
    /// editing), so it is disabled unless exactly one definition is checked.
    private var selectionBar: some View {
        let count = checkedIDs.count
        let hidden = checkedIDs.subtracting(rows.map(\.id)).count
        return HStack(spacing: Spacing.md) {
            Text("\(count) selected")
                .font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            if hidden > 0 {
                Text("· \(hidden) hidden by the current filter")
                    .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
            }
            Spacer()
            SegmentedActionBar(actions: [
                .init(id: "duplicate", title: "Duplicate", systemImage: "plus.square.on.square",
                      isDisabled: count != 1,
                      help: count == 1 ? "Duplicate the selected definition (the copy starts unused)"
                                       : "Select exactly one definition to duplicate") { duplicateChecked() },
                .init(id: "delete", title: count == 1 ? "Delete" : "Delete \(count)", systemImage: "trash",
                      isDestructive: true,
                      help: "Delete the selected \(count == 1 ? "definition" : "definitions") — references are stripped from every rule using them") { requestDeleteChecked() },
                .init(id: "clear", title: "Deselect", systemImage: "xmark") { checkedIDs.removeAll() },
            ])
        }
        .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
        .background(Theme.accentDim.opacity(0.6), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.emerald.opacity(0.3), lineWidth: 1))
        .transition(.opacity.combined(with: .move(edge: .top)))
    }

    private func toggleChecked(_ id: String) {
        if checkedIDs.contains(id) { checkedIDs.remove(id) } else { checkedIDs.insert(id) }
    }

    private func duplicateChecked() {
        guard checkedIDs.count == 1, let id = checkedIDs.first,
              let copyID = model.duplicateDefinition(id: id) else { return }
        // The copy becomes the selection (Finder's ⌘D convention) and flashes.
        checkedIDs = [copyID]
        flash(copyID)
    }

    private func requestDeleteChecked() {
        let candidates = model.definitions.filter { checkedIDs.contains($0.id) }
        guard !candidates.isEmpty else { return }
        deleteCandidates = candidates
    }

    // MARK: List

    private var listArea: some View {
        ScrollViewReader { proxy in
            Group {
                if rows.isEmpty {
                    noMatchState
                } else {
                    ScrollView {
                        LazyVStack(spacing: 6) {
                            ForEach(rows) { definition in
                                definitionRow(definition)
                            }
                        }
                        .padding(.bottom, Spacing.xl)
                    }
                    .scrollIndicators(.never)
                    .focusable()
                    .focusEffectDisabled()
                    .onMoveCommand { direction in moveSelection(direction) }
                    .onDeleteCommand { deleteSelection() }
                    .onKeyPress(.return) { openSelection() }
                    .onChange(of: flashRowID) { _, new in
                        if let new { withAnimation { proxy.scrollTo(new, anchor: .center) } }
                    }
                    .onChange(of: selectedRowID) { _, new in
                        if let new { proxy.scrollTo(new, anchor: nil) }
                    }
                }
            }
            .onAppear { consumePendingFocus(proxy: proxy) }
            .onChange(of: model.pendingFocus) { _, _ in consumePendingFocus(proxy: proxy) }
            .onChange(of: composerIntent) { wasPresented, isPresented in
                // A queued deep link (fired while the composer was up) runs
                // once it closes.
                if wasPresented != nil && isPresented == nil { consumePendingFocus(proxy: proxy) }
            }
        }
    }

    // MARK: Row

    private func definitionRow(_ definition: RuleDefinition) -> some View {
        let isAuthURI = definition.kind == .authuri
        let kind = definition.authoringKind
        let tint: Color = kind == .sudo ? Theme.emerald : Theme.info
        let selected = selectedRowID == definition.id || flashRowID == definition.id
        let usedBy = model.rulesUsing(definitionID: definition.id).count
        let unknown = isAuthURI
            && (definition.authURI.map { model.authRights.existence(of: $0) == false } ?? false)
        let checked = checkedIDs.contains(definition.id)

        return HStack(spacing: Spacing.sm) {
            // Checkbox for the batch selection — a sibling of the row button,
            // never nested inside it, so it reliably receives the click.
            Button { toggleChecked(definition.id) } label: {
                Image(systemName: checked ? "checkmark.square.fill" : "square")
                    .font(.system(size: 16))
                    .foregroundStyle(checked ? Theme.emerald : Theme.textMuted)
                    .frame(width: 20, height: 20)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(checked ? "Deselect" : "Select for batch delete / duplicate")
            .accessibilityLabel(checked ? "Deselect \(definition.name)" : "Select \(definition.name)")

            Button {
                selectedRowID = definition.id
                composerIntent = .edit(definitionID: definition.id)
            } label: {
                HStack(spacing: Spacing.md) {
                    Image(systemName: kind.symbol)
                        .font(.system(size: 13))
                        .foregroundStyle(tint)
                        .frame(width: 32, height: 32)
                        .background(tint.opacity(0.12),
                                   in: RoundedRectangle(cornerRadius: 8, style: .continuous))

                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: Spacing.sm) {
                            Text(definition.name.isEmpty ? "(unnamed)" : definition.name)
                                .font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.textPrimary).lineLimit(1)
                            if unknown {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .font(.system(size: 10)).foregroundStyle(Theme.warning)
                                    .help("No such authorization right on this Mac")
                            }
                            if kind == .appIdentity, !AppIdentityAvailability.enabled {
                                StatusBadge("Disabled in 0.9.0", tone: .degraded, symbol: "nosign")
                                    .help(AuthURIIdentityScope.disabledValidationMessage)
                            } else if kind == .appIdentity, let right = definition.authURI,
                               AuthURIIdentityScopeRegistry.current.state(for: right) == .provisional {
                                StatusBadge(AuthURIIdentityEligibility.provisional.label, tone: .pending, symbol: "flask.fill")
                            }
                        }
                        Text(target(for: definition)).font(.mono(10)).foregroundStyle(Theme.textMuted).lineLimit(1)
                    }

                    Spacer()

                    if !isAuthURI {
                        matchStyleChip(definition.matchType ?? .exact)
                    }

                    if usedBy == 0 {
                        StatusBadge("Unused", tone: .pending, symbol: "tray")
                            .help("No rule references this definition — it matches nothing until one does")
                    } else {
                        Text("Used by \(usedBy) \(usedBy == 1 ? "rule" : "rules")")
                            .font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textSecondary)
                            .frame(minWidth: 96, alignment: .trailing)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            Image(systemName: "chevron.right").font(.system(size: 11, weight: .semibold)).foregroundStyle(Theme.textMuted)
        }
        .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(selected ? Theme.accentDim : (checked ? Theme.emerald.opacity(0.06) : Theme.surface),
                    in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous)
            .strokeBorder(selected ? Theme.emerald.opacity(0.4) : (checked ? Theme.emerald.opacity(0.25) : Theme.hairline), lineWidth: 1))
        .id(definition.id)
        .help(definition.detail)
        .contextMenu {
            Button("Edit Definition…") {
                selectedRowID = definition.id
                composerIntent = .edit(definitionID: definition.id)
            }
            Button(checked ? "Deselect" : "Select") { toggleChecked(definition.id) }
            Button("Duplicate") {
                if let copyID = model.duplicateDefinition(id: definition.id) { flash(copyID) }
            }
            Button("Delete Definition…", role: .destructive) { deleteCandidates = [definition] }
        }
    }

    /// Compact match-style chip for sudo definitions — the one matcher fact
    /// worth surfacing without opening the composer.
    private func matchStyleChip(_ matchType: MatchType) -> some View {
        Text(chipLabel(for: matchType))
            .font(.system(size: 10, weight: .medium)).foregroundStyle(Theme.textSecondary)
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background(Theme.elevated.opacity(0.8), in: Capsule())
            .overlay(Capsule().strokeBorder(Theme.hairline, lineWidth: 1))
    }

    private func chipLabel(for matchType: MatchType) -> String {
        switch matchType {
        case .exact: return "exact path"
        case .glob: return "wildcard"
        case .regex: return "regex"
        case .prefixRegex: return "prefix + args"
        case .any: return "any command"
        }
    }

    // MARK: Empty states

    private var emptyLibraryState: some View {
        VStack(spacing: Spacing.md) {
            Image(systemName: "books.vertical").font(.system(size: 40)).foregroundStyle(Theme.textMuted)
            Text("No definitions yet")
                .font(.system(size: 16, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            Text("Definitions are the matchers rules share — a sudo command pattern or a macOS authorization right. Create one here, then reference it from any rule.")
                .font(.system(size: 12)).foregroundStyle(Theme.textMuted)
            HStack(spacing: Spacing.sm) {
                Button { composerIntent = .create(kind: .sudo) } label: {
                    Label("Sudo command", systemImage: "terminal.fill")
                }
                .buttonStyle(.emerald)
                Button { composerIntent = .create(kind: .authuri) } label: {
                    Label("Authorization right", systemImage: "lock.fill")
                }
                .buttonStyle(.ghost)
                if AppIdentityAvailability.enabled {
                    Button { composerIntent = .create(kind: .appIdentity) } label: {
                        Label("App Identity", systemImage: "app.badge.checkmark")
                    }
                    .buttonStyle(.ghost)
                }
            }
            .padding(.top, Spacing.xs)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .card()
    }

    private var noMatchState: some View {
        VStack(spacing: Spacing.md) {
            Image(systemName: "line.3.horizontal.decrease.circle").font(.system(size: 40)).foregroundStyle(Theme.textMuted)
            Text("No definitions match").font(.system(size: 16, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            Text("Adjust the search or filters above.").font(.system(size: 12)).foregroundStyle(Theme.textMuted)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .card()
    }

    // MARK: Selection + keyboard

    private func moveSelection(_ direction: MoveCommandDirection) {
        let ids = rows.map(\.id)
        guard !ids.isEmpty else { return }
        // A selection that's no longer visible (deleted, filtered out) must not
        // dead-end the arrows — fall back to the ends of the visible list.
        let currentIndex = selectedRowID.flatMap { ids.firstIndex(of: $0) }
        switch direction {
        case .down:
            if let index = currentIndex {
                if index + 1 < ids.count { selectedRowID = ids[index + 1] }
            } else {
                selectedRowID = ids.first
            }
        case .up:
            if let index = currentIndex {
                if index > 0 { selectedRowID = ids[index - 1] }
            } else {
                selectedRowID = ids.last
            }
        default:
            break
        }
    }

    private func openSelection() -> KeyPress.Result {
        guard let selected = selectedRowID, rows.contains(where: { $0.id == selected }) else { return .ignored }
        composerIntent = .edit(definitionID: selected)
        return .handled
    }

    /// ⌫: the checkbox selection when there is one, else the focused row.
    private func deleteSelection() {
        if !checkedIDs.isEmpty {
            requestDeleteChecked()
            return
        }
        guard let selected = selectedRowID,
              let definition = rows.first(where: { $0.id == selected }) else { return }
        deleteCandidates = [definition]
    }

    // MARK: Delete

    private var deleteTitle: String {
        switch deleteCandidates.count {
        case 0: return ""
        case 1:
            let one = deleteCandidates[0]
            return "Delete “\(one.name.isEmpty ? one.id : one.name)”?"
        default: return "Delete \(deleteCandidates.count) definitions?"
        }
    }

    /// Referential warning: deleting a definition also strips its reference
    /// from every rule using it (``PolicyBuilderModel/deleteDefinitions(ids:)``
    /// cascades), so the affected rules are named up front — the union over
    /// every candidate for a batch.
    private var deleteMessage: String {
        guard !deleteCandidates.isEmpty else { return "" }
        var seen = Set<String>()
        let users = deleteCandidates
            .flatMap { model.rulesUsing(definitionID: $0.id) }
            .filter { seen.insert($0.id).inserted }
        let these = deleteCandidates.count == 1 ? "this definition" : "these definitions"
        // Name what is about to go — the checked set can include rows the
        // current filter hides, so the confirmation must be verifiable.
        let listed = deleteCandidates.prefix(5).map { $0.name.isEmpty ? $0.id : $0.name }.joined(separator: ", ")
        let more = deleteCandidates.count > 5 ? " and \(deleteCandidates.count - 5) more" : ""
        let roster = deleteCandidates.count == 1 ? "" : " (\(listed)\(more))"
        guard !users.isEmpty else {
            return "No rules reference \(these)\(roster), so enforcement is unchanged."
        }
        let names = users.map { $0.name.isEmpty ? $0.id : $0.name }.joined(separator: ", ")
        let matcher = deleteCandidates.count == 1 ? "this matcher" : "these matchers"
        return "Deleting \(these)\(roster) also removes \(matcher) from \(users.count == 1 ? "1 rule" : "\(users.count) rules"): \(names). A rule left with no definitions matches nothing and compiles to nothing."
    }

    private func confirmDelete() {
        let ids = Set(deleteCandidates.map(\.id))
        guard !ids.isEmpty else { return }
        // Move the keyboard selection to a surviving neighbor before the
        // rows disappear.
        let visible = rows.map(\.id)
        if let current = selectedRowID, ids.contains(current), let index = visible.firstIndex(of: current) {
            selectedRowID = visible[(index + 1)...].first { !ids.contains($0) }
                ?? visible[..<index].last { !ids.contains($0) }
        }
        model.deleteDefinitions(ids: ids)
        checkedIDs.subtract(ids)
        deleteCandidates = []
    }

    // MARK: Deep links + save feedback

    /// Honors ``PolicyBuilderModel/pendingFocus`` for `.definition` — scroll
    /// to and flash a definition another screen just sent here. Deferred
    /// while the composer is up; re-runs when it closes.
    private func consumePendingFocus(proxy: ScrollViewProxy) {
        guard case .definition(let definitionID) = model.pendingFocus,
              composerIntent == nil else { return }
        model.pendingFocus = nil
        guard model.definition(id: definitionID) != nil else { return }
        flash(definitionID)
        proxy.scrollTo(definitionID, anchor: .center)
    }

    /// Emerald-flash a row. If the active filters would hide it, relax them —
    /// a save or duplicate must never look like a silent failure.
    private func flash(_ rowID: String) {
        if !rows.contains(where: { $0.id == rowID }) {
            query = ""
            kindFilter = .all
        }
        selectedRowID = rowID
        flashRowID = rowID
        Task {
            try? await Task.sleep(for: .seconds(1))
            if flashRowID == rowID { flashRowID = nil }
        }
    }

    /// Drops a selection that points at a definition that no longer exists
    /// (deleted elsewhere) — a stale selection otherwise feeds a dead id to
    /// the composer on Return.
    private func pruneStaleSelection() {
        if let selected = selectedRowID, model.definition(id: selected) == nil {
            selectedRowID = nil
        }
        let live = Set(model.definitions.map(\.id))
        if !checkedIDs.isSubset(of: live) { checkedIDs.formIntersection(live) }
    }
}
