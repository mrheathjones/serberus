import PolicyBuilderCore
import PrivMgrCore
import SwiftUI

/// The policy library: every authored ``Policy``, with create / duplicate /
/// delete / edit / export / publish. Two presentations share one state:
/// **Cards** (summary + a labelled action bar per policy) and a **List** (one
/// row per policy with a checkbox multi-selection driving batch Publish /
/// Export / Duplicate / Delete — the same selection anatomy as the Rules and
/// Definitions screens). The switch is remembered across launches.
///
/// Policies are mechanism-agnostic containers of shared library rules — the
/// sudo/authuri split happens at compile time — so both presentations
/// summarize what the policy *compiles to* (enabled rules, mechanisms
/// covered, validation) rather than a fixed rule type. There is deliberately
/// no per-policy on/off switch or scope/conditions here: a policy is
/// delivered and scoped by MDM, so whether it is live on a Mac is the MDM
/// assignment's call. Backed by the persisted store, so policies authored
/// here survive restarts.
struct PolicyLibraryView: View {
    @Bindable var model: PolicyBuilderModel
    /// Cards or list — persisted so the operator's choice sticks.
    @AppStorage("policies.viewMode") private var viewModeRaw = ViewMode.cards.rawValue
    @State private var showingWizard = false
    /// Policies awaiting the delete confirmation (one from a card / row /
    /// the keyboard, several from the list's checkbox selection).
    @State private var deleteCandidateIDs: [String] = []
    @State private var editorIntent: EditorIntent?
    @State private var exportingPolicy: ExportTarget?
    /// Card/row currently highlighted after a deep link, create, or
    /// duplicate — a mutation must never look like a silent failure.
    @State private var flashPolicyID: String?
    /// List view: keyboard focus row (distinct from the checkbox selection).
    @State private var selectedPolicyID: String?
    /// List view: checkbox multi-selection driving the batch bar.
    @State private var checkedIDs: Set<String> = []

    private enum ViewMode: String, CaseIterable {
        case cards, list
    }

    private var viewMode: ViewMode { ViewMode(rawValue: viewModeRaw) ?? .cards }

    private var viewModeBinding: Binding<ViewMode> {
        Binding(get: { viewMode }, set: { viewModeRaw = $0.rawValue })
    }

    /// How the details editor was opened; "Manage Rules" and "Details" share
    /// one editing surface (the details editor) so there is exactly one
    /// obvious path to every policy field.
    private enum EditorIntent: Identifiable {
        case details(policyID: String)
        case manageRules(policyID: String)

        var policyID: String {
            switch self {
            case .details(let id), .manageRules(let id): return id
            }
        }

        var focusRules: Bool {
            if case .manageRules = self { return true }
            return false
        }

        var id: String { (focusRules ? "rules::" : "details::") + policyID }
    }

    /// Identifiable wrapper so a policy id can drive the export `.sheet(item:)`.
    private struct ExportTarget: Identifiable { let id: String }

    private var policies: [Policy] { model.policies }
    private var visiblePolicyIDs: [String] { policies.map(\.id) }
    /// Checked ids in display order (the batch actions run in this order).
    private var orderedCheckedIDs: [String] { visiblePolicyIDs.filter(checkedIDs.contains) }

    private var subtitle: String {
        let attached = policies.reduce(0) { $0 + $1.rules.count }
        return "\(policies.count) \(policies.count == 1 ? "policy" : "policies") · \(attached) rule \(attached == 1 ? "assignment" : "assignments")"
    }

    private func displayName(_ id: String) -> String {
        guard let policy = model.policy(id: id) else { return id }
        return policy.name.isEmpty ? policy.id : policy.name
    }

    // MARK: Body

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.lg) {
            ScreenHeader("Policies", subtitle: subtitle) {
                HStack(spacing: Spacing.sm) {
                    SegmentedControl(selection: viewModeBinding,
                                     options: [.cards: "Cards", .list: "List"],
                                     label: "Policies layout")
                    Button { showingWizard = true } label: {
                        Label("New Policy", systemImage: "plus")
                    }
                    .buttonStyle(.tinted)
                    .keyboardShortcut("n", modifiers: .command)
                }
            }

            if policies.isEmpty {
                emptyState
            } else {
                switch viewMode {
                case .cards:
                    cardGrid
                case .list:
                    listHeader
                    if !checkedIDs.isEmpty {
                        selectionBar
                    }
                    policyList
                }
            }
        }
        .padding(Spacing.xl)
        .animation(.easeOut(duration: 0.15), value: checkedIDs.isEmpty)
        .onAppear {
            model.refreshDirectPublishGate()
            consumePendingFocus()
        }
        .onChange(of: model.pendingFocus) { _, _ in consumePendingFocus() }
        .onChange(of: model.policies) { _, _ in pruneStaleSelection() }
        .sheet(isPresented: $showingWizard) {
            CreatePolicyWizardView(model: model,
                                   onClose: { showingWizard = false },
                                   onCreated: { flashPolicy($0) })
        }
        .sheet(item: $editorIntent) { intent in
            PolicyDetailsEditorView(model: model,
                                    policyID: intent.policyID,
                                    focusRules: intent.focusRules) { editorIntent = nil }
        }
        .sheet(item: $exportingPolicy) { target in
            ExportSheet(model: model, policyID: target.id) { exportingPolicy = nil }
        }
        .alert(deleteTitle,
               isPresented: Binding(get: { !deleteCandidateIDs.isEmpty }, set: { if !$0 { deleteCandidateIDs = [] } })) {
            Button("Cancel", role: .cancel) { deleteCandidateIDs = [] }
            Button(deleteCandidateIDs.count > 1 ? "Delete \(deleteCandidateIDs.count)" : "Delete", role: .destructive) {
                confirmDelete()
            }
        } message: {
            Text(deleteMessage)
        }
        // The publish outcome lives on the model, so a batch that finished
        // while the operator was elsewhere still reports on return here.
        .alert(model.lastPublishSummary?.title ?? "",
               isPresented: Binding(get: { model.lastPublishSummary != nil },
                                    set: { if !$0 { model.lastPublishSummary = nil } })) {
            Button("OK", role: .cancel) { model.lastPublishSummary = nil }
        } message: {
            Text(model.lastPublishSummary?.message ?? "")
        }
    }

    // MARK: Cards

    private var cardGrid: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 380, maximum: 560), spacing: Spacing.lg)],
                          spacing: Spacing.lg) {
                    ForEach(policies) { policy in
                        policyCard(policy)
                    }
                }
                .padding(.bottom, Spacing.xl)
            }
            .scrollIndicators(.never)
            .onChange(of: flashPolicyID) { _, new in
                if let new { withAnimation { proxy.scrollTo(new, anchor: .center) } }
            }
        }
    }

    /// Everything a card or row summarizes about a policy, computed in one
    /// pass so the compiler runs once per policy (validation reports compile
    /// again — libraries are small, so clarity wins over caching here).
    private struct CardStats {
        var assignmentCount: Int
        var enabledResolvedCount: Int
        var allowCount: Int
        var denyCount: Int
        var coversSudo: Bool
        var coversAuthURI: Bool
        var reports: [ValidationReport]
    }

    private func stats(for policy: Policy) -> CardStats {
        // Counts reflect what actually compiles: enabled assignments that
        // resolve to a library rule. Disabled/dangling assignments still show
        // up in the "N of M rules enabled" line via assignmentCount.
        let enabledRules = policy.rules.filter(\.enabled).compactMap { model.rule(id: $0.ruleID) }
        let kinds = Set(enabledRules.flatMap { model.definitions(in: $0).map(\.kind) })
        return CardStats(
            assignmentCount: policy.rules.count,
            enabledResolvedCount: enabledRules.count,
            allowCount: enabledRules.filter { $0.action == .allow }.count,
            denyCount: enabledRules.filter { $0.action == .deny }.count,
            coversSudo: kinds.contains(.sudo),
            coversAuthURI: kinds.contains(.authuri),
            reports: model.validationReport(forPolicy: policy.id)
        )
    }

    private func policyCard(_ policy: Policy) -> some View {
        let stats = self.stats(for: policy)

        return VStack(alignment: .leading, spacing: Spacing.md) {
            HStack(spacing: Spacing.md) {
                Image(systemName: "square.stack.3d.up")
                    .font(.system(size: 14))
                    .foregroundStyle(Theme.emerald)
                    .frame(width: 34, height: 34)
                    .background(Theme.accentDim,
                               in: RoundedRectangle(cornerRadius: 9, style: .continuous))
                VStack(alignment: .leading, spacing: 2) {
                    Text(policy.name)
                        .font(.system(size: 15, weight: .semibold)).foregroundStyle(Theme.textPrimary)
                        .lineLimit(1)
                    Text(policy.id).font(.mono(10)).foregroundStyle(Theme.textMuted).lineLimit(1)
                }
                Spacer()
            }

            if !policy.summary.isEmpty {
                Text(policy.summary).font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true).lineLimit(3)
            }

            Divider().overlay(Theme.hairline)

            HStack(spacing: Spacing.sm) {
                StatusBadge("\(stats.allowCount) allow", tone: .healthy, symbol: "checkmark.shield.fill")
                if stats.denyCount > 0 {
                    StatusBadge("\(stats.denyCount) deny", tone: .degraded, symbol: "xmark.shield.fill")
                }
                if stats.coversSudo { mechanismChip("terminal.fill", "Sudo", Theme.emerald) }
                if stats.coversAuthURI { mechanismChip("lock.fill", "Auth rights", Theme.info) }
                Spacer()
                validationBadge(stats.reports)
            }

            HStack(spacing: Spacing.sm) {
                Text("\(stats.enabledResolvedCount) of \(stats.assignmentCount) \(stats.assignmentCount == 1 ? "rule" : "rules") enabled")
                    .font(.system(size: 10)).foregroundStyle(Theme.textMuted)
                Spacer()
                Text("v\(policy.policyVersion) · priority \(policy.profilePriority)")
                    .font(.system(size: 10)).foregroundStyle(Theme.textMuted)
            }

            actionBar(policy)
        }
        .card()
        .overlay(
            RoundedRectangle(cornerRadius: Radius.lg, style: .continuous)
                .strokeBorder(Theme.emerald, lineWidth: 2)
                .opacity(flashPolicyID == policy.id ? 1 : 0)
        )
        .animation(.easeInOut(duration: 0.35), value: flashPolicyID)
        .id(policy.id)
    }

    /// The card's actions in the Intel bar's button-picker idiom, every
    /// segment labelled (icon + title). Two groups: the editing entry points
    /// (Manage Rules / Details) and the lifecycle actions (Publish / Export /
    /// Duplicate / Delete). They render as ONE track when the card is wide
    /// enough and fall back to two stacked tracks on narrow cards — titles
    /// never truncate. Publish appears only where the admin Mac's config
    /// profile turns direct publish on (`commanderPublishEnabled`); it is
    /// disabled (with the reason as its tooltip) until the policy is
    /// publishable, and spins while in flight.
    private func actionBar(_ policy: Policy) -> some View {
        let editing = editingActions(policy)
        let lifecycle = lifecycleActions(policy)
        return ViewThatFits(in: .horizontal) {
            SegmentedActionBar(actions: editing + lifecycle)
            VStack(alignment: .leading, spacing: Spacing.xs) {
                SegmentedActionBar(actions: editing)
                SegmentedActionBar(actions: lifecycle)
            }
        }
    }

    private func editingActions(_ policy: Policy) -> [SegmentedActionBar.Action] {
        [
            .init(id: "rules", title: "Manage Rules", systemImage: "list.bullet") {
                editorIntent = .manageRules(policyID: policy.id)
            },
            .init(id: "details", title: "Details", systemImage: "pencil") {
                editorIntent = .details(policyID: policy.id)
            },
        ]
    }

    private func lifecycleActions(_ policy: Policy) -> [SegmentedActionBar.Action] {
        let publishing = model.publishingPolicyIDs.contains(policy.id)
        var actions: [SegmentedActionBar.Action] = []
        if model.directPublishEnabled {
            let blocker = model.publishBlocker(id: policy.id)
            actions.append(.init(id: "publish", title: "Publish", systemImage: "antenna.radiowaves.left.and.right",
                                 isDisabled: publishing || blocker != nil,
                                 isBusy: publishing,
                                 help: blocker ?? publishHelp) {
                runDirectPublish(policy.id)
            })
        }
        actions.append(.init(id: "export", title: "Export", systemImage: "arrow.up.doc",
                             help: "Save Jamf Schema / .mobileconfig / .plist for this policy") {
            exportingPolicy = ExportTarget(id: policy.id)
        })
        actions.append(.init(id: "duplicate", title: "Duplicate", systemImage: "plus.square.on.square",
                             help: "Duplicate this policy (the copy starts with the same rule assignments)") {
            duplicate(policy.id)
        })
        actions.append(.init(id: "delete", title: "Delete", systemImage: "trash", isDestructive: true,
                             help: "Delete this policy from the local library (its rules stay in the shared library)") {
            deleteCandidateIDs = [policy.id]
        })
        return actions
    }

    private var publishHelp: String {
        "Publish to \(model.mdm.vendor.displayName) — create or update the policy's profile via the API (the console shows its rules blank; prefer Export → Save Jamf Schema for console-editable rules)"
    }

    // MARK: List

    /// Select-all over the list + a caption. The list has no filters, so
    /// "visible" is the whole library.
    private var listHeader: some View {
        HStack(spacing: Spacing.md) {
            selectAllCheckbox
            Text(checkedIDs.isEmpty ? "Select policies for batch actions" : "Select all")
                .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
            Spacer()
        }
        .padding(.horizontal, Spacing.md)
    }

    private var selectAllCheckbox: some View {
        let visible = visiblePolicyIDs
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
        .help(all ? "Deselect all" : "Select all \(visible.count) \(visible.count == 1 ? "policy" : "policies")")
        .accessibilityLabel(all ? "Deselect all policies" : "Select all policies")
    }

    /// Batch actions for the checkbox selection, in the Intel-bar segmented
    /// idiom: Publish (only where the direct-publish gate is on; enabled when
    /// EVERY selected policy is publishable — the tooltip names the first
    /// blocker otherwise), Export and Duplicate (single-target, so exactly one
    /// must be checked), Delete N, Deselect.
    private var selectionBar: some View {
        let ids = orderedCheckedIDs
        let count = ids.count
        var actions: [SegmentedActionBar.Action] = []
        if model.directPublishEnabled {
            // One run at a time: the bar is disabled while ANY publish is in
            // flight (publishBlocker says so), and spins when it is one of ours.
            let busy = !model.publishingPolicyIDs.isDisjoint(with: checkedIDs)
            let firstBlocker = ids.lazy.compactMap { id in model.publishBlocker(id: id).map { (id, $0) } }.first
            actions.append(.init(id: "publish",
                                 title: count == 1 ? "Publish" : "Publish \(count)",
                                 systemImage: "antenna.radiowaves.left.and.right",
                                 isDisabled: busy || firstBlocker != nil,
                                 isBusy: busy,
                                 help: firstBlocker.map { "\(displayName($0.0)): \($0.1)" }
                                     ?? "Publish the selected \(count == 1 ? "policy" : "\(count) policies") to \(model.mdm.vendor.displayName) via the API — one profile each, named Serberus — <policy id> (the console shows the rules blank)") {
                publishChecked()
            })
        }
        actions.append(.init(id: "export", title: "Export", systemImage: "arrow.up.doc",
                             isDisabled: count != 1,
                             help: count == 1 ? "Save Jamf Schema / .mobileconfig / .plist for the selected policy"
                                              : "Select exactly one policy to export") {
            if count == 1, let id = ids.first { exportingPolicy = ExportTarget(id: id) }
        })
        actions.append(.init(id: "duplicate", title: "Duplicate", systemImage: "plus.square.on.square",
                             isDisabled: count != 1,
                             help: count == 1 ? "Duplicate the selected policy (the copy keeps the same rule assignments)"
                                              : "Select exactly one policy to duplicate") {
            duplicateChecked()
        })
        actions.append(.init(id: "delete", title: count == 1 ? "Delete" : "Delete \(count)", systemImage: "trash",
                             isDestructive: true,
                             help: "Delete the selected \(count == 1 ? "policy" : "policies") from the local library (their rules stay in the shared library)") {
            deleteCandidateIDs = ids
        })
        actions.append(.init(id: "clear", title: "Deselect", systemImage: "xmark") { checkedIDs.removeAll() })

        return HStack(spacing: Spacing.md) {
            Text("\(count) selected")
                .font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            Spacer()
            SegmentedActionBar(actions: actions)
        }
        .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
        .background(Theme.accentDim.opacity(0.6), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.emerald.opacity(0.3), lineWidth: 1))
        .transition(.opacity.combined(with: .move(edge: .top)))
    }

    private var policyList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 6) {
                    ForEach(policies) { policy in
                        policyRow(policy)
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
            .onChange(of: flashPolicyID) { _, new in
                if let new { withAnimation { proxy.scrollTo(new, anchor: .center) } }
            }
            .onChange(of: selectedPolicyID) { _, new in
                if let new { proxy.scrollTo(new, anchor: nil) }
            }
        }
    }

    private func policyRow(_ policy: Policy) -> some View {
        let stats = self.stats(for: policy)
        let checked = checkedIDs.contains(policy.id)
        let selected = selectedPolicyID == policy.id || flashPolicyID == policy.id
        let publishing = model.publishingPolicyIDs.contains(policy.id)

        return HStack(spacing: Spacing.sm) {
            // Checkbox for the batch selection — a sibling of the row button,
            // never nested inside it, so it reliably receives the click.
            Button { toggleChecked(policy.id) } label: {
                Image(systemName: checked ? "checkmark.square.fill" : "square")
                    .font(.system(size: 16))
                    .foregroundStyle(checked ? Theme.emerald : Theme.textMuted)
                    .frame(width: 20, height: 20)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(checked ? "Deselect" : "Select for batch publish / export / duplicate / delete")
            .accessibilityLabel(checked ? "Deselect \(policy.name)" : "Select \(policy.name)")

            Button {
                selectedPolicyID = policy.id
                editorIntent = .details(policyID: policy.id)
            } label: {
                HStack(spacing: Spacing.md) {
                    Image(systemName: "square.stack.3d.up")
                        .font(.system(size: 13))
                        .foregroundStyle(Theme.emerald)
                        .frame(width: 32, height: 32)
                        .background(Theme.accentDim, in: RoundedRectangle(cornerRadius: 8, style: .continuous))

                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: Spacing.sm) {
                            Text(policy.name.isEmpty ? policy.id : policy.name)
                                .font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.textPrimary).lineLimit(1)
                            if publishing {
                                ProgressView().controlSize(.mini)
                            }
                        }
                        Text(policy.summary.isEmpty ? policy.id : policy.summary)
                            .font(policy.summary.isEmpty ? .mono(10) : .system(size: 11))
                            .foregroundStyle(Theme.textMuted).lineLimit(1)
                    }

                    Spacer()

                    Text("\(stats.enabledResolvedCount) of \(stats.assignmentCount) \(stats.assignmentCount == 1 ? "rule" : "rules")")
                        .font(.system(size: 11))
                        .foregroundStyle(stats.enabledResolvedCount == 0 ? Theme.warning : Theme.textSecondary)
                        .help(stats.enabledResolvedCount == 0
                              ? "No enabled rule resolves to a definition — this policy compiles to nothing"
                              : "Enabled assignments that resolve to a library rule")
                    if stats.coversSudo { mechanismChip("terminal.fill", "Sudo", Theme.emerald) }
                    if stats.coversAuthURI { mechanismChip("lock.fill", "Auth rights", Theme.info) }
                    StatusBadge("\(stats.allowCount) allow", tone: .healthy, symbol: "checkmark.shield.fill")
                    if stats.denyCount > 0 {
                        StatusBadge("\(stats.denyCount) deny", tone: .degraded, symbol: "xmark.shield.fill")
                    }
                    validationBadge(stats.reports)
                    Text("v\(policy.policyVersion) · p\(policy.profilePriority)")
                        .font(.mono(10)).foregroundStyle(Theme.textMuted)
                        .frame(minWidth: 84, alignment: .trailing)
                        .help("Policy version \(policy.policyVersion) · priority \(policy.profilePriority)")
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
        .id(policy.id)
        .contextMenu {
            Button("Manage Rules…") {
                selectedPolicyID = policy.id
                editorIntent = .manageRules(policyID: policy.id)
            }
            Button("Details…") {
                selectedPolicyID = policy.id
                editorIntent = .details(policyID: policy.id)
            }
            Button(checked ? "Deselect" : "Select") { toggleChecked(policy.id) }
            Divider()
            if model.directPublishEnabled {
                Button("Publish to \(model.mdm.vendor.displayName)") { runDirectPublish(policy.id) }
                    .disabled(publishing || model.publishBlocker(id: policy.id) != nil)
            }
            Button("Export…") { exportingPolicy = ExportTarget(id: policy.id) }
            Button("Duplicate") { duplicate(policy.id) }
            Divider()
            Button("Delete Policy…", role: .destructive) { deleteCandidateIDs = [policy.id] }
        }
    }

    // MARK: Selection + keyboard (list)

    private func toggleChecked(_ id: String) {
        if checkedIDs.contains(id) { checkedIDs.remove(id) } else { checkedIDs.insert(id) }
    }

    private func moveSelection(_ direction: MoveCommandDirection) {
        let ids = visiblePolicyIDs
        guard !ids.isEmpty else { return }
        let currentIndex = selectedPolicyID.flatMap { ids.firstIndex(of: $0) }
        switch direction {
        case .down:
            if let index = currentIndex {
                if index + 1 < ids.count { selectedPolicyID = ids[index + 1] }
            } else {
                selectedPolicyID = ids.first
            }
        case .up:
            if let index = currentIndex {
                if index > 0 { selectedPolicyID = ids[index - 1] }
            } else {
                selectedPolicyID = ids.last
            }
        default:
            break
        }
    }

    private func openSelection() -> KeyPress.Result {
        guard let selected = selectedPolicyID, model.policy(id: selected) != nil else { return .ignored }
        editorIntent = .details(policyID: selected)
        return .handled
    }

    /// ⌫: the checkbox selection when there is one, else the focused row.
    private func deleteSelection() {
        if !checkedIDs.isEmpty {
            deleteCandidateIDs = orderedCheckedIDs
            return
        }
        guard let selected = selectedPolicyID, model.policy(id: selected) != nil else { return }
        deleteCandidateIDs = [selected]
    }

    private func duplicate(_ id: String) {
        if let copyID = model.duplicatePolicy(id: id) { flashPolicy(copyID) }
    }

    private func duplicateChecked() {
        guard checkedIDs.count == 1, let id = checkedIDs.first,
              let copyID = model.duplicatePolicy(id: id) else { return }
        // The copy becomes the selection (Finder's ⌘D convention) and flashes.
        checkedIDs = [copyID]
        flashPolicy(copyID)
    }

    /// Drops selection state pointing at policies that no longer exist.
    private func pruneStaleSelection() {
        let live = Set(model.policies.map(\.id))
        if let selected = selectedPolicyID, !live.contains(selected) { selectedPolicyID = nil }
        if !checkedIDs.isSubset(of: live) { checkedIDs.formIntersection(live) }
    }

    // MARK: Delete

    private var deleteTitle: String {
        switch deleteCandidateIDs.count {
        case 0: return ""
        case 1: return "Delete “\(displayName(deleteCandidateIDs[0]))”?"
        default: return "Delete \(deleteCandidateIDs.count) policies?"
        }
    }

    /// Names what is about to go (the checked set is verifiable) and what
    /// survives: the rules a policy references are shared, not owned.
    private var deleteMessage: String {
        guard !deleteCandidateIDs.isEmpty else { return "" }
        let listed = deleteCandidateIDs.prefix(5).map(displayName).joined(separator: ", ")
        let more = deleteCandidateIDs.count > 5 ? " and \(deleteCandidateIDs.count - 5) more" : ""
        let single = deleteCandidateIDs.count == 1
        let subject = single ? "This policy" : "These \(deleteCandidateIDs.count) policies (\(listed)\(more))"
        let rulesClause = single ? "it references stay" : "they reference stay"
        let profileClause = single
            ? "a profile that is already installed until it is removed in the MDM."
            : "profiles that are already installed until they are removed in the MDM."
        return "\(subject) will be removed from the local library. The rules \(rulesClause) in the shared library. Devices keep enforcing \(profileClause)"
    }

    private func confirmDelete() {
        let ids = Set(deleteCandidateIDs)
        guard !ids.isEmpty else { return }
        // Move the keyboard selection to a surviving neighbor before the rows
        // disappear.
        let visible = visiblePolicyIDs
        if let current = selectedPolicyID, ids.contains(current), let index = visible.firstIndex(of: current) {
            selectedPolicyID = visible[(index + 1)...].first { !ids.contains($0) }
                ?? visible[..<index].last { !ids.contains($0) }
        }
        model.deletePolicies(ids: ids)
        checkedIDs.subtract(ids)
        deleteCandidateIDs = []
    }

    // MARK: Publish

    /// Single publish — the model owns the in-flight set and the summary, so
    /// the spinner and the report survive a trip to another screen. The Task
    /// is deliberately unstructured: navigating away must not cancel a
    /// half-done publish.
    private func runDirectPublish(_ id: String) {
        guard model.publishBlocker(id: id) == nil else { return }
        Task { await model.publishPolicies(ids: [id]) }
    }

    /// Batch publish of the checked policies, in display order, one profile
    /// each (the same gated, validated path as a single publish). Runs only
    /// when every selected policy is publishable and nothing else is in
    /// flight; the model records one summary.
    private func publishChecked() {
        let ids = orderedCheckedIDs
        guard !ids.isEmpty, ids.allSatisfy({ model.publishBlocker(id: $0) == nil }) else { return }
        Task { await model.publishPolicies(ids: ids) }
    }

    // MARK: Shared chrome

    private func mechanismChip(_ symbol: String, _ text: String, _ color: Color) -> some View {
        HStack(spacing: 4) {
            Image(systemName: symbol).font(.system(size: 9))
            Text(text).font(.system(size: 10, weight: .medium))
        }
        .foregroundStyle(color)
        .padding(.horizontal, 8).padding(.vertical, 4)
        .background(color.opacity(0.12), in: Capsule())
        .overlay(Capsule().strokeBorder(color.opacity(0.3), lineWidth: 1))
    }

    /// Validation summary across the policy's compiled profiles. An empty
    /// report list means the policy compiles to nothing — surfaced distinctly
    /// from "Valid" so an inert policy is never mistaken for a healthy one.
    @ViewBuilder
    private func validationBadge(_ reports: [ValidationReport]) -> some View {
        let errors = reports.reduce(0) { $0 + $1.errors.count }
        let warnings = reports.reduce(0) { $0 + $1.warnings.count }
        if reports.isEmpty {
            StatusBadge("No compiled rules", tone: .offline, symbol: "tray")
        } else if errors > 0 {
            StatusBadge("\(errors) \(errors == 1 ? "error" : "errors")", tone: .degraded, symbol: "xmark.octagon.fill")
        } else if warnings > 0 {
            StatusBadge("\(warnings) \(warnings == 1 ? "warning" : "warnings")", tone: .pending, symbol: "exclamationmark.triangle.fill")
        } else {
            StatusBadge("Valid", tone: .healthy, symbol: "checkmark.seal.fill")
        }
    }

    private var emptyState: some View {
        VStack(spacing: Spacing.md) {
            Image(systemName: "square.stack.3d.up").font(.system(size: 40)).foregroundStyle(Theme.textMuted)
            Text("No policies yet").font(.system(size: 16, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            Text("Create your first policy to govern elevation.").font(.system(size: 12)).foregroundStyle(Theme.textMuted)
            Button { showingWizard = true } label: { Label("New Policy", systemImage: "plus") }
                .buttonStyle(.emerald).padding(.top, Spacing.xs)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .card()
    }

    // MARK: Focus

    /// Honors ``PolicyBuilderModel/pendingFocus`` — another screen deep-linked
    /// to one policy, so scroll-and-flash its card/row and open its editor.
    /// Deferred while any sheet is up so a presented editor is never yanked.
    private func consumePendingFocus() {
        guard case .policy(let id)? = model.pendingFocus else { return }
        guard editorIntent == nil, exportingPolicy == nil, !showingWizard else { return }
        model.pendingFocus = nil
        guard model.policy(id: id) != nil else { return }
        flashPolicy(id)
        editorIntent = .details(policyID: id)
    }

    /// Emerald-flash a card/row (scrolling happens via the `onChange` watchers).
    private func flashPolicy(_ id: String) {
        selectedPolicyID = id
        flashPolicyID = id
        Task {
            try? await Task.sleep(for: .seconds(1.5))
            if flashPolicyID == id { flashPolicyID = nil }
        }
    }
}
