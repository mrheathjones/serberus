import PolicyBuilderCore
import PrivMgrCore
import SwiftUI

/// Rules — the flat library of every ``PolicyRule``: searchable, filterable,
/// with create/edit/delete in place via the ``RuleComposerSheet``. Rules are
/// no longer grouped by policy: policies own assignment now (a rule can sit
/// in several policies at once), so this screen shows each rule exactly once
/// with its usage ("In N policies") alongside, plus a checkbox multi-selection
/// for batch delete / single duplicate (same anatomy as Definitions). Matchers
/// live one tier down on the Definitions screen.
struct RulesView: View {
    @Bindable var model: PolicyBuilderModel

    @State private var query = ""
    @State private var actionFilter: ActionFilter = .all
    @State private var elevationFilter: ElevationFilter = .all
    @State private var policyFilter: PolicyFilter = .all
    @State private var selectedRuleID: String?
    /// Briefly highlights a just-saved/duplicated rule's row.
    @State private var flashRuleID: String?
    @State private var composerIntent: RuleComposerIntent?
    /// Rules awaiting the delete confirmation (one from a row / the keyboard,
    /// several from the checkbox selection).
    @State private var deleteCandidates: [PolicyRule] = []
    /// Checkbox multi-selection — distinct from the keyboard focus row
    /// (`selectedRuleID`). Drives the batch bar (delete N / duplicate one).
    @State private var checkedIDs: Set<String> = []

    private enum ActionFilter: String, CaseIterable, Identifiable {
        case all = "All", allow = "Allow", deny = "Deny"
        var id: String { rawValue }
    }

    /// Filters on the allow-side elevation; picking Silent or Prompt hides
    /// deny rules (they have no elevation to speak of).
    private enum ElevationFilter: String, CaseIterable, Identifiable {
        case all = "All", silent = "Silent", prompt = "Prompt"
        var id: String { rawValue }
    }

    private enum PolicyFilter: Equatable {
        case all
        case unassigned
        case policy(String)
    }

    /// One rule joined with everything the row renders, resolved once per
    /// refresh instead of per subview.
    private struct Row: Identifiable {
        let rule: PolicyRule
        /// Resolved definitions (dangling ids dropped) — mechanism icons and
        /// tooltips derive from these.
        let definitions: [RuleDefinition]
        /// Policies with an assignment for this rule (enabled or not).
        let policyCount: Int
        var id: String { rule.id }
    }

    // MARK: Derived state

    private var unassignedCount: Int {
        model.rules.filter { model.policiesUsing(ruleID: $0.id).isEmpty }.count
    }

    private var headerSubtitle: String {
        let total = model.rules.count
        return "\(total) \(total == 1 ? "rule" : "rules") · \(unassignedCount) unassigned to any policy"
    }

    /// All rules with filters applied, name-sorted (id tiebreak) so the list
    /// is stable regardless of library insertion order.
    private var rows: [Row] {
        model.rules
            .map { rule in
                Row(rule: rule,
                    definitions: model.definitions(in: rule),
                    policyCount: model.policiesUsing(ruleID: rule.id).count)
            }
            .filter { matchesPolicy($0) && matchesAction($0.rule.action) && matchesElevation($0.rule) && matchesQuery($0) }
            .sorted {
                let order = $0.rule.name.localizedCaseInsensitiveCompare($1.rule.name)
                return order == .orderedSame ? $0.rule.id < $1.rule.id : order == .orderedAscending
            }
    }

    private var visibleRuleIDs: [String] { rows.map(\.id) }

    private func matchesPolicy(_ row: Row) -> Bool {
        switch policyFilter {
        case .all:
            return true
        case .unassigned:
            return row.policyCount == 0
        case .policy(let id):
            return model.policy(id: id)?.rules.contains { $0.ruleID == row.rule.id } ?? false
        }
    }

    private func matchesAction(_ action: RuleAction) -> Bool {
        switch actionFilter {
        case .all: return true
        case .allow: return action == .allow
        case .deny: return action == .deny
        }
    }

    private func matchesElevation(_ rule: PolicyRule) -> Bool {
        switch elevationFilter {
        case .all: return true
        case .silent: return rule.action == .allow && rule.elevationType == .silent
        case .prompt: return rule.action == .allow && rule.elevationType == .prompt
        }
    }

    private func matchesQuery(_ row: Row) -> Bool {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return true }
        if row.rule.name.lowercased().contains(q)
            || row.rule.id.lowercased().contains(q)
            || row.rule.detail.lowercased().contains(q) {
            return true
        }
        // Searching a definition name or target finds the rules that use it.
        return row.definitions.contains {
            $0.name.lowercased().contains(q)
                || ($0.authURI ?? "").lowercased().contains(q)
                || ($0.commandPattern ?? "").lowercased().contains(q)
        }
    }

    // MARK: Body

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.lg) {
            ScreenHeader("Rules", subtitle: headerSubtitle) {
                Button { composerIntent = .create } label: { Label("New Rule", systemImage: "plus") }
                    .buttonStyle(.tinted)
                    .keyboardShortcut("n", modifiers: .command)
            }

            if model.rules.isEmpty {
                emptyLibraryState
            } else {
                filterBar
                if !checkedIDs.isEmpty {
                    selectionBar
                }
                if unassignedCount > 0 {
                    Label("Unassigned rules aren't enforced until you add them to a policy — right-click a rule to add it.",
                          systemImage: "info.circle")
                        .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
                }
                if rows.isEmpty {
                    noMatchState
                } else {
                    ruleList
                }
            }
        }
        .padding(Spacing.xl)
        .animation(.easeOut(duration: 0.15), value: checkedIDs.isEmpty)
        .onChange(of: model.rules) { _, _ in pruneStaleState() }
        .onChange(of: model.policies) { _, _ in pruneStaleState() }
        .sheet(item: $composerIntent) { intent in
            RuleComposerSheet(model: model, intent: intent,
                              onSaved: { ruleID in flash(ruleID) },
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

    // MARK: Filter bar

    private var filterBar: some View {
        HStack(spacing: Spacing.md) {
            selectAllCheckbox
            HStack(spacing: Spacing.sm) {
                Image(systemName: "magnifyingglass").font(.system(size: 12)).foregroundStyle(Theme.textMuted)
                TextField("Search rules, definitions, targets…", text: $query)
                    .textFieldStyle(.plain).font(.system(size: 13)).foregroundStyle(Theme.textPrimary)
                if !query.isEmpty {
                    Button { query = "" } label: { Image(systemName: "xmark.circle.fill") }
                        .buttonStyle(.plain).foregroundStyle(Theme.textMuted)
                }
            }
            .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
            .background(Theme.elevated.opacity(0.7), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))

            Picker("", selection: $actionFilter) {
                ForEach(ActionFilter.allCases) { Text($0.rawValue).tag($0) }
            }.labelsHidden().fixedSize()
            Picker("", selection: $elevationFilter) {
                ForEach(ElevationFilter.allCases) { Text($0.rawValue).tag($0) }
            }.labelsHidden().fixedSize()

            Menu {
                Button("All policies") { policyFilter = .all }
                Button("Unassigned") { policyFilter = .unassigned }
                Divider()
                ForEach(model.policies) { policy in
                    Button(policy.name) { policyFilter = .policy(policy.id) }
                }
            } label: {
                HStack(spacing: 5) {
                    Image(systemName: "folder").font(.system(size: 10))
                    Text(policyFilterLabel).font(.system(size: 12, weight: .medium)).lineLimit(1)
                    Image(systemName: "chevron.up.chevron.down").font(.system(size: 8))
                }
            }
            .menuStyle(.borderlessButton).fixedSize()
            .ghostControlChrome(active: policyFilter != .all)
        }
    }

    private var policyFilterLabel: String {
        switch policyFilter {
        case .all: return "All policies"
        case .unassigned: return "Unassigned"
        case .policy(let id): return model.policy(id: id)?.name ?? id
        }
    }

    /// Header checkbox over the VISIBLE rows: checks them all, or clears
    /// them when every visible row is already checked. Shows a dash while
    /// only some are checked.
    private var selectAllCheckbox: some View {
        let visible = visibleRuleIDs
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
        .help(all ? "Deselect all" : "Select all \(visible.count) visible \(visible.count == 1 ? "rule" : "rules")")
        .accessibilityLabel(all ? "Deselect all rules" : "Select all visible rules")
    }

    // MARK: Selection bar

    /// Batch actions for the checkbox selection, in the Intel-bar segmented
    /// idiom. Duplicate is single-target only, so it is disabled unless
    /// exactly one rule is checked.
    private var selectionBar: some View {
        let count = checkedIDs.count
        let hidden = checkedIDs.subtracting(visibleRuleIDs).count
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
                      help: count == 1 ? "Duplicate the selected rule (the copy starts unassigned)"
                                       : "Select exactly one rule to duplicate") { duplicateChecked() },
                .init(id: "delete", title: count == 1 ? "Delete" : "Delete \(count)", systemImage: "trash",
                      isDestructive: true,
                      help: "Delete the selected \(count == 1 ? "rule" : "rules") — they are withdrawn from every policy that assigns them") { requestDeleteChecked() },
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
              let copyID = model.duplicateRule(id: id) else { return }
        // The copy becomes the selection (Finder's ⌘D convention) and flashes.
        checkedIDs = [copyID]
        flash(copyID)
    }

    private func requestDeleteChecked() {
        let candidates = model.rules.filter { checkedIDs.contains($0.id) }
        guard !candidates.isEmpty else { return }
        deleteCandidates = candidates
    }

    // MARK: List

    private var ruleList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 6) {
                    ForEach(rows) { row in
                        ruleRow(row)
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
            .onChange(of: flashRuleID) { _, new in
                if let new { withAnimation { proxy.scrollTo(new, anchor: .center) } }
            }
            .onChange(of: selectedRuleID) { _, new in
                if let new { proxy.scrollTo(new, anchor: nil) }
            }
            .onAppear { consumePendingFocus(proxy: proxy) }
            .onChange(of: model.pendingFocus) { _, _ in consumePendingFocus(proxy: proxy) }
            .onChange(of: composerIntent) { _, new in
                // A deep link that arrived while the composer was up runs
                // once it closes.
                if new == nil { consumePendingFocus(proxy: proxy) }
            }
        }
    }

    // MARK: Rule row

    private func ruleRow(_ row: Row) -> some View {
        let selected = selectedRuleID == row.id || flashRuleID == row.id
        let allow = row.rule.action == .allow
        let kinds = Set(row.definitions.map(\.kind))
        let glyph = mechanismGlyph(kinds)
        /// Referenced-but-deleted definitions — surfaced, never hidden.
        let missingCount = row.rule.definitionIDs.count - row.definitions.count
        let checked = checkedIDs.contains(row.id)

        return HStack(spacing: Spacing.sm) {
            // Checkbox for the batch selection — a sibling of the row button,
            // never nested inside it, so it reliably receives the click.
            Button { toggleChecked(row.id) } label: {
                Image(systemName: checked ? "checkmark.square.fill" : "square")
                    .font(.system(size: 16))
                    .foregroundStyle(checked ? Theme.emerald : Theme.textMuted)
                    .frame(width: 20, height: 20)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(checked ? "Deselect" : "Select for batch delete / duplicate")
            .accessibilityLabel(checked ? "Deselect \(row.rule.name)" : "Select \(row.rule.name)")

            Button {
                selectedRuleID = row.id
                composerIntent = .edit(ruleID: row.rule.id)
            } label: {
                HStack(spacing: Spacing.md) {
                    Image(systemName: glyph.symbol)
                        .font(.system(size: 13))
                        .foregroundStyle(glyph.tint)
                        .frame(width: 32, height: 32)
                        .background(glyph.tint.opacity(0.12),
                                   in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                        .help(mechanismHelp(kinds))

                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: Spacing.sm) {
                            Text(row.rule.name.isEmpty ? row.rule.id : row.rule.name)
                                .font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.textPrimary).lineLimit(1)
                            if missingCount > 0 {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .font(.system(size: 10)).foregroundStyle(Theme.warning)
                                    .help("References \(missingCount) deleted \(missingCount == 1 ? "definition" : "definitions") — open the rule to clean up")
                            }
                        }
                        Text(detailLine(row))
                            .font(.system(size: 11)).foregroundStyle(Theme.textMuted).lineLimit(1)
                    }

                    Spacer()

                    Text("\(row.definitions.count) \(row.definitions.count == 1 ? "definition" : "definitions")")
                        .font(.system(size: 10))
                        .foregroundStyle(row.definitions.isEmpty ? Theme.warning : Theme.textMuted)
                        .help(row.definitions.isEmpty
                              ? "No definitions — this rule never matches"
                              : row.definitions.map(\.name).joined(separator: "\n"))

                    if allow {
                        RuleDecisionBadge(row.rule.elevationType == .silent ? "silent" : "prompt",
                                          color: row.rule.elevationType == .silent ? Theme.warning : Theme.info)
                    }
                    RuleDecisionBadge(allow ? "allow" : "deny", color: allow ? Theme.success : Theme.critical)

                    if row.policyCount == 0 {
                        StatusBadge("Unassigned", tone: .pending, symbol: "tray")
                            .help("Not enforced — add it to a policy to take effect")
                    } else {
                        Text("In \(row.policyCount) \(row.policyCount == 1 ? "policy" : "policies")")
                            .font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textSecondary)
                            .lineLimit(1)
                            .help(model.policiesUsing(ruleID: row.rule.id).map(\.name).joined(separator: "\n"))
                    }

                    Text("priority \(row.rule.priority)")
                        .font(.system(size: 10)).foregroundStyle(Theme.textMuted)
                        .frame(minWidth: 60, alignment: .trailing)
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
        .id(row.id)
        .contextMenu {
            Button("Edit Rule…") {
                selectedRuleID = row.id
                composerIntent = .edit(ruleID: row.rule.id)
            }
            Button(checked ? "Deselect" : "Select") { toggleChecked(row.id) }
            Button("Duplicate") { duplicate(row.rule.id) }
            Menu("Add to Policy") {
                if model.policies.isEmpty {
                    Text("No policies yet")
                } else {
                    ForEach(model.policies) { policy in
                        let assigned = policy.rules.contains { $0.ruleID == row.rule.id }
                        Button(policy.name + (assigned ? " — already added" : "")) {
                            model.addRule(row.rule.id, toPolicy: policy.id)
                            flash(row.rule.id)
                        }
                        .disabled(assigned)
                    }
                }
            }
            Divider()
            Button("Delete Rule…", role: .destructive) { deleteCandidates = [row.rule] }
        }
    }

    /// The rule's own description, else its definitions' names, else the
    /// empty-rule hint — the second line never goes blank.
    private func detailLine(_ row: Row) -> String {
        if !row.rule.detail.isEmpty { return row.rule.detail }
        if !row.definitions.isEmpty { return row.definitions.map(\.name).joined(separator: " · ") }
        return "No definitions yet"
    }

    /// Leading icon derived from the rule's definitions: single-mechanism
    /// rules keep the familiar terminal/lock glyphs, mixed rules get a grid,
    /// empty rules a placeholder.
    private func mechanismGlyph(_ kinds: Set<RuleType>) -> (symbol: String, tint: Color) {
        if kinds == [.sudo] { return ("terminal.fill", Theme.emerald) }
        if kinds == [.authuri] { return ("lock.fill", Theme.info) }
        if kinds.isEmpty { return ("questionmark.square.dashed", Theme.textMuted) }
        return ("square.grid.2x2.fill", Theme.emerald)
    }

    private func mechanismHelp(_ kinds: Set<RuleType>) -> String {
        if kinds == [.sudo] { return "Sudo commands" }
        if kinds == [.authuri] { return "Authorization rights" }
        if kinds.isEmpty { return "No definitions" }
        return "Sudo commands + authorization rights"
    }

    // MARK: Empty states

    private var emptyLibraryState: some View {
        VStack(spacing: Spacing.md) {
            Image(systemName: "list.bullet.rectangle").font(.system(size: 40)).foregroundStyle(Theme.textMuted)
            Text("No rules yet").font(.system(size: 16, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            Text("A rule bundles one or more definitions with a decision — allow or deny, silent or prompted. Create one here, then add it to policies.")
                .font(.system(size: 12)).foregroundStyle(Theme.textMuted)
                .multilineTextAlignment(.center)
            Button { composerIntent = .create } label: { Label("New Rule", systemImage: "plus") }
                .buttonStyle(.emerald)
                .padding(.top, Spacing.xs)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .card()
    }

    private var noMatchState: some View {
        VStack(spacing: Spacing.md) {
            Image(systemName: "line.3.horizontal.decrease.circle").font(.system(size: 40)).foregroundStyle(Theme.textMuted)
            Text("No rules match").font(.system(size: 16, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            Text("Adjust the search or filters above.").font(.system(size: 12)).foregroundStyle(Theme.textMuted)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .card()
    }

    // MARK: Selection + keyboard

    private func moveSelection(_ direction: MoveCommandDirection) {
        let ids = visibleRuleIDs
        guard !ids.isEmpty else { return }
        // A selection that's no longer visible (deleted, filtered out) must not
        // dead-end the arrows — fall back to the ends of the visible list.
        let currentIndex = selectedRuleID.flatMap { ids.firstIndex(of: $0) }
        switch direction {
        case .down:
            if let index = currentIndex {
                if index + 1 < ids.count { selectedRuleID = ids[index + 1] }
            } else {
                selectedRuleID = ids.first
            }
        case .up:
            if let index = currentIndex {
                if index > 0 { selectedRuleID = ids[index - 1] }
            } else {
                selectedRuleID = ids.last
            }
        default:
            break
        }
    }

    private func openSelection() -> KeyPress.Result {
        guard let selected = selectedRuleID, model.rule(id: selected) != nil else { return .ignored }
        composerIntent = .edit(ruleID: selected)
        return .handled
    }

    /// ⌫: the checkbox selection when there is one, else the focused row.
    private func deleteSelection() {
        if !checkedIDs.isEmpty {
            requestDeleteChecked()
            return
        }
        guard let selected = selectedRuleID, let rule = model.rule(id: selected) else { return }
        deleteCandidates = [rule]
    }

    private var deleteTitle: String {
        switch deleteCandidates.count {
        case 0: return ""
        case 1:
            let one = deleteCandidates[0]
            return "Delete “\(one.name.isEmpty ? one.id : one.name)”?"
        default: return "Delete \(deleteCandidates.count) rules?"
        }
    }

    /// Names how many policies are affected — the union over every candidate
    /// for a batch.
    private var deleteMessage: String {
        guard !deleteCandidates.isEmpty else { return "" }
        var seen = Set<String>()
        let affected = deleteCandidates
            .flatMap { model.policiesUsing(ruleID: $0.id) }
            .filter { seen.insert($0.id).inserted }
        let these = deleteCandidates.count == 1 ? "the rule" : "these \(deleteCandidates.count) rules"
        // Name what is about to go — the checked set can include rows the
        // current filter hides, so the confirmation must be verifiable.
        let listed = deleteCandidates.prefix(5).map { $0.name.isEmpty ? $0.id : $0.name }.joined(separator: ", ")
        let more = deleteCandidates.count > 5 ? " and \(deleteCandidates.count - 5) more" : ""
        let roster = deleteCandidates.count == 1 ? "" : " (\(listed)\(more))"
        if affected.isEmpty {
            return "This removes \(these)\(roster) from the library. \(deleteCandidates.count == 1 ? "It isn't" : "None are") assigned to any policy, so enforcement is unchanged."
        }
        let names = affected.map(\.name).joined(separator: ", ")
        return "This removes \(these)\(roster) from the library and withdraws \(deleteCandidates.count == 1 ? "it" : "them") from \(affected.count) \(affected.count == 1 ? "policy" : "policies"): \(names). Devices keep enforcing the old versions until those policies are re-exported and republished."
    }

    private func confirmDelete() {
        let ids = Set(deleteCandidates.map(\.id))
        guard !ids.isEmpty else { return }
        // Move the keyboard selection to a surviving neighbor before the rows
        // disappear.
        let visible = visibleRuleIDs
        if let current = selectedRuleID, ids.contains(current), let index = visible.firstIndex(of: current) {
            selectedRuleID = visible[(index + 1)...].first { !ids.contains($0) }
                ?? visible[..<index].last { !ids.contains($0) }
        }
        model.deleteRules(ids: ids)
        checkedIDs.subtract(ids)
        deleteCandidates = []
    }

    private func duplicate(_ ruleID: String) {
        guard let newID = model.duplicateRule(id: ruleID) else { return }
        flash(newID)
    }

    // MARK: Deep links + save feedback

    /// Honors ``PolicyBuilderModel/pendingFocus`` for `.rule` links — scroll
    /// to and flash the rule another screen sent here. Other focus cases
    /// belong to other screens and are left untouched. Deferred while the
    /// composer is up; re-runs when it closes.
    private func consumePendingFocus(proxy: ScrollViewProxy) {
        guard case .rule(let ruleID) = model.pendingFocus, composerIntent == nil else { return }
        model.pendingFocus = nil
        guard model.rule(id: ruleID) != nil else { return }
        flash(ruleID)
        proxy.scrollTo(ruleID, anchor: .center)
    }

    /// Emerald-flash a rule's row. If the active filters would hide it,
    /// relax them first — a save, duplicate, or assign must never look like
    /// a silent failure.
    private func flash(_ ruleID: String) {
        if !rows.contains(where: { $0.id == ruleID }) {
            query = ""
            actionFilter = .all
            elevationFilter = .all
            policyFilter = .all
        }
        selectedRuleID = ruleID
        flashRuleID = ruleID
        Task {
            try? await Task.sleep(for: .seconds(1))
            if flashRuleID == ruleID { flashRuleID = nil }
        }
    }

    /// Drops UI state pointing at rules/policies that no longer exist —
    /// a stale policy filter otherwise strands the screen on "No rules match".
    private func pruneStaleState() {
        if let selected = selectedRuleID, model.rule(id: selected) == nil {
            selectedRuleID = nil
        }
        if case .policy(let id) = policyFilter, model.policy(id: id) == nil {
            policyFilter = .all
        }
        let live = Set(model.rules.map(\.id))
        if !checkedIDs.isSubset(of: live) { checkedIDs.formIntersection(live) }
    }
}
