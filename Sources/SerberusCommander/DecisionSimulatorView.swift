import PolicyBuilderCore
import PrivMgrCore
import SwiftUI

/// Decision Simulator — a request BUILDER on the left, the decision rendered
/// as a node-graph of the engine's evaluation path on the right. Uses the
/// same RuleEngine as the daemon, so the preview can never disagree with real
/// enforcement. The request target (sudo command / auth URI) is fixed; every
/// other facet is a ``DecisionSimulatorModel/Component`` the operator adds or
/// removes — a removed one contributes its neutral value. "Load example"
/// pulls any (rule, definition) pair from the live rule library — the
/// definition supplies the matcher, the rule the context.
struct DecisionSimulatorView: View {
    @Bindable var model: PolicyBuilderModel
    @State private var showingRights = false

    private typealias Component = DecisionSimulatorModel.Component

    private var simulator: DecisionSimulatorModel { model.simulator }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.lg) {
            ScreenHeader("Decision Simulator", subtitle: "Runs the daemon's exact rule engine") {
                HStack(spacing: Spacing.sm) {
                    loadExampleMenu
                    Button { model.runSimulation() } label: { Label("Simulate", systemImage: "play.fill") }
                        .buttonStyle(.emerald)
                        .keyboardShortcut(.return, modifiers: .command)
                }
            }

            HStack(alignment: .top, spacing: Spacing.lg) {
                inputColumn.frame(width: 360)
                resultPane.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
        }
        .padding(Spacing.xl)
        .onAppear { if simulator.result == nil { model.runSimulation() } }
        .sheet(isPresented: $showingRights) {
            AuthURIBrowserSheet(model: model,
                                onPick: { model.simulator.authURI = $0 }) { showingRights = false }
        }
    }

    private var loadExampleMenu: some View {
        Menu {
            if model.rules.isEmpty {
                Text("No rules")
            } else {
                ForEach(model.rules) { rule in
                    Menu(rule.name.isEmpty ? rule.id : rule.name) {
                        let defs = model.definitions(in: rule)
                        if defs.isEmpty {
                            Text("No definitions")
                        } else {
                            ForEach(defs) { definition in
                                Button(definition.name.isEmpty ? definition.id : definition.name) {
                                    load(rule: rule, definition: definition)
                                }
                            }
                        }
                    }
                }
            }
        } label: { Label("Load example", systemImage: "tray.and.arrow.down") }
            .menuStyle(.borderlessButton).fixedSize()
            .ghostControlChrome()
    }

    /// Pre-fills the simulator inputs from a library (rule, definition) pair
    /// and runs it: the definition supplies the matcher and identity pins,
    /// the rule the request context (justification). Setting a non-neutral
    /// value activates that component in the builder, so an example with a
    /// Team ID pin adds the Team ID + Signing rows by itself.
    private func load(rule: PolicyRule, definition: RuleDefinition) {
        let sim = model.simulator
        switch definition.kind {
        case .authuri:
            sim.requestKind = .authURI
            sim.authURI = definition.authURI ?? ""
        case .sudo:
            sim.requestKind = .sudo
            // Only a LITERAL command pattern is a path the canonicalizer can
            // take (exact / prefix+args); a glob/regex/any pattern is left to
            // whatever command is already typed so the example still runs.
            let matchType = definition.matchType ?? .exact
            if let pattern = definition.commandPattern, matchType == .exact || matchType == .prefixRegex {
                sim.sudoCommand = pattern
                sim.executablePath = pattern
            }
            // Seed the arguments from a literal arg pattern (no regex
            // metacharacters) so a prefix+args example can match its own rule;
            // otherwise clear them rather than leave a stale, misleading argv.
            if let args = definition.argPattern, !args.isEmpty,
               args.rangeOfCharacter(from: CharacterSet(charactersIn: "[](){}|*+?^$\\.")) == nil {
                sim.argvText = args
            } else {
                sim.argvText = ""
            }
        }
        // An App Identity definition pins the app's Team ID (the engine
        // checks it; the bundle-ID requirement is authd's, not the engine's).
        sim.teamID = definition.appTeamID ?? definition.requiredTeamID ?? ""
        sim.binaryHash = definition.requiredBinaryHash ?? ""
        if definition.requiredTeamID != nil || definition.appTeamID != nil { sim.signingStatus = .valid }
        sim.justificationProvided = rule.requireJustification
        model.runSimulation()
    }

    // MARK: Input (builder)

    private var inputColumn: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.lg) {
                requestCard
                componentsCard
            }
        }
        .scrollIndicators(.never)
    }

    /// The fixed part of the request: kind + target. The engine cannot
    /// evaluate without a target, so these are not removable components.
    private var requestCard: some View {
        inputCard("Request", "arrow.right.circle") {
            SegmentedControl(selection: $model.simulator.requestKind,
                             options: [.sudo: "Sudo", .authURI: "Auth URI"],
                             label: "Request kind")
            if simulator.requestKind == .authURI {
                authURIField
            } else {
                LabeledField(label: "Sudo command") {
                    TextField("/path/to/command", text: $model.simulator.sudoCommand)
                }
            }
        }
    }

    private var authURIField: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                Text("Auth URI").font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textSecondary)
                Spacer()
                Button { showingRights = true } label: {
                    Label("Browse", systemImage: "magnifyingglass").font(.system(size: 10))
                }
                .buttonStyle(.plain).foregroundStyle(Theme.emerald)
            }
            fieldChrome { TextField("system.preferences.network", text: $model.simulator.authURI) }
        }
    }

    /// The builder proper: one row per active component (each with its own
    /// remove ✕) and an "Add component" menu listing what is left.
    private var componentsCard: some View {
        let active = simulator.activeComponentsInOrder
        let available = simulator.availableComponents
        return VStack(alignment: .leading, spacing: Spacing.md) {
            HStack {
                Label("Components", systemImage: "square.stack.3d.up")
                    .font(.eyebrow).tracking(0.8)
                    .foregroundStyle(Theme.textMuted)
                Spacer()
                Text("\(active.count) of \(active.count + available.count)")
                    .font(.system(size: 10)).foregroundStyle(Theme.textMuted)
            }
            if active.isEmpty {
                Text("A bare request. Add components to shape it — anything left out contributes its neutral value (the remove button on each row says what that is).")
                    .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            ForEach(active) { component in
                componentRow(component)
            }
            addComponentMenu(available)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card()
        .animation(.easeOut(duration: 0.15), value: active)
    }

    private func addComponentMenu(_ available: [Component]) -> some View {
        Menu {
            if available.isEmpty {
                Text("Every component is in the request")
            } else {
                ForEach(available) { component in
                    Button {
                        model.simulator.add(component)
                    } label: { Label(component.title, systemImage: component.symbol) }
                }
            }
            Divider()
            Button("Reset to Defaults") { model.simulator.resetComponents() }
        } label: {
            Label("Add component", systemImage: "plus")
        }
        .menuStyle(.borderlessButton).fixedSize()
        .ghostControlChrome()
        .help("Add a facet of the request — user, identity pins, justification, cache…")
    }

    private func componentRow(_ component: Component) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: Spacing.xs) {
                Label(component.title, systemImage: component.symbol)
                    .font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textSecondary)
                Spacer()
                Button { model.simulator.remove(component) } label: {
                    Image(systemName: "xmark.circle.fill").font(.system(size: 12))
                }
                .buttonStyle(.plain).foregroundStyle(Theme.textMuted)
                .help("Remove — the engine then sees \(component.neutralDescription)")
                .accessibilityLabel("Remove \(component.title)")
            }
            componentField(component)
        }
        .transition(.opacity.combined(with: .move(edge: .top)))
    }

    @ViewBuilder
    private func componentField(_ component: Component) -> some View {
        switch component {
        case .user:
            fieldChrome { TextField("alice", text: $model.simulator.user) }
        case .uid:
            fieldChrome { TextField("501", value: $model.simulator.uid, format: .number) }
        case .arguments:
            fieldChrome { TextField("install wget", text: $model.simulator.argvText) }
        case .executablePath:
            fieldChrome {
                TextField(simulator.requestKind == .sudo ? "empty = the sudo command itself" : "empty = /usr/bin/security",
                          text: $model.simulator.executablePath)
            }
        case .teamID:
            fieldChrome { TextField("ABCDE12345", text: $model.simulator.teamID) }
        case .binaryHash:
            fieldChrome { TextField("sha256 hex digest", text: $model.simulator.binaryHash) }
        case .signing:
            fieldChrome {
                Picker("", selection: $model.simulator.signingStatus) {
                    ForEach(SigningStatus.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }
                .labelsHidden()
            }
        case .justification:
            Toggle("Justification provided", isOn: $model.simulator.justificationProvided)
                .font(.system(size: 12))
            if simulator.justificationProvided {
                fieldChrome { TextField("Why the elevation is needed", text: $model.simulator.justificationText) }
            }
        case .globalCache:
            Stepper("Global cache: \(simulator.globalCacheSeconds)s",
                    value: $model.simulator.globalCacheSeconds, in: 0...86_400, step: 30)
                .font(.system(size: 12))
                .foregroundStyle(Theme.textSecondary)
        }
    }

    /// The dark bordered field look ``LabeledField`` gives its content, for
    /// rows whose label line carries the remove button.
    private func fieldChrome(@ViewBuilder content: () -> some View) -> some View {
        content()
            .font(.system(size: 13)).foregroundStyle(Theme.textPrimary)
            .textFieldStyle(.plain)
            .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
            .background(Theme.background.opacity(0.55), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
    }

    private func inputCard(_ title: String, _ symbol: String, @ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            Label(title, systemImage: symbol)
                .font(.eyebrow).tracking(0.8)
                .foregroundStyle(Theme.textMuted)
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card()
    }

    // MARK: Result

    @ViewBuilder
    private var resultPane: some View {
        if let error = simulator.errorMessage {
            placeholder("Cannot simulate", symbol: "exclamationmark.triangle", detail: error, tone: .degraded)
        } else if let result = simulator.result {
            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.lg) {
                    DecisionBadge(decision: result.decision)
                    VStack(alignment: .leading, spacing: Spacing.sm) {
                        DetailRow(label: "Reason", value: result.reason)
                        if let rule = result.matchedRule { DetailRow(label: "Matched rule", value: rule, mono: true) }
                        if let profile = result.matchedProfile { DetailRow(label: "Profile", value: profile, mono: true) }
                        DetailRow(label: "Cache", value: result.cacheBehavior)
                        if let duration = result.grantDuration { DetailRow(label: "Grant", value: "\(Int(duration))s") }
                    }

                    if !result.warnings.isEmpty {
                        VStack(alignment: .leading, spacing: Spacing.xs) {
                            SectionLabel("Warnings")
                            ForEach(result.warnings, id: \.self) { warning in
                                Label(warning, systemImage: "exclamationmark.triangle.fill")
                                    .font(.system(size: 11)).foregroundStyle(Theme.warning)
                            }
                        }
                    }

                    VStack(alignment: .leading, spacing: Spacing.md) {
                        SectionLabel("Evaluation path")
                        TraceGraph(steps: result.evaluationTrace, decision: result.decision)
                    }

                    DisclosureGroup {
                        CodeBlock {
                            VStack(alignment: .leading, spacing: 4) {
                                ForEach(result.evaluationTrace, id: \.index) { step in
                                    Text("[\(step.index)] \(step.detail) → \(step.outcome)")
                                        .font(.mono(11)).foregroundStyle(Theme.textSecondary)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                }
                            }
                        }
                    } label: {
                        Text("Raw trace").font(.system(size: 12, weight: .medium)).foregroundStyle(Theme.textMuted)
                    }
                }
                .padding(Spacing.xl)
            }
            .scrollIndicators(.never)
            .card(padding: 0)
        } else {
            placeholder("Run a simulation", symbol: "play.circle", detail: "Build a request on the left and press Simulate (⌘↩), or Load example.", tone: .neutral)
        }
    }

    private func placeholder(_ title: String, symbol: String, detail: String, tone: StatusTone) -> some View {
        VStack(spacing: Spacing.md) {
            Image(systemName: symbol).font(.system(size: 38)).foregroundStyle(tone.color.opacity(0.7))
            Text(title).font(.system(size: 16, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            Text(detail).font(.system(size: 12)).foregroundStyle(Theme.textMuted)
                .multilineTextAlignment(.center).frame(maxWidth: 320)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .card()
    }
}

// MARK: - Trace node-graph

/// Renders the evaluation trace as a vertical flow of nodes ending in the
/// decision — the reference "node-graph" view of how the engine reasoned.
private struct TraceGraph: View {
    let steps: [TraceStep]
    let decision: Decision

    var body: some View {
        VStack(spacing: 0) {
            ForEach(steps, id: \.index) { step in
                TraceNode(step: step)
                connector
            }
            DecisionTerminal(decision: decision)
        }
    }

    private var connector: some View {
        Image(systemName: "chevron.compact.down")
            .font(.system(size: 13, weight: .bold))
            .foregroundStyle(Theme.border)
            .frame(height: 14)
    }
}

private struct TraceNode: View {
    let step: TraceStep

    private var tone: StatusTone {
        let o = step.outcome.lowercased()
        if o.contains("deny") { return .degraded }
        if o.contains("match") || o.contains("allow") || o.contains("grant") || o.contains("satisf") { return .healthy }
        if o.contains("no ") || o.contains("not ") || o.contains("skip") || o.contains("miss") { return .offline }
        return .neutral
    }

    var body: some View {
        HStack(alignment: .top, spacing: Spacing.md) {
            ZStack {
                Circle().fill(tone.color.opacity(0.15)).frame(width: 24, height: 24)
                    .overlay(Circle().strokeBorder(tone.color.opacity(0.5), lineWidth: 1))
                Text("\(step.index)").font(.system(size: 11, weight: .bold)).foregroundStyle(tone.color)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(step.detail).font(.system(size: 12, weight: .medium)).foregroundStyle(Theme.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
                Text(step.outcome).font(.mono(11)).foregroundStyle(tone.color)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(Spacing.md)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.elevated.opacity(0.5), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(tone.color.opacity(0.25), lineWidth: 1))
    }
}

private struct DecisionTerminal: View {
    let decision: Decision

    private var tone: StatusTone {
        switch decision {
        case .allow, .timedGrant: return .healthy
        case .prompt: return .pending
        case .deny: return .degraded
        }
    }
    private var title: String {
        switch decision {
        case .allow: return "ALLOW"
        case .timedGrant: return "TIMED GRANT"
        case .prompt: return "PROMPT"
        case .deny: return "DENY"
        }
    }
    private var icon: String {
        switch decision {
        case .allow: return "checkmark.shield.fill"
        case .timedGrant: return "clock.badge.checkmark.fill"
        case .prompt: return "questionmark.circle.fill"
        case .deny: return "xmark.shield.fill"
        }
    }

    var body: some View {
        HStack(spacing: Spacing.sm) {
            Image(systemName: icon).font(.system(size: 14, weight: .bold))
            Text(title).font(.system(size: 14, weight: .bold)).tracking(1)
        }
        .foregroundStyle(tone.color)
        .padding(.horizontal, Spacing.lg).padding(.vertical, Spacing.sm)
        .background(tone.color.opacity(0.14), in: Capsule())
        .overlay(Capsule().strokeBorder(tone.color.opacity(0.4), lineWidth: 1.5))
        .shadow(color: tone.color.opacity(0.35), radius: 8)
    }
}

private struct DecisionBadge: View {
    let decision: Decision

    private var tone: StatusTone {
        switch decision {
        case .allow, .timedGrant: return .healthy
        case .prompt: return .pending
        case .deny: return .degraded
        }
    }

    private var title: String {
        switch decision {
        case .allow: return "ALLOW"
        case .timedGrant: return "TIMED GRANT"
        case .prompt: return "PROMPT"
        case .deny: return "DENY"
        }
    }

    private var icon: String {
        switch decision {
        case .allow: return "checkmark.shield.fill"
        case .timedGrant: return "clock.badge.checkmark.fill"
        case .prompt: return "questionmark.circle.fill"
        case .deny: return "xmark.shield.fill"
        }
    }

    var body: some View {
        HStack(spacing: Spacing.md) {
            Image(systemName: icon)
                .font(.system(size: 26, weight: .semibold))
                .foregroundStyle(tone.color)
                .frame(width: 52, height: 52)
                .background(tone.color.opacity(0.12), in: RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: Radius.md, style: .continuous).strokeBorder(tone.color.opacity(0.35), lineWidth: 1))
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 22, weight: .bold)).tracking(1)
                    .foregroundStyle(tone.color)
                Text("decision").font(.system(size: 11)).foregroundStyle(Theme.textMuted)
            }
            Spacer()
        }
    }
}
