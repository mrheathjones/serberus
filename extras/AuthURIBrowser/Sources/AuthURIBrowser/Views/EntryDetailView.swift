import SwiftUI

struct EntryDetailView: View {
    let entry: AuthEntry
    let catalog: Catalog

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.lg) {
                header
                accessCard
                definitionCard
                if let definition = entry.effective, !definition.delegates.isEmpty {
                    resolutionCard(definition)
                }
                if let definition = entry.effective, !definition.mechanisms.isEmpty {
                    mechanismsCard(definition)
                }
                if !entry.driftedFields.isEmpty {
                    driftCard
                }
                rawCard
            }
            .padding(Spacing.xl)
            .frame(maxWidth: 900, alignment: .leading)
            .frame(maxWidth: .infinity, alignment: .topLeading)
        }
        .textSelection(.enabled)
        .navigationTitle("")
    }

    // MARK: Header

    private var header: some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            HStack(alignment: .firstTextBaseline, spacing: Spacing.sm) {
                // Zero-width spaces after each dot let a long right name wrap
                // at its components instead of mid-word.
                Text(entry.name.replacingOccurrences(of: ".", with: ".\u{200B}"))
                    .font(.mono(19, weight: .bold))
                    .foregroundStyle(Theme.textPrimary)
                if entry.kind == .rule { TagChip("named rule") }
                if entry.isWildcard { TagChip("wildcard prefix") }
                if entry.isCustom { TagChip("not in template", color: Theme.info) }
                if entry.isOverridden { TagChip("locally overridden", color: Theme.warning) }
                else if entry.isDrifted { TagChip("differs from template", color: Theme.warning) }
                if entry.isModified { TagChip("modified after creation") }
            }
            Text(entry.summary ?? "No description in the authorization database.")
                .font(.system(size: 13))
                .foregroundStyle(entry.summary == nil ? Theme.textMuted : Theme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: Spacing.sm) {
                Button { Clipboard.copy(entry.name) } label: { Label("Copy name", systemImage: "doc.on.doc") }
                    .buttonStyle(.ghost)
                Button { Clipboard.copy("security authorizationdb read \(entry.name)") } label: {
                    Label("Copy read command", systemImage: "terminal")
                }
                .buttonStyle(.ghost)
                if entry.live == nil, let status = entry.liveStatus {
                    PillBadge(text: "Live: \(status)", color: Theme.warning, symbol: "exclamationmark.circle")
                }
            }
            .padding(.top, Spacing.xxs)
        }
    }

    // MARK: Cards

    private var accessCard: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            SectionLabel("Who can satisfy it")
            BadgeRow(badges: entry.badges)
            VStack(alignment: .leading, spacing: Spacing.sm) {
                ForEach(Array(entry.paths.enumerated()), id: \.offset) { _, path in
                    HStack(alignment: .top, spacing: Spacing.sm) {
                        Image(systemName: path.badge.systemImage)
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundStyle(path.badge.tint)
                            .frame(width: 16, height: 16)
                        Text(path.explanation)
                            .font(.system(size: 12.5))
                            .foregroundStyle(Theme.textPrimary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            if let definition = entry.effective, let line = credentialLine(definition) {
                Text(line)
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.textMuted)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card()
    }

    private func credentialLine(_ definition: RuleDefinition) -> String? {
        var parts: [String] = []
        if let timeout = definition.timeoutDescription { parts.append("credential cached: \(timeout)") }
        if let shared = definition.shared { parts.append(shared ? "shared with other clients" : "not shared") }
        if let tries = definition.tries { parts.append("\(tries) tries") }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    private var definitionCard: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            SectionLabel(entry.live != nil ? "Live definition" : "Template definition")
            if let definition = entry.effective {
                VStack(alignment: .leading, spacing: 7) {
                    DetailRow(label: "class", value: definition.classDescription)
                    if let group = definition.group { DetailRow(label: "group", value: group, mono: true) }
                    if let value = definition.authenticateUser {
                        DetailRow(label: "authenticate-user", value: value ? "yes — password prompt" : "no — membership check only")
                    }
                    if let value = definition.allowRoot {
                        DetailRow(label: "allow-root", value: value ? "yes — root passes silently" : "no",
                                  valueColor: value ? Theme.critical : Theme.textPrimary)
                    }
                    if let value = definition.sessionOwner {
                        DetailRow(label: "session-owner", value: value ? "yes — the session owner qualifies" : "no")
                    }
                    if let value = definition.shared { DetailRow(label: "shared", value: value ? "yes" : "no") }
                    if let value = definition.timeoutDescription { DetailRow(label: "timeout", value: value) }
                    if let value = definition.tries { DetailRow(label: "tries", value: String(value)) }
                    if let value = definition.kOfN {
                        DetailRow(label: "k-of-n", value: "\(value) of \(definition.delegates.count) must pass")
                    }
                    if let value = definition.entitled {
                        DetailRow(label: "entitled", value: value ? "yes — caller needs the entitlement" : "no")
                    }
                    if let value = definition.entitledGroup { DetailRow(label: "entitled-group", value: value ? "yes" : "no") }
                    if let value = definition.vpnEntitledGroup { DetailRow(label: "vpn-entitled-group", value: value ? "yes" : "no") }
                    if let value = definition.passwordOnly { DetailRow(label: "password-only", value: value ? "yes — no Touch ID" : "no") }
                    if let value = definition.extractPassword { DetailRow(label: "extract-password", value: value ? "yes" : "no") }
                    if let value = definition.requireAppleSigned { DetailRow(label: "require-apple-signed", value: value ? "yes" : "no") }
                    if let value = definition.identifier { DetailRow(label: "identifier", value: value, mono: true) }
                    if let value = definition.requirement { DetailRow(label: "requirement", value: value, mono: true) }
                    if let value = definition.version { DetailRow(label: "version", value: String(value)) }
                    if let created = definition.created {
                        DetailRow(label: "created", value: created.formatted(date: .abbreviated, time: .shortened))
                    }
                    if let modified = definition.modified {
                        DetailRow(label: "modified", value: modified.formatted(date: .abbreviated, time: .shortened),
                                  valueColor: entry.isModified ? Theme.warning : Theme.textPrimary)
                    }
                }
            } else {
                Text("No definition could be read for this entry.")
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.textSecondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card()
    }

    private func resolutionCard(_ definition: RuleDefinition) -> some View {
        let tree = Catalog.resolver(for: catalog.entries).resolutionTree(name: entry.name, definition: definition)
        return VStack(alignment: .leading, spacing: Spacing.md) {
            SectionLabel("Resolution chain")
            Text(AccessResolver.summary(of: definition))
                .font(.mono(11))
                .foregroundStyle(Theme.textSecondary)
            if let children = tree.children {
                VStack(alignment: .leading, spacing: 5) {
                    ForEach(children) { child in
                        ResolutionNodeView(node: child, depth: 0, catalog: catalog)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card()
    }

    private func mechanismsCard(_ definition: RuleDefinition) -> some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            SectionLabel("Mechanisms")
            VStack(alignment: .leading, spacing: 5) {
                ForEach(Array(definition.mechanisms.enumerated()), id: \.offset) { index, mechanism in
                    HStack(spacing: Spacing.sm) {
                        Text("\(index + 1).")
                            .font(.mono(11))
                            .foregroundStyle(Theme.textMuted)
                            .frame(width: 24, alignment: .trailing)
                        Text(mechanism)
                            .font(.mono(12))
                            .foregroundStyle(Theme.textPrimary)
                        if mechanism.hasSuffix(",privileged") {
                            TagChip("privileged", color: Theme.warning)
                        }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card()
    }

    private var driftCard: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            HStack(spacing: Spacing.sm) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundStyle(Theme.warning)
                SectionLabel("Live value differs from system template")
            }
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: Spacing.lg, verticalSpacing: 6) {
                GridRow {
                    Text("key").font(.eyebrow).tracking(1).foregroundStyle(Theme.textMuted)
                    Text("template").font(.eyebrow).tracking(1).foregroundStyle(Theme.textMuted)
                    Text("live").font(.eyebrow).tracking(1).foregroundStyle(Theme.textMuted)
                }
                ForEach(entry.driftedFields, id: \.key) { drift in
                    GridRow {
                        Text(drift.key).font(.mono(11)).foregroundStyle(Theme.textSecondary)
                        Text(drift.template).font(.system(size: 12)).foregroundStyle(Theme.textPrimary)
                        Text(drift.live).font(.system(size: 12, weight: .medium)).foregroundStyle(Theme.warning)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card(stroke: Theme.warning.opacity(0.35))
    }

    private var rawCard: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            HStack {
                SectionLabel("Raw plist")
                Spacer()
                if let definition = entry.effective {
                    Button { Clipboard.copy(definition.xml) } label: { Label("Copy plist", systemImage: "doc.on.doc") }
                        .buttonStyle(.ghost)
                    if let template = entry.template, entry.live != nil {
                        Button { Clipboard.copy(template.xml) } label: { Label("Copy template plist", systemImage: "doc.on.doc") }
                            .buttonStyle(.ghost)
                    }
                }
            }
            if let definition = entry.effective {
                CodeBlock {
                    Text(definition.xml)
                        .font(.mono(11))
                        .foregroundStyle(Theme.textSecondary)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card()
    }
}

struct ResolutionNodeView: View {
    let node: ResolutionNode
    let depth: Int
    let catalog: Catalog

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) {
            Text(String(repeating: "    ", count: depth) + "└ ")
                .font(.mono(11))
                .foregroundStyle(Theme.textMuted)
            Button(node.name) { catalog.selectedID = node.name }
                .buttonStyle(.plain)
                .font(.mono(12, weight: .semibold))
                .foregroundStyle(catalog.entry(named: node.name) == nil ? Theme.textMuted : Theme.emerald)
                .disabled(catalog.entry(named: node.name) == nil)
            Text(node.summary)
                .font(.system(size: 12))
                .foregroundStyle(node.exists ? Theme.textSecondary : Theme.warning)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        if let children = node.children {
            ForEach(children) { child in
                ResolutionNodeView(node: child, depth: depth + 1, catalog: catalog)
            }
        }
    }
}
