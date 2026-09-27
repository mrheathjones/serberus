import PolicyBuilderCore
import PrivMgrCore
import SwiftUI

/// A capture file Commander has loaded and validated, ready to review.
struct ImportedCapture: Identifiable {
    let id = UUID()
    let capture: RuleCapture
    let fileName: String
    /// The Jamf upload this capture is (fetched from the Fleet Observer, or a
    /// file whose name matches an upload in the loaded fleet) — the review
    /// ledger records the import / rejection against it. `nil` = a local file
    /// with no known record; the ledger still remembers it by file name.
    var origin: FleetUpload? = nil
    /// Set when this capture came from the Fleet Observer with "delete from
    /// Jamf after import" on: the record is cleared only once the import
    /// commits (a definition is created), never on Cancel.
    var harvestFrom: FleetUpload? = nil
}

/// Import Capture (Rule Recorder, Commander side): the timeline of what the
/// user did — every sudo command and authorization right recorded in
/// Sentinel — with a checkbox per attempt. One selection opens the Definition
/// composer pre-filled; several create their definitions directly (each
/// still a plain Definition the admin binds to a Rule afterwards). Nothing is
/// published from here.
///
/// A capture is **evidence, not proof**: it is a user-supplied file. The sheet
/// shows everything the recorder saw, pre-selects only what Serberus does not
/// already govern, and collapses repeats — the admin still reads each path
/// before it becomes a definition.
struct ImportCaptureSheet: View {
    @Bindable var model: PolicyBuilderModel
    let imported: ImportedCapture
    /// Header title. The Fleet Observer reviews a capture in place ("Review
    /// Capture") and only leaves for Definitions when a definition is created;
    /// the Definitions file-import path keeps "Import Capture".
    var title: String = "Import Capture"
    /// Exactly one attempt chosen → open the composer with this draft.
    let onCreateOne: (DefinitionDraft) -> Void
    /// Several attempts created directly → the new definition ids.
    let onCreated: ([String]) -> Void
    /// Reviewed and REJECTED: no definition will be made from this capture.
    /// The caller records it (review ledger → it stops counting as an upload
    /// waiting) and, with the harvest switch on, clears the Jamf record.
    let onReject: () -> Void
    /// Whether rejecting also deletes the file from its Jamf record (the
    /// Fleet Observer's harvest switch) — for the confirmation text only.
    var deletesFromJamfOnReject = false
    let dismiss: () -> Void

    @State private var selected: Set<String> = []
    @State private var confirmingReject = false

    private var capture: RuleCapture { imported.capture }
    private var attempts: [CapturedAttempt] { capture.attempts }

    private static let time: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    /// Display cap for strings that come straight from the file (the decoder
    /// bounds the document, not each string).
    private static let maxShownCharacters = 300

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(Theme.hairline)
            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.lg) {
                    contextCard
                    attemptsCard
                }
                .padding(Spacing.xl)
            }
            .scrollIndicators(.never)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            Divider().overlay(Theme.hairline)
            footer
        }
        .frame(width: 820, height: 640)
        .background(Theme.background)
        .preferredColorScheme(.dark)
        .tint(Theme.emerald)
        .onAppear {
            // Pre-select what is most likely wanted: the FIRST occurrence of
            // each distinct target that is NOT already governed by a Serberus
            // rule. Repeats of the same command/right stay visible but
            // unchecked, with a hint pointing at the one that is.
            var seen = Set<String>()
            selected = Set(attempts.compactMap { attempt in
                guard attempt.matchedRuleID == nil, seen.insert(Self.targetKey(attempt)).inserted else { return nil }
                return attempt.id
            })
        }
    }

    // MARK: Header

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                    .font(.system(size: 17, weight: .bold)).foregroundStyle(Theme.textPrimary)
                Text(subtitle).font(.system(size: 12)).foregroundStyle(Theme.textMuted).lineLimit(1)
            }
            Spacer()
        }
        .padding(Spacing.lg)
    }

    private var subtitle: String {
        let seconds = Int(capture.endedAt.timeIntervalSince(capture.startedAt))
        let duration = String(format: "%d:%02d", seconds / 60, seconds % 60)
        let count = attempts.count
        return "\(imported.fileName) · \(count) \(count == 1 ? "attempt" : "attempts") · \(duration) · \(clip(capture.host.computerName)) · \(clip(capture.host.userName))"
    }

    // MARK: Context

    private var contextCard: some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            SectionLabel("Recorded on")
            DetailRow(label: "Mac", value: clip("\(capture.host.computerName)\(capture.host.serialNumber.map { " · \($0)" } ?? "")"), mono: true)
            DetailRow(label: "User", value: clip(capture.host.userName))
            DetailRow(label: "macOS", value: clip(capture.host.osVersion))
            DetailRow(label: "Serberus", value: serberusLine, valueColor: serberusConsulted ? Theme.textPrimary : Theme.warning)
            if !capture.notes.isEmpty {
                DetailRow(label: "Notes", value: clip(capture.notes, limit: 1_000))
            }
            if capture.argumentsRedacted {
                Text("Arguments were redacted by the recorder — sudo definitions will pin the command only.")
                    .font(.system(size: 11)).foregroundStyle(Theme.warning)
            }
            Text("A capture is evidence the user supplied, not proof: read each path before it becomes a definition. sudo definitions are pinned to the command's FIRST argument — clear the argument filter in the composer to match any arguments.")
                .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
        }
        .card()
    }

    private var serberusConsulted: Bool {
        (capture.host.enforcementMode ?? "") == "enforce" || (capture.host.enforcementMode ?? "") == "audit"
    }

    private var serberusLine: String {
        var parts: [String] = []
        if let state = capture.host.daemonState { parts.append(clip(state)) }
        if let mode = capture.host.enforcementMode { parts.append("\(clip(mode)) mode") }
        if let version = capture.componentVersions["daemonVersion"] { parts.append("daemon \(clip(version))") }
        if parts.isEmpty { return "not installed / unknown" }
        if !serberusConsulted { parts.append("— sudo attempts are from sudo's own log; Serberus was not consulted") }
        return parts.joined(separator: " · ")
    }

    // MARK: Attempts

    private var attemptsCard: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            HStack {
                SectionLabel("Attempts")
                Spacer()
                Button("Select all") { selected = Set(attempts.map(\.id)) }.buttonStyle(.ghost)
                Button("None") { selected.removeAll() }.buttonStyle(.ghost)
            }
            if attempts.isEmpty {
                Text("This capture recorded no attempts.")
                    .font(.system(size: 12)).foregroundStyle(Theme.textMuted)
            } else {
                LazyVStack(spacing: 0) {
                    ForEach(Array(attempts.enumerated()), id: \.element.id) { index, attempt in
                        row(attempt, firstSeenAt: firstOccurrence[Self.targetKey(attempt)])
                        if index < attempts.count - 1 { Divider().overlay(Theme.hairline) }
                    }
                }
            }
        }
        .card()
    }

    /// For each distinct target, the timestamp of its first attempt — drives
    /// the "same as HH:mm:ss" hint on repeats.
    private var firstOccurrence: [String: Date] {
        var first: [String: Date] = [:]
        for attempt in attempts {
            let key = Self.targetKey(attempt)
            if first[key] == nil { first[key] = attempt.timestamp }
        }
        return first
    }

    private func row(_ attempt: CapturedAttempt, firstSeenAt: Date?) -> some View {
        let isOn = Binding(
            get: { selected.contains(attempt.id) },
            set: { on in if on { selected.insert(attempt.id) } else { selected.remove(attempt.id) } }
        )
        let isRepeat = firstSeenAt.map { $0 < attempt.timestamp } ?? false
        return HStack(alignment: .top, spacing: Spacing.md) {
            Toggle("", isOn: isOn).toggleStyle(.checkbox).labelsHidden()
                .accessibilityLabel("Include \(attempt.target)")
            Text(Self.time.string(from: attempt.timestamp))
                .font(.mono(11)).foregroundStyle(Theme.textMuted)
                .frame(width: 60, alignment: .leading)
            RuleDecisionBadge(attempt.kind == .sudo ? "sudo" : "right",
                              color: attempt.kind == .sudo ? Theme.info : Theme.emerald)
            VStack(alignment: .leading, spacing: 3) {
                Text(clip(attempt.target))
                    .font(.mono(12)).foregroundStyle(Theme.textPrimary)
                    .lineLimit(2)
                    .textSelection(.enabled)
                HStack(spacing: Spacing.sm) {
                    if let user = attempt.user { Text(clip(user)) }
                    if attempt.kind == .authuri, let client = attempt.clientPath {
                        Text(clip((client as NSString).lastPathComponent))
                    }
                    if let resolved = attempt.resolvedCommand { Text("→ \(clip(resolved))").font(.mono(10)) }
                    if let team = attempt.teamID { Text("Team \(clip(team))") }
                    if let rule = attempt.matchedRuleID {
                        Text("Serberus rule \(clip(rule))").foregroundStyle(Theme.emerald)
                    } else if let verdict = attempt.serberusOutcome {
                        Text("Serberus \(clip(verdict)) · no rule matched").foregroundStyle(Theme.warning)
                    }
                    if let branch = attempt.predictedBranch,
                       !AppIdentityAvailability.enabled, branch != BranchMatchResolver.nativeDefault {
                        // The daemon composes no per-app branch in 0.9.0.
                        Text("per-app branch ignored (disabled in 0.9.0)").foregroundStyle(Theme.warning)
                            .help(AuthURIIdentityScope.disabledValidationMessage)
                    } else if let branch = attempt.predictedBranch {
                        let isNative = branch == BranchMatchResolver.nativeDefault
                        Text(isNative ? "branch: native-default" : "branch: \(clip(String(branch.split(separator: ".").suffix(2).joined(separator: "."))))")
                            .foregroundStyle(isNative ? Theme.warning : Theme.emerald)
                            .help(isNative ? "No app branch's code requirement matches the logged client — authd would fall back to the right's native definition (e.g. the client is a mediator such as /usr/libexec/smd)."
                                           : "The logged client satisfies this per-app branch's code requirement. A prediction from the capture; the raw authd lines are the source of truth.")
                        if let evidence = attempt.branchEvidence, !evidence.isEmpty {
                            Text("authd named a branch ×\(evidence.count)").foregroundStyle(Theme.emerald)
                        }
                    }
                    if isRepeat, let firstSeenAt {
                        Text("same as \(Self.time.string(from: firstSeenAt))").foregroundStyle(Theme.textMuted)
                    }
                    if let existing = existingDefinition(for: attempt) {
                        Text("already defined: \(existing.id)").foregroundStyle(Theme.warning)
                    }
                }
                .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
                .lineLimit(1)
            }
            Spacer(minLength: Spacing.md)
            StatusBadge(outcomeLabel(attempt), tone: outcomeTone(attempt))
        }
        .padding(.vertical, Spacing.sm)
    }

    /// What makes two attempts "the same thing to author": kind + the path /
    /// right + the first argument. Team ID is deliberately not part of the
    /// key (two runs of one binary always share it).
    static func targetKey(_ attempt: CapturedAttempt) -> String {
        switch attempt.kind {
        case .sudo:
            return "sudo|\(attempt.resolvedCommand ?? attempt.sudoCommand ?? "")|\(attempt.argv?.first ?? "")"
        case .authuri:
            return "authuri|\(attempt.authURI ?? "")"
        }
    }

    /// A library definition that already matches this attempt's target — a
    /// hint, not a block (the admin may want a narrower/different pin).
    /// Considers both the logged path and its realpath on both sides.
    private func existingDefinition(for attempt: CapturedAttempt) -> RuleDefinition? {
        model.definitions.first { definition in
            switch attempt.kind {
            case .sudo:
                guard definition.kind == .sudo else { return false }
                let defined = Set([definition.commandPattern, definition.resolvedCommandPattern].compactMap { $0 })
                let seen = Set([attempt.sudoCommand, attempt.resolvedCommand].compactMap { $0 })
                return !defined.isDisjoint(with: seen)
            case .authuri:
                return definition.kind == .authuri && definition.authURI == attempt.authURI
            }
        }
    }

    /// An `unknown` sudo outcome with a Serberus verdict (older captures, or
    /// a deny text no phrase-list knows) reads as that verdict.
    private func effectiveOutcome(_ attempt: CapturedAttempt) -> CapturedOutcome {
        guard attempt.outcome == .unknown, let verdict = attempt.serberusOutcome else { return attempt.outcome }
        switch verdict {
        case "granted": return .granted
        case "denied": return .denied
        default: return .unknown
        }
    }

    private func outcomeLabel(_ attempt: CapturedAttempt) -> String {
        switch effectiveOutcome(attempt) {
        case .granted: return "granted"
        case .denied: return "denied"
        case .failed: return "failed"
        case .requested: return "requested"
        case .unknown: return "unknown"
        }
    }

    private func outcomeTone(_ attempt: CapturedAttempt) -> StatusTone {
        switch effectiveOutcome(attempt) {
        case .granted: return .healthy
        case .denied: return .degraded
        case .failed: return .pending
        case .requested, .unknown: return .neutral
        }
    }

    /// A string from the file as shown: hidden characters as visible escapes
    /// (``DisplayText/escapingInvisibles(_:)``), then capped.
    private func clip(_ text: String, limit: Int = ImportCaptureSheet.maxShownCharacters) -> String {
        let shown = DisplayText.escapingInvisibles(text)
        return shown.count <= limit ? shown : String(shown.prefix(limit)) + "…"
    }

    // MARK: Footer

    private var selectedAttempts: [CapturedAttempt] { attempts.filter { selected.contains($0.id) } }

    /// Selected attempts collapsed to one per distinct target (first in
    /// time order wins), minus anything with no target to author.
    private var authorableAttempts: [CapturedAttempt] {
        var seen = Set<String>()
        return selectedAttempts.filter { attempt in
            let target: String? = attempt.kind == .sudo ? attempt.sudoCommand : attempt.authURI
            guard let target, !target.isEmpty else { return false }
            return seen.insert(Self.targetKey(attempt)).inserted
        }
    }

    private var footer: some View {
        HStack {
            Text(footerStatus)
                .font(.system(size: 12)).foregroundStyle(Theme.textMuted)
            Spacer()
            // Order: Cancel · Reject · Create (leading→trailing). Cancel leaves
            // the capture waiting for another look; Reject = reviewed, deliberately
            // not a definition; Create is the primary (trailing) action.
            Button("Cancel") { dismiss() }.buttonStyle(.ghost).keyboardShortcut(.cancelAction)
            Button { confirmingReject = true } label: {
                Label("Reject", systemImage: "xmark.circle").foregroundStyle(Theme.critical)
            }
                .buttonStyle(.ghost)
                .help("Mark this capture reviewed with NO definition created — it stops counting as an upload waiting\(deletesFromJamfOnReject && imported.origin != nil ? " and is removed from the Jamf record" : "")")
                .confirmationDialog("Reject this capture?", isPresented: $confirmingReject, titleVisibility: .visible) {
                    Button("Reject Capture", role: .destructive) { onReject() }
                    Button("Keep Reviewing", role: .cancel) {}
                } message: {
                    Text(rejectMessage)
                }
            if authorableAttempts.count == 1, let only = authorableAttempts.first {
                Button("Create Definition") {
                    onCreateOne(AppIdentityAvailability.available(
                        CaptureImporter.draft(for: only, capture: capture, existingIDs: existingIDs)))
                }
                .buttonStyle(.emerald).keyboardShortcut(.defaultAction)
            } else {
                Button("Create \(authorableAttempts.count) Definitions") { createSelected() }
                    .buttonStyle(.emerald).keyboardShortcut(.defaultAction)
                    .disabled(authorableAttempts.count < 2)
            }
        }
        .padding(Spacing.lg)
    }

    private var rejectMessage: String {
        var text = "\(imported.fileName) is marked reviewed — no definition is created from it — so it no longer counts as an upload waiting on the Dashboard."
        if let origin = imported.origin {
            text += deletesFromJamfOnReject
                ? " It is also removed from \(origin.deviceName)'s Jamf record (the Fleet Observer harvest switch is on)."
                : " The file stays on \(origin.deviceName)'s Jamf record (shown as Rejected in Fleet Observer) until you delete it there."
        }
        text += " Cancel instead if you want to come back to it."
        return text
    }

    private var footerStatus: String {
        if selected.isEmpty { return "Select the attempts to turn into definitions" }
        let collapsed = selectedAttempts.count - authorableAttempts.count
        var text = "\(selected.count) selected"
        if collapsed > 0 { text += " · \(collapsed) repeat\(collapsed == 1 ? "" : "s") collapsed" }
        return text
    }

    private var existingIDs: Set<String> { Set(model.definitions.map(\.id)) }

    /// Creates one definition per distinct selected target, in time order,
    /// with slugs unique across the library and the batch — persisted once.
    private func createSelected() {
        // No App Identity drafts while per-app rules are disabled.
        let drafts = CaptureImporter.drafts(for: authorableAttempts, capture: capture, existingIDs: existingIDs)
            .map(AppIdentityAvailability.available)
        model.upsertDefinitions(drafts.map { $0.toDefinition() })
        onCreated(drafts.map(\.definitionID))
    }
}
