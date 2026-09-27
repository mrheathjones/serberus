import AppKit
import PrivMgrCore
import SerberusIntelCore
import SerberusUI
import SwiftUI
import UniformTypeIdentifiers

/// Capture (Rule Recorder) review: what was recorded → notes + redaction →
/// Save… / Upload to Jamf. Mirrors ``ExportSheet``'s shape so the two Intel
/// hand-offs feel like one tool.
///
/// The review step is deliberate: the user sees exactly which sudo commands
/// (with arguments) and which rights are about to leave this Mac, can strip
/// arguments, and can discard — nothing is written or uploaded without it.
struct CaptureReviewSheet: View {
    @Bindable var model: IntelModel
    @Environment(\.dismiss) private var dismiss
    @State private var confirmDiscard = false
    /// A failed local save — surfaced in place; the capture stays in review.
    @State private var saveError: String?

    private static let captureType = UTType(filenameExtension: RuleCapture.fileExtension) ?? .json

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            header
            Divider()
            Group {
                switch model.capturePhase {
                case .idle:
                    Text("No capture in progress.").foregroundStyle(.secondary)
                case .recording:
                    progress("Recording…")
                case .building:
                    progress("Assembling the capture…")
                case let .review(capture):
                    review(capture)
                case .uploading:
                    progress("Uploading to Jamf…")
                case let .uploaded(_, computerID):
                    success(computerID: computerID)
                case let .failed(_, message):
                    failure(message)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            Divider()
            footer
        }
        .padding(20)
        .frame(width: 720, height: 600)
        .confirmationDialog("Discard this capture?", isPresented: $confirmDiscard, titleVisibility: .visible) {
            Button("Discard Capture", role: .destructive) {
                model.discardCapture()
                dismiss()
            }
            Button("Keep", role: .cancel) {}
        } message: {
            Text("Nothing has been saved or uploaded. The recorded attempts will be lost.")
        }
        .alert("Couldn't save the capture",
               isPresented: Binding(get: { saveError != nil }, set: { if !$0 { saveError = nil } })) {
            Button("OK") { saveError = nil }
        } message: {
            Text(saveError ?? "")
        }
    }

    // MARK: Header

    private var header: some View {
        HStack(spacing: 12) {
            SerberusMark(tone: .emerald)
                .frame(width: 28, height: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text("Capture")
                    .font(.headline)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var subtitle: String {
        guard let capture = model.capturePhase.capture else {
            return "Every sudo and authorization attempt on this Mac, recorded for Commander's Import Capture."
        }
        let seconds = Int(capture.endedAt.timeIntervalSince(capture.startedAt))
        let duration = String(format: "%d:%02d", seconds / 60, seconds % 60)
        let count = capture.attempts.count
        return "\(count) \(count == 1 ? "attempt" : "attempts") · \(duration) · \(capture.host.computerName) · \(capture.host.userName)"
    }

    // MARK: Review

    private func review(_ capture: RuleCapture) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            if capture.attempts.isEmpty {
                emptyState
            } else {
                List(capture.attempts) { attempt in
                    CapturedAttemptRow(attempt: attempt, redacted: model.captureRedactArguments)
                }
                .listStyle(.inset)
            }

            if let enforcement = capture.host.enforcementMode, enforcement != "enforce" {
                Label(
                    "Serberus is in \(enforcement) mode on this Mac — sudo attempts below come from sudo's own log; Serberus was not consulted.",
                    systemImage: "info.circle"
                )
                .font(.caption)
                .foregroundStyle(.secondary)
            }

            TextField("Notes for the admin (what was the user trying to do?)", text: $model.captureNotes, axis: .vertical)
                .lineLimit(2...4)
                .textFieldStyle(.roundedBorder)

            Toggle("Redact sudo arguments (keep only the command paths)", isOn: $model.captureRedactArguments)
                .toggleStyle(.checkbox)
            Text("Arguments can carry secrets. Redaction removes them from the saved/uploaded file; the rule can still pin the command.")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    private var emptyState: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("No attempts were recorded", systemImage: "waveform.slash")
                .font(.headline)
            if let reason = model.captureUnavailable {
                Text("The Serberus daemon could not be polled: \(reason). Without it, sudo and authorization lines cannot be read as a standard user.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                Text("Nothing used sudo or asked for an authorization right while recording. Start a capture, reproduce the user's action, then stop.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    private func progress(_ label: String) -> some View {
        VStack(spacing: 12) {
            ProgressView()
            Text(label).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func success(computerID: String) -> some View {
        VStack(spacing: 10) {
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 40))
                .foregroundStyle(SerberusBrand.emerald)
            Text("Uploaded to Jamf")
                .font(.headline)
            Text("Capture attached to computer record \(computerID). In Commander: Definitions → Import Capture.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func failure(_ message: String) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Upload failed", systemImage: "xmark.octagon.fill")
                .font(.headline)
                .foregroundStyle(SerberusBrand.critical)
            Text(message)
                .font(.callout)
                .textSelection(.enabled)
                .foregroundStyle(.secondary)
            Text("The capture is not lost — go back to save it locally or try the upload again.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    // MARK: Footer

    @ViewBuilder
    private var footer: some View {
        HStack {
            switch model.capturePhase {
            case .review:
                Button("Discard", role: .destructive) { confirmDiscard = true }
            case .failed:
                Button("Back to Review") { model.retryCaptureReview() }
            default:
                EmptyView()
            }

            Button("Close") { dismiss() }
                .keyboardShortcut(.cancelAction)

            Spacer()

            switch model.capturePhase {
            case let .review(capture):
                Button("Save…") { save(capture) }
                    .disabled(capture.attempts.isEmpty)
                // No default-action shortcut: Return in the Notes field must
                // never fire a network upload.
                Button("Upload to Jamf") {
                    Task { await model.uploadCapture(capture) }
                }
                .buttonStyle(.borderedProminent)
                .disabled(capture.attempts.isEmpty)

            case .uploaded:
                Button("Done") {
                    model.resetCapture()
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)

            case .idle, .recording, .building, .uploading, .failed:
                EmptyView()
            }
        }
    }

    /// Writes the finalized capture where the user chooses.
    private func save(_ capture: RuleCapture) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = model.finalizedCapture(capture).suggestedFileName
        panel.allowedContentTypes = [Self.captureType, .json]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        do {
            try model.saveCapture(capture, to: destination)
            NSWorkspace.shared.activateFileViewerSelecting([destination])
            model.resetCapture()
            dismiss()
        } catch {
            // Surface in place; the capture stays in review so the user can
            // pick another location or upload instead.
            saveError = "Couldn't write \(destination.path): \(error.localizedDescription)"
        }
    }
}

/// One recorded attempt: kind, time, what, who, how it ended, and whether
/// Serberus already had a rule for it.
struct CapturedAttemptRow: View {
    let attempt: CapturedAttempt
    let redacted: Bool

    private static let time: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(Self.time.string(from: attempt.timestamp))
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(.secondary)
                .frame(width: 62, alignment: .leading)
            Text(attempt.kind == .sudo ? "SUDO" : "RIGHT")
                .font(.system(size: 10, weight: .bold))
                .padding(.horizontal, 6).padding(.vertical, 2)
                .background(Color.primary.opacity(0.08), in: RoundedRectangle(cornerRadius: 4, style: .continuous))
            VStack(alignment: .leading, spacing: 2) {
                Text(target)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(2)
                    .textSelection(.enabled)
                HStack(spacing: 8) {
                    if let user = attempt.user { Text(user) }
                    if attempt.kind == .authuri, let client = attempt.clientPath {
                        Text((client as NSString).lastPathComponent)
                    }
                    if let team = attempt.teamID { Text("Team \(team)") }
                    if let rule = attempt.matchedRuleID {
                        Text("Serberus rule \(rule)").foregroundStyle(SerberusBrand.emerald)
                    } else if let verdict = attempt.serberusOutcome {
                        Text("Serberus \(verdict) · no rule matched").foregroundStyle(SerberusBrand.amber)
                    }
                    // Composed (per-app) right: which branch the client binary
                    // satisfies, and whether authd itself named a branch row.
                    // Per-app rules are disabled in 0.9.0: the daemon
                    // composes no branch, so a predicted app branch is only
                    // what an older build would have done.
                    if let branch = attempt.predictedBranch,
                       !AuthURIIdentityScope.perAppPinsEnabled, branch != BranchMatchResolver.nativeDefault {
                        Text("per-app branch ignored: per-app rules are disabled in Serberus 0.9.0")
                            .foregroundStyle(SerberusBrand.amber)
                    } else if let branch = attempt.predictedBranch {
                        let isNative = branch == BranchMatchResolver.nativeDefault
                        Text(isNative ? "branch: native-default (no app branch matches this client)"
                                      : "branch: \((branch as NSString).pathExtension.isEmpty ? branch : String(branch.split(separator: ".").suffix(2).joined(separator: ".")))")
                            .foregroundStyle(isNative ? SerberusBrand.amber : SerberusBrand.emerald)
                        if let evidence = attempt.branchEvidence {
                            Text(evidence.isEmpty ? "authd named no branch" : "authd named a branch ×\(evidence.count)")
                        }
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            Spacer()
            Text(outcomeLabel)
                .font(.caption.weight(.semibold))
                .foregroundStyle(outcomeColor)
        }
        .padding(.vertical, 3)
    }

    private var target: String {
        guard attempt.kind == .sudo, redacted else { return attempt.target }
        return attempt.sudoCommand ?? attempt.target
    }

    private var outcomeLabel: String {
        switch attempt.outcome {
        case .granted: return "granted"
        case .denied: return "denied"
        case .failed: return attempt.sudoStatus ?? "failed"
        case .requested: return "requested"
        case .unknown: return attempt.sudoStatus ?? "unknown"
        }
    }

    private var outcomeColor: Color {
        switch attempt.outcome {
        case .granted: return SerberusBrand.emerald
        case .denied: return SerberusBrand.critical
        case .failed: return SerberusBrand.amber
        case .requested, .unknown: return .secondary
        }
    }
}
