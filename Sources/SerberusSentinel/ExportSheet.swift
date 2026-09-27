import AppKit
import SerberusIntelCore
import SerberusUI
import SwiftUI

/// Collect → review → save/upload.
///
/// The review step is deliberate: the manifest knows which artifacts are
/// missing, and the user should see that *before* sending a bundle to the
/// Service Desk, not after someone opens it.
struct ExportSheet: View {
    @Bindable var model: IntelModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            header

            Divider()

            Group {
                switch model.exportPhase {
                case .idle:
                    idle
                case .collecting:
                    progress("Collecting Serberus logs…")
                case let .ready(bundle):
                    review(bundle)
                case .uploading:
                    progress("Uploading to Jamf…")
                case let .uploaded(computerID):
                    success(computerID: computerID)
                case let .failed(message):
                    failure(message)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)

            Divider()
            footer
        }
        .padding(20)
        .frame(width: 620, height: 520)
    }

    private var header: some View {
        HStack(spacing: 12) {
            SerberusMark(tone: .emerald)
                .frame(width: 28, height: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text("Export Serberus Logs")
                    .font(.headline)
                Text("Collects the unified log, signed decision logs, daemon state, and this Mac's details.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var idle: some View {
        VStack(alignment: .leading, spacing: 12) {
            Picker("Time range", selection: $model.window) {
                ForEach(LogWindow.allCases) { window in
                    Text(window.label).tag(window)
                }
            }
            .pickerStyle(.menu)
            .frame(maxWidth: 260)

            Toggle("Include info and debug messages", isOn: $model.includeInfoAndDebug)
            Text("Serberus logs at notice level and above, so this is only needed if Support asks for it. It makes the export considerably larger.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func progress(_ label: String) -> some View {
        VStack(spacing: 12) {
            ProgressView()
            Text(label).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func review(_ bundle: IntelBundle) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(bundle.suggestedFileName)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)

            if !bundle.manifest.missing.isEmpty {
                Label(
                    "\(bundle.manifest.missing.count) item(s) could not be collected. This is often expected — details below.",
                    systemImage: "exclamationmark.triangle.fill"
                )
                .font(.caption)
                .foregroundStyle(SerberusBrand.amber)
            }

            List(bundle.manifest.artifacts) { artifact in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: artifact.status.isCollected ? "checkmark.circle.fill" : "minus.circle")
                        .foregroundStyle(artifact.status.isCollected ? SerberusBrand.emerald : Color.secondary)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(artifact.path)
                            .font(.system(.caption, design: .monospaced))
                        Text(statusText(artifact))
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .listStyle(.inset)
        }
    }

    private func statusText(_ artifact: IntelArtifact) -> String {
        switch artifact.status {
        case let .collected(byteCount):
            return "\(artifact.detail) — \(ByteCountFormatter.string(fromByteCount: Int64(byteCount), countStyle: .file))"
        case let .unavailable(reason):
            return "Not collected: \(reason)"
        }
    }

    private func success(computerID: String) -> some View {
        VStack(spacing: 10) {
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 40))
                .foregroundStyle(SerberusBrand.emerald)
            Text("Uploaded to Jamf")
                .font(.headline)
            Text("Attached to computer record \(computerID).")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func failure(_ message: String) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Export failed", systemImage: "xmark.octagon.fill")
                .font(.headline)
                .foregroundStyle(SerberusBrand.critical)
            Text(message)
                .font(.callout)
                .textSelection(.enabled)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var footer: some View {
        HStack {
            Button("Close") { dismiss() }
                .keyboardShortcut(.cancelAction)

            Spacer()

            switch model.exportPhase {
            case .idle:
                Button("Collect Logs") {
                    Task { await model.collectBundle() }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)

            case let .ready(bundle):
                Button("Save…") { save(bundle) }
                Button("Upload to Jamf") {
                    Task { await model.upload(bundle: bundle) }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)

            case .failed:
                Button("Try Again") { model.resetExport() }
                    .buttonStyle(.borderedProminent)

            case .uploaded:
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)

            case .collecting, .uploading:
                EmptyView()
            }
        }
    }

    /// Copies the staged zip to a user-chosen location.
    private func save(_ bundle: IntelBundle) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = bundle.suggestedFileName
        panel.allowedContentTypes = [.zip]
        panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        do {
            try? FileManager.default.removeItem(at: destination)
            try FileManager.default.copyItem(at: bundle.archiveURL, to: destination)
            NSWorkspace.shared.activateFileViewerSelecting([destination])
        } catch {
            model.exportPhase = .failed(error.localizedDescription)
        }
    }
}
