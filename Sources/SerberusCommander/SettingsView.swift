import AppKit
import PolicyBuilderCore
import PrivMgrCore
import SwiftUI

/// Settings — connect Serberus to an MDM of choice (vendor, URL, credentials),
/// test connectivity live, browse the MDM's configuration profiles, publish
/// policies, and view the production (MDM-delivered) connection status.
struct SettingsView: View {
    @Bindable var model: PolicyBuilderModel
    @State private var jitSaved: URL?
    @State private var jitSaveError: String?
    @State private var configSaved: URL?
    @State private var configSaveError: String?
    @State private var setupSaved: URL?
    @State private var setupError: String?

    private var mdm: MDMSettingsModel { model.mdm }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                ScreenHeader("Settings", subtitle: "Connect to your MDM and manage configuration profiles")
                connectionCard
                configProfilesCard
                jitAdminCard
                configCard
                productionCard
                postureCard
                permissionsCard
                if JamfSetupFiles.isAvailable { jamfSetupCard }
                securityCard
            }
            .padding(Spacing.xl)
        }
        .scrollIndicators(.never)
        .onAppear { model.refreshDirectPublishGate() }
    }

    // MARK: MDM connection

    private var connectionCard: some View {
        VStack(alignment: .leading, spacing: Spacing.lg) {
            HStack {
                SectionLabel("MDM connection")
                Spacer()
                if let savedAt = mdm.savedAt {
                    Text("saved \(savedAt.formatted(date: .omitted, time: .shortened))")
                        .font(.system(size: 10)).foregroundStyle(Theme.textMuted)
                }
            }

            VStack(alignment: .leading, spacing: 5) {
                Text("Vendor").font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textSecondary)
                Picker("", selection: $model.mdm.vendor) {
                    // Only implemented vendors are offered. One saved before
                    // they were hidden stays listed so the selection still
                    // shows, with the notice below.
                    ForEach(MDMVendor.allCases.filter { $0.isSupported || $0 == mdm.vendor }) { vendor in
                        Text(vendor.displayName + (vendor.isSupported ? "" : " (not implemented)")).tag(vendor)
                    }
                }
                .labelsHidden().pickerStyle(.menu).fixedSize()
            }

            if !mdm.vendor.isSupported {
                notice("\(mdm.vendor.displayName) is not implemented. You can save the connection, but testing will report it as unsupported.",
                       symbol: "info.circle", tone: .neutral)
            }

            LabeledField(label: mdm.vendor.instanceLabel) {
                TextField(mdm.vendor.instancePlaceholder, text: $model.mdm.instanceURL)
                    .textContentType(.URL).autocorrectionDisabled()
            }
            HStack(spacing: Spacing.lg) {
                LabeledField(label: mdm.vendor.clientIDLabel) {
                    TextField("", text: $model.mdm.clientID).autocorrectionDisabled()
                }
                LabeledField(label: mdm.vendor.clientSecretLabel) {
                    SecureField("", text: $model.mdm.clientSecret)
                }
            }

            HStack(spacing: Spacing.sm) {
                Button { mdm.save() } label: { Label("Save", systemImage: "square.and.arrow.down") }
                    .buttonStyle(.ghost)
                Button { mdm.save(); Task { await mdm.test() } } label: {
                    Label("Test Connection", systemImage: "bolt.horizontal.circle")
                }
                .buttonStyle(.emerald)
                .disabled(!model.mdm.connection.isComplete || isTesting)
                Spacer()
                testStatus
            }
        }
        .card()
    }

    private var isTesting: Bool { if case .testing = mdm.testState { return true }; return false }

    @ViewBuilder
    private var testStatus: some View {
        switch mdm.testState {
        case .idle:
            EmptyView()
        case .testing:
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text("Testing…").font(.system(size: 11)).foregroundStyle(Theme.textMuted)
            }
        case let .result(result):
            if result.isSuccess {
                StatusBadge(result.headline, tone: .healthy, symbol: "checkmark.circle.fill")
            } else {
                StatusBadge(result.headline, tone: resultTone(result), symbol: "exclamationmark.triangle.fill")
            }
        }
    }

    private func resultTone(_ result: MDMResult) -> StatusTone {
        switch result {
        case .invalidCredentials, .insufficientPermissions: return .degraded
        case .unreachable, .misconfigured, .notSupported:   return .pending
        case .connected:                                    return .healthy
        }
    }

    // MARK: Config profiles

    private var configProfilesCard: some View {
        VStack(alignment: .leading, spacing: Spacing.lg) {
            HStack {
                SectionLabel("Configuration profiles")
                Spacer()
                Button { Task { await mdm.fetchProfiles() } } label: {
                    Label("Fetch from MDM", systemImage: "arrow.clockwise")
                }
                .buttonStyle(.ghost).disabled(!model.mdm.connection.isComplete)
            }

            switch mdm.profilesState {
            case .idle:
                notice("Fetch to list the configuration profiles in your MDM.", symbol: "tray", tone: .neutral)
            case .loading:
                HStack(spacing: 8) { ProgressView().controlSize(.small); Text("Loading profiles…").font(.system(size: 12)).foregroundStyle(Theme.textMuted) }
            case let .loaded(profiles):
                if profiles.isEmpty {
                    notice("No configuration profiles found in the MDM.", symbol: "tray", tone: .neutral)
                } else {
                    VStack(spacing: 4) {
                        ForEach(profiles) { profile in
                            HStack(spacing: Spacing.md) {
                                Image(systemName: "doc.badge.gearshape").font(.system(size: 12)).foregroundStyle(Theme.info)
                                Text(profile.name).font(.system(size: 12, weight: .medium)).foregroundStyle(Theme.textPrimary)
                                Spacer()
                                Text("#\(profile.id)").font(.mono(10)).foregroundStyle(Theme.textMuted)
                            }
                            .padding(.horizontal, Spacing.sm).padding(.vertical, 6)
                            .background(Theme.background.opacity(0.4), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
                        }
                    }
                }
            case let .failed(result):
                notice(result.headline, symbol: "exclamationmark.triangle.fill", tone: resultTone(result))
            }

            // (The old "Publish a policy → Publish to MDM…" menu that lived
            // here is gone: it published rule policies with no validation /
            // conflict gate, under a per-profile name that diverged from the
            // stable "Serberus — <policy id>", and it bypassed the
            // commanderPublishEnabled gate. Rule publish lives on the policy
            // card / Edit Policy / Export sheet only.)
            publishStatus
        }
        .card()
    }

    @ViewBuilder
    private var publishStatus: some View {
        switch mdm.publishState {
        case .idle:
            EmptyView()
        case .working:
            HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Publishing…").font(.system(size: 11)).foregroundStyle(Theme.textMuted) }
        case let .result(result):
            notice(result.headline, symbol: result.isSuccess ? "checkmark.seal.fill" : "exclamationmark.triangle.fill",
                   tone: result.isSuccess ? .healthy : resultTone(result))
        }
    }

    // MARK: JIT local-admin policy

    private var jit: JITAdminSettingsModel { model.jitAdmin }

    private var jitAdminCard: some View {
        VStack(alignment: .leading, spacing: Spacing.lg) {
            SectionLabel("Just-in-time admin")

            VStack(alignment: .leading, spacing: 5) {
                Text("Provider").font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textSecondary)
                SegmentedControl(selection: $model.jitAdmin.provider,
                                 options: [.disabled: "Disabled", .serberus: "Serberus (native)",
                                           .jamfConnect: "Jamf Connect / Self Service+"],
                                 label: "Provider")
            }

            switch jit.provider {
            case .disabled:
                notice("Self-service local-admin elevation is off. Choose a provider to let scoped users temporarily elevate.",
                       symbol: "info.circle", tone: .neutral)
            case .serberus:
                LabeledField(label: "Eligible groups (comma-separated)") {
                    TextField("staff, developers", text: $model.jitAdmin.eligibleGroupsText).autocorrectionDisabled()
                }
                HStack(spacing: Spacing.lg) {
                    LabeledField(label: "Max window (minutes)") {
                        TextField("15", value: $model.jitAdmin.durationMinutes, format: .number)
                    }
                    LabeledField(label: "Min justification length") {
                        TextField("10", value: $model.jitAdmin.justificationMinLength, format: .number)
                    }
                }
                Toggle("Require justification", isOn: $model.jitAdmin.requireJustification)
                    .toggleStyle(.switch).tint(Theme.emerald)
            case .jamfConnect:
                LabeledField(label: "Jamf Connect elevation command (full path, blank for the default)") {
                    TextField(JamfConnectCommand.jamfConnectDefault.path, text: $model.jitAdmin.jamfConnectPath)
                        .autocorrectionDisabled()
                }
                LabeledField(label: "Arguments (used only with a custom path, space-separated)") {
                    TextField(JamfConnectCommand.jamfConnectDefault.arguments.joined(separator: " "),
                              text: $model.jitAdmin.jamfConnectArgsText).autocorrectionDisabled()
                }
                notice("The menu bar app becomes a single button that runs this command to trigger Jamf Connect elevation, after checking that the binary is signed by Jamf. Jamf Connect owns the reason prompt, eligibility, and expiration; Serberus watches the elevations Jamf Connect logs so it can step aside for sudo while the user is an admin.",
                       symbol: "info.circle", tone: .neutral)
                notice("Privilege elevation with URLCommandLineElevation must be enabled in the Jamf Connect / Self Service+ profile.",
                       symbol: "exclamationmark.circle", tone: .neutral)
            }

            if let blocker = jit.exportBlocker {
                notice(blocker, symbol: "exclamationmark.triangle.fill", tone: .pending)
            }
            if let jitSaved {
                HStack(spacing: 6) {
                    Label("Saved \(jitSaved.lastPathComponent)", systemImage: "checkmark.seal").foregroundStyle(.green)
                    Button("Reveal in Finder") { NSWorkspace.shared.activateFileViewerSelecting([jitSaved]) }
                        .buttonStyle(.link)
                }
                .font(.system(size: 12))
            }
            if let jitSaveError {
                notice(jitSaveError, symbol: "exclamationmark.triangle", tone: .degraded)
            }
            if let error = jit.lastExportError {
                notice(error, symbol: "exclamationmark.triangle", tone: .degraded)
            }

            HStack(spacing: Spacing.sm) {
                Button { jit.save() } label: { Label("Save", systemImage: "square.and.arrow.down") }
                    .buttonStyle(.ghost)
                Button { exportJIT() } label: { Label("Export .mobileconfig", systemImage: "arrow.up.doc") }
                    .buttonStyle(.ghost).disabled(!jit.canExport)
                Button { Task { await publishJIT() } } label: { Label("Publish to Jamf", systemImage: "arrow.up.doc.on.clipboard") }
                    .buttonStyle(.emerald)
                    .disabled(!jit.canExport || !model.mdm.connection.isComplete)
                    .help(model.mdm.connection.isComplete
                          ? "Create a new JIT Admin configuration profile in your MDM (scope it there)"
                          : "Configure the MDM connection above to publish")
                Spacer()
            }
            publishStatus
        }
        .card()
    }

    private func exportJIT() {
        jitSaved = nil
        jitSaveError = nil
        guard let result = jit.export() else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = result.suggestedFilename
        panel.canCreateDirectories = true
        panel.title = "Export JIT Admin .mobileconfig"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try result.data.write(to: url, options: .atomic)
            jitSaved = url
        } catch {
            jitSaveError = "Could not save \(url.lastPathComponent): \(error.localizedDescription)"
        }
    }

    /// Generates the JIT `.mobileconfig` and creates it as a new profile in the MDM.
    private func publishJIT() async {
        guard let result = jit.export() else { return }
        await model.mdm.publish(name: "Serberus — JIT Admin", mobileconfig: result.data)
    }

    // MARK: Daemon config (break-glass) authoring

    private var daemonConfig: DaemonConfigSettingsModel { model.daemonConfig }

    private var configCard: some View {
        VStack(alignment: .leading, spacing: Spacing.lg) {
            SectionLabel("Daemon configuration")

            VStack(alignment: .leading, spacing: 5) {
                Text("Enforcement mode").font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textSecondary)
                SegmentedControl(selection: $model.daemonConfig.enforcementMode,
                                 options: [.enforce: "Enforce", .audit: "Audit", .monitor: "Monitor"],
                                 label: "Enforcement mode")
            }

            LabeledField(label: "PAM bypass users (comma-separated)") {
                TextField("breakglass-admin", text: $model.daemonConfig.pamBypassUsersText).autocorrectionDisabled()
            }
            LabeledField(label: "PAM bypass groups (comma-separated)") {
                TextField("serberus-breakglass", text: $model.daemonConfig.pamBypassGroupsText).autocorrectionDisabled()
            }
            if let validationError = daemonConfig.bypassValidationError {
                notice(validationError, symbol: "exclamationmark.triangle.fill", tone: .degraded)
            }

            LabeledField(label: "Sudo enrollment users (comma-separated)") {
                TextField("jane, sam", text: $model.daemonConfig.sudoEnrollmentUsersText).autocorrectionDisabled()
            }
            LabeledField(label: "Sudo enrollment group (must already exist)") {
                TextField("serberus-sudoers", text: $model.daemonConfig.sudoEnrollmentGroupText).autocorrectionDisabled()
            }
            if let validationError = daemonConfig.sudoEnrollmentValidationError {
                notice(validationError, symbol: "exclamationmark.triangle.fill", tone: .degraded)
            }
            notice("Enrolled standard users may reach the curated sudo command paths; pam_serberus and the daemon still decide allow/prompt/deny. Leaving both fields empty is valid — it removes the drop-in and grants no one. The group is not auto-created: it must already exist.",
                   symbol: "info.circle", tone: .neutral)

            HStack(spacing: Spacing.lg) {
                Stepper("Sudo cache: \(daemonConfig.sudoCacheSeconds)s",
                        value: $model.daemonConfig.sudoCacheSeconds,
                        in: DaemonConfigSettingsModel.cacheRange, step: 60)
                    .font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                Stepper("Prompt timeout: \(daemonConfig.promptTimeoutSeconds)s",
                        value: $model.daemonConfig.promptTimeoutSeconds,
                        in: DaemonConfigSettingsModel.timeoutRange, step: 5)
                    .font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
            }

            VStack(alignment: .leading, spacing: Spacing.xs) {
                Toggle("Time-bound elevation grants", isOn: $model.daemonConfig.timeBoundGrantsEnabled)
                    .toggleStyle(.switch).tint(Theme.emerald)
                if daemonConfig.timeBoundGrantsEnabled {
                    Stepper("Default grant duration: \(daemonConfig.defaultGrantDurationMinutes == 0 ? "off (per-rule only)" : "\(daemonConfig.defaultGrantDurationMinutes) min")",
                            value: $model.daemonConfig.defaultGrantDurationMinutes,
                            in: DaemonConfigSettingsModel.grantDurationMinutesRange, step: 5)
                        .font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                }
                Text("Key timeBoundGrantsEnabled — on by default. A rule's own duration wins; a rule left at \"Use org default\" uses the default above (0 = no default, so that rule only caches its decision), and a rule set to \"One time only\" never gets a grant. When on, grants expire and need re-approval. When off, no grant is issued: a prompt rule asks every time. Never adds the user to the admins group.")
                    .font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Toggle("Daemon enabled", isOn: $model.daemonConfig.daemonEnabled)
                .toggleStyle(.switch).tint(Theme.emerald)

            VStack(alignment: .leading, spacing: Spacing.xs) {
                Toggle("Allow Serberus Commander to publish rules directly to Jamf", isOn: $model.daemonConfig.commanderPublishEnabled)
                    .toggleStyle(.switch).tint(Theme.emerald)
                Text("Key commanderPublishEnabled — an admin-console gate the daemon ignores. This only AUTHORS the profile: Commander shows its Publish to Jamf buttons on a Mac once a Config profile with this ON is installed there (see Endpoint connection below). Off by default because API-published profiles render blank in the Jamf console; the console-editable paths are Save Jamf Schema and Save .plist.")
                    .font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }

            VStack(alignment: .leading, spacing: Spacing.xs) {
                Toggle("Use Touch ID for per-app authorization rules", isOn: $model.daemonConfig.enableBiometrics)
                    .toggleStyle(.switch).tint(Theme.emerald)
                Text("Key enableBiometrics — no effect in Serberus 0.9.0: it applies to App Identity definitions only, and per-app rules are disabled in this release. ON authenticates the SESSION OWNER ONLY, which is what lets macOS offer Touch ID: biometrics cannot stand in for a different person, so a rule that also admits admins always shows the name-and-password form instead. OFF (the default) is session-owner-or-admin. The right's preserved native branch is unchanged either way, so callers that match no pinned app still get its native rule.")
                    .font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
                // Spelled out at authoring time rather than left in a caption:
                // this trades a principal away, and the admin turning it on is
                // the one accepting that.
                if model.daemonConfig.enableBiometrics {
                    notice("Touch ID ON removes the admin fallback for pinned apps. Only the person logged in can approve — a nearby admin can no longer authenticate on a standard user's behalf, and a shared or kiosk Mac where the console account is not the intended approver loses that path entirely. Anyone enrolled in Touch ID on that Mac can approve with a fingerprint alone.",
                           symbol: "exclamationmark.triangle.fill", tone: .pending)
                }
            }

            if daemonConfig.requiresBrickRiskAcknowledgement {
                VStack(alignment: .leading, spacing: Spacing.sm) {
                    notice("Enforce mode with no PAM bypass: if the daemon is unreachable, sudo is denied for EVERYONE on the device — pam_serberus fails closed. Add a break-glass user or group before shipping this profile.",
                           symbol: "exclamationmark.octagon.fill", tone: .degraded)
                    Toggle("I understand the lockout risk — export with no break-glass anyway",
                           isOn: $model.daemonConfig.brickRiskAcknowledged)
                        .toggleStyle(.switch).tint(Theme.warning)
                        .font(.system(size: 12))
                }
            }
            if let configSaved {
                HStack(spacing: 6) {
                    Label("Saved \(configSaved.lastPathComponent)", systemImage: "checkmark.seal").foregroundStyle(.green)
                    Button("Reveal in Finder") { NSWorkspace.shared.activateFileViewerSelecting([configSaved]) }
                        .buttonStyle(.link)
                }
                .font(.system(size: 12))
            }
            if let configSaveError {
                notice(configSaveError, symbol: "exclamationmark.triangle", tone: .degraded)
            }
            if let error = daemonConfig.lastExportError {
                notice(error, symbol: "exclamationmark.triangle", tone: .degraded)
            }

            HStack(spacing: Spacing.sm) {
                Button { daemonConfig.save() } label: { Label("Save", systemImage: "square.and.arrow.down") }
                    .buttonStyle(.ghost)
                Button { exportConfig() } label: { Label("Export .mobileconfig", systemImage: "arrow.up.doc") }
                    .buttonStyle(.ghost).disabled(!daemonConfig.canExport)
                Button { Task { await publishConfig() } } label: { Label("Publish to Jamf", systemImage: "arrow.up.doc.on.clipboard") }
                    .buttonStyle(.emerald)
                    .disabled(!daemonConfig.canExport || !model.mdm.connection.isComplete)
                    .help(model.mdm.connection.isComplete
                          ? "Create a new Daemon Config configuration profile in your MDM (scope it there)"
                          : "Configure the MDM connection above to publish")
                Spacer()
            }
            notice("The Jamf connection keys (jamfProURL, API client ID/secret) live in the same com.herojoneslabs.serberus.config domain but are delivered by a separate profile — the two payloads union on the device.",
                   symbol: "info.circle", tone: .neutral)
            publishStatus
        }
        .card()
    }

    private func exportConfig() {
        configSaved = nil
        configSaveError = nil
        guard let result = daemonConfig.export() else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = result.suggestedFilename
        panel.canCreateDirectories = true
        panel.title = "Export Daemon Config .mobileconfig"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try result.data.write(to: url, options: .atomic)
            configSaved = url
        } catch {
            configSaveError = "Could not save \(url.lastPathComponent): \(error.localizedDescription)"
        }
    }

    /// Generates the config `.mobileconfig` and creates it as a new profile in the MDM.
    private func publishConfig() async {
        guard let result = daemonConfig.export() else { return }
        await model.mdm.publish(name: "Serberus — Daemon Config", mobileconfig: result.data)
    }

    // MARK: Production (MDM-delivered) status

    private var productionCard: some View {
        VStack(alignment: .leading, spacing: Spacing.lg) {
            HStack {
                SectionLabel("Endpoint connection (MDM-delivered)")
                Spacer()
                Text("read-only").font(.system(size: 11)).foregroundStyle(Theme.textMuted)
            }
            HStack {
                Text("Direct publish").font(.system(size: 12)).foregroundStyle(Theme.textMuted).frame(width: 120, alignment: .leading)
                if model.directPublishEnabled {
                    StatusBadge("On", tone: .healthy, symbol: "antenna.radiowaves.left.and.right")
                } else {
                    StatusBadge("Off", tone: .offline, symbol: "antenna.radiowaves.left.and.right.slash")
                }
                Text("commanderPublishEnabled (managed profile only) — \(model.directPublishEnabled ? "Commander shows Publish to Jamf for policies on this Mac" : "Publish to Jamf is hidden on this Mac; rules ship via Save Jamf Schema / Save .plist (console-editable)")")
                    .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
            }
            switch model.jamfConnectionState() {
            case let .configured(credentials):
                DetailRow(label: "Instance", value: credentials.serverURL.host() ?? credentials.serverURL.absoluteString)
                HStack {
                    Text("Status").font(.system(size: 12)).foregroundStyle(Theme.textMuted).frame(width: 120, alignment: .leading)
                    StatusBadge("Configured", tone: .healthy, symbol: "checkmark.circle.fill")
                    Spacer()
                }
                DetailRow(label: "Client ID", value: Self.truncate(credentials.clientID), mono: true)
                DetailRow(label: "Managed by", value: "com.herojoneslabs.serberus.config", mono: true)
            case let .notConfigured(missingKey):
                HStack {
                    Text("Status").font(.system(size: 12)).foregroundStyle(Theme.textMuted).frame(width: 120, alignment: .leading)
                    StatusBadge("Not configured", tone: .offline)
                    Spacer()
                }
                DetailRow(label: "Missing", value: "\(missingKey)", mono: true, valueColor: Theme.warning)
                notice("On managed endpoints this is delivered by the com.herojoneslabs.serberus.config profile. The connection above is for authoring from this admin Mac.",
                       symbol: "info.circle", tone: .neutral)
            }
        }
        .card()
    }

    // MARK: Dashboard & fleet posture (check-in windows, risk signals, menu bar)

    private var fleet: FleetObserverModel { model.fleet }

    private var postureCard: some View {
        VStack(alignment: .leading, spacing: Spacing.lg) {
            SectionLabel("Dashboard & fleet posture")
            Text("Check-in windows classify every Serberus Mac from its last Jamf contact — the Dashboard posture ring, the Fleet Observer check-in filter, the menu bar counts and the “Offline Serberus Macs” risk signal all use these two numbers.")
                .font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: Spacing.xl) {
                thresholdStepper(title: "Stale after", value: staleBinding,
                                 range: FleetDevice.FreshnessThresholds.minimumDays...max(FleetDevice.FreshnessThresholds.minimumDays, fleet.thresholds.offlineAfterDays - 1),
                                 help: "Days since last Jamf contact after which a Mac shows as Stale (default 1)")
                thresholdStepper(title: "Offline after", value: offlineBinding,
                                 range: (fleet.thresholds.staleAfterDays + 1)...(FleetDevice.FreshnessThresholds.maximumDays + 1),
                                 help: "Days since last Jamf contact after which a Mac shows as Offline (default 7)")
                Spacer()
                if fleet.thresholds != .default {
                    Button("Reset to 1 / 7") { fleet.thresholds = .default }.buttonStyle(.ghost)
                }
            }

            Divider().overlay(Theme.hairline)

            VStack(alignment: .leading, spacing: Spacing.sm) {
                Text("Risk signals").font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.textPrimary)
                Text("Each signal's score is a 0–100 severity heuristic (base weight + a step per affected rule or Mac, capped); Low < 35 ≤ Medium < 65 ≤ High. Switch off the ones that do not apply to your fleet — the Dashboard lists the rest, highest first.")
                    .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(RiskSignal.Kind.configurable) { kind in
                    riskSignalRow(kind)
                }
            }

            Divider().overlay(Theme.hairline)

            HStack(alignment: .top, spacing: Spacing.sm) {
                Image(systemName: "menubar.arrow.up.rectangle").font(.system(size: 13)).foregroundStyle(Theme.emerald).frame(width: 22)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Menu bar").font(.system(size: 12, weight: .medium)).foregroundStyle(Theme.textPrimary)
                    Text("Commander keeps a menu-bar item: Serberus device count, check-in and daemon-state breakdown, and the Macs with uploads waiting — each row jumps to its filtered Fleet Observer list, and the icon turns amber while uploads wait.")
                        .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .card()
    }

    private var staleBinding: Binding<Int> {
        Binding(get: { fleet.thresholds.staleAfterDays },
                set: { fleet.thresholds = .init(staleAfterDays: $0, offlineAfterDays: fleet.thresholds.offlineAfterDays) })
    }

    private var offlineBinding: Binding<Int> {
        Binding(get: { fleet.thresholds.offlineAfterDays },
                set: { fleet.thresholds = .init(staleAfterDays: fleet.thresholds.staleAfterDays, offlineAfterDays: $0) })
    }

    private func thresholdStepper(title: String, value: Binding<Int>, range: ClosedRange<Int>, help: String) -> some View {
        HStack(spacing: Spacing.sm) {
            Text(title).font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
            Stepper(value: value, in: range) {
                Text("\(value.wrappedValue) \(value.wrappedValue == 1 ? "day" : "days")")
                    .font(.system(size: 12, weight: .semibold).monospacedDigit()).foregroundStyle(Theme.textPrimary)
                    .frame(minWidth: 52, alignment: .leading)
            }
            .help(help)
        }
    }

    private func riskSignalRow(_ kind: RiskSignal.Kind) -> some View {
        let isOn = Binding(get: { !model.disabledRiskSignals.contains(kind) },
                           set: { on in
                               if on { model.disabledRiskSignals.remove(kind) } else { model.disabledRiskSignals.insert(kind) }
                           })
        return Toggle(isOn: isOn) {
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(kind.title).font(.system(size: 12, weight: .medium)).foregroundStyle(Theme.textPrimary)
                    if kind.isFleetDerived {
                        Text("fleet").font(.system(size: 9.5, weight: .semibold)).foregroundStyle(Theme.textMuted)
                            .padding(.horizontal, 6).padding(.vertical, 2).background(Theme.elevated, in: Capsule())
                    }
                }
                Text(kind.explanation).font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .toggleStyle(.switch).tint(Theme.emerald)
    }

    private var permissionsCard: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            SectionLabel("Required API permissions")
            ForEach(model.publish.permissions) { permission in
                HStack(spacing: Spacing.md) {
                    Image(systemName: permission.tier == .required ? "checkmark.seal.fill"
                                      : (permission.tier == .optional ? "plus.circle" : "circle.dashed"))
                        .font(.system(size: 13))
                        .foregroundStyle(permission.tier == .required ? Theme.emerald : Theme.textMuted)
                        .frame(width: 22)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(permission.id).font(.system(size: 13, weight: .medium)).foregroundStyle(Theme.textPrimary)
                        Text(permission.feature).font(.system(size: 11)).foregroundStyle(Theme.textMuted)
                    }
                    Spacer()
                    if permission.tier != .required {
                        Text(permission.tier == .optional ? "Optional" : "V1.1")
                            .font(.system(size: 10, weight: .semibold)).foregroundStyle(Theme.textMuted)
                            .padding(.horizontal, 7).padding(.vertical, 3)
                            .background(Theme.elevated, in: Capsule())
                    }
                }
            }
        }
        .card()
    }

    // MARK: Jamf setup files

    /// Every bundled EA script, config-profile schema, and sample rule set, each
    /// with its own download button — the files an admin uploads into Jamf for a
    /// new deployment. No single bundle: download exactly what you need.
    private var jamfSetupCard: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            SectionLabel("Jamf setup files")
            Text("Download the extension-attribute scripts, Application & Custom Settings schemas, and sample rule sets to upload into Jamf when standing up a new deployment.")
                .font(.system(size: 11.5)).foregroundStyle(Theme.textMuted)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(JamfSetupFiles.Category.allCases) { category in
                let files = JamfSetupFiles.files(in: category)
                if !files.isEmpty {
                    VStack(alignment: .leading, spacing: 5) {
                        Text(category.rawValue.uppercased())
                            .font(.system(size: 10, weight: .bold)).tracking(0.8).foregroundStyle(Theme.textSecondary)
                        Text(category.blurb).font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
                            .fixedSize(horizontal: false, vertical: true)
                        ForEach(files) { file in
                            HStack(spacing: Spacing.sm) {
                                Image(systemName: Self.icon(for: file.name)).font(.system(size: 12))
                                    .foregroundStyle(Theme.emerald).frame(width: 18)
                                Text(file.name).font(.mono(11)).foregroundStyle(Theme.textPrimary)
                                    .lineLimit(1).truncationMode(.middle)
                                Spacer(minLength: Spacing.md)
                                Button { downloadSetupFile(file) } label: { Label("Download", systemImage: "arrow.down.circle") }
                                    .buttonStyle(.ghost).font(.system(size: 11))
                                    .help("Save \(file.name) to disk")
                            }
                        }
                    }
                    .padding(.top, Spacing.xs)
                }
            }
            if let setupSaved {
                notice("Saved \(setupSaved.lastPathComponent).", symbol: "checkmark.circle.fill", tone: .healthy)
            }
            if let setupError {
                notice(setupError, symbol: "exclamationmark.triangle.fill", tone: .degraded)
            }
        }
        .card()
    }

    private static func icon(for fileName: String) -> String {
        if fileName.hasSuffix(".sh") { return "terminal" }
        if fileName.hasSuffix(".json") { return "curlybraces" }
        if fileName.lowercased().hasPrefix("readme") { return "doc.text" }
        return "doc"
    }

    private func downloadSetupFile(_ file: JamfSetupFiles.SetupFile) {
        setupSaved = nil
        setupError = nil
        let panel = NSSavePanel()
        panel.nameFieldStringValue = file.name
        panel.canCreateDirectories = true
        panel.title = "Download \(file.name)"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            if FileManager.default.fileExists(atPath: url.path) {
                try FileManager.default.removeItem(at: url)
            }
            try FileManager.default.copyItem(at: file.url, to: url)
            setupSaved = url
        } catch {
            setupError = "Could not save \(file.name): \(error.localizedDescription)"
        }
    }

    private var securityCard: some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            SectionLabel("Credential security")
            notice("The connection secret you enter here is stored in the macOS Keychain of this admin Mac. Endpoint credentials delivered via MDM are configuration, not secret storage — recoverable by privileged local processes (an intentional V1 architecture choice).",
                   symbol: "exclamationmark.shield.fill", tone: .pending)
        }
        .card()
    }

    private func notice(_ text: String, symbol: String, tone: StatusTone) -> some View {
        HStack(alignment: .top, spacing: Spacing.sm) {
            Image(systemName: symbol).font(.system(size: 12)).foregroundStyle(tone.color)
            Text(text).font(.system(size: 12)).foregroundStyle(Theme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(Spacing.md)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tone.color.opacity(0.08), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(tone.color.opacity(0.25), lineWidth: 1))
    }

    static func truncate(_ value: String) -> String {
        guard value.count > 8 else { return value }
        return value.prefix(8) + "…"
    }
}
