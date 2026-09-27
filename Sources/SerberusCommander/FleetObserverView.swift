import AppKit
import PolicyBuilderCore
import PrivMgrCore
import SwiftUI
import UniformTypeIdentifiers

/// Fleet Observer — the managed fleet as Jamf knows it, read live through
/// Commander's MDM connection (Jamf IS the fleet data plane). Two tabs:
/// **Devices** (one card per computer: user, OS, last check-in, uploads,
/// Serberus posture when the org publishes the EAs (any EA whose name contains "Serberus")) and **Uploads** (every
/// capture and Intel bundle any device uploaded from Sentinel, newest
/// first). An upload can be **downloaded** to disk, a capture **imported**
/// straight into Definitions → Import Capture, and a harvested file
/// **deleted** from the record (the one write — optionally automatic after
/// a download) so Jamf never accumulates files Commander already has.
struct FleetObserverView: View {
    @Bindable var model: PolicyBuilderModel
    @State private var query = ""
    @State private var tab: Tab = .devices
    @State private var selectedDeviceID: String?
    /// Devices-tab filters (check-in state · daemon State · Mode · uploads
    /// waiting). Seeded by a ``FleetRoute`` from the Dashboard / menu bar.
    @State private var filter = FleetFilter()
    /// Uploads-tab device filter (a menu-bar "TESTMAC01 · 1 upload" row lands here).
    @State private var uploadsDeviceID: String?
    @State private var alert: FleetAlert?
    /// Upload awaiting the delete confirmation.
    @State private var deleteCandidate: FleetUpload?
    /// Upload awaiting the reject confirmation (context-menu Reject). Confirmed
    /// like Delete, because a reject with the harvest switch on removes the only
    /// copy from Jamf.
    @State private var rejectCandidate: FleetUpload?
    /// A capture fetched from a Jamf record, presented HERE (Review Capture)
    /// rather than navigating to Definitions — the review stays on Uploads, and
    /// only "Create Definition" pushes to Definitions (item: the review flow).
    @State private var reviewingCapture: ImportedCapture?
    /// "Delete from Jamf after download / import" — the harvest workflow
    /// (download, then clear the record). Remembered across launches.
    @AppStorage("fleet.deleteAfterDownload") private var deleteAfterDownload = false
    /// The fleet in Jamf is usually much bigger than the Macs Serberus is on;
    /// by default only Macs with inventory evidence of Serberus are listed.
    @AppStorage("fleet.includeAllComputers") private var includeAllComputers = false

    private enum Tab: Hashable { case devices, uploads }

    fileprivate struct FleetAlert: Identifiable {
        let id = UUID()
        let title: String
        let message: String
    }

    private var fleet: FleetObserverModel { model.fleet }
    /// The connection Fleet Observer runs on — the Settings connection when
    /// complete, else the config-profile-delivered Jamf credentials.
    private var connection: MDMConnection { model.effectiveJamfConnection }
    private var isLoading: Bool { fleet.state == .loading }
    /// Why the connection can't drive the screen (nil = good to go).
    private var connectionProblem: String? { FleetObserverModel.connectionProblem(connection) }

    private var scopedDevices: [FleetDevice] { includeAllComputers ? fleet.devices : fleet.serberusDevices }
    private var trimmedQuery: String { query.trimmingCharacters(in: .whitespaces) }

    private func matches(_ device: FleetDevice, _ q: String) -> Bool {
        device.name.localizedCaseInsensitiveContains(q)
            || (device.user ?? "").localizedCaseInsensitiveContains(q)
            || (device.realName ?? "").localizedCaseInsensitiveContains(q)
            || (device.serialNumber ?? "").localizedCaseInsensitiveContains(q)
    }

    /// Scope → filters → search, in that order.
    private var filteredDevices: [FleetDevice] { fleet.devices(in: scopedDevices, matching: filter) }

    private var devices: [FleetDevice] {
        let q = trimmedQuery
        guard !q.isEmpty else { return filteredDevices }
        return filteredDevices.filter { matches($0, q) }
    }

    /// Macs the search would find if the Serberus-only scope were widened.
    private var hiddenMatches: Int {
        let q = trimmedQuery
        guard !includeAllComputers, !q.isEmpty else { return 0 }
        return fleet.devices.filter { !$0.hasSerberus && matches($0, q) }.count
    }

    private var uploads: [FleetUpload] {
        let q = query.trimmingCharacters(in: .whitespaces)
        let pool = uploadsDeviceID.map { id in fleet.uploads.filter { $0.computerID == id } } ?? fleet.uploads
        guard !q.isEmpty else { return pool }
        return pool.filter { upload in
            upload.fileName.localizedCaseInsensitiveContains(q)
                || upload.deviceName.localizedCaseInsensitiveContains(q)
                || (upload.serialNumber ?? "").localizedCaseInsensitiveContains(q)
                || upload.kind.label.localizedCaseInsensitiveContains(q)
        }
    }

    private var subtitle: String {
        guard connectionProblem == nil else { return "Connect Jamf in Settings to see your fleet" }
        switch fleet.state {
        case .idle: return "Not loaded yet"
        case .loading where fleet.devices.isEmpty: return "Loading computers from \(model.mdm.vendor.displayName)…"
        case .failed(let reason) where fleet.devices.isEmpty: return reason
        default:
            let shown = fleet.serberusDevices.count
            var parts = ["\(shown) Serberus \(shown == 1 ? "device" : "devices")"]
            if fleet.otherDeviceCount > 0 {
                parts[0] += includeAllComputers
                    ? " + \(fleet.otherDeviceCount) without Serberus"
                    : " (\(fleet.otherDeviceCount) other \(fleet.otherDeviceCount == 1 ? "Mac" : "Macs") hidden)"
            }
            if let total = fleet.truncatedTotal { parts[0] += " · first \(fleet.devices.count) of \(total) in Jamf" }
            let waiting = fleet.waitingUploads.count
            let reviewed = fleet.reviewedUploads.count
            var uploadsPart = "\(waiting) \(waiting == 1 ? "upload" : "uploads") waiting"
            if waiting > 0 { uploadsPart += " on \(fleet.devicesWithWaitingUploads.count) \(fleet.devicesWithWaitingUploads.count == 1 ? "device" : "devices")" }
            if reviewed > 0 { uploadsPart += " · \(reviewed) reviewed" }
            parts.append(uploadsPart)
            if case .failed = fleet.state {
                parts.append("last refresh failed")
            } else if let refreshed = fleet.lastRefreshed {
                parts.append("refreshed \(refreshed.formatted(date: .omitted, time: .shortened))")
            }
            return parts.joined(separator: " · ")
        }
    }

    // MARK: Body

    var body: some View {
        // A selected device opens as a full-pane record view IN PLACE — not a
        // nested NavigationStack. A NavigationStack inside the split view's detail
        // fought the app's custom sidebar (which drives `selectedSection`
        // manually), trapping navigation on the device view. Swapping the pane
        // keeps sidebar navigation working: RootView just replaces this view.
        ZStack {
            if let deviceID = selectedDeviceID {
                DeviceDetailView(model: model, deviceID: deviceID, alert: $alert,
                                 onDownload: { download($0) }, onImport: { importCapture($0) },
                                 onDelete: { delete($0) }, onClose: { selectedDeviceID = nil })
            } else {
                listContent
            }
        }
        // Load + route consumption live at the top level so they fire whether the
        // list or a device record is showing (a menu-bar deep link while a device
        // is open clears the selection via `consumeRoute` and applies the filter).
        .onAppear {
            // First visit — or a visit after the Jamf connection changed —
            // loads automatically; otherwise Refresh is explicit (every
            // refresh is a fleet-wide Jamf read).
            if connectionProblem == nil, fleet.needsLoad(for: connection) {
                Task { await fleet.refresh(connection: connection) }
            }
            consumeRoute()
        }
        .onChange(of: model.pendingFleetRoute) { _, _ in consumeRoute() }
    }

    private var listContent: some View {
        VStack(alignment: .leading, spacing: Spacing.lg) {
            ScreenHeader("Fleet Observer", subtitle: subtitle) {
                HStack(spacing: Spacing.sm) {
                    SegmentedControl(selection: $tab,
                                     options: [.devices: "Devices", .uploads: "Uploads"],
                                     label: "Fleet view")
                        .fixedSize()
                    Button {
                        Task { await fleet.refresh(connection: connection) }
                    } label: {
                        if isLoading {
                            HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Refreshing…") }
                        } else {
                            Label("Refresh", systemImage: "arrow.clockwise")
                        }
                    }
                    .buttonStyle(.tinted)
                    .fixedSize()
                    .disabled(isLoading || connectionProblem != nil)
                    .keyboardShortcut("r", modifiers: .command)
                    .help(connectionProblem ?? "Reload the computer inventory from \(model.mdm.vendor.displayName) (⌘R)")
                }
                // Keep the tab + Refresh at full size even on a narrow window;
                // the title truncates before these controls do.
                .fixedSize()
            }

            if let problem = connectionProblem {
                notConfiguredState(problem)
            } else {
                // Search lives on its own row so it can shrink without squeezing
                // the header controls.
                searchField
                    .frame(maxWidth: 420, alignment: .leading)
                // A failed refresh with stale devices on screen is flagged on
                // BOTH tabs, plus a truncated walk.
                if case .failed(let reason) = fleet.state, !fleet.devices.isEmpty {
                    notice(reason, symbol: "exclamationmark.triangle.fill", tone: .degraded)
                }
                if let total = fleet.truncatedTotal {
                    notice("Showing the first \(fleet.devices.count) of \(total) computers — the inventory walk stops at \(JamfFleetClient.maxPages * JamfFleetClient.pageSize). Narrow the fleet with a smart group, or raise the cap.",
                           symbol: "exclamationmark.triangle.fill", tone: .pending)
                }
                switch tab {
                case .devices: devicesPane
                case .uploads: uploadsPane
                }
            }
        }
        .padding(Spacing.xl)
        // Review Capture — presented on the Uploads view. Reject / Cancel stay
        // here; only "Create Definition" hands off to the Definitions screen.
        .sheet(item: $reviewingCapture) { imported in
            ImportCaptureSheet(
                model: model,
                imported: imported,
                title: "Review Capture",
                onCreateOne: { draft in
                    // Single attempt → open the pre-filled composer on Definitions.
                    // The ledger + harvest complete when that composer saves.
                    model.pendingComposerPrefill = PendingComposerPrefill(
                        draft: draft, fileName: imported.fileName,
                        origin: imported.origin, harvestFrom: imported.harvestFrom)
                    reviewingCapture = nil
                    model.selectedSection = .definitions
                },
                onCreated: { ids in
                    // Batch → the definitions are already saved. Hand the
                    // completion (ledger record + harvest delete) to Definitions
                    // so any "couldn't delete from Jamf" notice renders where the
                    // operator lands — not on this view, which is about to unmount.
                    model.pendingImportCompletion = PendingImportCompletion(
                        definitionIDs: ids, fileName: imported.fileName,
                        origin: imported.origin, harvestFrom: imported.harvestFrom)
                    reviewingCapture = nil
                    model.selectedSection = .definitions
                },
                onReject: {
                    if let origin = imported.origin { reject(origin) }
                    reviewingCapture = nil
                },
                deletesFromJamfOnReject: deleteAfterDownload,
                dismiss: { reviewingCapture = nil }
            )
        }
        .confirmationDialog(deleteCandidate.map(Self.deleteTitle) ?? "",
                            isPresented: Binding(get: { deleteCandidate != nil && selectedDeviceID == nil },
                                                 set: { if !$0 { deleteCandidate = nil } }),
                            titleVisibility: .visible) {
            Button("Delete from Jamf", role: .destructive) {
                if let upload = deleteCandidate { delete(upload) }
                deleteCandidate = nil
            }
            Button("Keep", role: .cancel) { deleteCandidate = nil }
        } message: {
            Text(Self.deleteMessage)
        }
        .confirmationDialog(rejectCandidate.map { "Reject \($0.fileName)?" } ?? "",
                            isPresented: Binding(get: { rejectCandidate != nil && selectedDeviceID == nil },
                                                 set: { if !$0 { rejectCandidate = nil } }),
                            titleVisibility: .visible) {
            Button("Reject", role: .destructive) {
                if let upload = rejectCandidate { reject(upload) }
                rejectCandidate = nil
            }
            Button("Keep", role: .cancel) { rejectCandidate = nil }
        } message: {
            Text(rejectMessage(rejectCandidate))
        }
        // The alert is shown on whichever window is frontmost: the detail
        // sheet presents it itself while it is up (an alert queued on the
        // parent would wait until the sheet closes).
        .alert(alert?.title ?? "",
               isPresented: Binding(get: { alert != nil && selectedDeviceID == nil }, set: { if !$0 { alert = nil } })) {
            Button("OK", role: .cancel) { alert = nil }
        } message: {
            Text(alert?.message ?? "")
        }
        .onChange(of: fleet.lastError) { _, error in
            // Reload failures (the one non-throwing path) are events: fresh
            // id each time, so repeats still surface.
            guard let error else { return }
            alert = FleetAlert(title: "Jamf request failed", message: error.message)
            fleet.lastError = nil
        }
    }


    /// Applies a pending ``FleetRoute``: tab + filters (+ the uploads device
    /// chip). The search box is left alone — the route narrows, the operator
    /// may still search within it.
    private func consumeRoute() {
        guard let route = model.pendingFleetRoute else { return }
        model.pendingFleetRoute = nil
        selectedDeviceID = nil
        switch route {
        case let .devices(routeFilter):
            tab = .devices
            filter = routeFilter
            // Every count that produces a deep link (Dashboard posture ring +
            // lines, menu-bar check-in / state rows, the offline risk signal)
            // is computed over Serberus Macs ONLY. So a filtered route must
            // land on the Serberus-only scope, or the list would show a
            // different (larger) number than the row the operator clicked —
            // check-in filters included, not just state/mode/uploads.
            if routeFilter.isActive, includeAllComputers {
                includeAllComputers = false
            }
        case let .uploads(deviceID):
            tab = .uploads
            uploadsDeviceID = deviceID
        }
    }

    /// Routes a thrown download/import error to the alert (the sheet or the
    /// screen, whichever is up). A `CancellationError` means "already in
    /// flight" and is deliberately silent.
    private func surface(_ error: Error, title: String) {
        if error is CancellationError { return }
        alert = FleetAlert(title: title, message: FleetObserverModel.describe(error))
    }

    private var searchField: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass").foregroundStyle(Theme.textMuted)
            TextField("Search devices, users, serials, uploads", text: $query)
                .textFieldStyle(.plain)
                .frame(maxWidth: .infinity)
            if !query.isEmpty {
                Button { query = "" } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.plain).foregroundStyle(Theme.textMuted)
            }
        }
        .font(.system(size: 12))
        .padding(.horizontal, Spacing.md).padding(.vertical, 7)
        .background(Theme.elevated, in: RoundedRectangle(cornerRadius: Radius.chip, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.chip, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
    }

    // MARK: Devices

    @ViewBuilder
    private var devicesPane: some View {
        switch fleet.state {
        case .idle:
            placeholder("Load your fleet", symbol: "laptopcomputer.and.arrow.down",
                        detail: "Refresh reads every computer from \(model.mdm.vendor.displayName) (API role: Read Computers).", tone: .neutral)
        case .loading where fleet.devices.isEmpty:
            loadingState
        case .failed(let reason) where fleet.devices.isEmpty:
            placeholder("Couldn't load the fleet", symbol: "exclamationmark.triangle", detail: reason, tone: .degraded)
        default:
            scopeBar
            filterBar
            if devices.isEmpty {
                let noneAtAll = fleet.devices.isEmpty
                let noneWithSerberus = !includeAllComputers && fleet.serberusDevices.isEmpty
                let hidden = hiddenMatches
                if filter.isActive, !scopedDevices.isEmpty, filteredDevices.isEmpty {
                    // The FILTERS emptied the list (not the scope, not the search).
                    VStack(spacing: Spacing.md) {
                        Image(systemName: "line.3.horizontal.decrease.circle").font(.system(size: 38)).foregroundStyle(Theme.textMuted)
                        Text("No Macs match the filters").font(.system(size: 16, weight: .semibold)).foregroundStyle(Theme.textPrimary)
                        Text("\(filter.summary()) — none of the \(scopedDevices.count) \(includeAllComputers ? "computers" : "Serberus Macs") in the list match.")
                            .font(.system(size: 12)).foregroundStyle(Theme.textMuted)
                            .multilineTextAlignment(.center).frame(maxWidth: 480)
                        Button { filter = .all } label: { Label("Clear filters", systemImage: "xmark.circle") }
                            .buttonStyle(.ghost)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .card()
                } else if hidden > 0 {
                    // The search DID match — just Macs the Serberus-only scope hides.
                    VStack(spacing: Spacing.md) {
                        Image(systemName: "eye.slash").font(.system(size: 38)).foregroundStyle(Theme.textMuted)
                        Text("\(hidden) hidden \(hidden == 1 ? "Mac matches" : "Macs match")")
                            .font(.system(size: 16, weight: .semibold)).foregroundStyle(Theme.textPrimary)
                        Text("No Serberus inventory evidence yet (no EA value collected, no package receipt, no upload). Include Macs without Serberus to see \(hidden == 1 ? "it" : "them").")
                            .font(.system(size: 12)).foregroundStyle(Theme.textMuted)
                            .multilineTextAlignment(.center).frame(maxWidth: 480)
                        Button { includeAllComputers = true } label: { Label("Show hidden Macs", systemImage: "eye") }
                            .buttonStyle(.ghost)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .card()
                } else {
                    placeholder(noneAtAll ? "No computers in \(model.mdm.vendor.displayName)"
                                    : (noneWithSerberus ? "No Macs with Serberus yet" : "No devices match"),
                                symbol: "line.3.horizontal.decrease.circle",
                                detail: noneAtAll ? "Enroll a Mac and run inventory, then Refresh."
                                    : (noneWithSerberus
                                        ? "Commander recognises a Serberus Mac from the inventory: an extension attribute whose name contains “Serberus” (any naming convention, e.g. EA_Serberus_State) with a real value (deploy the EAs in Support/jamf-extension-attributes), a Serberus package receipt, or a Serberus upload on the record. Switch on “Include Macs without Serberus” to see the whole fleet."
                                        : "Adjust the search above."),
                                tone: .neutral)
                }
            } else {
                ScrollView {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 300, maximum: 420), spacing: Spacing.lg)],
                              spacing: Spacing.lg) {
                        ForEach(devices) { device in
                            Button { selectedDeviceID = device.id } label: {
                                FleetDeviceCard(device: device, freshness: fleet.freshness(of: device),
                                                waitingUploads: fleet.waitingUploads(on: device.id).count)
                            }
                                .buttonStyle(.plain)
                                .contextMenu {
                                    Button("Details…") { selectedDeviceID = device.id }
                                    if !device.uploads.isEmpty {
                                        Button("Show Uploads") { tab = .uploads; uploadsDeviceID = device.id }
                                    }
                                    if let url = FleetLinks.jamfComputerURL(instanceURL: model.effectiveJamfConnection.instanceURL, computerID: device.id, serial: device.serialNumber) {
                                        Button("Open in \(model.mdm.vendor.displayName)") { NSWorkspace.shared.open(url) }
                                    }
                                }
                        }
                    }
                    .padding(.bottom, Spacing.xl)
                }
                .scrollIndicators(.never)
            }
        }
    }

    /// Serberus-only by default; the switch widens the list to the whole Jamf
    /// fleet (coverage / rollout checks).
    private var scopeBar: some View {
        HStack(spacing: Spacing.md) {
            Toggle("Include Macs without Serberus", isOn: $includeAllComputers)
                .toggleStyle(.switch).tint(Theme.emerald).font(.system(size: 12))
                .help("Off: only Macs with inventory evidence of Serberus (an EA named with “Serberus” carrying a real value, a Serberus package receipt, or a Serberus upload). On: every computer in \(model.mdm.vendor.displayName).")
            Spacer()
            Text("\(fleet.serberusDevices.count) with Serberus · \(fleet.otherDeviceCount) without")
                .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
        }
        .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
    }

    /// Check-in state · daemon State · enforcement Mode · uploads waiting.
    /// The State / Mode menus list the values the fleet actually reports
    /// (the Serberus EAs — `not reported` for Macs without a value), with
    /// counts, so the filter is never an empty guess.
    private var filterBar: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: Spacing.md) { filterControls; Spacer(minLength: Spacing.md); filterStatus }
            VStack(alignment: .leading, spacing: Spacing.sm) {
                HStack(spacing: Spacing.md) { filterControls }
                HStack { filterStatus }
            }
        }
        .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
    }

    @ViewBuilder
    private var filterControls: some View {
        SegmentedControl(selection: $filter.freshness,
                         options: [nil: "All", .fresh: "Checked in", .stale: "Stale", .offline: "Offline", .unknown: "Unknown"],
                         label: "Check-in state")
            .fixedSize()
            .help("Check-in state from the Mac's last Jamf contact: stale after \(fleet.thresholds.staleAfterDays) \(fleet.thresholds.staleAfterDays == 1 ? "day" : "days"), offline after \(fleet.thresholds.offlineAfterDays) (Settings → Dashboard & fleet posture)")
        postureMenu(title: "State", symbol: "heart.text.square", selection: $filter.state, values: fleet.stateCounts,
                    help: "Daemon state the Serberus State extension attribute reported at last recon (healthy, degraded, not installed, …)")
        postureMenu(title: "Mode", symbol: "shield.lefthalf.filled", selection: $filter.mode, values: fleet.modeCounts,
                    help: "Enforcement mode the Serberus Mode extension attribute reported (enforce, audit, monitor, …)")
        Button {
            filter.waitingUploadsOnly.toggle()
        } label: {
            HStack(spacing: 5) {
                Image(systemName: filter.waitingUploadsOnly ? "checkmark.circle.fill" : "tray.and.arrow.down").font(.system(size: 10))
                Text("Uploads waiting").font(.system(size: 12, weight: .medium))
            }
        }
        .buttonStyle(.plain)
        .ghostControlChrome(active: filter.waitingUploadsOnly)
        .help("Only Macs with a capture or Intel bundle nobody has imported, rejected, or downloaded yet")
        .accessibilityAddTraits(.isToggle)
        .accessibilityValue(filter.waitingUploadsOnly ? "on" : "off")
    }

    @ViewBuilder
    private var filterStatus: some View {
        if filter.isActive {
            Text("\(filteredDevices.count) of \(scopedDevices.count) · \(filter.summary())")
                .font(.system(size: 11)).foregroundStyle(Theme.textSecondary).lineLimit(1)
            Button { filter = .all } label: { Label("Clear", systemImage: "xmark.circle.fill") }
                .buttonStyle(.plain).font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textMuted)
                .help("Clear the check-in / state / mode / uploads filters")
        } else {
            Text("\(scopedDevices.count) \(scopedDevices.count == 1 ? "Mac" : "Macs")")
                .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
        }
    }

    /// A State / Mode filter menu: "Any" + each reported value with its count.
    private func postureMenu(title: String, symbol: String, selection: Binding<String?>,
                             values: [(value: String, count: Int)], help: String) -> some View {
        Menu {
            Button("Any \(title.lowercased())") { selection.wrappedValue = nil }
            if !values.isEmpty { Divider() }
            ForEach(values, id: \.value) { entry in
                Button {
                    selection.wrappedValue = entry.value
                } label: {
                    if selection.wrappedValue == entry.value {
                        Label("\(entry.value) · \(entry.count)", systemImage: "checkmark")
                    } else {
                        Text("\(entry.value) · \(entry.count)")
                    }
                }
            }
            if values.isEmpty {
                Text("No Serberus \(title.lowercased()) EA values reported yet").foregroundStyle(.secondary)
            }
        } label: {
            HStack(spacing: 5) {
                Image(systemName: symbol).font(.system(size: 10))
                Text(selection.wrappedValue.map { "\(title): \($0)" } ?? title)
                    .font(.system(size: 12, weight: .medium)).lineLimit(1)
                Image(systemName: "chevron.up.chevron.down").font(.system(size: 8))
            }
        }
        .menuStyle(.borderlessButton).fixedSize()
        .ghostControlChrome(active: selection.wrappedValue != nil)
        .help(help)
    }

    // MARK: Uploads

    @ViewBuilder
    private var uploadsPane: some View {
        switch fleet.state {
        case .idle:
            placeholder("Load your fleet", symbol: "tray.and.arrow.down",
                        detail: "Uploads are attachments on each computer's Jamf record — Refresh reads them with the inventory.", tone: .neutral)
        case .loading where fleet.devices.isEmpty:
            loadingState
        case .failed(let reason) where fleet.devices.isEmpty:
            placeholder("Couldn't load the fleet", symbol: "exclamationmark.triangle", detail: reason, tone: .degraded)
        default:
            harvestBar
            if let deviceID = uploadsDeviceID {
                uploadsDeviceChip(deviceID)
            }
            if uploads.isEmpty {
                placeholder(fleet.uploads.isEmpty ? "No uploads on any record" : "No uploads match",
                            symbol: "tray.and.arrow.down",
                            detail: fleet.uploads.isEmpty
                                ? "When a user uploads a capture (Intel → Capture) or an Intel bundle (Intel → Export) from Serberus Sentinel, it shows up here — download it, import a capture straight into Definitions (or reject it after review), then delete it from the record."
                                : (uploadsDeviceID != nil ? "This device has no uploads on its record. Clear the device filter to see the whole fleet." : "Adjust the search above."),
                            tone: .neutral)
            } else {
                ScrollView {
                    LazyVStack(spacing: 6) {
                        ForEach(uploads) { upload in
                            uploadRow(upload)
                        }
                    }
                    .padding(.bottom, Spacing.xl)
                }
                .scrollIndicators(.never)
            }
        }
    }

    /// The harvest switch: download / import / reject, then clear the record.
    private var harvestBar: some View {
        HStack(spacing: Spacing.md) {
            Toggle("Delete from Jamf after download, import, or reject", isOn: $deleteAfterDownload)
                .toggleStyle(.switch).tint(Theme.emerald).font(.system(size: 12))
                .help("After a successful Download, Import, or Reject, remove the file from the computer's Jamf record so the record never accumulates files Commander already dealt with (API role Update Computers). Off: the file stays on the record but is still marked reviewed here, so it no longer counts as waiting.")
            Spacer()
            let waiting = fleet.waitingUploads
            let captures = waiting.filter { $0.kind == .capture }.count
            let bundles = waiting.filter { $0.kind == .intel }.count
            let reviewed = fleet.reviewedUploads.count
            Text("\(captures) \(captures == 1 ? "capture" : "captures") · \(bundles) Intel \(bundles == 1 ? "bundle" : "bundles") waiting\(reviewed > 0 ? " · \(reviewed) reviewed" : "")")
                .font(.system(size: 11)).foregroundStyle(Theme.textMuted)
                .help("Waiting = on a Jamf record and not yet imported, rejected, or downloaded. Reviewed uploads stay listed (with their decision) until deleted from the record.")
        }
        .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
    }

    /// "Uploads on TESTMAC01 ×" — the Uploads tab narrowed to one device.
    private func uploadsDeviceChip(_ deviceID: String) -> some View {
        let device = fleet.device(id: deviceID)
        return HStack(spacing: Spacing.sm) {
            Image(systemName: "laptopcomputer").font(.system(size: 11)).foregroundStyle(Theme.emerald)
            Text("Uploads on \(device?.name ?? "device \(deviceID)")")
                .font(.system(size: 12, weight: .medium)).foregroundStyle(Theme.textPrimary)
            if let serial = device?.serialNumber { Text(serial).font(.mono(10)).foregroundStyle(Theme.textMuted) }
            Spacer()
            Button("Details…") { selectedDeviceID = deviceID }.buttonStyle(.plain)
                .font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textSecondary)
            Button { uploadsDeviceID = nil } label: { Label("Show all devices", systemImage: "xmark.circle.fill") }
                .buttonStyle(.plain).font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.textMuted)
        }
        .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
        .background(Theme.accentDim.opacity(0.6), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.emerald.opacity(0.3), lineWidth: 1))
    }

    private func uploadRow(_ upload: FleetUpload) -> some View {
        let busy = fleet.downloading.contains(upload.id) || fleet.deleting.contains(upload.id)
        let importing = fleet.importing.contains(upload.id)
        let deleting = fleet.deleting.contains(upload.id)
        let isCapture = upload.kind == .capture
        let review = fleet.reviews.entry(for: upload)
        return HStack(spacing: Spacing.md) {
            Image(systemName: isCapture ? "waveform.badge.magnifyingglass" : "shippingbox")
                .font(.system(size: 13)).foregroundStyle(isCapture ? Theme.emerald : Theme.info)
                .frame(width: 32, height: 32)
                .background((isCapture ? Theme.emerald : Theme.info).opacity(0.12), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .help(upload.kind.label)
            VStack(alignment: .leading, spacing: 2) {
                Text(upload.fileName).font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.textPrimary).lineLimit(1)
                HStack(spacing: Spacing.xs) {
                    Text(upload.kind.label).font(.system(size: 11, weight: .medium)).foregroundStyle(isCapture ? Theme.emerald : Theme.info)
                    Text("· \(upload.deviceName)").font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                    if let serial = upload.serialNumber {
                        Text("· \(serial)").font(.mono(10)).foregroundStyle(Theme.textMuted)
                    }
                }
            }
            Spacer()
            if let review {
                ReviewBadge(entry: review)
            } else {
                StatusBadge("Waiting", tone: .pending, symbol: "clock")
                    .help("Not yet imported, rejected, or downloaded — counts toward “Uploads waiting”")
            }
            if let recorded = upload.recordedAt {
                Text(recorded.formatted(date: .abbreviated, time: .shortened))
                    .font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                    .help("Recorded \(recorded.formatted())")
            }
            Text(Self.size(upload.sizeBytes)).font(.mono(10)).foregroundStyle(Theme.textMuted)
                .frame(minWidth: 56, alignment: .trailing)
            SegmentedActionBar(actions: uploadActions(upload, busy: busy, importing: importing, deleting: deleting))
        }
        .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
        .opacity(review == nil ? 1 : 0.78)
        .contextMenu {
            Button("Show Device…") { selectedDeviceID = upload.computerID }
            Button("Download…") { download(upload) }.disabled(busy)
            if isCapture {
                Button("Review Capture…") { importCapture(upload) }.disabled(busy)
            }
            Divider()
            if review == nil {
                Button("Reject (mark reviewed, no definition)") { rejectCandidate = upload }.disabled(busy)
            } else {
                Button("Mark as Waiting Again") { fleet.reviews.forget(fileName: upload.fileName) }
            }
            Divider()
            Button("Delete from Jamf…", role: .destructive) { deleteCandidate = upload }.disabled(busy)
        }
    }

    /// Review (captures only; primary, first) · Download (all kinds) · Delete —
    /// shared by the Uploads rows and the device detail sheet.
    fileprivate static func actions(for upload: FleetUpload, busy: Bool, importing: Bool, deleting: Bool,
                                    download: @escaping () -> Void, importCapture: @escaping () -> Void,
                                    delete: @escaping () -> Void) -> [SegmentedActionBar.Action] {
        var actions: [SegmentedActionBar.Action] = []
        if upload.kind == .capture {
            actions.append(.init(id: "review", title: "Review", systemImage: "square.and.arrow.down",
                                 isPrimary: true, isDisabled: busy, isBusy: importing,
                                 help: "Fetch this capture and review it here — import it into Definitions or reject it") { importCapture() })
        }
        actions.append(.init(id: "download", title: "Download", systemImage: "arrow.down.circle",
                             isPrimary: upload.kind != .capture,
                             isDisabled: busy, isBusy: busy && !importing && !deleting,
                             help: upload.kind == .capture ? "Save this capture to disk" : "Save this Intel bundle (.zip) to disk") { download() })
        actions.append(.init(id: "delete", title: "Delete", systemImage: "trash",
                             isDestructive: true, isDisabled: busy, isBusy: deleting,
                             help: "Remove this file from the computer's Jamf record (API role Update Computers) — do this once you have reviewed or downloaded it") { delete() })
        return actions
    }

    private func uploadActions(_ upload: FleetUpload, busy: Bool, importing: Bool, deleting: Bool) -> [SegmentedActionBar.Action] {
        Self.actions(for: upload, busy: busy, importing: importing, deleting: deleting,
                     download: { download(upload) }, importCapture: { importCapture(upload) },
                     delete: { deleteCandidate = upload })
    }

    // MARK: Capture actions

    /// Download → Save panel (suggested name = the Sentinel's file name),
    /// then — when the harvest switch is on — delete it from the record.
    private func download(_ upload: FleetUpload) {
        guard !fleet.downloading.contains(upload.id) else { return }
        Task {
            do {
                let data = try await fleet.downloadUpload(upload, connection: connection)
                let panel = NSSavePanel()
                panel.nameFieldStringValue = upload.suggestedSaveName
                panel.canCreateDirectories = true
                panel.title = upload.kind == .capture ? "Save Capture" : "Save Intel Bundle"
                if upload.kind == .capture, let type = UTType(filenameExtension: RuleCapture.fileExtension) {
                    panel.allowedContentTypes = [type, .json]
                } else if upload.kind == .intel {
                    panel.allowedContentTypes = [.zip]
                }
                guard panel.runModal() == .OK, let url = panel.url else { return }
                do {
                    try data.write(to: url, options: .atomic)
                } catch {
                    alert = FleetAlert(title: "Couldn't save \(upload.kind.label.lowercased())", message: error.localizedDescription)
                    return
                }
                // Saved to disk = dealt with: it stops counting as waiting
                // (an import later upgrades the decision to "imported").
                if fleet.reviews.entry(for: upload) == nil {
                    fleet.reviews.record(upload, decision: .downloaded)
                }
                if deleteAfterDownload { await deleteAfterHarvest(upload) }
            } catch {
                surface(error, title: "Couldn't download \(upload.kind.label.lowercased())")
            }
        }
    }

    /// Download + validate → present **Review Capture** here on the Uploads view
    /// (the Rule Recorder loop closed from the admin side). The review — import
    /// into Definitions, or reject — happens in place; only "Create Definition"
    /// leaves for Definitions. With the harvest switch on, the record is cleared
    /// ONLY once the import commits, so Cancel must be lossless.
    private func importCapture(_ upload: FleetUpload) {
        guard upload.kind == .capture, !fleet.downloading.contains(upload.id) else { return }
        Task {
            do {
                let loaded = try await fleet.fetchCapture(upload, connection: connection)
                let review = ImportedCapture(capture: loaded, fileName: upload.suggestedSaveName,
                                             origin: upload, harvestFrom: deleteAfterDownload ? upload : nil)
                // Dismiss the device sheet first (if the review was launched from
                // it), then present the review sheet on the next run-loop turn —
                // two sheets cannot swap in one transaction.
                selectedDeviceID = nil
                Task { @MainActor in reviewingCapture = review }
            } catch {
                surface(error, title: "Couldn't review capture")
            }
        }
    }

    /// Reject (after the confirmation dialog): reviewed, no definition —
    /// recorded in the ledger (so it stops counting as waiting) and, with the
    /// harvest switch on, removed from the record.
    private func reject(_ upload: FleetUpload) {
        fleet.reviews.record(upload, decision: .rejected)
        guard deleteAfterDownload else { return }
        Task { await deleteAfterHarvest(upload, verb: "Rejected") }
    }

    /// The reject confirmation body — spells out that the file is removed from
    /// Jamf when the harvest switch is on (a capture never downloaded then
    /// exists nowhere), and stays on the record otherwise.
    private func rejectMessage(_ upload: FleetUpload?) -> String {
        let device = upload?.deviceName ?? "the device"
        if deleteAfterDownload {
            return "This capture is marked reviewed with NO definition created, and — because “Delete from Jamf after download, import, or reject” is on — removed from \(device)'s Jamf record. If you have not downloaded it, this deletes the only copy. It stops counting as an upload waiting either way."
        }
        return "This capture is marked reviewed with NO definition created — it stops counting as an upload waiting. The file stays on \(device)'s Jamf record (shown as Rejected) until you delete it. You can undo with “Mark as Waiting Again.”"
    }

    /// Explicit Delete (after the confirmation dialog).
    private func delete(_ upload: FleetUpload) {
        guard !fleet.deleting.contains(upload.id) else { return }
        Task {
            do {
                try await fleet.deleteUpload(upload, connection: connection)
            } catch {
                surface(error, title: "Couldn't delete from Jamf")
            }
        }
    }

    /// Post-harvest delete after a DOWNLOAD: a failure here must not look like
    /// the download failed — the file is safely on disk — so it is reported
    /// as its own, softer message. (The import path defers its delete to the
    /// Definitions screen, see `importCapture`.)
    private func deleteAfterHarvest(_ upload: FleetUpload, verb: String = "Downloaded") async {
        do {
            try await fleet.deleteUpload(upload, connection: connection)
        } catch {
            if error is CancellationError { return }
            alert = FleetAlert(title: "\(verb), but not deleted from Jamf",
                               message: "\(upload.fileName) was \(verb.lowercased()), but removing it from \(upload.deviceName)'s record failed: \(FleetObserverModel.describe(error)) It is marked reviewed here; you can delete it from the row later.")
        }
    }

    /// Shared confirmation strings — the screen and the device sheet each
    /// present their own dialog (a dialog attached under a sheet is queued).
    fileprivate static func deleteTitle(_ upload: FleetUpload) -> String {
        "Delete \(upload.fileName) from \(upload.deviceName)'s Jamf record?"
    }
    fileprivate static let deleteMessage = "The file is removed from the computer record in Jamf (API role Update Computers). Anything you already downloaded or imported is unaffected."

    // MARK: States + helpers

    private var loadingState: some View {
        VStack(spacing: Spacing.md) {
            ProgressView().controlSize(.regular)
            Text("Reading the computer inventory…").font(.system(size: 12)).foregroundStyle(Theme.textMuted)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .card()
    }

    private func notConfiguredState(_ problem: String) -> some View {
        VStack(spacing: Spacing.md) {
            Image(systemName: "antenna.radiowaves.left.and.right.slash").font(.system(size: 38)).foregroundStyle(Theme.textMuted)
            Text("Connect Jamf to observe the fleet").font(.system(size: 16, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            Text("Fleet Observer reads your computers, their check-ins, and any Serberus uploads (captures and Intel bundles) they sent from Sentinel, straight from Jamf (API role: Read Computers). It uses the connection you enter in Settings, or the Jamf credentials your com.herojoneslabs.serberus.config profile delivers to this Mac. \(problem)")
                .font(.system(size: 12)).foregroundStyle(Theme.textMuted)
                .multilineTextAlignment(.center).frame(maxWidth: 460)
            Button { model.selectedSection = .settings } label: { Label("Open Settings", systemImage: "gearshape") }
                .buttonStyle(.emerald).padding(.top, Spacing.xs)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .card()
    }

    private func placeholder(_ title: String, symbol: String, detail: String, tone: StatusTone) -> some View {
        VStack(spacing: Spacing.md) {
            Image(systemName: symbol).font(.system(size: 38)).foregroundStyle(tone == .neutral ? Theme.textMuted : tone.color.opacity(0.8))
            Text(title).font(.system(size: 16, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            Text(detail).font(.system(size: 12)).foregroundStyle(Theme.textMuted)
                .multilineTextAlignment(.center).frame(maxWidth: 480)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .card()
    }

    private func notice(_ text: String, symbol: String, tone: StatusTone) -> some View {
        Label(text, systemImage: symbol)
            .font(.system(size: 11)).foregroundStyle(tone.color)
            .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(tone.color.opacity(0.08), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
    }

    static func size(_ bytes: Int?) -> String {
        guard let bytes else { return "—" }
        return ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }
}

/// Jamf console deep links.
enum FleetLinks {
    /// The computer's record in the Jamf Pro console (`computers.html?id=<id>&o=r`)
    /// — the inventory already gave us the id; the serial search is the
    /// fallback when it is somehow empty. `nil` when there is no instance URL.
    /// The instance path is kept (a Jamf behind a context path still works).
    static func jamfComputerURL(instanceURL: String, computerID: String, serial: String?) -> URL? {
        let trimmed = instanceURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let base = URL(string: trimmed),
              base.scheme != nil, base.host != nil,
              var components = URLComponents(url: base.appendingPathComponent("computers.html"), resolvingAgainstBaseURL: false) else { return nil }
        if !computerID.isEmpty {
            components.queryItems = [URLQueryItem(name: "id", value: computerID), URLQueryItem(name: "o", value: "r")]
        } else if let serial, !serial.isEmpty {
            components.queryItems = [URLQueryItem(name: "queryType", value: "Computers"), URLQueryItem(name: "query", value: serial)]
        } else {
            return nil
        }
        return components.url
    }
}

// MARK: - Device card

struct FleetDeviceCard: View {
    let device: FleetDevice
    /// Check-in state under the model's thresholds (`fleet.freshness(of:)`).
    var freshness: FleetDevice.Freshness
    /// Uploads on this record not yet imported / rejected / downloaded.
    var waitingUploads: Int = 0

    private var tone: StatusTone { FleetFormat.tone(for: freshness) }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.md) {
            HStack(spacing: Spacing.md) {
                Image(systemName: "laptopcomputer")
                    .font(.system(size: 14)).foregroundStyle(Theme.emerald)
                    .frame(width: 34, height: 34)
                    .background(Theme.accentDim, in: RoundedRectangle(cornerRadius: 9, style: .continuous))
                VStack(alignment: .leading, spacing: 1) {
                    Text(device.name).font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.textPrimary).lineLimit(1)
                    Text(device.user ?? device.realName ?? "no assigned user")
                        .font(.system(size: 11)).foregroundStyle(device.user == nil && device.realName == nil ? Theme.textMuted : Theme.textSecondary)
                        .lineLimit(1)
                }
                Spacer()
                if !device.hasSerberus {
                    StatusBadge("No Serberus", tone: .offline, symbol: "minus.circle")
                        .help(device.posture.isEmpty
                              ? "No Serberus inventory evidence: no Serberus extension attribute collected, no Serberus package receipt, no upload on the record"
                              : "Serberus extension attributes report not installed; no Serberus package receipt or upload on the record")
                }
                if waitingUploads > 0 {
                    StatusBadge("\(waitingUploads) waiting", tone: .pending, symbol: "tray.and.arrow.down")
                        .help("\(waitingUploads) of \(device.uploads.count) \(device.uploads.count == 1 ? "upload" : "uploads") on the record not yet imported, rejected, or downloaded (\(device.captures.count) \(device.captures.count == 1 ? "capture" : "captures"), \(device.intelBundles.count) Intel \(device.intelBundles.count == 1 ? "bundle" : "bundles") in all)")
                } else if !device.uploads.isEmpty {
                    StatusBadge("\(device.uploads.count) reviewed", tone: .offline, symbol: "checkmark")
                        .help("Every upload on this record has been imported, rejected, or downloaded — still on the record until deleted")
                }
            }
            Divider().overlay(Theme.hairline)
            HStack {
                StatusBadge(freshness.label, tone: tone, symbol: tone.symbol)
                Spacer()
                if let os = device.osVersion {
                    Label("macOS \(os)", systemImage: "apple.logo").font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                }
            }
            HStack {
                Text(device.serialNumber ?? "no serial").font(.mono(10)).foregroundStyle(Theme.textMuted)
                Spacer()
                Text(FleetFormat.relative(device.lastContact)).font(.system(size: 10)).foregroundStyle(Theme.textMuted)
            }
            if !device.displayPosture.isEmpty {
                HStack(spacing: Spacing.xs) {
                    ForEach(device.displayPosture.prefix(3), id: \.self) { item in
                        Text("\(item.label): \(item.value)")
                            .font(.system(size: 10, weight: .medium)).foregroundStyle(Theme.textSecondary)
                            .padding(.horizontal, 8).padding(.vertical, 3)
                            .background(Theme.elevated.opacity(0.8), in: Capsule())
                            .overlay(Capsule().strokeBorder(Theme.hairline, lineWidth: 1))
                            .lineLimit(1)
                    }
                }
            }
        }
        .card()
        .contentShape(Rectangle())
    }
}

/// "Imported · 12:54" / "Rejected" / "Downloaded" — the review ledger's
/// decision for an upload, with the when/what in the tooltip.
struct ReviewBadge: View {
    let entry: CaptureReviewLedger.Entry

    var body: some View {
        StatusBadge(entry.decision.label, tone: FleetFormat.tone(for: entry.decision), symbol: symbol)
            .help(help)
    }

    private var symbol: String {
        switch entry.decision {
        case .imported: return "checkmark.circle.fill"
        case .rejected: return "xmark.circle.fill"
        case .downloaded: return "arrow.down.circle.fill"
        }
    }

    private var help: String {
        var text: String
        switch entry.decision {
        case .imported:
            text = entry.definitionIDs.isEmpty
                ? "Imported into Definitions"
                : "Imported — definition\(entry.definitionIDs.count == 1 ? "" : "s") \(entry.definitionIDs.joined(separator: ", "))"
        case .rejected:
            text = "Reviewed and rejected — not made into a definition"
        case .downloaded:
            text = "Downloaded to disk from Fleet Observer"
        }
        text += " on \(entry.reviewedAt.formatted(date: .abbreviated, time: .shortened)). No longer counts as waiting; still on the Jamf record until deleted."
        return text
    }
}

enum FleetFormat {
    static func tone(for decision: CaptureReviewLedger.Decision) -> StatusTone {
        switch decision {
        case .imported: return .healthy
        case .rejected: return .offline
        case .downloaded: return .neutral
        }
    }

    static func tone(for freshness: FleetDevice.Freshness) -> StatusTone {
        switch freshness {
        case .fresh: return .healthy
        case .stale: return .pending
        case .offline: return .offline
        case .unknown: return .neutral
        }
    }

    static func relative(_ date: Date?) -> String {
        guard let date else { return "never checked in" }
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return "seen \(formatter.localizedString(for: date, relativeTo: Date()))"
    }

}

// MARK: - Device detail

/// One device: the Jamf facts, Serberus posture (EA) when present, and its
/// captures with Download / Import. Reads the live device from the model so
/// a reload reflects immediately.
struct DeviceDetailView: View {
    @Bindable var model: PolicyBuilderModel
    let deviceID: String
    /// Shared with the Fleet screen: while this sheet is up, it presents the
    /// alert itself (a queued parent alert would wait for the sheet to close).
    @Binding fileprivate var alert: FleetObserverView.FleetAlert?
    var onDownload: (FleetUpload) -> Void
    var onImport: (FleetUpload) -> Void
    /// Called AFTER the user confirmed in this sheet's own dialog.
    var onDelete: (FleetUpload) -> Void
    /// Back to the fleet list — clears the parent's `selectedDeviceID` (the pane
    /// swaps back in place; this view is not a sheet).
    var onClose: () -> Void
    @State private var deleteCandidate: FleetUpload?
    @State private var eventFilter: EventFilter = .all
    @State private var eventsNewestFirst = true

    /// Outcome filter for the recent-events list.
    fileprivate enum EventFilter: Hashable { case all, denied, granted, prompts }

    private var fleet: FleetObserverModel { model.fleet }
    private var device: FleetDevice? { fleet.device(id: deviceID) }
    private var reloading: Bool { fleet.reloading.contains(deviceID) }

    var body: some View {
        VStack(spacing: 0) {
            if let device {
                // Top back bar — this is an in-place pane, so it carries its own
                // "back to the fleet list" affordance (Esc / the footer Back too).
                HStack(spacing: Spacing.xs) {
                    Button { onClose() } label: {
                        Label("Fleet", systemImage: "chevron.left").font(.system(size: 12, weight: .medium))
                    }
                    .buttonStyle(.plain).foregroundStyle(Theme.emerald)
                    .help("Back to the fleet list")
                    Spacer()
                }
                .padding(.horizontal, Spacing.xl).padding(.top, Spacing.md).padding(.bottom, Spacing.xs)
                ScrollView {
                    VStack(alignment: .leading, spacing: Spacing.xl) {
                        header(device)
                        // Posture leads the record — the dashboard-card summary
                        // (State / Mode / Version / Last Upload / Uploads) sits
                        // directly under the device header.
                        if !nonEnforcementPosture(device).isEmpty || !device.uploads.isEmpty { posture(device) }
                        facts(device)
                        if device.hasSerberus { enforcement(device) }
                        if device.hasSerberus { recentEvents(device) }
                        uploads(device)
                    }
                    .padding(Spacing.xl)
                }
                .scrollIndicators(.never)
                Divider().overlay(Theme.hairline)
                footer(device)
            } else {
                VStack(spacing: Spacing.md) {
                    Text("This device is no longer in the loaded fleet.").font(.system(size: 13)).foregroundStyle(Theme.textMuted)
                    Button("Back to fleet") { onClose() }.buttonStyle(.ghost).keyboardShortcut(.cancelAction)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Theme.background)
        .tint(Theme.emerald)
        .alert(alert?.title ?? "", isPresented: Binding(get: { alert != nil }, set: { if !$0 { alert = nil } })) {
            Button("OK", role: .cancel) { alert = nil }
        } message: {
            Text(alert?.message ?? "")
        }
        .confirmationDialog(deleteCandidate.map(FleetObserverView.deleteTitle) ?? "",
                            isPresented: Binding(get: { deleteCandidate != nil }, set: { if !$0 { deleteCandidate = nil } }),
                            titleVisibility: .visible) {
            Button("Delete from Jamf", role: .destructive) {
                if let upload = deleteCandidate { onDelete(upload) }
                deleteCandidate = nil
            }
            Button("Keep", role: .cancel) { deleteCandidate = nil }
        } message: {
            Text(FleetObserverView.deleteMessage)
        }
    }

    private func header(_ device: FleetDevice) -> some View {
        HStack(spacing: Spacing.md) {
            Image(systemName: "laptopcomputer").font(.system(size: 26)).foregroundStyle(Theme.emerald)
            VStack(alignment: .leading, spacing: 2) {
                Text(device.name).font(.system(size: 20, weight: .bold)).foregroundStyle(Theme.textPrimary)
                Text([device.serialNumber, device.user ?? device.realName].compactMap { $0 }.joined(separator: " · "))
                    .font(.mono(11)).foregroundStyle(Theme.textMuted)
            }
            Spacer()
            let freshness = fleet.freshness(of: device)
            let tone = FleetFormat.tone(for: freshness)
            StatusBadge(freshness.label, tone: tone, symbol: tone.symbol)
                .help("Last Jamf contact \(FleetFormat.relative(device.lastContact)) — stale after \(fleet.thresholds.staleAfterDays) \(fleet.thresholds.staleAfterDays == 1 ? "day" : "days"), offline after \(fleet.thresholds.offlineAfterDays)")
        }
    }

    private func facts(_ device: FleetDevice) -> some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            SectionLabel("Jamf inventory")
            DetailRow(label: "Serial", value: device.serialNumber ?? "—", mono: true)
            DetailRow(label: "User", value: [device.user, device.realName, device.email].compactMap { $0 }.joined(separator: " · ").nilIfEmpty ?? "—")
            DetailRow(label: "OS", value: device.osVersion.map { "macOS \($0)\(device.osBuild.map { " (\($0))" } ?? "")" } ?? "—")
            DetailRow(label: "Model", value: device.model ?? "—")
            DetailRow(label: "Last contact", value: device.lastContact.map { "\($0.formatted()) — \(FleetFormat.relative($0))" } ?? "never")
            DetailRow(label: "Enrolled", value: device.lastEnrolled?.formatted(date: .abbreviated, time: .omitted) ?? "—")
            DetailRow(label: "Managed", value: device.managed.map { $0 ? "Yes" : "No" } ?? "—")
            DetailRow(label: "Jamf ID", value: device.id, mono: true)
            DetailRow(label: "Serberus",
                      value: serberusSummary(device),
                      valueColor: device.hasSerberus ? Theme.textPrimary : Theme.warning)
        }
        .card()
    }

    /// One line for the facts card; the posture section below shows the EA
    /// values themselves, so only the evidence KINDS are summarised here.
    private func serberusSummary(_ device: FleetDevice) -> String {
        guard device.hasSerberus else {
            return device.posture.isEmpty
                ? "No inventory evidence — no Serberus extension attribute collected, no package receipt, no upload"
                : "Extension attributes report not installed; no Serberus package receipt or upload"
        }
        let eas = device.serberusEvidence.filter { $0.hasPrefix("EA ") }.count
        let packages = device.serberusEvidence.filter { $0.hasPrefix("package ") }.map { String($0.dropFirst("package ".count)) }
        var parts: [String] = []
        if eas > 0 { parts.append("\(eas) extension \(eas == 1 ? "attribute" : "attributes") with a value") }
        if !packages.isEmpty { parts.append("package \(packages.joined(separator: ", "))") }
        if !device.uploads.isEmpty { parts.append("\(device.uploads.count) \(device.uploads.count == 1 ? "upload" : "uploads") on the record") }
        return (device.hasInstallEvidence ? "Installed — " : "Uploads only (no EA value or receipt yet) — ") + parts.joined(separator: " · ")
    }

    // MARK: Enforcement (fleet telemetry EAs)

    /// The Serberus posture EAs minus the telemetry ones (State, Mode, Version,
    /// Uploads, …) — what the generic posture card shows. Shared with the device
    /// card via ``FleetDevice/displayPosture``.
    private func nonEnforcementPosture(_ device: FleetDevice) -> [PostureItem] {
        device.displayPosture
    }

    /// This Mac's decision counts from the fleet telemetry EAs. Graceful
    /// "not reported" when the org hasn't deployed them (never shows a phantom 0).
    private func enforcement(_ device: FleetDevice) -> some View {
        let hasCounts = device.denials24h != nil || device.activeGrants != nil || device.prompts24h != nil
        let lastDecision = device.postureValue("last decision")
        return VStack(alignment: .leading, spacing: Spacing.sm) {
            SectionLabel("Enforcement (last recon)")
            if !hasCounts, lastDecision == nil {
                Text("No enforcement telemetry reported yet. Deploy the EA_Serberus_Denials_24h / _Grants_Active / _Prompts_24h extension attributes (Support/jamf-extension-attributes) and run inventory to see this Mac's decision counts here.")
                    .font(.system(size: 12)).foregroundStyle(Theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                if hasCounts {
                    HStack(spacing: Spacing.md) {
                        enforcementStat("Denials · 24h", device.denials24h, tone: (device.denials24h ?? 0) > 0 ? .degraded : .neutral)
                        enforcementStat("Active grants", device.activeGrants, tone: (device.activeGrants ?? 0) > 0 ? .pending : .neutral)
                        enforcementStat("Prompts · 24h", device.prompts24h, tone: (device.prompts24h ?? 0) > 0 ? .pending : .neutral)
                    }
                }
                if let lastDecision {
                    DetailRow(label: "Last decision", value: lastDecision)
                }
                Text("From this Mac's Serberus telemetry extension attributes at inventory time — as fresh as the last recon, not a live per-decision feed. The events behind them live in Serberus Sentinel's Intel tab on that Mac.")
                    .font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .card()
    }

    private func enforcementStat(_ label: String, _ value: Int?, tone: StatusTone) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value.map(String.init) ?? "—")
                .font(.metric(22)).foregroundStyle(value == nil ? Theme.textMuted : tone.color)
            Text(label).font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
        .background(Theme.background.opacity(0.4), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
    }

    /// The attempted command as a line: `sudo <cmd + args>` for sudo, the right
    /// for an authorization attempt.
    private static func command(for event: FleetDecisionEvent) -> String {
        let target = event.target.isEmpty ? "—" : event.target
        return event.kind == "authuri" ? target : "sudo \(target)"
    }

    /// The individual recent denial/prompt events (debug telemetry EA). Present
    /// only while the org runs the debug profile on this Mac; otherwise a hint.
    /// Applies the outcome filter + sort direction to the raw (newest-first) list.
    private func visibleEvents(_ events: [FleetDecisionEvent]) -> [FleetDecisionEvent] {
        let filtered = events.filter { event in
            switch eventFilter {
            case .all: return true
            case .denied: return event.outcome == "denied"
            case .granted: return event.outcome == "granted"
            case .prompts: return event.prompt
            }
        }
        return eventsNewestFirst ? filtered : filtered.sorted { $0.at < $1.at }
    }

    private func recentEvents(_ device: FleetDevice) -> some View {
        let events = device.recentDecisionEvents
        let shown = visibleEvents(events)
        return VStack(alignment: .leading, spacing: Spacing.sm) {
            HStack {
                SectionLabel("Recent Elevations")
                Spacer()
                if !events.isEmpty {
                    Text("\(shown.count) of \(events.count) · last 24h").font(.system(size: 10)).foregroundStyle(Theme.textMuted)
                }
            }
            if events.isEmpty {
                Text("No individual events published. Deploy the debug-telemetry profile (com.herojoneslabs.serberus.debug → Enable debug telemetry) and the EA_Serberus_Recent_Events extension attribute to this Mac while debugging; the daemon publishes the last 24h of denials & prompts here (and withdraws them when the profile is removed).")
                    .font(.system(size: 11.5)).foregroundStyle(Theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                HStack(spacing: Spacing.sm) {
                    SegmentedControl(selection: $eventFilter,
                                     options: [.all: "All", .denied: "Denied", .granted: "Granted", .prompts: "Prompts"],
                                     label: "Filter events")
                        .fixedSize()
                    Spacer()
                    Button { eventsNewestFirst.toggle() } label: {
                        HStack(spacing: 4) {
                            Image(systemName: eventsNewestFirst ? "arrow.down" : "arrow.up").font(.system(size: 9, weight: .bold))
                            Text(eventsNewestFirst ? "Newest" : "Oldest").font(.system(size: 11, weight: .medium))
                        }
                    }
                    .buttonStyle(.plain).ghostControlChrome(active: false)
                    .help("Sort by time — \(eventsNewestFirst ? "newest first (tap for oldest)" : "oldest first (tap for newest)")")
                }
                if shown.isEmpty {
                    Text("No events match this filter.").font(.system(size: 11.5)).foregroundStyle(Theme.textMuted)
                        .padding(.vertical, Spacing.xs)
                }
                ForEach(shown) { event in
                    VStack(alignment: .leading, spacing: 3) {
                        // "Denied: sudo jamf checkJSSConnection"
                        HStack(alignment: .firstTextBaseline, spacing: 5) {
                            Text("\(event.outcome.capitalized):")
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundStyle(event.outcome == "granted" ? Theme.success : Theme.critical)
                            Text(Self.command(for: event))
                                .font(.mono(12)).foregroundStyle(Theme.textPrimary)
                                .lineLimit(2).truncationMode(.middle).textSelection(.enabled)
                            Spacer(minLength: Spacing.sm)
                            if event.prompt { StatusBadge("prompt", tone: .pending, symbol: "bell.badge") }
                        }
                        if let reason = event.reason, !reason.isEmpty {
                            Text("Reason: \(reason)")
                                .font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                        }
                        if let justification = event.justification, !justification.isEmpty {
                            Text("Justification: “\(justification)”")
                                .font(.system(size: 11)).foregroundStyle(Theme.textSecondary)
                                .italic().lineLimit(3).textSelection(.enabled)
                        }
                        HStack(spacing: Spacing.sm) {
                            if !event.user.isEmpty {
                                Text("User: \(event.user)").font(.system(size: 10)).foregroundStyle(Theme.textMuted)
                            }
                            Spacer()
                            if event.at != .distantPast {
                                Text(event.at.formatted(date: .abbreviated, time: .standard))
                                    .font(.mono(10)).foregroundStyle(Theme.textMuted)
                            }
                        }
                    }
                    .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Theme.background.opacity(0.4), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
                }
                Text("Individual decisions from this Mac's debug telemetry EA, at inventory time — as fresh as the last recon. Arguments are redacted.")
                    .font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .card()
    }

    private func posture(_ device: FleetDevice) -> some View {
        // The EA-published "Uploads" row (if any) is dropped from the generic
        // cards — it gets its own dedicated, clickable card below that jumps to
        // the Uploads review tab.
        let generic = nonEnforcementPosture(device).filter { $0.label.caseInsensitiveCompare("Uploads") != .orderedSame }
        return VStack(alignment: .leading, spacing: Spacing.md) {
            SectionLabel("Serberus posture")
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: Spacing.md)],
                      alignment: .leading, spacing: Spacing.md) {
                ForEach(generic, id: \.self) { item in
                    let meta = Self.postureMeta(label: item.label, value: item.value)
                    PostureCard(label: item.label, value: item.value.isEmpty ? "—" : item.value,
                                symbol: meta.symbol, tone: meta.tone)
                }
                uploadsPostureCard(device)
            }
            Text("Published by your Serberus extension attributes (any EA whose name contains “Serberus”) at inventory time — as fresh as the last recon. The Uploads card opens this Mac's uploads for review.")
                .font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
        }
        .card()
    }

    /// The dedicated, clickable Uploads posture card. Its value prefers the
    /// EA-published "Uploads" summary; failing that it derives one from the Jamf
    /// record's attachments. A "N waiting" badge counts uploads not yet reviewed
    /// (imported / rejected / downloaded). Tapping opens the Uploads review tab
    /// filtered to this Mac.
    private func uploadsPostureCard(_ device: FleetDevice) -> some View {
        let waiting = fleet.waitingUploads(on: deviceID).count
        let ea = device.postureValue("uploads")
        let value: String = {
            if let ea, !ea.isEmpty { return ea }
            if device.uploads.isEmpty { return "None" }
            var parts: [String] = []
            if device.captures.count > 0 { parts.append("capture \(device.captures.count)") }
            if device.intelBundles.count > 0 { parts.append("intel \(device.intelBundles.count)") }
            return parts.isEmpty ? "\(device.uploads.count) on record" : parts.joined(separator: " · ")
        }()
        let hasUploads = !device.uploads.isEmpty
            || (ea.map { !$0.isEmpty && $0.caseInsensitiveCompare("none") != .orderedSame } ?? false)
        return PostureCard(
            label: "Uploads",
            value: value,
            symbol: "tray.and.arrow.up.fill",
            tone: waiting > 0 ? .pending : (hasUploads ? .neutral : .offline),
            badge: waiting > 0 ? "\(waiting) waiting" : nil,
            action: { model.openFleetObserver(.uploads(deviceID: deviceID)) }
        )
    }

    /// Glyph + tone for a posture card, keyed off the de-conventioned EA label
    /// and (for State / Mode) its value so the card reads its health at a glance.
    private static func postureMeta(label: String, value: String) -> (symbol: String, tone: StatusTone) {
        let key = label.lowercased()
        let v = value.lowercased()
        switch key {
        case "state":
            if v.contains("healthy") { return ("checkmark.seal.fill", .healthy) }
            if v.contains("degraded") { return ("exclamationmark.triangle.fill", .degraded) }
            if v.contains("kill") || v.contains("not installed") { return ("xmark.seal.fill", .degraded) }
            if v.contains("await") || v.contains("pending") { return ("hourglass", .pending) }
            return ("checkmark.seal", .neutral)
        case "mode":
            if v.contains("enforce") { return ("shield.lefthalf.filled", .healthy) }
            if v.contains("audit") || v.contains("monitor") { return ("eye.fill", .pending) }
            if v.contains("not installed") { return ("shield.slash.fill", .offline) }
            return ("shield", .neutral)
        case "version": return ("number", .neutral)
        case "last upload": return ("clock.arrow.circlepath", .neutral)
        default: return ("info.circle", .neutral)
        }
    }

    /// A dashboard-style tile for one Serberus posture value (State, Mode,
    /// Version, Last Upload, Uploads). Mirrors ``MetricTile``'s glyph-chip +
    /// value + label language but scales the value font to fit long EA strings
    /// (dates, the uploads summary). With an `action` the whole tile is a button
    /// (hover lifts it, a chevron marks the link) — used for the Uploads card.
    private struct PostureCard: View {
        let label: String
        let value: String
        let symbol: String
        var tone: StatusTone = .neutral
        var badge: String? = nil
        var action: (() -> Void)? = nil
        @State private var hovering = false

        /// Short single-token values (healthy, enforce, 3.17) get the big metric
        /// font; anything with a space or over ~10 chars (dates, upload
        /// summaries) drops to a wrapping label so it never overflows the tile.
        private var big: Bool { value.count <= 10 && !value.contains(" ") }

        var body: some View {
            if let action {
                Button(action: action) { content }
                    .buttonStyle(.plain)
                    .onHover { hovering = $0 }
                    .accessibilityLabel("\(value) \(label)")
                    .accessibilityHint("Open the uploads for review")
                    .animation(.easeOut(duration: 0.12), value: hovering)
            } else {
                content
            }
        }

        private var linkable: Bool { action != nil }

        private var content: some View {
            VStack(alignment: .leading, spacing: Spacing.sm) {
                HStack(spacing: Spacing.xs) {
                    Image(systemName: symbol)
                        .font(.system(size: 14, weight: .semibold))
                        .foregroundStyle(tone.color)
                        .frame(width: 28, height: 28)
                        .background(tone.color.opacity(0.14), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                    Spacer(minLength: Spacing.xs)
                    if let badge {
                        Text(badge)
                            .font(.system(size: 9.5, weight: .bold))
                            .foregroundStyle(Theme.warning)
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background(Theme.warning.opacity(0.16), in: Capsule())
                    } else if linkable {
                        Image(systemName: "chevron.right")
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundStyle(hovering ? Theme.textSecondary : Theme.textMuted)
                    }
                }
                Text(value)
                    .font(big ? .metric(24) : .system(size: 13, weight: .semibold))
                    .foregroundStyle(Theme.textPrimary)
                    .lineLimit(big ? 1 : 3)
                    .minimumScaleFactor(big ? 1 : 0.75)
                    .fixedSize(horizontal: false, vertical: true)
                Text(label)
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.textSecondary)
            }
            .frame(maxWidth: .infinity, minHeight: 92, alignment: .leading)
            .padding(.horizontal, Spacing.md).padding(.vertical, Spacing.sm)
            .background(Theme.background.opacity(hovering && linkable ? 0.7 : 0.4),
                        in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous)
                .strokeBorder(hovering && linkable ? tone.color.opacity(0.45) : Theme.hairline, lineWidth: 1))
            .contentShape(RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
        }
    }

    private func uploads(_ device: FleetDevice) -> some View {
        VStack(alignment: .leading, spacing: Spacing.sm) {
            HStack {
                SectionLabel("Uploads")
                Spacer()
                Text("\(device.uploads.count) of \(device.attachmentCount) \(device.attachmentCount == 1 ? "attachment" : "attachments")")
                    .font(.system(size: 10)).foregroundStyle(Theme.textMuted)
            }
            if device.uploads.isEmpty {
                Text("Nothing waiting on this Mac's record. A user uploads a capture (Intel → Capture) or an Intel bundle (Intel → Export) from Serberus Sentinel; it then appears here to download, import, and delete.")
                    .font(.system(size: 12)).foregroundStyle(Theme.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(device.uploads) { upload in
                    let busy = fleet.downloading.contains(upload.id) || fleet.deleting.contains(upload.id)
                    let importing = fleet.importing.contains(upload.id)
                    let deleting = fleet.deleting.contains(upload.id)
                    let isCapture = upload.kind == .capture
                    HStack(spacing: Spacing.md) {
                        Image(systemName: isCapture ? "waveform.badge.magnifyingglass" : "shippingbox")
                            .font(.system(size: 12)).foregroundStyle(isCapture ? Theme.emerald : Theme.info)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(upload.fileName).font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.textPrimary).lineLimit(1)
                            Text([upload.kind.label,
                                  upload.recordedAt.map { "recorded \($0.formatted(date: .abbreviated, time: .shortened))" },
                                  FleetObserverView.size(upload.sizeBytes)].compactMap { $0 }.joined(separator: " · "))
                                .font(.system(size: 10.5)).foregroundStyle(Theme.textMuted)
                        }
                        Spacer()
                        if let review = fleet.reviews.entry(for: upload) {
                            ReviewBadge(entry: review)
                        } else {
                            StatusBadge("Waiting", tone: .pending, symbol: "clock")
                        }
                        SegmentedActionBar(actions: FleetObserverView.actions(
                            for: upload, busy: busy, importing: importing, deleting: deleting,
                            download: { onDownload(upload) }, importCapture: { onImport(upload) }, delete: { deleteCandidate = upload }))
                    }
                    .padding(.horizontal, Spacing.sm).padding(.vertical, 6)
                    .background(Theme.background.opacity(0.4), in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
                }
            }
        }
        .card()
    }

    private func footer(_ device: FleetDevice) -> some View {
        HStack(spacing: Spacing.sm) {
            // Back to the fleet list (Esc too).
            Button("Back") { onClose() }.buttonStyle(.ghost).keyboardShortcut(.cancelAction)
            Button {
                Task { await fleet.reloadDevice(id: deviceID, connection: model.effectiveJamfConnection) }
            } label: {
                if reloading {
                    HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Reloading…") }
                } else {
                    Label("Reload", systemImage: "arrow.clockwise")
                }
            }
            .buttonStyle(.ghost).disabled(reloading)
            .help("Re-read this computer's record (attachments included) from \(model.mdm.vendor.displayName)")
            Spacer()
            let url = FleetLinks.jamfComputerURL(instanceURL: model.effectiveJamfConnection.instanceURL, computerID: device.id, serial: device.serialNumber)
            Button("Open in \(model.mdm.vendor.displayName)") {
                if let url { NSWorkspace.shared.open(url) }
            }
            .buttonStyle(.emerald)
            .disabled(url == nil)
            .help(url == nil ? "No instance URL configured in Settings" : "Open this computer's record in \(model.mdm.vendor.displayName)")
        }
        .padding(Spacing.lg)
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
