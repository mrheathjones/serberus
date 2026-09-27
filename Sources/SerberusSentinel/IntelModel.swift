import Foundation
import Observation
import PrivMgrCore
import SerberusIntelCore

/// Which log source the table is showing.
enum ViewMode: String, CaseIterable, Identifiable {
    case live = "Live"
    case history = "History"
    /// System-wide macOS authorization-right attempts (authURI events), polled
    /// through the daemon. Distinct from Live/History, which show Serberus's
    /// own decisions.
    case authorizations = "Authorizations"

    var id: String { rawValue }
}

/// State of an export attempt.
enum ExportPhase: Equatable {
    case idle
    case collecting
    case ready(IntelBundle)
    case uploading
    case uploaded(computerID: String)
    case failed(String)
}

/// State of a **Capture** (Rule Recorder) session: record every sudo and
/// authorization attempt on this Mac until the user stops, review, then save
/// the `.serberuscapture` file or attach it to this Mac's Jamf record for
/// Commander's "Import Capture".
///
/// `.review` / `.uploading` / `.failed` hold the RAW capture (notes and
/// redaction are applied on save/upload via `finalizedCapture`), so a failed
/// upload returns to review with nothing lost; only `.uploaded` holds the
/// finalized document that actually left the Mac.
enum CapturePhase: Equatable {
    case idle
    case recording(startedAt: Date)
    /// Polling stopped; the capture is being assembled off the main actor.
    case building
    case review(RuleCapture)
    case uploading(RuleCapture)
    case uploaded(RuleCapture, computerID: String)
    case failed(RuleCapture, String)

    /// The capture under review / just handled, when there is one.
    var capture: RuleCapture? {
        switch self {
        case .idle, .recording, .building: return nil
        case let .review(capture), let .uploading(capture): return capture
        case let .uploaded(capture, _), let .failed(capture, _): return capture
        }
    }
}

@MainActor
@Observable
final class IntelModel {
    // MARK: Log viewing

    var mode: ViewMode = .live {
        didSet { modeChanged(from: oldValue) }
    }

    /// Entries currently shown. Live and history each own their own buffer so
    /// switching modes doesn't destroy the other's results.
    private(set) var liveEntries: [LogEntry] = []
    private(set) var historyEntries: [LogEntry] = []
    /// System authorization attempts (authURI events), polled via the daemon.
    private(set) var authorizationEntries: [LogEntry] = []
    /// Set when the authorization poll can't reach the daemon, so the view can
    /// say why it's empty instead of implying nothing happened.
    private(set) var authorizationUnavailable: String?
    /// Freeze the Authorizations feed so a triggered right can be read before
    /// the next poll scrolls it away.
    private(set) var authorizationPaused = false
    /// Show only lines that actually name a right, hiding authd's credential /
    /// mechanism / sheet noise. On by default — the raw stream buries the one
    /// line the user is looking for.
    var authorizationRightsOnly = true
    /// Collapse authd's several lines per decision into one row per attempt.
    /// On by default — the raw per-line view repeats one right many times.
    var authorizationGrouped = true

    var window: LogWindow = .oneHour
    var searchText: String = ""
    var minimumLevel: LogLevel = .default
    var includeInfoAndDebug: Bool = false {
        // The level flags are baked into the argv, so a change has to restart
        // a running stream to take effect.
        didSet { if isStreaming { restartStream() } }
    }

    private(set) var isStreaming = false
    private(set) var isLoadingHistory = false
    private(set) var loadError: String?

    /// Cap on retained live entries.
    ///
    /// A busy enforce-mode Mac can emit continuously; without a cap the array
    /// grows until the app is killed. Oldest are dropped — a diagnostics tail
    /// is about what is happening now, and the export path re-queries `log`
    /// independently, so nothing that matters is lost by trimming here.
    private static let liveEntryLimit = 5_000

    private var streamTask: Task<Void, Never>?
    private var jsonlTask: Task<Void, Never>?
    private var authorizationTask: Task<Void, Never>?
    private let streamer = LogStreamer()
    private let tailer = JSONLTailer()
    private let jsonlSource = JSONLLogSource()
    private let authorizationTailer = AuthorizationTailer()

    /// Endpoint's Serberus authURI rules, for tagging live authorization
    /// events with the rule that governs them. Reloaded when the tab is
    /// opened so an MDM push mid-session is picked up.
    private var ruleStore = SerberusRuleStore.load()

    /// The Serberus rule governing `right`, or nil if none — drives the
    /// per-row "matches a rule" tag.
    func ruleTag(forRight right: String) -> AuthorizationRuleTag? {
        ruleStore.tag(forRight: right)
    }

    /// Authorization rows collapsed to one per attempt.
    ///
    /// Grouped from the **unfiltered** buffer on purpose: authd states an
    /// attempt's failure on lines that name no right (`copy_rights:
    /// authorization failed`), which is precisely what the Rights-only filter
    /// removes. Grouping the filtered set would throw away the evidence needed
    /// to resolve a failed attempt, silently leaving it neutral. Filters are
    /// applied to the resulting attempts instead — and Rights-only is moot
    /// here, since every attempt names a right by construction.
    var visibleAttempts: [AuthorizationAttempt] {
        let needle = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return AuthorizationGrouper.group(authorizationEntries).filter { attempt in
            guard !needle.isEmpty else { return true }
            return attempt.right.lowercased().contains(needle)
                || (attempt.client?.lowercased().contains(needle) ?? false)
                || attempt.outcome.rawValue.contains(needle)
        }
    }

    /// Whether this process can read the system unified log.
    ///
    /// False for a standard user: `/var/db/diagnostics` is root:admin 0750.
    /// The app does not treat that as an error — Serberus's own JSONL records
    /// are readable by everyone and are the authoritative allow/deny record —
    /// but the UI says so, because "no lines from pam_serberus" should never
    /// look like "nothing happened".
    let unifiedLogAvailable = UnifiedLogAccess.isReadable()

    // MARK: Export

    var exportPhase: ExportPhase = .idle

    private let collector: IntelCollector
    private let uploaderFactory: @Sendable () -> JamfAttachmentUploader
    /// Device-side record of what was uploaded, for the "Serberus — Uploads"
    /// extension attributes (see ``JamfUploadLedger``).
    private let uploadLedger: JamfUploadLedger

    // MARK: Capture (Rule Recorder)

    private(set) var capturePhase: CapturePhase = .idle
    /// Live counter for the bar button while recording; the final count once
    /// stopped.
    private(set) var captureAttemptCount = 0
    private(set) var captureElapsedSeconds = 0
    /// Why a source could not be polled (daemon down), surfaced so an empty
    /// capture is explained.
    private(set) var captureUnavailable: String?
    /// Review-sheet inputs, applied when the capture is saved or uploaded.
    var captureNotes = ""
    var captureRedactArguments = false

    private let captureSession: CaptureSession
    private var captureTickTask: Task<Void, Never>?

    init(
        collector: IntelCollector = IntelCollector(),
        uploaderFactory: @escaping @Sendable () -> JamfAttachmentUploader = { JamfAttachmentUploader() },
        captureSession: CaptureSession = CaptureSession(),
        uploadLedger: JamfUploadLedger = JamfUploadLedger()
    ) {
        self.collector = collector
        self.uploaderFactory = uploaderFactory
        self.captureSession = captureSession
        self.uploadLedger = uploadLedger
    }

    var isCapturing: Bool {
        if case .recording = capturePhase { return true }
        return false
    }

    /// Recording or still assembling — the states a quit should warn about.
    var captureInProgress: Bool {
        switch capturePhase {
        case .recording, .building: return true
        default: return false
        }
    }

    /// Starts recording. The session runs its own authd + sudo pollers, so it
    /// keeps recording across Live / History / Authorizations mode switches
    /// (and across tab switches — the model lives for the app's lifetime).
    func startCapture() {
        guard !captureInProgress else { return }
        captureTickTask?.cancel()
        captureNotes = ""
        captureRedactArguments = false
        captureAttemptCount = 0
        captureElapsedSeconds = 0
        captureUnavailable = nil
        let now = Date()
        captureSession.start(at: now)
        capturePhase = .recording(startedAt: now)
        captureTickTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                // Guarded: a cancelled sleep returns immediately.
                if Task.isCancelled { break }
                guard let self else { return }
                self.captureElapsedSeconds = Int(Date().timeIntervalSince(now))
                self.captureAttemptCount = self.captureSession.attemptCount
                self.captureUnavailable = self.captureSession.unavailable
            }
        }
    }

    /// Stops polling (cheap, immediate) and assembles the capture OFF the
    /// main actor — host probe, decision-log read, identity inspection and
    /// hashing must not freeze the window — then moves to review.
    func stopCapture() {
        captureTickTask?.cancel()
        captureTickTask = nil
        guard let snapshot = captureSession.stopCollecting() else {
            capturePhase = .idle
            return
        }
        captureUnavailable = snapshot.unavailable
        capturePhase = .building
        let session = captureSession
        Task { [weak self] in
            let capture = await Task.detached(priority: .userInitiated) { session.build(from: snapshot) }.value
            guard let self, case .building = self.capturePhase else { return }   // discarded meanwhile
            self.captureAttemptCount = capture.attempts.count
            self.capturePhase = .review(capture)
        }
    }

    /// Abandons the recording, the build, or the review without saving anything.
    func discardCapture() {
        captureTickTask?.cancel()
        captureTickTask = nil
        captureSession.cancel()
        capturePhase = .idle
        captureAttemptCount = 0
        captureElapsedSeconds = 0
    }

    /// The capture as it will be written: the review notes applied, arguments
    /// redacted if the user asked.
    func finalizedCapture(_ base: RuleCapture) -> RuleCapture {
        var capture = RuleCapture(
            schemaVersion: base.schemaVersion,
            host: base.host,
            componentVersions: base.componentVersions,
            startedAt: base.startedAt,
            endedAt: base.endedAt,
            attempts: base.attempts,
            notes: captureNotes,
            argumentsRedacted: base.argumentsRedacted
        )
        if captureRedactArguments { capture = capture.redactingArguments() }
        return capture
    }

    /// Writes the finalized capture to `url` (the user's save-panel choice).
    func saveCapture(_ base: RuleCapture, to url: URL) throws {
        try finalizedCapture(base).encoded().write(to: url, options: .atomic)
    }

    /// Attaches the finalized capture to this Mac's Jamf computer record via
    /// the same uploader, role, and endpoint as the support bundle.
    func uploadCapture(_ base: RuleCapture) async {
        let capture = finalizedCapture(base)
        // Transient and failure states carry the RAW capture so a failed
        // upload returns to review with arguments intact and the Redact
        // checkbox still meaning what it says.
        capturePhase = .uploading(base)
        let staging = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-capture", isDirectory: true)
        let fileURL = staging.appendingPathComponent(capture.suggestedFileName)
        defer { try? FileManager.default.removeItem(at: fileURL) }
        do {
            try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: true)
            try capture.encoded().write(to: fileURL, options: .atomic)
            let result = try await uploaderFactory().upload(
                fileURL: fileURL, mimeType: "application/json", serialNumber: capture.host.serialNumber
            )
            // Ledger write is best-effort: an unwritable home must never turn a
            // successful upload into a failure in the UI.
            let size = (try? FileManager.default.attributesOfItem(atPath: fileURL.path))?[.size] as? Int
            try? uploadLedger.record(kind: .capture, fileName: result.fileName, computerID: result.computerID,
                                     serialNumber: capture.host.serialNumber, sizeBytes: size)
            capturePhase = .uploaded(capture, computerID: result.computerID)
        } catch {
            capturePhase = .failed(base, error.localizedDescription)
        }
    }

    /// Back to review after a failed upload (the capture is not lost).
    func retryCaptureReview() {
        if case let .failed(capture, _) = capturePhase { capturePhase = .review(capture) }
    }

    /// Done with a saved/uploaded capture. If a recording or build is still
    /// running this discards it (the session and tick must never outlive the
    /// phase that owns them).
    func resetCapture() {
        guard !captureInProgress else {
            discardCapture()
            return
        }
        capturePhase = .idle
        captureAttemptCount = 0
        captureElapsedSeconds = 0
    }

    // MARK: Derived

    /// The entries the table renders, after level and text filtering.
    var visibleEntries: [LogEntry] {
        var source: [LogEntry]
        switch mode {
        case .live: source = liveEntries
        case .history: source = historyEntries
        case .authorizations:
            source = authorizationEntries
            // Cut the credential/mechanism/sheet noise down to the lines that
            // actually name a right — the whole reason someone opened this tab.
            if authorizationRightsOnly {
                source = source.filter { AuthorizationParser.info(from: $0.message).namesRight }
            }
        }
        let needle = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return source.filter { entry in
            guard entry.level.severity >= minimumLevel.severity else { return false }
            guard !needle.isEmpty else { return true }
            return entry.message.lowercased().contains(needle)
                || entry.category.lowercased().contains(needle)
                || entry.subsystem.lowercased().contains(needle)
                || entry.processName.lowercased().contains(needle)
        }
    }

    var canExport: Bool {
        switch exportPhase {
        case .collecting, .uploading: return false
        default: return true
        }
    }

    /// Entries captured for the current mode, before any filtering.
    private var currentModeBufferCount: Int {
        switch mode {
        case .live: return liveEntries.count
        case .history: return historyEntries.count
        case .authorizations: return authorizationEntries.count
        }
    }

    /// Rows the table will actually render — attempts when grouped, entries
    /// otherwise. The empty state and the "N shown" counter both key off this,
    /// so they can't disagree with what's on screen.
    var visibleRowCount: Int {
        if mode == .authorizations && authorizationGrouped { return visibleAttempts.count }
        return visibleEntries.count
    }

    /// True when the mode captured entries but the active filters (Rights only,
    /// search text, level) hid all of them. Lets the empty state say "hidden by
    /// a filter" instead of "nothing happened" — the difference between telling
    /// the user to adjust a toggle and sending them to re-trigger an event that
    /// was actually captured.
    var entriesHiddenByFilter: Bool {
        visibleRowCount == 0 && currentModeBufferCount > 0
    }

    /// How many captured entries the filters are currently hiding.
    var hiddenEntryCount: Int {
        visibleRowCount == 0 ? currentModeBufferCount : 0
    }

    // MARK: Live streaming

    /// Starts the live tail.
    ///
    /// Two sources run concurrently and merge into one buffer:
    ///   - the daemon's JSONL decisions/integrity — always, no privilege;
    ///   - `log stream` — only when the unified log is readable (admin).
    /// A standard user therefore gets a live view with no elevation at all.
    func startStreaming() {
        guard !isStreaming else { return }
        isStreaming = true
        loadError = nil

        jsonlTask = Task { [weak self, tailer] in
            for await entry in tailer.stream() {
                guard let self else { return }
                self.append(entry)
            }
        }

        guard unifiedLogAvailable else { return }
        let query = LogQuery(includeInfoAndDebug: includeInfoAndDebug)
        streamTask = Task { [weak self, streamer] in
            for await entry in streamer.stream(query: query) {
                guard let self else { return }
                self.append(entry)
            }
        }
    }

    func stopStreaming() {
        streamTask?.cancel()
        streamTask = nil
        streamer.stop()
        jsonlTask?.cancel()
        jsonlTask = nil
        tailer.stop()
        isStreaming = false
    }

    private func restartStream() {
        stopStreaming()
        startStreaming()
    }

    /// Inserts in timestamp order.
    ///
    /// The two live sources do not arrive in lockstep — the JSONL tail polls on
    /// an interval while `log stream` is immediate — so a plain append would
    /// interleave a decision *after* later unified-log lines and read as though
    /// events happened out of order. Scanning back from the end is O(1) for the
    /// common case (the newest entry) and only walks as far as the skew.
    private func append(_ entry: LogEntry) {
        var index = liveEntries.count
        while index > 0, liveEntries[index - 1].date > entry.date {
            index -= 1
        }
        liveEntries.insert(entry, at: index)

        if liveEntries.count > Self.liveEntryLimit {
            liveEntries.removeFirst(liveEntries.count - Self.liveEntryLimit)
        }
    }

    func clearLive() {
        if mode == .authorizations {
            authorizationEntries.removeAll()
        } else {
            liveEntries.removeAll()
        }
    }

    private func modeChanged(from previous: ViewMode) {
        guard previous != mode else { return }
        // Leaving a mode stops whatever feed it was running.
        if previous == .live { stopStreaming() }
        if previous == .authorizations { stopAuthorizations() }

        switch mode {
        case .live:
            startStreaming()
        case .history:
            if historyEntries.isEmpty { Task { await loadHistory() } }
        case .authorizations:
            // Respect an explicit pause across a tab round-trip: if the user
            // froze the feed, re-entering the tab must NOT silently resume it
            // and scroll the right they were reading out of view.
            if !authorizationPaused { startAuthorizations() }
        }
    }

    // MARK: Authorizations (authURI events, via the daemon poll)

    func startAuthorizations() {
        guard authorizationTask == nil else { return }
        authorizationPaused = false
        authorizationUnavailable = nil
        // Refresh rules on (re)start so a profile pushed mid-session is
        // reflected in the tags.
        ruleStore = SerberusRuleStore.load()
        authorizationTask = Task { [weak self, authorizationTailer] in
            for await event in authorizationTailer.stream() {
                guard let self else { return }
                switch event {
                case let .entry(entry):
                    self.authorizationUnavailable = nil
                    self.appendAuthorization(entry)
                case let .unavailable(reason):
                    self.authorizationUnavailable = reason
                }
            }
        }
    }

    func stopAuthorizations() {
        authorizationTask?.cancel()
        authorizationTask = nil
        authorizationTailer.stop()
    }

    /// Pause/resume the live feed so a triggered right can be read.
    ///
    /// Pause tears the poll down entirely (no background daemon calls while
    /// frozen); the collected buffer stays put. Resume starts a fresh poll —
    /// authd's own persistent log still holds anything that fired during the
    /// pause, so a longer look-back on the first resumed poll would even
    /// back-fill it, though the default short window shows only what's current.
    func toggleAuthorizationsPaused() {
        if authorizationPaused {
            startAuthorizations()   // clears authorizationPaused
        } else {
            stopAuthorizations()
            authorizationPaused = true
        }
    }

    private func appendAuthorization(_ entry: LogEntry) {
        // The tailer already sorts and de-duplicates, and returns entries in
        // ascending time, so a plain append keeps them ordered.
        authorizationEntries.append(entry)
        if authorizationEntries.count > Self.liveEntryLimit {
            authorizationEntries.removeFirst(authorizationEntries.count - Self.liveEntryLimit)
        }
    }

    // MARK: History

    /// Loads the history view, merging both readable sources.
    ///
    /// The JSONL read is the floor: it always works and never fails the load.
    /// A `log show` failure degrades to a note rather than an error, because
    /// for a standard user it is the *expected* outcome, not a fault.
    func loadHistory() async {
        isLoadingHistory = true
        loadError = nil
        defer { isLoadingHistory = false }

        let selectedWindow = window
        let source = jsonlSource
        var merged = await Task.detached { source.entries(window: selectedWindow) }.value

        if unifiedLogAvailable {
            let reader = LogReader(query: LogQuery(includeInfoAndDebug: includeInfoAndDebug))
            do {
                merged.append(contentsOf: try await reader.show(window: selectedWindow))
            } catch {
                loadError = error.localizedDescription
            }
        }
        historyEntries = merged.sorted { $0.date < $1.date }
    }

    // MARK: Export

    /// Collects a bundle into the user's temporary directory.
    ///
    /// Staged in a temp directory rather than written straight to Downloads:
    /// the user chooses the final destination in a save panel, and an upload
    /// -only user never gets a stray zip in their Downloads folder.
    func collectBundle() async {
        exportPhase = .collecting
        do {
            let staging = FileManager.default.temporaryDirectory
                .appendingPathComponent("serberus-intel", isDirectory: true)
            try FileManager.default.createDirectory(at: staging, withIntermediateDirectories: true)
            let bundle = try await collector.collect(window: window, destinationDirectory: staging)
            exportPhase = .ready(bundle)
        } catch {
            exportPhase = .failed(error.localizedDescription)
        }
    }

    func upload(bundle: IntelBundle) async {
        exportPhase = .uploading
        do {
            let result = try await uploaderFactory().upload(bundle: bundle)
            let size = (try? FileManager.default.attributesOfItem(atPath: bundle.archiveURL.path))?[.size] as? Int
            try? uploadLedger.record(kind: .intel, fileName: result.fileName, computerID: result.computerID,
                                     serialNumber: bundle.manifest.host.serialNumber, sizeBytes: size)
            exportPhase = .uploaded(computerID: result.computerID)
        } catch {
            exportPhase = .failed(error.localizedDescription)
        }
    }

    func resetExport() {
        exportPhase = .idle
    }
}
