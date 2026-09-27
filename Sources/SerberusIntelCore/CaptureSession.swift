import Foundation
import PrivMgrCore

// MARK: - Builder (pure)

/// Turns the raw material of a Capture session — authd lines, sudo lines, the
/// daemon's decision events — into a ``RuleCapture``. Pure and injectable so
/// the whole mapping is testable with fixture entries and no daemon.
public struct CaptureBuilder: Sendable {
    public typealias RuleTag = @Sendable (String) -> AuthorizationRuleTag?

    /// What the builder needs to know about a path before touching it.
    public struct FileInfo: Sendable, Equatable {
        public let isRegularFile: Bool
        public let size: Int
        public init(isRegularFile: Bool, size: Int) {
            self.isRegularFile = isRegularFile
            self.size = size
        }
    }

    /// Looks up the identity of a binary on disk at capture time. Injected so
    /// tests do not depend on what is signed on the build Mac.
    public let identity: any BinaryIdentityInspecting
    /// Produces the "Serberus rule for this right" lookup. Invoked ONCE per
    /// build (it loads the managed-preferences rule store), then applied per
    /// right.
    public let ruleTagProvider: @Sendable () -> RuleTag
    /// `nil` when the path does not exist (a capture from another Mac, a
    /// typo'd command sudo still logs). Identity inspection and realpath are
    /// skipped for anything that is not a regular file on disk.
    public let fileInfo: @Sendable (String) -> FileInfo?
    /// `realpath` of a path, for symlinked binaries.
    public let resolveSymlinks: @Sendable (String) -> String
    /// Keep sudo attempts by users other than the console user. Off by default:
    /// a capture is the console user's session (the daemon already scopes the
    /// poll to them; this is the builder's own guarantee).
    public let includeOtherUsers: Bool
    /// Predicts which composed branch (per-app sub-rule vs native-default) a
    /// client binary resolves against on an identity-scoped right. Injected
    /// so tests never depend on what is signed on the build Mac.
    public let branchResolver: BranchMatchResolver

    /// How far a Serberus `DecisionEvent` may sit from sudo's own log line and
    /// still be the same attempt. The daemon decides DURING PAM — before sudo
    /// writes its line — so the event normally precedes the line by well under
    /// a second; a prompt rule adds the user's think time, hence the generous
    /// bound.
    public static let decisionMatchTolerance: TimeInterval = 120
    /// Binaries above this size are identity-pinned by Team ID only if at all —
    /// never hashed (a capture must not read gigabytes off disk on the main
    /// path because a log line named a path).
    public static let maxHashedBinaryBytes = 64 * 1024 * 1024

    public init(
        identity: any BinaryIdentityInspecting = BinaryIdentityInspector(),
        ruleTagProvider: @escaping @Sendable () -> RuleTag = { { _ in nil } },
        fileInfo: @escaping @Sendable (String) -> FileInfo? = { path in
            guard let attributes = try? FileManager.default.attributesOfItem(atPath: path) else { return nil }
            let type = attributes[.type] as? FileAttributeType
            let size = (attributes[.size] as? NSNumber)?.intValue ?? 0
            return FileInfo(isRegularFile: type == .typeRegular, size: size)
        },
        resolveSymlinks: @escaping @Sendable (String) -> String = {
            URL(fileURLWithPath: $0).resolvingSymlinksInPath().path
        },
        includeOtherUsers: Bool = false,
        branchResolver: BranchMatchResolver = BranchMatchResolver()
    ) {
        self.identity = identity
        self.ruleTagProvider = ruleTagProvider
        self.fileInfo = fileInfo
        self.resolveSymlinks = resolveSymlinks
        self.includeOtherUsers = includeOtherUsers
        self.branchResolver = branchResolver
    }

    /// Builds the capture. Entries outside `[startedAt, endedAt]` (with a 1 s
    /// grace for clock skew between `log show` and the app) are dropped.
    public func build(
        authorizationEntries: [LogEntry],
        sudoEntries: [LogEntry],
        decisions: [DecisionEvent],
        host: CaptureHost,
        componentVersions: [String: String] = [:],
        consoleUser: String,
        startedAt: Date,
        endedAt: Date,
        notes: String = ""
    ) -> RuleCapture {
        let lower = startedAt.addingTimeInterval(-1)
        let upper = endedAt.addingTimeInterval(1)
        func inWindow(_ date: Date) -> Bool { date >= lower && date <= upper }

        let ruleTag = ruleTagProvider()
        // One inspection per distinct path per build: N attempts from the same
        // client cost one SecStaticCode + one hash.
        var pinCache: [String: Pin?] = [:]
        func pin(for path: String) -> Pin? {
            if let cached = pinCache[path] { return cached }
            let computed = identityPin(for: path)
            pinCache[path] = computed
            return computed
        }

        var attempts: [CapturedAttempt] = []

        // authURI: one attempt per (engine, right), from the grouper that
        // already knows authd's multi-line shape.
        for attempt in AuthorizationGrouper.group(authorizationEntries) where inWindow(attempt.date) {
            let client = attempt.client
            let clientPin = client.flatMap(pin(for:))
            let tag = ruleTag(attempt.right)
            // Per-branch instrumentation for composed rights: which sub-rule
            // the logged client binary satisfies (a prediction from the code
            // requirement — `/usr/libexec/smd` as the client means
            // native-default, i.e. smd-mediated), plus any authd line that
            // NAMES a branch row (authd's own word, when it gives one).
            let candidates = tag?.identityCandidates ?? []
            let rawMessages = attempt.lines.map(\.message)
            let predicted = branchResolver.predictedBranch(clientPath: client, candidates: candidates)
            let evidence = candidates.isEmpty ? nil : BranchMatchResolver.evidence(in: rawMessages)
            attempts.append(CapturedAttempt(
                id: UUID().uuidString,
                kind: .authuri,
                timestamp: attempt.date,
                user: consoleUser,
                authURI: attempt.right,
                clientPath: client,
                teamID: clientPin?.teamID,
                binaryHash: clientPin?.hash,
                // The CLIENT's pid from `by client '…' [pid]` when authd named
                // one — never authd's own process id (seen in the first live
                // capture: every authuri attempt carried authd's pid 610).
                pid: Self.clientPID(in: attempt.lines),
                outcome: Self.outcome(attempt.outcome),
                matchedRuleID: tag?.ruleID,
                rawLines: rawMessages,
                predictedBranch: predicted,
                branchEvidence: evidence
            ))
        }

        // sudo: one attempt per `COMMAND=` line, in time order, each enriched
        // by at most ONE Serberus decision (and each decision used once).
        var seenSudo = Set<String>()
        var claimedDecisions = Set<UUID>()
        let sudoLines = sudoEntries
            .filter { inWindow($0.date) && SudoAttemptParser.isAttemptLine($0) }
            .sorted { $0.date < $1.date }
        for entry in sudoLines {
            guard let info = SudoAttemptParser.info(from: entry.message) else { continue }
            guard includeOtherUsers || info.user == consoleUser else { continue }
            let dedupKey = "\(entry.timestamp)|\(entry.processID)|\(entry.message)"
            guard seenSudo.insert(dedupKey).inserted else { continue }

            let resolved = resolvedPath(for: info.command)
            let decision = Self.assignDecision(
                to: entry.date, user: info.user, command: info.command, resolved: resolved,
                in: decisions, claimed: &claimedDecisions
            )
            // The identity the daemon validated at decision time is the truth
            // when it exists (as a PAIR — never mixed with a later on-disk
            // reading); otherwise inspect the binary now.
            let effectivePin = decision.flatMap(Self.decisionPin) ?? pin(for: resolved ?? info.command)
            // sudo's status prose is the primary verdict; when it is a shape
            // we cannot classify but the daemon DID decide, the daemon's
            // verdict settles it (granted / denied — a "would-*" monitor
            // verdict says nothing about what sudo did, so it is left alone).
            let outcome = info.outcome == .unknown
                ? (decision.flatMap(Self.outcome(fromDecision:)) ?? .unknown)
                : info.outcome
            attempts.append(CapturedAttempt(
                id: UUID().uuidString,
                kind: .sudo,
                timestamp: entry.date,
                user: info.user,
                sudoCommand: info.command,
                resolvedCommand: resolved,
                argv: info.arguments,
                sudoStatus: info.status,
                teamID: effectivePin?.teamID,
                binaryHash: effectivePin?.hash,
                pid: entry.processID,
                outcome: outcome,
                matchedRuleID: decision?.ruleID,
                matchedProfileKey: decision?.profileKey,
                serberusOutcome: decision?.outcome.rawValue,
                rawLines: [entry.message]
            ))
        }

        attempts.sort { $0.timestamp < $1.timestamp }
        return RuleCapture(
            host: host,
            componentVersions: componentVersions,
            startedAt: startedAt,
            endedAt: endedAt,
            attempts: attempts,
            notes: notes
        )
    }

    // MARK: Helpers

    struct Pin: Sendable, Equatable {
        let teamID: String?
        let hash: String?
    }

    private func resolvedPath(for command: String) -> String? {
        guard fileInfo(command) != nil else { return nil }
        let resolved = resolveSymlinks(command)
        return resolved == command ? nil : resolved
    }

    private func identityPin(for path: String) -> Pin? {
        guard let info = fileInfo(path), info.isRegularFile, info.size <= Self.maxHashedBinaryBytes else {
            return nil
        }
        let identity = identity.inspect(canonicalPath: path)
        let hash = identity.sha256.isEmpty ? nil : identity.sha256
        guard identity.teamID != nil || hash != nil else { return nil }
        return Pin(teamID: identity.teamID, hash: hash)
    }

    /// The identity a decision event carries, as a pair, or nil when it
    /// carries neither (the daemon stamps empty strings for "none").
    static func decisionPin(_ event: DecisionEvent) -> Pin? {
        let teamID = nonEmpty(event.processTeamID)
        let hash = nonEmpty(event.processHash)
        guard teamID != nil || hash != nil else { return nil }
        return Pin(teamID: teamID, hash: hash)
    }

    static func nonEmpty(_ value: String?) -> String? {
        guard let value, !value.isEmpty else { return nil }
        return value
    }

    static func outcome(_ outcome: AuthorizationOutcome) -> CapturedOutcome {
        switch outcome {
        case .granted: return .granted
        case .denied: return .denied
        case .failed: return .failed
        case .requested: return .requested
        }
    }

    /// The daemon's verdict as a capture outcome, for an otherwise
    /// unclassifiable sudo status. Monitor-mode "would-*" verdicts return nil.
    static func outcome(fromDecision event: DecisionEvent) -> CapturedOutcome? {
        switch event.outcome {
        case .granted: return .granted
        case .denied: return .denied
        case .wouldGrant, .wouldDeny: return nil
        }
    }

    private static let clientPIDPattern = try! NSRegularExpression(pattern: #"by client '[^']*' \[(\d+)\]"#)

    /// The requesting client's pid from authd's `by client '/path' [pid]`,
    /// when any line of the attempt names one.
    static func clientPID(in lines: [LogEntry]) -> Int? {
        for entry in lines {
            let message = entry.message
            let range = NSRange(message.startIndex..., in: message)
            guard let match = clientPIDPattern.firstMatch(in: message, range: range),
                  let pidRange = Range(match.range(at: 1), in: message),
                  let pid = Int(message[pidRange]) else { continue }
            return pid
        }
        return nil
    }

    /// The daemon decides DURING PAM, i.e. before sudo writes its own line, so
    /// a line's decision sits at or just before it. This grace absorbs
    /// sub-second ordering noise between the two clocks — and is kept SHORT so
    /// it can never reach the NEXT attempt's decision (back-to-back runs are
    /// ~1 s apart).
    static let decisionPrecedesLineGrace: TimeInterval = 0.25

    /// Assigns at most one decision event to a sudo line: same user, same
    /// command (logged path OR realpath — the daemon records the canonical
    /// binary), within ``decisionMatchTolerance``, not already claimed by an
    /// earlier line. Prefers the LATEST decision at or before the line (within
    /// ``decisionPrecedesLineGrace``) and only falls back to the earliest later
    /// one (a prompt rule: the event lands after the user's think time) — so
    /// two back-to-back runs of the same command each get their own decision,
    /// in order.
    static func assignDecision(
        to date: Date,
        user: String,
        command: String,
        resolved: String?,
        in decisions: [DecisionEvent],
        claimed: inout Set<UUID>
    ) -> DecisionEvent? {
        let wanted = Set([command, resolved].compactMap { $0 })
        let candidates = decisions.filter { event in
            guard !claimed.contains(event.eventID), event.userName == user else { return false }
            let eventPaths = Set([event.sudoCommand, event.processPath].compactMap { $0 })
            guard !wanted.isDisjoint(with: eventPaths) else { return false }
            return abs(event.timestamp.timeIntervalSince(date)) <= decisionMatchTolerance
        }
        let grace = date.addingTimeInterval(decisionPrecedesLineGrace)
        let chosen = candidates.filter { $0.timestamp <= grace }.max { $0.timestamp < $1.timestamp }
            ?? candidates.filter { $0.timestamp > grace }.min { $0.timestamp < $1.timestamp }
        if let chosen { claimed.insert(chosen.eventID) }
        return chosen
    }
}

// MARK: - Session (live)

/// Everything a session collected, frozen at stop — cheap to take on the main
/// actor; the heavy build happens from it elsewhere.
public struct CaptureSnapshot: Sendable {
    public let startedAt: Date
    public let endedAt: Date
    public let authorizationEntries: [LogEntry]
    public let sudoEntries: [LogEntry]
    /// Why a source could not be polled, if it could not.
    public let unavailable: String?
}

/// One Capture recording: starts the authd and sudo pollers, accumulates
/// their entries, and hands the buffers to ``CaptureBuilder`` on stop.
///
/// Owned by the Sentinel's `IntelModel` for the life of the app; it is not
/// tied to the Intel tab's view mode, so a capture keeps recording while the
/// user switches tabs. All shared state is behind one lock, and every
/// consumer task carries the session `generation` it was started for, so an
/// event from a previous session can never land in the next one's buffers.
public final class CaptureSession: @unchecked Sendable {
    public enum Source: Sendable { case authorizations, sudo }

    private let authorizationTailer: AuthorizationTailer
    private let sudoTailer: SudoTailer
    private let decisionSource: JSONLLogSource
    private let builder: CaptureBuilder
    private let host: @Sendable () -> (CaptureHost, [String: String])
    private let consoleUser: String

    private let lock = NSLock()
    private var generation = 0
    private var authorizationEntries: [LogEntry] = []
    private var sudoEntries: [LogEntry] = []
    private var unavailableReasons: [Source: String] = [:]
    private var startedAt: Date?
    private var tasks: [Task<Void, Never>] = []
    /// `attemptCount` is asked every second by the UI; re-grouping the whole
    /// authd buffer each time is O(n log n), so the answer is cached until a
    /// buffer actually changes.
    private var countCache: (auth: Int, sudo: Int, count: Int)?

    public init(
        client: IntelXPCClient = IntelXPCClient(),
        decisionSource: JSONLLogSource = JSONLLogSource(),
        builder: CaptureBuilder? = nil,
        host: @escaping @Sendable () -> (CaptureHost, [String: String]) = {
            let context = HostProbe().current()
            return (
                CaptureHost(
                    serialNumber: context.serialNumber,
                    computerName: context.computerName,
                    osVersion: context.osVersion,
                    userName: context.userName,
                    daemonState: context.daemonState,
                    enforcementMode: context.enforcementMode
                ),
                context.componentVersions
            )
        },
        consoleUser: String = NSUserName(),
        pollInterval: TimeInterval = 2.0,
        pollWindow: String = "10s"
    ) {
        self.authorizationTailer = AuthorizationTailer(client: client, interval: pollInterval, window: pollWindow)
        self.sudoTailer = SudoTailer(client: client, interval: pollInterval, window: pollWindow)
        self.decisionSource = decisionSource
        // The rule store is loaded once per BUILD (not per right, not at init),
        // so a profile pushed mid-capture is reflected.
        self.builder = builder ?? CaptureBuilder(ruleTagProvider: {
            let store = SerberusRuleStore.load()
            return { right in store.tag(forRight: right) }
        })
        self.host = host
        self.consoleUser = consoleUser
    }

    public var isRecording: Bool {
        lock.lock(); defer { lock.unlock() }
        return startedAt != nil
    }

    public var startDate: Date? {
        lock.lock(); defer { lock.unlock() }
        return startedAt
    }

    /// Attempts observed so far — what the Capture button's counter shows.
    /// Grouped the same way the final capture will be, so the number does not
    /// jump on stop.
    public var attemptCount: Int {
        lock.lock()
        if let cached = countCache, cached.auth == authorizationEntries.count, cached.sudo == sudoEntries.count {
            lock.unlock()
            return cached.count
        }
        let auth = authorizationEntries
        let sudo = sudoEntries
        lock.unlock()
        let count = AuthorizationGrouper.group(auth).count + sudo.filter(SudoAttemptParser.isAttemptLine).count
        lock.lock()
        countCache = (auth.count, sudo.count, count)
        lock.unlock()
        return count
    }

    /// First reason a source could not be polled (e.g. the daemon is down),
    /// so the UI can say why a capture is empty instead of implying nothing
    /// happened. Cleared when that source recovers.
    public var unavailable: String? {
        lock.lock(); defer { lock.unlock() }
        return unavailableReasons[.sudo] ?? unavailableReasons[.authorizations]
    }

    /// Starts both pollers. Idempotent while recording.
    public func start(at date: Date = Date()) {
        lock.lock()
        guard startedAt == nil else { lock.unlock(); return }
        // Defensive: any straggler tasks from a previous session.
        let stale = tasks
        tasks = []
        generation += 1
        let session = generation
        startedAt = date
        authorizationEntries.removeAll()
        sudoEntries.removeAll()
        unavailableReasons.removeAll()
        countCache = nil
        lock.unlock()
        stale.forEach { $0.cancel() }

        let authTask = Task { [weak self, authorizationTailer] in
            for await event in authorizationTailer.stream() {
                guard let self else { return }
                switch event {
                case let .entry(entry): self.append(entry, to: .authorizations, generation: session)
                case let .unavailable(reason): self.noteUnavailable(reason, for: .authorizations, generation: session)
                }
            }
        }
        let sudoTask = Task { [weak self, sudoTailer] in
            for await event in sudoTailer.stream() {
                guard let self else { return }
                switch event {
                case let .entry(entry): self.append(entry, to: .sudo, generation: session)
                case let .unavailable(reason): self.noteUnavailable(reason, for: .sudo, generation: session)
                case .recovered: self.noteRecovered(for: .sudo, generation: session)
                }
            }
        }
        lock.lock()
        // A stop() that raced in between would have advanced nothing (tasks
        // were empty); only adopt the tasks if this session is still current.
        if generation == session, startedAt != nil {
            tasks = [authTask, sudoTask]
            lock.unlock()
        } else {
            lock.unlock()
            authTask.cancel()
            sudoTask.cancel()
        }
    }

    /// Stops polling and freezes what was collected. Cheap — safe on the main
    /// actor. Returns `nil` if no session was running.
    public func stopCollecting(at date: Date = Date()) -> CaptureSnapshot? {
        lock.lock()
        guard let started = startedAt else { lock.unlock(); return nil }
        startedAt = nil
        let running = tasks
        tasks = []
        let snapshot = CaptureSnapshot(
            startedAt: started,
            endedAt: date,
            authorizationEntries: authorizationEntries,
            sudoEntries: sudoEntries,
            unavailable: unavailableReasons[.sudo] ?? unavailableReasons[.authorizations]
        )
        lock.unlock()

        authorizationTailer.stop()
        sudoTailer.stop()
        running.forEach { $0.cancel() }
        return snapshot
    }

    /// The heavy half: host probe, decision-log read, identity inspection,
    /// grouping. Run it off the main actor (it is `nonisolated` and the
    /// snapshot is `Sendable`).
    public func build(from snapshot: CaptureSnapshot, notes: String = "") -> RuleCapture {
        let (hostInfo, versions) = host()
        // Decisions a little either side of the window: the daemon's event can
        // land after sudo's own line (prompt think-time), and clocks differ.
        let decisions = decisionSource.decisionEvents(
            from: snapshot.startedAt.addingTimeInterval(-5),
            to: snapshot.endedAt.addingTimeInterval(CaptureBuilder.decisionMatchTolerance)
        )
        return builder.build(
            authorizationEntries: snapshot.authorizationEntries,
            sudoEntries: snapshot.sudoEntries,
            decisions: decisions,
            host: hostInfo,
            componentVersions: versions,
            consoleUser: consoleUser,
            startedAt: snapshot.startedAt,
            endedAt: snapshot.endedAt,
            notes: notes
        )
    }

    /// Stop + build in one call (tests, non-UI callers).
    public func stop(at date: Date = Date(), notes: String = "") -> RuleCapture? {
        guard let snapshot = stopCollecting(at: date) else { return nil }
        return build(from: snapshot, notes: notes)
    }

    /// Abandons a running session without building anything.
    public func cancel() {
        _ = stopCollecting()
    }

    // MARK: Consumers

    private func append(_ entry: LogEntry, to source: Source, generation: Int) {
        lock.lock()
        defer { lock.unlock() }
        guard generation == self.generation, startedAt != nil else { return }
        switch source {
        case .authorizations: authorizationEntries.append(entry)
        case .sudo: sudoEntries.append(entry)
        }
        // Delivery proves the source is back, whether or not it said so.
        unavailableReasons[source] = nil
    }

    private func noteUnavailable(_ reason: String, for source: Source, generation: Int) {
        lock.lock()
        defer { lock.unlock() }
        guard generation == self.generation, startedAt != nil else { return }
        if unavailableReasons[source] == nil { unavailableReasons[source] = reason }
    }

    private func noteRecovered(for source: Source, generation: Int) {
        lock.lock()
        defer { lock.unlock() }
        guard generation == self.generation else { return }
        unavailableReasons[source] = nil
    }
}
