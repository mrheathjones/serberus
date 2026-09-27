import Darwin
import Foundation
import OpenDirectory
import PrivMgrCore

/// Runs a subprocess to completion off the calling actor, returning its exit
/// code and captured output. Used for the directory-service and delegation
/// commands the daemon shells out to, and for the installer's tools (`lsbom`,
/// `pkgutil`, `installer`), whose output can run to megabytes.
public struct ProcessCommandRunner: CommandRunning {
    /// Wall-clock budget for ``run(path:arguments:)``. Test seam — production
    /// always takes ``defaultTimeout``.
    private let timeout: TimeInterval

    public init() { self.timeout = Self.defaultTimeout }

    /// Internal: lets a test prove the timeout fires without waiting out the
    /// full production budget.
    init(timeout: TimeInterval) { self.timeout = timeout }

    /// Runs `path` and returns its exit status, THROWING
    /// ``JITAdminError/commandTimedOut(path:seconds:)`` if it overruns.
    ///
    /// Fails closed by construction: ``CommandRunning/run(path:arguments:)`` is
    /// `throws`, and the sole caller (`DirectoryServicesGroupController.mutate`)
    /// propagates, so a `dseditgroup` promote that times out grants no admin.
    public func run(path: String, arguments: [String]) async throws -> Int32 {
        let timed = try await Self.execute(path: path, arguments: arguments, timeout: timeout)
        guard !timed.timedOut else {
            throw JITAdminError.commandTimedOut(path: path, seconds: timeout)
        }
        return timed.status
    }

    struct Result: Sendable {
        let status: Int32
        let stdout: String
    }

    /// Wall-clock budget for the directory-service commands below. Matches
    /// ``SudoersManager``'s `visudoTimeout`: these are small, local tools that
    /// either answer in milliseconds or are wedged.
    static let defaultTimeout: TimeInterval = 10

    /// Runs `path` to completion under ``defaultTimeout``, THROWING if it expires.
    ///
    /// The bound matters: these commands run on the daemon's policy-reload path
    /// (via `JITAdminManager`), and the previous unbounded `readDataToEndOfFile()`
    /// + `waitUntilExit()` sat inside a continuation that would then never resume
    /// — parking the reload loop forever, which is silent policy drift with
    /// nothing logged.
    ///
    /// Bounding a call converts a HANG into an ANSWER, so every caller must be
    /// checked for which direction its error path fails:
    /// - ``DirectoryServicesGroupController/groups(forUser:)`` swallows it into
    ///   an empty set ⇒ `isEligible` false ⇒ denied. Fails closed.
    /// - ``DirectoryServicesGroupController/isMember(user:group:)`` PROPAGATES —
    ///   swallowing it would report "not a member", which the JIT promote path
    ///   reads as "safe to promote and later demote". Fails closed only because
    ///   it throws.
    /// - ``DirectoryServicesGroupController/addMember(user:group:)`` propagates
    ///   ⇒ a promote that times out grants no admin. Fails closed.
    /// - ``DirectoryServicesGroupController/removeMember(user:group:)``
    ///   propagates ⇒ ``JITAdminManager`` keeps the grant active and retries,
    ///   rather than recording a demotion that never happened.
    static func execute(path: String, arguments: [String]) async throws -> Result {
        let timed = try await execute(path: path, arguments: arguments, timeout: defaultTimeout)
        guard !timed.timedOut else {
            throw JITAdminError.commandTimedOut(path: path, seconds: defaultTimeout)
        }
        return Result(status: timed.status, stdout: timed.stdout)
    }

    /// A subprocess result that also carries stderr and whether the run exceeded
    /// its deadline. Used by the fail-closed `visudo` validation path, where a
    /// hung validator must be treated as a failure rather than blocking forever.
    struct TimedResult: Sendable {
        let status: Int32
        let stdout: String
        let stderr: String
        /// True when the process did not exit before `timeout` and was killed.
        let timedOut: Bool
        /// True when stdout and stderr together passed the output cap. The
        /// process was killed, `status` is ``outputLimitExceededStatus`` and
        /// the captured output is incomplete.
        var outputLimitExceeded: Bool = false
    }

    /// The most stdout + stderr ``execute(path:arguments:timeout:outputLimit:)``
    /// keeps. A payload listing of a large package is a few MiB; past this the
    /// tool is misbehaving.
    static let defaultOutputLimit = 64 << 20

    /// The status reported for a run whose output passed the cap, whatever the
    /// process itself returned: never 0, so every caller that checks for
    /// success fails closed.
    static let outputLimitExceededStatus: Int32 = 125

    /// Runs `path` with `arguments` under a wall-clock `timeout`. On expiry the
    /// process is sent SIGTERM, then SIGKILL if it is still running after a
    /// short grace period, and `timedOut` is set — the caller decides how to
    /// treat it (the sudoers path treats a timeout as fail-closed). stderr is
    /// captured so a validation failure can be logged with its diagnostic.
    ///
    /// stdout and stderr are drained WHILE the process runs, so a tool that
    /// writes more than a pipe buffer (64 KiB) — `lsbom` on a real package —
    /// never blocks on a full pipe. Together they are capped at `outputLimit`
    /// bytes: past it the process is SIGKILLed and the result reports
    /// ``outputLimitExceededStatus`` (fail closed). After the process exits the
    /// pipes are read to end-of-file, for at most a short grace period, so a
    /// descendant that inherited them cannot hold the call open.
    static func execute(
        path: String, arguments: [String], timeout: TimeInterval,
        outputLimit: Int = defaultOutputLimit
    ) async throws -> TimedResult {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: path)
                process.arguments = arguments
                let outPipe = Pipe()
                let errPipe = Pipe()
                process.standardOutput = outPipe
                process.standardError = errPipe

                let exited = DispatchSemaphore(value: 0)
                process.terminationHandler = { _ in exited.signal() }
                do {
                    try process.run()
                } catch {
                    continuation.resume(throwing: error)
                    return
                }

                let output = OutputDrain(limit: outputLimit) {
                    if process.isRunning { kill(process.processIdentifier, SIGKILL) }
                }
                output.start(stdout: outPipe.fileHandleForReading, stderr: errPipe.fileHandleForReading)

                let timedOut = exited.wait(timeout: .now() + timeout) == .timedOut
                if timedOut {
                    process.terminate()
                    // Give SIGTERM a brief moment. A child that ignores it is
                    // then SIGKILLed, so nothing keeps running after the caller
                    // has been told it failed (and, for example, has deleted its
                    // staging directory or released its slot).
                    if exited.wait(timeout: .now() + 2) == .timedOut {
                        kill(process.processIdentifier, SIGKILL)
                        _ = exited.wait(timeout: .now() + 2)
                    }
                }

                let captured = output.finish(grace: 2)
                process.waitUntilExit()
                withExtendedLifetime((outPipe, errPipe)) {}
                continuation.resume(returning: TimedResult(
                    status: captured.exceeded ? outputLimitExceededStatus : process.terminationStatus,
                    stdout: String(decoding: captured.stdout, as: UTF8.self),
                    stderr: String(decoding: captured.stderr, as: UTF8.self),
                    timedOut: timedOut,
                    outputLimitExceeded: captured.exceeded
                ))
            }
        }
    }

    /// Reads a child's stdout and stderr as data arrives, with one byte cap
    /// across both. Non-blocking descriptors under dispatch read sources, so
    /// ``finish(grace:)`` can stop waiting on a pipe a descendant still holds.
    private final class OutputDrain: @unchecked Sendable {
        private let lock = NSLock()
        private var buffers = [Data(), Data()]
        private var total = 0
        private var exceeded = false
        private let limit: Int
        private let onExceeded: () -> Void
        private let queue = DispatchQueue(label: "com.herojoneslabs.serberus.process-output")
        private let group = DispatchGroup()
        private var sources: [DispatchSourceRead] = []

        init(limit: Int, onExceeded: @escaping () -> Void) {
            self.limit = limit
            self.onExceeded = onExceeded
        }

        func start(stdout: FileHandle, stderr: FileHandle) {
            for (index, handle) in [stdout, stderr].enumerated() {
                let fd = handle.fileDescriptor
                _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
                let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
                group.enter()
                source.setEventHandler { [weak self, weak source] in
                    guard let self, let source else { return }
                    self.drain(fd: fd, into: index, source: source)
                }
                // The FileHandle owns the descriptor; the source only reads it.
                source.setCancelHandler { [group] in group.leave() }
                sources.append(source)
                source.resume()
            }
        }

        /// Reads what is available: to end-of-file (cancel), to EAGAIN (wait
        /// for the next event), or until the cap is passed (kill, cancel).
        private func drain(fd: Int32, into index: Int, source: DispatchSourceRead) {
            var chunk = [UInt8](repeating: 0, count: 64 << 10)
            while !source.isCancelled {
                let count = chunk.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
                if count > 0 {
                    if !append(chunk[0..<count], to: index) {
                        onExceeded()
                        source.cancel()
                    }
                    continue
                }
                if count < 0 && errno == EINTR { continue }
                if count < 0 && errno == EAGAIN { return }
                source.cancel() // end-of-file, or a read error
            }
        }

        private func append(_ bytes: ArraySlice<UInt8>, to index: Int) -> Bool {
            lock.lock(); defer { lock.unlock() }
            guard !exceeded else { return false }
            guard total + bytes.count <= limit else {
                exceeded = true
                return false
            }
            buffers[index].append(contentsOf: bytes)
            total += bytes.count
            return true
        }

        /// Waits up to `grace` seconds for both pipes to reach end-of-file,
        /// stops reading, and returns what was captured.
        func finish(grace: TimeInterval) -> (stdout: Data, stderr: Data, exceeded: Bool) {
            if group.wait(timeout: .now() + grace) == .timedOut {
                queue.sync { sources.filter { !$0.isCancelled }.forEach { $0.cancel() } }
                group.wait()
            }
            sources.removeAll()
            lock.lock(); defer { lock.unlock() }
            return (buffers[0], buffers[1], exceeded)
        }
    }
}

/// Production ``GroupMembershipControlling`` backed by `dseditgroup` (membership
/// mutation + checks) and `id` (group enumeration). All mutating calls require
/// the daemon's root privileges.
public struct DirectoryServicesGroupController: GroupMembershipControlling {
    private let dseditgroup: String
    private let idTool: String
    private let runner: ProcessCommandRunner

    public init(
        dseditgroup: String = "/usr/sbin/dseditgroup",
        idTool: String = "/usr/bin/id",
        runner: ProcessCommandRunner = ProcessCommandRunner()
    ) {
        self.dseditgroup = dseditgroup
        self.idTool = idTool
        self.runner = runner
    }

    public func isMember(user: String, group: String) async throws -> Bool {
        // `dseditgroup -o checkmember -m <user> <group>` exits 0 when a member and
        // 67 when definitively not — a clean `false`. It exits 64 when it cannot
        // find the user record, which a deleted account, a RENAMED account and an
        // unreachable directory node all produce alike; that throws
        // ``JITAdminError/userRecordNotFound(user:)`` so the demotion paths can
        // decide which it is from the grant's uid (``JITAccountResolving``). Any
        // other status, a LAUNCH failure, or a TIMEOUT throws too.
        //
        // Deliberately NOT `try?`. Swallowing the error would report "not a
        // member" for a user whose membership is merely unknown, and
        // ``JITAdminManager/grantSerberus`` reads that as "safe to promote and
        // schedule a demotion" — which would later strip a permanent admin's own
        // rights. `dseditgroup` opens an OpenDirectory session and so can block
        // on an unreachable directory node; that must fail closed, not open.
        let result = try await ProcessCommandRunner.execute(
            path: dseditgroup, arguments: ["-o", "checkmember", "-m", user, group])
        return try Self.interpretCheckMember(status: result.status, user: user)
    }

    /// `dseditgroup -o checkmember` exit status → membership. 0 = member;
    /// ``checkMemberNotAMemberStatus`` (67) = definitively NOT a member;
    /// ``checkMemberNoSuchUserStatus`` (64) throws
    /// ``JITAdminError/userRecordNotFound(user:)``. Every other status is an
    /// ERROR and THROWS — reading it as "not a member" would let the JIT promote
    /// path treat a possible permanent admin as safe to promote-and-later-demote.
    static func interpretCheckMember(status: Int32, user: String = "") throws -> Bool {
        switch status {
        case 0: return true
        case checkMemberNotAMemberStatus: return false
        case checkMemberNoSuchUserStatus: throw JITAdminError.userRecordNotFound(user: user)
        default: throw JITAdminError.membershipCommandFailed(status: status)
        }
    }

    /// `dseditgroup -o checkmember`'s "no, not a member" exit status.
    static let checkMemberNotAMemberStatus: Int32 = 67
    /// `dseditgroup -o checkmember`'s "unable to find the user record" status.
    static let checkMemberNoSuchUserStatus: Int32 = 64

    public func groups(forUser user: String) async -> Set<String> {
        // `id -Gn <user>` prints space-separated group names.
        guard let result = try? await ProcessCommandRunner.execute(
            path: idTool, arguments: ["-Gn", user]), result.status == 0 else {
            return []
        }
        let names = result.stdout
            .split(whereSeparator: { $0 == " " || $0 == "\n" })
            .map(String.init)
        return Set(names)
    }

    public func addMember(user: String, group: String) async throws {
        try await mutate(op: "-a", user: user, group: group)
    }

    public func removeMember(user: String, group: String) async throws {
        try await mutate(op: "-d", user: user, group: group)
    }

    private func mutate(op: String, user: String, group: String) async throws {
        let status = try await runner.run(
            path: dseditgroup, arguments: ["-o", "edit", op, user, "-t", "user", group])
        guard status == 0 else {
            throw JITAdminError.membershipCommandFailed(status: status)
        }
    }
}

public enum JITAdminError: Error, Sendable, Equatable {
    case membershipCommandFailed(status: Int32)
    /// A directory-service command exceeded its wall-clock budget and was killed.
    /// Distinct from a non-zero exit so the fail-safe reason is legible in logs.
    case commandTimedOut(path: String, seconds: TimeInterval)
    /// `dseditgroup` could not find the user's record. NOT "not a member": the
    /// account may have been deleted, renamed, or live on a directory node that
    /// is unreachable right now (see ``JITAccountResolving``).
    case userRecordNotFound(user: String)
}

// MARK: - Local account lookups (thread-safe `_r` variants)

/// Local directory lookups used by the ESF exec gate's break-glass exemption
/// and the runtime break-glass resolvability check. All use the reentrant
/// `getpwnam_r` / `getpwuid_r` / `getgrnam_r` — these run concurrently from the
/// ES authorization tasks, where the static-buffer variants would race.
public enum LocalAccounts {
    /// The user record's name for `uid`, or nil.
    public static func userName(uid: uid_t) -> String? {
        if case let .found(name) = lookupUser(uid: uid) { return name }
        return nil
    }

    /// The record name `getpwnam_r` returns for `name`, or nil when nothing
    /// resolves. Directory name lookups are case-insensitive and follow record
    /// aliases, so this can differ from `name` (`"ROOT"` answers `root`).
    public static func canonicalUserName(_ name: String) -> String? {
        if case let .found(canonical) = lookupUser(named: name) { return canonical }
        return nil
    }

    /// Whether a user named EXACTLY `name` resolves: `getpwnam_r` must return a
    /// record whose `pw_name` is byte-for-byte `name`. A case or alias match does
    /// not count, because break-glass entries are compared exactly against the
    /// authenticating account's canonical name, so such an entry never matches.
    /// A name containing U+0000 never resolves: the C lookup would read it only
    /// up to the NUL (`pam_serberus` refuses such an entry the same way).
    public static func userExists(_ name: String) -> Bool {
        guard !name.contains("\0"), let canonical = canonicalUserName(name) else { return false }
        return namesMatchExactly(canonical, name)
    }

    /// Byte-for-byte name equality. Swift `==` on `String` uses canonical
    /// Unicode equivalence; account-name matching here, like `pam_serberus`'s,
    /// compares the exact bytes.
    public static func namesMatchExactly(_ lhs: String, _ rhs: String) -> Bool {
        lhs.utf8.elementsEqual(rhs.utf8)
    }

    /// `getpwnam_r(name)`, keeping "found nothing" apart from "the lookup
    /// failed". Neither proves an account is gone: Libinfo also answers "found
    /// nothing" when a directory node is unreachable.
    public static func lookupUser(named name: String) -> AccountLookup {
        passwdLookup { pwd, buffer, size, result in
            getpwnam_r(name, &pwd, buffer, size, &result)
        }
    }

    /// `getpwuid_r(uid)`, with the same three outcomes as ``lookupUser(named:)``.
    public static func lookupUser(uid: uid_t) -> AccountLookup {
        passwdLookup { pwd, buffer, size, result in
            getpwuid_r(uid, &pwd, buffer, size, &result)
        }
    }

    /// The gid of the group named `name`, or nil when it does not resolve.
    public static func groupID(_ name: String) -> gid_t? {
        var group = Darwin.group()
        var result: UnsafeMutablePointer<Darwin.group>?
        var size = 4096
        while size <= 1 << 20 {
            var buffer = [CChar](repeating: 0, count: size)
            let status = getgrnam_r(name, &group, &buffer, size, &result)
            if status == ERANGE { size *= 4; continue }
            guard status == 0, result != nil else { return nil }
            return group.gr_gid
        }
        return nil
    }

    /// Whether a group named `name` resolves.
    public static func groupExists(_ name: String) -> Bool { groupID(name) != nil }

    /// A group lookup for break-glass: absent, present with no members, or
    /// present with at least one (``groupHasMembers(group:listed:gid:probes:)``).
    public enum GroupMembers: Sendable, Equatable {
        case notFound
        case empty
        case hasMembers
    }

    /// The directory lookups behind a group's break-glass membership. The
    /// defaults are production; tests inject their own so the answer does not
    /// depend on the host's accounts. Mirrors `serberus_group_probes` in
    /// `pam_config.h`.
    public struct GroupProbes: Sendable {
        /// An account whose canonical name is exactly the given name exists.
        public var userExists: @Sendable (String) -> Bool
        /// A GroupMembers GeneratedUID of the named group names an existing account.
        public var generatedUIDMember: @Sendable (String) -> Bool
        /// Some account's primary group is the given gid.
        public var primaryGroupInUse: @Sendable (gid_t) -> Bool

        public init(
            userExists: @escaping @Sendable (String) -> Bool = { LocalAccounts.userExists($0) },
            generatedUIDMember: @escaping @Sendable (String) -> Bool = { LocalAccounts.generatedUIDMemberExists(group: $0) },
            primaryGroupInUse: @escaping @Sendable (gid_t) -> Bool = { LocalAccounts.primaryGroupInUse($0) }
        ) {
            self.userExists = userExists
            self.generatedUIDMember = generatedUIDMember
            self.primaryGroupInUse = primaryGroupInUse
        }
    }

    /// `getgrnam_r(name)` classified by ``groupHasMembers(group:listed:gid:probes:)``.
    /// A name containing U+0000 is not looked up at all.
    public static func groupMembers(_ name: String, probes: GroupProbes = GroupProbes()) -> GroupMembers {
        guard !name.isEmpty, !name.contains("\0") else { return .notFound }
        var group = Darwin.group()
        var result: UnsafeMutablePointer<Darwin.group>?
        var size = 4096
        while size <= 1 << 20 {
            var buffer = [CChar](repeating: 0, count: size)
            let status = getgrnam_r(name, &group, &buffer, size, &result)
            if status == ERANGE { size *= 4; continue }
            guard status == 0, result != nil else { return .notFound }
            // gr_mem and gr_name point into `buffer`: copy them while it is alive.
            var listed: [String] = []
            if var cursor = group.gr_mem {
                while let member = cursor.pointee {
                    listed.append(String(cString: member))
                    cursor += 1
                }
            }
            let canonical = group.gr_name.map { String(cString: $0) } ?? name
            return groupHasMembers(group: canonical, listed: listed, gid: group.gr_gid, probes: probes)
                ? .hasMembers : .empty
        }
        return .notFound
    }

    /// The break-glass definition of a group with members, identical to
    /// `serberus_config_group_has_members` in `pam_config.c` and
    /// `serberus_pam_group_resolves` in `pam-lib.sh`. A member is any of:
    /// - a non-empty name in its member list (`gr_mem`, which is what
    ///   `dscacheutil` prints as `users:`) that is exactly an existing
    ///   account's name;
    /// - a GroupMembers GeneratedUID of the group that resolves to an existing
    ///   account;
    /// - an account whose primary group it is.
    ///
    /// A deleted account's name left behind in the group does not count, and
    /// nested groups do not count.
    public static func groupHasMembers(
        group: String, listed: [String], gid: gid_t, probes: GroupProbes
    ) -> Bool {
        if listed.contains(where: { !$0.isEmpty && probes.userExists($0) }) { return true }
        if probes.generatedUIDMember(group) { return true }
        return probes.primaryGroupInUse(gid)
    }

    /// Whether any value of the Open Directory `GroupMembers` attribute of the
    /// group named `group` passes ``generatedUIDNamesUser(_:)``. `getgrnam_r`
    /// reports only the GroupMembership names, and some tools record a member
    /// by GeneratedUID alone.
    public static func generatedUIDMemberExists(group: String) -> Bool {
        guard !group.isEmpty, !group.contains("\0"),
              let node = try? ODNode(session: ODSession.default(), type: ODNodeType(kODNodeTypeAuthentication)),
              let record = try? node.record(withRecordType: kODRecordTypeGroups, name: group,
                                            attributes: [kODAttributeTypeGroupMembers]),
              let values = try? record.values(forAttribute: kODAttributeTypeGroupMembers) else { return false }
        return values.contains { value in
            guard let text = value as? String else { return false }
            return generatedUIDNamesUser(text)
        }
    }

    /// Whether the 16 bytes at `uuid` are a GeneratedUID that `mbr_uuid_to_id`
    /// maps to the root USER (uid 0). A group, any other user, or a UUID that
    /// doesn't resolve is not.
    static func isRootUser(uuid: UnsafePointer<UInt8>) -> Bool {
        guard let api = Membership.api else { return false }
        var id: id_t = .max
        var type: Int32 = -1
        guard api.uuidToID(uuid, &id, &type) == 0 else { return false }
        return type == Membership.idTypeUID && id == 0
    }

    /// Whether `uuid` is a GeneratedUID that `mbr_uuid_to_id` maps to a USER id
    /// for which `getpwuid_r` finds an account. A group's UUID, an unparseable
    /// string, or a uid with no account does not count.
    public static func generatedUIDNamesUser(_ uuid: String) -> Bool {
        guard let parsed = UUID(uuidString: uuid), let api = Membership.api else { return false }
        var bytes = parsed.uuid
        var id: id_t = 0
        var type: Int32 = -1
        let status = withUnsafeBytes(of: &bytes) { raw in
            api.uuidToID(raw.bindMemory(to: UInt8.self).baseAddress!, &id, &type)
        }
        guard status == 0, type == Membership.idTypeUID else { return false }
        if case .found = lookupUser(uid: id) { return true }
        return false
    }

    /// Upper bound on the accounts ``primaryGroupInUse(_:)`` reads; the same as
    /// `SERBERUS_PRIMARY_GID_SCAN_MAX` in `pam_config.c`.
    static let primaryGroupScanLimit = 100_000

    /// `getpwent` iterates one process-wide cursor, so scans are serialized.
    private static let enumerationLock = NSLock()

    /// Whether an account the directory search policy enumerates (`getpwent`,
    /// as `pam_config.c` does) has `gid` as its primary group. Reads at most
    /// ``primaryGroupScanLimit`` entries. A gid above `Int32.max` never
    /// matches: `dscacheutil` prints it negative and the installer preflight
    /// skips it (nobody, nogroup).
    public static func primaryGroupInUse(_ gid: gid_t) -> Bool {
        guard gid <= gid_t(Int32.max) else { return false }
        enumerationLock.lock()
        defer { enumerationLock.unlock() }
        setpwent()
        defer { endpwent() }
        var scanned = 0
        while scanned < primaryGroupScanLimit, let entry = getpwent() {
            if entry.pointee.pw_gid == gid { return true }
            scanned += 1
        }
        return false
    }

    /// The `GeneratedUID` of the account with `uid`, uppercased, or nil when no
    /// account resolves. `mbr_uid_to_uuid` answers a uid with no record with a
    /// synthesized `FFFFEEEE-DDDD-CCCC-BBBB-AAAA…` value; that is not an account's
    /// GeneratedUID and is reported as nil.
    public static func generatedUID(uid: uid_t) -> String? {
        guard let api = Membership.api else { return nil }
        var bytes = [UInt8](repeating: 0, count: 16)
        guard api.uidToUUID(uid, &bytes) == 0 else { return nil }
        let text = UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                               bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
            .uuidString.uppercased()
        return isSynthesizedGeneratedUID(text) ? nil : text
    }

    /// Whether `uuid` is the compatibility UUID membership APIs synthesize for
    /// an id with no directory record.
    static func isSynthesizedGeneratedUID(_ uuid: String) -> Bool {
        uuid.uppercased().hasPrefix("FFFFEEEE-DDDD-CCCC-BBBB-AAAA")
    }

    /// Whether `uid` is a member of `groupName` — including nested groups and
    /// primary-group membership (`mbr_check_membership`, the same check
    /// `pam_serberus` uses for `pamBypass.groups`). nil when either side does
    /// not resolve or the check itself fails.
    public static func isMember(uid: uid_t, ofGroup groupName: String) -> Bool? {
        guard let gid = groupID(groupName), let api = Membership.api else { return nil }
        var userUUID = [UInt8](repeating: 0, count: 16)
        var groupUUID = [UInt8](repeating: 0, count: 16)
        guard api.uidToUUID(uid, &userUUID) == 0, api.gidToUUID(gid, &groupUUID) == 0 else { return nil }
        var isMember: Int32 = 0
        guard api.checkMembership(&userUUID, &groupUUID, &isMember) == 0 else { return nil }
        return isMember != 0
    }

    /// `<membership.h>` is not part of the Swift Darwin module, so the four
    /// libSystem entry points are resolved once with `dlsym`.
    private struct Membership: @unchecked Sendable {
        typealias UIDToUUID = @convention(c) (uid_t, UnsafeMutablePointer<UInt8>) -> Int32
        typealias GIDToUUID = @convention(c) (gid_t, UnsafeMutablePointer<UInt8>) -> Int32
        typealias Check = @convention(c) (UnsafePointer<UInt8>, UnsafePointer<UInt8>, UnsafeMutablePointer<Int32>) -> Int32
        typealias UUIDToID = @convention(c) (UnsafePointer<UInt8>, UnsafeMutablePointer<id_t>, UnsafeMutablePointer<Int32>) -> Int32
        /// `ID_TYPE_UID` in `<membership.h>`.
        static let idTypeUID: Int32 = 0
        let uidToUUID: UIDToUUID
        let gidToUUID: GIDToUUID
        let checkMembership: Check
        let uuidToID: UUIDToID

        static let api: Membership? = {
            let handle = UnsafeMutableRawPointer(bitPattern: -2) // RTLD_DEFAULT
            guard let uid = dlsym(handle, "mbr_uid_to_uuid"),
                  let gid = dlsym(handle, "mbr_gid_to_uuid"),
                  let check = dlsym(handle, "mbr_check_membership"),
                  let toID = dlsym(handle, "mbr_uuid_to_id") else { return nil }
            return Membership(uidToUUID: unsafeBitCast(uid, to: UIDToUUID.self),
                              gidToUUID: unsafeBitCast(gid, to: GIDToUUID.self),
                              checkMembership: unsafeBitCast(check, to: Check.self),
                              uuidToID: unsafeBitCast(toID, to: UUIDToID.self))
        }()
    }

    private static func passwdLookup(
        _ lookup: (inout passwd, UnsafeMutablePointer<CChar>, Int, inout UnsafeMutablePointer<passwd>?) -> Int32
    ) -> AccountLookup {
        var pwd = passwd()
        var result: UnsafeMutablePointer<passwd>?
        var size = 4096
        while size <= 1 << 20 {
            var buffer = [CChar](repeating: 0, count: size)
            let status = buffer.withUnsafeMutableBufferPointer { raw in
                lookup(&pwd, raw.baseAddress!, size, &result)
            }
            if status == ERANGE { size *= 4; continue }
            guard status == 0 else { return .failed }
            guard result != nil, let name = pwd.pw_name else { return .notFound }
            return .found(String(cString: name))
        }
        return .failed
    }
}

/// One passwd lookup's outcome.
public enum AccountLookup: Sendable, Equatable {
    /// A record resolved; its canonical `pw_name`.
    case found(String)
    /// The lookup answered, without error, that it found nothing.
    case notFound
    /// The lookup itself failed.
    case failed
}

// MARK: - JIT account identity (deleted, renamed, or unreachable)

/// The local directory node's answer about one user record.
public enum LocalNodeLookup: Sendable, Equatable {
    case present
    case absent
    /// The query failed, timed out, or could not be asked.
    case failed
}

/// Queries the LOCAL directory node (`/Local/Default`) directly. A record found
/// there exists whatever the network directories say. Injectable for tests.
public protocol LocalDirectoryProbing: Sendable {
    func userRecord(named name: String) async -> LocalNodeLookup
    func userRecord(uid: uid_t) async -> LocalNodeLookup
    /// Whether the directory search policy includes any node besides the local
    /// ones, so accounts may live on a network directory. nil when unknown.
    func networkDirectoryConfigured() async -> Bool?
}

/// Production ``LocalDirectoryProbing`` backed by `/usr/bin/dscl`, bounded by
/// ``ProcessCommandRunner``'s timeout.
public struct DSCLLocalDirectoryProbe: LocalDirectoryProbing {
    private let dscl: String

    public init(dscl: String = "/usr/bin/dscl") { self.dscl = dscl }

    public func userRecord(named name: String) async -> LocalNodeLookup {
        // The name becomes part of a record path, so one that could name a
        // different path is never asked about.
        guard !name.isEmpty, !name.contains("/"), name != ".", name != ".." else { return .failed }
        guard let result = try? await ProcessCommandRunner.execute(
            path: dscl, arguments: [".", "-read", "/Users/\(name)", "RecordName"],
            timeout: ProcessCommandRunner.defaultTimeout), !result.timedOut else { return .failed }
        if result.status == 0 { return .present }
        return Self.isRecordNotFound(status: result.status, output: result.stdout + result.stderr) ? .absent : .failed
    }

    public func userRecord(uid: uid_t) async -> LocalNodeLookup {
        guard let result = try? await ProcessCommandRunner.execute(
            path: dscl, arguments: [".", "-search", "/Users", "UniqueID", String(uid)]),
              result.status == 0 else { return .failed }
        return result.stdout.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? .absent : .present
    }

    public func networkDirectoryConfigured() async -> Bool? {
        guard let result = try? await ProcessCommandRunner.execute(
            path: dscl, arguments: ["/Search", "-read", "/", "CSPSearchPath"]),
              result.status == 0 else { return nil }
        return Self.searchPathHasNetworkNode(result.stdout)
    }

    /// `dscl` reports a missing record as `DS Error: -14136 (eDSRecordNotFound)`
    /// and a non-zero exit. Any other failure is not absence.
    static func isRecordNotFound(status: Int32, output: String) -> Bool {
        status != 0 && output.contains("eDSRecordNotFound")
    }

    /// Parses `dscl /Search -read / CSPSearchPath`, which prints one node on the
    /// same line or one node per following line. nil when there is no such key.
    static func searchPathHasNetworkNode(_ output: String) -> Bool? {
        guard let range = output.range(of: "CSPSearchPath:") else { return nil }
        let nodes = output[range.upperBound...]
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        guard !nodes.isEmpty else { return nil }
        return nodes.contains { !$0.hasPrefix("/Local/") && !$0.hasPrefix("/BSD/") }
    }
}

/// What became of the account a JIT grant row names, once `dseditgroup` could
/// no longer find its record.
public enum JITAccountIdentity: Sendable, Equatable {
    /// The account still resolves under the row's name.
    case present
    /// The row's uid now resolves to this other name: the account was renamed.
    case renamed(to: String)
    /// The row's uid now resolves to this other name, but that account's
    /// GeneratedUID differs from the one recorded at promotion: the uid was
    /// reused by a NEW account. The promoted account is gone; the new one was
    /// never promoted by Serberus and must not be demoted.
    case uidReused(by: String)
    /// Confirmed deleted: nothing resolves by name or uid, the local node has
    /// no such record, and no network directory could be hiding it.
    case gone
    /// Could not be decided (a failed lookup, a directory outage, or a possible
    /// network account). The grant stays active and the demotion is retried.
    case undetermined(String)
}

/// Decides ``JITAccountIdentity`` for a JIT grant row. Injectable for tests.
public protocol JITAccountResolving: Sendable {
    /// `uid` is nil for a row whose uid cannot be trusted (an unverifiable row);
    /// a rename can then not be detected, and absence needs the name alone.
    func identify(user: String, uid: uid_t?) async -> JITAccountIdentity
    /// As ``identify(user:uid:)``, with the GeneratedUID recorded when the
    /// account was promoted (nil for rows written before it was recorded), so a
    /// uid reused by a new account is told apart from a rename.
    func identify(user: String, uid: uid_t?, generatedUID: String?) async -> JITAccountIdentity
}

public extension JITAccountResolving {
    /// Resolvers that do not look at GeneratedUIDs answer as before.
    func identify(user: String, uid: uid_t?, generatedUID: String?) async -> JITAccountIdentity {
        await identify(user: user, uid: uid)
    }
}

/// Production ``JITAccountResolving``: `getpwuid_r` / `getpwnam_r` plus the
/// local directory node. Fails closed — only a positive answer from every
/// source retires a row, because a row retired while the user is still in
/// `admin` leaves a permanent admin nothing will ever demote.
public struct DirectoryJITAccountResolver: JITAccountResolving {
    private let byName: @Sendable (String) -> AccountLookup
    private let byUID: @Sendable (uid_t) -> AccountLookup
    private let localNode: LocalDirectoryProbing
    private let generatedUIDForUID: @Sendable (uid_t) -> String?

    public init(
        byName: @escaping @Sendable (String) -> AccountLookup = { LocalAccounts.lookupUser(named: $0) },
        byUID: @escaping @Sendable (uid_t) -> AccountLookup = { LocalAccounts.lookupUser(uid: $0) },
        localNode: LocalDirectoryProbing = DSCLLocalDirectoryProbe(),
        generatedUIDForUID: @escaping @Sendable (uid_t) -> String? = { LocalAccounts.generatedUID(uid: $0) }
    ) {
        self.byName = byName
        self.byUID = byUID
        self.localNode = localNode
        self.generatedUIDForUID = generatedUIDForUID
    }

    public func identify(user: String, uid: uid_t?) async -> JITAccountIdentity {
        await identify(user: user, uid: uid, generatedUID: nil)
    }

    public func identify(user: String, uid: uid_t?, generatedUID: String?) async -> JITAccountIdentity {
        // The uid first: a renamed account keeps it.
        if let uid {
            switch byUID(uid) {
            case let .found(name):
                if LocalAccounts.namesMatchExactly(name, user) { return .present }
                // Another name holds the uid. With a GeneratedUID recorded at
                // promotion, a rename keeps it and a reused uid does not. Without
                // one (an older row), this is read as a rename, as before.
                guard let recorded = generatedUID else { return .renamed(to: name) }
                guard let current = generatedUIDForUID(uid) else {
                    return .undetermined("uid \(uid) now resolves to \(name) but its GeneratedUID could not be read")
                }
                return current.caseInsensitiveCompare(recorded) == .orderedSame
                    ? .renamed(to: name) : .uidReused(by: name)
            case .failed:
                return .undetermined("uid \(uid) lookup failed")
            case .notFound:
                break
            }
        }
        switch byName(user) {
        case .found: return .present
        case .failed: return .undetermined("name lookup failed")
        case .notFound: break
        }
        switch await localNode.userRecord(named: user) {
        case .absent: break
        case .present: return .undetermined("the local directory node still has a record named \(user)")
        case .failed: return .undetermined("the local directory node could not be queried by name")
        }
        if let uid {
            switch await localNode.userRecord(uid: uid) {
            case .absent: break
            case .present: return .undetermined("the local directory node still has a record with uid \(uid)")
            case .failed: return .undetermined("the local directory node could not be queried by uid")
            }
        }
        switch await localNode.networkDirectoryConfigured() {
        case false?: return .gone
        case true?: return .undetermined("a network directory is configured; the account may be on an unreachable node")
        case nil: return .undetermined("the directory search policy could not be read")
        }
    }
}

// MARK: - Break-glass (pamBypass) resolvability

/// Resolves `pamBypass` entries against the local directory. Injectable so
/// daemon tests do not depend on the host's accounts.
public protocol BypassResolving: Sendable {
    /// Whether a user named exactly `name` exists (see ``LocalAccounts/userExists(_:)``).
    func userResolves(_ name: String) -> Bool
    /// Whether a group named `name` exists AND has at least one member that is
    /// an existing account (``LocalAccounts/groupHasMembers(group:listed:gid:probes:)``).
    func groupResolves(_ name: String) -> Bool
    /// Whether `name` is a group that exists but has no members. Used only to
    /// explain why such an entry counts as unresolved.
    func groupIsEmpty(_ name: String) -> Bool
    /// The account name the directory returns for `name` when it resolves to a
    /// DIFFERENT spelling (another case, or an alias), else nil. Used only to
    /// explain why such an entry counts as unresolved.
    func mismatchedUserName(_ name: String) -> String?
}

public extension BypassResolving {
    func mismatchedUserName(_ name: String) -> String? { nil }
    func groupIsEmpty(_ name: String) -> Bool { false }
}

/// Treats every entry as resolvable. The ``DaemonController`` /
/// ``StartupCoordinator`` default, so unit tests are independent of the host's
/// accounts; production wires ``LocalBypassResolver``.
public struct AssumeResolvableBypass: BypassResolving {
    public init() {}
    public func userResolves(_ name: String) -> Bool { true }
    public func groupResolves(_ name: String) -> Bool { true }
}

/// Production: `getpwnam_r` / `getgrnam_r`. A user entry resolves only when
/// the returned `pw_name` equals the entry exactly; groups resolve by any name
/// the directory accepts, because group break-glass is a membership check, but
/// only when the group has at least one member that is an existing account: a
/// group that is empty, or lists only deleted accounts, bypasses nobody (the
/// same rule as `pam_config.c` and the installer preflight). An entry
/// containing U+0000 never resolves.
public struct LocalBypassResolver: BypassResolving {
    public init() {}
    public func userResolves(_ name: String) -> Bool { LocalAccounts.userExists(name) }
    public func groupResolves(_ name: String) -> Bool { LocalAccounts.groupMembers(name) == .hasMembers }
    public func groupIsEmpty(_ name: String) -> Bool { LocalAccounts.groupMembers(name) == .empty }
    public func mismatchedUserName(_ name: String) -> String? {
        guard let canonical = LocalAccounts.canonicalUserName(name),
              !LocalAccounts.namesMatchExactly(canonical, name) else { return nil }
        return canonical
    }
}

/// Break-glass resolvability: whether the `pamBypass` entries of an enforcing
/// config name real local users or groups.
public enum BypassResolution {
    /// An ENFORCING config whose `pamBypass` names entries, NONE of which
    /// resolves to a real local user or group — i.e. enforcement with zero
    /// working break-glass (a typo'd profile). Reported as
    /// `degraded(bypass_unresolvable)`. A DELIVERED config in this state is also
    /// not enforceable: ``EffectiveConfigResolver`` treats it exactly like an
    /// empty `pamBypass` (falls back to last-known-good, never snapshots it).
    ///
    /// An EMPTY bypass is not this condition: an enforcing config can only carry
    /// one as the deliberate fail-closed config, which reports `config_missing`.
    public static func isUnresolvable(_ config: SerberusConfig, resolver: BypassResolving) -> Bool {
        guard config.daemonEnabled, config.enforcementMode == .enforce else { return false }
        let bypass = config.pamBypass
        guard !(bypass.users.isEmpty && bypass.groups.isEmpty) else { return false }
        if bypass.users.contains(where: resolver.userResolves) { return false }
        if bypass.groups.contains(where: resolver.groupResolves) { return false }
        return true
    }

    /// Every `pamBypass` entry of an enforcing config that does not resolve,
    /// as `user <name>` / `group <name>`, so each can be logged even when
    /// others resolve (a partial typo is otherwise invisible). A user entry that
    /// the directory answers under another spelling says so, and so does a
    /// group that exists but has no members, because either entry would
    /// otherwise look correct to whoever reads the profile.
    public static func unresolvedEntries(_ config: SerberusConfig, resolver: BypassResolving) -> [String] {
        guard config.daemonEnabled, config.enforcementMode == .enforce else { return [] }
        let users = config.pamBypass.users.filter { !resolver.userResolves($0) }.map { name -> String in
            guard let canonical = resolver.mismatchedUserName(name) else { return "user \(name)" }
            return "user \(name) (resolves to '\(canonical)'; entries are matched exactly)"
        }
        let groups = config.pamBypass.groups.filter { !resolver.groupResolves($0) }.map { name -> String in
            resolver.groupIsEmpty(name) ? "group \(name) (group \(name) has no members)" : "group \(name)"
        }
        return users + groups
    }
}
