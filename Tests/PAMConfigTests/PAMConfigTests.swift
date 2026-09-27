import CoreFoundation
import Foundation
import Testing

/// Exercises the PAM module's pure C config reader (`pam_config.c`) — the
/// break-glass logic that decides whether `pam_serberus.so` intercepts sudo
/// at all. The managed plist path is an explicit parameter, so every test
/// points it at temp fixtures. Values seeded into the real config domain's
/// unmanaged CFPreferences layer must be ignored: only the managed plist (or
/// the daemon's snapshot) is policy.
///
/// Fail-closed contract under test (must stay byte-identical to
/// `ManagedPreferencesReader.readConfig()`): absent/invalid config means
/// enforcementMode "enforce" with an EMPTY bypass set.
@Suite("pam_config break-glass reader")
struct PAMConfigTests {

    /// The readers only honor files owned by the required owner (root in
    /// production). Fixtures here are owned by the test user, so point the
    /// owner check at it. Every suite sets the same value, so parallel tests
    /// can't disagree about it.
    init() {
        serberus_config_set_required_owner_uid_for_testing(getuid())
    }

    // MARK: helpers

    /// Writes `object` as an XML plist to a unique temp path and returns it.
    private func writePlist(_ object: Any) throws -> String {
        let url = try uniqueFixtureURL()
        let data = try PropertyListSerialization.data(
            fromPropertyList: object, format: .xml, options: 0)
        try data.write(to: url)
        return url.path
    }

    /// Writes raw bytes (a deliberately unparseable "plist") and returns the path.
    private func writeGarbage(_ bytes: Data) throws -> String {
        let url = try uniqueFixtureURL()
        try bytes.write(to: url)
        return url.path
    }

    private func uniqueFixtureURL() throws -> URL {
        try uniqueFixtureDirectory().appendingPathComponent("com.herojoneslabs.serberus.config.plist")
    }

    private func uniqueFixtureDirectory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("pam-config-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    /// Writes a last-known-good snapshot fixture (same key shape as the managed
    /// domain — that parity is the whole point) and returns its path.
    private func writeLKG(_ object: Any) throws -> String {
        let url = try uniqueFixtureDirectory()
            .appendingPathComponent("last-known-good-config.plist")
        let data = try PropertyListSerialization.data(
            fromPropertyList: object, format: .xml, options: 0)
        try data.write(to: url)
        return url.path
    }

    /// Writes an EXISTING-but-unparseable snapshot (truncated write, hand-edit).
    private func writeCorruptLKG() throws -> String {
        let url = try uniqueFixtureDirectory()
            .appendingPathComponent("last-known-good-config.plist")
        try Data("<?xml version=\"1.0\"?><plist><dict><key>enforcem".utf8).write(to: url)
        return url.path
    }

    /// The real config domain. pam_config.c used to fall back to its unforced
    /// CFPreferences layers; tests seed values here to prove they're ignored.
    private let realConfigDomain = "com.herojoneslabs.serberus.config"

    private let missingPlistPath = "/nonexistent/serberus-pam-config-tests/config.plist"
    private let missingLKGPath = "/nonexistent/serberus-pam-config-tests/last-known-good-config.plist"

    private func readMode(path: String?) -> String {
        var buffer = [CChar](repeating: 0, count: 32)
        serberus_config_copy_enforcement_mode(path, &buffer, buffer.count)
        return buffer.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
    }

    private func bypassArray(_ innerKey: String, path: String?) -> [String]? {
        guard let array = serberus_config_copy_bypass_array(
            path, innerKey as CFString) else { return nil }
        return (array as NSArray) as? [String]
    }

    private func userInBypass(_ user: String, path: String?) -> Bool {
        serberus_config_user_in_bypass_users(path, user)
    }

    private func isPresent(path: String?) -> Bool {
        serberus_config_is_present(path)
    }

    private func isEnforceable(path: String?) -> Bool {
        serberus_config_is_enforceable(path)
    }

    /// The C source-resolution verdict: managed / last-known-good / bootstrap.
    /// Fixture names such as "breakglass" don't exist on the test Mac, so the
    /// resolver treats every name as real except those prefixed "missing-".
    private func resolveSource(path: String?, lkg: String?) -> Int32 {
        serberus_config_resolve_source_with(path, lkg) { name, _ in
            guard let name else { return false }
            return !String(cString: name).hasPrefix("missing-")
        }
    }

    /// Seeds one key into the real config domain's unforced (user) layer for
    /// the duration of `body`, then removes it again, so nothing outlives the run.
    private func withUnmanagedPreference(key: String, value: CFPropertyList,
                                         body: () -> Void) {
        let domain = realConfigDomain
        CFPreferencesSetAppValue(key as CFString, value, domain as CFString)
        CFPreferencesAppSynchronize(domain as CFString)
        defer {
            CFPreferencesSetAppValue(key as CFString, nil, domain as CFString)
            CFPreferencesAppSynchronize(domain as CFString)
        }
        body()
    }

    /// Reads a string config value; nil when the C reader reports absent (key
    /// missing, empty, or wrong type).
    private func readString(_ key: String, path: String?) -> String? {
        var buffer = [CChar](repeating: 0, count: 1024)
        let present = serberus_config_copy_string(
            path, key as CFString, &buffer, buffer.count)
        guard present else { return nil }
        return buffer.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
    }

    // MARK: custom sudo messages (serberus_config_copy_string)

    @Test("managed plist supplies custom sudo deny/allow messages")
    func customSudoMessages() throws {
        let path = try writePlist([
            "enforcementMode": "enforce",
            "sudoDenyMessage": "Blocked: {command}. Ping #it-help.",
            "sudoAllowMessage": "Running {command} under IT policy.",
        ])
        #expect(readString("sudoDenyMessage", path: path)
            == "Blocked: {command}. Ping #it-help.")
        #expect(readString("sudoAllowMessage", path: path)
            == "Running {command} under IT policy.")
    }

    @Test("an absent message key reports absent (nil ⇒ caller keeps its default)")
    func absentMessageIsNil() throws {
        let path = try writePlist(["enforcementMode": "enforce"])
        #expect(readString("sudoDenyMessage", path: path) == nil)
        #expect(readString("sudoAllowMessage", path: path) == nil)
    }

    @Test("an empty-string message is treated as absent (no blank line emitted)")
    func emptyMessageIsAbsent() throws {
        let path = try writePlist(["sudoDenyMessage": ""])
        #expect(readString("sudoDenyMessage", path: path) == nil)
    }

    @Test("a non-string message value is absent (fail safe to the default)")
    func nonStringMessageIsAbsent() throws {
        let path = try writePlist(["sudoDenyMessage": 42])
        #expect(readString("sudoDenyMessage", path: path) == nil)
    }

    @Test("messages are read from the last-known-good snapshot too (same reader, any source file)")
    func messageReadFromLKGSnapshot() throws {
        // pam passes the resolved source path (managed OR LKG) to the reader; a
        // snapshot that carries the key must be honored just like the managed plist.
        let lkg = try writeLKG([
            "enforcementMode": "enforce",
            "pamBypass": ["groups": ["admin"], "users": [String]()],
            "sudoDenyMessage": "Denied (from LKG): {command}",
        ])
        #expect(readString("sudoDenyMessage", path: lkg)
            == "Denied (from LKG): {command}")
    }

    // MARK: managed plist present

    @Test("managed plist supplies enforcementMode and pamBypass users")
    func managedPlistUsers() throws {
        let path = try writePlist([
            "enforcementMode": "monitor",
            "pamBypass": ["users": ["breakglass-admin"], "groups": []],
        ])
        #expect(readMode(path: path) == "monitor")
        #expect(bypassArray("users", path: path) == ["breakglass-admin"])
        #expect(userInBypass("breakglass-admin", path: path))
        #expect(!userInBypass("someone-else", path: path))
    }

    @Test("managed plist supplies pamBypass groups")
    func managedPlistGroups() throws {
        let path = try writePlist([
            "enforcementMode": "audit",
            "pamBypass": ["groups": ["admin", "serberus-jit"]],
        ])
        #expect(readMode(path: path) == "audit")
        #expect(bypassArray("groups", path: path) == ["admin", "serberus-jit"])
        // No users key at all -> nil array, no user bypass.
        #expect(bypassArray("users", path: path) == nil)
        #expect(!userInBypass("breakglass-admin", path: path))
    }

    @Test("managed plist with both populated bypass arrays")
    func managedPlistBoth() throws {
        let path = try writePlist([
            "pamBypass": [
                "users": ["breakglass-admin", "tuser"],
                "groups": ["admin"],
            ],
        ])
        #expect(bypassArray("users", path: path) == ["breakglass-admin", "tuser"])
        #expect(bypassArray("groups", path: path) == ["admin"])
        #expect(userInBypass("tuser", path: path))
    }

    @Test("managed plist with empty bypass arrays bypasses no one")
    func managedPlistEmptyArrays() throws {
        let path = try writePlist([
            "enforcementMode": "enforce",
            "pamBypass": ["users": [], "groups": []],
        ])
        #expect(readMode(path: path) == "enforce")
        #expect(bypassArray("users", path: path) == [])
        #expect(bypassArray("groups", path: path) == [])
        #expect(!userInBypass("breakglass-admin", path: path))
    }

    // MARK: only the managed plist counts

    @Test("absent managed plist yields fail-closed defaults")
    func absentEverythingFailsClosed() {
        #expect(readMode(path: missingPlistPath) == "enforce")
        #expect(bypassArray("users", path: missingPlistPath) == nil)
        #expect(bypassArray("groups", path: missingPlistPath) == nil)
        #expect(!userInBypass("anyone", path: missingPlistPath))
    }

    @Test("an unmanaged enforcementMode can't weaken enforcement")
    func unmanagedModeIsIgnored() {
        withUnmanagedPreference(key: "enforcementMode", value: "audit" as CFString) {
            #expect(readMode(path: missingPlistPath) == "enforce")
        }
    }

    @Test("an unmanaged pamBypass grants no break-glass")
    func unmanagedBypassIsIgnored() {
        let bypass = ["users": ["breakglass-admin"], "groups": ["admin"]] as CFDictionary
        withUnmanagedPreference(key: "pamBypass", value: bypass) {
            #expect(bypassArray("users", path: missingPlistPath) == nil)
            #expect(bypassArray("groups", path: missingPlistPath) == nil)
            #expect(!userInBypass("breakglass-admin", path: missingPlistPath))
        }
    }

    // MARK: managed-layer precedence

    @Test("a managed value is read, whatever the unmanaged layer says")
    func managedKeyIsAuthoritative() throws {
        let path = try writePlist(["enforcementMode": "audit"])
        withUnmanagedPreference(key: "enforcementMode", value: "monitor" as CFString) {
            #expect(readMode(path: path) == "audit")
        }
    }

    @Test("a key absent from the managed plist takes the default, not an unmanaged value")
    func absentManagedKeyUsesDefault() throws {
        let path = try writePlist(["unrelatedKey": 1])
        withUnmanagedPreference(key: "enforcementMode", value: "monitor" as CFString) {
            #expect(readMode(path: path) == "enforce")
        }
    }

    @Test("a mistyped managed value fails closed instead of falling through")
    func mistypedManagedValueDoesNotFallThrough() throws {
        // Managed layer HAS the key but with the wrong type: the value is
        // authoritative and invalid -> enforce, never the weaker layer's value.
        let path = try writePlist(["enforcementMode": 42])
        withUnmanagedPreference(key: "enforcementMode", value: "monitor" as CFString) {
            #expect(readMode(path: path) == "enforce")
        }
    }

    // MARK: malformed / invalid input fails closed

    @Test("unparseable managed plist fails closed to the defaults")
    func garbagePlistFailsClosed() throws {
        let path = try writeGarbage(Data("this is not a property list".utf8))
        #expect(readMode(path: path) == "enforce")
        #expect(bypassArray("users", path: path) == nil)
        #expect(!userInBypass("anyone", path: path))
    }

    @Test("non-dictionary plist root is treated as absent")
    func nonDictionaryRootFailsClosed() throws {
        let path = try writePlist(["just", "an", "array"])
        #expect(readMode(path: path) == "enforce")
        #expect(bypassArray("groups", path: path) == nil)
    }

    @Test("wrong-typed values fail closed (parity with the Swift reader)")
    func wrongTypedValuesFailClosed() throws {
        // Mirrors ManagedPreferencesReaderTests.invalidValues.
        let path = try writePlist([
            "enforcementMode": 42,
            "pamBypass": "not-a-dict",
        ])
        #expect(readMode(path: path) == "enforce")
        #expect(bypassArray("users", path: path) == nil)
        #expect(bypassArray("groups", path: path) == nil)
        #expect(!userInBypass("anyone", path: path))
    }

    @Test("unknown enforcementMode string defaults to enforce")
    func unknownModeFailsClosed() throws {
        let path = try writePlist(["enforcementMode": "yolo"])
        #expect(readMode(path: path) == "enforce")
    }

    @Test("non-string bypass members are filtered out safely")
    func nonStringBypassMembersIgnored() throws {
        let path = try writePlist([
            "pamBypass": [
                "users": ["breakglass-admin", 42, true],
                "groups": ["admin", 7],
            ],
        ])
        #expect(bypassArray("users", path: path) == ["breakglass-admin"])
        #expect(bypassArray("groups", path: path) == ["admin"])
        #expect(userInBypass("breakglass-admin", path: path))
        #expect(!userInBypass("42", path: path))
    }

    // MARK: parity fixtures with ManagedPreferencesReader

    @Test("empty config parity: enforce + empty bypass, exactly like readConfig()")
    func emptyConfigParity() throws {
        // ManagedPreferencesReaderTests.emptyDomainDefaults expects
        // enforcementMode == .enforce and pamBypass == PAMBypass().
        let path = try writePlist([String: Any]())
        #expect(readMode(path: path) == "enforce")
        #expect(bypassArray("users", path: path) == nil)
        #expect(bypassArray("groups", path: path) == nil)
    }

    @Test("full config parity fixture matches the Swift reader's expectations")
    func fullConfigParity() throws {
        // Mirrors ManagedPreferencesReaderTests.fullConfig: audit mode,
        // groups [admin, serberus-jit], users [breakglass-admin].
        let path = try writePlist([
            "enforcementMode": "audit",
            "pamBypass": [
                "groups": ["admin", "serberus-jit"],
                "users": ["breakglass-admin"],
            ],
        ])
        #expect(readMode(path: path) == "audit")
        #expect(bypassArray("groups", path: path) == ["admin", "serberus-jit"])
        #expect(bypassArray("users", path: path) == ["breakglass-admin"])
        #expect(userInBypass("breakglass-admin", path: path))
    }

    // MARK: presence + enforceability (the safety condition, in C)

    @Test("configIsPresent parity: any delivered key counts, no keys does not")
    func configPresence() throws {
        let empty = try writePlist([String: Any]())
        #expect(!isPresent(path: empty))
        #expect(!isPresent(path: missingPlistPath))

        let delivered = try writePlist(["enforcementMode": "enforce"])
        #expect(isPresent(path: delivered))

        // A key set only in the unmanaged layer is not delivered config.
        withUnmanagedPreference(key: "pamBypass", value: ["groups": ["admin"]] as CFDictionary) {
            #expect(!isPresent(path: missingPlistPath))
        }
    }

    @Test("isEnforceable parity: enforce needs a break-glass, monitor/audit never do")
    func enforceability() throws {
        // enforce + empty bypass = the lockout config. NOT enforceable.
        let unsafe = try writePlist([
            "enforcementMode": "enforce",
            "pamBypass": ["users": [], "groups": []],
        ])
        #expect(!isEnforceable(path: unsafe))

        // Absent config also parses to enforce + no bypass -> not enforceable.
        #expect(!isEnforceable(path: missingPlistPath))

        // enforce + one bypass entry (either list) = enforceable.
        let withUser = try writePlist([
            "enforcementMode": "enforce",
            "pamBypass": ["users": ["breakglass"], "groups": []],
        ])
        #expect(isEnforceable(path: withUser))
        let withGroup = try writePlist([
            "enforcementMode": "enforce",
            "pamBypass": ["groups": ["admin"]],
        ])
        #expect(isEnforceable(path: withGroup))

        // monitor / audit deny nothing -> inherently safe, bypass irrelevant.
        for mode in ["monitor", "audit"] {
            let path = try writePlist(["enforcementMode": mode])
            #expect(isEnforceable(path: path))
        }

        // A non-string bypass member is filtered out and cannot make an
        // enforcing config look safe.
        let bogus = try writePlist([
            "enforcementMode": "enforce",
            "pamBypass": ["users": [42], "groups": [true]],
        ])
        #expect(!isEnforceable(path: bogus))
    }

    // MARK: config-source resolution (enrollment race / tamper contract)

    @Test("a present, enforceable managed config wins even when a snapshot exists")
    func managedSourceWins() throws {
        let managed = try writePlist([
            "enforcementMode": "enforce",
            "pamBypass": ["groups": ["admin"]],
        ])
        let lkg = try writeLKG([
            "enforcementMode": "enforce",
            "pamBypass": ["users": ["stale-breakglass"]],
        ])
        #expect(resolveSource(path: managed, lkg: lkg)
            == SERBERUS_CONFIG_SOURCE_MANAGED)
    }

    @Test("absent managed plist + existing snapshot -> last-known-good supplies break-glass")
    func lastKnownGoodSuppliesBypass() throws {
        // The snapshot's key shape IS the managed domain's, so the very same
        // readers parse it — that is the contract with the daemon's writer.
        let lkg = try writeLKG([
            "daemonEnabled": true,
            "enforcementMode": "enforce",
            "sudoCacheSeconds": 0,
            "promptTimeoutSeconds": 60,
            "pamBypass": ["groups": ["admin"], "users": ["breakglass"]],
            "sudoEnrollment": ["users": [], "idpGroups": [], "idpSource": "disabled"],
        ])

        #expect(resolveSource(path: missingPlistPath, lkg: lkg)
            == SERBERUS_CONFIG_SOURCE_LAST_KNOWN_GOOD)

        // pam_serberus reads the snapshot with NO composite fallback behind it.
        #expect(readMode(path: lkg) == "enforce")
        #expect(bypassArray("groups", path: lkg) == ["admin"])
        #expect(bypassArray("users", path: lkg) == ["breakglass"])
        #expect(userInBypass("breakglass", path: lkg))
        #expect(!userInBypass("someone-else", path: lkg))
        // Enforceable by construction — that is why falling back cannot lock anyone out.
        #expect(isEnforceable(path: lkg))
    }

    @Test("an enforcing config whose break-glass entries all fail to resolve falls back like an empty one")
    func unresolvableBypassFallsBack() throws {
        let typo = try writePlist([
            "enforcementMode": "enforce",
            "pamBypass": ["users": ["missing-breakglas"], "groups": ["missing-admins"]],
        ])
        // Still enforceable on paper (parity with SerberusConfig.isEnforceable)...
        #expect(isEnforceable(path: typo))
        // ...but it never governs: snapshot if one exists, bootstrap otherwise.
        let lkg = try writeLKG([
            "enforcementMode": "enforce",
            "pamBypass": ["users": ["breakglass"]],
        ])
        #expect(resolveSource(path: typo, lkg: lkg) == SERBERUS_CONFIG_SOURCE_LAST_KNOWN_GOOD)
        #expect(resolveSource(path: typo, lkg: missingLKGPath) == SERBERUS_CONFIG_SOURCE_BOOTSTRAP)

        // One resolvable entry is enough.
        let partial = try writePlist([
            "enforcementMode": "enforce",
            "pamBypass": ["users": ["missing-breakglas", "breakglass"]],
        ])
        #expect(resolveSource(path: partial, lkg: lkg) == SERBERUS_CONFIG_SOURCE_MANAGED)

        // Monitor never needs a resolvable break-glass.
        let monitor = try writePlist([
            "enforcementMode": "monitor",
            "pamBypass": ["users": ["missing-breakglas"]],
        ])
        #expect(resolveSource(path: monitor, lkg: lkg) == SERBERUS_CONFIG_SOURCE_MANAGED)
    }

    @Test("the production resolver finds real accounts and refuses unknown ones")
    func defaultResolver() {
        #expect(serberus_config_default_name_resolves("root", false))
        #expect(serberus_config_default_name_resolves("admin", true))
        #expect(!serberus_config_default_name_resolves("serberus-no-such-user-7f3a", false))
        #expect(!serberus_config_default_name_resolves("", false))
    }

    /// Calls serberus_config_group_has_members for a group named `group` with
    /// `names` as a NULL-terminated gr_mem list.
    private func groupHasMembers(_ names: [String], group: String = "fixture", gid: gid_t,
                                 probes: serberus_group_probes) -> Bool {
        var list: [UnsafeMutablePointer<CChar>?] = names.map { strdup($0) } + [nil]
        defer { list.forEach { free($0) } }
        var probes = probes
        return list.withUnsafeMutableBufferPointer { buffer in
            group.withCString { serberus_config_group_has_members($0, buffer.baseAddress, gid, &probes) }
        }
    }

    /// Fixture directory: accounts `breakglass` and `itadmin` exist (exact
    /// names only); group `uuidonly` has a GroupMembers GeneratedUID naming an
    /// account; gid 613 is some account's primary group.
    private static let fixtureProbes = serberus_group_probes(
        user_exists: { name in
            guard let name else { return false }
            return ["breakglass", "itadmin"].contains(String(cString: name))
        },
        generated_uid_member: { group in
            guard let group else { return false }
            return String(cString: group) == "uuidonly"
        },
        primary_gid_in_use: { $0 == 613 })

    /// A directory in which no account exists at all.
    private static let emptyProbes = serberus_group_probes(
        user_exists: { _ in false }, generated_uid_member: { _ in false }, primary_gid_in_use: { _ in false })

    @Test("group members: a listed name that is an existing account, a GroupMembers UUID that is one, or a primary-gid account")
    func groupHasMembersDefinition() {
        let probes = Self.fixtureProbes
        #expect(groupHasMembers(["breakglass"], gid: 610, probes: probes))
        #expect(groupHasMembers(["deleted-user", "itadmin"], gid: 610, probes: probes))
        #expect(!groupHasMembers([], gid: 611, probes: probes))
        #expect(!groupHasMembers([""], gid: 612, probes: probes))
        #expect(groupHasMembers([], gid: 613, probes: probes))
        #expect(groupHasMembers([], group: "uuidonly", gid: 614, probes: probes))
        // A deleted account's name left behind in the group is not a member.
        #expect(!groupHasMembers(["deleted-user"], gid: 615, probes: probes))
        // Names are exact: a case variant, or one with a space, is not the account.
        #expect(!groupHasMembers(["BreakGlass", " breakglass", "breakglass "], gid: 616, probes: probes))
        var none = probes
        #expect(!serberus_config_group_has_members("fixture", nil, 617, &none))
        #expect(!serberus_config_group_has_members("uuidonly", nil, 613, nil))
    }

    @Test("GeneratedUIDs resolve through mbr_uuid_to_id to an existing account only")
    func generatedUIDsNameUsers() {
        // root's compatibility UUID maps to uid 0, which exists.
        #expect(serberus_config_generated_uid_names_user("FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000000"))
        // A group's compatibility UUID maps to a gid, not a user.
        #expect(!serberus_config_generated_uid_names_user("ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000050"))
        #expect(!serberus_config_generated_uid_names_user("00000000-1111-2222-3333-444444444444"))
        #expect(!serberus_config_generated_uid_names_user("not-a-uuid"))
        #expect(!serberus_config_generated_uid_names_user(""))
        #expect(!serberus_config_generated_uid_names_user(nil))
        #expect(!serberus_config_group_generated_uid_member("serberus-no-such-group-7f3a"))
        #expect(!serberus_config_group_generated_uid_member(""))
    }

    @Test("the production probes find real accounts")
    func productionProbes() {
        #expect(serberus_config_user_exists("root"))
        #expect(!serberus_config_user_exists("ROOT"))
        #expect(!serberus_config_user_exists(" root"))
        #expect(!serberus_config_user_exists(""))
        var uid: uid_t = 99
        #expect(serberus_config_user_uid_exact("root", &uid) && uid == 0)
        uid = 99
        #expect(!serberus_config_user_uid_exact("serberus-no-such-user-7f3a", &uid) && uid == 99)
        // staff is every local user's primary group; asked twice, the second
        // answer comes from the per-process cache and must agree.
        #expect(serberus_config_primary_gid_in_use(20))
        #expect(serberus_config_primary_gid_in_use(20))
        // A gid above INT32_MAX never matches by primary group (nobody, nogroup).
        #expect(!serberus_config_primary_gid_in_use(gid_t(UInt32.max - 1)))
    }

    @Test("a group lookup is classified by the injected probes, whatever the host's members")
    func groupLookupWithInjectedProbes() {
        // admin exists on every Mac. With a directory in which no account
        // exists it has no members; with one in which its listed names do, it
        // has. Deterministic whatever the host's group actually holds.
        var empty = Self.emptyProbes
        var everyone = serberus_group_probes(
            user_exists: { _ in true }, generated_uid_member: { _ in true }, primary_gid_in_use: { _ in true })
        #expect(serberus_config_group_lookup("admin", &empty) == SERBERUS_GROUP_EMPTY)
        #expect(serberus_config_group_lookup("admin", &everyone) == SERBERUS_GROUP_HAS_MEMBERS)
        #expect(serberus_config_group_lookup("serberus-no-such-group-7f3a", &everyone) == SERBERUS_GROUP_NOT_FOUND)
        #expect(serberus_config_group_lookup("", &everyone) == SERBERUS_GROUP_NOT_FOUND)
        #expect(!serberus_config_default_name_resolves("serberus-no-such-group-7f3a", true))
    }

    @Test("an enforcing config whose only group has no members does not govern")
    func emptyGroupBypassFallsBack() throws {
        // The resolver is a C function pointer (no captures): it classifies
        // every group with the empty-directory probes, so admin has no members.
        let config = try writePlist([
            "enforcementMode": "enforce",
            "pamBypass": ["groups": ["admin"]],
        ])
        let emptyDirectory = serberus_config_resolve_source_with(config, missingLKGPath) { name, isGroup in
            guard let name, isGroup else { return false }
            var probes = serberus_group_probes(
                user_exists: { _ in false }, generated_uid_member: { _ in false }, primary_gid_in_use: { _ in false })
            return serberus_config_group_lookup(name, &probes) == SERBERUS_GROUP_HAS_MEMBERS
        }
        #expect(emptyDirectory == SERBERUS_CONFIG_SOURCE_BOOTSTRAP)
        let populated = serberus_config_resolve_source_with(config, missingLKGPath) { name, isGroup in
            guard let name, isGroup else { return false }
            var probes = serberus_group_probes(
                user_exists: { _ in true }, generated_uid_member: { _ in false }, primary_gid_in_use: { _ in false })
            return serberus_config_group_lookup(name, &probes) == SERBERUS_GROUP_HAS_MEMBERS
        }
        #expect(populated == SERBERUS_CONFIG_SOURCE_MANAGED)
    }

    @Test("an entry containing U+0000 never resolves and is not shortened")
    func nulInBypassEntryIsRefused() throws {
        #expect(serberus_config_copy_cstring("root\u{0}x" as CFString) == nil)
        let plain = serberus_config_copy_cstring("root" as CFString)
        #expect(plain.map { String(cString: $0) } == "root")
        free(plain)
        // XML cannot carry U+0000; a binary plist (what an MDM may deliver) can.
        let config = try writeGarbage(PropertyListSerialization.data(
            fromPropertyList: [
                "enforcementMode": "enforce",
                "pamBypass": ["users": ["root\u{0}x"], "groups": ["admin\u{0}x"]],
            ] as [String: Any], format: .binary, options: 0))
        // A resolver that would accept anything never sees the shortened name.
        let source = serberus_config_resolve_source_with(config, missingLKGPath) { name, _ in
            guard let name else { return false }
            let text = String(cString: name)
            return text != "root" && text != "admin"
        }
        #expect(source == SERBERUS_CONFIG_SOURCE_BOOTSTRAP)
        #expect(serberus_config_resolve_source(config, missingLKGPath) == SERBERUS_CONFIG_SOURCE_BOOTSTRAP)
    }

    @Test("names with whitespace are compared byte for byte, never trimmed")
    func whitespaceNamesAreExact() {
        #expect(!serberus_config_default_name_resolves(" root", false))
        #expect(!serberus_config_default_name_resolves("root ", false))
        #expect(!serberus_config_default_name_resolves("root\n", false))
    }

    @Test("a user resolves only under its exact canonical name, never a case variant")
    func defaultResolverIsCaseExactForUsers() {
        // Open Directory would find "ROOT", but break-glass matches exactly.
        #expect(!serberus_config_default_name_resolves("ROOT", false))
        #expect(!serberus_config_default_name_resolves("Root", false))
    }

    @Test("a break-glass list naming a user only in the wrong case does not govern")
    func caseVariantBypassFallsBack() throws {
        // The production resolver, not the fixture one: "root" really exists.
        let exact = try writePlist([
            "enforcementMode": "enforce",
            "pamBypass": ["users": ["root"]],
        ])
        #expect(serberus_config_resolve_source(exact, missingLKGPath) == SERBERUS_CONFIG_SOURCE_MANAGED)

        let wrongCase = try writePlist([
            "enforcementMode": "enforce",
            "pamBypass": ["users": ["ROOT"]],
        ])
        #expect(serberus_config_resolve_source(wrongCase, missingLKGPath) == SERBERUS_CONFIG_SOURCE_BOOTSTRAP)
        #expect(!userInBypass("root", path: wrongCase))
    }

    @Test("a break-glass name longer than 255 bytes still reaches the resolver")
    func longBypassNameReachesResolver() throws {
        let long = String(repeating: "g", count: 600)
        let config = try writePlist([
            "enforcementMode": "enforce",
            "pamBypass": ["groups": [long]],
        ])
        // The resolver is a C function pointer (no captures): it resolves only
        // the full, untruncated name.
        let source = serberus_config_resolve_source_with(config, missingLKGPath) { name, _ in
            guard let name else { return false }
            return String(cString: name) == String(repeating: "g", count: 600)
        }
        #expect(source == SERBERUS_CONFIG_SOURCE_MANAGED)
    }

    @Test("a delivered but UNSAFE config (enforce, no bypass) falls back to the snapshot")
    func unsafeManagedConfigFallsBackToSnapshot() throws {
        // The partial-profile case: e.g. only a standalone sudoEnrollment
        // profile landed, so the domain has keys but no break-glass.
        let partial = try writePlist([
            "sudoEnrollment": ["group": "staff"],
            "enforcementMode": "enforce",
        ])
        #expect(isPresent(path: partial))
        #expect(!isEnforceable(path: partial))

        let lkg = try writeLKG([
            "enforcementMode": "enforce",
            "pamBypass": ["groups": ["admin"]],
        ])
        #expect(resolveSource(path: partial, lkg: lkg)
            == SERBERUS_CONFIG_SOURCE_LAST_KNOWN_GOOD)
    }

    @Test("bootstrap: no managed config and no snapshot -> pass sudo through")
    func bootstrapDetection() {
        // The ONLY fail-open: a Mac that has never been configured (the Jamf
        // Core pkg beat the config profile). pam_serberus returns PAM_IGNORE.
        #expect(resolveSource(path: missingPlistPath, lkg: missingLKGPath)
            == SERBERUS_CONFIG_SOURCE_BOOTSTRAP)
        // A nil/empty snapshot path is treated as "no snapshot", never as a hit.
        #expect(resolveSource(path: missingPlistPath, lkg: nil)
            == SERBERUS_CONFIG_SOURCE_BOOTSTRAP)
        #expect(resolveSource(path: missingPlistPath, lkg: "")
            == SERBERUS_CONFIG_SOURCE_BOOTSTRAP)
    }

    @Test("an empty managed plist with no snapshot is bootstrap, not enforcement")
    func emptyManagedPlistIsBootstrap() throws {
        // An empty/unparseable managed plist parses to the fail-safe defaults
        // (enforce, no bypass) — which is exactly the brick config. With no
        // snapshot it must be BOOTSTRAP (inert), never a silent enforce.
        let empty = try writePlist([String: Any]())
        #expect(resolveSource(path: empty, lkg: missingLKGPath)
            == SERBERUS_CONFIG_SOURCE_BOOTSTRAP)
        let garbage = try writeGarbage(Data("not a plist".utf8))
        #expect(resolveSource(path: garbage, lkg: missingLKGPath)
            == SERBERUS_CONFIG_SOURCE_BOOTSTRAP)
    }

    @Test("an EXISTING but corrupt snapshot does NOT bootstrap — it fails closed")
    func corruptSnapshotDoesNotBootstrap() throws {
        // THE security boundary. The fail-open is gated on the snapshot FILE not
        // existing (lstat), never on its contents: a Mac that has been
        // configured can never be dropped back into pass-through by corrupting
        // (or truncating, or hand-editing) the snapshot.
        let corrupt = try writeCorruptLKG()
        #expect(FileManager.default.fileExists(atPath: corrupt))
        #expect(resolveSource(path: missingPlistPath, lkg: corrupt)
            == SERBERUS_CONFIG_SOURCE_LAST_KNOWN_GOOD)

        // And reading it fails CLOSED: enforce, no bypass -> pam_serberus
        // consults the daemon and denies if it is unreachable.
        #expect(readMode(path: corrupt) == "enforce")
        #expect(bypassArray("users", path: corrupt) == nil)
        #expect(bypassArray("groups", path: corrupt) == nil)
        #expect(!userInBypass("breakglass", path: corrupt))
        #expect(!isEnforceable(path: corrupt))
    }

    @Test("a snapshot in a directory the caller can't search still counts as existing")
    func unsearchableSnapshotDirectoryDoesNotBootstrap() throws {
        // Inside setuid sudo the probe runs with the invoking user's real uid.
        // access() would report EACCES as "absent" (bootstrap); the lstat
        // probe counts anything but ENOENT/ENOTDIR as present.
        let lkg = try writeLKG(["enforcementMode": "enforce", "pamBypass": ["users": ["breakglass"]]])
        let directory = (lkg as NSString).deletingLastPathComponent
        #expect(chmod(directory, 0) == 0)
        defer { chmod(directory, 0o755) }
        if getuid() != 0 {
            #expect(access(lkg, F_OK) != 0)
        }
        #expect(resolveSource(path: missingPlistPath, lkg: lkg)
            == SERBERUS_CONFIG_SOURCE_LAST_KNOWN_GOOD)
    }

    @Test("a dangling symlink at the snapshot path is not an absent snapshot")
    func danglingSnapshotSymlinkDoesNotBootstrap() throws {
        let directory = try uniqueFixtureDirectory()
        let link = directory.appendingPathComponent("last-known-good-config.plist").path
        #expect(symlink(directory.appendingPathComponent("gone.plist").path, link) == 0)
        #expect(resolveSource(path: missingPlistPath, lkg: link)
            == SERBERUS_CONFIG_SOURCE_LAST_KNOWN_GOOD)
        // The readers refuse it (O_NOFOLLOW), so it fails closed.
        #expect(readMode(path: link) == "enforce")
        #expect(bypassArray("users", path: link) == nil)
    }

    @Test("a snapshot whose bypass was hand-emptied still does not bootstrap")
    func hollowedSnapshotDoesNotBootstrap() throws {
        // Parseable but no longer enforceable (an attacker stripping pamBypass
        // rather than deleting the file). Still LAST_KNOWN_GOOD -> the daemon is
        // consulted, and it is running on its own resolution. Not pass-through.
        let hollow = try writeLKG([
            "enforcementMode": "enforce",
            "pamBypass": ["users": [], "groups": []],
        ])
        #expect(resolveSource(path: missingPlistPath, lkg: hollow)
            == SERBERUS_CONFIG_SOURCE_LAST_KNOWN_GOOD)
    }

    @Test("the on-disk key shape is the managed config domain's, so pam_config.c can parse it")
    func snapshotKeyShapeParity() throws {
        // The exact dictionary LastKnownGoodConfigStore.plistDictionary(for:)
        // writes (minus the omitted-when-nil sudoEnrollment.group). Every key
        // pam_serberus needs must read identically from it and from a managed
        // plist carrying the same keys.
        let snapshot: [String: Any] = [
            "daemonEnabled": true,
            "enforcementMode": "enforce",
            "sudoCacheSeconds": 0,
            "promptTimeoutSeconds": 60,
            "pamBypass": ["groups": ["admin"], "users": ["breakglass"]],
            "sudoEnrollment": [
                "group": "staff",
                "users": [String](),
                "idpGroups": [String](),
                "idpSource": "disabled",
                "idpStatePath": "Library/Preferences/com.jamf.connect.state.plist",
                "idpGroupsKey": "UserGroups",
                "requireRootOwnedState": false,
            ],
        ]
        let asSnapshot = try writeLKG(snapshot)
        let asManaged = try writePlist(snapshot)

        #expect(readMode(path: asSnapshot) == readMode(path: asManaged))
        #expect(bypassArray("users", path: asSnapshot)
            == bypassArray("users", path: asManaged))
        #expect(bypassArray("groups", path: asSnapshot)
            == bypassArray("groups", path: asManaged))
        #expect(userInBypass("breakglass", path: asSnapshot))
    }

    // MARK: kill switch (daemonEnabled) — F3

    private func daemonEnabled(path: String?) -> Bool {
        serberus_config_daemon_enabled(path)
    }

    @Test("daemonEnabled defaults TRUE when the key is absent (fail toward enforcing)")
    func daemonEnabledDefaultsTrue() throws {
        // A config with no daemonEnabled key at all → enforcing (not a kill switch).
        let path = try writePlist(["enforcementMode": "enforce"])
        #expect(daemonEnabled(path: path))
        // Absent everywhere → still TRUE (fail toward enforcing, never a fail-open
        // kill switch from a missing key).
        #expect(daemonEnabled(path: missingPlistPath))
    }

    @Test("daemonEnabled=false is the kill switch (pam passes sudo through)")
    func daemonEnabledFalseIsKillSwitch() throws {
        // This is the value pam_serberus reads to short-circuit to PAM_IGNORE
        // without consulting the daemon.
        let path = try writePlist(["daemonEnabled": false, "enforcementMode": "enforce"])
        #expect(!daemonEnabled(path: path))
    }

    @Test("daemonEnabled=true reads back true")
    func daemonEnabledTrueReadsTrue() throws {
        let path = try writePlist(["daemonEnabled": true])
        #expect(daemonEnabled(path: path))
    }

    @Test("a mistyped daemonEnabled keeps the default TRUE, never a fail-open kill switch")
    func daemonEnabledMistypedFailsTowardEnforcing() throws {
        // A non-boolean daemonEnabled must NOT read as a kill switch — a garbled
        // value can never silently disable enforcement.
        let path = try writePlist(["daemonEnabled": "false"]) // string, not bool
        #expect(daemonEnabled(path: path))
        let numeric = try writePlist(["daemonEnabled": 0]) // integer, not bool
        #expect(daemonEnabled(path: numeric))
    }

    @Test("the managed layer is authoritative for daemonEnabled (kill switch cannot be masked)")
    func daemonEnabledManagedIsAuthoritative() throws {
        // Managed says OFF; a weaker CFPreferences layer says ON. The kill switch
        // in the managed profile must win (per-key authoritative), so an attacker
        // cannot re-enable Serberus from a user-writable layer — and vice versa a
        // managed re-enable is not overridden by a stale user value.
        let path = try writePlist(["daemonEnabled": false])
        withUnmanagedPreference(key: "daemonEnabled", value: kCFBooleanTrue) {
            #expect(!daemonEnabled(path: path))
        }
    }

    @Test("daemonEnabled reads from the last-known-good snapshot with no composite behind it")
    func daemonEnabledFromSnapshot() throws {
        // A kill switch is never snapshotted, but the reader must still honor the
        // snapshot's daemonEnabled.
        let enabledSnap = try writeLKG(["daemonEnabled": true, "enforcementMode": "enforce",
                                        "pamBypass": ["groups": ["admin"]]])
        #expect(daemonEnabled(path: enabledSnap))
        let disabledSnap = try writeLKG(["daemonEnabled": false])
        #expect(!daemonEnabled(path: disabledSnap))
    }
}

// MARK: - Config file trust (owner / mode / symlink)

/// `pam_config.c` honors a plist only when its directory is a real directory
/// owned by the required owner and not group/other-writable, and the file —
/// opened O_NOFOLLOW, checked on the descriptor — is a regular file owned by
/// the required owner and not group/other-writable. Anything else reads as
/// ABSENT, exactly like `ManagedPreferencesReader`. Fixtures are owned by the
/// test user, which stands in for root via the (hidden) test hook.
@Suite("pam_config file trust")
struct PAMConfigFileTrustTests {

    init() {
        serberus_config_set_required_owner_uid_for_testing(getuid())
    }

    private let fm = FileManager.default

    /// A fresh 0755 directory with a valid `enforcementMode: audit` plist (0644).
    private func makeFixture() throws -> (dir: URL, file: URL) {
        let dir = fm.temporaryDirectory
            .appendingPathComponent("pam-trust-tests-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir.path)
        let file = dir.appendingPathComponent("com.herojoneslabs.serberus.config.plist")
        let data = try PropertyListSerialization.data(
            fromPropertyList: ["enforcementMode": "audit", "pamBypass": ["users": ["breakglass"]]],
            format: .xml, options: 0)
        try data.write(to: file)
        try fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
        return (dir, file)
    }

    private func mode(_ path: String) -> String {
        var buffer = [CChar](repeating: 0, count: 32)
        serberus_config_copy_enforcement_mode(path, &buffer, buffer.count)
        return buffer.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
    }

    @Test("an owner-held, non-group/other-writable file in a trusted directory is read")
    func trustedFileIsRead() throws {
        let fixture = try makeFixture()
        #expect(serberus_config_file_is_trusted_for_owner(fixture.file.path, getuid()))
        #expect(mode(fixture.file.path) == "audit")
        #expect(serberus_config_is_present(fixture.file.path))
        #expect(serberus_config_user_in_bypass_users(fixture.file.path, "breakglass"))
    }

    @Test("a file owned by someone other than the required owner is refused")
    func wrongOwnerIsRefused() throws {
        let fixture = try makeFixture()
        let otherUID: uid_t = getuid() == 0 ? 501 : 0
        #expect(!serberus_config_file_is_trusted_for_owner(fixture.file.path, otherUID))
    }

    @Test("a group- or other-writable file reads as absent", arguments: [0o664, 0o646, 0o666])
    func writableFileIsAbsent(permissions: Int) throws {
        let fixture = try makeFixture()
        try fm.setAttributes([.posixPermissions: permissions], ofItemAtPath: fixture.file.path)
        #expect(!serberus_config_file_is_trusted_for_owner(fixture.file.path, getuid()))
        // Treated as absent: fail-closed defaults, no bypass, not present.
        #expect(mode(fixture.file.path) == "enforce")
        #expect(!serberus_config_is_present(fixture.file.path))
        #expect(!serberus_config_user_in_bypass_users(fixture.file.path, "breakglass"))
    }

    @Test("a group- or other-writable directory makes its files absent", arguments: [0o775, 0o757, 0o777])
    func writableDirectoryIsAbsent(permissions: Int) throws {
        let fixture = try makeFixture()
        try fm.setAttributes([.posixPermissions: permissions], ofItemAtPath: fixture.dir.path)
        defer { try? fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: fixture.dir.path) }
        #expect(!serberus_config_file_is_trusted_for_owner(fixture.file.path, getuid()))
        #expect(mode(fixture.file.path) == "enforce")
        #expect(!serberus_config_is_present(fixture.file.path))
    }

    @Test("a symlinked config file is refused (O_NOFOLLOW)")
    func symlinkedFileIsRefused() throws {
        let fixture = try makeFixture()
        let link = fixture.dir.appendingPathComponent("link.plist")
        try fm.createSymbolicLink(at: link, withDestinationURL: fixture.file)
        #expect(!serberus_config_file_is_trusted_for_owner(link.path, getuid()))
        #expect(mode(link.path) == "enforce")
    }

    @Test("a file reached through a symlinked directory is refused (lstat)")
    func symlinkedDirectoryIsRefused() throws {
        let fixture = try makeFixture()
        let linkDir = fm.temporaryDirectory
            .appendingPathComponent("pam-trust-link-\(UUID().uuidString)")
        try fm.createSymbolicLink(at: linkDir, withDestinationURL: fixture.dir)
        defer { try? fm.removeItem(at: linkDir) }
        let viaLink = linkDir.appendingPathComponent(fixture.file.lastPathComponent).path
        #expect(!serberus_config_file_is_trusted_for_owner(viaLink, getuid()))
        #expect(mode(viaLink) == "enforce")
    }

    @Test("a directory in place of the file is refused")
    func directoryInPlaceOfFileIsRefused() throws {
        let fixture = try makeFixture()
        let sub = fixture.dir.appendingPathComponent("sub.plist", isDirectory: true)
        try fm.createDirectory(at: sub, withIntermediateDirectories: false)
        #expect(!serberus_config_file_is_trusted_for_owner(sub.path, getuid()))
    }

    @Test("an untrusted snapshot still selects last-known-good (existence), then fails closed")
    func untrustedSnapshotFailsClosedNotBootstrap() throws {
        let fixture = try makeFixture()
        try fm.setAttributes([.posixPermissions: 0o666], ofItemAtPath: fixture.file.path)
        let source = serberus_config_resolve_source(
            "/nonexistent/serberus-pam-trust/config.plist", fixture.file.path)
        #expect(source == SERBERUS_CONFIG_SOURCE_LAST_KNOWN_GOOD)
        #expect(mode(fixture.file.path) == "enforce")
        #expect(!serberus_config_user_in_bypass_users(fixture.file.path, "breakglass"))
    }

    @Test("a relative path with no directory component is refused")
    func bareFileNameIsRefused() {
        #expect(!serberus_config_file_is_trusted_for_owner("config.plist", getuid()))
    }
}

// MARK: - Daemon peer requirement

@Suite("pam_serberus daemon peer requirement")
struct DaemonPeerRequirementTests {

    private func build(_ team: String?, capacity: Int = 256) -> (Bool, String) {
        var buffer = [CChar](repeating: 0x7F, count: capacity)
        let ok = serberus_daemon_peer_requirement(team, &buffer, buffer.count)
        return (ok, buffer.withUnsafeBufferPointer { String(cString: $0.baseAddress!) })
    }

    @Test("a known team pins identifier, Apple anchor and the leaf OU")
    func teamRequirement() {
        let (ok, requirement) = build("M5RQTPC7A2")
        #expect(ok)
        #expect(requirement == """
            identifier "com.herojoneslabs.serberus.daemon" and anchor apple generic and \
            certificate leaf[subject.OU] = "M5RQTPC7A2"
            """)
    }

    @Test("no team (ad-hoc / unsigned module) keeps identifier + Apple anchor", arguments: [nil, ""] as [String?])
    func noTeamRequirement(team: String?) {
        let (ok, requirement) = build(team)
        #expect(ok)
        #expect(requirement == #"identifier "com.herojoneslabs.serberus.daemon" and anchor apple generic"#)
    }

    @Test("a malformed team is refused, never quoted into the requirement",
          arguments: [#"ABC" or anchor apple generic or "X"#, "abcdefghij", "TEAM ID", "?",
                      "M5RQTPC7A", "M5RQTPC7A2X", String(repeating: "A", count: 32),
                      String(repeating: "A", count: 33)])
    func malformedTeamIsRefused(team: String) {
        let (ok, requirement) = build(team)
        #expect(!ok)
        #expect(requirement.isEmpty)
    }

    @Test("a buffer too small yields no (truncated, weaker) requirement")
    func truncationIsRefused() {
        let (ok, requirement) = build("M5RQTPC7A2", capacity: 40)
        #expect(!ok)
        #expect(requirement.isEmpty)
    }

    @Test("the identifier matches BundleConfig.daemonBundleID")
    func identifierConstant() {
        #expect(SERBERUS_DAEMON_SIGNING_IDENTIFIER == "com.herojoneslabs.serberus.daemon")
    }
}

// MARK: - pam_sm_setcred flags

@Suite("pam_sm_setcred timestamp clearing")
struct SetcredFlagTests {

    @Test("ESTABLISH and REINITIALIZE (sudo 1.9.x begin_session) clear a gated request's timestamp",
          arguments: [PAM_ESTABLISH_CRED, PAM_REINITIALIZE_CRED,
                      PAM_ESTABLISH_CRED | PAM_SILENT, PAM_REINITIALIZE_CRED | PAM_SILENT])
    func clears(flags: Int) {
        #expect(serberus_setcred_should_clear_timestamp(Int32(truncatingIfNeeded: flags), true))
    }

    @Test("a request the module stepped aside for keeps sudo's native ticket",
          arguments: [PAM_ESTABLISH_CRED, PAM_REINITIALIZE_CRED, PAM_ESTABLISH_CRED | PAM_SILENT])
    func ungatedLeavesAlone(flags: Int) {
        #expect(!serberus_setcred_should_clear_timestamp(Int32(truncatingIfNeeded: flags), false))
    }

    @Test("DELETE, REFRESH and no flags leave it alone",
          arguments: [0, PAM_DELETE_CRED, PAM_REFRESH_CRED, PAM_SILENT])
    func leavesAlone(flags: Int) {
        #expect(!serberus_setcred_should_clear_timestamp(Int32(truncatingIfNeeded: flags), true))
    }

    private func path(ruser: String?, recorded: String?, capacity: Int = 1024) -> String? {
        var buffer = [CChar](repeating: 0x7F, count: capacity)
        let ok = withOptionalCString(ruser) { ruserPtr in
            withOptionalCString(recorded) { recordedPtr in
                serberus_timestamp_path(ruserPtr, recordedPtr, &buffer, buffer.count)
            }
        }
        let text = buffer.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        #expect(ok == !text.isEmpty)
        return ok ? text : nil
    }

    private func withOptionalCString<R>(_ string: String?, _ body: (UnsafePointer<CChar>?) -> R) -> R {
        guard let string else { return body(nil) }
        return string.withCString { body($0) }
    }

    @Test("PAM_RUSER (the invoking user sudo keys the ticket to) wins over the recorded PAM_USER")
    func ruserWins() {
        // targetpw / rootpw: PAM_USER at authentication was the target.
        #expect(path(ruser: "alice", recorded: "root") == "/var/db/sudo/ts/alice")
        #expect(path(ruser: "alice", recorded: nil) == "/var/db/sudo/ts/alice")
    }

    @Test("the recorded user is used only when PAM_RUSER is unset")
    func recordedFallback() {
        #expect(path(ruser: nil, recorded: "bob") == "/var/db/sudo/ts/bob")
        #expect(path(ruser: nil, recorded: nil) == nil)
    }

    @Test("unsafe names are refused, and an unsafe PAM_RUSER does not fall back to the recorded user",
          arguments: ["", ".", "..", "../root", "a/b", "/", "alice/"])
    func unsafeNamesRefused(name: String) {
        #expect(!name.withCString { serberus_timestamp_user_is_safe($0) })
        #expect(path(ruser: name, recorded: "bob") == nil)
        #expect(path(ruser: nil, recorded: name) == nil)
    }

    @Test("names that only look odd are still plain file names", arguments: ["...", ".alice", "alice.b", "a b"])
    func oddButSafeNames(name: String) {
        #expect(name.withCString { serberus_timestamp_user_is_safe($0) })
        #expect(path(ruser: name, recorded: nil) == "/var/db/sudo/ts/\(name)")
    }

    @Test("a path that does not fit yields nothing rather than a truncated path")
    func truncationRefused() {
        #expect(path(ruser: "alice", recorded: nil, capacity: 20) == nil)
        #expect(path(ruser: "alice", recorded: nil, capacity: 22) == "/var/db/sudo/ts/alice")
    }

    private func uidPath(_ uid: uid_t, capacity: Int = 1024) -> String? {
        var buffer = [CChar](repeating: 0x7F, count: capacity)
        let ok = serberus_timestamp_uid_path(uid, &buffer, buffer.count)
        let text = buffer.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        #expect(ok == !text.isEmpty)
        return ok ? text : nil
    }

    @Test("sudo 1.9.15+ keys the ticket to the numeric uid")
    func uidKeyedPath() {
        #expect(uidPath(501) == "/var/db/sudo/ts/501")
        #expect(uidPath(0) == "/var/db/sudo/ts/0")
        #expect(uidPath(uid_t(UInt32.max) - 1) == "/var/db/sudo/ts/4294967294")
        #expect(uidPath(501, capacity: 19) == nil)
        #expect(uidPath(501, capacity: 20) == "/var/db/sudo/ts/501")
    }

    @Test("the ticket user is PAM_RUSER, else the recorded user, and never an unsafe name")
    func ticketUser() {
        func user(_ ruser: String?, _ recorded: String?) -> String? {
            withOptionalCString(ruser) { ruserPtr in
                withOptionalCString(recorded) { recordedPtr in
                    serberus_timestamp_ticket_user(ruserPtr, recordedPtr).map { String(cString: $0) }
                }
            }
        }
        #expect(user("alice", "root") == "alice")
        #expect(user(nil, "bob") == "bob")
        #expect(user("../root", "bob") == nil)
        #expect(user(nil, nil) == nil)
    }

    @Test("the invoking user's name resolves to the uid the ticket file is named after")
    func ticketUserResolvesToUID() {
        // The module's own lookup: exact getpwnam_r. The current user's ticket
        // is "<dir>/<getuid()>".
        guard let me = getpwuid(getuid())?.pointee.pw_name.map({ String(cString: $0) }) else { return }
        var uid: uid_t = .max
        #expect(serberus_config_user_uid_exact(me, &uid))
        #expect(uid == getuid())
        #expect(uidPath(uid) == "/var/db/sudo/ts/\(getuid())")
        // A case variant is not the account, so no uid file is removed for it.
        let variant = me.uppercased() == me ? me.lowercased() : me.uppercased()
        if variant != me {
            uid = .max
            #expect(!serberus_config_user_uid_exact(variant, &uid))
            #expect(uid == .max)
        }
    }
}

// MARK: - Daemon reply decoding (native)

@Suite("daemon reply decision decoding")
struct DecisionCodeTests {
    private func code(_ decision: String?) -> Int32 {
        guard let decision else { return serberus_decision_code(nil) }
        return decision.withCString { serberus_decision_code($0) }
    }

    @Test("the known decisions map to their codes")
    func known() {
        #expect(code(SERBERUS_XPC_DECISION_ALLOW) == SERBERUS_DECIDE_ALLOW)
        #expect(code(SERBERUS_XPC_DECISION_DENY) == SERBERUS_DECIDE_DENY)
        #expect(code(SERBERUS_XPC_DECISION_PROMPT_PENDING) == SERBERUS_DECIDE_PENDING)
        #expect(code(SERBERUS_XPC_DECISION_PENDING) == SERBERUS_DECIDE_PENDING)
        #expect(code(SERBERUS_XPC_DECISION_NATIVE) == SERBERUS_DECIDE_NATIVE)
        #expect(SERBERUS_XPC_DECISION_NATIVE == "native")
    }

    @Test("a missing, unknown or near-miss decision fails closed to deny",
          arguments: ["", "Native", "native ", "nativ", "NATIVE", "allowed", "ALLOW", "ignore", "pam_ignore"])
    func unknownFailsClosed(decision: String) {
        #expect(code(decision) == SERBERUS_DECIDE_DENY)
    }

    @Test("a NULL decision fails closed to deny")
    func nullFailsClosed() {
        #expect(code(nil) == SERBERUS_DECIDE_DENY)
    }

    @Test("native on a poll reply is a deny; the other poll codes pass through")
    func nativeOnPollIsDeny() {
        #expect(serberus_poll_code(SERBERUS_DECIDE_NATIVE) == SERBERUS_DECIDE_DENY)
        #expect(serberus_poll_code(SERBERUS_DECIDE_ALLOW) == SERBERUS_DECIDE_ALLOW)
        #expect(serberus_poll_code(SERBERUS_DECIDE_DENY) == SERBERUS_DECIDE_DENY)
        #expect(serberus_poll_code(SERBERUS_DECIDE_PENDING) == SERBERUS_DECIDE_PENDING)
        #expect(serberus_poll_code(SERBERUS_DECIDE_UNREACH) == SERBERUS_DECIDE_UNREACH)
    }

    @Test("native is the only answer that leaves the request ungated (sudo keeps its ticket)")
    func nativeIsNotGated() {
        #expect(!serberus_decision_marks_gated(SERBERUS_DECIDE_NATIVE))
        for code in [SERBERUS_DECIDE_ALLOW, SERBERUS_DECIDE_DENY, SERBERUS_DECIDE_UNREACH, SERBERUS_DECIDE_PENDING] {
            #expect(serberus_decision_marks_gated(code))
        }
    }
}

// MARK: - Authentication posture (drop-in rule)

@Suite("pam_serberus posture and the sudoers drop-in rule")
struct AuthPostureTests {

    private let managed = SERBERUS_CONFIG_SOURCE_MANAGED
    private let lkg = SERBERUS_CONFIG_SOURCE_LAST_KNOWN_GOOD
    private let bootstrap = SERBERUS_CONFIG_SOURCE_BOOTSTRAP

    private func posture(_ source: Int32, kill: Bool = false, _ mode: String?, dropIn: Bool) -> Int32 {
        guard let mode else { return serberus_auth_posture(source, kill, nil, dropIn) }
        return mode.withCString { serberus_auth_posture(source, kill, $0, dropIn) }
    }

    @Test("without a drop-in: bootstrap / kill switch / monitor pass through, audit audits, enforce enforces")
    func noDropIn() {
        #expect(posture(bootstrap, "enforce", dropIn: false) == SERBERUS_POSTURE_PASS_THROUGH)
        #expect(posture(managed, kill: true, "enforce", dropIn: false) == SERBERUS_POSTURE_PASS_THROUGH)
        #expect(posture(lkg, kill: true, "audit", dropIn: false) == SERBERUS_POSTURE_PASS_THROUGH)
        #expect(posture(managed, "monitor", dropIn: false) == SERBERUS_POSTURE_PASS_THROUGH)
        #expect(posture(managed, "audit", dropIn: false) == SERBERUS_POSTURE_AUDIT)
        #expect(posture(lkg, "audit", dropIn: false) == SERBERUS_POSTURE_AUDIT)
        #expect(posture(managed, "enforce", dropIn: false) == SERBERUS_POSTURE_ENFORCE)
        #expect(posture(lkg, "enforce", dropIn: false) == SERBERUS_POSTURE_ENFORCE)
    }

    @Test("with the drop-in still on disk every posture enforces",
          arguments: ["enforce", "audit", "monitor"])
    func dropInEnforces(mode: String) {
        #expect(posture(bootstrap, mode, dropIn: true) == SERBERUS_POSTURE_ENFORCE)
        #expect(posture(managed, kill: true, mode, dropIn: true) == SERBERUS_POSTURE_ENFORCE)
        #expect(posture(lkg, kill: true, mode, dropIn: true) == SERBERUS_POSTURE_ENFORCE)
        #expect(posture(managed, mode, dropIn: true) == SERBERUS_POSTURE_ENFORCE)
        #expect(posture(lkg, mode, dropIn: true) == SERBERUS_POSTURE_ENFORCE)
    }

    @Test("an unknown or missing mode fails closed to enforce", arguments: ["", "Monitor", "off", nil] as [String?])
    func unknownModeEnforces(mode: String?) {
        #expect(posture(managed, mode, dropIn: false) == SERBERUS_POSTURE_ENFORCE)
    }

    @Test("an unrecognized config source is not bootstrap (fail closed)")
    func unknownSourceEnforces() {
        #expect(posture(99, "enforce", dropIn: false) == SERBERUS_POSTURE_ENFORCE)
    }
}
