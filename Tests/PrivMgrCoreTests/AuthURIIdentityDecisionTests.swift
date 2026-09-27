import Foundation
import Security
import Testing
@testable import PrivMgrCore

/// The plugin's policy brain. This is the layer that decides whether a caller
/// is the pinned app, so every branch of it is covered here — the live plugin
/// path adds only hint plumbing and signature resolution on top. Per-app pins
/// are disabled in production, so these tests inject
/// `perAppPinsEnabled: true` to keep the matcher covered for a later release.
@Suite("SerberusAuthPolicy — per-app identity decisions")
struct SerberusAuthDecisionTests {
    static let daemonsModify = "com.apple.ServiceManagement.daemons.modify"
    static let bless = "com.apple.ServiceManagement.blesshelper"
    static let composer = AppIdentityBranch(teamID: "483DWKW443", bundleID: "com.jamfsoftware.Composer")
    static let postman = AppIdentityBranch(teamID: "H7H8Q7M5CK", bundleID: "com.postmanlabs.mac")

    private func policy(_ branches: [(String, AppIdentityBranch)]) -> SerberusAuthPolicy {
        let rules = branches.enumerated().map { index, pair in
            Rule(id: "r\(index)", type: .authuri, action: .allow, description: "", priority: 50,
                 match: MatchCriteria(authURI: pair.0), appIdentity: pair.1)
        }
        return SerberusAuthPolicy(profiles: [
            RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_svc", profilePriority: 50, rules: rules),
        ], perAppPinsEnabled: true)
    }

    private func caller(right: String, creator: AppIdentityBranch?) -> SerberusAuthCaller {
        SerberusAuthCaller(right: right, creatorIdentifier: creator?.bundleID, creatorTeamID: creator?.teamID)
    }

    @Test("the pinned app is allowed; a different app on the same right is denied")
    func matchAndMismatch() {
        let p = policy([(Self.daemonsModify, Self.composer)])
        #expect(p.decide(caller(right: Self.daemonsModify, creator: Self.composer)) == .allow(matched: Self.composer))

        let vscode = AppIdentityBranch(teamID: "UBF8T346G9", bundleID: "com.microsoft.VSCode")
        let denied = p.decide(caller(right: Self.daemonsModify, creator: vscode))
        #expect(!denied.isAllow)
        if case let .deny(reason) = denied {
            #expect(reason.contains("com.microsoft.VSCode"))
            #expect(reason.contains("matches no pinned app"))
        }
    }

    @Test("the creator is what matters: an smd-mediated call still matches on the creator")
    func creatorWinsOverMediatorClient() {
        // The SMJobBless shape: the client is Apple's
        // smd, the creator (the only identity the decision sees) is the app.
        let p = policy([(Self.daemonsModify, Self.composer)])
        #expect(p.decide(caller(right: Self.daemonsModify, creator: Self.composer)) == .allow(matched: Self.composer))
    }

    @Test("an unverified creator never matches: there is no client-PID fallback")
    func noClientFallback() {
        // The caller type carries no client identity at all any more: a
        // recycled client PID can never stand in for the creator.
        let p = policy([(Self.daemonsModify, Self.postman)])
        let unverified = SerberusAuthCaller(right: Self.daemonsModify, creatorIdentifier: nil, creatorTeamID: nil)
        #expect(!p.decide(unverified).isAllow)
        let halfResolved = SerberusAuthCaller(right: Self.daemonsModify,
                                              creatorIdentifier: Self.postman.bundleID, creatorTeamID: nil)
        #expect(!p.decide(halfResolved).isAllow)
    }

    @Test("an identity-scoped DENY rule never becomes a branch (it would be enforced as an allow)")
    func denyPinIsNotABranch() {
        let denyPin = RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_d", profilePriority: 50, rules: [
            Rule(id: "deny-pin", type: .authuri, action: .deny, description: "", priority: 50,
                 match: MatchCriteria(authURI: Self.daemonsModify), appIdentity: Self.composer),
        ])
        let p = SerberusAuthPolicy(profiles: [denyPin], perAppPinsEnabled: true)
        #expect(p.branches(forRight: Self.daemonsModify).isEmpty)
        #expect(!p.decide(caller(right: Self.daemonsModify, creator: Self.composer)).isAllow)
    }

    @Test("pins are per right: the same app on a different right is denied")
    func rightScoped() {
        let p = policy([(Self.daemonsModify, Self.composer)])
        let other = p.decide(caller(right: Self.bless, creator: Self.composer))
        #expect(!other.isAllow)
        if case let .deny(reason) = other { #expect(reason.contains("no identity-scoped rule")) }
    }

    @Test("N apps on one right each match independently")
    func multipleApps() {
        let p = policy([(Self.daemonsModify, Self.composer), (Self.daemonsModify, Self.postman)])
        #expect(p.branches(forRight: Self.daemonsModify).count == 2)
        #expect(p.decide(caller(right: Self.daemonsModify, creator: Self.composer)) == .allow(matched: Self.composer))
        #expect(p.decide(caller(right: Self.daemonsModify, creator: Self.postman)) == .allow(matched: Self.postman))
    }

    @Test("fails closed: unknown right, empty policy, and an unresolvable caller all deny")
    func failsClosed() {
        let p = policy([(Self.daemonsModify, Self.composer)])
        #expect(!p.decide(caller(right: "system.preferences.datetime", creator: Self.composer)).isAllow)
        #expect(!SerberusAuthPolicy(profiles: [], perAppPinsEnabled: true).decide(caller(right: Self.daemonsModify, creator: Self.composer)).isAllow)

        let unresolvable = SerberusAuthCaller(right: Self.daemonsModify, creatorIdentifier: nil, creatorTeamID: nil)
        let denied = p.decide(unresolvable)
        #expect(!denied.isAllow)
        if case let .deny(reason) = denied { #expect(reason.contains("unresolvable")) }
    }

    @Test("the team ID is part of the match: same bundle ID under another team is denied")
    func teamIsPartOfTheMatch() {
        let p = policy([(Self.daemonsModify, Self.composer)])
        let impostor = AppIdentityBranch(teamID: "AAAAAAAAAA", bundleID: "com.jamfsoftware.Composer")
        #expect(!p.decide(caller(right: Self.daemonsModify, creator: impostor)).isAllow)
    }

    @Test("a plain authuri rule contributes no branch")
    func plainRulesIgnored() {
        let plain = RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_p", profilePriority: 50, rules: [
            Rule(id: "plain", type: .authuri, action: .allow, description: "", priority: 50,
                 match: MatchCriteria(authURI: Self.daemonsModify)),
        ])
        #expect(SerberusAuthPolicy(profiles: [plain]).branches(forRight: Self.daemonsModify).isEmpty)
    }

    @Test("duplicate pins across profiles collapse to one branch")
    func duplicatesCollapse() {
        let p = policy([(Self.daemonsModify, Self.composer), (Self.daemonsModify, Self.composer)])
        #expect(p.branches(forRight: Self.daemonsModify).count == 1)
    }
}

/// What a RUNNING creator must look like: the pure half of the plugin's live
/// `SecCode` verification.
@Suite("SerberusRuntimeSigningPolicy — live creator validation")
struct SerberusRuntimeSigningPolicyTests {
    private let runtime = SerberusRuntimeSigningPolicy.hardenedRuntimeFlag
    private let valid = SerberusRuntimeSigningPolicy.dynamicValidFlag

    @Test("a hardened, valid process with no dangerous entitlements is accepted")
    func accepted() {
        #expect(SerberusRuntimeSigningPolicy.rejectionReason(
            codeSigningFlags: runtime, dynamicStatus: valid | runtime,
            entitlements: ["com.apple.security.app-sandbox": true]) == nil)
        #expect(SerberusRuntimeSigningPolicy.rejectionReason(
            codeSigningFlags: runtime, dynamicStatus: nil, entitlements: nil) == nil)
    }

    @Test("no hardened runtime, or no flags at all, is rejected")
    func requiresHardenedRuntime() {
        #expect(SerberusRuntimeSigningPolicy.rejectionReason(
            codeSigningFlags: 0, dynamicStatus: valid, entitlements: nil)?.contains("hardened runtime") == true)
        #expect(SerberusRuntimeSigningPolicy.rejectionReason(
            codeSigningFlags: nil, dynamicStatus: valid, entitlements: nil) != nil)
    }

    @Test("a live status without CS_VALID is rejected")
    func requiresValidDynamicStatus() {
        #expect(SerberusRuntimeSigningPolicy.rejectionReason(
            codeSigningFlags: runtime, dynamicStatus: runtime, entitlements: nil) != nil)
    }

    @Test("each injection-enabling entitlement is rejected unless explicitly false", arguments: [
        "com.apple.security.get-task-allow",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.disable-executable-page-protection",
        "com.apple.security.cs.allow-unsigned-executable-memory",
    ])
    func rejectsInjectableEntitlements(_ key: String) {
        #expect(SerberusRuntimeSigningPolicy.rejectionReason(
            codeSigningFlags: runtime, dynamicStatus: valid, entitlements: [key: true])?.contains(key) == true)
        // A non-boolean value is treated as granting the capability.
        #expect(SerberusRuntimeSigningPolicy.rejectionReason(
            codeSigningFlags: runtime, dynamicStatus: valid, entitlements: [key: 1]) != nil)
        #expect(SerberusRuntimeSigningPolicy.rejectionReason(
            codeSigningFlags: runtime, dynamicStatus: valid, entitlements: [key: false]) == nil)
    }

    @Test("the requirement pins identifier, Apple anchor and team; malformed input yields none")
    func requirement() throws {
        let text = try #require(SerberusRuntimeSigningPolicy.requirement(identifier: "com.postmanlabs.mac",
                                                                          teamID: "H7H8Q7M5CK"))
        #expect(text.contains("identifier \"com.postmanlabs.mac\""))
        #expect(text.contains("anchor apple generic"))
        #expect(text.contains("certificate leaf[subject.OU] = \"H7H8Q7M5CK\""))
        var compiled: SecRequirement?
        #expect(SecRequirementCreateWithString(text as CFString, [], &compiled) == errSecSuccess)

        #expect(SerberusRuntimeSigningPolicy.requirement(identifier: "a\" or anchor apple", teamID: "H7H8Q7M5CK") == nil)
        #expect(SerberusRuntimeSigningPolicy.requirement(identifier: "com.example", teamID: "short") == nil)
    }
}

/// A pinned app the requesting user can write is never trusted: the signature
/// says who signed it, not who can change what it loads next.
@Suite("SerberusBundleWritabilityPolicy", .serialized)
struct SerberusBundleWritabilityTests {
    /// A uid that owns nothing on this Mac and is in no group.
    static let stranger: uid_t = 48_213
    static let never: @Sendable (gid_t) -> Bool = { _ in false }

    /// `<tmp>/<uuid>/Fixture.app/Contents/{MacOS/app, Resources/r, Frameworks/F.framework/F}`,
    /// dirs 0755 and files 0644.
    private func makeBundle() throws -> (bundle: URL, root: URL) {
        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        let bundle = root.appendingPathComponent("Fixture.app")
        let fm = FileManager.default
        for dir in ["Contents/MacOS", "Contents/Resources", "Contents/Frameworks/F.framework"] {
            try fm.createDirectory(at: bundle.appendingPathComponent(dir), withIntermediateDirectories: true,
                                   attributes: [.posixPermissions: 0o755])
        }
        for file in ["Contents/MacOS/app", "Contents/Resources/r", "Contents/Frameworks/F.framework/F", "Contents/Info.plist"] {
            try Data("x".utf8).write(to: bundle.appendingPathComponent(file))
            try fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: bundle.appendingPathComponent(file).path)
        }
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: root.path)
        return (bundle, root)
    }

    private func chmod(_ url: URL, _ mode: Int) throws {
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
    }

    @Test("a tree nobody else can write passes for a stranger")
    func cleanTreePasses() throws {
        let (bundle, root) = try makeBundle()
        defer { try? FileManager.default.removeItem(at: root) }
        let verdict = SerberusBundleWritabilityPolicy.evaluate(bundlePath: bundle.path, requester: Self.stranger,
                                                               isMember: Self.never)
        #expect(verdict == .notWritable, "\(verdict)")
    }

    @Test("owned by the requester → refused (the owner can always chmod)")
    func ownerRefused() throws {
        let (bundle, root) = try makeBundle()
        defer { try? FileManager.default.removeItem(at: root) }
        let verdict = SerberusBundleWritabilityPolicy.evaluate(bundlePath: bundle.path, requester: getuid(),
                                                               isMember: Self.never)
        #expect(verdict.refusalReason?.contains("owned by uid") == true, "\(verdict)")
    }

    @Test("a nested other-writable file is found")
    func otherWritableNested() throws {
        let (bundle, root) = try makeBundle()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = bundle.appendingPathComponent("Contents/Frameworks/F.framework/F")
        try chmod(file, 0o646)
        let verdict = SerberusBundleWritabilityPolicy.evaluate(bundlePath: bundle.path, requester: Self.stranger,
                                                               isMember: Self.never)
        #expect(verdict == .writable(path: SerberusBundleWritabilityPolicy.realPath(file.path)!, reason: "other-writable"), "\(verdict)")
    }

    @Test("group-writable refuses only when the requester is in that group")
    func groupWritable() throws {
        let (bundle, root) = try makeBundle()
        defer { try? FileManager.default.removeItem(at: root) }
        try chmod(bundle.appendingPathComponent("Contents/Resources"), 0o775)
        #expect(SerberusBundleWritabilityPolicy.evaluate(bundlePath: bundle.path, requester: Self.stranger,
                                                         isMember: Self.never) == .notWritable)
        let member = SerberusBundleWritabilityPolicy.evaluate(bundlePath: bundle.path, requester: Self.stranger,
                                                              isMember: { _ in true })
        #expect(member.refusalReason?.contains("group-writable") == true, "\(member)")
    }

    @Test("a writable PARENT directory refuses (the bundle can be renamed away and replaced)")
    func writableParent() throws {
        let (bundle, root) = try makeBundle()
        defer { try? FileManager.default.removeItem(at: root) }
        try chmod(root, 0o757)
        let verdict = SerberusBundleWritabilityPolicy.evaluate(bundlePath: bundle.path, requester: Self.stranger,
                                                               isMember: Self.never)
        #expect(verdict == .writable(path: SerberusBundleWritabilityPolicy.realPath(root.path)!, reason: "other-writable"), "\(verdict)")
    }

    @Test("over the entry cap → refused, never half-checked")
    func entryCap() throws {
        let (bundle, root) = try makeBundle()
        defer { try? FileManager.default.removeItem(at: root) }
        let verdict = SerberusBundleWritabilityPolicy.evaluate(bundlePath: bundle.path, requester: Self.stranger,
                                                               isMember: Self.never, maxEntries: 12)
        guard case .unverifiable = verdict else { Issue.record("\(verdict)"); return }
        // Large enough for Xcode-sized apps (about 170,000 entries).
        #expect(SerberusBundleWritabilityPolicy.defaultMaxEntries >= 400_000)
    }

    @Test("a symlink inside the bundle is fine; one resolving outside it refuses")
    func symlinks() throws {
        let (bundle, root) = try makeBundle()
        defer { try? FileManager.default.removeItem(at: root) }
        let fm = FileManager.default
        try fm.createSymbolicLink(atPath: bundle.appendingPathComponent("Contents/Frameworks/F.framework/Current").path,
                                  withDestinationPath: "F")
        #expect(SerberusBundleWritabilityPolicy.evaluate(bundlePath: bundle.path, requester: Self.stranger,
                                                         isMember: Self.never) == .notWritable)
        try fm.createSymbolicLink(atPath: bundle.appendingPathComponent("Contents/Resources/escape").path,
                                  withDestinationPath: NSTemporaryDirectory())
        let verdict = SerberusBundleWritabilityPolicy.evaluate(bundlePath: bundle.path, requester: Self.stranger,
                                                               isMember: Self.never)
        guard case .unverifiable = verdict else { Issue.record("\(verdict)"); return }
    }

    @Test("a missing path is unverifiable (fail closed)")
    func missingPath() {
        let verdict = SerberusBundleWritabilityPolicy.evaluate(bundlePath: "/nonexistent/\(UUID().uuidString).app",
                                                               requester: Self.stranger, isMember: Self.never)
        #expect(verdict.refusalReason != nil)
    }

    @Test("a bundle in /Applications' root:admin 0775 shape refuses an admin-group member only")
    func adminGroupApplications() {
        // Synthetic filesystem: /Applications root:admin 0775, the app root:wheel 0755.
        let infos: [String: SerberusBundleWritabilityPolicy.FileInfo] = [
            "/": .init(uid: 0, gid: 0, mode: S_IFDIR | 0o755),
            "/Applications": .init(uid: 0, gid: 80, mode: S_IFDIR | 0o775),
            "/Applications/X.app": .init(uid: 0, gid: 0, mode: S_IFDIR | 0o755),
        ]
        func run(_ isMember: @escaping (gid_t) -> Bool) -> SerberusBundleWritabilityPolicy.Verdict {
            SerberusBundleWritabilityPolicy.evaluate(
                bundlePath: "/Applications/X.app", requester: 502, isMember: isMember,
                lstatInfo: { infos[$0] }, listEntries: { _ in [] }, aclGrant: { _, _, _ in .none },
                resolvePath: { $0 }, volumeInfo: { _ in Self.dataVolume })
        }
        #expect(run { _ in false } == .notWritable)
        #expect(run { $0 == 80 } == .writable(path: "/Applications", reason: "group-writable by gid 80, which the requester is in"))
    }

    /// The system data volume: local, ownership honoured, mounted by root.
    static let dataVolume = SerberusBundleWritabilityPolicy.VolumeInfo(
        flags: UInt32(MNT_LOCAL), owner: 0, mountPoint: "/System/Volumes/Data")

    @Test("a bundle on a volume where owner and mode prove nothing is unverifiable",
          arguments: [
            SerberusBundleWritabilityPolicy.VolumeInfo(flags: UInt32(MNT_LOCAL | MNT_IGNORE_OWNERSHIP), owner: 0, mountPoint: "/Volumes/Image"),
            SerberusBundleWritabilityPolicy.VolumeInfo(flags: 0, owner: 0, mountPoint: "/Volumes/Share"),
            SerberusBundleWritabilityPolicy.VolumeInfo(flags: UInt32(MNT_LOCAL), owner: 501, mountPoint: "/Volumes/Mine"),
          ])
    func untrustedVolumes(volume: SerberusBundleWritabilityPolicy.VolumeInfo) {
        let infos: [String: SerberusBundleWritabilityPolicy.FileInfo] = [
            "/": .init(uid: 0, gid: 0, mode: S_IFDIR | 0o755),
            "/Volumes": .init(uid: 0, gid: 0, mode: S_IFDIR | 0o755),
            "/Volumes/X": .init(uid: 0, gid: 0, mode: S_IFDIR | 0o755),
            "/Volumes/X/X.app": .init(uid: 0, gid: 0, mode: S_IFDIR | 0o755),
        ]
        var volumeQueries: [String] = []
        let verdict = SerberusBundleWritabilityPolicy.evaluate(
            bundlePath: "/Volumes/X/X.app/Contents/MacOS/X", requester: 502, isMember: { _ in false },
            lstatInfo: { infos[$0] }, listEntries: { _ in [] }, aclGrant: { _, _, _ in .none },
            resolvePath: { $0 }, volumeInfo: { volumeQueries.append($0); return volume })
        guard case let .unverifiable(reason) = verdict else { Issue.record("\(verdict)"); return }
        #expect(reason.contains(volume.mountPoint), "\(reason)")
        #expect(volumeQueries == ["/Volumes/X/X.app"])
        #expect(SerberusBundleWritabilityPolicy.volumeRefusal(volume) != nil)
        // An unreadable volume is refused too.
        let unknown = SerberusBundleWritabilityPolicy.evaluate(
            bundlePath: "/Volumes/X/X.app", requester: 502, isMember: { _ in false },
            lstatInfo: { infos[$0] }, listEntries: { _ in [] }, aclGrant: { _, _, _ in .none },
            resolvePath: { $0 }, volumeInfo: { _ in nil })
        guard case .unverifiable = unknown else { Issue.record("\(unknown)"); return }
    }

    @Test("the system data volume and this Mac's temporary directory are trusted volumes")
    func trustedVolumes() throws {
        #expect(SerberusBundleWritabilityPolicy.volumeRefusal(Self.dataVolume) == nil)
        let volume = try #require(SerberusBundleWritabilityPolicy.volumeInfo(NSTemporaryDirectory()))
        #expect(SerberusBundleWritabilityPolicy.volumeRefusal(volume) == nil, "\(volume)")
    }

    @Test("system membership lookup agrees with the current user's primary group")
    func systemMembership() {
        let isMember = SerberusBundleWritabilityPolicy.systemMembership(uid: getuid())
        #expect(isMember(getgid()))
        #expect(!SerberusBundleWritabilityPolicy.systemMembership(uid: Self.stranger)(80))
    }

    @Test("the bulk directory read agrees with lstat for every entry")
    func bulkMatchesLstat() throws {
        let (bundle, root) = try makeBundle()
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createSymbolicLink(atPath: bundle.appendingPathComponent("Contents/Frameworks/F.framework/Current").path,
                                                   withDestinationPath: "F")
        try chmod(bundle.appendingPathComponent("Contents/Resources/r"), 0o640)
        for directory in ["Contents", "Contents/Frameworks/F.framework", "Contents/Resources"] {
            let path = bundle.appendingPathComponent(directory).path
            let entries = try #require(SerberusBundleWritabilityPolicy.bulkEntries(path))
            let names = try FileManager.default.contentsOfDirectory(atPath: path)
            #expect(Set(entries.map(\.name)) == Set(names))
            for entry in entries {
                let stat = try #require(SerberusBundleWritabilityPolicy.lstatInfo(path + "/" + entry.name))
                #expect(entry.info.uid == stat.uid && entry.info.gid == stat.gid && entry.info.mode == stat.mode,
                        "\(entry.name): \(entry.info) vs \(stat)")
                #expect(!entry.info.hasACL)
            }
        }
        #expect(SerberusBundleWritabilityPolicy.bulkEntries(bundle.appendingPathComponent("Contents/Info.plist").path) == nil)
    }

    @Test("an ACL entry that lets the requester write refuses; one for somebody else does not")
    func aclGrantsWrite() throws {
        let (bundle, root) = try makeBundle()
        defer { try? FileManager.default.removeItem(at: root) }
        let file = bundle.appendingPathComponent("Contents/Resources/r")
        let me = NSUserName()
        let chmodTool = Process()
        chmodTool.executableURL = URL(fileURLWithPath: "/bin/chmod")
        chmodTool.arguments = ["+a", "user:\(me) allow write", file.path]
        try chmodTool.run(); chmodTool.waitUntilExit()
        try #require(chmodTool.terminationStatus == 0)

        // The bulk read flags the entry as carrying an ACL.
        let entries = try #require(SerberusBundleWritabilityPolicy.bulkEntries(file.deletingLastPathComponent().path))
        #expect(entries.first { $0.name == "r" }?.info.hasACL == true)
        // The ACL names this user: a grant for this uid (as a stranger to the
        // file's owner and mode) is found; for another uid it is not.
        let path = SerberusBundleWritabilityPolicy.realPath(file.path)!
        guard case .write = SerberusBundleWritabilityPolicy.aclGrant(path: path, requester: getuid(), isMember: Self.never) else {
            Issue.record("expected a write grant"); return
        }
        #expect(SerberusBundleWritabilityPolicy.aclGrant(path: path, requester: Self.stranger, isMember: Self.never) == .none)
        // No ACL at all is .none.
        #expect(SerberusBundleWritabilityPolicy.aclGrant(path: SerberusBundleWritabilityPolicy.realPath(bundle.path)!,
                                                         requester: getuid(), isMember: Self.never) == .none)

        // Through the walk, with ownership taken out of the picture: the
        // requester is this uid, but every entry reports another owner.
        let verdict = SerberusBundleWritabilityPolicy.evaluate(
            bundlePath: bundle.path, requester: getuid(), isMember: Self.never,
            lstatInfo: { SerberusBundleWritabilityPolicy.lstatInfo($0).map { .init(uid: 0, gid: 0, mode: $0.mode) } },
            listEntries: { SerberusBundleWritabilityPolicy.bulkEntries($0)?.map {
                .init(name: $0.name, info: .init(uid: 0, gid: 0, mode: $0.info.mode, hasACL: $0.info.hasACL)) } })
        #expect(verdict.refusalReason?.contains("ACL allows") == true, "\(verdict)")
    }

    @Test("an unreadable ACL is unverifiable")
    func aclUnreadable() throws {
        let (bundle, root) = try makeBundle()
        defer { try? FileManager.default.removeItem(at: root) }
        // Only entries the bulk read flags as carrying an ACL are read.
        let flagged = SerberusBundleWritabilityPolicy.evaluate(
            bundlePath: bundle.path, requester: Self.stranger, isMember: Self.never,
            listEntries: { SerberusBundleWritabilityPolicy.bulkEntries($0)?.map {
                .init(name: $0.name, info: .init(uid: $0.info.uid, gid: $0.info.gid, mode: $0.info.mode, hasACL: true)) } },
            aclGrant: { path, _, _ in path.hasSuffix("/Contents") ? .unreadable("boom") : .none })
        guard case let .unverifiable(reason) = flagged else { Issue.record("\(flagged)"); return }
        #expect(reason.contains("ACL"))
    }

    @Test("a helper inside an app is walked from the outermost bundle")
    func outermostApp() throws {
        #expect(SerberusBundleWritabilityPolicy.outermostBundle(
            of: "/Applications/Foo.app/Contents/Library/LoginItems/Helper.app/Contents/MacOS/Helper") == "/Applications/Foo.app")
        #expect(SerberusBundleWritabilityPolicy.outermostBundle(
            of: "/Applications/Foo.app/Contents/XPCServices/S.xpc") == "/Applications/Foo.app")
        #expect(SerberusBundleWritabilityPolicy.outermostBundle(of: "/usr/local/bin/tool") == "/usr/local/bin/tool")
        // Case-insensitive, and code outside any app stops at its own bundle.
        #expect(SerberusBundleWritabilityPolicy.outermostBundle(
            of: "/Applications/Foo.APP/Contents/Library/Helper.app/Contents/MacOS/Helper") == "/Applications/Foo.APP")
        #expect(SerberusBundleWritabilityPolicy.outermostBundle(
            of: "/Library/Vendor/Agent.xpc/Contents/MacOS/Agent") == "/Library/Vendor/Agent.xpc")
        #expect(SerberusBundleWritabilityPolicy.outermostBundle(
            of: "/Library/Frameworks/V.framework/Versions/A/Helpers/Tool") == "/Library/Frameworks/V.framework")
        #expect(SerberusBundleWritabilityPolicy.outermostBundle(
            of: "/Library/Vendor/Plug.Bundle/Contents/MacOS/Plug") == "/Library/Vendor/Plug.Bundle")
        #expect(SerberusBundleWritabilityPolicy.outermostBundle(
            of: "/Library/Vendor/Ext.appex/Contents/MacOS/Ext") == "/Library/Vendor/Ext.appex")

        // Writable code BESIDE the helper (the app's Frameworks) refuses.
        let (bundle, root) = try makeBundle()
        defer { try? FileManager.default.removeItem(at: root) }
        let helper = bundle.appendingPathComponent("Contents/Library/LoginItems/Helper.app/Contents/MacOS")
        try FileManager.default.createDirectory(at: helper, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o755])
        try Data("x".utf8).write(to: helper.appendingPathComponent("Helper"))
        try chmod(helper.appendingPathComponent("Helper"), 0o755)
        #expect(SerberusBundleWritabilityPolicy.evaluate(bundlePath: helper.deletingLastPathComponent().deletingLastPathComponent().path,
                                                         requester: Self.stranger, isMember: Self.never) == .notWritable)
        let framework = bundle.appendingPathComponent("Contents/Frameworks/F.framework/F")
        try chmod(framework, 0o646)
        let verdict = SerberusBundleWritabilityPolicy.evaluate(
            bundlePath: helper.deletingLastPathComponent().deletingLastPathComponent().path,
            requester: Self.stranger, isMember: Self.never)
        #expect(verdict == .writable(path: SerberusBundleWritabilityPolicy.realPath(framework.path)!, reason: "other-writable"), "\(verdict)")
    }

    @Test("refusals carry an administrator-actionable message")
    func adminMessage() {
        let writable = SerberusBundleWritabilityPolicy.Verdict.writable(path: "/Applications/X.app", reason: "owned by uid 501")
        let message = writable.adminMessage(bundle: "com.x (TEAM)", requester: 501)
        #expect(message?.contains("Fix:") == true)
        #expect(message?.contains("normal authentication") == true)
        let capped = SerberusBundleWritabilityPolicy.Verdict.unverifiable("the bundle has more than 400000 entries")
        #expect(capped.adminMessage(bundle: "com.x (TEAM)", requester: 501)?.contains("400000") == true)
        #expect(SerberusBundleWritabilityPolicy.Verdict.notWritable.adminMessage(bundle: "x", requester: 1) == nil)
    }

    @Test("walk timing on Xcode.app (skipped when it is not installed)",
          .enabled(if: FileManager.default.fileExists(atPath: "/Applications/Xcode.app"), "Xcode.app not installed"))
    func xcodeTiming() {
        let start = ContinuousClock.now
        let verdict = SerberusBundleWritabilityPolicy.evaluate(bundlePath: "/Applications/Xcode.app",
                                                               requester: Self.stranger, isMember: Self.never)
        let elapsed = ContinuousClock.now - start
        print("SerberusBundleWritabilityPolicy: /Applications/Xcode.app walked in \(elapsed): \(verdict)")
        // Whatever the verdict, it must not be the entry cap.
        if case let .unverifiable(reason) = verdict { #expect(!reason.contains("entries"), "\(reason)") }
    }
}

// MARK: - Per-app pins disabled in production

extension SerberusAuthDecisionTests {
    @Test("the production policy denies every request, even a creator that would verify against the pin")
    func disabledProductionDeniesEverything() {
        let pins = RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_svc", profilePriority: 50, rules: [
            Rule(id: "composer", type: .authuri, action: .allow, description: "", priority: 50,
                 match: MatchCriteria(authURI: Self.daemonsModify), appIdentity: Self.composer),
            Rule(id: "composer-bless", type: .authuri, action: .allow, description: "", priority: 50,
                 match: MatchCriteria(authURI: Self.bless), appIdentity: Self.composer),
        ])
        let production = SerberusAuthPolicy(profiles: [pins])
        let disabled = SerberusAuthDecision.deny(reason: "per-app rules are disabled in this build")
        #expect(production.decide(caller(right: Self.daemonsModify, creator: Self.composer)) == disabled)
        #expect(production.decide(caller(right: Self.bless, creator: Self.composer)) == disabled)
        #expect(production.decide(caller(right: Self.daemonsModify, creator: nil)) == disabled)
    }
}

extension SerberusAuthDecisionTests {
    @Test("the same token is allowed only when the switch is injected on (the matcher is kept for later)")
    func disabledSwitchOnStillMatches() {
        let pins = RuleProfile(policyVersion: "1.0.0", profileKey: "rules_authuri_svc", profilePriority: 50, rules: [
            Rule(id: "composer", type: .authuri, action: .allow, description: "", priority: 50,
                 match: MatchCriteria(authURI: Self.daemonsModify), appIdentity: Self.composer),
        ])
        #expect(SerberusAuthPolicy(profiles: [pins], perAppPinsEnabled: true)
            .decide(caller(right: Self.daemonsModify, creator: Self.composer)) == .allow(matched: Self.composer))
        #expect(AuthURIIdentityScope.disabledMechanismReason == "per-app rules are disabled in this build")
    }
}
