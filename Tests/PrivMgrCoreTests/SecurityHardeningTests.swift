import Darwin
import Foundation
import Testing
@testable import PrivMgrCore

// MARK: - Argument redaction

@Suite("ArgumentRedactor — hardened coverage")
struct ArgumentRedactorHardeningTests {
    private let r = ArgumentRedactor.placeholder

    @Test("double- and single-dash, next-token and = forms, case-insensitive")
    func flagForms() {
        #expect(ArgumentRedactor.redact(["tool", "--Password", "hunter2"]) == ["tool", "--Password", r])
        #expect(ArgumentRedactor.redact(["tool", "-password", "hunter2"]) == ["tool", "-password", r])
        #expect(ArgumentRedactor.redact(["tool", "--passwd=hunter2"]) == ["tool", "--passwd=\(r)"])
        #expect(ArgumentRedactor.redact(["tool", "-pass=hunter2"]) == ["tool", "-pass=\(r)"])
        #expect(ArgumentRedactor.redact(["tool", "--ACCESS-TOKEN", "abc"]) == ["tool", "--ACCESS-TOKEN", r])
    }

    @Test("names CONTAINING a secret word are redacted")
    func containedWords() {
        for flag in ["--db-password", "--adminPassword", "--client_secret", "--auth-token", "--api_key",
                     "--apiKey", "--private-key", "--credentials", "--auth", "--key", "--passphrase",
                     "--bearer", "--x-api-key", "--oauth-token"] {
            #expect(ArgumentRedactor.redact(["tool", flag, "v"]) == ["tool", flag, r], "\(flag) leaked")
            #expect(ArgumentRedactor.redact(["tool", flag + "=v"]) == ["tool", flag + "=" + r], "\(flag)= leaked")
        }
    }

    @Test("harmless flags stay readable: -k, --keychain, --author, --bypass, -p (sudo prompt)")
    func harmlessFlags() {
        let argv = ["tool", "-k", "x", "--keychain", "login.keychain", "--author", "me",
                    "--bypass-cache", "y", "-p", "Password:", "-pfoo", "--monkey", "z"]
        #expect(ArgumentRedactor.redact(argv) == argv)
    }

    @Test("NAME=value environment-style tokens with secret names are redacted")
    func nameValueTokens() {
        let argv = ["env", "API_TOKEN=abc", "DB_PASSWORD=x", "AWS_SECRET_ACCESS_KEY=y", "PATH=/usr/bin",
                    "PWD=/tmp", "https://host/?password=q"]
        #expect(ArgumentRedactor.redact(argv)
                == ["env", "API_TOKEN=\(r)", "DB_PASSWORD=\(r)", "AWS_SECRET_ACCESS_KEY=\(r)", "PATH=/usr/bin",
                    "PWD=/tmp", "https://host/?password=\(r)"])
    }

    @Test("jamf -password is redacted (argv[0] form and program form)")
    func jamfPassword() {
        #expect(ArgumentRedactor.redact(["/usr/local/bin/jamf", "createAccount", "-username", "a", "-password", "pw"])
                == ["/usr/local/bin/jamf", "createAccount", "-username", "a", "-password", r])
        #expect(ArgumentRedactor.redact(["createAccount", "-password", "pw"], program: "/usr/local/jamf/bin/jamf")
                == ["createAccount", "-password", r])
    }

    @Test("security -w is redacted ONLY for the security tool")
    func securityDashW() {
        #expect(ArgumentRedactor.redact(["add-generic-password", "-a", "me", "-s", "svc", "-w", "pw"],
                                        program: "/usr/bin/security")
                == ["add-generic-password", "-a", "me", "-s", "svc", "-w", r])
        #expect(ArgumentRedactor.redact(["security", "add-generic-password", "-wpw"])
                == ["security", "add-generic-password", "-w\(r)"])
        // Another tool's -w (e.g. `sysctl -w`) is untouched.
        #expect(ArgumentRedactor.redact(["-w", "kern.x=1"], program: "/usr/sbin/sysctl") == ["-w", "kern.x=1"])
    }

    @Test("curl -u/--user user:pass keeps the user, drops the password — only for curl")
    func curlUser() {
        #expect(ArgumentRedactor.redact(["-u", "alice:s3cret", "https://x"], program: "/usr/bin/curl")
                == ["-u", "alice:\(r)", "https://x"])
        #expect(ArgumentRedactor.redact(["curl", "-ualice:s3cret"]) == ["curl", "-ualice:\(r)"])
        #expect(ArgumentRedactor.redact(["curl", "--user=alice:s3cret"]) == ["curl", "--user=alice:\(r)"])
        #expect(ArgumentRedactor.redact(["curl", "--user", "alice"]) == ["curl", "--user", "alice"])
        #expect(ArgumentRedactor.redact(["curl", "-H", "Authorization: Bearer t0k"])
                == ["curl", "-H", "Authorization: \(r)"])
        #expect(ArgumentRedactor.redact(["curl", "-H", "Accept: application/json"])
                == ["curl", "-H", "Accept: application/json"])
        // Not curl: -u is left alone (e.g. `sudo -u root`).
        #expect(ArgumentRedactor.redact(["-u", "root", "id"], program: "/usr/bin/sudo") == ["-u", "root", "id"])
    }

    @Test("function-reference form still compiles and redacts (DecisionEvent init path)")
    func functionReference() {
        let arguments: [String]? = ["tool", "--token", "abc"]
        #expect(arguments.map(ArgumentRedactor.redact) == ["tool", "--token", r])
    }
}

// MARK: - Argument redaction: URLs, tool rules, free text

@Suite("ArgumentRedactor — URLs, tool rules, free text")
struct ArgumentRedactorToolRuleTests {
    private let r = ArgumentRedactor.placeholder

    @Test("URL userinfo passwords are redacted in any token; the user is kept")
    func urlUserinfo() {
        #expect(ArgumentRedactor.redact(["git", "clone", "https://user:pass@host/repo.git"])
                == ["git", "clone", "https://user:\(r)@host/repo.git"])
        #expect(ArgumentRedactor.redact(["mount", "smb://u:p@srv/share"]) == ["mount", "smb://u:\(r)@srv/share"])
        #expect(ArgumentRedactor.redact(["mount_smbfs", "//u:p@srv/share", "/Volumes/x"])
                == ["mount_smbfs", "//u:\(r)@srv/share", "/Volumes/x"])
        #expect(ArgumentRedactor.redact(["tool", "--url=https://a:b@h/x"]) == ["tool", "--url=https://a:\(r)@h/x"])
        #expect(ArgumentRedactor.redact(["env", "DATABASE_URL=postgres://app:pw@db:5432/x"])
                == ["env", "DATABASE_URL=postgres://app:\(r)@db:5432/x"])
        // A user without a password carries no secret.
        #expect(ArgumentRedactor.redact(["ssh", "ssh://git@github.com/x"]) == ["ssh", "ssh://git@github.com/x"])
    }

    @Test("sensitive query / fragment parameters are redacted, others kept")
    func queryParameters() {
        let url = "https://h/p?access_token=a&token=b&password=c&secret=d&sig=e&key=f&page=2#id_token=g"
        #expect(ArgumentRedactor.redact(["open", url])
                == ["open", "https://h/p?access_token=\(r)&token=\(r)&password=\(r)&secret=\(r)&sig=\(r)&key=\(r)&page=2#id_token=\(r)"])
    }

    @Test("dscl . -passwd <path> <old> <new>: every token after the path is redacted")
    func dsclPasswd() {
        #expect(ArgumentRedactor.redact([".", "-passwd", "/Users/bob", "old", "new"], program: "/usr/bin/dscl")
                == [".", "-passwd", "/Users/bob", r, r])
        #expect(ArgumentRedactor.redact(["dscl", ".", "-authonly", "bob", "pw"]) == ["dscl", ".", "-authonly", "bob", r])
        #expect(ArgumentRedactor.redact(["dscl", "-u", "admin", "-P", "pw", ".", "-read", "/Users/bob"])
                == ["dscl", "-u", "admin", "-P", r, ".", "-read", "/Users/bob"])
    }

    @Test("security -p/-P/-o/-w (separate or attached)")
    func securityFlags() {
        #expect(ArgumentRedactor.redact(["security", "unlock-keychain", "-p", "pw", "login.keychain"])
                == ["security", "unlock-keychain", "-p", r, "login.keychain"])
        #expect(ArgumentRedactor.redact(["security", "set-keychain-password", "-o", "old", "-p", "new"])
                == ["security", "set-keychain-password", "-o", r, "-p", r])
        #expect(ArgumentRedactor.redact(["security", "import", "c.p12", "-P", "pw"])
                == ["security", "import", "c.p12", "-P", r])
        #expect(ArgumentRedactor.redact(["security", "create-keychain", "-ppw", "k"])
                == ["security", "create-keychain", "-p\(r)", "k"])
    }

    @Test("openssl -passin/-passout/-pass pass:x and -k")
    func openssl() {
        #expect(ArgumentRedactor.redact(["openssl", "pkcs12", "-passin", "pass:x", "-passout", "pass:y"])
                == ["openssl", "pkcs12", "-passin", "pass:\(r)", "-passout", "pass:\(r)"])
        #expect(ArgumentRedactor.redact(["openssl", "enc", "-pass", "pass:x", "-k", "key"])
                == ["openssl", "enc", "-pass", "pass:\(r)", "-k", r])
        #expect(ArgumentRedactor.redact(["openssl", "rsa", "-passin", "env:PW"])
                == ["openssl", "rsa", "-passin", "env:PW"])
    }

    @Test("curl: short bundles, attached -u/-H, data bodies with sensitive names, forms, certs, cookies")
    func curlBundles() {
        #expect(ArgumentRedactor.redact(["curl", "-sSfu", "alice:pw", "https://x"])
                == ["curl", "-sSfu", "alice:\(r)", "https://x"])
        #expect(ArgumentRedactor.redact(["curl", "-suBOB:pw"]) == ["curl", "-suBOB:\(r)"])
        #expect(ArgumentRedactor.redact(["curl", "-HAuthorization: Bearer abc"]) == ["curl", "-HAuthorization: \(r)"])
        #expect(ArgumentRedactor.redact(["curl", "-sH", "X-Api-Key: abc"]) == ["curl", "-sH", "X-Api-Key: \(r)"])
        #expect(ArgumentRedactor.redact(["curl", "-d", "user=bob&password=pw", "https://x"])
                == ["curl", "-d", r, "https://x"])
        #expect(ArgumentRedactor.redact(["curl", "--data-raw", "{\"token\":\"abc\"}"]) == ["curl", "--data-raw", r])
        #expect(ArgumentRedactor.redact(["curl", "-d", "name=bob"]) == ["curl", "-d", "name=bob"])
        #expect(ArgumentRedactor.redact(["curl", "-d", "@body.json"]) == ["curl", "-d", "@body.json"])
        #expect(ArgumentRedactor.redact(["curl", "-F", "password=pw", "-F", "file=@a"])
                == ["curl", "-F", "password=\(r)", "-F", "file=@a"])
        #expect(ArgumentRedactor.redact(["curl", "-E", "cert.pem:pw"]) == ["curl", "-E", "cert.pem:\(r)"])
        #expect(ArgumentRedactor.redact(["curl", "-b", "session=abc"]) == ["curl", "-b", r])
        #expect(ArgumentRedactor.redact(["curl", "-o", "out.txt", "https://x"]) == ["curl", "-o", "out.txt", "https://x"])
    }

    @Test("mysql -pPW, ldapsearch -w, sshpass -p, docker login -p")
    func assortedTools() {
        #expect(ArgumentRedactor.redact(["mysql", "-uroot", "-psecret", "db"]) == ["mysql", "-uroot", "-p\(r)", "db"])
        #expect(ArgumentRedactor.redact(["mysql", "-p", "db"]) == ["mysql", "-p", "db"])   // bare -p prompts
        #expect(ArgumentRedactor.redact(["ldapsearch", "-D", "cn=x", "-w", "pw", "-b", "dc=y"])
                == ["ldapsearch", "-D", "cn=x", "-w", r, "-b", "dc=y"])
        #expect(ArgumentRedactor.redact(["ldappasswd", "-a", "old", "-s", "new", "-w", "bind"])
                == ["ldappasswd", "-a", r, "-s", r, "-w", r])
        #expect(ArgumentRedactor.redact(["sshpass", "-p", "pw", "ssh", "host"]) == ["sshpass", "-p", r, "ssh", "host"])
        #expect(ArgumentRedactor.redact(["sshpass", "-ppw", "ssh", "host"]) == ["sshpass", "-p\(r)", "ssh", "host"])
        #expect(ArgumentRedactor.redact(["docker", "login", "-u", "me", "-p", "pw", "reg.io"])
                == ["docker", "login", "-u", "me", "-p", r, "reg.io"])
        #expect(ArgumentRedactor.redact(["docker", "run", "-p", "8080:80", "img"])
                == ["docker", "run", "-p", "8080:80", "img"])   // a port, not a password
        #expect(ArgumentRedactor.redact(["docker", "login", "--password-stdin", "reg.io"])
                == ["docker", "login", "--password-stdin", "reg.io"])
    }

    @Test("networksetup wireless / proxy passwords")
    func networksetup() {
        #expect(ArgumentRedactor.redact(["networksetup", "-setairportnetwork", "en0", "Office", "wifipw"])
                == ["networksetup", "-setairportnetwork", "en0", "Office", r])
        #expect(ArgumentRedactor.redact(["networksetup", "-setairportpassword", "en0", "pw"])
                == ["networksetup", "-setairportpassword", r, r])
        #expect(ArgumentRedactor.redact(["networksetup", "-setwebproxy", "Wi-Fi", "proxy", "8080", "on", "u", "pw"])
                == ["networksetup", "-setwebproxy", "Wi-Fi", "proxy", "8080", "on", "u", r])
        #expect(ArgumentRedactor.redact(["networksetup", "-setairportnetwork", "en0", "Open"])
                == ["networksetup", "-setairportnetwork", "en0", "Open"])
    }

    @Test("a colon-less URL userinfo (a token) is redacted whole; ssh-style user names stay")
    func tokenUserinfo() {
        #expect(ArgumentRedactor.redact(["git", "clone", "https://ghp_TOKEN@github.com/org/repo.git"])
                == ["git", "clone", "https://\(r)@github.com/org/repo.git"])
        #expect(ArgumentRedactor.redact(["git", "remote", "add", "o", "--url=https://TOKEN@h/x"])
                == ["git", "remote", "add", "o", "--url=https://\(r)@h/x"])
        #expect(ArgumentRedactor.redact(["git", "clone", "git+ssh://git@github.com/x"])
                == ["git", "clone", "git+ssh://git@github.com/x"])
        #expect(ArgumentRedactor.redact(["git", "clone", "https://github.com/x"]) == ["git", "clone", "https://github.com/x"])
    }

    @Test("git -c http.extraheader carrying a credential; other -c values stay")
    func gitExtraHeader() {
        #expect(ArgumentRedactor.redact(["git", "-c", "http.extraheader=AUTHORIZATION: bearer tok", "fetch"])
                == ["git", "-c", "http.extraheader=AUTHORIZATION: \(r)", "fetch"])
        #expect(ArgumentRedactor.redact(["git", "-chttp.https://h/.extraHeader=Authorization: Basic abc", "pull"])
                == ["git", "-chttp.https://h/.extraHeader=Authorization: \(r)", "pull"])
        #expect(ArgumentRedactor.redact(["git", "-c", "user.token=abc", "push"]) == ["git", "-c", "user.token=\(r)", "push"])
        #expect(ArgumentRedactor.redact(["git", "-c", "http.extraheader=X-Trace: 1", "fetch"])
                == ["git", "-c", "http.extraheader=X-Trace: 1", "fetch"])
        #expect(ArgumentRedactor.redact(["git", "-c", "core.editor=vim", "commit"]) == ["git", "-c", "core.editor=vim", "commit"])
    }

    @Test("dscl -create/-change of a password attribute: every value after it")
    func dsclPasswordAttribute() {
        #expect(ArgumentRedactor.redact(["dscl", ".", "-create", "/Users/u", "Password", "pw"])
                == ["dscl", ".", "-create", "/Users/u", "Password", r])
        #expect(ArgumentRedactor.redact(["dscl", ".", "-change", "/Users/u", "Password", "old", "new"])
                == ["dscl", ".", "-change", "/Users/u", "Password", r, r])
        #expect(ArgumentRedactor.redact([".", "create", "/Users/u", "dsAttrTypeStandard:Password", "pw"], program: "/usr/bin/dscl")
                == [".", "create", "/Users/u", "dsAttrTypeStandard:Password", r])
        // A non-password attribute stays readable.
        #expect(ArgumentRedactor.redact(["dscl", ".", "-create", "/Users/u", "UserShell", "/bin/zsh"])
                == ["dscl", ".", "-create", "/Users/u", "UserShell", "/bin/zsh"])
    }

    @Test("password-like NAME=value (MYSQL_PWD, pw) and form bodies naming them; PWD itself stays")
    func passwordLikeAssignments() {
        #expect(ArgumentRedactor.redact(["env", "MYSQL_PWD=x", "mysql"]) == ["env", "MYSQL_PWD=\(r)", "mysql"])
        #expect(ArgumentRedactor.redact(["tool", "pw=x"]) == ["tool", "pw=\(r)"])
        #expect(ArgumentRedactor.redact(["tool", "db_passcode=1234"]) == ["tool", "db_passcode=\(r)"])
        #expect(ArgumentRedactor.redact(["curl", "-d", "user=bob&pw=x", "https://x"]) == ["curl", "-d", r, "https://x"])
        #expect(ArgumentRedactor.redact(["env", "PWD=/Users/bob", "OLDPWD=/tmp", "ls"])
                == ["env", "PWD=/Users/bob", "OLDPWD=/tmp", "ls"])
        #expect(ArgumentRedactor.redact(["dd", "--pwrite", "x"]) == ["dd", "--pwrite", "x"])
    }

    @Test("ssh-keygen -N/-P, zip/unzip -P, 7z -p…, htpasswd -b, sqlcmd -P")
    func archiveAndKeyTools() {
        #expect(ArgumentRedactor.redact(["ssh-keygen", "-t", "ed25519", "-N", "new", "-f", "k"])
                == ["ssh-keygen", "-t", "ed25519", "-N", r, "-f", "k"])
        #expect(ArgumentRedactor.redact(["ssh-keygen", "-p", "-P", "old", "-N", "new", "-f", "k"])
                == ["ssh-keygen", "-p", "-P", r, "-N", r, "-f", "k"])
        #expect(ArgumentRedactor.redact(["zip", "-r", "-P", "pw", "a.zip", "dir"]) == ["zip", "-r", "-P", r, "a.zip", "dir"])
        #expect(ArgumentRedactor.redact(["unzip", "-P", "pw", "a.zip"]) == ["unzip", "-P", r, "a.zip"])
        #expect(ArgumentRedactor.redact(["7z", "a", "-psecret", "a.7z", "dir"]) == ["7z", "a", "-p\(r)", "a.7z", "dir"])
        #expect(ArgumentRedactor.redact(["7zz", "x", "-p", "a.7z"]) == ["7zz", "x", "-p", "a.7z"])   // bare -p prompts
        #expect(ArgumentRedactor.redact(["htpasswd", "-b", ".htpasswd", "bob", "pw"])
                == ["htpasswd", "-b", ".htpasswd", "bob", r])
        #expect(ArgumentRedactor.redact(["htpasswd", "-nbB", "bob", "pw"]) == ["htpasswd", "-nbB", "bob", r])
        #expect(ArgumentRedactor.redact(["htpasswd", "-D", ".htpasswd", "bob"]) == ["htpasswd", "-D", ".htpasswd", "bob"])
        #expect(ArgumentRedactor.redact(["sqlcmd", "-S", "srv", "-U", "sa", "-P", "pw"])
                == ["sqlcmd", "-S", "srv", "-U", "sa", "-P", r])
    }

    @Test("jamf -passhash")
    func jamfPasshash() {
        #expect(ArgumentRedactor.redact(["jamf", "createAccount", "-username", "a", "-passhash", "HASH"])
                == ["jamf", "createAccount", "-username", "a", "-passhash", r])
    }

    @Test("security find-*-password -w prints the password and takes no value: the service stays readable")
    func securityFindPassword() {
        #expect(ArgumentRedactor.redact(["security", "find-generic-password", "-w", "-s", "svc"])
                == ["security", "find-generic-password", "-w", "-s", "svc"])
        #expect(ArgumentRedactor.redact(["security", "find-internet-password", "-s", "host", "-w"])
                == ["security", "find-internet-password", "-s", "host", "-w"])
        // add-* still takes the password after -w.
        #expect(ArgumentRedactor.redact(["security", "add-generic-password", "-s", "svc", "-a", "me", "-w", "pw"])
                == ["security", "add-generic-password", "-s", "svc", "-a", "me", "-w", r])
    }

    @Test("justification text is split on ALL whitespace, separators preserved")
    func freeTextWhitespace() {
        #expect(ArgumentRedactor.redact(text: "need\t--password\nhunter2  now")
                == "need\t--password\n\(r)  now")
        #expect(ArgumentRedactor.redact(text: "see https://u:p@h/x?token=t please")
                == "see https://u:\(r)@h/x?token=\(r) please")
        #expect(ArgumentRedactor.redact(text: "  plain text\n") == "  plain text\n")
    }
}

// MARK: - Last-known-good snapshot completeness

@Suite("LastKnownGoodConfigStore — every enforcement key round-trips", .serialized)
struct LastKnownGoodCompletenessTests {
    private func temporaryURL() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("serberus-lkg-full-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appendingPathComponent("last-known-good-config.plist")
    }

    /// Every field populated with a NON-default value, credentials excluded.
    private func fullyPopulated() -> SerberusConfig {
        SerberusConfig(
            jamfProURL: nil, jamfAPIClientID: nil, jamfAPIClientSecret: nil,
            daemonEnabled: true,
            enforcementMode: .audit,
            sudoCacheSeconds: 300,
            promptTimeoutSeconds: 90,
            pamBypass: PAMBypass(groups: ["admin", "it"], users: ["breakglass"]),
            sudoEnrollment: SerberusConfig.SudoEnrollment(
                group: "staff", users: ["carol", "dave"], idpGroups: ["Eng-Admins"],
                idpSource: .jamfConnectState, idpStatePath: "Library/Preferences/custom.plist",
                idpGroupsKey: "Groups", requireRootOwnedState: false
            ),
            commanderPublishEnabled: true,
            timeBoundGrantsEnabled: true,
            defaultGrantDurationMinutes: 45,
            enableBiometrics: true
        )
    }

    @Test("load(save(c)) == c for a fully populated config")
    func roundTrip() throws {
        let url = try temporaryURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let store = LastKnownGoodConfigStore(url: url, requiredOwnerUID: getuid())
        let config = fullyPopulated()

        try store.save(config)
        #expect(store.load() == config)
        #expect(!store.needsRefresh(for: config))
    }

    @Test("credentials (and the Jamf URL) are never written, even when present")
    func credentialsExcluded() throws {
        let url = try temporaryURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let base = fullyPopulated()
        let withSecrets = SerberusConfig(
            jamfProURL: URL(string: "https://example.jamfcloud.com"),
            jamfAPIClientID: "client-id", jamfAPIClientSecret: "s3cret",
            daemonEnabled: base.daemonEnabled, enforcementMode: base.enforcementMode,
            sudoCacheSeconds: base.sudoCacheSeconds, promptTimeoutSeconds: base.promptTimeoutSeconds,
            pamBypass: base.pamBypass, sudoEnrollment: base.sudoEnrollment,
            commanderPublishEnabled: base.commanderPublishEnabled,
            timeBoundGrantsEnabled: base.timeBoundGrantsEnabled,
            defaultGrantDurationMinutes: base.defaultGrantDurationMinutes,
            enableBiometrics: base.enableBiometrics
        )
        try LastKnownGoodConfigStore(url: url, requiredOwnerUID: getuid()).save(withSecrets)

        let text = try String(contentsOf: url, encoding: .utf8)
        #expect(!text.contains("s3cret"))
        #expect(!text.contains("client-id"))
        #expect(!text.contains("jamfAPIClient"))
        // Everything else survives.
        #expect(LastKnownGoodConfigStore(url: url, requiredOwnerUID: getuid()).load() == base)
    }

    @Test("pass-through keys (sudo messages, guardian) are copied from the managed domain, type-checked")
    func passthroughKeys() throws {
        let url = try temporaryURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let source = DictionaryPreferencesSource(domains: [BundleConfig.configDomain: [
            "sudoDenyMessage": "Denied: {command}",
            "sudoAllowMessage": "Allowed: {command}",
            "sudoPromptDeniedMessage": "You said no",
            "sudoPromptTimeoutMessage": "Too slow",
            "guardianEnabled": true,
            "guardianDetectionSeconds": 7,
            "jamfAPIClientSecret": "s3cret",   // never copied
        ]])
        let store = LastKnownGoodConfigStore(url: url, passthroughSource: source, requiredOwnerUID: getuid())
        try store.save(fullyPopulated())

        let data = try #require(FileManager.default.contents(atPath: url.path))
        let plist = try #require(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        #expect(plist["sudoDenyMessage"] as? String == "Denied: {command}")
        #expect(plist["sudoAllowMessage"] as? String == "Allowed: {command}")
        #expect(plist["sudoPromptDeniedMessage"] as? String == "You said no")
        #expect(plist["sudoPromptTimeoutMessage"] as? String == "Too slow")
        #expect(plist["guardianEnabled"] as? Bool == true)
        #expect(plist["guardianDetectionSeconds"] as? Int == 7)
        #expect(plist["jamfAPIClientSecret"] == nil)
        #expect(plist["timeBoundGrantsEnabled"] as? Bool == true)
        #expect(plist["defaultGrantDurationMinutes"] as? Int == 45)
        #expect(plist["enableBiometrics"] as? Bool == true)
        #expect(store.load() == fullyPopulated())
    }

    @Test("needsRefresh flags a snapshot that lacks keys the live config now carries")
    func staleSnapshotNeedsRefresh() throws {
        let url = try temporaryURL()
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        // An older build's snapshot: only the original six keys.
        let legacy: [String: Any] = [
            "daemonEnabled": true, "enforcementMode": "enforce", "sudoCacheSeconds": 0,
            "promptTimeoutSeconds": 60, "pamBypass": ["groups": ["admin"], "users": [String]()],
        ]
        try PropertyListSerialization.data(fromPropertyList: legacy, format: .xml, options: 0).write(to: url)
        let store = LastKnownGoodConfigStore(url: url, requiredOwnerUID: getuid())
        #expect(store.needsRefresh(for: fullyPopulated()))
    }
}

// MARK: - Grant store: permissions + JIT row retention

@Suite("GrantStore — hardening", .serialized)
struct GrantStoreHardeningTests {
    let keyProvider = InMemoryKeyProvider.random()

    private func mode(_ path: String) -> mode_t? {
        var info = stat()
        guard lstat(path, &info) == 0 else { return nil }
        return info.st_mode & 0o777
    }

    private func jitGrant(user: String = "alice", expiresAt: Date) -> Grant {
        Grant(user: user, uid: 501, ruleID: "jit-self-service", profileKey: JITAdminGrant.profileKey,
              teamID: "", binaryHash: "", canonicalPath: JITAdminGrant.canonicalPath,
              grantedAt: Fixtures.now.addingTimeInterval(-3600), expiresAt: expiresAt, policyVersion: "jit")
    }

    private func binaryGrant(expiresAt: Date?) -> Grant {
        Grant(user: "bob", uid: 502, ruleID: "allow-brew", profileKey: "rules_sudo_test",
              teamID: "", binaryHash: "abc", canonicalPath: "/opt/homebrew/bin/brew",
              grantedAt: Fixtures.now.addingTimeInterval(-3600), expiresAt: expiresAt, policyVersion: "1.0.0")
    }

    @Test("a new database and its WAL companions are created 0600")
    func newDatabaseIsPrivate() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { for suffix in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(atPath: path + suffix) } }
        let store = try GrantStore(path: path, keyProvider: keyProvider)
        try await store.insert(binaryGrant(expiresAt: nil))

        #expect(mode(path) == 0o600)
        for suffix in ["-wal", "-shm"] where FileManager.default.fileExists(atPath: path + suffix) {
            #expect(mode(path + suffix) == 0o600, "\(suffix) not private")
        }
        await store.close()
    }

    @Test("an existing world-readable database is tightened to 0600 on open")
    func existingDatabaseIsTightened() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { for suffix in ["", "-wal", "-shm"] { try? FileManager.default.removeItem(atPath: path + suffix) } }
        do {
            let store = try GrantStore(path: path, keyProvider: keyProvider)
            await store.close()
        }
        chmod(path, 0o644)
        #expect(mode(path) == 0o644)

        let reopened = try GrantStore(path: path, keyProvider: keyProvider)
        #expect(mode(path) == 0o600)
        await reopened.close()
    }

    @Test("cleanupExpired keeps an expired JIT grant whose demotion never landed")
    func cleanupKeepsUnrevokedJIT() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try GrantStore(path: path, keyProvider: keyProvider)
        let pendingDemotion = jitGrant(expiresAt: Fixtures.now.addingTimeInterval(-60))
        let demoted = jitGrant(user: "carol", expiresAt: Fixtures.now.addingTimeInterval(-60))
        try await store.insert(pendingDemotion)
        try await store.insert(demoted)
        try await store.insert(binaryGrant(expiresAt: Fixtures.now.addingTimeInterval(-60)))
        _ = try await store.revoke(grantID: demoted.grantID, now: Fixtures.now)

        let removed = try await store.cleanupExpired(now: Fixtures.now)

        #expect(removed == 2) // the binary grant + the already-demoted JIT row
        let remaining = try await store.allGrants()
        #expect(remaining.map(\.grantID) == [pendingDemotion.grantID])
        await store.close()
    }

    @Test("the kill-switch revokeAll leaves JIT rows for the JIT manager to demote")
    func revokeAllSkipsJIT() async throws {
        let path = Fixtures.tempDatabasePath()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try GrantStore(path: path, keyProvider: keyProvider)
        let jit = jitGrant(expiresAt: Fixtures.now.addingTimeInterval(600))
        try await store.insert(jit)
        try await store.insert(binaryGrant(expiresAt: Fixtures.now.addingTimeInterval(600)))

        let count = try await store.revokeAll(now: Fixtures.now)

        #expect(count == 1)
        let rows = try await store.allGrants()
        #expect(rows.first { $0.grantID == jit.grantID }?.revokedAt == nil)
        #expect(rows.first { $0.grantID != jit.grantID }?.revokedAt != nil)
        await store.close()
    }
}

// MARK: - Decision log file handling

@Suite("SignedJSONLWriter — file hardening", .serialized)
struct LogFileHardeningTests {
    private func event() -> IntegrityEvent {
        IntegrityEvent(timestamp: Fixtures.now, kind: .policyChange, detail: "x", daemonVersion: "t")
    }

    @Test("appends refuse to write THROUGH a symlink planted at the day file")
    func refusesSymlink() async throws {
        let dir = try Fixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let victim = dir.appendingPathComponent("victim.txt")
        try Data("original\n".utf8).write(to: victim)
        let dayFile = dir.appendingPathComponent("integrity-\(LogDay.stamp(for: Fixtures.now)).jsonl")
        try FileManager.default.createSymbolicLink(at: dayFile, withDestinationURL: victim)

        let logger = try IntegrityLogger(directory: dir)
        await #expect(throws: (any Error).self) { try await logger.log(event()) }
        #expect(try String(contentsOf: victim, encoding: .utf8) == "original\n")
    }

    @Test("a group/other-writable log directory and day file are tightened; files are never writable by others")
    func tightensLooseModes() async throws {
        let dir = try Fixtures.tempDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        chmod(dir.path, 0o777)
        let logger = try IntegrityLogger(directory: dir)
        try await logger.log(event())

        var info = stat()
        #expect(lstat(dir.path, &info) == 0)
        #expect(info.st_mode & 0o022 == 0)
        let dayFile = dir.appendingPathComponent("integrity-\(LogDay.stamp(for: Fixtures.now)).jsonl")
        #expect(lstat(dayFile.path, &info) == 0)
        #expect(info.st_mode & 0o022 == 0)
        #expect(try String(contentsOf: dayFile, encoding: .utf8).split(separator: "\n").count == 1)

        // A pre-existing loose file is tightened on the next append, and appends accumulate.
        chmod(dayFile.path, 0o666)
        try await logger.log(event())
        #expect(lstat(dayFile.path, &info) == 0)
        #expect(info.st_mode & 0o022 == 0)
        #expect(try String(contentsOf: dayFile, encoding: .utf8).split(separator: "\n").count == 2)
    }
}

// MARK: - Argument redaction: admin tools and wrapped commands

@Suite("ArgumentRedactor — admin tools and wrapped commands")
struct ArgumentRedactorAdminToolTests {
    private let r = ArgumentRedactor.placeholder

    @Test("security set-*-partition-list -k is the keychain password; elsewhere -k names a keychain")
    func securityPartitionList() {
        #expect(ArgumentRedactor.redact(["set-key-partition-list", "-S", "apple-tool:,apple:", "-s", "-k", "LoginPw123",
                                         "login.keychain"], program: "/usr/bin/security")
                == ["set-key-partition-list", "-S", "apple-tool:,apple:", "-s", "-k", r, "login.keychain"])
        #expect(ArgumentRedactor.redact(["security", "set-generic-password-partition-list", "-kPw"])
                == ["security", "set-generic-password-partition-list", "-k\(r)"])
        #expect(ArgumentRedactor.redact(["import", "cert.p12", "-k", "/Library/Keychains/System.keychain"],
                                        program: "security")
                == ["import", "cert.p12", "-k", "/Library/Keychains/System.keychain"])
    }

    @Test("env-prefix assignments with secret-like names; PWD / OLDPWD stay visible")
    func envAssignments() {
        let argv = ["SSHPASS=hunter2", "GITHUB_TOKEN=ghp_x", "AWS_SECRET=s", "SIGNING_KEY=k", "DBPASSWORD=p",
                    "GITHUB_PAT=ghp_y", "PWD=/tmp", "OLDPWD=/", "PATH=/usr/bin", "LANG=C"]
        #expect(ArgumentRedactor.redact(argv, program: "/usr/bin/env")
                == ["SSHPASS=\(r)", "GITHUB_TOKEN=\(r)", "AWS_SECRET=\(r)", "SIGNING_KEY=\(r)", "DBPASSWORD=\(r)",
                    "GITHUB_PAT=\(r)", "PWD=/tmp", "OLDPWD=/", "PATH=/usr/bin", "LANG=C"])
    }

    @Test("wget --header (both forms), --password, --http-password")
    func wget() {
        #expect(ArgumentRedactor.redact(["--header", "Authorization: Bearer abc123", "https://x"], program: "wget")
                == ["--header", "Authorization: \(r)", "https://x"])
        #expect(ArgumentRedactor.redact(["--header=Authorization: Bearer abc123", "https://x"], program: "wget")
                == ["--header=Authorization: \(r)", "https://x"])
        #expect(ArgumentRedactor.redact(["--header", "Accept: text/html", "https://x"], program: "wget")
                == ["--header", "Accept: text/html", "https://x"])
        #expect(ArgumentRedactor.redact(["--password", "p", "--http-password=q", "--user", "me"], program: "wget")
                == ["--password", r, "--http-password=\(r)", "--user", "me"])
    }

    @Test("keytool -storepass / -keypass / -srcstorepass / -new; :env and :file sources kept")
    func keytool() {
        #expect(ArgumentRedactor.redact(["-importcert", "-keystore", "cacerts", "-storepass", "s3cret",
                                         "-keypass", "k3y", "-srcstorepass", "x", "-alias", "a"], program: "keytool")
                == ["-importcert", "-keystore", "cacerts", "-storepass", r, "-keypass", r, "-srcstorepass", r,
                    "-alias", "a"])
        #expect(ArgumentRedactor.redact(["-storepasswd", "-new", "n3w", "-storepass:env", "KS_PW"], program: "keytool")
                == ["-storepasswd", "-new", r, "-storepass:env", "KS_PW"])
    }

    @Test("redis-cli -a, smbclient -U user%pass, vault login <token>")
    func cliPasswords() {
        #expect(ArgumentRedactor.redact(["-a", "s3cret", "ping"], program: "redis-cli") == ["-a", r, "ping"])
        #expect(ArgumentRedactor.redact(["//h/s", "-U", "user%s3cret"], program: "smbclient")
                == ["//h/s", "-U", "user%\(r)"])
        #expect(ArgumentRedactor.redact(["//h/s", "-Uuser%s3cret"], program: "smbclient") == ["//h/s", "-Uuser%\(r)"])
        #expect(ArgumentRedactor.redact(["//h/s", "--user=user%s3cret"], program: "smbclient")
                == ["//h/s", "--user=user%\(r)"])
        #expect(ArgumentRedactor.redact(["//h/s", "-U", "user"], program: "smbclient") == ["//h/s", "-U", "user"])
        #expect(ArgumentRedactor.redact(["login", "s.abcdef"], program: "vault") == ["login", r])
        #expect(ArgumentRedactor.redact(["login", "-method=userpass", "username=me", "password=pw"], program: "vault")
                == ["login", "-method=userpass", "username=me", "password=\(r)"])
        #expect(ArgumentRedactor.redact(["read", "secret/data/app"], program: "vault") == ["read", "secret/data/app"])
    }

    @Test("dsconfigad -p / -lp, pwpolicy -p, createmobileaccount -p")
    func macAdminTools() {
        #expect(ArgumentRedactor.redact(["-add", "corp.example", "-u", "admin", "-p", "pw", "-lu", "la", "-lp", "lpw"],
                                        program: "/usr/sbin/dsconfigad")
                == ["-add", "corp.example", "-u", "admin", "-p", r, "-lu", "la", "-lp", r])
        #expect(ArgumentRedactor.redact(["-a", "diradmin", "-p", "s3cret", "-u", "bob", "-setpolicy", "x"],
                                        program: "pwpolicy")
                == ["-a", "diradmin", "-p", r, "-u", "bob", "-setpolicy", "x"])
        #expect(ArgumentRedactor.redact(["-n", "bob", "-p", "pw", "-v"], program: "createmobileaccount")
                == ["-n", "bob", "-p", r, "-v"])
    }

    @Test("launchctl setenv and defaults write redact only values of sensitive names")
    func namedValues() {
        #expect(ArgumentRedactor.redact(["setenv", "API_TOKEN", "abc"], program: "launchctl")
                == ["setenv", "API_TOKEN", r])
        #expect(ArgumentRedactor.redact(["setenv", "EDITOR", "vim"], program: "launchctl") == ["setenv", "EDITOR", "vim"])
        #expect(ArgumentRedactor.redact(["write", "/Library/Preferences/x", "APIToken", "abc"], program: "defaults")
                == ["write", "/Library/Preferences/x", "APIToken", r])
        #expect(ArgumentRedactor.redact(["write", "com.x", "Password", "-string", "pw"], program: "defaults")
                == ["write", "com.x", "Password", r, r])
        #expect(ArgumentRedactor.redact(["-currentHost", "write", "-app", "Foo", "ClientSecret", "s"], program: "defaults")
                == ["-currentHost", "write", "-app", "Foo", "ClientSecret", r])
        #expect(ArgumentRedactor.redact(["write", "com.x", "{ token = abc; }"], program: "defaults")
                == ["write", "com.x", r])
        #expect(ArgumentRedactor.redact(["write", "com.x", "ShowAll", "-bool", "true"], program: "defaults")
                == ["write", "com.x", "ShowAll", "-bool", "true"])
    }

    @Test("openssl passwd plaintext is redacted; its options and salt are kept")
    func opensslPasswd() {
        #expect(ArgumentRedactor.redact(["passwd", "-6", "-salt", "abc", "plaintext"], program: "openssl")
                == ["passwd", "-6", "-salt", "abc", r])
        #expect(ArgumentRedactor.redact(["passwd", "-stdin"], program: "openssl") == ["passwd", "-stdin"])
        #expect(ArgumentRedactor.redact(["x509", "-in", "passwd", "-noout"], program: "openssl")
                == ["x509", "-in", "passwd", "-noout"])
    }

    @Test("a sensitive header given as one token is redacted for any tool")
    func headerTokens() {
        #expect(ArgumentRedactor.redact(["GET", "https://x", "Authorization:Bearer abc123"], program: "http")
                == ["GET", "https://x", "Authorization: \(r)"])
        #expect(ArgumentRedactor.redact(["X-Api-Key:abc"], program: "http") == ["X-Api-Key: \(r)"])
        #expect(ArgumentRedactor.redact(["Accept:json", "key:value", "https://h:8080/x"], program: "http")
                == ["Accept:json", "key:value", "https://h:8080/x"])
    }

    @Test("sh / bash / zsh -c: the inner command is redacted; everything else is kept as typed")
    func shellWrappers() {
        #expect(ArgumentRedactor.redact(["-c", "mysql -pS3cret db"], program: "/bin/sh")
                == ["-c", "mysql -p\(r) db"])
        #expect(ArgumentRedactor.redact(["-lc", "cd /tmp && curl -u me:pw https://x | tee out"], program: "bash")
                == ["-lc", "cd /tmp && curl -u me:\(r) https://x | tee out"])
        #expect(ArgumentRedactor.redact(["-o", "pipefail", "-c", "API_TOKEN='a b' ./deploy --password \"x y\""],
                                        program: "zsh")
                == ["-o", "pipefail", "-c", "API_TOKEN=\(r) ./deploy --password \(r)"])
        #expect(ArgumentRedactor.redact(["bash", "-c", "security unlock-keychain -p pw; echo done"])
                == ["bash", "-c", "security unlock-keychain -p \(r); echo done"])
        // Nothing sensitive: untouched, byte for byte.
        let plain = "echo 'hello   world' && ls -la ~"
        #expect(ArgumentRedactor.redact(["-c", plain], program: "sh") == ["-c", plain])
        // A script file, not -c: its arguments get the ordinary rules only.
        #expect(ArgumentRedactor.redact(["script.sh", "-p", "x"], program: "sh") == ["script.sh", "-p", "x"])
    }

    @Test("env VAR=… cmd, xargs cmd and launchctl asuser cmd are unwrapped")
    func argvWrappers() {
        #expect(ArgumentRedactor.redact(["SSHPASS=hunter2", "sshpass", "-e", "ssh", "host"], program: "env")
                == ["SSHPASS=\(r)", "sshpass", "-e", "ssh", "host"])
        #expect(ArgumentRedactor.redact(["-i", "PATH=/bin", "security", "add-generic-password", "-w", "pw"],
                                        program: "/usr/bin/env")
                == ["-i", "PATH=/bin", "security", "add-generic-password", "-w", r])
        #expect(ArgumentRedactor.redact(["-S", "mysql -pS3cret"], program: "env") == ["-S", "mysql -p\(r)"])
        #expect(ArgumentRedactor.redact(["-n", "1", "-I", "{}", "curl", "-u", "me:pw", "{}"], program: "xargs")
                == ["-n", "1", "-I", "{}", "curl", "-u", "me:\(r)", "{}"])
        #expect(ArgumentRedactor.redact(["asuser", "501", "security", "add-generic-password", "-w", "s3cret"],
                                        program: "launchctl")
                == ["asuser", "501", "security", "add-generic-password", "-w", r])
        // Nested wrappers.
        #expect(ArgumentRedactor.redact(["env", "bash", "-c", "xargs mysql -pX"])
                == ["env", "bash", "-c", "xargs mysql -p\(r)"])
    }

    @Test("redaction stays idempotent over already-redacted wrapped commands")
    func idempotent() {
        let once = ArgumentRedactor.redact(["-c", "mysql -pS3cret db; wget --header 'Authorization: Bearer t' x"],
                                           program: "sh")
        #expect(ArgumentRedactor.redact(once, program: "sh") == once)
    }
}

@Suite("ArgumentRedactor — transparent wrappers, su -c, interpreter strings")
struct TransparentWrapperRedactionTests {
    private let r = ArgumentRedactor.placeholder

    private func leaks(_ argv: [String], program: String?, _ secret: String = "S3cret") -> Bool {
        ArgumentRedactor.redact(argv, program: program).contains { $0.contains(secret) }
    }

    @Test("caffeinate, nohup, nice, timeout and arch run the rest of argv as a command")
    func prefixWrappers() {
        #expect(ArgumentRedactor.redact(["-i", "security", "add-generic-password", "-a", "me", "-s", "svc", "-w", "S3cret"],
                                        program: "/usr/bin/caffeinate")
                == ["-i", "security", "add-generic-password", "-a", "me", "-s", "svc", "-w", r])
        #expect(ArgumentRedactor.redact(["-t", "600", "security", "unlock-keychain", "-p", "S3cret"], program: "caffeinate")
                == ["-t", "600", "security", "unlock-keychain", "-p", r])
        #expect(ArgumentRedactor.redact(["mysql", "-pS3cret", "db"], program: "/usr/bin/nohup")
                == ["mysql", "-p\(r)", "db"])
        #expect(ArgumentRedactor.redact(["-n", "5", "mysqldump", "-pS3cret", "db"], program: "/usr/bin/nice")
                == ["-n", "5", "mysqldump", "-p\(r)", "db"])
        #expect(ArgumentRedactor.redact(["-n5", "mysqldump", "-pS3cret"], program: "nice") == ["-n5", "mysqldump", "-p\(r)"])
        #expect(ArgumentRedactor.redact(["30", "curl", "-u", "bob:S3cret", "https://h/"], program: "timeout")
                == ["30", "curl", "-u", "bob:\(r)", "https://h/"])
        #expect(ArgumentRedactor.redact(["-s", "KILL", "-k", "5", "30", "curl", "-u", "bob:S3cret", "https://h/"],
                                        program: "timeout")
                == ["-s", "KILL", "-k", "5", "30", "curl", "-u", "bob:\(r)", "https://h/"])
        #expect(ArgumentRedactor.redact(["-arm64", "sshpass", "-p", "S3cret", "ssh", "host"], program: "/usr/bin/arch")
                == ["-arm64", "sshpass", "-p", r, "ssh", "host"])
        #expect(ArgumentRedactor.redact(["-arch", "x86_64", "sshpass", "-p", "S3cret", "ssh", "host"], program: "arch")
                == ["-arch", "x86_64", "sshpass", "-p", r, "ssh", "host"])
    }

    @Test("time, command, exec, doas, sudo, chroot and script are unwrapped too")
    func morePrefixWrappers() {
        #expect(!leaks(["-p", "curl", "-u", "bob:S3cret", "https://h/"], program: "/usr/bin/time"))
        #expect(!leaks(["-p", "mysql", "-pS3cret"], program: "command"))
        #expect(!leaks(["-a", "name", "mysql", "-pS3cret"], program: "exec"))
        #expect(!leaks(["-u", "svc", "mysql", "-pS3cret"], program: "doas"))
        #expect(!leaks(["-u", "svc", "-H", "PGPASS=x", "mysql", "-pS3cret"], program: "sudo"))
        #expect(!leaks(["--user=svc", "security", "unlock-keychain", "-p", "S3cret"], program: "sudo"))
        #expect(!leaks(["-u", "svc", "/var/root/jail", "mysql", "-pS3cret"], program: "/usr/sbin/chroot"))
        #expect(!leaks(["-q", "/tmp/typescript", "mysql", "-pS3cret"], program: "/usr/bin/script"))
        #expect(!leaks(["-q", "-c", "mysql -pS3cret", "/tmp/out"], program: "script"))
        // Wrappers nest.
        #expect(!leaks(["nice", "-n", "5", "caffeinate", "-i", "mysql", "-pS3cret"], program: "nohup"))
    }

    @Test("wrappers and reserved words inside a shell -c string")
    func insideShellString() {
        for command in [
            "exec /usr/bin/security add-generic-password -a me -s svc -w S3cret",
            "time curl -u admin:S3cret https://h/",
            "nohup security unlock-keychain -p S3cret login.keychain",
            "while true; do curl -u u:S3cret x; done",
            "! mysql -pS3cret db",
        ] {
            #expect(!leaks(["-c", command], program: "/bin/sh"), "\(command)")
        }
    }

    @Test("su [flags] user -c <string> is a shell command line")
    func suDashC() {
        #expect(ArgumentRedactor.redact(["-", "svc", "-c", "mysql -pS3cret db"], program: "/usr/bin/su")
                == ["-", "svc", "-c", "mysql -p\(r) db"])
        #expect(!leaks(["-l", "svc", "--command=mysql -pS3cret"], program: "su"))
        #expect(!leaks(["svc", "-lc", "security unlock-keychain -p S3cret"], program: "su"))
        #expect(ArgumentRedactor.redact(["-", "svc"], program: "su") == ["-", "svc"])
    }

    @Test("osascript -e and interpreter -e / -c strings are redacted as command text")
    func interpreterStrings() {
        let apple = #"do shell script "security add-generic-password -a me -s svc -w S3cret""#
        #expect(!leaks(["-e", apple], program: "/usr/bin/osascript"))
        #expect(ArgumentRedactor.redact(["-e", apple], program: "osascript")
                == ["-e", #"do shell script "security add-generic-password -a me -s svc -w \#(r)""#])
        #expect(!leaks(["-e", #"system("mysql -pS3cret db")"#], program: "/usr/bin/perl"))
        #expect(!leaks(["-e", "system('curl -u bob:S3cret https://h/')"], program: "ruby"))
        #expect(!leaks(["-c", "import os; os.system('mysql -pS3cret')"], program: "/usr/bin/python3"))
        #expect(!leaks(["-c", "import os; os.system('mysql -pS3cret')"], program: "python3.12"))
        #expect(!leaks(["-e", #"require('child_process').execSync("curl -u bob:S3cret https://h/")"#], program: "node"))
        #expect(!leaks(["--eval=require('child_process').execSync('mysql -pS3cret')"], program: "node"))
        // Idempotent.
        let once = ArgumentRedactor.redact(["-e", apple], program: "osascript")
        #expect(ArgumentRedactor.redact(once, program: "osascript") == once)
    }

    @Test("ordinary arguments behind the same wrappers are untouched")
    func normalArgumentsUntouched() {
        let cases: [(String, [String])] = [
            ("caffeinate", ["-i", "make", "-j", "8", "install"]),
            ("nohup", ["rsync", "-av", "/src/", "/dst/"]),
            ("nice", ["-n", "10", "tar", "-czf", "out.tgz", "dir"]),
            ("timeout", ["30", "curl", "-sS", "https://example.com/status"]),
            ("arch", ["-arm64", "brew", "install", "jq"]),
            ("sudo", ["-u", "svc", "launchctl", "list"]),
            ("chroot", ["/jail", "/bin/ls", "-la"]),
            ("su", ["-", "svc", "-c", "ls -la /tmp"]),
            ("osascript", ["-e", #"display dialog "Hello""#]),
            ("osascript", ["-e", #"tell application "Finder" to activate"#]),
            ("python3", ["-c", "print('hello world')"]),
            ("perl", ["-e", #"print "ok\n""#]),
        ]
        for (program, argv) in cases {
            #expect(ArgumentRedactor.redact(argv, program: program) == argv, "\(program) \(argv)")
        }
    }
}
