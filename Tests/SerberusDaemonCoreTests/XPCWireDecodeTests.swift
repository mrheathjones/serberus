import Foundation
import Testing
import PrivMgrCore
import SerberusXPCShim
@testable import SerberusDaemonCore

/// Raw xpc-dictionary contract tests (XPC wire schema v1.0 — FROZEN).
///
/// These construct real xpc dictionaries with the C keys from
/// `serberus_xpc_keys.h` — exactly as `pam_serberus.c` builds them — and run
/// them through the listener's decode/encode helpers. Every key and value
/// comes from the shim header constants, never a string literal, so any drift
/// in the frozen contract breaks these tests at the source.
@Suite("XPC wire decode/encode — the frozen PAM dictionary contract")
struct XPCWireDecodeTests {

    // MARK: Message builders (mirror pam_serberus.c ask_daemon / poll)

    /// Builds a sudo request the way `pam_serberus.c` does: type=sudo, user,
    /// command, pid (int64), optional tty, and argv as an xpc array of
    /// strings that excludes the command itself.
    private func sudoMessage(
        type: String? = SERBERUS_XPC_TYPE_SUDO,
        user: String? = "tuser",
        command: String? = "/usr/bin/true",
        argv: [String]? = ["--flag", "value"],
        tty: String? = "ttys004",
        pid: Int64? = 4242
    ) -> xpc_object_t {
        let message = xpc_dictionary_create(nil, nil, 0)
        if let type { xpc_dictionary_set_string(message, SERBERUS_XPC_KEY_TYPE, type) }
        if let user { xpc_dictionary_set_string(message, SERBERUS_XPC_KEY_USER, user) }
        if let command { xpc_dictionary_set_string(message, SERBERUS_XPC_KEY_COMMAND, command) }
        if let pid { xpc_dictionary_set_int64(message, SERBERUS_XPC_KEY_PID, pid) }
        if let tty { xpc_dictionary_set_string(message, SERBERUS_XPC_KEY_TTY, tty) }
        if let argv {
            let array = xpc_array_create(nil, 0)
            for argument in argv {
                xpc_array_append_value(array, xpc_string_create(argument))
            }
            xpc_dictionary_set_value(message, SERBERUS_XPC_KEY_ARGV, array)
        }
        return message
    }

    private func authURIMessage(user: String? = "tuser", uri: String? = "system.preferences.datetime") -> xpc_object_t {
        let message = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(message, SERBERUS_XPC_KEY_TYPE, SERBERUS_XPC_TYPE_AUTHURI)
        if let user { xpc_dictionary_set_string(message, SERBERUS_XPC_KEY_USER, user) }
        if let uri { xpc_dictionary_set_string(message, SERBERUS_XPC_KEY_AUTHURI, uri) }
        return message
    }

    private func pollMessage(type: String? = SERBERUS_XPC_TYPE_POLL_PROMPT, requestID: String?) -> xpc_object_t {
        let message = xpc_dictionary_create(nil, nil, 0)
        if let type { xpc_dictionary_set_string(message, SERBERUS_XPC_KEY_TYPE, type) }
        if let requestID { xpc_dictionary_set_string(message, SERBERUS_XPC_KEY_REQUEST_ID, requestID) }
        return message
    }

    // MARK: Contract parity

    @Test("Swift PAMXPCKey constants match the C shim header (single source of truth)")
    func swiftKeysMatchShimHeader() {
        // Request keys
        #expect(PAMXPCKey.type == SERBERUS_XPC_KEY_TYPE)
        #expect(PAMXPCKey.user == SERBERUS_XPC_KEY_USER)
        #expect(PAMXPCKey.command == SERBERUS_XPC_KEY_COMMAND)
        #expect(PAMXPCKey.argv == SERBERUS_XPC_KEY_ARGV)
        #expect(PAMXPCKey.authURI == SERBERUS_XPC_KEY_AUTHURI)
        #expect(PAMXPCKey.pid == SERBERUS_XPC_KEY_PID)
        #expect(PAMXPCKey.tty == SERBERUS_XPC_KEY_TTY)
        // Response keys
        #expect(PAMXPCKey.decision == SERBERUS_XPC_KEY_DECISION)
        #expect(PAMXPCKey.cacheSeconds == SERBERUS_XPC_KEY_CACHESECONDS)
        #expect(PAMXPCKey.grantID == SERBERUS_XPC_KEY_GRANTID)
        #expect(PAMXPCKey.ruleID == SERBERUS_XPC_KEY_RULEID)
        #expect(PAMXPCKey.requestID == SERBERUS_XPC_KEY_REQUEST_ID)
        // Type values
        #expect(PAMXPCKey.typeSudo == SERBERUS_XPC_TYPE_SUDO)
        #expect(PAMXPCKey.typeAuthURI == SERBERUS_XPC_TYPE_AUTHURI)
        #expect(PAMXPCKey.typePollPrompt == SERBERUS_XPC_TYPE_POLL_PROMPT)
        // Decision values
        #expect(PAMXPCKey.decisionAllow == SERBERUS_XPC_DECISION_ALLOW)
        #expect(PAMXPCKey.decisionDeny == SERBERUS_XPC_DECISION_DENY)
        #expect(PAMXPCKey.decisionPromptPending == SERBERUS_XPC_DECISION_PROMPT_PENDING)
        #expect(PAMXPCKey.decisionPending == SERBERUS_XPC_DECISION_PENDING)
        #expect(PAMXPCKey.decisionNative == SERBERUS_XPC_DECISION_NATIVE)
    }

    // MARK: PAM request decoding

    @Test("a sudo dictionary built exactly like pam_serberus.c decodes to a typed PAMRequest")
    func sudoDecodes() {
        let request = XPCListenerService.decodePAMRequest(sudoMessage())
        #expect(request == PAMRequest(user: "tuser", kind: .sudo(
            command: "/usr/bin/true",
            argv: ["--flag", "value"],
            tty: "ttys004"
        )))
    }

    @Test("argv is preserved as a list, excludes the command, and is never flattened")
    func argvPreserved() throws {
        let argv = ["install", "--cask", "some app with spaces"]
        let request = try #require(XPCListenerService.decodePAMRequest(
            sudoMessage(command: "/opt/homebrew/bin/brew", argv: argv)
        ))
        guard case let .sudo(command, decodedArgv, _) = request.kind else {
            Issue.record("expected a sudo kind")
            return
        }
        #expect(command == "/opt/homebrew/bin/brew")
        #expect(decodedArgv == argv)
    }

    @Test("a missing or empty argv array decodes to an empty argv, not a failure")
    func argvMissingOrEmpty() throws {
        let missing = try #require(XPCListenerService.decodePAMRequest(sudoMessage(argv: nil)))
        guard case let .sudo(_, missingArgv, _) = missing.kind else {
            Issue.record("expected a sudo kind")
            return
        }
        #expect(missingArgv == [])

        let empty = try #require(XPCListenerService.decodePAMRequest(sudoMessage(argv: [])))
        guard case let .sudo(_, emptyArgv, _) = empty.kind else {
            Issue.record("expected a sudo kind")
            return
        }
        #expect(emptyArgv == [])
    }

    @Test("tty is optional on the wire")
    func ttyOptional() throws {
        let request = try #require(XPCListenerService.decodePAMRequest(sudoMessage(tty: nil)))
        guard case let .sudo(_, _, tty) = request.kind else {
            Issue.record("expected a sudo kind")
            return
        }
        #expect(tty == nil)
    }

    @Test("an authuri dictionary decodes to the authURI kind")
    func authURIDecodes() {
        let request = XPCListenerService.decodePAMRequest(authURIMessage())
        #expect(request == PAMRequest(user: "tuser", kind: .authURI("system.preferences.datetime")))
    }

    // MARK: Malformed dictionaries fail closed (decode to nil)

    @Test("missing type, user, or command fails decoding closed")
    func missingRequiredFields() {
        #expect(XPCListenerService.decodePAMRequest(sudoMessage(type: nil)) == nil)
        #expect(XPCListenerService.decodePAMRequest(sudoMessage(user: nil)) == nil)
        #expect(XPCListenerService.decodePAMRequest(sudoMessage(command: nil)) == nil)
        #expect(XPCListenerService.decodePAMRequest(authURIMessage(user: nil)) == nil)
        #expect(XPCListenerService.decodePAMRequest(authURIMessage(uri: nil)) == nil)
    }

    @Test("an unknown type value fails decoding closed")
    func unknownType() {
        #expect(XPCListenerService.decodePAMRequest(sudoMessage(type: "root_me_please")) == nil)
    }

    @Test("wrong-typed values fail decoding closed")
    func wrongTypes() {
        // user carried as an int64 instead of a string
        let badUser = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(badUser, SERBERUS_XPC_KEY_TYPE, SERBERUS_XPC_TYPE_SUDO)
        xpc_dictionary_set_int64(badUser, SERBERUS_XPC_KEY_USER, 501)
        xpc_dictionary_set_string(badUser, SERBERUS_XPC_KEY_COMMAND, "/usr/bin/true")
        #expect(XPCListenerService.decodePAMRequest(badUser) == nil)

        // argv carried as a single string instead of an array: decoding still
        // succeeds (argv is best-effort) but yields an empty argv.
        let badArgv = sudoMessage(argv: nil)
        xpc_dictionary_set_string(badArgv, SERBERUS_XPC_KEY_ARGV, "flattened args")
        let request = XPCListenerService.decodePAMRequest(badArgv)
        guard case let .sudo(_, argv, _)? = request?.kind else {
            Issue.record("expected a sudo kind")
            return
        }
        #expect(argv == [])
    }

    @Test("non-string argv members are dropped, string members survive")
    func mixedArgvMembers() throws {
        let message = sudoMessage(argv: nil)
        let array = xpc_array_create(nil, 0)
        xpc_array_append_value(array, xpc_string_create("keep-me"))
        xpc_array_append_value(array, xpc_int64_create(99))
        xpc_array_append_value(array, xpc_string_create("me-too"))
        xpc_dictionary_set_value(message, SERBERUS_XPC_KEY_ARGV, array)

        let request = try #require(XPCListenerService.decodePAMRequest(message))
        guard case let .sudo(_, argv, _) = request.kind else {
            Issue.record("expected a sudo kind")
            return
        }
        #expect(argv == ["keep-me", "me-too"])
    }

    // MARK: poll_prompt decoding

    @Test("a poll_prompt dictionary decodes to its round-trip ticket")
    func pollPromptDecodes() {
        let ticket = UUID()
        let decoded = XPCListenerService.decodePollPrompt(pollMessage(requestID: ticket.uuidString))
        #expect(decoded == ticket)
    }

    @Test("non-poll, missing-ticket, and malformed-ticket dictionaries are not polls")
    func pollPromptRejectsMalformed() {
        // A sudo request must fall through to the normal PAM path.
        #expect(XPCListenerService.decodePollPrompt(sudoMessage()) == nil)
        // poll_prompt without a ticket is unanswerable.
        #expect(XPCListenerService.decodePollPrompt(pollMessage(requestID: nil)) == nil)
        // A ticket that is not a UUID fails closed.
        #expect(XPCListenerService.decodePollPrompt(pollMessage(requestID: "not-a-uuid")) == nil)
        // Wrong type value with a valid ticket is still not a poll.
        #expect(XPCListenerService.decodePollPrompt(
            pollMessage(type: SERBERUS_XPC_TYPE_SUDO, requestID: UUID().uuidString)
        ) == nil)
    }

    // MARK: Poll verdict → reply mapping

    @Test("poll verdicts map to the PAM wire replies")
    func pollReplyMapping() {
        #expect(XPCListenerService.pollReply(for: .approved)
            == .pam(PAMResponse(decision: .allow, cacheSeconds: 0, grantID: nil, ruleID: nil)))
        // Non-approvals carry the verdict detail so PAM can say "you declined"
        // vs "timed out" instead of the misleading policy-deny message.
        #expect(XPCListenerService.pollReply(for: .denied) == .pamPromptDenied(timedOut: false))
        #expect(XPCListenerService.pollReply(for: .timedOut) == .pamPromptDenied(timedOut: true))
        #expect(XPCListenerService.pollReply(for: nil) == .pamPromptUnresolved)
    }

    @Test("a prompt deny encodes decision deny plus the verdict detail")
    func encodePromptDenied() {
        let denied = xpc_dictionary_create(nil, nil, 0)
        XPCListenerService.encode(.pamPromptDenied(timedOut: false), into: denied)
        #expect(XPCListenerService.string(denied, SERBERUS_XPC_KEY_DECISION) == SERBERUS_XPC_DECISION_DENY)
        #expect(XPCListenerService.string(denied, SERBERUS_XPC_KEY_VERDICT) == SERBERUS_XPC_VERDICT_DENIED)
        #expect(xpc_dictionary_get_int64(denied, SERBERUS_XPC_KEY_CACHESECONDS) == 0)

        let timedOut = xpc_dictionary_create(nil, nil, 0)
        XPCListenerService.encode(.pamPromptDenied(timedOut: true), into: timedOut)
        #expect(XPCListenerService.string(timedOut, SERBERUS_XPC_KEY_DECISION) == SERBERUS_XPC_DECISION_DENY)
        #expect(XPCListenerService.string(timedOut, SERBERUS_XPC_KEY_VERDICT) == SERBERUS_XPC_VERDICT_TIMED_OUT)
    }

    // MARK: Reply encoding (daemon → PAM)

    @Test("an allow response encodes decision, cacheSeconds, grantID, and ruleID")
    func encodeAllow() {
        let grantID = UUID()
        let response = xpc_dictionary_create(nil, nil, 0)
        XPCListenerService.encode(
            .pam(PAMResponse(decision: .allow, cacheSeconds: 300, grantID: grantID, ruleID: "allow-echo")),
            into: response
        )
        #expect(XPCListenerService.string(response, SERBERUS_XPC_KEY_DECISION) == SERBERUS_XPC_DECISION_ALLOW)
        // The cacheSeconds key must be present on every allow/deny reply.
        #expect(xpc_dictionary_get_value(response, SERBERUS_XPC_KEY_CACHESECONDS) != nil)
        #expect(xpc_dictionary_get_int64(response, SERBERUS_XPC_KEY_CACHESECONDS) == 300)
        #expect(XPCListenerService.string(response, SERBERUS_XPC_KEY_GRANTID) == grantID.uuidString)
        #expect(XPCListenerService.string(response, SERBERUS_XPC_KEY_RULEID) == "allow-echo")
    }

    @Test("a timedGrant response encodes as an allow on the wire")
    func encodeTimedGrantAsAllow() {
        let response = xpc_dictionary_create(nil, nil, 0)
        XPCListenerService.encode(
            .pam(PAMResponse(decision: .timedGrant, cacheSeconds: 0, grantID: UUID(), ruleID: "grant-echo")),
            into: response
        )
        #expect(XPCListenerService.string(response, SERBERUS_XPC_KEY_DECISION) == SERBERUS_XPC_DECISION_ALLOW)
    }

    @Test("a native response encodes decision native and nothing else PAM could act on")
    func encodeNative() {
        let response = xpc_dictionary_create(nil, nil, 0)
        XPCListenerService.encode(.pam(.native(ruleID: "jit-native", grantID: UUID())), into: response)
        #expect(XPCListenerService.string(response, SERBERUS_XPC_KEY_DECISION) == SERBERUS_XPC_DECISION_NATIVE)
        #expect(xpc_dictionary_get_value(response, SERBERUS_XPC_KEY_CACHESECONDS) == nil)
        #expect(xpc_dictionary_get_value(response, SERBERUS_XPC_KEY_GRANTID) == nil)
        #expect(xpc_dictionary_get_value(response, SERBERUS_XPC_KEY_REQUEST_ID) == nil)
    }

    @Test("a native response is never an allow to code that does not know about native")
    func nativeIsNotAllow() {
        let native = PAMResponse.native(ruleID: "jit-native")
        #expect(native.native)
        #expect(!native.isAllow)
        #expect(native.decision == .deny)
    }

    @Test("a deny response encodes decision deny with cacheSeconds present and zero")
    func encodeDeny() {
        let response = xpc_dictionary_create(nil, nil, 0)
        XPCListenerService.encode(.pam(.deny), into: response)
        #expect(XPCListenerService.string(response, SERBERUS_XPC_KEY_DECISION) == SERBERUS_XPC_DECISION_DENY)
        #expect(xpc_dictionary_get_value(response, SERBERUS_XPC_KEY_CACHESECONDS) != nil)
        #expect(xpc_dictionary_get_int64(response, SERBERUS_XPC_KEY_CACHESECONDS) == 0)
        // No grant, no rule → the optional keys are omitted, not empty.
        #expect(xpc_dictionary_get_value(response, SERBERUS_XPC_KEY_GRANTID) == nil)
        #expect(xpc_dictionary_get_value(response, SERBERUS_XPC_KEY_RULEID) == nil)
    }

    @Test("a prompt response encodes prompt_pending and echoes the requestID ticket")
    func encodePromptPending() {
        let ticket = UUID()
        let response = xpc_dictionary_create(nil, nil, 0)
        XPCListenerService.encode(
            .pam(PAMResponse(decision: .prompt, cacheSeconds: 0, grantID: nil, ruleID: "prompt-echo",
                             promptRequestID: ticket)),
            into: response
        )
        #expect(XPCListenerService.string(response, SERBERUS_XPC_KEY_DECISION)
            == SERBERUS_XPC_DECISION_PROMPT_PENDING)
        // PAM polls with exactly this ticket (pam_serberus.c echoes it verbatim).
        #expect(XPCListenerService.string(response, SERBERUS_XPC_KEY_REQUEST_ID) == ticket.uuidString)
    }

    @Test("a prompt response without a ticket omits requestID (PAM fails closed on it)")
    func encodePromptPendingWithoutTicket() {
        let response = xpc_dictionary_create(nil, nil, 0)
        XPCListenerService.encode(
            .pam(PAMResponse(decision: .prompt, cacheSeconds: 0, grantID: nil, ruleID: nil)),
            into: response
        )
        #expect(XPCListenerService.string(response, SERBERUS_XPC_KEY_DECISION)
            == SERBERUS_XPC_DECISION_PROMPT_PENDING)
        #expect(xpc_dictionary_get_value(response, SERBERUS_XPC_KEY_REQUEST_ID) == nil)
    }

    @Test("an unresolved poll encodes the pending decision so PAM keeps polling")
    func encodePending() {
        let response = xpc_dictionary_create(nil, nil, 0)
        XPCListenerService.encode(.pamPromptUnresolved, into: response)
        #expect(XPCListenerService.string(response, SERBERUS_XPC_KEY_DECISION) == SERBERUS_XPC_DECISION_PENDING)
    }
}
