#ifndef SERBERUS_XPC_KEYS_H
#define SERBERUS_XPC_KEYS_H

/// Shared C ↔ Swift XPC dictionary keys.
///
/// Both the daemon (Swift) and the PAM module (C) include this header
/// so the wire contract has a single source of truth. Keep these in sync with
/// `PAMXPCKey` in PrivMgrCore.

// PAM -> Daemon request
#define SERBERUS_XPC_KEY_TYPE      "type"      // "sudo" | "authuri"
#define SERBERUS_XPC_KEY_USER      "user"      // authenticating username
#define SERBERUS_XPC_KEY_COMMAND   "command"   // canonical command (sudo only)
#define SERBERUS_XPC_KEY_ARGV      "argv"      // xpc array of arg strings (sudo)
#define SERBERUS_XPC_KEY_AUTHURI   "authURI"   // right name (authuri only)
#define SERBERUS_XPC_KEY_PID       "pid"       // informational only
#define SERBERUS_XPC_KEY_TTY       "tty"       // terminal device (sudo only)

// Daemon -> PAM response
#define SERBERUS_XPC_KEY_DECISION      "decision"     // "allow" | "deny" | "prompt_pending" | "pending" | "native"
#define SERBERUS_XPC_KEY_CACHESECONDS  "cacheSeconds" // 0 = do not cache
#define SERBERUS_XPC_KEY_GRANTID       "grantID"      // UUID of created grant
#define SERBERUS_XPC_KEY_RULEID        "ruleID"       // matched rule id
#define SERBERUS_XPC_KEY_REQUEST_ID    "requestID"    // prompt round-trip ticket
#define SERBERUS_XPC_KEY_VERDICT       "verdict"      // poll deny detail (optional; absent on older daemons)

// Request type values
#define SERBERUS_XPC_TYPE_SUDO        "sudo"
#define SERBERUS_XPC_TYPE_AUTHURI     "authuri"
#define SERBERUS_XPC_TYPE_POLL_PROMPT "poll_prompt"  // PAM polls a pending prompt verdict

// Decision values
#define SERBERUS_XPC_DECISION_ALLOW          "allow"
#define SERBERUS_XPC_DECISION_DENY           "deny"
#define SERBERUS_XPC_DECISION_PROMPT_PENDING "prompt_pending" // prompt raised; poll with requestID
#define SERBERUS_XPC_DECISION_PENDING        "pending"        // poll: verdict not ready yet
#define SERBERUS_XPC_DECISION_NATIVE         "native"         // JIT admin in their window: PAM_IGNORE, not gated

// Verdict values (poll deny detail — how the prompt resolved)
#define SERBERUS_XPC_VERDICT_DENIED    "denied"     // the user declined the prompt
#define SERBERUS_XPC_VERDICT_TIMED_OUT "timed-out"  // the prompt expired unanswered

#endif /* SERBERUS_XPC_KEYS_H */
