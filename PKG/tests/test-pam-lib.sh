#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: test-pam-lib.sh
# Author: Heath Jones
# Date: 2026-07-11
# Modified: 2026-09-27
# Purpose: Shell test harness for PKG/Scripts/pam-lib.sh — the safety-critical
#          sudo_local merge/removal and break-glass preflight logic shared by
#          the Serberus installer scripts. Runs entirely against temp fixture
#          files (never /etc, never root, no system writes). The pamBypass
#          RESOLUTION helpers are smoke-tested against always-present
#          accounts (root/wheel) and then replaced with hermetic mocks so no
#          preflight test depends on this machine's accounts. Also bash -n
#          validates every script build-pam-test-pkg.sh generates (via its
#          --emit-scripts mode) plus the static PKG scripts. Runnable
#          standalone or via ./PKG/build-pam-test-pkg.sh --self-test; exits
#          nonzero on any failure.
# Version: 1.7 - Coverage for pam-lib 1.8: the plugin gate ignores a
#          user-created right carrying the marker comment and a .standin
#          record, and blocks on a pending .json, .branches or .projection
#          record, a composition row that invokes SerberusAuth, or a right
#          that delegates to a composition row; the query copies match; the bootout wait is ExitTimeOut plus 5 s; the daemon is
#          refused with no recorded team and no signed module (its own team
#          is never enough); the upgrade marker (root-only directory, mode
#          0600, a symlink replaced, never followed); the data-only purge; the
#          CLI folder chain check; ACL entries whose principal has a space
#          (users and groups, plain and inherited) are read whole, directly
#          and through the module-dir, module-path and CLI-dir checks, and a
#          line that does not parse counts as granting write.
#          1.6 - Coverage for pam-lib 1.7: a directory at the sudo_local path
#          is refused by the merge, the removal and the temp-file install
#          (also through a symlink); break-glass user entries must match the
#          record's name exactly (case and alias mismatches reported) and
#          groups must have a member (users line or primary group); the
#          post-bootout wait (serberus_launchd_wait_gone) and the plist's
#          ExitTimeOut; the recorded install team (root-owned, not writable,
#          well-formed); removal of a stray pam_serberus.so.2; the narrowed
#          AuthorizationDB residue query (SerberusAuth: mechanisms or the
#          daemon's managed marker only; the copies in uninstall.sh and
#          verify-uninstall.sh match).
#          1.5 - Coverage for pam-lib 1.6: serberus_daemon_trusted (strict,
#          Apple anchor, daemon identifier, pinned team; ad-hoc, foreign
#          team, re-identified, symlinked, missing and empty/malformed team
#          all refused) and the manual steps; a drop-in that survives its rm
#          is FAILED (status 1); failed chmod/mv leave no sudo_local temp
#          file; the 8 s window, launchd `runs` / `last exit code` / signal
#          restart detection (fresh bootstrap vs own kickstart vs no mark),
#          the pre-merge pid re-check, state.plist freshness against the
#          bootstrap mark (degraded accepted, unknown/stale/missing refused)
#          and a named-but-missing CLI.
#          1.4 - Coverage for pam-lib 1.5: sudo_local written 0444 through a
#          temp file (removal keeps the original mode); a DANGLING sudo_local
#          symlink is replaced, never written through; the read-only
#          /etc/pam.d/sudo "include sudo_local first" check; the directory
#          half of the chain check and the module lock (symlink refused);
#          the stable-pid launchd wait (mock launchctl handing out pid
#          sequences — a crash loop never counts as up) and the serberus CLI
#          health check (fresh / STALE / failing / user-owned); bounded
#          one-shots (124 on timeout); the AuthorizationDB residue check on a
#          sqlite fixture of the auth.db schema; the teardown re-arm safety
#          net.
#          1.3 - Coverage for pam-lib 1.4: sudo_local merge POSITION (a
#          Serberus line below pam_tid.so is moved above it; already-canonical
#          files stay byte-identical; user lines keep their order; duplicates
#          collapse; only a canonical template is used), the module
#          path-chain safety check on a fake root tree (stubbed ownership
#          hook + one real-stat smoke test), name-only pamBypass user
#          resolution (all-digit UIDs rejected), the same-team codesign
#          helpers and the launchd "running, not just loaded" check (mocked
#          tools). bash -n now covers every static PKG/Support script.
#          1.2 - Coverage for serberus_pam_remove_sudoers_dropin: the
#          marker-guarded, single-exact-path removal of the coarse
#          /etc/sudoers.d/serberus allowlist (absent/foreign/removed outcomes,
#          both header case variants, admin sibling untouched, anchored-header
#          guard, default-path constant).
#          1.1 - Coverage for the /usr/local/lib/pam absolute-path auth line,
#          legacy bare-name line cleanup, and the resolvable-bypass preflight
#          (typo'd pamBypass entries provide zero break-glass).
#          1.0 - Initial Script
#
######################################################################
############## End Script Information Block ##########################
######################################################################

####################################################################
############## Begin Define Variables Block ########################
####################################################################
##############################
### Core Defined Variables ###
### MODIFY AT YOUR OWN RISK ##
##############################

set -euo pipefail

export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

readonly BASENAME="/usr/bin/basename"
readonly BASH_BIN="/bin/bash"
readonly CAT="/bin/cat"
readonly CHMOD="/bin/chmod"
readonly DIRNAME="/usr/bin/dirname"
readonly GREP="/usr/bin/grep"
readonly LN="/bin/ln"
readonly LS_BIN="/bin/ls"
readonly MKDIR="/bin/mkdir"
readonly MKTEMP="/usr/bin/mktemp"
readonly RM="/bin/rm"
readonly SQLITE3="/usr/bin/sqlite3"
readonly STAT="/usr/bin/stat"

readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.7"
readonly SCRIPT_DIR=$(cd "$("${DIRNAME}" "$0")" && pwd)
readonly PKG_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

readonly PAM_LIB="${PKG_DIR}/Scripts/pam-lib.sh"
readonly BUILD_SCRIPT="${PKG_DIR}/build-pam-test-pkg.sh"
readonly REPO_DIR=$(cd "${PKG_DIR}/.." && pwd)

FIXTURES=$("${MKTEMP}" -d -t serberus-pam-lib-tests)
readonly FIXTURES
trap '"${RM}" -rf "${FIXTURES}"' EXIT

PASS_COUNT=0
FAIL_COUNT=0

##################################
### End User Defined Variables ###
##################################
####################################################################
############## End Define Variables Block ##########################
####################################################################

###################################################################################
############## Begin Function Block ###############################################
###################################################################################
##############################
### Core Defined Functions ###
### MODIFY AT YOUR OWN RISK ##
##############################

log_info() {
    printf '[INFO] %s\n' "$*"
}

log_error() {
    printf '[ERROR] %s\n' "$*" >&2
}

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    printf '[PASS] %s\n' "$*"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf '[FAIL] %s\n' "$*" >&2
}

# assert_eq <expected> <actual> <label>
assert_eq() {
    if [[ "$1" == "$2" ]]
    then
        pass "$3"
    else
        fail "$3 — expected '$1', got '$2'"
    fi
}

# assert_line_count <file> <pattern> <expected-count> <label>
assert_line_count() {
    local actual
    actual=$("${GREP}" -Ec "$2" "$1" 2>/dev/null) || actual=0
    if [[ "${actual}" -eq "$3" ]]
    then
        pass "$4"
    else
        fail "$4 — expected $3 line(s) matching '$2' in $1, got ${actual}"
    fi
}

# assert_true <label> <command...>   (asserts exit 0)
assert_true() {
    local label="$1"
    shift
    if "$@"
    then
        pass "${label}"
    else
        fail "${label} — expected success from: $*"
    fi
}

# assert_false <label> <command...>  (asserts nonzero exit)
assert_false() {
    local label="$1"
    shift
    if "$@"
    then
        fail "${label} — expected failure from: $*"
    else
        pass "${label}"
    fi
}

##################################
### End Core Defined Functions ###
##################################

########################################
######## User Defined Functions ########
### Place your script functions here ###
########################################

# write_config_plist <path> <mode-xml-or-empty> <users-xml> <groups-xml> —
# builds a config plist fixture; empty mode omits the enforcementMode key.
write_config_plist() {
    local path="$1"
    local mode_xml="$2"
    local users_xml="$3"
    local groups_xml="$4"
    {
        printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>'
        printf '%s\n' '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
        printf '%s\n' '<plist version="1.0">'
        printf '%s\n' '<dict>'
        if [[ -n "${mode_xml}" ]]
        then
            printf '    <key>enforcementMode</key>\n    %s\n' "${mode_xml}"
        fi
        if [[ -n "${users_xml}" || -n "${groups_xml}" ]]
        then
            printf '    <key>pamBypass</key>\n    <dict>\n'
            printf '        <key>users</key>\n        <array>%s</array>\n' "${users_xml}"
            printf '        <key>groups</key>\n        <array>%s</array>\n' "${groups_xml}"
            printf '    </dict>\n'
        fi
        printf '%s\n' '</dict>'
        printf '%s\n' '</plist>'
    } > "${path}"
}

test_merge_creates_absent_file() {
    local f="${FIXTURES}/sudo_local_absent"
    local result
    result=$(serberus_pam_merge_sudo_local "${f}")
    assert_eq "created" "${result}" "merge into absent file reports created"
    assert_line_count "${f}" '^[^#]*pam_serberus\.so' 1 "created file has exactly one active module line"
    assert_true "created file carries the created tag" \
        "${GREP}" -Fq "${SERBERUS_PAM_CREATED_TAG}" "${f}"

    # The auth line MUST reference the module by absolute path — a bare name
    # resolves against sealed /usr/lib/pam and dlopen-fails inside the
    # `requisite` line, bricking sudo.
    assert_true "created auth line uses the absolute module path" \
        "${GREP}" -Eq '^auth[[:space:]].*[[:space:]]/usr/local/lib/pam/pam_serberus\.so([[:space:]]|$)' "${f}"

    # Idempotency: double-run = single line, byte-identical file.
    local before after
    before=$("${CAT}" "${f}")
    result=$(serberus_pam_merge_sudo_local "${f}")
    after=$("${CAT}" "${f}")
    assert_eq "present" "${result}" "second merge reports present"
    assert_eq "${before}" "${after}" "second merge leaves file byte-identical"
    assert_line_count "${f}" '^[^#]*pam_serberus\.so' 1 "double-run still exactly one module line"
}

test_merge_creates_from_template() {
    # A CANONICAL template (the shipped Support/sudo_local shape) is copied.
    local template="${FIXTURES}/sudo_local_template"
    "${CAT}" > "${template}" <<'EOF'
# sudo_local: managed by com.herojoneslabs.serberus — do not edit
auth       requisite      /usr/local/lib/pam/pam_serberus.so # serberus-managed
EOF
    local f="${FIXTURES}/sudo_local_from_template"
    local result
    result=$(serberus_pam_merge_sudo_local "${f}" "${template}")
    assert_eq "created" "${result}" "merge with template reports created"
    assert_true "template auth line present" \
        "${GREP}" -Fq "auth       requisite      /usr/local/lib/pam/pam_serberus.so # serberus-managed" "${f}"
    assert_true "template creation stamped the created tag" \
        "${GREP}" -Fq "${SERBERUS_PAM_CREATED_TAG}" "${f}"
    assert_line_count "${f}" '^[^#]*pam_serberus\.so' 1 "template creation has one active module line"
    assert_true "file created from the canonical template is canonical" \
        serberus_pam_sudo_local_is_canonical "${f}"

    # A NON-canonical (legacy `required`, bare-name) template is ignored in
    # favour of the built-in canonical line.
    local legacy_template="${FIXTURES}/sudo_local_template_legacy"
    "${CAT}" > "${legacy_template}" <<'EOF'
# sudo_local: managed by com.herojoneslabs.serberus — do not edit
auth required pam_serberus.so
EOF
    local g="${FIXTURES}/sudo_local_from_legacy_template"
    result=$(serberus_pam_merge_sudo_local "${g}" "${legacy_template}")
    assert_eq "created" "${result}" "merge with a legacy template reports created"
    assert_false "legacy template line was NOT copied" \
        "${GREP}" -Fq "auth required pam_serberus.so" "${g}"
    assert_true "legacy template replaced by the canonical line" \
        serberus_pam_sudo_local_is_canonical "${g}"

    # The shipped template itself must be canonical.
    assert_true "Support/sudo_local (the shipped template) is canonical" \
        serberus_pam_sudo_local_is_canonical "${REPO_DIR}/Support/sudo_local"
}

test_merge_inserts_above_pam_tid() {
    local f="${FIXTURES}/sudo_local_tid"
    "${CAT}" > "${f}" <<'EOF'
# user comment kept
auth       sufficient     pam_tid.so
auth       optional       pam_example.so custom_arg
EOF
    local result
    result=$(serberus_pam_merge_sudo_local "${f}")
    assert_eq "merged" "${result}" "merge into pam_tid file reports merged"

    # Serberus line must be the FIRST auth line — above pam_tid.so, or Touch
    # ID could satisfy sudo before Serberus ever evaluates.
    local first_auth
    first_auth=$("${GREP}" -E '^[[:space:]]*auth' "${f}" | head -n 1)
    assert_true "serberus line is the first auth line" \
        "${GREP}" -q "pam_serberus.so" <(printf '%s\n' "${first_auth}")

    # Existing user lines preserved byte-identical.
    assert_true "pam_tid.so line preserved" \
        "${GREP}" -Fq "auth       sufficient     pam_tid.so" "${f}"
    assert_true "user module line preserved" \
        "${GREP}" -Fq "auth       optional       pam_example.so custom_arg" "${f}"
    assert_true "user comment preserved" \
        "${GREP}" -Fq "# user comment kept" "${f}"
    assert_false "merged pre-existing file did NOT get the created tag" \
        "${GREP}" -Fq "${SERBERUS_PAM_CREATED_TAG}" "${f}"

    # Idempotency on the merged file.
    local before after
    before=$("${CAT}" "${f}")
    result=$(serberus_pam_merge_sudo_local "${f}")
    after=$("${CAT}" "${f}")
    assert_eq "present" "${result}" "re-merge on merged file reports present"
    assert_eq "${before}" "${after}" "re-merge leaves merged file byte-identical"
    assert_line_count "${f}" '^[^#]*pam_serberus\.so' 1 "merged file has exactly one module line"
}

# OpenPAM matches the facility and control flag in any case and starts a
# comment at `#` anywhere; the merge and the canonical check must read lines
# the same way, or `AUTH sufficient pam_tid.so` stays above Serberus.
test_merge_matches_auth_case_insensitively() {
    local f="${FIXTURES}/sudo_local_upper"
    local result
    printf 'AUTH       sufficient     pam_tid.so\n' > "${f}"
    assert_false "an upper-case AUTH line above nothing is not canonical" \
        serberus_pam_sudo_local_is_canonical "${f}"
    result=$(serberus_pam_merge_sudo_local "${f}")
    assert_eq "merged" "${result}" "merge into an AUTH (upper-case) Touch ID file reports merged"
    assert_eq "${SERBERUS_PAM_AUTH_LINE}" "$(head -n 1 "${f}")" \
        "the Serberus line is inserted ABOVE the upper-case AUTH line"
    assert_true "the merged file is canonical" serberus_pam_sudo_local_is_canonical "${f}"
    assert_eq "present" "$(serberus_pam_merge_sudo_local "${f}")" "a second merge finds it canonical"

    # A mixed-case Serberus line the daemon accepts is already canonical.
    "${RM}" -f "${f}"
    printf 'Auth       REQUISITE      %s\nauth sufficient pam_tid.so\n' "${SERBERUS_PAM_MODULE_PATH}" > "${f}"
    assert_true "facility and control in any case are canonical" \
        serberus_pam_sudo_local_is_canonical "${f}"
    assert_eq "present" "$(serberus_pam_merge_sudo_local "${f}")" "a mixed-case canonical line is left alone"

    # A comment glued to the facility is a comment: `#auth` is no auth line,
    # and `auth#x` is the word auth.
    "${RM}" -f "${f}"
    printf '#auth sufficient pam_tid.so\nauth#x\n' > "${f}"
    result=$(serberus_pam_merge_sudo_local "${f}")
    assert_eq "merged" "${result}" "merge into a file with glued comments reports merged"
    assert_eq "#auth sufficient pam_tid.so" "$(head -n 1 "${f}")" "a commented auth line is not where the line goes"
    assert_eq "${SERBERUS_PAM_AUTH_LINE}" "$(sed -n 2p "${f}")" "the line goes above the first real auth line"
    "${RM}" -f "${f}"
}

# The daemon test that reads the shipped template "as the installer writes
# it" (PAMGateVerifierTests) carries the created header as a literal; it must
# be exactly what pam-lib.sh writes.
test_created_header_matches_swift_literal() {
    local swift="${REPO_DIR}/Tests/SerberusDaemonCoreTests/PAMGateVerifierTests.swift"
    assert_eq "# sudo_local: created by com.herojoneslabs.serberus # serberus-created" \
        "${SERBERUS_PAM_CREATED_HEADER}" "the created header expands as the Swift test expects"
    assert_true "the Swift test's installerCreatedHeader literal is pam-lib.sh's header" \
        "${GREP}" -Fq "static let installerCreatedHeader = \"${SERBERUS_PAM_CREATED_HEADER}\"" "${swift}"

    # Create from the shipped template: header, then the template, verbatim.
    local f="${FIXTURES}/sudo_local_created"
    "${RM}" -f "${f}"
    assert_eq "created" "$(serberus_pam_merge_sudo_local "${f}" "${REPO_DIR}/Support/sudo_local")" \
        "create from the shipped template reports created"
    assert_eq "${SERBERUS_PAM_CREATED_HEADER}" "$(head -n 1 "${f}")" "the created file starts with the header"
    assert_eq "$("${CAT}" "${REPO_DIR}/Support/sudo_local")" "$(sed 1d "${f}")" \
        "the rest of the created file is the template, verbatim"
    "${RM}" -f "${f}"
}

# The installers refuse to wire sudo_local while a file OpenPAM would read in
# its place exists — the same list the daemon's verifier refuses.
test_shadowing_policy_paths() {
    local root="${FIXTURES}/shadow-root"
    local out
    local status
    "${MKDIR}" -p "${root}"

    status=0
    out=$(serberus_pam_shadowing_policy_present "${root}") || status=$?
    assert_eq "1" "${status}" "no shadowing policy file: status 1"
    assert_eq "" "${out}" "no shadowing policy file: nothing printed"

    "${MKDIR}" -p "${root}/usr/local/etc/pam.d" "${root}/private/var/db/ManagedConfigurationFiles/com.apple.pam/etc/pam.d"
    printf 'auth required pam_permit.so\n' > "${root}/usr/local/etc/pam.d/sudo"
    "${LN}" -s "/no/such/target" "${root}/private/var/db/ManagedConfigurationFiles/com.apple.pam/etc/pam.d/sudo_local"
    status=0
    out=$(serberus_pam_shadowing_policy_present "${root}") || status=$?
    assert_eq "0" "${status}" "a shadowing policy file: status 0"
    assert_true "the /usr/local/etc file is reported" \
        "${GREP}" -qx "/usr/local/etc/pam.d/sudo" <<< "${out}"
    assert_true "a dangling symlink counts (lstat, as the daemon checks)" \
        "${GREP}" -qx "/private/var/db/ManagedConfigurationFiles/com.apple.pam/etc/pam.d/sudo_local" <<< "${out}"
    assert_eq "2" "$(printf '%s\n' "${out}" | "${GREP}" -c .)" "exactly the existing files are reported"

    # The list is the daemon's, entry for entry.
    local swift_list
    swift_list=$("${PAM_LIB_AWK}" '
        /static let defaultShadowingPolicyPaths = \[/ { on = 1; next }
        on && /^[[:space:]]*\]/ { exit }
        on { gsub(/^[[:space:]]*"|",?[[:space:]]*$/, ""); print }
    ' "${REPO_DIR}/Sources/SerberusDaemonCore/PAMGateVerifier.swift")
    assert_eq "${swift_list}" "$(printf '%s\n' "${SERBERUS_PAM_SHADOWING_POLICY_PATHS[@]}")" \
        "pam-lib.sh checks the same shadowing paths as PAMGateVerifier"

    # The production postinstall checks them, and aborts, before it
    # bootstraps the daemon or wires sudo_local.
    local postinstall="${PKG_DIR}/Scripts/postinstall"
    local check_line
    local bootstrap_line
    local wire_line
    check_line=$("${GREP}" -n '^if ! shadowing_pam_policy_absent$' "${postinstall}" | cut -d: -f1)
    bootstrap_line=$("${GREP}" -n 'bootstrap system "${LAUNCHD_PLIST}"' "${postinstall}" | head -n 1 | cut -d: -f1)
    wire_line=$("${GREP}" -n '^if ! wire_sudo_local$' "${postinstall}" | cut -d: -f1)
    assert_true "postinstall runs the shadowing check" test -n "${check_line}"
    assert_true "the shadowing check comes before the daemon bootstrap" \
        test "${check_line:-999999}" -lt "${bootstrap_line:-0}"
    assert_true "the shadowing check comes before sudo_local is wired" \
        test "${check_line:-999999}" -lt "${wire_line:-0}"
    assert_true "a shadowing file aborts the install as pam_not_wired" \
        "${GREP}" -A2 -q '^if ! shadowing_pam_policy_absent$' "${postinstall}"
    assert_eq 'abort_install "pam_not_wired"' \
        "$("${GREP}" -A2 '^if ! shadowing_pam_policy_absent$' "${postinstall}" | "${GREP}" -o 'abort_install "pam_not_wired"')" \
        "the abort reason is pam_not_wired"
    "${RM}" -rf "${root}"
}

test_merge_respects_existing_user_wiring() {
    # A user's own `requisite` wiring of the module (by its absolute path, the
    # only form that loads since the 1.1 relocation) is left exactly as written.
    # Any other control or path is rewritten; see the next test.
    local f="${FIXTURES}/sudo_local_user_wired"
    "${CAT}" > "${f}" <<'EOF'
auth requisite /usr/local/lib/pam/pam_serberus.so debug_flag
EOF
    local before after result
    before=$("${CAT}" "${f}")
    result=$(serberus_pam_merge_sudo_local "${f}")
    after=$("${CAT}" "${f}")
    assert_eq "present" "${result}" "user-wired file reports present"
    assert_eq "${before}" "${after}" "user-wired file left byte-identical"
}

test_merge_replaces_legacy_bare_name_line() {
    # A bare-name line resolves against the sealed /usr/lib/pam, where the
    # module can't exist: dlopen fails and sudo is bricked. Merging replaces it.
    local f="${FIXTURES}/sudo_local_legacy_bare"
    "${CAT}" > "${f}" <<'EOF'
auth required pam_serberus.so debug_flag
EOF
    local result
    result=$(serberus_pam_merge_sudo_local "${f}")
    assert_eq "merged" "${result}" "legacy bare-name line is merged over"
    assert_line_count "${f}" '^[^#]*[[:space:]]pam_serberus\.so([[:space:]]|$)' 0 "no bare-name module line remains"
    assert_line_count "${f}" '^[^#]*/usr/local/lib/pam/pam_serberus\.so' 1 "exactly one absolute-path module line"
}

# ---- C: merge POSITION — the Serberus line must be the FIRST active auth line ----
# A `requisite` Serberus line sitting BELOW `auth sufficient pam_tid.so` used
# to be reported `present` and left there: Touch ID then ended the chain
# before Serberus ever ran.
test_merge_moves_line_above_pam_tid() {
    local f="${FIXTURES}/sudo_local_below_tid"
    "${CAT}" > "${f}" <<'EOF'
# user header comment
auth       sufficient     pam_tid.so
auth       requisite      /usr/local/lib/pam/pam_serberus.so # serberus-managed
auth       optional       pam_example.so custom_arg
# trailing user comment
EOF
    assert_false "line below pam_tid.so is not canonical" \
        serberus_pam_sudo_local_is_canonical "${f}"
    local result
    result=$(serberus_pam_merge_sudo_local "${f}")
    assert_eq "merged" "${result}" "misplaced Serberus line reports merged (moved)"
    assert_true "moved file is canonical" serberus_pam_sudo_local_is_canonical "${f}"

    local expected
    expected=$(printf '%s\n' \
        "# user header comment" \
        "${SERBERUS_PAM_AUTH_LINE}" \
        "auth       sufficient     pam_tid.so" \
        "auth       optional       pam_example.so custom_arg" \
        "# trailing user comment")
    assert_eq "${expected}" "$("${CAT}" "${f}")" \
        "Serberus line moved above pam_tid.so; user lines preserved in order"

    # Idempotent from here on.
    local before
    before=$("${CAT}" "${f}")
    assert_eq "present" "$(serberus_pam_merge_sudo_local "${f}")" "re-merge after the move reports present"
    assert_eq "${before}" "$("${CAT}" "${f}")" "re-merge after the move is byte-identical"
}

test_merge_upgrade_below_tid_is_moved() {
    # Legacy `required` line BELOW pam_tid.so: the upgrade rewrites AND moves.
    local f="${FIXTURES}/sudo_local_legacy_below_tid"
    "${CAT}" > "${f}" <<'EOF'
auth       sufficient     pam_tid.so
auth       required       /usr/local/lib/pam/pam_serberus.so # serberus-managed
EOF
    assert_eq "merged" "$(serberus_pam_merge_sudo_local "${f}")" "legacy line below pam_tid.so reports merged"
    local first_auth
    first_auth=$("${GREP}" -E '^[[:space:]]*auth' "${f}" | head -n 1)
    assert_eq "${SERBERUS_PAM_AUTH_LINE}" "${first_auth}" "upgraded line is now the first auth line"
    assert_line_count "${f}" '^[^#]*pam_serberus\.so' 1 "exactly one active module line after the upgrade"
    assert_line_count "${f}" '^[^#]*required[^#]*pam_serberus' 0 "no required-control Serberus line remains"
    assert_true "pam_tid.so line survives the upgrade" \
        "${GREP}" -Fq "auth       sufficient     pam_tid.so" "${f}"
}

test_merge_already_canonical_untouched() {
    local f="${FIXTURES}/sudo_local_canonical"
    "${CAT}" > "${f}" <<'EOF'
# admin notes
auth       requisite      /usr/local/lib/pam/pam_serberus.so # serberus-managed
auth       sufficient     pam_tid.so
# auth required pam_serberus.so   (old, commented out by the admin)
EOF
    local before
    before=$("${CAT}" "${f}")
    assert_eq "present" "$(serberus_pam_merge_sudo_local "${f}")" "canonical file reports present"
    assert_eq "${before}" "$("${CAT}" "${f}")" "canonical file left byte-identical"
}

test_merge_replaces_symlinked_sudo_local() {
    # The daemon lstat()s sudo_local and refuses a symlink, so a canonical
    # file reached through a link is NOT present: the merge replaces the link
    # with a regular file carrying the same lines, and the target is untouched.
    local target="${FIXTURES}/sudo_local_link_target"
    local link="${FIXTURES}/sudo_local_link"
    printf '%s\n' "${SERBERUS_PAM_AUTH_LINE}" > "${target}"
    "${RM}" -f "${link}"
    "${LN}" -s "${target}" "${link}"
    assert_false "symlinked sudo_local is not canonical" serberus_pam_sudo_local_is_canonical "${link}"
    assert_eq "merged" "$(serberus_pam_merge_sudo_local "${link}")" "symlinked sudo_local reports merged"
    assert_false "sudo_local is no longer a symlink" test -L "${link}"
    assert_true "replacement is canonical" serberus_pam_sudo_local_is_canonical "${link}"
    assert_eq "${SERBERUS_PAM_AUTH_LINE}" "$("${CAT}" "${target}")" "link target left untouched"
    "${RM}" -f "${target}" "${link}"
}

test_merge_collapses_duplicates_and_keeps_comments() {
    local f="${FIXTURES}/sudo_local_duplicates"
    "${CAT}" > "${f}" <<'EOF'
auth       requisite      /usr/local/lib/pam/pam_serberus.so # serberus-managed
# auth requisite /usr/local/lib/pam/pam_serberus.so   (admin's commented copy)
auth       sufficient     pam_tid.so
auth       requisite      /usr/local/lib/pam/pam_serberus.so # serberus-managed
EOF
    assert_false "duplicate Serberus lines are not canonical" \
        serberus_pam_sudo_local_is_canonical "${f}"
    assert_eq "merged" "$(serberus_pam_merge_sudo_local "${f}")" "duplicates report merged"
    assert_line_count "${f}" '^[^#]*pam_serberus\.so' 1 "duplicates collapsed to one active line"
    assert_true "admin's commented-out Serberus line preserved" \
        "${GREP}" -Fq "# auth requisite /usr/local/lib/pam/pam_serberus.so   (admin's commented copy)" "${f}"
    assert_true "collapsed file is canonical" serberus_pam_sudo_local_is_canonical "${f}"
}

# ---- E: module path-chain safety on a FAKE root tree ----
# The ownership hook is stubbed from a table (lines "<path> <uid> <mode>";
# anything unlisted is "0 755"), so the checks run without root. Each check
# runs in a subshell so the stubs never leak into later tests.
PATH_TABLE=""

# path_check <root> <module> — runs serberus_pam_module_path_is_safe with the
# stubbed hooks; stderr (reasons) is kept in ${FIXTURES}/path_reasons.
path_check() {
    local root="$1"
    local module="$2"
    (
        serberus_pam_path_owner_mode() {
            local line
            line=$("${GREP}" -F "$1 " "${PATH_TABLE}" 2>/dev/null | head -n 1)
            if [[ -n "${line}" ]]
            then
                printf '%s' "${line#"$1 "}"
            else
                printf '0 755'
            fi
        }
        serberus_pam_make_root_dir() {
            "${MKDIR}" "$1"
        }
        serberus_pam_module_path_is_safe "${module}" "${root}"
    ) 2> "${FIXTURES}/path_reasons"
}

reasons_mention() {
    "${GREP}" -Fq "$1" "${FIXTURES}/path_reasons"
}

make_fake_root() {
    local root="$1"
    "${RM}" -rf "${root}"
    "${MKDIR}" -p "${root}/usr/local/lib/pam"
    printf 'module' > "${root}/usr/local/lib/pam/pam_serberus.so"
}

test_module_path_safety() {
    local root="${FIXTURES}/fakeroot"
    local module="${root}/usr/local/lib/pam/pam_serberus.so"
    PATH_TABLE="${FIXTURES}/path_table"
    make_fake_root "${root}"

    : > "${PATH_TABLE}"
    printf '%s 0 444\n' "${module}" >> "${PATH_TABLE}"
    assert_true "root-owned, non-writable chain is safe" path_check "${root}" "${module}"

    # Intel Homebrew layout: /usr/local/lib owned by the user.
    printf '%s 501 755\n' "${root}/usr/local/lib" >> "${PATH_TABLE}"
    assert_false "user-owned /usr/local/lib is refused" path_check "${root}" "${module}"
    assert_true "reason names the user-owned directory" reasons_mention "${root}/usr/local/lib is owned by uid 501"
    assert_true "reason explains the Homebrew fix" reasons_mention "Homebrew"

    # Group-writable /usr/local (root-owned, but its group can write).
    : > "${PATH_TABLE}"
    printf '%s 0 444\n' "${module}" >> "${PATH_TABLE}"
    printf '%s 0 775\n' "${root}/usr/local" >> "${PATH_TABLE}"
    assert_false "group-writable /usr/local is refused" path_check "${root}" "${module}"
    assert_true "reason names the writable directory" reasons_mention "group- or other-writable (mode 775)"

    # World-writable (sticky) directory.
    : > "${PATH_TABLE}"
    printf '%s 0 444\n' "${module}" >> "${PATH_TABLE}"
    printf '%s 0 1777\n' "${root}/usr/local/lib/pam" >> "${PATH_TABLE}"
    assert_false "world-writable module dir is refused" path_check "${root}" "${module}"

    # Module itself writable / not root-owned.
    : > "${PATH_TABLE}"
    printf '%s 0 666\n' "${module}" >> "${PATH_TABLE}"
    assert_false "group/other-writable module is refused" path_check "${root}" "${module}"
    : > "${PATH_TABLE}"
    printf '%s 501 444\n' "${module}" >> "${PATH_TABLE}"
    assert_false "user-owned module is refused" path_check "${root}" "${module}"

    # Symlinked directory in the chain.
    : > "${PATH_TABLE}"
    printf '%s 0 444\n' "${module}" >> "${PATH_TABLE}"
    "${RM}" -rf "${FIXTURES}/elsewhere"
    "${MKDIR}" -p "${FIXTURES}/elsewhere/pam"
    printf 'module' > "${FIXTURES}/elsewhere/pam/pam_serberus.so"
    "${RM}" -rf "${root}/usr/local/lib"
    "${LN}" -s "${FIXTURES}/elsewhere" "${root}/usr/local/lib"
    assert_false "symlinked /usr/local/lib is refused" path_check "${root}" "${module}"
    assert_true "reason says symlink" reasons_mention "is a symlink"

    # Symlinked module.
    make_fake_root "${root}"
    "${RM}" -f "${module}"
    "${LN}" -s "${FIXTURES}/elsewhere/pam/pam_serberus.so" "${module}"
    assert_false "symlinked module is refused" path_check "${root}" "${module}"

    # Missing module directory: created (stubbed hook), then the missing
    # module itself fails; once present, the chain passes.
    make_fake_root "${root}"
    "${RM}" -rf "${root}/usr/local/lib"
    : > "${PATH_TABLE}"
    printf '%s 0 444\n' "${module}" >> "${PATH_TABLE}"
    assert_false "missing module fails even after its directories are created" path_check "${root}" "${module}"
    assert_true "missing /usr/local/lib/pam was created" test -d "${root}/usr/local/lib/pam"
    printf 'module' > "${module}"
    assert_true "chain passes once the module exists" path_check "${root}" "${module}"

    # Malformed inputs.
    assert_false "relative module path is refused" path_check "" "usr/local/lib/pam/pam_serberus.so"
    assert_false "module outside the given root is refused" path_check "${root}" "/tmp/pam_serberus.so"

    # REAL ownership hook (no stub): this user's fixture tree is not
    # root-owned, so the real check must refuse it.
    make_fake_root "${root}"
    assert_false "real stat: a user-owned fixture tree is refused" \
        serberus_pam_module_path_is_safe "${module}" "${root}" 2>/dev/null
    assert_true "real hook reports the owner uid and mode" \
        test -n "$(serberus_pam_path_owner_mode "${module}")"

    "${RM}" -rf "${root}" "${FIXTURES}/elsewhere" "${PATH_TABLE}" "${FIXTURES}/path_reasons"
}

# ---- pamBypass users resolve by NAME only ----
# pam_serberus compares login names, so "501" provides no break-glass even
# though `id -u 501` succeeds. A mock dscacheutil that "finds" every name
# proves the digit check runs before (and regardless of) the lookup.

# env_resolve <dscacheutil mock> <name>
env_resolve() {
    local PAM_LIB_DSCACHEUTIL="$1"
    serberus_pam_user_resolves "$2"
}

test_user_resolver_rejects_numeric_uids() {
    local mock="${FIXTURES}/mock-dscacheutil"
    "${CAT}" > "${mock}" <<'EOF'
#! /bin/bash
printf 'name: %s\n' "${5:-x}"
EOF
    "${CHMOD}" 755 "${mock}"
    assert_false "all-digit name (a UID) never resolves, even when dscacheutil answers" \
        env_resolve "${mock}" "501"
    assert_false "UID 0 never resolves" env_resolve "${mock}" "0"
    assert_true "a name resolves when dscacheutil answers" env_resolve "${mock}" "breakglass"
    assert_false "empty name never resolves" env_resolve "${mock}" ""

    # Real dscacheutil: root resolves by name, its UID does not.
    assert_true "real resolver: root resolves by name" serberus_pam_user_resolves "root"
    assert_false "real resolver: numeric 0 is rejected" serberus_pam_user_resolves "0"

    # End to end: an enforce config whose only bypass entry is a UID is no
    # break-glass at all.
    local managed="${FIXTURES}/managed-uid.plist"
    write_config_plist "${managed}" '<string>enforce</string>' '<string>501</string>' ''
    assert_eq "0" "$(serberus_pam_resolvable_bypass_count "${managed}" 2>/dev/null)" \
        "a numeric pamBypass user resolves to zero entries"
    assert_false "preflight fails when the only bypass user is a UID" \
        serberus_pam_preflight_break_glass "${managed}"
    "${RM}" -f "${mock}" "${managed}"
}

# ---- same-team codesign helpers (mock codesign) ----
test_codesign_team_helpers() {
    local mock="${FIXTURES}/mock-codesign"
    "${CAT}" > "${mock}" <<'EOF'
#! /bin/bash
# -dv <path>: report a team unless the path contains "adhoc".
if [[ "$1" == "-dv" ]]
then
    if [[ "$2" == *adhoc* ]]
    then
        printf 'Identifier=x\nTeamIdentifier=not set\n' >&2
    else
        printf 'Identifier=x\nTeamIdentifier=ABCDE12345\n' >&2
    fi
    exit 0
fi
# --verify --strict -R <req> <path>: succeed only for the ABCDE12345 requirement.
if [[ "$1" == "--verify" && "$3" == "-R" ]]
then
    [[ "$4" == '=anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345"' ]]
    exit $?
fi
exit 2
EOF
    "${CHMOD}" 755 "${mock}"
    local PAM_LIB_CODESIGN="${mock}"
    assert_eq "ABCDE12345" "$(serberus_codesign_team_id /fake/daemon)" "team id parsed from codesign -dv"
    assert_false "ad-hoc code has no team id" serberus_codesign_team_id /fake/adhoc-daemon
    assert_true "module signed by the daemon's team satisfies the requirement" \
        serberus_codesign_satisfies_team /fake/module "ABCDE12345"
    assert_false "a different team fails the requirement" \
        serberus_codesign_satisfies_team /fake/module "ZZZZZ99999"
    assert_false "a malformed team is rejected before codesign runs" \
        serberus_codesign_satisfies_team /fake/module 'X" or anchor apple'
    "${RM}" -f "${mock}"
}

# ---- launchd liveness: loaded is not running (mock launchctl) ----
test_launchd_job_running() {
    local mock="${FIXTURES}/mock-launchctl"
    local state_file="${FIXTURES}/mock-launchctl-state"
    "${CAT}" > "${mock}" <<EOF
#! /bin/bash
case "\$(< "${state_file}")" in
    running) printf 'system/x = {\n\tstate = running\n\tpid = 4242\n\tendpoints = {\n\t\tstate = active\n\t}\n}\n' ;;
    spawn)   printf 'system/x = {\n\tstate = spawn scheduled\n\tlast exit code = 9: Killed\n\tendpoints = {\n\t\tstate = running\n\t\tpid = 1\n\t}\n}\n' ;;
    *)       exit 113 ;;
esac
EOF
    "${CHMOD}" 755 "${mock}"
    local PAM_LIB_LAUNCHCTL="${mock}"
    local PAM_LIB_SLEEP="/usr/bin/true"
    printf 'running' > "${state_file}"
    assert_true "running job with a pid is running" serberus_launchd_job_running "x"
    printf 'spawn' > "${state_file}"
    assert_false "loaded job in a kill loop (nested lines only) is NOT running" serberus_launchd_job_running "x"
    assert_false "wait gives up on a job that never runs" serberus_launchd_wait_running "x" 2 2>/dev/null
    printf 'absent' > "${state_file}"
    assert_false "unloaded job is not running" serberus_launchd_job_running "x"
    "${RM}" -f "${mock}" "${state_file}"
}


test_merge_appends_when_no_auth_line() {
    local f="${FIXTURES}/sudo_local_no_auth"
    "${CAT}" > "${f}" <<'EOF'
# only comments here
session    required       pam_example_session.so
EOF
    local result
    result=$(serberus_pam_merge_sudo_local "${f}")
    assert_eq "merged" "${result}" "merge into no-auth file reports merged"
    assert_line_count "${f}" '^[^#]*pam_serberus\.so' 1 "appended exactly one module line"
    assert_true "session line preserved" \
        "${GREP}" -Fq "session    required       pam_example_session.so" "${f}"
}

test_removal_from_merged_file() {
    local f="${FIXTURES}/sudo_local_remove_merged"
    "${CAT}" > "${f}" <<'EOF'
auth       sufficient     pam_tid.so
EOF
    serberus_pam_merge_sudo_local "${f}" >/dev/null

    local result
    result=$(serberus_pam_remove_sudo_local "${f}")
    assert_eq "cleaned" "${result}" "removal from merged file reports cleaned"
    assert_true "file kept after cleaning (we did not create it)" test -f "${f}"
    assert_line_count "${f}" 'pam_serberus' 0 "no serberus content remains"
    assert_true "pam_tid.so user line survives removal" \
        "${GREP}" -Fq "auth       sufficient     pam_tid.so" "${f}"

    # Removal is idempotent: second run reports untouched.
    result=$(serberus_pam_remove_sudo_local "${f}")
    assert_eq "untouched" "${result}" "second removal reports untouched"
}

test_removal_deletes_created_file() {
    local f="${FIXTURES}/sudo_local_remove_created"
    serberus_pam_merge_sudo_local "${f}" >/dev/null
    local result
    result=$(serberus_pam_remove_sudo_local "${f}")
    assert_eq "deleted" "${result}" "removal of created file reports deleted"
    assert_false "created file was deleted" test -e "${f}"
}

test_removal_keeps_created_file_with_user_additions() {
    local f="${FIXTURES}/sudo_local_created_then_edited"
    serberus_pam_merge_sudo_local "${f}" >/dev/null
    # The merge ships the file 0444; the admin's edit (as root, which ignores
    # the mode) is modeled by making it writable for this non-root harness.
    "${CHMOD}" u+w "${f}"
    printf 'auth       sufficient     pam_tid.so\n' >> "${f}"

    local result
    result=$(serberus_pam_remove_sudo_local "${f}")
    assert_eq "cleaned" "${result}" "created-then-edited file reports cleaned (not deleted)"
    assert_true "user addition survives" \
        "${GREP}" -Fq "auth       sufficient     pam_tid.so" "${f}"
    assert_line_count "${f}" 'pam_serberus' 0 "serberus lines gone from edited file"
}

# Pre-relocation installs wired sudo_local with a BARE module name. Removal
# must strip that legacy form too — and must NOT eat user lines whose
# trailing comments merely mention serberus.
test_removal_strips_legacy_bare_name_line() {
    local f="${FIXTURES}/sudo_local_legacy_bare_line"
    "${CAT}" > "${f}" <<'EOF'
auth       required       pam_serberus.so # serberus-managed
auth       sufficient     pam_tid.so # keep above serberus
EOF
    local result
    result=$(serberus_pam_remove_sudo_local "${f}")
    assert_eq "cleaned" "${result}" "legacy bare-name wired file reports cleaned"
    assert_line_count "${f}" 'pam_serberus' 0 "legacy bare-name module line stripped"
    assert_true "user line mentioning serberus in a comment survives" \
        "${GREP}" -Fq "auth       sufficient     pam_tid.so # keep above serberus" "${f}"
    assert_true "file kept (not created by Serberus)" test -f "${f}"
}

test_removal_handles_legacy_create_if_absent_file() {
    # The pre-1.1 production postinstall / Support/sudo_local shape: managed
    # header, no marker tags. Must still be recognized as ours and deleted.
    local f="${FIXTURES}/sudo_local_legacy"
    "${CAT}" > "${f}" <<'EOF'
# sudo_local: managed by com.herojoneslabs.serberus — do not edit
auth required pam_serberus.so
EOF
    local result
    result=$(serberus_pam_remove_sudo_local "${f}")
    assert_eq "deleted" "${result}" "legacy create-if-absent file deleted"
    assert_false "legacy file gone" test -e "${f}"
}

test_removal_absent_and_foreign_files() {
    local result
    result=$(serberus_pam_remove_sudo_local "${FIXTURES}/never_existed")
    assert_eq "absent" "${result}" "removal on absent path reports absent"

    local f="${FIXTURES}/sudo_local_foreign"
    "${CAT}" > "${f}" <<'EOF'
auth       sufficient     pam_tid.so
EOF
    local before after
    before=$("${CAT}" "${f}")
    result=$(serberus_pam_remove_sudo_local "${f}")
    after=$("${CAT}" "${f}")
    assert_eq "untouched" "${result}" "foreign file reports untouched"
    assert_eq "${before}" "${after}" "foreign file left byte-identical"
}

test_has_module_detection() {
    local f="${FIXTURES}/sudo_local_commented"
    "${CAT}" > "${f}" <<'EOF'
# auth required pam_serberus.so   (disabled)
auth       sufficient     pam_tid.so
EOF
    assert_false "commented-out module line does not count as wired" \
        serberus_pam_sudo_local_has_module "${f}"
    assert_false "missing file does not count as wired" \
        serberus_pam_sudo_local_has_module "${FIXTURES}/never_existed"
}

# Smoke-test the REAL resolvers against accounts every macOS box has, BEFORE
# the hermetic mocks replace them. root/wheel always exist; the bogus names
# cannot.
test_real_resolvers() {
    assert_true "real resolver: user root resolves" \
        serberus_pam_user_resolves "root"
    assert_false "real resolver: bogus user does not resolve" \
        serberus_pam_user_resolves "serberus-no-such-user-fixture"
    assert_true "real resolver: group wheel resolves" \
        serberus_pam_group_resolves "wheel"
    assert_false "real resolver: bogus group does not resolve" \
        serberus_pam_group_resolves "serberus-no-such-group-fixture"
}

# Hermetic resolver mocks — pam-lib.sh documents these functions as
# overridable precisely so the preflight tests never depend on the accounts
# of the machine running them. ONLY these fixture names resolve.
install_resolver_mocks() {
    serberus_pam_user_resolves() {
        [[ "$1" == "breakglass" || "$1" == "alpha" ]]
    }
    serberus_pam_group_resolves() {
        [[ "$1" == "admin" ]]
    }
    log_info "Hermetic resolver mocks installed (users: breakglass, alpha; groups: admin)"
}

# A4: a non-empty pamBypass whose entries resolve to NO real user/group is
# zero break-glass — the preflight must treat it as no-bypass.
test_preflight_resolvable_bypass() {
    local managed="${FIXTURES}/managed.plist"
    "${RM}" -f "${managed}"

    # Typo'd user only ("brekglass") => raw count 1, resolvable 0 => FAIL.
    write_config_plist "${managed}" '<string>enforce</string>' '<string>brekglass</string>' ''
    assert_eq "1" "$(serberus_pam_bypass_count "${managed}")" \
        "typo'd bypass still counts as a raw string member"
    assert_eq "0" "$(serberus_pam_resolvable_bypass_count "${managed}" 2>/dev/null)" \
        "typo'd bypass resolves to zero entries"
    assert_false "preflight fails on enforce with only an unresolvable bypass user" \
        serberus_pam_preflight_break_glass "${managed}"

    # Each unresolvable entry is reported on stderr for the caller to log.
    local notes
    notes=$(serberus_pam_resolvable_bypass_count "${managed}" 2>&1 >/dev/null)
    assert_true "unresolvable user is reported by name on stderr" \
        "${GREP}" -q 'user "brekglass"' <(printf '%s\n' "${notes}")

    # Typo'd group only => FAIL.
    write_config_plist "${managed}" '<string>enforce</string>' '' '<string>adminz</string>'
    assert_false "preflight fails on enforce with only an unresolvable bypass group" \
        serberus_pam_preflight_break_glass "${managed}"
    notes=$(serberus_pam_resolvable_bypass_count "${managed}" 2>&1 >/dev/null)
    assert_true "unresolvable group is reported by name on stderr" \
        "${GREP}" -q 'group "adminz"' <(printf '%s\n' "${notes}")

    # One typo'd user + one REAL group => resolvable 1 => PASS.
    write_config_plist "${managed}" '<string>enforce</string>' '<string>brekglass</string>' '<string>admin</string>'
    assert_eq "1" "$(serberus_pam_resolvable_bypass_count "${managed}" 2>/dev/null)" \
        "mixed bypass counts only the resolvable entry"
    assert_true "preflight passes when at least one bypass entry resolves" \
        serberus_pam_preflight_break_glass "${managed}"

    # Both real => resolvable 2, nothing on stderr.
    write_config_plist "${managed}" '<string>enforce</string>' '<string>breakglass</string>' '<string>admin</string>'
    assert_eq "2" "$(serberus_pam_resolvable_bypass_count "${managed}" 2>/dev/null)" \
        "fully resolvable bypass counts every entry"
    notes=$(serberus_pam_resolvable_bypass_count "${managed}" 2>&1 >/dev/null)
    assert_eq "" "${notes}" "no stderr reports when every entry resolves"

    "${RM}" -f "${managed}"
}

test_preflight_failures() {
    local managed="${FIXTURES}/managed.plist"

    # Absent config (no managed plist) => enforce + no bypass => FAIL.
    "${RM}" -f "${managed}"
    assert_false "preflight fails on absent config" \
        serberus_pam_preflight_break_glass "${managed}"

    # enforce + no pamBypass key => FAIL.
    write_config_plist "${managed}" '<string>enforce</string>' '' ''
    assert_false "preflight fails on enforce with no bypass" \
        serberus_pam_preflight_break_glass "${managed}"

    # enforce + EMPTY pamBypass arrays => FAIL.
    write_config_plist "${managed}" '<string>enforce</string>' ' ' ' '
    assert_false "preflight fails on enforce with empty bypass arrays" \
        serberus_pam_preflight_break_glass "${managed}"

    # Unknown mode string is enforce (fail closed) => FAIL without bypass.
    write_config_plist "${managed}" '<string>observe</string>' '' ''
    assert_false "preflight fails on unknown mode with no bypass" \
        serberus_pam_preflight_break_glass "${managed}"

    # Mistyped mode (integer) => enforce => FAIL without bypass.
    write_config_plist "${managed}" '<integer>1</integer>' '' ''
    assert_false "preflight fails on mistyped mode with no bypass" \
        serberus_pam_preflight_break_glass "${managed}"

    # Non-string bypass members are filtered like pam_config.c: an array of
    # one integer counts zero => FAIL under enforce.
    write_config_plist "${managed}" '<string>enforce</string>' '<integer>42</integer>' ''
    assert_false "preflight fails when bypass has only non-string members" \
        serberus_pam_preflight_break_glass "${managed}"

    # Garbage plist => unparseable => enforce + no bypass => FAIL.
    printf 'not a plist\n' > "${managed}"
    assert_false "preflight fails on garbage plist" \
        serberus_pam_preflight_break_glass "${managed}"

    "${RM}" -f "${managed}"
}

test_preflight_passes() {
    local managed="${FIXTURES}/managed.plist"
    "${RM}" -f "${managed}"

    # monitor passes with no bypass.
    write_config_plist "${managed}" '<string>monitor</string>' '' ''
    assert_true "preflight passes on monitor" \
        serberus_pam_preflight_break_glass "${managed}"

    # audit passes with no bypass.
    write_config_plist "${managed}" '<string>audit</string>' '' ''
    assert_true "preflight passes on audit" \
        serberus_pam_preflight_break_glass "${managed}"

    # enforce + populated users passes.
    write_config_plist "${managed}" '<string>enforce</string>' '<string>breakglass</string>' ''
    assert_true "preflight passes on enforce with bypass user" \
        serberus_pam_preflight_break_glass "${managed}"

    # enforce + populated groups passes.
    write_config_plist "${managed}" '<string>enforce</string>' '' '<string>admin</string>'
    assert_true "preflight passes on enforce with bypass group" \
        serberus_pam_preflight_break_glass "${managed}"

    # Absent mode key + populated bypass passes (enforce default, bypass set).
    write_config_plist "${managed}" '' '<string>breakglass</string>' ''
    assert_true "preflight passes on default mode with bypass user" \
        serberus_pam_preflight_break_glass "${managed}"

    "${RM}" -f "${managed}"
}

# serberus_pam_config_present mirrors pam_config.c's serberus_config_is_present:
# an ABSENT config (no delivered key) must be distinguishable from a PRESENT
# config whose values equal the fail-safe defaults. That distinction is what
# lets the preinstall abort ONLY on the genuine brick (config PRESENT + enforce
# + a bypass list in which nothing resolves), not on the survivable
# awaiting-config / enrollment-race case.
test_config_present() {
    local managed="${FIXTURES}/managed.plist"
    "${RM}" -f "${managed}"

    assert_false "config_present false when the managed plist is missing" \
        serberus_pam_config_present "${managed}"

    write_config_plist "${managed}" '<string>enforce</string>' '' ''
    assert_true "config_present true when the managed plist carries enforcementMode" \
        serberus_pam_config_present "${managed}"

    write_config_plist "${managed}" '' '<string>breakglass</string>' ''
    assert_true "config_present true when the managed plist carries only pamBypass" \
        serberus_pam_config_present "${managed}"

    # A plist that EXISTS but carries NONE of the known config keys => ABSENT
    # (the enrollment-race / unrelated-plist case must not read as configured).
    {
        printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>'
        printf '%s\n' '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
        printf '%s\n' '<plist version="1.0"><dict><key>unrelatedKey</key><integer>1</integer></dict></plist>'
    } > "${managed}"
    assert_false "config_present false when the plist has no known config key" \
        serberus_pam_config_present "${managed}"

    "${RM}" -f "${managed}"
}

# pam_serberus reads only the managed plist, so the preflight must too: a
# break-glass account or pass-through mode set only in root's own preferences
# (`defaults write`) does nothing at sudo time and must not satisfy the check.
test_preflight_ignores_unmanaged_config() {
    local managed="${FIXTURES}/managed.plist"
    local unmanaged="${FIXTURES}/unmanaged.plist"
    "${RM}" -f "${managed}" "${unmanaged}"

    write_config_plist "${unmanaged}" '<string>monitor</string>' '<string>breakglass</string>' '<string>admin</string>'
    assert_eq "enforce" "$(serberus_pam_effective_mode "${managed}" "${unmanaged}")" \
        "an unmanaged monitor mode is ignored"
    assert_eq "0" "$(serberus_pam_bypass_count "${managed}" "${unmanaged}")" \
        "an unmanaged bypass list is ignored"
    assert_false "config_present ignores an unmanaged plist" \
        serberus_pam_config_present "${managed}" "${unmanaged}"
    assert_false "preflight fails when only an unmanaged plist carries break-glass" \
        serberus_pam_preflight_break_glass "${managed}" "${unmanaged}"

    # A mistyped mode in the managed plist fails closed.
    write_config_plist "${managed}" '<integer>1</integer>' '' ''
    assert_eq "enforce" "$(serberus_pam_effective_mode "${managed}")" \
        "mistyped managed mode fails closed"

    # Bypass count only counts string members across both arrays.
    write_config_plist "${managed}" '<string>enforce</string>' \
        '<string>alpha</string><integer>7</integer>' '<string>admin</string>'
    assert_eq "2" "$(serberus_pam_bypass_count "${managed}")" \
        "bypass count filters non-string members"

    "${RM}" -f "${managed}" "${unmanaged}"
}

# The coarse sudoers drop-in removal: marker-guarded, scoped to ONE exact path.
# A teardown must remove it unconditionally and BEFORE the fine PAM gate, but
# it must NEVER delete a same-named admin-authored file (marker guard) and must
# never touch any sibling /etc/sudoers.d entry (single exact path).
test_sudoers_dropin_removal() {
    local dir="${FIXTURES}/sudoersd"
    "${RM}" -rf "${dir}"
    mkdir -p "${dir}"

    # Absent path => absent, nothing done.
    assert_eq "absent" "$(serberus_pam_remove_sudoers_dropin "${dir}/never_existed")" \
        "removal on absent drop-in reports absent"

    # A file with NO Serberus managed header (an admin's own same-named file)
    # is preserved byte-identical.
    local foreign="${dir}/foreign"
    "${CAT}" > "${foreign}" <<'EOF'
# an admin's own /etc/sudoers.d/serberus, hand-authored
%staff ALL=(ALL) NOPASSWD: /usr/bin/whoami
EOF
    local before
    before=$("${CAT}" "${foreign}")
    assert_eq "foreign" "$(serberus_pam_remove_sudoers_dropin "${foreign}")" \
        "unmarked admin file reports foreign"
    assert_true "unmarked admin file preserved" test -f "${foreign}"
    assert_eq "${before}" "$("${CAT}" "${foreign}")" "unmarked admin file left byte-identical"

    # The uppercase "DO NOT EDIT" header (SudoersGenerator.defaultHeader) is
    # recognized => removed.
    local ours="${dir}/serberus"
    "${CAT}" > "${ours}" <<'EOF'
# /etc/sudoers.d/serberus: managed by com.herojoneslabs.serberus — DO NOT EDIT
%serberus ALL=(root) /usr/bin/softwareupdate # serberus-managed
EOF
    assert_eq "removed" "$(serberus_pam_remove_sudoers_dropin "${ours}")" \
        "marked drop-in (DO NOT EDIT header) reports removed"
    assert_false "marked drop-in deleted" test -e "${ours}"

    # The lowercase "do not edit" header (BundleConfig.sudoersManagedHeader)
    # variant is recognized too => removed.
    local ours_lc="${dir}/serberus_lc"
    "${CAT}" > "${ours_lc}" <<'EOF'
# /etc/sudoers.d/serberus: managed by com.herojoneslabs.serberus — do not edit
%serberus ALL=(root) /usr/bin/softwareupdate # serberus-managed
EOF
    assert_eq "removed" "$(serberus_pam_remove_sudoers_dropin "${ours_lc}")" \
        "marked drop-in (do-not-edit header) reports removed"
    assert_false "lowercase-header drop-in deleted" test -e "${ours_lc}"

    # Only our exact path: our marked file next to an admin sibling in the same
    # dir; removing ours must leave the sibling untouched (no glob, no dir).
    local mine="${dir}/serberus"
    local sibling="${dir}/90-admin-custom"
    "${CAT}" > "${mine}" <<'EOF'
# /etc/sudoers.d/serberus: managed by com.herojoneslabs.serberus — DO NOT EDIT
%serberus ALL=(root) /usr/bin/softwareupdate # serberus-managed
EOF
    "${CAT}" > "${sibling}" <<'EOF'
%admins ALL=(ALL) ALL
EOF
    assert_eq "removed" "$(serberus_pam_remove_sudoers_dropin "${mine}")" \
        "removing our drop-in reports removed"
    assert_false "our drop-in gone" test -e "${mine}"
    assert_true "sibling admin drop-in untouched" test -f "${sibling}"

    # The guard is ANCHORED to the first-line managed header: a file that only
    # mentions the domain in some other comment is NOT ours => preserved.
    local mention="${dir}/mention"
    "${CAT}" > "${mention}" <<'EOF'
# admin note: replaces com.herojoneslabs.serberus for team X
%team ALL=(ALL) ALL
EOF
    assert_eq "foreign" "$(serberus_pam_remove_sudoers_dropin "${mention}")" \
        "domain mentioned off the managed-header anchor does not count as marked"
    assert_true "domain-mention file preserved" test -f "${mention}"

    # Default path constant tracks the shipped Swift BundleConfig path.
    assert_eq "/etc/sudoers.d/serberus" "${SERBERUS_SUDOERS_PATH}" \
        "default drop-in path constant is /etc/sudoers.d/serberus"

    "${RM}" -rf "${dir}"
}

# ---- pam-lib 1.5: sudo_local modes + dangling symlink ----
# Created/merged files are written 0444 through a temp file; removal keeps the
# original mode; a DANGLING sudo_local symlink is replaced, never written
# through to its target.
test_merge_modes_and_dangling_symlink() {
    local f="${FIXTURES}/sudo_local_mode_created"
    "${RM}" -f "${f}"
    serberus_pam_merge_sudo_local "${f}" >/dev/null
    assert_eq "444" "$("${STAT}" -f '%Lp' "${f}")" "created sudo_local is 0444"

    local merged="${FIXTURES}/sudo_local_mode_merged"
    printf 'auth       sufficient     pam_tid.so\n' > "${merged}"
    "${CHMOD}" 644 "${merged}"
    assert_eq "merged" "$(serberus_pam_merge_sudo_local "${merged}")" "merge into a 0644 file reports merged"
    assert_eq "444" "$("${STAT}" -f '%Lp' "${merged}")" "merged sudo_local is 0444"

    local cleaned="${FIXTURES}/sudo_local_mode_cleaned"
    printf 'auth       sufficient     pam_tid.so\n%s\n' "${SERBERUS_PAM_AUTH_LINE}" > "${cleaned}"
    "${CHMOD}" 640 "${cleaned}"
    assert_eq "cleaned" "$(serberus_pam_remove_sudo_local "${cleaned}")" "removal from a 0640 file reports cleaned"
    assert_eq "640" "$("${STAT}" -f '%Lp' "${cleaned}")" "removal keeps the original mode (0640)"

    local link="${FIXTURES}/sudo_local_dangling"
    local target="${FIXTURES}/dangling-target/should-not-exist"
    "${RM}" -rf "${FIXTURES}/dangling-target" "${link}"
    "${MKDIR}" -p "${FIXTURES}/dangling-target"
    "${LN}" -s "${target}" "${link}"
    assert_true "fixture: sudo_local is a dangling symlink" test -L "${link}"
    assert_eq "created" "$(serberus_pam_merge_sudo_local "${link}")" "dangling symlink: merge reports created"
    assert_false "dangling symlink replaced by a regular file" test -L "${link}"
    assert_true "replacement is canonical" serberus_pam_sudo_local_is_canonical "${link}"
    assert_false "the symlink's target was NOT written through" test -e "${target}"

    "${RM}" -rf "${f}" "${merged}" "${cleaned}" "${link}" "${FIXTURES}/dangling-target"
}

# ---- a DIRECTORY at the sudo_local path is refused, never written into ----
# awk reads a directory as empty and `mv tmp dir` drops the file inside it,
# so without the guard the merge would report `merged` and leave a stray
# sudo_local.serberus-*.<pid> in the directory.
test_sudo_local_directory_refused() {
    local dir="${FIXTURES}/sudo_local_is_a_dir"
    "${RM}" -rf "${dir}"
    "${MKDIR}" -p "${dir}"
    local status=0
    local result
    result=$(serberus_pam_merge_sudo_local "${dir}") || status=$?
    assert_eq "FAILED" "${result}" "directory at sudo_local: merge prints FAILED"
    assert_eq "1" "${status}" "directory at sudo_local: merge returns 1"
    assert_eq "" "$("${LS_BIN}" -A "${dir}")" "directory at sudo_local: nothing written inside it"

    status=0
    result=$(serberus_pam_remove_sudo_local "${dir}") || status=$?
    assert_eq "FAILED" "${result}" "directory at sudo_local: removal prints FAILED"
    assert_eq "1" "${status}" "directory at sudo_local: removal returns 1"
    assert_eq "" "$("${LS_BIN}" -A "${dir}")" "directory at sudo_local: removal wrote nothing inside it"

    local link="${FIXTURES}/sudo_local_link_to_dir"
    "${RM}" -f "${link}"
    "${LN}" -s "${dir}" "${link}"
    status=0
    result=$(serberus_pam_merge_sudo_local "${link}") || status=$?
    assert_eq "FAILED" "${result}" "symlink to a directory at sudo_local: merge prints FAILED"
    assert_eq "" "$("${LS_BIN}" -A "${dir}")" "symlink to a directory: nothing written through it"

    local tmp="${FIXTURES}/sudo_local_install_temp"
    printf 'x\n' > "${tmp}"
    assert_false "install_temp refuses a directory target" \
        serberus_pam_install_temp "${tmp}" "${dir}" 444
    assert_false "install_temp removes its temp file after refusing" test -e "${tmp}"
    assert_eq "" "$("${LS_BIN}" -A "${dir}")" "install_temp moved nothing into the directory"
    "${RM}" -rf "${dir}" "${link}" "${tmp}"
}

# ---- break-glass names: exact user names, groups with members ----
# Directory lookups are case-insensitive and alias-aware, but pam_serberus
# compares the exact login name; a group bypasses nobody unless a member is an
# existing account. The fixture directory is the one the C tests
# (PAMConfigTests) and the daemon tests (StartupCoordinatorTests) use.
test_bypass_exact_names_and_group_members() {
    local mock="${FIXTURES}/mock-dscacheutil-records"
    "${CAT}" > "${mock}" <<'MOCK_EOF'
#! /bin/bash
# $2 = user|group, $4 = name|uid, $5 = value
case "$2:$4:$5" in
    user:name:breakglass) printf 'name: breakglass\npassword: ********\nuid: 502\n' ;;
    user:name:BreakGlass) printf 'name: breakglass\npassword: ********\nuid: 502\n' ;;
    user:name:bg-alias)   printf 'name: breakglass\npassword: ********\nuid: 502\n' ;;
    user:name:itadmin)    printf 'name: itadmin\npassword: ********\nuid: 503\n' ;;
    user:uid:502)         printf 'name: breakglass\npassword: ********\nuid: 502\n' ;;
    group:name:emergency) printf 'name: emergency\npassword: *\ngid: 610\nusers: breakglass \n' ;;
    group:name:mixed)     printf 'name: mixed\npassword: *\ngid: 620\nusers: deleted-user itadmin\n' ;;
    group:name:stale)     printf 'name: stale\npassword: *\ngid: 621\nusers: deleted-user\n' ;;
    group:name:cased)     printf 'name: cased\npassword: *\ngid: 622\nusers: BreakGlass\n' ;;
    group:name:empty)     printf 'name: empty\npassword: *\ngid: 611\n' ;;
    group:name:blank)     printf 'name: blank\npassword: *\ngid: 612\nusers: \n' ;;
    group:name:primary)   printf 'name: primary\npassword: *\ngid: 613\n' ;;
    group:name:uuidonly)  printf 'name: uuidonly\npassword: *\ngid: 614\n' ;;
    group:name:UuidOnly)  printf 'name: uuidonly\npassword: *\ngid: 614\n' ;;
    group:name:compat)    printf 'name: compat\npassword: *\ngid: 623\n' ;;
    group:name:grpuuid)   printf 'name: grpuuid\npassword: *\ngid: 624\n' ;;
    group:name:ghostuuid) printf 'name: ghostuuid\npassword: *\ngid: 625\n' ;;
    group:name:nobody)    printf 'name: nobody\npassword: *\ngid: -2\n' ;;
esac
exit 0
MOCK_EOF
    local dscl_mock="${FIXTURES}/mock-dscl-primary"
    "${CAT}" > "${dscl_mock}" <<'MOCK_EOF'
#! /bin/bash
# Primary groups come from the search policy (what getpwent enumerates), the
# same accounts pam_config.c and the daemon scan. GroupMembers and
# GeneratedUID searches answer only for the fixture records.
[[ "$1" == "/Search" ]] || exit 1
case "$2:$3:$4:${5:-}" in
    -list:/Users:PrimaryGroupID:)
        printf 'breakglass               502\nsomeone                  613\n_ftp                     -2\n' ;;
    -read:/Groups/uuidonly:GroupMembers:)
        printf 'GroupMembers:\n 11111111-2222-3333-4444-555555555555 A1B2C3D4-0000-1111-2222-333344445555\n' ;;
    -read:/Groups/compat:GroupMembers:)
        printf 'GroupMembers: FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001F6\n' ;;
    -read:/Groups/grpuuid:GroupMembers:)
        printf 'GroupMembers: ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000050\n' ;;
    -read:/Groups/ghostuuid:GroupMembers:)
        printf 'GroupMembers: FFFFEEEE-DDDD-CCCC-BBBB-AAAA00000999 11111111-2222-3333-4444-555555555555\n' ;;
    -read:/Groups/*:GroupMembers:)
        printf 'No such key: GroupMembers\n' >&2 ;;
    -search:/Users:GeneratedUID:A1B2C3D4-0000-1111-2222-333344445555)
        printf 'itadmin\t\tGeneratedUID = (\n    "A1B2C3D4-0000-1111-2222-333344445555"\n)\n' ;;
esac
exit 0
MOCK_EOF
    "${CHMOD}" 755 "${mock}" "${dscl_mock}"
    local PAM_LIB_DSCACHEUTIL="${mock}"
    local PAM_LIB_DSCL="${dscl_mock}"
    local status

    status=0
    serberus_pam_user_resolves "breakglass" || status=$?
    assert_eq "0" "${status}" "user whose record name matches exactly resolves"
    status=0
    serberus_pam_user_resolves "BreakGlass" || status=$?
    assert_eq "2" "${status}" "user found only by case is a mismatch (status 2)"
    assert_eq "breakglass" "${SERBERUS_PAM_RESOLVED_NAME}" "the mismatch reports the real account name"
    status=0
    serberus_pam_user_resolves "bg-alias" || status=$?
    assert_eq "2" "${status}" "user found only by alias is a mismatch (status 2)"
    status=0
    serberus_pam_user_resolves "nobody-here" || status=$?
    assert_eq "1" "${status}" "unknown user does not resolve (status 1)"

    # group name : expected status : why
    local row
    local group
    local expected
    local why
    for row in \
        "emergency:0:a listed name that is an existing account counts" \
        "mixed:0:one existing account among stale names counts" \
        "stale:2:a deleted account's name left in the group is not a member" \
        "cased:2:a listed name that matches an account only by case is not a member" \
        "empty:2:no users line, no GroupMembers and no primary members is empty" \
        "blank:2:a blank users line is empty" \
        "primary:0:an account's primary group counts" \
        "uuidonly:0:a GroupMembers GeneratedUID of an existing account counts" \
        "UuidOnly:0:GroupMembers is read under the record's canonical name" \
        "compat:0:a compatibility UUID counts when its uid is an account" \
        "grpuuid:2:a group's UUID in GroupMembers is not a member" \
        "ghostuuid:2:UUIDs that name no account are not members" \
        "nobody:2:a negative gid never counts by primary group" \
        "no-such-group:1:an unknown group does not resolve"
    do
        group="${row%%:*}"
        expected="${row#*:}"
        why="${expected#*:}"
        expected="${expected%%:*}"
        status=0
        serberus_pam_group_resolves "${group}" || status=$?
        assert_eq "${expected}" "${status}" "group ${group}: ${why}"
    done

    assert_true "GeneratedUID of a user record resolves" \
        serberus_pam_generated_uid_resolves "a1b2c3d4-0000-1111-2222-333344445555"
    assert_false "a malformed GeneratedUID never resolves" \
        serberus_pam_generated_uid_resolves "not-a-uuid"

    local managed="${FIXTURES}/managed-names.plist"
    write_config_plist "${managed}" '<string>enforce</string>' '<string>BreakGlass</string>' '<string>empty</string><string>stale</string>'
    assert_eq "0" "$(serberus_pam_resolvable_bypass_count "${managed}" 2>/dev/null)" \
        "a case-mismatched user, an empty group and a stale group are zero break-glass"
    local notes
    notes=$(serberus_pam_resolvable_bypass_count "${managed}" 2>&1 >/dev/null)
    assert_true "the case mismatch is reported with the real account name" \
        "${GREP}" -q 'user "BreakGlass" matches account "breakglass" only by case or alias' <<< "${notes}"
    assert_true "the empty group is reported" \
        "${GREP}" -q 'group "empty" exists but has no members' <<< "${notes}"
    assert_true "the stale group is reported" \
        "${GREP}" -q 'group "stale" exists but has no members' <<< "${notes}"
    assert_false "preflight fails when the only entries are a case mismatch and memberless groups" \
        serberus_pam_preflight_break_glass "${managed}" 2>/dev/null

    write_config_plist "${managed}" '<string>enforce</string>' '<string>breakglass</string>' ''
    assert_true "preflight passes with the exact user name" \
        serberus_pam_preflight_break_glass "${managed}"
    write_config_plist "${managed}" '<string>enforce</string>' '' '<string>emergency</string>'
    assert_true "preflight passes with a group that has a member" \
        serberus_pam_preflight_break_glass "${managed}"
    write_config_plist "${managed}" '<string>enforce</string>' '' '<string>uuidonly</string>'
    assert_true "preflight passes with a group whose only member is recorded by GeneratedUID" \
        serberus_pam_preflight_break_glass "${managed}"
    "${RM}" -f "${managed}" "${mock}" "${dscl_mock}"
}

# ---- break-glass names are compared byte for byte ----
# pam_serberus and the daemon look up and compare each pamBypass entry
# exactly: nothing is trimmed, a newline does not split an entry, and an
# entry containing U+0000 never resolves. The preflight must agree, or it
# passes a profile the module and the daemon then refuse.
test_bypass_names_byte_exact() {
    local mock="${FIXTURES}/mock-dscacheutil-exact"
    "${CAT}" > "${mock}" <<'MOCK_EOF'
#! /bin/bash
# Only the exact names answer: any trimming or splitting would find them.
case "$2:$4:$5" in
    user:name:breakglass) printf 'name: breakglass\npassword: ********\nuid: 502\n' ;;
    group:name:admin)     printf 'name: admin\npassword: *\ngid: 80\nusers: breakglass\n' ;;
    group:name:emergency) printf 'name: emergency\npassword: *\ngid: 610\nusers: breakglass\n' ;;
esac
exit 0
MOCK_EOF
    "${CHMOD}" 755 "${mock}"
    local PAM_LIB_DSCACHEUTIL="${mock}"
    local PAM_LIB_DSCL="/usr/bin/false"
    local managed="${FIXTURES}/managed-exact.plist"
    local users_xml
    local notes

    # Leading, trailing and inner whitespace; a trailing newline; a newline
    # that would, if split, add the group "emergency".
    users_xml='<string> breakglass</string><string>breakglass </string><string>break glass</string>'
    users_xml+=$'<string>breakglass\n</string><string>\tbreakglass</string>'
    users_xml+=$'<string>nobody\ngroups emergency</string>'
    write_config_plist "${managed}" '<string>enforce</string>' "${users_xml}" '<string> admin</string>'
    assert_eq "7" "$(serberus_pam_bypass_count "${managed}")" "every string entry counts as a raw member"
    assert_eq "0" "$(serberus_pam_resolvable_bypass_count "${managed}" 2>/dev/null)" \
        "whitespace and newlines are never trimmed or split: zero break-glass"
    assert_false "preflight fails when every entry differs from a real name by whitespace" \
        serberus_pam_preflight_break_glass "${managed}" 2>/dev/null

    # The pairs themselves carry the exact bytes.
    local kind
    local name
    local -a seen=()
    while IFS= read -r -d '' kind && IFS= read -r -d '' name
    do
        seen+=("${kind}=${name}")
    done < <(serberus_pam_bypass_entries "${managed}")
    assert_eq "7" "${#seen[@]}" "one entry per plist string, none split"
    assert_eq "users= breakglass" "${seen[0]}" "a leading space is kept"
    assert_eq $'users=breakglass\n' "${seen[3]}" "a trailing newline is kept"
    assert_eq $'users=nobody\ngroups emergency' "${seen[5]}" "an inner newline does not split the entry"
    assert_eq "groups= admin" "${seen[6]:-}" "a group's leading space is kept"

    # U+0000: a C string would end there, so "breakglass<NUL>x" would read as
    # "breakglass". The module and the daemon refuse it; so does the preflight.
    write_config_plist "${managed}" '<string>enforce</string>' '<string>breakglass&#0;x</string>' '<string>admin&#0;</string>'
    assert_eq "0" "$(serberus_pam_resolvable_bypass_count "${managed}" 2>/dev/null)" \
        "entries containing a NUL never resolve"
    notes=$(serberus_pam_resolvable_bypass_count "${managed}" 2>&1 >/dev/null)
    assert_true "the NUL entry is reported" \
        "${GREP}" -q 'users entry "breakglass…" contains a NUL character' <<< "${notes}"
    assert_true "the NUL group entry is reported" \
        "${GREP}" -q 'groups entry "admin…" contains a NUL character' <<< "${notes}"
    assert_false "preflight fails when the only entries contain NUL" \
        serberus_pam_preflight_break_glass "${managed}" 2>/dev/null

    # Control: the exact names pass.
    write_config_plist "${managed}" '<string>enforce</string>' '<string>breakglass</string>' '<string>admin</string>'
    assert_eq "2" "$(serberus_pam_resolvable_bypass_count "${managed}" 2>/dev/null)" \
        "the exact names resolve"
    "${RM}" -f "${managed}" "${mock}"
}

# ---- after a bootout, wait until launchd has dropped the job ----
test_launchd_wait_gone() {
    local mock="${FIXTURES}/mock-launchctl-gone"
    local calls="${FIXTURES}/mock-launchctl-gone-calls"
    local loaded_for="${FIXTURES}/mock-launchctl-gone-n"
    "${CAT}" > "${mock}" <<MOCK_EOF
#! /bin/bash
count=\$(( \$(/bin/cat "${calls}" 2>/dev/null || printf 0) + 1 ))
printf '%s' "\${count}" > "${calls}"
if [[ "\${count}" -le "\$(/bin/cat "${loaded_for}")" ]]
then
    printf 'system/x = {\n\tstate = running\n}\n'
    exit 0
fi
exit 113
MOCK_EOF
    "${CHMOD}" 755 "${mock}"
    local PAM_LIB_LAUNCHCTL="${mock}"
    local PAM_LIB_SLEEP="/usr/bin/true"

    printf '0' > "${loaded_for}"
    : > "${calls}"
    assert_true "wait_gone: a job already gone returns at once" serberus_launchd_wait_gone "x" 5
    assert_eq "1" "$(< "${calls}")" "wait_gone: one launchctl print when already gone"

    printf '3' > "${loaded_for}"
    : > "${calls}"
    assert_true "wait_gone: a job that goes within the timeout" serberus_launchd_wait_gone "x" 5
    assert_eq "4" "$(< "${calls}")" "wait_gone: polled until the job was gone"

    printf '99' > "${loaded_for}"
    : > "${calls}"
    assert_false "wait_gone: a job still loaded after the timeout fails" \
        serberus_launchd_wait_gone "x" 5 2>/dev/null
    assert_eq "6" "$(< "${calls}")" "wait_gone: gives up after the timeout (one poll per second)"
    assert_eq "20" "${SERBERUS_DAEMON_EXIT_TIMEOUT}" "the daemon's ExitTimeOut is 20 s"
    assert_eq "25" "${SERBERUS_DAEMON_BOOTOUT_WAIT}" "the default wait is the ExitTimeOut plus 5 s"
    assert_eq "20" "$(/usr/libexec/PlistBuddy -c 'Print :ExitTimeOut' "${REPO_DIR}/Support/com.herojoneslabs.serberus.daemon.plist" 2>/dev/null)" \
        "the LaunchDaemon plist states the same ExitTimeOut (20)"
    "${RM}" -f "${mock}" "${calls}" "${loaded_for}"
}

# ---- the install-time team recorded in version.plist ----
test_recorded_team() {
    local plist="${FIXTURES}/version-team.plist"
    "${CAT}" > "${plist}" <<'MOCK_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>daemonVersion</key><string>0.9.0</string>
    <key>installTeamID</key><string>ABCDE12345</string>
</dict>
</plist>
MOCK_EOF
    OWNER_MODE="0 644"
    assert_eq "ABCDE12345" "$(recorded_team_as "${plist}")" \
        "recorded team: read from a root-owned version.plist"
    OWNER_MODE="501 644"
    assert_false "recorded team: a version.plist not owned by root is ignored" \
        recorded_team_as "${plist}"
    OWNER_MODE="0 666"
    assert_false "recorded team: a group/other-writable version.plist is ignored" \
        recorded_team_as "${plist}"
    OWNER_MODE="0 644"
    /usr/bin/plutil -replace installTeamID -string "not-a-team" "${plist}"
    assert_false "recorded team: a malformed team is ignored" recorded_team_as "${plist}"
    /usr/bin/plutil -remove installTeamID "${plist}"
    assert_false "recorded team: no key, no team (callers fall back)" recorded_team_as "${plist}"
    local link="${FIXTURES}/version-team-link.plist"
    "${LN}" -sf "${plist}" "${link}"
    assert_false "recorded team: a symlinked version.plist is ignored" recorded_team_as "${link}"
    assert_false "recorded team: a missing version.plist gives no team" \
        recorded_team_as "${FIXTURES}/no-such-version.plist"
    assert_eq "/Library/Application Support/Serberus/version.plist" "${SERBERUS_VERSION_PLIST}" \
        "recorded team: default path is the installed version.plist"
    "${RM}" -f "${plist}" "${link}"
}

# recorded_team_as <plist> — serberus_recorded_team with the ownership hook
# stubbed to OWNER_MODE ("<uid> <mode>"), so no root is needed.
recorded_team_as() {
    (
        serberus_pam_path_owner_mode() {
            printf '%s' "${OWNER_MODE}"
        }
        serberus_recorded_team "$1"
    )
}

# ---- OpenPAM loads <module>.2 first: installers remove a stray one ----
test_remove_versioned_module() {
    local dir="${FIXTURES}/versioned-module"
    "${RM}" -rf "${dir}"
    "${MKDIR}" -p "${dir}"
    local path="${dir}/pam_serberus.so.2"
    assert_eq "absent" "$(serberus_pam_remove_versioned_module "${path}")" "no .so.2: absent"
    printf 'x' > "${path}"
    assert_eq "removed" "$(serberus_pam_remove_versioned_module "${path}")" "a stray .so.2 is removed"
    assert_false "the stray .so.2 is gone" test -e "${path}"
    "${LN}" -s "${FIXTURES}/nowhere.so" "${path}"
    assert_eq "removed" "$(serberus_pam_remove_versioned_module "${path}")" "a dangling .so.2 link is removed"
    assert_false "the .so.2 link is gone" test -L "${path}"
    "${MKDIR}" -p "${path}"
    local status=0
    serberus_pam_remove_versioned_module "${path}" >/dev/null || status=$?
    assert_eq "1" "${status}" "a directory at .so.2 is FAILED (status 1)"
    assert_eq "${SERBERUS_PAM_MODULE_PATH}.2" "${SERBERUS_PAM_MODULE_VERSIONED_PATH}" \
        "the default path is the module path plus .2"
    "${RM}" -rf "${dir}"
}

# ---- /etc/pam.d/sudo must include sudo_local FIRST (read-only check) ----
test_pam_sudo_includes_sudo_local() {
    local f="${FIXTURES}/pam_sudo"
    "${CAT}" > "${f}" <<'EOF'
# sudo: auth account password session
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
EOF
    assert_true "Apple's stock /etc/pam.d/sudo includes sudo_local first" \
        serberus_pam_sudo_includes_sudo_local "${f}"

    "${CAT}" > "${f}" <<'EOF'
# sudo: auth account password session
auth       sufficient     pam_smartcard.so
auth       include        sudo_local
auth       required       pam_opendirectory.so
EOF
    assert_false "sudo_local included AFTER another auth module is refused" \
        serberus_pam_sudo_includes_sudo_local "${f}" 2>/dev/null

    "${CAT}" > "${f}" <<'EOF'
#auth      include        sudo_local
auth       required       pam_opendirectory.so
EOF
    assert_false "commented-out include is refused" serberus_pam_sudo_includes_sudo_local "${f}" 2>/dev/null
    assert_false "missing /etc/pam.d/sudo is refused" \
        serberus_pam_sudo_includes_sudo_local "${FIXTURES}/no-such-pam-sudo" 2>/dev/null
    "${RM}" -f "${f}"
}

# ---- directory half of the chain check + module lock ----
# The directory check runs BEFORE root chowns/chmods the module; it does not
# look at the module at all. The lock refuses a symlinked module.
test_module_dir_check_and_lock() {
    local root="${FIXTURES}/fakeroot-dir"
    local module="${root}/usr/local/lib/pam/pam_serberus.so"
    PATH_TABLE="${FIXTURES}/path_table_dir"
    make_fake_root "${root}"
    "${RM}" -f "${module}"
    : > "${PATH_TABLE}"
    assert_true "directory check passes with the module still missing" \
        dir_check "${root}" "${module}"
    printf '%s 501 755\n' "${root}/usr/local/lib" >> "${PATH_TABLE}"
    assert_false "directory check refuses a user-owned /usr/local/lib" dir_check "${root}" "${module}"

    "${LN}" -s "${FIXTURES}/nowhere.so" "${module}"
    assert_false "lock refuses a symlinked module (no chown/chmod through it)" \
        serberus_pam_lock_module "${module}" 2>/dev/null
    "${RM}" -f "${module}"
    assert_false "lock refuses a missing module" serberus_pam_lock_module "${module}" 2>/dev/null
    "${RM}" -rf "${root}" "${PATH_TABLE}"
}

# dir_check <root> <module> — serberus_pam_module_dir_is_safe with the same
# stubbed ownership hooks as path_check.
dir_check() {
    local root="$1"
    local module="$2"
    (
        serberus_pam_path_owner_mode() {
            local line
            line=$("${GREP}" -F "$1 " "${PATH_TABLE}" 2>/dev/null | head -n 1)
            if [[ -n "${line}" ]]
            then
                printf '%s' "${line#"$1 "}"
            else
                printf '0 755'
            fi
        }
        serberus_pam_make_root_dir() {
            "${MKDIR}" "$1"
        }
        serberus_pam_module_dir_is_safe "${module}" "${root}"
    ) 2>/dev/null
}

# ---- launchd: the SAME pid must hold ~3 s; the CLI must report fresh ----
# The mock launchctl hands out pids from a sequence file, one per `print`;
# the last line repeats forever.
test_launchd_stable_pid() {
    local mock="${FIXTURES}/mock-launchctl-seq"
    local seq_file="${FIXTURES}/mock-launchctl-pids"
    local calls="${FIXTURES}/mock-launchctl-calls"
    "${CAT}" > "${mock}" <<EOF
#! /bin/bash
count=\$(( \$(/bin/cat "${calls}" 2>/dev/null || printf 0) + 1 ))
printf '%s' "\${count}" > "${calls}"
pid=\$(/usr/bin/sed -n "\${count}p" "${seq_file}")
if [[ -z "\${pid}" ]]
then
    pid=\$(/usr/bin/tail -n 1 "${seq_file}")
fi
if [[ "\${pid}" == "none" ]]
then
    printf 'system/x = {\n\tstate = spawn scheduled\n}\n'
    exit 0
fi
printf 'system/x = {\n\tstate = running\n\tpid = %s\n}\n' "\${pid}"
EOF
    "${CHMOD}" 755 "${mock}"
    local PAM_LIB_LAUNCHCTL="${mock}"
    local PAM_LIB_SLEEP="/usr/bin/true"

    printf '100\n100\n100\n100\n' > "${seq_file}"
    : > "${calls}"
    assert_true "one pid held across the stability window counts as up" \
        serberus_launchd_wait_running "x" 5

    # A respawn loop: a new pid at every poll — "running" every time, never up.
    local i
    : > "${seq_file}"
    for ((i = 1; i <= 40; i++))
    do
        printf '%s\n' "$((200 + i))" >> "${seq_file}"
    done
    : > "${calls}"
    assert_false "a changing pid (crash/AMFI kill loop) never counts as up" \
        serberus_launchd_wait_running "x" 5 2>/dev/null

    # Flapping first, then stable: the window restarts and then passes.
    printf '301\nnone\n302\n303\n303\n303\n303\n' > "${seq_file}"
    : > "${calls}"
    assert_true "the stability window restarts on a new pid, then passes" \
        serberus_launchd_wait_running "x" 10

    printf '100\n' > "${seq_file}"
    : > "${calls}"
    assert_eq "100" "$(serberus_launchd_job_pid "x")" "job pid parsed from launchctl print"
    "${RM}" -f "${mock}" "${seq_file}" "${calls}"
}

# The CLI health check runs `serberus status` only from a root-only chain
# (ownership hook stubbed to "root, 0755") and needs a fresh, non-STALE state.
test_cli_health_check() {
    # Physical path: /var is a symlink on macOS, and the check refuses any
    # symlinked directory above the CLI.
    local dir
    dir="$(cd -P "${FIXTURES}" && pwd)/cli-bin"
    local cli="${dir}/serberus"
    "${MKDIR}" -p "${dir}"
    local PAM_LIB_SLEEP="/usr/bin/true"
    local status=0
    (
        serberus_pam_path_owner_mode() {
            printf '0 755'
        }
        printf '#! /bin/bash\nprintf "Serberus daemon status:\\n  State            healthy\\n"\n' > "${cli}"
        "${CHMOD}" 755 "${cli}"
        serberus_cli_health_ok "${cli}"
    ) 2>/dev/null || status=$?
    assert_eq "0" "${status}" "a fresh serberus status passes the health check"

    status=0
    (
        serberus_pam_path_owner_mode() {
            printf '0 755'
        }
        printf '#! /bin/bash\nprintf "  Updated          2026-01-01T00:00:00Z (9h — STALE)\\n"\n' > "${cli}"
        serberus_cli_health_ok "${cli}"
    ) 2>/dev/null || status=$?
    assert_eq "1" "${status}" "a STALE state fails the health check"

    status=0
    (
        serberus_pam_path_owner_mode() {
            printf '0 755'
        }
        printf '#! /bin/bash\nexit 1\n' > "${cli}"
        serberus_cli_health_ok "${cli}"
    ) 2>/dev/null || status=$?
    assert_eq "1" "${status}" "serberus status exit 1 (no state.plist) fails the health check"

    status=0
    (
        serberus_pam_path_owner_mode() {
            printf '501 755'
        }
        printf '#! /bin/bash\nexit 0\n' > "${cli}"
        serberus_cli_health_ok "${cli}"
    ) 2>/dev/null || status=$?
    assert_eq "1" "${status}" "a user-owned CLI is never executed as root"
    "${RM}" -rf "${dir}"
}

# ---- bounded one-shots ----
test_run_bounded() {
    local status=0
    serberus_run_bounded 5 /usr/bin/true || status=$?
    assert_eq "0" "${status}" "bounded: a quick command returns its own status (0)"
    status=0
    serberus_run_bounded 5 /bin/sh -c 'exit 3' || status=$?
    assert_eq "3" "${status}" "bounded: a failing command returns its own status (3)"
    status=0
    serberus_run_bounded 1 /bin/sleep 30 2>/dev/null || status=$?
    assert_eq "124" "${status}" "bounded: a hung command is killed and reported as 124"
}

# ---- AuthorizationDB residue check (sqlite fixture of the auth.db schema) ----
test_authdb_free_of_serberus() {
    local db="${FIXTURES}/auth.db"
    local backups="${FIXTURES}/authdb-backups"
    "${RM}" -f "${db}"
    "${RM}" -rf "${backups}"
    "${SQLITE3}" "${db}" <<'EOF'
CREATE TABLE rules (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, type INTEGER, class INTEGER, "group" TEXT, kofn INTEGER, timeout REAL, flags INTEGER, tries INTEGER, version INTEGER, created REAL, modified REAL, hash BLOB, identifier TEXT, requirement BLOB, comment TEXT);
CREATE TABLE mechanisms (id INTEGER PRIMARY KEY, plugin TEXT NOT NULL, param TEXT NOT NULL, privileged INTEGER NOT NULL DEFAULT 0);
CREATE TABLE mechanisms_map (r_id INTEGER NOT NULL, m_id INTEGER NOT NULL, ord INTEGER NOT NULL);
CREATE TABLE delegates_map (r_id INTEGER NOT NULL, d_id INTEGER NOT NULL, ord INTEGER NOT NULL);
INSERT INTO rules (id, name, "group", comment) VALUES (1, 'system.preferences', 'admin', 'Checked by the Admin framework');
INSERT INTO mechanisms (id, plugin, param) VALUES (1, 'builtin', 'authenticate');
INSERT INTO mechanisms_map VALUES (1, 1, 0);
EOF
    assert_true "a native AuthorizationDB is free of Serberus" serberus_authdb_free_of_serberus "${db}" "${backups}"

    # The marker comment proves nothing: any user can write it
    # (config.add.* is class=allow).
    "${SQLITE3}" "${db}" "INSERT INTO rules (id, name, comment) VALUES (2, 'x.custom', 'Serberus projection (require admin). Managed by serberusd; do not edit.');"
    assert_true "a user-created right carrying the marker comment does not block removal" \
        serberus_authdb_free_of_serberus "${db}" "${backups}"
    "${SQLITE3}" "${db}" "INSERT INTO rules (id, name, \"group\", identifier, comment) VALUES (3, 'config.add.serberus-note', 'serberus', 'com.example.serberus', 'about serberus');"
    assert_true "a user-created right that only mentions serberus is not residue" \
        serberus_authdb_free_of_serberus "${db}" "${backups}"

    # A composition row that invokes SerberusAuth blocks (plugin name
    # compared without regard to case, never as a prefix).
    "${SQLITE3}" "${db}" "INSERT INTO rules (id, name) VALUES (4, 'com.herojoneslabs.serberus.branch.system.preferences.com.example.app'); INSERT INTO mechanisms (id, plugin, param) VALUES (2, 'SerberusAuth', 'identity'); INSERT INTO mechanisms_map VALUES (4, 2, 0);"
    assert_false "a branch row that invokes SerberusAuth blocks removal" \
        serberus_authdb_free_of_serberus "${db}" "${backups}" 2>/dev/null
    "${SQLITE3}" "${db}" "UPDATE mechanisms SET plugin = 'serberusauth' WHERE id = 2;"
    assert_false "the SerberusAuth plugin name is matched without regard to case" \
        serberus_authdb_free_of_serberus "${db}" "${backups}" 2>/dev/null
    "${SQLITE3}" "${db}" "UPDATE mechanisms SET plugin = 'SerberusAuthExtra' WHERE id = 2;"
    assert_true "a plugin that merely starts with SerberusAuth is not residue" \
        serberus_authdb_free_of_serberus "${db}" "${backups}"
    "${SQLITE3}" "${db}" "DELETE FROM mechanisms_map WHERE r_id = 4; UPDATE mechanisms SET plugin = 'SerberusAuth' WHERE id = 2; INSERT INTO mechanisms_map VALUES (2, 2, 0);"
    assert_true "a right outside the composition prefix that names SerberusAuth does not block" \
        serberus_authdb_free_of_serberus "${db}" "${backups}"
    "${SQLITE3}" "${db}" "DELETE FROM mechanisms_map WHERE r_id = 2;"

    # A right that delegates to a composition row blocks.
    "${SQLITE3}" "${db}" "INSERT INTO delegates_map VALUES (1, 4, 0);"
    assert_false "a right that delegates to a composition row blocks removal" \
        serberus_authdb_free_of_serberus "${db}" "${backups}" 2>/dev/null
    "${SQLITE3}" "${db}" "DELETE FROM delegates_map;"
    assert_true "an unreferenced composition row without SerberusAuth does not block" \
        serberus_authdb_free_of_serberus "${db}" "${backups}"

    # Pending records block; a .standin does not.
    "${MKDIR}" -p "${backups}"
    : > "${backups}/system.preferences.standin"
    assert_true "a .standin record does not block removal" \
        serberus_authdb_free_of_serberus "${db}" "${backups}"
    assert_false "a .standin alone is nothing to restore" \
        serberus_authdb_records_pending "${backups}"
    local suffix
    for suffix in json branches projection
    do
        : > "${backups}/system.preferences.${suffix}"
        assert_false "a .${suffix} record blocks removal" \
            serberus_authdb_free_of_serberus "${db}" "${backups}" 2>/dev/null
        assert_true "a .${suffix} record is pending" \
            serberus_authdb_records_pending "${backups}"
        "${RM}" -f "${backups}/system.preferences.${suffix}"
    done
    "${CHMOD}" 000 "${backups}"
    assert_false "a backups folder that cannot be listed is never treated as clean" \
        serberus_authdb_free_of_serberus "${db}" "${backups}" 2>/dev/null
    "${CHMOD}" 755 "${backups}"
    assert_true "a missing backups folder holds nothing" \
        serberus_authdb_free_of_serberus "${db}" "${FIXTURES}/no-such-backups"

    # Every copy of the query is the same.
    local query_copy
    query_copy=$("${GREP}" -o '"SELECT DISTINCT r.name FROM rules.*;"' "${PKG_DIR}/Scripts/uninstall.sh")
    assert_eq "\"${SERBERUS_AUTHDB_QUERY}\"" "${query_copy}" \
        "uninstall.sh FALLBACK_AUTHDB_QUERY matches pam-lib.sh SERBERUS_AUTHDB_QUERY"
    query_copy=$("${GREP}" -o '"SELECT DISTINCT r.name FROM rules r JOIN.*;"' "${PKG_DIR}/verify-uninstall.sh")
    assert_eq "\"${SERBERUS_AUTHDB_QUERY}\"" "${query_copy}" \
        "verify-uninstall.sh query matches pam-lib.sh SERBERUS_AUTHDB_QUERY"
    assert_false "the gate never uses the marker comment" \
        "${GREP}" -q 'Managed by serberusd' <<< "${SERBERUS_AUTHDB_QUERY}"
    assert_true "the composition-row prefix in the query is AuthURIIdentityScope.rowPrefix" \
        "${GREP}" -qF 'rowPrefix = "com.herojoneslabs.serberus.branch."' \
        "${REPO_DIR}/Sources/PrivMgrCore/Policy/AuthURIIdentityScope.swift"

    assert_false "an unreadable database is never treated as clean" \
        serberus_authdb_free_of_serberus "${FIXTURES}/no-such-auth.db" "${backups}" 2>/dev/null
    printf 'not a database' > "${db}"
    assert_false "an unqueryable database is never treated as clean" \
        serberus_authdb_free_of_serberus "${db}" "${backups}" 2>/dev/null
    "${RM}" -f "${db}"
    "${RM}" -rf "${backups}"
}

# acl_check_listing <entry>… — serberus_pam_path_acl_grants_write on a real
# path with the `ls -led` hook stubbed: a mode line, then each <entry> on its
# own line, written as ls prints one (" N: <principal>[ inherited]
# <allow|deny> <perms>"). Prints what the check prints; returns its status.
acl_check_listing() {
    local -a entries=("$@")
    (
        serberus_pam_path_acl_listing() {
            printf 'drwxr-xr-x+ 3 root  wheel  96 Sep 27 09:00 %s\n' "$1"
            printf '%s\n' "${entries[@]}"
        }
        serberus_pam_path_acl_grants_write "${FIXTURES}"
    )
}

# acl_listing_grants <entry>… — the same, status only.
acl_listing_grants() {
    acl_check_listing "$@" > /dev/null
}

# with_acl_entry <path> <entry> <command…> — runs <command…> with the
# `ls -led` hook stubbed: <path> lists <entry> after its mode line, every
# other path lists no ACL.
with_acl_entry() {
    local acl_path="$1"
    local acl_entry="$2"
    shift 2
    (
        serberus_pam_path_acl_listing() {
            if [[ "$1" == "${acl_path}" ]]
            then
                printf 'drwxr-xr-x+ 3 root  wheel  96 Sep 27 09:00 %s\n%s\n' "$1" "${acl_entry}"
            else
                printf 'drwxr-xr-x  3 root  wheel  96 Sep 27 09:00 %s\n' "$1"
            fi
        }
        "$@"
    )
}

# ---- root-only checks are ACL-aware (real chmod +a on scratch paths) ----
test_root_locked_acl() {
    local dir="${FIXTURES}/acl-check"
    "${RM}" -rf "${dir}"
    "${MKDIR}" -p "${dir}/d" "${dir}/inherit"
    : > "${dir}/f"
    local status=0
    (
        serberus_pam_path_owner_mode() {
            printf '0 755'
        }
        serberus_pam_path_is_root_locked "${dir}/d" "directory"
    ) || status=$?
    assert_eq "0" "${status}" "ACL: a directory with no ACL passes (mode and owner modelled as root 755)"

    "${CHMOD}" +a "everyone allow add_file" "${dir}/d"
    status=0
    (
        serberus_pam_path_owner_mode() {
            printf '0 755'
        }
        serberus_pam_path_is_root_locked "${dir}/d" "directory"
    ) 2>/dev/null || status=$?
    assert_eq "1" "${status}" "ACL: an allow add_file entry for everyone fails the root-only check"
    assert_true "ACL: the refusal names the ACL entry" \
        "${GREP}" -q 'group:everyone allow add_file' <<< "$(
            serberus_pam_path_owner_mode() { printf '0 755'; }
            serberus_pam_path_is_root_locked "${dir}/d" "directory" 2>&1
        )"

    "${CHMOD}" +a "staff deny write,delete" "${dir}/f"
    assert_false "ACL: a deny entry grants nothing" serberus_pam_path_acl_grants_write "${dir}/f"
    "${CHMOD}" +a "user:root allow write,chown" "${dir}/f"
    assert_false "ACL: an allow entry for user:root is fine" serberus_pam_path_acl_grants_write "${dir}/f"
    "${CHMOD}" +a "staff allow readattr,readsecurity" "${dir}/f"
    assert_false "ACL: an allow entry without a write permission is fine" serberus_pam_path_acl_grants_write "${dir}/f"
    local perm
    for perm in write append delete writesecurity chown
    do
        "${CHMOD}" -N "${dir}/f"
        "${CHMOD}" +a "staff allow ${perm}" "${dir}/f"
        assert_true "ACL: allow ${perm} for a group is refused" serberus_pam_path_acl_grants_write "${dir}/f"
    done
    "${CHMOD}" -N "${dir}/d"
    for perm in add_subdirectory delete_child
    do
        "${CHMOD}" -N "${dir}/d"
        "${CHMOD}" +a "$(/usr/bin/id -un) allow ${perm}" "${dir}/d"
        assert_true "ACL: allow ${perm} for a user other than root is refused" serberus_pam_path_acl_grants_write "${dir}/d"
    done
    "${CHMOD}" +a "everyone allow add_file,file_inherit,directory_inherit,only_inherit" "${dir}/inherit"
    assert_true "ACL: an inherit-only entry counts" serberus_pam_path_acl_grants_write "${dir}/inherit"
    "${MKDIR}" "${dir}/inherit/child"
    assert_true "ACL: an inherited entry counts" serberus_pam_path_acl_grants_write "${dir}/inherit/child"
    assert_false "ACL: a missing path has no ACL" serberus_pam_path_acl_grants_write "${dir}/missing"
    (
        serberus_pam_path_acl_listing() {
            return 1
        }
        serberus_pam_path_acl_grants_write "${dir}/f" > /dev/null
    ) && status=0 || status=$?
    assert_eq "0" "${status}" "ACL: an ACL that cannot be read counts as granting write"

    # ls prints a principal's name as is, spaces included, so an entry is
    # read from the right (stubbed listings, written as ls prints them).
    local entry
    for entry in \
        ' 0: group:CORP\Domain Users allow add_file,delete_child' \
        ' 0: group:Mac Developers inherited allow write,add_file' \
        ' 0: user:CORP\jane doe allow add_subdirectory' \
        ' 0: user:jane doe inherited allow delete_child,file_inherit,directory_inherit'
    do
        assert_true "ACL: a spaced principal is read whole and refused (${entry# })" \
            acl_listing_grants "${entry}"
    done
    assert_eq '1: group:CORP\Domain Users allow add_file' \
        "$(acl_check_listing ' 0: user:root allow write,chown' ' 1: group:CORP\Domain Users allow add_file')" \
        "ACL: the refusal names the whole spaced entry, after an allow for user:root"
    assert_false "ACL: a deny entry for a spaced principal grants nothing" \
        acl_listing_grants ' 0: group:CORP\Domain Users deny add_file,delete_child'
    assert_false "ACL: an inherited deny entry for a spaced principal grants nothing" \
        acl_listing_grants ' 0: group:Mac Developers inherited deny write,add_file'
    assert_false "ACL: an allow without a write permission for a spaced principal is fine" \
        acl_listing_grants ' 0: user:CORP\jane doe allow list,search,readattr,readsecurity'
    assert_false "ACL: an allow entry for user:root is fine (listing)" \
        acl_listing_grants ' 0: user:root allow write,delete,chown'
    assert_false "ACL: an inherited allow entry for user:root is fine" \
        acl_listing_grants ' 0: user:root inherited allow add_file,delete_child,file_inherit'
    assert_true "ACL: a user named 'root admin' is not user:root" \
        acl_listing_grants ' 0: user:root admin allow add_file'
    assert_true "ACL: a user named 'root ' (trailing space) is not user:root" \
        acl_listing_grants ' 0: user:root  allow write'

    # A line that does not parse counts as granting write, and is printed.
    for entry in \
        ' 0: group:staff allow' \
        ' 0: group:staff unknown add_file' \
        ' 0:' \
        'group:staff allow add_file'
    do
        assert_true "ACL: a line that does not parse counts as write ('${entry}')" \
            acl_listing_grants "${entry}"
    done
    assert_eq '0: group:staff unknown add_file' "$(acl_check_listing ' 0: group:staff unknown add_file')" \
        "ACL: a line that does not parse is printed as the offending entry"
    assert_true "ACL: a name broken by a newline counts as write (its first line has no action)" \
        acl_listing_grants ' 0: group:foo' 'bar allow add_file'
    "${CHMOD}" -R -N "${dir}" 2>/dev/null || true
    "${RM}" -rf "${dir}"
}

# ---- the CLI's folder chain is checked on its own, with its own reason ----
test_cli_dir_is_root_only() {
    local status=0
    (
        serberus_pam_path_owner_mode() {
            printf '0 755'
        }
        serberus_cli_dir_is_root_only "/usr/local/bin/serberus"
    ) || status=$?
    assert_eq "0" "${status}" "CLI folder chain: root-owned 755 folders pass"
    local reason
    reason=$(
        serberus_pam_path_owner_mode() {
            if [[ "$1" == "/usr/local/bin" ]]
            then
                printf '501 755'
            else
                printf '0 755'
            fi
        }
        serberus_cli_dir_is_root_only "/usr/local/bin/serberus" 2>&1
    ) && status=0 || status=$?
    assert_eq "1" "${status}" "CLI folder chain: a user-owned /usr/local/bin fails"
    assert_true "CLI folder chain: the reason names /usr/local/bin" \
        "${GREP}" -qF '/usr/local/bin is not a root-only directory' <<< "${reason}"
    status=0
    (
        serberus_pam_path_owner_mode() {
            if [[ "$1" == "/usr/local" ]]
            then
                printf '0 775'
            else
                printf '0 755'
            fi
        }
        serberus_cli_dir_is_root_only "/usr/local/bin/serberus"
    ) 2>/dev/null || status=$?
    assert_eq "1" "${status}" "CLI folder chain: a group-writable /usr/local fails"
}

# ---- the module-dir, module-path and CLI-dir checks read a spaced ACL
# principal whole (the `ls -led` hook stubbed) ----
test_chain_checks_spaced_acl_principal() {
    local root="${FIXTURES}/fakeroot-acl"
    local module="${root}/usr/local/lib/pam/pam_serberus.so"
    local entry=' 0: group:CORP\Domain Users inherited allow add_file,delete_child'
    PATH_TABLE="${FIXTURES}/path_table_acl"
    make_fake_root "${root}"
    : > "${PATH_TABLE}"
    printf '%s 0 444\n' "${module}" >> "${PATH_TABLE}"

    assert_true "spaced ACL principal: the module chain passes when no path lists the entry" \
        with_acl_entry "${root}/elsewhere" "${entry}" path_check "${root}" "${module}"
    assert_false "spaced ACL principal: the module-dir check refuses it on /usr/local/lib/pam" \
        with_acl_entry "${root}/usr/local/lib/pam" "${entry}" dir_check "${root}" "${module}"
    assert_false "spaced ACL principal: the module-dir check refuses it on /usr/local" \
        with_acl_entry "${root}/usr/local" "${entry}" dir_check "${root}" "${module}"
    assert_false "spaced ACL principal: the module-path check refuses it on the module" \
        with_acl_entry "${module}" ' 0: group:CORP\Domain Users allow write' path_check "${root}" "${module}"
    assert_true "spaced ACL principal: the module refusal names the whole entry" \
        reasons_mention '(0: group:CORP\Domain Users allow write)'

    # The CLI check walks every real directory above the CLI up to /, so the
    # fixture is a physical path (/var is a symlink on macOS).
    local cli_dir
    cli_dir="$(cd -P "${FIXTURES}" && pwd)/cli-acl/bin"
    "${MKDIR}" -p "${cli_dir}"
    local status=0
    (
        serberus_pam_path_owner_mode() {
            printf '0 755'
        }
        with_acl_entry "${cli_dir}/elsewhere" "${entry}" serberus_cli_dir_is_root_only "${cli_dir}/serberus"
    ) || status=$?
    assert_eq "0" "${status}" "spaced ACL principal: the CLI folder chain passes when no folder lists the entry"
    local reason
    reason=$(
        serberus_pam_path_owner_mode() {
            printf '0 755'
        }
        with_acl_entry "${cli_dir}" "${entry}" serberus_cli_dir_is_root_only "${cli_dir}/serberus" 2>&1
    ) && status=0 || status=$?
    assert_eq "1" "${status}" "spaced ACL principal: the CLI-dir check refuses it on the CLI's folder"
    assert_true "spaced ACL principal: the CLI refusal names the folder" \
        "${GREP}" -qF "${cli_dir} is not a root-only directory" <<< "${reason}"
    "${RM}" -rf "${root}" "${PATH_TABLE}" "${FIXTURES}/path_reasons" "${cli_dir%/bin}"
}

# ---- the upgrade marker the preinstall writes for the new daemon ----
test_upgrade_marker() {
    local dir="${FIXTURES}/upgrade-support"
    local marker="${dir}/.upgrade-in-progress"
    "${MKDIR}" -p "${dir}"
    local status=0
    (
        serberus_pam_path_owner_mode() {
            printf '0 755'
        }
        local PAM_LIB_CHOWN="/usr/bin/true"
        serberus_write_upgrade_marker "${marker}"
    ) || status=$?
    assert_eq "0" "${status}" "upgrade marker: written into a root-only directory"
    assert_true "upgrade marker: one startedAt line (UTC ISO 8601)" \
        "${GREP}" -Eq '^startedAt=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' "${marker}"
    assert_eq "600" "$("${STAT}" -f '%Lp' "${marker}")" "upgrade marker: mode 0600"

    "${RM}" -f "${marker}"
    "${LN}" -s "${FIXTURES}/elsewhere" "${marker}"
    status=0
    (
        serberus_pam_path_owner_mode() {
            printf '0 755'
        }
        local PAM_LIB_CHOWN="/usr/bin/true"
        serberus_write_upgrade_marker "${marker}"
    ) || status=$?
    assert_eq "0" "${status}" "upgrade marker: a symlink in its place is replaced"
    assert_false "upgrade marker: never written through the symlink" test -e "${FIXTURES}/elsewhere"
    assert_false "upgrade marker: the result is a plain file, not a symlink" test -L "${marker}"

    status=0
    (
        serberus_pam_path_owner_mode() {
            printf '501 755'
        }
        serberus_write_upgrade_marker "${marker}"
    ) 2>/dev/null || status=$?
    assert_eq "1" "${status}" "upgrade marker: refused in a directory a user owns"
    assert_eq "/Library/Application Support/Serberus/.upgrade-in-progress" "${SERBERUS_UPGRADE_MARKER}" \
        "upgrade marker: the path the daemon reads"
    "${RM}" -rf "${dir}"
}

# ---- --purge removes data only ----
test_purge_support_data() {
    local dir="${FIXTURES}/purge-support"
    "${RM}" -rf "${dir}"
    "${MKDIR}" -p "${dir}/Serberus Sentinel Agent.app/Contents" "${dir}/Serberus Guardian.app" \
        "${dir}/.install-markers" "${dir}/authdb-backups" "${dir}/logs"
    : > "${dir}/state.plist"
    : > "${dir}/grants.sqlite"
    : > "${dir}/.grants-hmac-key.key"
    : > "${dir}/uninstall.sh"
    : > "${dir}/uninstall-serberus-commander.sh"
    : > "${dir}/pam-lib.sh"
    : > "${dir}/authdb-backups/system.preferences.json"
    serberus_purge_support_data "${dir}" 1 > /dev/null
    assert_true "purge: the Sentinel agent app stays" test -d "${dir}/Serberus Sentinel Agent.app"
    assert_true "purge: the Guardian app stays" test -d "${dir}/Serberus Guardian.app"
    assert_true "purge: uninstall helpers stay" test -f "${dir}/uninstall-serberus-commander.sh"
    assert_true "purge: pam-lib.sh stays" test -f "${dir}/pam-lib.sh"
    assert_true "purge: the install-marker directory stays" test -d "${dir}/.install-markers"
    assert_true "purge: authdb-backups kept when asked (failed restore)" test -d "${dir}/authdb-backups"
    assert_false "purge: state removed" test -e "${dir}/state.plist"
    assert_false "purge: grants removed" test -e "${dir}/grants.sqlite"
    assert_false "purge: dot-file keys removed" test -e "${dir}/.grants-hmac-key.key"
    assert_false "purge: data folders removed" test -e "${dir}/logs"
    serberus_purge_support_data "${dir}" 0 > /dev/null
    assert_false "purge: authdb-backups removed after a good restore" test -e "${dir}/authdb-backups"
    "${RM}" -rf "${dir}"
}

# ---- teardown safety net: a wired sudo_local keeps its daemon armed ----
test_daemon_rearm_if_wired() {
    local mock="${FIXTURES}/mock-launchctl-rearm"
    local log="${FIXTURES}/mock-launchctl-rearm.log"
    "${CAT}" > "${mock}" <<EOF
#! /bin/bash
printf '%s\n' "\$*" >> "${log}"
if [[ "\$1" == "print" ]]
then
    exit 113
fi
exit 0
EOF
    "${CHMOD}" 755 "${mock}"
    local PAM_LIB_LAUNCHCTL="${mock}"
    local plist="${FIXTURES}/daemon.plist"
    printf '<plist/>\n' > "${plist}"

    local wired="${FIXTURES}/sudo_local_rearm_wired"
    printf '%s\n' "${SERBERUS_PAM_AUTH_LINE}" > "${wired}"
    : > "${log}"
    assert_false "wired sudo_local: rearm reports it had to act" \
        serberus_daemon_rearm_if_wired "${wired}" "x" "${plist}" 2>/dev/null
    assert_true "wired sudo_local: the label is re-enabled" "${GREP}" -qx 'enable system/x' "${log}"
    assert_true "wired sudo_local: an unloaded job is bootstrapped again" \
        "${GREP}" -qx "bootstrap system ${plist}" "${log}"

    local clean="${FIXTURES}/sudo_local_rearm_clean"
    printf 'auth       sufficient     pam_tid.so\n' > "${clean}"
    : > "${log}"
    assert_true "unwired sudo_local: nothing to do" \
        serberus_daemon_rearm_if_wired "${clean}" "x" "${plist}"
    assert_false "unwired sudo_local: launchctl never called" test -s "${log}"
    "${RM}" -f "${mock}" "${log}" "${plist}" "${wired}" "${clean}"
}

# ---- pam-lib 1.6: the daemon trust gate before any one-shot ----
# Mock codesign: -dv reports team ABCDE12345 unless the path contains
# "adhoc" (no team) or "otherteam" (ZZZZZ99999); --verify -R succeeds only
# for the exact daemon requirement with the team the mock "signed" the path
# with, and fails for a path containing "reident" (wrong identifier).
write_trust_codesign_mock() {
    local mock="$1"
    "${CAT}" > "${mock}" <<'MOCK_EOF'
#! /bin/bash
path="${!#}"
team="ABCDE12345"
if [[ "${path}" == *adhoc* ]]
then
    team=""
elif [[ "${path}" == *otherteam* ]]
then
    team="ZZZZZ99999"
fi
if [[ "$1" == "-dv" ]]
then
    printf 'Identifier=com.herojoneslabs.serberus.daemon\nTeamIdentifier=%s\n' "${team:-not set}" >&2
    exit 0
fi
if [[ "$1" == "--verify" && "$2" == "--strict" && "$3" == "-R" ]]
then
    [[ -n "${team}" && "${path}" != *reident* ]] || exit 3
    [[ "$4" == "=anchor apple generic and identifier \"com.herojoneslabs.serberus.daemon\" and certificate leaf[subject.OU] = \"${team}\"" ]]
    exit $?
fi
exit 2
MOCK_EOF
    "${CHMOD}" 755 "${mock}"
}

test_daemon_trusted() {
    local mock="${FIXTURES}/mock-codesign-trust"
    write_trust_codesign_mock "${mock}"
    local PAM_LIB_CODESIGN="${mock}"
    local dir="${FIXTURES}/trust"
    "${MKDIR}" -p "${dir}"
    local good="${dir}/daemon"
    local adhoc="${dir}/adhoc-daemon"
    local reident="${dir}/reident-daemon"
    local other="${dir}/otherteam-daemon"
    local link="${dir}/link-daemon"
    : > "${good}"
    : > "${adhoc}"
    : > "${reident}"
    : > "${other}"
    "${LN}" -sf "${good}" "${link}"

    assert_true "trusted: strict, Apple anchor, daemon identifier, pinned team" \
        serberus_daemon_trusted "${good}" "ABCDE12345"
    local SERBERUS_PAM_MODULE_PATH="${dir}/module.so"
    : > "${SERBERUS_PAM_MODULE_PATH}"
    assert_true "trusted: with no recorded team, the installed module's team pins it" \
        serberus_daemon_trusted "${good}"
    SERBERUS_PAM_MODULE_PATH="${dir}/no-such-module.so"
    assert_false "untrusted: no recorded team and no module — its own team is never enough" \
        serberus_daemon_trusted "${good}" 2>/dev/null
    SERBERUS_PAM_MODULE_PATH="${dir}/adhoc-module.so"
    : > "${SERBERUS_PAM_MODULE_PATH}"
    assert_false "untrusted: no recorded team and an unsigned module" \
        serberus_daemon_trusted "${good}" 2>/dev/null
    assert_false "untrusted: signed by a different team than the pin" \
        serberus_daemon_trusted "${other}" "ABCDE12345" 2>/dev/null
    assert_false "untrusted: ad-hoc (no Team ID to pin)" \
        serberus_daemon_trusted "${adhoc}" 2>/dev/null
    assert_false "untrusted: valid team but not the daemon identifier" \
        serberus_daemon_trusted "${reident}" "ABCDE12345" 2>/dev/null
    assert_false "untrusted: an empty pinned team never matches" \
        serberus_daemon_trusted "${adhoc}" "" 2>/dev/null
    assert_false "untrusted: a malformed team is refused before codesign runs" \
        serberus_daemon_trusted "${good}" 'X" or anchor apple' 2>/dev/null
    assert_false "untrusted: a symlinked daemon path" \
        serberus_daemon_trusted "${link}" "ABCDE12345" 2>/dev/null
    assert_false "untrusted: a missing daemon" \
        serberus_daemon_trusted "${dir}/missing" "ABCDE12345" 2>/dev/null

    assert_true "manual demote steps name dseditgroup" \
        "${GREP}" -q 'dseditgroup -o edit -d <user> -t user admin' <<< "$(serberus_daemon_manual_steps demote)"
    assert_true "manual restore steps name security authorizationdb write" \
        "${GREP}" -qF 'security authorizationdb write <right> < /x/<right>.json' <<< "$(serberus_daemon_manual_steps restore /x)"
    assert_eq "com.herojoneslabs.serberus.daemon" "${SERBERUS_DAEMON_IDENTIFIER}" \
        "the pinned daemon identifier"
    "${RM}" -rf "${dir}" "${mock}"
}

# ---- pam-lib 1.6: a drop-in that survives its rm is FAILED, never "removed" ----
test_sudoers_dropin_removal_failure() {
    local dropin="${FIXTURES}/sudoers-dropin-stuck"
    printf '%s\n' '# /etc/sudoers.d/serberus: managed by com.herojoneslabs.serberus — DO NOT EDIT' > "${dropin}"
    local result
    local status=0
    result=$(PAM_LIB_RM=/usr/bin/true serberus_pam_remove_sudoers_dropin "${dropin}") || status=$?
    assert_eq "FAILED" "${result}" "a drop-in still present after rm reports FAILED"
    assert_eq "1" "${status}" "a drop-in still present after rm returns 1"
    assert_true "the stuck drop-in is still there (nothing claimed otherwise)" test -f "${dropin}"
    status=0
    result=$(serberus_pam_remove_sudoers_dropin "${dropin}") || status=$?
    assert_eq "removed:0" "${result}:${status}" "a removable drop-in still reports removed (status 0)"
}

# ---- pam-lib 1.6: a failed chmod/mv leaves no sudo_local.serberus-* temp ----
test_sudo_local_temp_cleanup() {
    local dir="${FIXTURES}/tempclean"
    "${MKDIR}" -p "${dir}"
    local f="${dir}/sudo_local"
    local result
    local status=0
    result=$(PAM_LIB_MV=/usr/bin/false serberus_pam_merge_sudo_local "${f}") || status=$?
    assert_eq "FAILED:1" "${result}:${status}" "create: a failed mv reports FAILED (status 1)"
    assert_false "create: no sudo_local was left behind" test -e "${f}"

    printf 'auth       sufficient     pam_tid.so\n' > "${f}"
    status=0
    result=$(PAM_LIB_MV=/usr/bin/false serberus_pam_merge_sudo_local "${f}") || status=$?
    assert_eq "FAILED:1" "${result}:${status}" "merge: a failed mv reports FAILED (status 1)"
    assert_eq "auth       sufficient     pam_tid.so" "$("${CAT}" "${f}")" "merge: sudo_local unchanged after the failed mv"

    printf '%s\n%s\n' "${SERBERUS_PAM_AUTH_LINE}" 'auth       sufficient     pam_tid.so' > "${f}"
    status=0
    result=$(PAM_LIB_CHMOD=/usr/bin/false serberus_pam_remove_sudo_local "${f}") || status=$?
    assert_eq "FAILED:1" "${result}:${status}" "remove: a failed chmod reports FAILED (status 1)"
    assert_true "remove: the wired file is unchanged" serberus_pam_sudo_local_has_module "${f}"

    local leftovers
    leftovers=$(/usr/bin/find "${dir}" -name 'sudo_local.serberus-*' | /usr/bin/wc -l | /usr/bin/tr -d ' ')
    assert_eq "0" "${leftovers}" "no sudo_local.serberus-*.<pid> temp files remain"
    "${RM}" -rf "${dir}"
}

# ---- pam-lib 1.6: liveness sees restarts, failed exits and stale state ----
# The mock launchctl hands out one line per `print` from a sequence file
# ("pid|runs|last exit code|last terminating signal"); the last line repeats.
# A nested endpoints section carries decoy counters that must be ignored.
write_counter_launchctl_mock() {
    local mock="$1"
    local seq_file="$2"
    local calls="$3"
    "${CAT}" > "${mock}" <<MOCK_EOF
#! /bin/bash
count=\$(( \$(/bin/cat "${calls}" 2>/dev/null || printf 0) + 1 ))
printf '%s' "\${count}" > "${calls}"
line=\$(/usr/bin/sed -n "\${count}p" "${seq_file}")
if [[ -z "\${line}" ]]
then
    line=\$(/usr/bin/tail -n 1 "${seq_file}")
fi
IFS='|' read -r pid runs code signal <<< "\${line}"
printf 'system/x = {\n'
if [[ "\${pid}" == "none" ]]
then
    printf '\tstate = spawn scheduled\n'
else
    printf '\tstate = running\n'
fi
printf '\truns = %s\n' "\${runs}"
if [[ "\${pid}" != "none" ]]
then
    printf '\tpid = %s\n' "\${pid}"
fi
printf '\tlast exit code = %s\n' "\${code}"
if [[ -n "\${signal}" ]]
then
    printf '\tlast terminating signal = %s\n' "\${signal}"
fi
printf '\tendpoints = {\n\t\truns = 99\n\t\tlast exit code = 1\n\t}\n}\n'
MOCK_EOF
    "${CHMOD}" 755 "${mock}"
}

# write_state_plist <path> <state> <updatedAt> — empty state/updatedAt omit
# the key.
write_state_plist() {
    {
        printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>'
        printf '%s\n' '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
        printf '%s\n' '<plist version="1.0">' '<dict>'
        if [[ -n "$2" ]]
        then
            printf '    <key>state</key><string>%s</string>\n' "$2"
        fi
        if [[ "$2" == "degraded" ]]
        then
            printf '    <key>degradedReason</key><string>pam_not_wired</string>\n'
        fi
        if [[ -n "$3" ]]
        then
            printf '    <key>updatedAt</key><string>%s</string>\n' "$3"
        fi
        printf '%s\n' '</dict>' '</plist>'
    } > "$1"
}

test_launchd_restart_detection() {
    local mock="${FIXTURES}/mock-launchctl-counters"
    local seq_file="${FIXTURES}/mock-launchctl-counters-seq"
    local calls="${FIXTURES}/mock-launchctl-counters-calls"
    write_counter_launchctl_mock "${mock}" "${seq_file}" "${calls}"
    local PAM_LIB_LAUNCHCTL="${mock}"
    local PAM_LIB_SLEEP="/usr/bin/true"

    assert_eq "8" "${SERBERUS_LAUNCHD_STABLE_SECONDS}" \
        "the stability window (8 s) is longer than the 5 s ThrottleInterval"

    local out
    printf '100|1|(never exited)|\n' > "${seq_file}"
    : > "${calls}"
    out=$("${mock}")
    assert_eq "1" "$(serberus_launchd_job_field "${out}" "runs")" "runs parsed from the job's own line (not the nested one)"
    assert_eq "(never exited)" "$(serberus_launchd_job_field "${out}" "last exit code")" "last exit code parsed"

    : > "${calls}"
    assert_true "fresh bootstrap: one pid, runs 1, never exited — up" \
        serberus_launchd_wait_running "x" 5 "" "" "" "" 1
    assert_eq "100" "${SERBERUS_LAUNCHD_UP_PID}" "the accepted pid is kept for the pre-merge re-check"
    assert_true "pid unchanged right before the merge" serberus_launchd_pid_unchanged "x"
    printf '101|2|1|\n' > "${seq_file}"
    : > "${calls}"
    assert_false "a new pid right before the merge refuses" serberus_launchd_pid_unchanged "x" 2>/dev/null

    # Crash after ~4 s: runs advances inside the (now 8 s) window.
    printf '200|1|(never exited)|\n200|1|(never exited)|\n200|1|(never exited)|\n200|1|(never exited)|\n201|2|1|\n201|2|1|\n' > "${seq_file}"
    : > "${calls}"
    assert_false "a restart inside the window (runs 1 -> 2) is refused, not retried" \
        serberus_launchd_wait_running "x" 10 2>/dev/null

    # A failed exit already recorded when the first poll sees the new pid.
    printf '300|2|1|\n' > "${seq_file}"
    : > "${calls}"
    assert_false "fresh bootstrap: a non-zero last exit code is refused" \
        serberus_launchd_wait_running "x" 5 "" "" "" "" 1 2>/dev/null
    printf '301|2|(never exited)|Killed: 9\n' > "${seq_file}"
    : > "${calls}"
    assert_false "fresh bootstrap: a terminating signal is refused" \
        serberus_launchd_wait_running "x" 5 "" "" "" "" 1 2>/dev/null

    # The caller restarted the job itself (kickstart -k): that first SIGTERM
    # is the baseline, only a NEW failure counts.
    printf '400|2|(never exited)|Terminated: 15\n' > "${seq_file}"
    : > "${calls}"
    assert_true "own kickstart (fresh_job 0): the baseline signal is accepted" \
        serberus_launchd_wait_running "x" 5 "" "" "" "" 0
    printf '400|2|(never exited)|Terminated: 15\n401|3|(never exited)|Killed: 9\n' > "${seq_file}"
    : > "${calls}"
    assert_false "own kickstart (fresh_job 0): a later kill still refuses" \
        serberus_launchd_wait_running "x" 5 "" "" "" "" 0 2>/dev/null

    # A daemon that restarted long ago (no bootstrap mark): relative only.
    printf '500|7|1|\n' > "${seq_file}"
    : > "${calls}"
    assert_true "no bootstrap mark: an old failure with no new restart is up" \
        serberus_launchd_wait_running "x" 5

    # A CLI that is named but missing fails the check.
    printf '600|1|(never exited)|\n' > "${seq_file}"
    : > "${calls}"
    assert_false "a named but missing serberus CLI fails the health check" \
        serberus_launchd_wait_running "x" 5 "${FIXTURES}/no-such-cli" 2>/dev/null
    "${RM}" -f "${mock}" "${seq_file}" "${calls}"
}

test_daemon_state_fresh() {
    local plist="${FIXTURES}/state.plist"
    local now
    now=$(/bin/date -u +%s)
    local since=$((now - 5))
    local fresh_stamp
    fresh_stamp=$(/bin/date -u -r "${now}" '+%Y-%m-%dT%H:%M:%S.123Z')
    local old_stamp
    old_stamp=$(/bin/date -u -r "$((now - 600))" '+%Y-%m-%dT%H:%M:%S.000Z')

    write_state_plist "${plist}" "healthy" "${fresh_stamp}"
    assert_true "state written since the bootstrap counts" serberus_daemon_state_fresh "${plist}" "${since}"
    write_state_plist "${plist}" "degraded" "${fresh_stamp}"
    assert_true "degraded(pam_not_wired) before wiring is accepted" serberus_daemon_state_fresh "${plist}" "${since}"
    write_state_plist "${plist}" "healthy" "${old_stamp}"
    assert_false "a state.plist the PREVIOUS daemon wrote does not count" \
        serberus_daemon_state_fresh "${plist}" "${since}" 2>/dev/null
    write_state_plist "${plist}" "unknown" "${fresh_stamp}"
    assert_false "state unknown does not count" serberus_daemon_state_fresh "${plist}" "${since}" 2>/dev/null
    write_state_plist "${plist}" "" "${fresh_stamp}"
    assert_false "no state key does not count" serberus_daemon_state_fresh "${plist}" "${since}" 2>/dev/null
    write_state_plist "${plist}" "healthy" ""
    assert_false "no updatedAt does not count" serberus_daemon_state_fresh "${plist}" "${since}" 2>/dev/null
    "${RM}" -f "${plist}"
    assert_false "a missing state.plist does not count" serberus_daemon_state_fresh "${plist}" "${since}" 2>/dev/null

    # Wired into the wait: a stable pid with only a stale state is not up.
    local mock="${FIXTURES}/mock-launchctl-state"
    local seq_file="${FIXTURES}/mock-launchctl-state-seq"
    local calls="${FIXTURES}/mock-launchctl-state-calls"
    write_counter_launchctl_mock "${mock}" "${seq_file}" "${calls}"
    local PAM_LIB_LAUNCHCTL="${mock}"
    local PAM_LIB_SLEEP="/usr/bin/true"
    printf '700|1|(never exited)|\n' > "${seq_file}"
    write_state_plist "${plist}" "healthy" "${old_stamp}"
    : > "${calls}"
    assert_false "stable pid + a stale state.plist is NOT up" \
        serberus_launchd_wait_running "x" 5 "" "" "${plist}" "${since}" 2>/dev/null
    write_state_plist "${plist}" "degraded" "${fresh_stamp}"
    : > "${calls}"
    assert_true "stable pid + a fresh state.plist is up" \
        serberus_launchd_wait_running "x" 5 "" "" "${plist}" "${since}"
    assert_true "the bootstrap mark is epoch seconds" \
        "${GREP}" -Eq '^[0-9]+$' <<< "$(serberus_launchd_bootstrap_mark)"
    "${RM}" -f "${mock}" "${seq_file}" "${calls}" "${plist}"
}

test_generated_scripts_pass_bash_n() {
    local gen_dir="${FIXTURES}/generated"
    if ! "${BASH_BIN}" "${BUILD_SCRIPT}" --emit-scripts "${gen_dir}" >/dev/null
    then
        fail "build-pam-test-pkg.sh --emit-scripts failed"
        return 0
    fi

    local script
    for script in \
        "${gen_dir}/scripts/preinstall" \
        "${gen_dir}/scripts/postinstall" \
        "${gen_dir}/scripts/pam-lib.sh" \
        "${gen_dir}/payload/Library/Application Support/Serberus/uninstall-serberus-pam-test.sh"
    do
        if [[ ! -f "${script}" ]]
        then
            fail "expected generated script missing: ${script}"
            continue
        fi
        if "${BASH_BIN}" -n "${script}"
        then
            pass "bash -n: ${script#"${gen_dir}/"}"
        else
            fail "bash -n FAILED: ${script}"
        fi
    done

    # Static scripts in the repo must stay parseable too.
    for script in \
        "${PKG_DIR}"/*.sh \
        "${PKG_DIR}"/Scripts/* \
        "${PKG_DIR}"/tools/*.sh \
        "${PKG_DIR}"/tests/*.sh \
        "${REPO_DIR}"/Support/*.sh
    do
        if "${BASH_BIN}" -n "${script}"
        then
            pass "bash -n: ${script#"${REPO_DIR}/"}"
        else
            fail "bash -n FAILED: ${script}"
        fi
    done
}

##################################
### End User Defined Functions ###
##################################
###################################################################################
############## End Function Block #################################################
###################################################################################

#####################################################
################## Run Script Block #################
#####################################################

log_info "${SCRIPT_NAME} v${SCRIPT_VERSION} starting (fixtures: ${FIXTURES})"

if [[ ! -f "${PAM_LIB}" ]]
then
    log_error "Cannot find ${PAM_LIB}"
    exit 1
fi
# shellcheck source=../Scripts/pam-lib.sh
source "${PAM_LIB}"

test_merge_creates_absent_file
test_merge_creates_from_template
test_merge_inserts_above_pam_tid
test_merge_respects_existing_user_wiring
test_merge_replaces_legacy_bare_name_line
test_merge_moves_line_above_pam_tid
test_merge_upgrade_below_tid_is_moved
test_merge_already_canonical_untouched
test_merge_collapses_duplicates_and_keeps_comments
test_merge_replaces_symlinked_sudo_local
test_merge_appends_when_no_auth_line
test_removal_from_merged_file
test_removal_deletes_created_file
test_removal_keeps_created_file_with_user_additions
test_removal_strips_legacy_bare_name_line
test_removal_handles_legacy_create_if_absent_file
test_removal_absent_and_foreign_files
test_sudoers_dropin_removal
test_has_module_detection
test_config_present
test_module_path_safety
test_codesign_team_helpers
test_launchd_job_running
test_merge_modes_and_dangling_symlink
test_sudo_local_directory_refused
test_bypass_exact_names_and_group_members
test_bypass_names_byte_exact
test_merge_matches_auth_case_insensitively
test_created_header_matches_swift_literal
test_shadowing_policy_paths
test_launchd_wait_gone
test_recorded_team
test_remove_versioned_module
test_pam_sudo_includes_sudo_local
test_module_dir_check_and_lock
test_launchd_stable_pid
test_cli_health_check
test_run_bounded
test_authdb_free_of_serberus
test_root_locked_acl
test_cli_dir_is_root_only
test_chain_checks_spaced_acl_principal
test_upgrade_marker
test_purge_support_data
test_daemon_rearm_if_wired
test_daemon_trusted
test_sudoers_dropin_removal_failure
test_sudo_local_temp_cleanup
test_launchd_restart_detection
test_daemon_state_fresh

# Resolver smoke tests run with the REAL id/dscacheutil implementations;
# every preflight test after this point runs against the hermetic mocks
# (fixture names like "breakglass"/"admin" must resolve deterministically).
test_real_resolvers
test_user_resolver_rejects_numeric_uids
install_resolver_mocks

test_preflight_resolvable_bypass
test_preflight_failures
test_preflight_passes
test_preflight_ignores_unmanaged_config
test_generated_scripts_pass_bash_n

printf '\n[RESULT] %d passed, %d failed\n' "${PASS_COUNT}" "${FAIL_COUNT}"
if [[ "${FAIL_COUNT}" -ne 0 ]]
then
    exit 1
fi

log_info "${SCRIPT_NAME} completed successfully"
exit 0

###########################################################
################## End Script Block #######################
###########################################################
