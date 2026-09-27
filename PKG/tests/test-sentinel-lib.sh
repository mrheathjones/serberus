#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: test-sentinel-lib.sh
# Author: Heath Jones
# Date: 2026-07-13
# Modified: 2026-09-26
# Purpose: Shell test harness for the installer scripts the PKG builders
#          generate (build-core-test-pkg.sh first, plus the pam-test,
#          daemon-test, uninstall, sentinel-app and commander builders via
#          their --emit-scripts modes) and the static PKG/Scripts. Verifies
#          the safety-critical ORDERING invariants at the shell level, entirely
#          on temp fixtures / generated artifacts (never /etc, never root, no
#          system writes):
#            - the generated POSTINSTALL enables + bootstraps the DAEMON and
#              waits for it to RUN, then validates the MODULE, then wires
#              sudo_local LAST; every failure takes the ONE abort path
#              (drop-in -> unwire -> disable -> bootout -> drop-in -> demote
#              JIT -> restore authdb -> exit 1), so a daemon that fails never
#              leaves sudo wired to the `requisite` module and a reboot cannot
#              resurrect it;
#            - every full UNINSTALL (sentinel helper, uninstall pkg, daemon
#              helper, production uninstall.sh) runs drop-in -> unwire ->
#              disable -> bootout -> demote JIT -> restore -> plugin -> files,
#              re-checks the drop-in after the bootout, re-enables the daemon
#              when the unwire fails, and deletes the SerberusAuth plugin only
#              when the restore succeeded;
#            - nothing root runs uses a user-writable PATH or `which`; every
#              called log_* function is defined; relaunch markers live in a
#              root-only directory; per-user deletes are symlink/owner-guarded;
#            - the generated PREINSTALL runs the break-glass preflight, which
#              ABORTS (exit 1) on the ONE genuine brick (config PRESENT + enforce
#              + a pamBypass that resolves to no account + NO last-known-good
#              snapshot) and WARNS + PROCEEDS otherwise (an un-configured install
#              is inert, not bricked — see test_preinstall_preflight_warns_and_
#              proceeds) and carries NO daemon-loaded install gate (the daemon
#              ships in this same pkg);
#            - the break-glass SAFETY PREDICATE itself (functional, via pam-lib.sh
#              with hermetic resolver mocks) still returns false on enforce +
#              no-resolvable-bypass — that drives either a WARNING or the abort,
#              depending on config-present + snapshot-present.
#          Also bash -n validates every generated script (via --emit-scripts)
#          plus the static PKG builders/libs. Runnable standalone or via
#          ./PKG/build-core-test-pkg.sh --self-test; exits nonzero on any failure.
# Version: 1.7 - New checks: no one-shot (--restore-authdb included) runs
#          beside a daemon still loaded; every script's SCRIPT_VERSION equals
#          its header's Version; the uninstallers remove every endpoint
#          component and never Commander (functional run of the uninstall
#          pkg's support-folder cleanup), and --purge is data only; the
#          postinstall checks the CLI's folder chain before the bootstrap and
#          every postinstall names the installer log; every shipped plist,
#          profile and entitlements file passes xmllint; the committed
#          project.pbxproj's MARKETING_VERSION equals VERSION; the demote
#          tool's system-account, Jamf Connect and parameter-4 handling
#          (functional parser run); the upload EAs' descriptor check against
#          a swap after the path check; the ESF=off production build; the
#          Sentinel app helper's --purge removes only the Sentinel's files
#          and keeps Commander's library (functional run, sudo mocked).
#          Header: the abort and teardown orders the scripts follow.
#          1.6 - New checks: one product version (VERSION equals
#          MARKETING_VERSION and DaemonVersion.current; scripts read the file;
#          generated Info.plists use $(MARKETING_VERSION); the core test
#          version.plist carries the product version, cliVersion and
#          installTeamID); teardown order drop-in -> unwire -> disable ->
#          bootout (waiting until launchd drops the job) -> drop-in -> demote
#          -> drop-in, with a surviving drop-in failing the run; one-shots
#          pinned to the recorded team and skipped beside a live daemon;
#          preinstalls re-check the drop-in after the bootout; test helpers
#          source pam-lib.sh through a root-only chain; a stray
#          pam_serberus.so.2 removed; per-user purges and upload EAs resolve
#          accounts through their records; Recent Events cut to whole events
#          (valid JSON); build-serberusd-bundle.sh refuses ad-hoc and checks
#          the team; build-pam.sh --install never builds; the demote tool
#          ignores JIT-only admins; the core postinstall's freshness mark is
#          retaken before kickstart. assert_sequence may repeat a step.
#          1.5 - New checks: every daemon one-shot (uninstallers, devtool,
#          legacy restore, postinstall abort paths) is gated on
#          serberus_daemon_trusted and --demote-jit exit 3 is informational;
#          upgrades demote JIT admins with the OLD binary after the bootout
#          and the production preinstall removes test-ring leftovers; a
#          surviving sudoers drop-in stops every teardown before the unwire;
#          the liveness gate (bootstrap mark, state.plist, pid re-check,
#          criterion 10 for the CLI) and per-step chown/chmod checks; ad-hoc
#          signing refused by the daemon-test and production builders; the
#          Xcode daemon identifier; the dev tools' atomic replace, refusal
#          while wired and re-arm; per-user purges as the user and anchored
#          pkill patterns; GUI require_boot_volume under Installer; the
#          SerberusTest-<v>.pkg name and README rows; Auth URI Browser
#          argument handling and scratch dir; bundle-free daemon/PAM
#          payloads; uninstall.sh's root-only pam-lib.sh chain; the upload
#          EAs' bounded ledger copy and the 64 KiB events cap; ISO header
#          dates under extras/.
#          1.4 - Tracks the core builder rename (build-core-test-pkg.sh,
#          SerberusCore-<v>.pkg). New structural checks: every preinstall that
#          boots the daemon out tears the gates down FIRST (drop-in -> unwire
#          -> bootout) and the production break-glass preflight runs in the
#          preinstall, not the postinstall; every emitted root script has an
#          EXIT trap (postinstalls: set right after pam-lib.sh is sourced,
#          with a success marker before exit 0) and umask 022; every abort
#          keeps the daemon running when an active line survives the unwire
#          (no bootout on that branch); the stable-pid wait is used before
#          wiring (PAM test pkg included); every generated pre/postinstall
#          requires the boot volume; the four bundle-shipping builders pin
#          BundleIsRelocatable=false; every daemon codesign carries
#          --identifier com.herojoneslabs.serberus.daemon; restores gate the
#          plugin on the live AuthorizationDB check; the demote tool has no
#          force override; EAs and builders use a system-only PATH with no
#          `which` and no style-guide pragma.
#          1.3 - New teardown/abort ORDER assertions (line numbers in the
#          emitted scripts), restore-gates-plugin, enable-before-bootstrap,
#          running-not-loaded, module chain/team checks, system-only PATH,
#          undefined log_* detection, root-only relaunch markers; emits the
#          other builders' scripts too.
#          1.2 - Preinstall preflight ABORTS again on the genuine brick and WARNS
#          + PROCEEDS otherwise (F1); structural assertions updated to require the
#          config-present/snapshot-absent-gated exit 1.
#          1.1 - Preinstall preflight relaxed ABORT -> WARN + PROCEED; the
#          structural assertions now guard that it never re-acquires an exit 1.
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

readonly AWK="/usr/bin/awk"
readonly BASENAME="/usr/bin/basename"
readonly BASH_BIN="/bin/bash"
readonly DIRNAME="/usr/bin/dirname"
readonly FIND="/usr/bin/find"
readonly GREP="/usr/bin/grep"
readonly ID_BIN="/usr/bin/id"
readonly LN_BIN="/bin/ln"
readonly MKDIR_BIN="/bin/mkdir"
readonly MKTEMP="/usr/bin/mktemp"
readonly RM="/bin/rm"
readonly SORT="/usr/bin/sort"
readonly XMLLINT="/usr/bin/xmllint"

readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.7"
readonly SCRIPT_DIR=$(cd "$("${DIRNAME}" "$0")" && pwd)
readonly PKG_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
readonly REPO_DIR=$(cd "${PKG_DIR}/.." && pwd)

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

readonly PAM_LIB="${PKG_DIR}/Scripts/pam-lib.sh"
readonly BUILD_SCRIPT="${PKG_DIR}/build-core-test-pkg.sh"

FIXTURES=$("${MKTEMP}" -d -t serberus-core-lib-tests)
readonly FIXTURES
trap '"${RM}" -rf "${FIXTURES}"' EXIT

# Emitted-once artifacts (generated by --emit-scripts) reused across tests.
GEN_DIR=""
GEN_PREINSTALL=""
GEN_POSTINSTALL=""
GEN_UNINSTALL=""
GEN_PAM_LIB=""
GEN_TEST_POSTINSTALL=""
GEN_TEST_UNINSTALL=""
GEN_PAM_POSTINSTALL=""
GEN_PAM_UNINSTALL=""
GEN_UNINSTALL_PKG=""
GEN_ALL=()

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

# Line number (1-based, file-global) of the FIRST occurrence of <pattern> at or
# after the "Run Script Block" banner in <file>. Prints empty if not found —
# this restricts ordering assertions to the RUN block, so a function DEFINITION
# earlier in the file never confuses the call-order check.
run_block_line() {
    local file="$1"
    local pattern="$2"
    "${AWK}" -v pat="${pattern}" '
        /Run Script Block/ { inrun = 1 }
        inrun && $0 ~ pat { print NR; exit }
    ' "${file}"
}

# assert_order <file> <earlier-pattern> <later-pattern> <label> — both patterns
# must be found in the run block and earlier must precede later.
assert_order() {
    local file="$1"
    local earlier="$2"
    local later="$3"
    local label="$4"
    local a b
    a=$(run_block_line "${file}" "${earlier}")
    b=$(run_block_line "${file}" "${later}")
    if [[ -z "${a}" ]]
    then
        fail "${label} — earlier pattern '${earlier}' not found in run block of ${file##*/}"
        return 0
    fi
    if [[ -z "${b}" ]]
    then
        fail "${label} — later pattern '${later}' not found in run block of ${file##*/}"
        return 0
    fi
    if [[ "${a}" -lt "${b}" ]]
    then
        pass "${label} (line ${a} < ${b})"
    else
        fail "${label} — expected '${earlier}' (line ${a}) before '${later}' (line ${b})"
    fi
}

# short <path> — a path relative to the fixtures or the repo, for labels.
short() {
    local path="${1#"${FIXTURES}/"}"
    printf '%s' "${path#"${REPO_DIR}/"}"
}

# assert_sequence <file> <label> <pattern>... — every pattern must be found in
# the run block, each strictly after the previous one. The FIRST pattern must
# be its first match in the run block; each later one is looked for after
# the previous match, so a step may appear twice to assert that it repeats.
assert_sequence() {
    local file="$1"
    local label="$2"
    shift 2
    local previous=""
    local previous_line=0
    local pattern
    local line
    local first
    for pattern in "$@"
    do
        line=$("${AWK}" -v pat="${pattern}" -v min="${previous_line}" '
            /Run Script Block/ { inrun = 1 }
            inrun && NR > min && $0 ~ pat { print NR; exit }
        ' "${file}")
        if [[ -z "${line}" ]]
        then
            first=$(run_block_line "${file}" "${pattern}")
            if [[ -n "${first}" && -n "${previous}" ]]
            then
                fail "${label} — '${previous}' (line ${previous_line}) must come before '${pattern}' (line ${first}) in ${file##*/}"
            else
                fail "${label} — '${pattern}' not found in run block of ${file##*/}"
            fi
            return 0
        fi
        previous="${pattern}"
        previous_line="${line}"
    done
    pass "${label}"
}

# function_body <file> <name> — prints the body of `name() {` … first `}` at
# column 0.
function_body() {
    "${AWK}" -v fn="$2" '
        $0 ~ "^" fn "\\(\\) \\{" { inf = 1 }
        inf { print }
        inf && /^}/ { exit }
    ' "$1"
}

# body_order <file> <function> <label> <pattern>... — each pattern matches a
# line of the function body AFTER the previous pattern's match (so the same
# pattern may appear twice to assert a repeated step).
body_order() {
    local file="$1"
    local fn="$2"
    local label="$3"
    shift 3
    local body
    body=$(function_body "${file}" "${fn}")
    if [[ -z "${body}" ]]
    then
        fail "${label} — function ${fn} not found in ${file##*/}"
        return 0
    fi
    local previous_line=0
    local pattern
    local line
    for pattern in "$@"
    do
        line=$(printf '%s\n' "${body}" | "${GREP}" -nE -- "${pattern}" \
            | "${AWK}" -F: -v min="${previous_line}" '$1 > min { print $1; exit }') || true
        if [[ -z "${line}" ]]
        then
            fail "${label} — '${pattern}' missing or out of order in ${fn}() of ${file##*/}"
            return 0
        fi
        previous_line="${line}"
    done
    pass "${label}"
}

# Emit every package builder's generated scripts ONCE and cache their paths.
emit_generated_scripts() {
    GEN_DIR="${FIXTURES}/generated"
    if ! "${BASH_BIN}" "${BUILD_SCRIPT}" --emit-scripts "${GEN_DIR}" >/dev/null
    then
        log_error "build-core-test-pkg.sh --emit-scripts failed"
        exit 1
    fi
    GEN_PREINSTALL="${GEN_DIR}/scripts/preinstall"
    GEN_POSTINSTALL="${GEN_DIR}/scripts/postinstall"
    GEN_PAM_LIB="${GEN_DIR}/scripts/pam-lib.sh"
    GEN_UNINSTALL="${GEN_DIR}/payload/Library/Application Support/Serberus/uninstall-serberus-sentinel-test.sh"

    local builder
    local dir
    for builder in build-pam-test-pkg build-test-pkg build-uninstall-pkg \
        build-sentinel-app-pkg build-commander-pkg
    do
        dir="${FIXTURES}/gen-${builder}"
        if ! "${BASH_BIN}" "${PKG_DIR}/${builder}.sh" --emit-scripts "${dir}" >/dev/null
        then
            log_error "${builder}.sh --emit-scripts failed"
            exit 1
        fi
    done
    # Auth URI Browser has no root helpers of its own; emitted apart from the
    # gen-* set (its scripts are plain app drops without require_boot_volume).
    if ! "${BASH_BIN}" "${PKG_DIR}/build-authuribrowser-pkg.sh" --emit-scripts \
        "${FIXTURES}/emit-authuribrowser" >/dev/null
    then
        log_error "build-authuribrowser-pkg.sh --emit-scripts failed"
        exit 1
    fi
    GEN_TEST_POSTINSTALL="${FIXTURES}/gen-build-test-pkg/scripts/postinstall"
    GEN_TEST_UNINSTALL="${FIXTURES}/gen-build-test-pkg/payload/Library/Application Support/Serberus/uninstall-serberusd-test.sh"
    GEN_PAM_POSTINSTALL="${FIXTURES}/gen-build-pam-test-pkg/scripts/postinstall"
    GEN_PAM_UNINSTALL="${FIXTURES}/gen-build-pam-test-pkg/payload/Library/Application Support/Serberus/uninstall-serberus-pam-test.sh"
    GEN_UNINSTALL_PKG="${FIXTURES}/gen-build-uninstall-pkg/scripts/postinstall"

    # Every generated script, for the whole-set checks below.
    GEN_ALL=()
    local script
    while IFS= read -r script
    do
        GEN_ALL+=("${script}")
    done < <("${FIND}" "${GEN_DIR}" "${FIXTURES}"/gen-* -type f \
        \( -path '*/scripts/*' -o -name '*.sh' \) ! -name '*.entitlements' | "${SORT}")
}

# ---- POSTINSTALL ordering: daemon-running -> module-validate -> wire sudo_local ----
test_postinstall_install_order() {
    assert_true "generated postinstall exists" test -f "${GEN_POSTINSTALL}"

    assert_sequence "${GEN_POSTINSTALL}" \
        "postinstall: fix_ownership -> daemon bootstrap+running -> module validation -> wire sudo_local" \
        '^if ! fix_ownership$' \
        'if ! bootstrap_and_verify_daemon' \
        'if ! module_validation_passes' \
        '^if ! wire_sudo_local$'
}

# Every failure branch in the run block must take the ONE abort path.
test_postinstall_wire_is_guarded() {
    local file
    local guard
    for file in "${GEN_POSTINSTALL}" "${GEN_TEST_POSTINSTALL}" "${GEN_PAM_POSTINSTALL}" \
        "${PKG_DIR}/Scripts/postinstall"
    do
        local run
        run=$("${AWK}" '/Run Script Block/{inrun=1} inrun{print}' "${file}")
        local guards
        guards=$(printf '%s\n' "${run}" | "${GREP}" -c '^if ! ')
        local aborts
        aborts=$("${AWK}" '/Run Script Block/{inrun=1} inrun && /^if ! /{getline; getline; print}' "${file}" \
            | "${GREP}" -c 'abort_install')
        if [[ "${guards}" -gt 0 && "${guards}" -eq "${aborts}" ]]
        then
            pass "$(short "${file}"): all ${guards} run-block failure branches call abort_install"
        else
            fail "$(short "${file}"): ${guards} failure branches but ${aborts} abort_install calls"
        fi
    done
    # The PAM-only abort removes the drop-in and self-heals sudo_local (it
    # owns no daemon, so it leaves the daemon alone).
    body_order "${GEN_PAM_POSTINSTALL}" abort_install \
        "pam-test postinstall: abort = drop-in -> self-heal sudo_local -> exit 1" \
        'serberus_pam_remove_sudoers_dropin' 'serberus_pam_remove_sudo_local' '^[[:space:]]+exit 1$'
    for guard in 'if ! bootstrap_and_verify_daemon' 'if ! module_validation_passes' '^if ! wire_sudo_local$'
    do
        assert_true "sentinel postinstall run block guards: ${guard}" \
            "${GREP}" -Eq "${guard}" "${GEN_POSTINSTALL}"
    done
}

# B: the abort path stops the daemon for good (disable + bootout) and removes
# the sudoers drop-in, in the same order as the uninstall. The disable comes
# only after the unwire: an abort interrupted between the two must not leave
# sudo_local wired behind a disabled daemon.
test_postinstall_abort_path() {
    local file
    for file in "${GEN_POSTINSTALL}" "${GEN_TEST_POSTINSTALL}" "${PKG_DIR}/Scripts/postinstall"
    do
        body_order "${file}" abort_install \
            "$(short "${file}"): abort = drop-in -> unwire -> disable -> bootout -> drop-in -> demote JIT -> restore -> exit 1" \
            '^[[:space:]]+(if ! )?remove_sudoers_dropin$' \
            '^[[:space:]]+(if ! )?unwire_sudo_local$' \
            '^[[:space:]]+disable_daemon$' \
            '^[[:space:]]+bootout_daemon$' \
            '^[[:space:]]+(if ! )?remove_sudoers_dropin$' \
            '^[[:space:]]+demote_jit_admins$' \
            '^[[:space:]]+restore_(authdb|authorization_db)$' \
            '^[[:space:]]+exit 1$'
        body_order "${file}" disable_daemon "$(short "${file}"): disable_daemon runs launchctl disable" \
            'LAUNCHCTL}" disable "system/'
        body_order "${file}" bootout_daemon "$(short "${file}"): the bootout waits until launchd drops the job" \
            'LAUNCHCTL}" bootout "system/' 'serberus_launchd_wait_gone' 'DAEMON_GONE=0'
        body_order "${file}" demote_jit_admins "$(short "${file}"): no --demote-jit beside a daemon still loaded" \
            'DAEMON_GONE' 'run_daemon_oneshot|serberus_run_bounded'
    done

    # Functional (pam-lib.sh on temp fixtures): the unwire self-heals a
    # sudo_local a PREVIOUS install wired, and is a NO-OP on a fresh install.
    local prev="${FIXTURES}/sudo_local_prevwired"
    printf '%s\n%s\n' "${SERBERUS_PAM_CREATED_HEADER}" "${SERBERUS_PAM_AUTH_LINE}" > "${prev}"
    assert_true "prior-wired fixture: active pam_serberus.so line present before self-heal" \
        serberus_pam_sudo_local_has_module "${prev}"
    serberus_pam_remove_sudo_local "${prev}" >/dev/null
    assert_false "self-heal: active pam_serberus.so line removed (sudo falls back to Apple stack)" \
        serberus_pam_sudo_local_has_module "${prev}"

    local fresh="${FIXTURES}/sudo_local_fresh"
    printf '%s\n' 'auth       sufficient     pam_tid.so' > "${fresh}"
    local before after
    before=$(< "${fresh}")
    assert_eq "untouched" "$(serberus_pam_remove_sudo_local "${fresh}")" \
        "fresh install: unwire reports untouched (nothing wired)"
    after=$(< "${fresh}")
    assert_eq "${before}" "${after}" "fresh install: sudo_local left byte-identical"
    "${RM}" -f "${prev}" "${fresh}"
}

# A label disabled by an uninstall/abort must not block the next install:
# every installer enables it BEFORE bootstrap, and "up" means running.
test_postinstall_enable_and_running() {
    local file
    local enable_line
    local bootstrap_line
    for file in "${GEN_POSTINSTALL}" "${GEN_TEST_POSTINSTALL}" "${PKG_DIR}/Scripts/postinstall" \
        "${REPO_DIR}/Support/serberusd-devtool.sh"
    do
        enable_line=$("${GREP}" -n 'LAUNCHCTL}" enable "system/' "${file}" | head -n 1 | cut -d: -f1)
        bootstrap_line=$("${GREP}" -n 'LAUNCHCTL}" bootstrap system' "${file}" | head -n 1 | cut -d: -f1)
        if [[ -n "${enable_line}" && -n "${bootstrap_line}" && "${enable_line}" -lt "${bootstrap_line}" ]]
        then
            pass "${file##*/}: launchctl enable (line ${enable_line}) precedes bootstrap (line ${bootstrap_line})"
        else
            fail "${file##*/}: launchctl enable must precede bootstrap (enable@${enable_line:-?}, bootstrap@${bootstrap_line:-?})"
        fi
    done
    assert_true "sentinel postinstall waits for a RUNNING daemon" \
        "${GREP}" -q 'serberus_launchd_wait_running' "${GEN_POSTINSTALL}"
    assert_true "production postinstall waits for a RUNNING daemon" \
        "${GREP}" -q 'if ! serberus_launchd_wait_running' "${PKG_DIR}/Scripts/postinstall"
    assert_true "daemon-test postinstall waits for a STABLE daemon pid" \
        "${GREP}" -q '^if ! serberus_launchd_wait_running' "${GEN_TEST_POSTINSTALL}"
    assert_order "${GEN_PAM_POSTINSTALL}" '^if ! serberus_launchd_wait_running' '^if ! wire_sudo_local$' \
        "pam-test postinstall: stable daemon pid BEFORE wiring sudo_local"
}

# E + signature pinning: every path that wires sudo_local checks the module's
# directory chain and its team first.
test_postinstall_module_checks() {
    local file
    for file in "${GEN_POSTINSTALL}" "${GEN_PAM_POSTINSTALL}" "${PKG_DIR}/Scripts/postinstall"
    do
        assert_true "$(short "${file}"): checks the module's directory chain" \
            "${GREP}" -q 'serberus_pam_module_path_is_safe' "${file}"
        assert_true "$(short "${file}"): pins the module to the daemon's team" \
            "${GREP}" -q 'serberus_codesign_satisfies_team "${PAM_MODULE}"' "${file}"
        assert_true "$(short "${file}"): post-merge sanity requires the canonical line" \
            "${GREP}" -q 'serberus_pam_sudo_local_is_canonical' "${file}"
    done
    assert_true "production postinstall pins the SerberusAuth plugin to the daemon's team" \
        "${GREP}" -q 'serberus_codesign_satisfies_team "${AUTH_PLUGIN}"' "${PKG_DIR}/Scripts/postinstall"
    assert_true "production postinstall refuses a team-less daemon (no --strict fallback)" \
        "${GREP}" -q 'production requires a Developer ID signature' "${PKG_DIR}/Scripts/postinstall"
    assert_true "Support/build-pam.sh --install checks the directory chain" \
        "${GREP}" -q 'serberus_pam_module_path_is_safe' "${REPO_DIR}/Support/build-pam.sh"
    local script
    for script in preinstall postinstall
    do
        assert_true "production ${script} refuses a target volume other than /" \
            "${GREP}" -Eq '^require_boot_volume$' "${PKG_DIR}/Scripts/${script}"
    done
}

# ---- A: teardown ORDER in every full uninstall ----
# drop-in -> unwire -> disable -> bootout (wait until gone) -> drop-in ->
# demote JIT -> drop-in -> restore authdb -> plugin (only if restored) ->
# files. The disable comes after the unwire, so an interrupted run never
# leaves sudo_local wired behind a disabled daemon.
test_uninstall_teardown_order() {
    assert_true "generated uninstall helper exists" test -f "${GEN_UNINSTALL}"
    local file
    for file in "${GEN_UNINSTALL}" "${GEN_UNINSTALL_PKG}" "${GEN_TEST_UNINSTALL}" \
        "${PKG_DIR}/Scripts/uninstall.sh"
    do
        assert_sequence "${file}" \
            "$(short "${file}"): drop-in -> unwire -> disable -> bootout -> drop-in -> demote JIT -> drop-in -> restore -> plugin -> files" \
            '^remove_sudoers_dropin(_or_stop)?$' \
            '^unwire_sudo_local$' \
            '^disable_daemon$' \
            '^bootout_daemon$' \
            '^recheck_sudoers_dropin$' \
            '^demote_jit_admins$' \
            '^recheck_sudoers_dropin$' \
            '^restore_(authdb|authorization_db)$' \
            '^remove_auth_plugin_if_restored$' \
            '^remove_(components|daemon_files|artifacts)$'

        # The drop-in is checked AGAIN after the bootout: the running daemon
        # could rewrite it until it stopped.
        local second
        second=$("${AWK}" '/Run Script Block/{inrun=1} inrun && /^(remove_sudoers_dropin(_or_stop)?|recheck_sudoers_dropin)( \|\| .*)?$/{n++; if (n==2) {print NR; exit}}' "${file}")
        local bootout
        bootout=$(run_block_line "${file}" '^bootout_daemon$')
        if [[ -n "${second}" && -n "${bootout}" && "${second}" -gt "${bootout}" ]]
        then
            pass "$(short "${file}"): drop-in re-checked after the bootout"
        else
            fail "$(short "${file}"): drop-in must be re-checked after the bootout"
        fi

        # A drop-in that survives a re-check fails the run (exit 1).
        assert_order "${file}" '^UNINSTALL_SUCCEEDED=1$' 'DROPIN_SURVIVED}" -eq 1' \
            "$(short "${file}"): a surviving drop-in makes the run exit non-zero"
        body_order "${file}" recheck_sudoers_dropin \
            "$(short "${file}"): a failed re-check is recorded" 'DROPIN_SURVIVED=1'
        body_order "${file}" bootout_daemon \
            "$(short "${file}"): the bootout waits until launchd drops the job" \
            'bootout "system/' 'serberus_launchd_wait_gone'
        body_order "${file}" demote_jit_admins \
            "$(short "${file}"): no --demote-jit beside a daemon still loaded" \
            'DAEMON_GONE' 'demote-jit'
        # The daemon-test pkg owns no module (its PAM-test sibling does).
        if [[ "${file}" != "${GEN_TEST_UNINSTALL}" ]]
        then
            assert_true "$(short "${file}"): removes a stray pam_serberus.so.2" \
                "${GREP}" -Eq 'SERBERUS_PAM_MODULE_VERSIONED_PATH|PAM_MODULE_VERSIONED' "${file}"
        fi

        # A failed unwire re-enables the (still running) daemon and stops.
        body_order "${file}" unwire_sudo_local \
            "$(short "${file}"): failed unwire re-enables the daemon before exit 1" \
            'LAUNCHCTL}" enable|^[[:space:]]+reenable_daemon$' 'exit 1'

        # demote-jit and restore try BOTH daemon forms.
        assert_true "$(short "${file}"): demote/restore know the flat test binary" \
            "${GREP}" -Eq 'PrivilegedHelperTools/(com\.herojoneslabs\.serberus|\$\{ORG\})\.daemon"' "${file}"
        assert_true "$(short "${file}"): demote/restore know the production bundle" \
            "${GREP}" -q 'serberusd.app' "${file}"
        assert_true "$(short "${file}"): runs --demote-jit" \
            "${GREP}" -q -- '--demote-jit' "${file}"
    done

    # The PAM-only helper owns no daemon: drop-in -> unwire -> drop-in -> module.
    assert_sequence "${GEN_PAM_UNINSTALL}" \
        "pam-test uninstall: drop-in -> unwire -> module" \
        '^remove_sudoers_dropin(_or_stop)?$' '^unwire_sudo_local$' '^remove_module_and_receipt$'
    local pam_second
    pam_second=$("${AWK}" '/Run Script Block/{inrun=1} inrun && /^(if ! )?remove_sudoers_dropin(_or_stop)?( \|\| .*)?$/{n++} END{print n+0}' "${GEN_PAM_UNINSTALL}")
    assert_eq "2" "${pam_second}" "pam-test uninstall: drop-in removed before AND after the unwire"
    assert_order "${GEN_PAM_UNINSTALL}" '^UNINSTALL_SUCCEEDED=1$' 'DROPIN_SURVIVED}" -eq 1' \
        "pam-test uninstall: a surviving drop-in makes the run exit non-zero"
    assert_true "pam-test uninstall: removes a stray pam_serberus.so.2" \
        "${GREP}" -q 'SERBERUS_PAM_MODULE_VERSIONED_PATH' "${GEN_PAM_UNINSTALL}"
    local helper
    for helper in "${GEN_UNINSTALL}" "${GEN_TEST_UNINSTALL}" "${GEN_PAM_UNINSTALL}"
    do
        body_order "${helper}" source_pam_lib \
            "$(short "${helper}"): pam-lib.sh is sourced only through a root-only path chain" \
            'path_chain_is_root_only' 'source "'
    done
}

# The restore result GATES the plugin (and backups) deletion.
test_restore_gates_plugin_removal() {
    local file
    for file in "${GEN_UNINSTALL}" "${GEN_UNINSTALL_PKG}" "${GEN_TEST_UNINSTALL}" \
        "${PKG_DIR}/Scripts/uninstall.sh"
    do
        body_order "${file}" remove_auth_plugin_if_restored \
            "$(short "${file}"): plugin removal returns early unless the restore succeeded" \
            'AUTHDB_RESTORE_OK}" -ne 1' 'return 0' 'RM}" -rf|remove_component'

        assert_true "$(short "${file}"): AUTHDB_RESTORE_OK starts at 0" \
            "${GREP}" -Eq '^AUTHDB_RESTORE_OK=0$' "${file}"

        # AUTHDB_RESTORE_OK=1 is only ever set inside the restore function.
        local fn
        fn=$("${GREP}" -Eo '^restore_(authdb|authorization_db)\(\)' "${file}" | head -n 1)
        fn="${fn%()}"
        local range
        range=$("${AWK}" -v fn="${fn}" '$0 ~ "^" fn "\\(\\) \\{" {s=NR} s && !e && NR>s && /^}/ {e=NR} END{print s" "e}' "${file}")
        local start="${range% *}"
        local end="${range#* }"
        local set_line
        local outside=0
        while IFS= read -r set_line
        do
            if [[ "${set_line}" -lt "${start}" || "${set_line}" -gt "${end}" ]]
            then
                outside=1
            fi
        done < <("${GREP}" -nE '^[^#]*AUTHDB_RESTORE_OK=1' "${file}" | cut -d: -f1)
        assert_eq "0" "${outside}" "$(short "${file}"): only ${fn} sets AUTHDB_RESTORE_OK=1"
        body_order "${file}" "${fn}" "$(short "${file}"): ${fn} runs --restore-authdb" '--restore-authdb'
    done
}

# ---- D: no PATH hijack in anything root runs ----
test_root_scripts_use_system_path() {
    local -a root_scripts=(
        "${PKG_DIR}/Scripts/preinstall"
        "${PKG_DIR}/Scripts/postinstall"
        "${PKG_DIR}/Scripts/uninstall.sh"
        "${PKG_DIR}/Scripts/pam-lib.sh"
        "${PKG_DIR}/verify-uninstall.sh"
        "${REPO_DIR}/Support/serberusd-devtool.sh"
        "${REPO_DIR}/Support/build-pam.sh"
        "${PKG_DIR}/tools/demote-console-user-from-admin.sh"
    )
    local script
    for script in "${REPO_DIR}"/Support/jamf-extension-attributes/*.sh
    do
        root_scripts+=("${script}")
    done
    for script in "${GEN_ALL[@]}"
    do
        root_scripts+=("${script}")
    done
    for script in "${root_scripts[@]}"
    do
        local label="$(short "${script}")"
        label="${label#"${REPO_DIR}/"}"
        if "${GREP}" -Eq '\$\(which ' "${script}"
        then
            fail "${label}: resolves tools with \$(which …) — use absolute paths"
        else
            pass "${label}: no \$(which …) tool resolution"
        fi
        local bad_path
        bad_path=$("${GREP}" -E '^[[:space:]]*export PATH=' "${script}" \
            | "${GREP}" -vF 'export PATH="/usr/bin:/bin:/usr/sbin:/sbin"' || true)
        if [[ -n "${bad_path}" ]]
        then
            fail "${label}: PATH must be /usr/bin:/bin:/usr/sbin:/sbin (found: ${bad_path})"
        else
            pass "${label}: system-only PATH"
        fi
    done
    local default
    for default in AWK CAT DSCACHEUTIL GREP ID MV PLUTIL RM STAT CODESIGN LAUNCHCTL
    do
        assert_true "pam-lib.sh PAM_LIB_${default} defaults to an absolute path" \
            "${GREP}" -Eq "^PAM_LIB_${default}=\"\\\$\\{PAM_LIB_${default}:-/" "${PKG_DIR}/Scripts/pam-lib.sh"
    done
}

# ---- F: relaunch markers live in a root-only directory, not /private/tmp ----
test_install_markers_not_in_tmp() {
    local script
    for script in "${FIXTURES}"/gen-build-sentinel-app-pkg/scripts/* "${FIXTURES}"/gen-build-commander-pkg/scripts/*
    do
        local label="$(short "${script}")"
        if "${GREP}" -Eq 'touch "?/private/tmp' "${script}"
        then
            fail "${label}: root touches a fixed /private/tmp name"
        else
            pass "${label}: no fixed /private/tmp marker is created"
        fi
    done
    for script in "${FIXTURES}"/gen-build-sentinel-app-pkg/scripts/preinstall "${FIXTURES}"/gen-build-commander-pkg/scripts/preinstall
    do
        assert_true "$(short "${script}"): marker under the root-only .install-markers dir" \
            "${GREP}" -q '^MARKER="/Library/Application Support/Serberus/.install-markers/' "${script}"
        body_order "${script}" prepare_marker_dir "$(short "${script}"): marker dir refuses symlinks and non-root owners" \
            '-L "\$\{SUPPORT_DIR\}"' 'mkdir -p -m 700' 'marker_dir_is_trusted'
    done
    for script in "${FIXTURES}"/gen-build-sentinel-app-pkg/scripts/postinstall "${FIXTURES}"/gen-build-commander-pkg/scripts/postinstall
    do
        assert_true "$(short "${script}"): relaunch only on a trusted marker" \
            "${GREP}" -q 'marker_is_trusted' "${script}"
    done
    # Per-user purges go through the symlink/ownership guard.
    for script in "${FIXTURES}/gen-build-sentinel-app-pkg/payload/Library/Application Support/Serberus/uninstall-serberus-sentinel-app.sh" \
        "${FIXTURES}/gen-build-commander-pkg/payload/Library/Application Support/Serberus/uninstall-serberus-commander.sh"
    do
        assert_true "${script##*/}: per-user deletes go through safe_user_remove" \
            "${GREP}" -q 'safe_user_remove "\${user_name}" "\${user_home}"' "${script}"
        assert_true "${script##*/}: accounts come from their records (dscl), not /Users folder names" \
            "${GREP}" -q '/usr/bin/dscl . -list /Users NFSHomeDirectory' "${script}"
        assert_false "${script##*/}: no loop over /Users/*" \
            "${GREP}" -q 'in /Users/\*' "${script}"
        assert_false "${script##*/}: no raw rm under a user home" \
            "${GREP}" -Eq 'rm -r?f "\$\{user_home\}' "${script}"
    done
    assert_true "uninstall pkg: per-user cache purge checks symlinks and ownership" \
        "${GREP}" -q 'purge_user_cache "${user}" "${home}"' "${GEN_UNINSTALL_PKG}"
    assert_true "uninstall pkg: accounts come from their records (dscl), not /Users folder names" \
        "${GREP}" -q 'DSCL}" . -list /Users NFSHomeDirectory' "${GEN_UNINSTALL_PKG}"
    assert_false "uninstall pkg: no loop over /Users/*" \
        "${GREP}" -q 'in /Users/\*' "${GEN_UNINSTALL_PKG}"
}

# ---- F: every log_* function a script calls is defined in that script ----
# (PKG/Scripts/uninstall.sh once called an undefined log_error under set -e.)
check_log_functions_defined() {
    local script="$1"
    local label="$2"
    local defined
    # `|| true`: a script with no log_* at all makes grep exit 1 (pipefail).
    defined=$("${GREP}" -Eo '^[[:space:]]*log_[a-z_]+\(\)' "${script}" | "${GREP}" -Eo 'log_[a-z_]+' | "${SORT}" -u) || true
    local called
    called=$("${GREP}" -Eo '(^[[:space:]]*|(\|\||&&|;|then|else|do)[[:space:]]+)log_[a-z_]+([[:space:]]|$)' "${script}" \
        | "${GREP}" -Eo 'log_[a-z_]+' | "${SORT}" -u) || true
    local name
    local missing=""
    for name in ${called}
    do
        if ! "${GREP}" -qx "${name}" <<< "${defined}"
        then
            missing+=" ${name}"
        fi
    done
    if [[ -z "${missing}" ]]
    then
        pass "${label}: every called log_* function is defined"
    else
        fail "${label}: calls undefined${missing}"
    fi
}

test_log_functions_defined() {
    local script
    for script in "${GEN_ALL[@]}"
    do
        check_log_functions_defined "${script}" "$(short "${script}")"
    done
    for script in "${PKG_DIR}"/*.sh "${PKG_DIR}"/Scripts/* "${PKG_DIR}"/tools/*.sh \
        "${PKG_DIR}"/tests/*.sh "${REPO_DIR}"/Support/*.sh
    do
        check_log_functions_defined "${script}" "${script#"${REPO_DIR}/"}"
    done
}

# ---- PREINSTALL: break-glass preflight, and NO daemon-loaded install gate ----
test_preinstall_structure() {
    assert_true "generated preinstall exists" test -f "${GEN_PREINSTALL}"

    # The break-glass preflight (READ-only) runs FIRST — BEFORE the MUTATING
    # legacy uninstall and same-prefix bootout — so what it reports describes the
    # machine as we FOUND it, and so any future fail-closed gate added here would
    # still leave a prior install intact.
    assert_order "${GEN_PREINSTALL}" 'preflight_break_glass' 'uninstall_legacy_daemon' \
        "preinstall: break-glass preflight BEFORE legacy uninstall"
    assert_order "${GEN_PREINSTALL}" 'preflight_break_glass' 'bootout_daemon' \
        "preinstall: break-glass preflight BEFORE same-prefix bootout"

    # Pre-Sentinel-rename cleanup (2026-08-19 repackage): the preinstall removes
    # the three old-named GUI app orphans and forgets the old …coretestpkg
    # receipt. It runs AFTER the read-only preflight (so an abort strands
    # nothing) and is best-effort / non-fatal (outside the sudo/authURI chain).
    assert_order "${GEN_PREINSTALL}" 'preflight_break_glass' 'remove_prerename_artifacts' \
        "preinstall: break-glass preflight BEFORE pre-rename cleanup"
    assert_true "preinstall run block invokes pre-rename cleanup" \
        "${GREP}" -Eq '^remove_prerename_artifacts$' "${GEN_PREINSTALL}"
    assert_true "preinstall removes old SerberusCapture.app orphan" \
        "${GREP}" -Fq '/Applications/SerberusCapture.app' "${GEN_PREINSTALL}"
    assert_true "preinstall removes old Serberus.app (Commander) orphan" \
        "${GREP}" -Fq '/Applications/Serberus.app' "${GEN_PREINSTALL}"
    assert_true "preinstall removes old SerberusAgent.app (Sentinel GUI) orphan" \
        "${GREP}" -Fq '/Applications/SerberusAgent.app' "${GEN_PREINSTALL}"
    assert_true "preinstall forgets the pre-rename …coretestpkg receipt" \
        "${GREP}" -Fq 'com.herojoneslabs.serberus.coretestpkg' "${GEN_PREINSTALL}"

    # It must NOT carry the PAM-only pkg's daemon-loaded install gate: the
    # daemon ships in THIS pkg and comes up in the postinstall, so gating the
    # install on "daemon loaded" here would be wrong.
    assert_false "preinstall has NO 'daemon is NOT loaded and enforce' install gate" \
        "${GREP}" -Eq 'is NOT loaded and enforcementMode' "${GEN_PREINSTALL}"
}

# ---- PREINSTALL: the preflight ABORTS only on the genuine brick, else WARNS ----
# The enrollment-race contract with the brick protection restored (F1). APNS
# queuing routinely lands this pkg BEFORE the config profile:
#   - no usable config anywhere -> the daemon is awaitingConfig and pam_serberus
#     returns PAM_IGNORE, so sudo passes through natively and NOTHING is mutated
#     -> WARN + PROCEED (inert);
#   - config missing/unsafe but a last-known-good snapshot exists -> both halves
#     run on the snapshot, which is enforceable by construction (break-glass
#     intact) -> WARN + PROCEED;
#   - config PRESENT + enforce + a pamBypass that resolves to NO account + NO
#     snapshot -> the daemon WILL enforce with a break-glass that resolves to
#     nobody -> every user denied -> BRICK -> ABORT (exit 1).
# The abort must be present (the iteration-2 blanket WARN removed it), guarded by
# config-present + snapshot-absent, and must NOT fire in the survivable cases.
test_preinstall_preflight_warns_and_proceeds() {
    local body
    body=$("${AWK}" '/^preflight_break_glass\(\)/{inf=1} inf{print} inf&&/^}$/{exit}' "${GEN_PREINSTALL}")

    assert_true "preinstall preflight ABORTS (exit 1) on the genuine brick" \
        "${GREP}" -Fq 'exit 1' <(printf '%s\n' "${body}")
    assert_true "preinstall preflight names the FAILED/abort outcome" \
        "${GREP}" -Fq 'BREAK-GLASS PREFLIGHT FAILED' <(printf '%s\n' "${body}")
    # The abort is gated on config-present + snapshot-absent, never a blanket abort.
    assert_true "preinstall preflight gates the abort on serberus_pam_config_present" \
        "${GREP}" -Fq 'serberus_pam_config_present' <(printf '%s\n' "${body}")
    assert_true "preinstall preflight warns + proceeds in the survivable cases" \
        "${GREP}" -Fq 'BREAK-GLASS PREFLIGHT WARNING' <(printf '%s\n' "${body}")

    # Both warning branches must be present and must name what actually happens.
    assert_true "preinstall preflight names the INERT (awaiting-config) outcome" \
        "${GREP}" -Fq 'INERT' <(printf '%s\n' "${body}")
    assert_true "preinstall preflight names the last-known-good fallback outcome" \
        "${GREP}" -Fq 'last-known-good' <(printf '%s\n' "${body}")

    # It still reports the effective config (mode + bypass counts) either way.
    assert_true "preinstall preflight still logs the effective config" \
        "${GREP}" -Fq 'Effective config: enforcementMode=' <(printf '%s\n' "${body}")

    # The last-known-good path must match the daemon's + pam_config.h's constant.
    assert_true "preinstall knows the last-known-good snapshot path" \
        "${GREP}" -Fq '/Library/Application Support/Serberus/last-known-good-config.plist' \
        "${GEN_PREINSTALL}"

    # The preflight call must still be present in the run block as a bare call,
    # ahead of every mutating step.
    local run
    run=$("${AWK}" '/Run Script Block/{inrun=1} inrun{print}' "${GEN_PREINSTALL}")
    assert_true "preinstall run block invokes the break-glass preflight FIRST" \
        "${GREP}" -Eq '^preflight_break_glass$' <(printf '%s\n' "${run}")
}

# ---- sudo_local merge: canonical line + upgrade from the legacy control ----
# The active line must use `requisite` (deny returns the stack immediately, no
# post-deny password prompt). A file already wired with the older `required`
# control must be REWRITTEN in place on upgrade — reporting `present` and
# leaving the stale control would keep the looping-prompt behavior forever.
test_sudo_local_requisite_and_upgrade() {
    # Canonical create writes the requisite line.
    local created="${FIXTURES}/sudo_local_created"
    "${RM}" -f "${created}"
    serberus_pam_merge_sudo_local "${created}" >/dev/null
    assert_true "created sudo_local uses the requisite control" \
        "${GREP}" -Eq '^auth[[:space:]]+requisite[[:space:]]+.*pam_serberus\.so' "${created}"

    # A legacy `required` line is rewritten to `requisite` and reports merged.
    local legacy="${FIXTURES}/sudo_local_legacy_required"
    printf '%s\nauth       required       /usr/local/lib/pam/pam_serberus.so # serberus-managed\n' \
        "${SERBERUS_PAM_CREATED_HEADER}" > "${legacy}"
    assert_eq "merged" "$(serberus_pam_merge_sudo_local "${legacy}")" \
        "legacy required line reports merged (rewritten in place)"
    assert_true "upgraded sudo_local now uses requisite" \
        "${GREP}" -Eq '^auth[[:space:]]+requisite[[:space:]]+.*pam_serberus\.so' "${legacy}"
    assert_false "upgraded sudo_local no longer has a required pam_serberus line" \
        "${GREP}" -Eq '^auth[[:space:]]+required[[:space:]]+.*pam_serberus\.so' "${legacy}"

    # An already-canonical file is a no-op (present).
    assert_eq "present" "$(serberus_pam_merge_sudo_local "${legacy}")" \
        "already-requisite sudo_local reports present (idempotent)"

    "${RM}" -f "${created}" "${legacy}"
}

# ---- Functional break-glass preflight (via pam-lib.sh + hermetic mocks) ----
install_resolver_mocks() {
    serberus_pam_user_resolves() {
        [[ "$1" == "breakglass" || "$1" == "alpha" ]]
    }
    serberus_pam_group_resolves() {
        [[ "$1" == "admin" ]]
    }
}

# The predicate is unchanged — only the preinstall's REACTION to it changed
# (abort -> warn). It is still the definition of "safely enforceable", and it is
# still what the daemon's LKG snapshot invariant is built on, so it keeps its
# tests.
test_breakglass_preflight_functional() {
    local managed="${FIXTURES}/managed.plist"
    "${RM}" -f "${managed}"

    # Absent config => enforce + no bypass => not safely enforceable (the
    # preinstall WARNS; the daemon/PAM fall back to the LKG snapshot, or stay
    # inert when there is none).
    assert_false "preflight fails on absent config (enforce + no bypass)" \
        serberus_pam_preflight_break_glass "${managed}"

    # enforce + only a typo'd (unresolvable) bypass => not safely enforceable.
    write_config_plist "${managed}" '<string>enforce</string>' '<string>brekglass</string>' ''
    assert_eq "0" "$(serberus_pam_resolvable_bypass_count "${managed}" 2>/dev/null)" \
        "typo'd bypass resolves to zero entries"
    assert_false "preflight fails on enforce + only-unresolvable bypass" \
        serberus_pam_preflight_break_glass "${managed}"

    # monitor mode passes with no bypass (safe to install).
    write_config_plist "${managed}" '<string>monitor</string>' '' ''
    assert_true "preflight passes on monitor" \
        serberus_pam_preflight_break_glass "${managed}"

    # enforce + one RESOLVABLE bypass entry passes.
    write_config_plist "${managed}" '<string>enforce</string>' '<string>breakglass</string>' ''
    assert_true "preflight passes on enforce + resolvable bypass" \
        serberus_pam_preflight_break_glass "${managed}"

    "${RM}" -f "${managed}"
}

# Every generated pre/postinstall and uninstall script, excluding the staged
# pam-lib.sh (a sourced library, not a root entry point).
generated_root_scripts() {
    local script
    for script in "${GEN_ALL[@]}"
    do
        if [[ "${script##*/}" != "pam-lib.sh" ]]
        then
            printf '%s\n' "${script}"
        fi
    done
}

# ---- upgrade posture: tear the gates down BEFORE the daemon goes ----
# A failed or interrupted upgrade must fall back to native sudo, never to
# blanket denial: every preinstall that boots the daemon out first removes
# the sudoers drop-in and unwires sudo_local, and never disables the label.
test_preinstall_teardown_first() {
    local file
    for file in "${PKG_DIR}/Scripts/preinstall" "${GEN_PREINSTALL}" \
        "${FIXTURES}/gen-build-test-pkg/scripts/preinstall"
    do
        assert_sequence "${file}" \
            "$(short "${file}"): teardown-first: drop-in -> unwire -> bootout" \
            '^[[:space:]]*remove_sudoers_dropin$' \
            '^[[:space:]]*unwire_sudo_local$' \
            '^[[:space:]]*bootout_daemon$'
        # Before the unwire, straight after the bootout (the old daemon could
        # re-provision it until then) and after --demote-jit (up to 120 s).
        assert_sequence "${file}" \
            "$(short "${file}"): drop-in -> unwire -> bootout -> drop-in -> demote JIT -> drop-in" \
            '^[[:space:]]*remove_sudoers_dropin$' \
            '^[[:space:]]*unwire_sudo_local$' \
            '^[[:space:]]*bootout_daemon$' \
            '^[[:space:]]*remove_sudoers_dropin$' \
            '^[[:space:]]*demote_jit_with_old_daemon$' \
            '^[[:space:]]*remove_sudoers_dropin$'
        body_order "${file}" bootout_daemon \
            "$(short "${file}"): the bootout waits until launchd drops the job" \
            'bootout "system/' 'serberus_launchd_wait_gone' 'DAEMON_GONE=0'
        body_order "${file}" demote_jit_with_old_daemon \
            "$(short "${file}"): --demote-jit is pinned to the recorded team and skipped beside a live daemon" \
            'DAEMON_GONE' 'serberus_recorded_team' 'serberus_daemon_trusted "\$\{binary\}" "\$\{team\}"'
        assert_false "$(short "${file}"): --demote-jit does not require the (booted-out) job to be loaded" \
            "${GREP}" -q 'LAUNCHCTL}" print' <<< "$(function_body "${file}" demote_jit_with_old_daemon)"
        body_order "${file}" remove_sudoers_dropin \
            "$(short "${file}"): a drop-in surviving after the unwire re-bootstraps the old daemon" \
            'SUDO_LOCAL_UNWIRED' 'bootstrap system'
        assert_false "$(short "${file}"): the preinstall never disables the daemon label" \
            "${GREP}" -q 'LAUNCHCTL}" disable' "${file}"
        body_order "${file}" unwire_sudo_local \
            "$(short "${file}"): a surviving pam_serberus line stops the upgrade before the bootout" \
            'serberus_pam_sudo_local_has_module' 'exit 1'
    done

    # The production break-glass preflight runs in the PREINSTALL, before the
    # teardown — never in the postinstall after it.
    assert_order "${PKG_DIR}/Scripts/preinstall" '^if ! preflight_break_glass$' '^[[:space:]]*remove_sudoers_dropin$' \
        "production preinstall: break-glass preflight BEFORE the teardown"
    assert_false "production postinstall no longer runs the break-glass preflight" \
        "${GREP}" -Eq '^[^#]*preflight_break_glass' "${PKG_DIR}/Scripts/postinstall"

    # The PAM-only pkg owns no daemon: drop-in -> unwire, no bootout, and the
    # read-only gates (preflight, daemon present) come first.
    local pam_pre="${FIXTURES}/gen-build-pam-test-pkg/scripts/preinstall"
    assert_sequence "${pam_pre}" \
        "pam-test preinstall: preflight -> daemon required -> drop-in -> unwire" \
        '^preflight_break_glass$' '^require_daemon$' '^remove_sudoers_dropin$' '^unwire_sudo_local$'
    assert_false "pam-test preinstall never boots the daemon out" \
        "${GREP}" -q 'LAUNCHCTL}" bootout' "${pam_pre}"
}

# ---- EXIT traps: no root script can end half-way without its safety net ----
test_exit_traps() {
    local script
    while IFS= read -r script
    do
        assert_true "$(short "${script}"): installs an EXIT trap" \
            "${GREP}" -Eq '^trap [a-z_]+ EXIT$' "${script}"
    done < <(generated_root_scripts)
    for script in "${PKG_DIR}/Scripts/preinstall" "${PKG_DIR}/Scripts/postinstall" \
        "${PKG_DIR}/Scripts/uninstall.sh"
    do
        assert_true "$(short "${script}"): installs an EXIT trap" \
            "${GREP}" -Eq '^trap [a-z_]+ EXIT$' "${script}"
    done

    # Postinstalls: the trap is armed right after pam-lib.sh is sourced, runs
    # the abort path, and a success marker is set just before exit 0.
    local next
    for script in "${GEN_POSTINSTALL}" "${GEN_TEST_POSTINSTALL}" "${GEN_PAM_POSTINSTALL}" \
        "${PKG_DIR}/Scripts/postinstall"
    do
        next=$("${AWK}" '/Run Script Block/{inrun=1} inrun && prev == "source_pam_lib" {print; exit} inrun {prev=$0}' "${script}")
        assert_eq "trap on_exit EXIT" "${next}" "$(short "${script}"): EXIT trap armed right after source_pam_lib"
        body_order "${script}" on_exit "$(short "${script}"): the EXIT trap runs the abort path unless the install succeeded" \
            'INSTALL_SUCCEEDED}" -eq 1' 'abort_install'
        assert_true "$(short "${script}"): success marker set before the final exit 0" \
            "${GREP}" -Eq '^INSTALL_SUCCEEDED=1$' "${script}"
    done

    # Uninstallers (set -e): stopping early re-arms a daemon that sudo_local
    # still points at.
    for script in "${GEN_UNINSTALL}" "${GEN_TEST_UNINSTALL}" "${GEN_PAM_UNINSTALL}" \
        "${GEN_UNINSTALL_PKG}" "${PKG_DIR}/Scripts/uninstall.sh"
    do
        body_order "${script}" on_exit "$(short "${script}"): the EXIT trap keeps the daemon enabled while sudo_local is wired" \
            'UNINSTALL_SUCCEEDED}" -eq 1' 'serberus_daemon_rearm_if_wired|reenable_daemon'
        assert_true "$(short "${script}"): success marker set before the final exit 0" \
            "${GREP}" -Eq '^UNINSTALL_SUCCEEDED=1$' "${script}"
    done
}

# ---- umask: nothing root writes is group/other-writable by accident ----
test_umask() {
    local script
    local -a statics=(
        "${PKG_DIR}/Scripts/preinstall"
        "${PKG_DIR}/Scripts/postinstall"
        "${PKG_DIR}/Scripts/uninstall.sh"
        "${PKG_DIR}/verify-uninstall.sh"
        "${PKG_DIR}/tools/demote-console-user-from-admin.sh"
        "${REPO_DIR}/Support/serberusd-devtool.sh"
        "${REPO_DIR}/Support/build-pam.sh"
    )
    while IFS= read -r script
    do
        statics+=("${script}")
    done < <(generated_root_scripts)
    for script in "${statics[@]}"
    do
        assert_true "$(short "${script}"): umask 022" "${GREP}" -Eq '^umask 022$' "${script}"
    done
}

# ---- an abort never stops the daemon while sudo_local is still wired ----
# If an active pam_serberus line SURVIVES the unwire, the abort re-arms the
# daemon and exits — the bootout/demote/restore steps are not reached.
test_abort_keeps_daemon_when_unwire_fails() {
    local file
    local branch
    for file in "${GEN_POSTINSTALL}" "${GEN_TEST_POSTINSTALL}" "${PKG_DIR}/Scripts/postinstall"
    do
        branch=$(function_body "${file}" abort_install | "${AWK}" '
            /if ! unwire_sudo_local/ { inb = 1; next }
            inb && /^    fi$/ { exit }
            inb { print }
        ')
        if [[ -z "${branch}" ]]
        then
            fail "$(short "${file}"): abort_install has no 'if ! unwire_sudo_local' branch"
            continue
        fi
        assert_true "$(short "${file}"): surviving line => daemon re-armed" \
            "${GREP}" -q 'serberus_daemon_rearm_if_wired' <(printf '%s\n' "${branch}")
        assert_true "$(short "${file}"): surviving line => exit 1 (loud failure)" \
            "${GREP}" -Eq '^[[:space:]]+exit 1$' <(printf '%s\n' "${branch}")
        assert_false "$(short "${file}"): surviving line => NO bootout on that branch" \
            "${GREP}" -Eq 'bootout_daemon|LAUNCHCTL}" bootout' <(printf '%s\n' "${branch}")
        body_order "${file}" unwire_sudo_local "$(short "${file}"): unwire reports a surviving line (return 1)" \
            'serberus_pam_sudo_local_has_module' 'return 1'
    done
}

# ---- $3: every generated pre/postinstall installs on the running system only ----
test_require_boot_volume() {
    local script
    for script in "${GEN_DIR}"/scripts/preinstall "${GEN_DIR}"/scripts/postinstall \
        "${FIXTURES}"/gen-*/scripts/preinstall "${FIXTURES}"/gen-*/scripts/postinstall
    do
        if [[ ! -f "${script}" ]]
        then
            continue
        fi
        assert_true "$(short "${script}"): calls require_boot_volume" \
            "${GREP}" -Eq '^require_boot_volume$' "${script}"
        assert_true "$(short "${script}"): reads the target volume from \$3" \
            "${GREP}" -Eq 'TARGET_VOLUME="\$\{3:-\}"' "${script}"
    done
}

# ---- bundles in a payload are never relocatable ----
test_relocatable_bundles_pinned() {
    local builder
    for builder in build-pkg build-core-test-pkg build-sentinel-app-pkg build-commander-pkg build-authuribrowser-pkg
    do
        assert_true "${builder}.sh: analyzes the payload into a component plist" \
            "${GREP}" -q -- '--analyze --root "${PAYLOAD_DIR}" "${COMPONENT_PLIST}"' "${PKG_DIR}/${builder}.sh"
        assert_true "${builder}.sh: pins BundleIsRelocatable false" \
            "${GREP}" -q 'BundleIsRelocatable false' "${PKG_DIR}/${builder}.sh"
        assert_true "${builder}.sh: pkgbuild uses the component plist" \
            "${GREP}" -q -- '--component-plist "${COMPONENT_PLIST}"' "${PKG_DIR}/${builder}.sh"
    done
}

# ---- the daemon's signing identifier is pinned by its peers ----
# A flat binary named com.herojoneslabs.serberus.daemon would otherwise get the
# identifier "com.herojoneslabs.serberus" (codesign treats ".daemon" as an
# extension), and the PAM module rejects the daemon — every sudo denies.
test_daemon_codesign_identifier() {
    local file
    local commands
    local cmd
    local count
    for file in "${PKG_DIR}/build-core-test-pkg.sh" "${PKG_DIR}/build-test-pkg.sh" \
        "${REPO_DIR}/Support/serberusd-devtool.sh" "${REPO_DIR}/Support/build-serberusd-bundle.sh"
    do
        commands=$("${AWK}" '
            /"\$\{CODESIGN\}"/ {
                cmd = $0
                while (cmd ~ /\\[[:space:]]*$/ && (getline more) > 0) { cmd = cmd " " more }
                print cmd
            }
        ' "${file}" | "${GREP}" -E -- '--sign ' | "${GREP}" -E 'INSTALL_BINARY_PATH|BUNDLE_PATH|\{staged\}' || true)
        count=0
        while IFS= read -r cmd
        do
            if [[ -z "${cmd}" ]]
            then
                continue
            fi
            count=$((count + 1))
            if [[ "${cmd}" == *'--identifier "${BUNDLE_ID}"'* ]]
            then
                pass "$(short "${file}"): daemon codesign pins --identifier \${BUNDLE_ID}"
            else
                fail "$(short "${file}"): daemon codesign without --identifier: ${cmd}"
            fi
        done <<< "${commands}"
        if [[ "${count}" -eq 0 ]]
        then
            fail "$(short "${file}"): no daemon codesign found to check"
        fi
        assert_true "$(short "${file}"): BUNDLE_ID is com.herojoneslabs.serberus.daemon" \
            "${GREP}" -q '^readonly BUNDLE_ID="com.herojoneslabs.serberus.daemon"$' "${file}"
    done
}

# ---- the plugin goes only when the LIVE AuthorizationDB is clean ----
test_restore_checks_live_authdb() {
    local file
    local fn
    for file in "${GEN_UNINSTALL}" "${GEN_UNINSTALL_PKG}" "${GEN_TEST_UNINSTALL}" \
        "${PKG_DIR}/Scripts/uninstall.sh"
    do
        fn=$("${GREP}" -Eo '^restore_(authdb|authorization_db)\(\)' "${file}" | head -n 1)
        fn="${fn%()}"
        body_order "${file}" "${fn}" "$(short "${file}"): restore exit 0 is followed by the live AuthorizationDB check" \
            '--restore-authdb' 'authdb_free_of_serberus' 'AUTHDB_RESTORE_OK=1'
        # Every AUTHDB_RESTORE_OK=1 sits directly under an authdb check.
        local unguarded
        unguarded=$("${AWK}" '
            /^[^#]*AUTHDB_RESTORE_OK=1/ { if (p1 !~ /authdb_free_of_serberus/ && p2 !~ /authdb_free_of_serberus/) print NR }
            { p2 = p1; p1 = $0 }
        ' "${file}")
        assert_eq "" "${unguarded}" "$(short "${file}"): every AUTHDB_RESTORE_OK=1 is gated on the live AuthorizationDB check"
        assert_true "$(short "${file}"): one-shots run with a deadline" \
            "${GREP}" -Eq 'serberus_run_bounded|run_bounded|run_daemon_oneshot' "${file}"
    done
    body_order "${REPO_DIR}/Support/serberusd-devtool.sh" do_uninstall \
        "serberusd-devtool.sh: --purge keeps authdb-backups unless the restore succeeded and the AuthorizationDB is clean" \
        'run_daemon_oneshot --restore-authdb' 'serberus_authdb_free_of_serberus' 'restore_ok=1' \
        'restore_ok}" -eq 1' 'EXCEPT'
}

# ---- core pkg: renamed file, unchanged receipt ----
test_core_pkg_naming() {
    local builder="${PKG_DIR}/build-core-test-pkg.sh"
    assert_true "core builder writes SerberusCore-<version>.pkg" \
        "${GREP}" -q 'OUTPUT_PKG="${BUILD_DIR}/SerberusCore-${PKG_VERSION}.pkg"' "${builder}"
    assert_true "core builder keeps the …sentineltestpkg receipt identifier" \
        "${GREP}" -q '^readonly PKG_IDENTIFIER="com.herojoneslabs.serberus.sentineltestpkg"$' "${builder}"
    assert_true "core uninstall helper forgets the current receipt" \
        "${GREP}" -q 'PKGUTIL}" --forget "${PKG_IDENTIFIER}"' "${GEN_UNINSTALL}"
    assert_true "core uninstall helper forgets the old …coretestpkg receipt" \
        "${GREP}" -q 'PKGUTIL}" --forget "${LEGACY_CORE_RECEIPT}"' "${GEN_UNINSTALL}"
    assert_true "combined builder wraps SerberusCore-<version>.pkg" \
        "${GREP}" -q 'SerberusCore-${AGENT_VERSION}.pkg' "${PKG_DIR}/build-combined-pkg.sh"
    assert_false "no script code still references build-sentinel-test-pkg.sh" \
        "${GREP}" -rEq '^[^#]*build-sentinel-test-pkg' "${PKG_DIR}"/*.sh "${PKG_DIR}/Scripts" "${PKG_DIR}/tools" "${REPO_DIR}/Support"
}

# ---- demote tool: the last usable admin is never demoted ----
test_demote_tool_admin_checks() {
    local tool="${PKG_DIR}/tools/demote-console-user-from-admin.sh"
    assert_true "demote tool requires another admin's SecureToken" \
        "${GREP}" -q -- '-secureTokenStatus' "${tool}"
    assert_true "demote tool requires a volume owner on Apple silicon" \
        "${GREP}" -q 'apfs listUsers /' "${tool}"
    assert_true "demote tool parses 'Volume Owner: Yes'" \
        "${GREP}" -q 'Volume Owner: Yes' "${tool}"
    assert_false "demote tool has no force override" \
        "${GREP}" -Eq 'PARAM_FORCE|FORCE' "${tool}"
    assert_true "demote tool: the organisation name is Jamf parameter 4, default \"your IT team\"" \
        "${GREP}" -qF 'readonly ORG_NAME_FRIENDLY="${4:-your IT team}"' "${tool}"
    assert_false "demote tool: no organisation name is hardcoded" \
        "${GREP}" -q 'Hero Jones Labs' "${tool}"
    assert_order "${tool}" '^if is_system_account' 'DSEDITGROUP}" -o edit -d' \
        "demote tool: a system console user exits before any demotion"
    assert_order "${tool}" '^if ! load_jc_elevated' '^other_admins=' \
        "demote tool: Jamf Connect elevations are loaded before the admins are counted"
    assert_true "demote tool: JIT grants are matched by uid too" \
        "${GREP}" -q 'SELECT DISTINCT uid FROM grants' "${tool}"

    # Functional: system accounts, and the Jamf Connect log parser.
    local fns
    fns=$("${AWK}" '/^(is_system_account|jc_open_elevations)\(\) \{/,/^}/' "${tool}")
    local open
    open=$(
        JQ="/usr/bin/jq"
        ID="/usr/bin/id"
        FIRST_USER_UID=500
        eval "${fns}"
        is_system_account "_mbsetupuser" && printf 'system:_mbsetupuser\n'
        is_system_account "root" && printf 'system:root\n'
        jc_open_elevations <<'NDJSON'
Filtering the log data using "subsystem == ..."
{"processImagePath":"/Applications/Jamf Connect.app/Contents/MacOS/Jamf Connect","eventMessage":"User alice elevated to admin for 30 minutes."}
{"processImagePath":"/Applications/Self Service+.app/Contents/MacOS/Self Service+","eventMessage":"bob elevated to administrator for 5 minutes"}
{"processImagePath":"/Library/Application Support/JamfConnect/helper","eventMessage":"Removed user bob from the admin group."}
{"processImagePath":"/Users/carol/fake/Jamf Connect","eventMessage":"User carol elevated to admin for 30 minutes."}
{"processImagePath":"/Applications/Self Service.app/Contents/MacOS/JCDaemon.app/Contents/MacOS/JCDaemon","eventMessage":"Added user dave to admin group."}
{"processImagePath":"/Applications/Self Service.app/Contents/MacOS/JCDaemon.app/Contents/MacOS/JCDaemon","eventMessage":"Added user erin to admin group."}
{"processImagePath":"/Applications/Self Service.app/Contents/MacOS/JCDaemon.app/Contents/MacOS/JCDaemon","eventMessage":"Removed user erin from admin group."}
{"processImagePath":"/Applications/Self Service.app/Contents/MacOS/Jamf Connect.app/Contents/MacOS/Jamf Connect","eventMessage":"Added user frank to admin group."}
{"processImagePath":"/Applications/Self Service.app/Contents/MacOS/JCDaemon.app/Contents/MacOS/JCDaemon","eventMessage":"User dave elevated to admin for stated reason: x\nAdded user gina to admin group."}
NDJSON
    )
    assert_true "demote tool: _mbsetupuser is a system account" "${GREP}" -qx 'system:_mbsetupuser' <<< "${open}"
    assert_true "demote tool: a uid below 500 is a system account" "${GREP}" -qx 'system:root' <<< "${open}"
    assert_true "demote tool: an open Jamf Connect elevation is found" "${GREP}" -qx 'alice' <<< "${open}"
    assert_false "demote tool: an elevation Jamf Connect later removed is closed" "${GREP}" -qx 'bob' <<< "${open}"
    assert_false "demote tool: an entry from outside Jamf Connect's folders is ignored" "${GREP}" -qx 'carol' <<< "${open}"
    assert_true "demote tool: \"Added user\" from Self Service's JCDaemon is an open elevation" "${GREP}" -qx 'dave' <<< "${open}"
    assert_false "demote tool: an \"Added user\" JCDaemon later removed is closed" "${GREP}" -qx 'erin' <<< "${open}"
    assert_false "demote tool: the Jamf Connect menu app inside Self Service is ignored" "${GREP}" -qx 'frank' <<< "${open}"
    assert_false "demote tool: a typed elevation reason is not an entry" "${GREP}" -qx 'gina' <<< "${open}"
}

# ---- no `which`, no /usr/local/bin-first PATH, no style-guide pragma ----
test_no_which_anywhere() {
    local script
    for script in "${PKG_DIR}"/*.sh "${PKG_DIR}"/Scripts/* "${PKG_DIR}"/tools/*.sh \
        "${REPO_DIR}"/Support/*.sh "${REPO_DIR}"/Support/jamf-extension-attributes/*.sh
    do
        local label="${script#"${REPO_DIR}/"}"
        assert_false "${label}: no \$(which …)" "${GREP}" -Eq '=\$\(which ' "${script}"
        assert_false "${label}: no \"which preferred over command -v\" pragma" \
            "${GREP}" -q 'preferred over `command -v`' "${script}"
        assert_false "${label}: PATH does not put /usr/local/bin first" \
            "${GREP}" -Eq '^[[:space:]]*export PATH="/usr/local/bin' "${script}"
    done
    for script in "${REPO_DIR}"/Support/jamf-extension-attributes/*.sh
    do
        assert_true "${script##*/}: EA uses the system-only PATH" \
            "${GREP}" -qx 'export PATH="/usr/bin:/bin:/usr/sbin:/sbin"' "${script}"
    done
}

# ---- one product version: the VERSION file ----
# Scripts read VERSION; the Swift constant and project.yml keep literals that
# must equal it. Test packages keep their own package numbers, but
# version.plist carries the product version.
test_single_version_source() {
    local version_file="${REPO_DIR}/VERSION"
    local version
    version=$(serberus_product_version "${REPO_DIR}")
    assert_true "VERSION holds MAJOR.MINOR.PATCH" test -n "${version}"

    assert_eq "${version}" \
        "$("${AWK}" -F'"' '/^[[:space:]]+MARKETING_VERSION:/ { print $2; exit }' "${REPO_DIR}/project.yml")" \
        "project.yml MARKETING_VERSION equals VERSION"
    # The committed project (CI builds from it) must be regenerated with the
    # bump: every MARKETING_VERSION in it equals VERSION, and there is one.
    local pbxproj="${REPO_DIR}/Serberus.xcodeproj/project.pbxproj"
    local pbx_versions
    pbx_versions=$("${AWK}" '/MARKETING_VERSION = / { v = $3; sub(/;$/, "", v); gsub(/"/, "", v); print v }' "${pbxproj}" | "${SORT}" -u)
    assert_eq "${version}" "${pbx_versions}" \
        "Serberus.xcodeproj/project.pbxproj: every MARKETING_VERSION equals VERSION (run xcodegen generate after a bump)"
    local swift="${REPO_DIR}/Sources/SerberusDaemonCore/DaemonPaths.swift"
    local key
    for key in daemonVersion pamModuleVersion cliVersion
    do
        assert_eq "${version}" \
            "$("${AWK}" -F'"' -v k="${key}" '$0 ~ "^[[:space:]]+" k ": \"" { print $2; exit }' "${swift}")" \
            "DaemonPaths.swift DaemonVersion.current.${key} equals VERSION"
    done
    local plist
    for plist in "${REPO_DIR}"/Support/Generated/*-Info.plist
    do
        assert_eq '$(MARKETING_VERSION)' \
            "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "${plist}" 2>/dev/null)" \
            "${plist##*/}: CFBundleShortVersionString is \$(MARKETING_VERSION)"
        assert_eq '$(CURRENT_PROJECT_VERSION)' \
            "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "${plist}" 2>/dev/null)" \
            "${plist##*/}: CFBundleVersion is \$(CURRENT_PROJECT_VERSION)"
    done

    # Scripts read the file instead of carrying a copy.
    local script
    for script in "${PKG_DIR}/build-pkg.sh" "${REPO_DIR}/Support/build-serberusd-bundle.sh" \
        "${PKG_DIR}/build-core-test-pkg.sh"
    do
        assert_true "$(short "${script}"): reads VERSION through version-lib.sh" \
            "${GREP}" -q 'serberus_product_version "${REPO_DIR}"' "${script}"
    done
    assert_false "build-pkg.sh carries no version literal" \
        "${GREP}" -Eq '^readonly PKG_VERSION="[0-9]' "${PKG_DIR}/build-pkg.sh"
    assert_false "build-serberusd-bundle.sh carries no version literal" \
        "${GREP}" -Eq '^readonly BUNDLE_VERSION="[0-9]' "${REPO_DIR}/Support/build-serberusd-bundle.sh"
    body_order "${PKG_DIR}/build-pkg.sh" stage_scripts \
        "build-pkg.sh stages VERSION beside the postinstall" 'REPO_DIR}/VERSION" "\$\{SCRIPTS_STAGE_DIR\}/VERSION"'
    local post="${PKG_DIR}/Scripts/postinstall"
    assert_true "production postinstall reads the staged VERSION" \
        "${GREP}" -q '^readonly VERSION_FILE="${SCRIPT_DIR}/VERSION"$' "${post}"
    assert_false "production postinstall carries no version literal" \
        "${GREP}" -Eq '^readonly (DAEMON|PAM|CLI)_VERSION="[0-9]' "${post}"

    # The core test package: product version in version.plist, package
    # number kept apart.
    local core="${PKG_DIR}/build-core-test-pkg.sh"
    for key in daemonVersion pamModuleVersion cliVersion
    do
        assert_true "core test pkg: version.plist ${key} is the product version" \
            "${GREP}" -qF "<key>${key}</key><string>\${PRODUCT_VERSION}</string>" "${core}"
    done
    assert_true "core test pkg: the package number is packageVersion" \
        "${GREP}" -qF '<key>packageVersion</key><string>${PKG_VERSION}</string>' "${core}"

    # version-lib.sh accepts only MAJOR.MINOR.PATCH.
    local probe="${FIXTURES}/VERSION-probe"
    printf '1.2.3\n' > "${probe}"
    assert_eq "1.2.3" "$(serberus_version_from_file "${probe}")" "version-lib: 1.2.3 accepted"
    printf '1.2\n' > "${probe}"
    assert_false "version-lib: 1.2 refused" serberus_version_from_file "${probe}"
    printf '1.2.3-beta\n' > "${probe}"
    assert_false "version-lib: 1.2.3-beta refused" serberus_version_from_file "${probe}"
    assert_false "version-lib: a missing file is refused" serberus_version_from_file "${FIXTURES}/no-VERSION"
    "${RM}" -f "${probe}"
}

# ---- the install-time team pins the daemon in every teardown ----
test_install_team_recorded() {
    local post="${PKG_DIR}/Scripts/postinstall"
    body_order "${post}" write_version_plist \
        "production postinstall records the validated team in version.plist" \
        'cliVersion' 'DAEMON_TEAM' 'SERBERUS_INSTALL_TEAM_KEY'
    assert_true "core test pkg records installTeamID in version.plist" \
        "${GREP}" -qF '<key>installTeamID</key><string>${install_team}</string>' "${PKG_DIR}/build-core-test-pkg.sh"
    body_order "${PKG_DIR}/Scripts/uninstall.sh" daemon_trusted \
        "Scripts/uninstall.sh: the daemon is pinned to the recorded team" \
        'recorded_team' 'serberus_daemon_trusted "\$\{path\}" "\$\{team\}"'
    body_order "${PKG_DIR}/Scripts/uninstall.sh" recorded_team \
        "Scripts/uninstall.sh: the inline fallback reads installTeamID from a root-only file" \
        'serberus_recorded_team' 'path_is_root_locked' 'installTeamID'
    body_order "${REPO_DIR}/Support/serberusd-devtool.sh" run_daemon_oneshot \
        "serberusd-devtool.sh: one-shots are pinned to the recorded team" \
        'serberus_recorded_team' 'serberus_daemon_trusted "\$\{INSTALL_BINARY_PATH\}" "\$\{team\}"'
}

# ---- builders: no ad-hoc daemon bundle; --install never builds ----
test_bundle_and_pam_install_guards() {
    local bundle="${REPO_DIR}/Support/build-serberusd-bundle.sh"
    body_order "${bundle}" verify_inputs \
        "build-serberusd-bundle.sh refuses SIGNING_IDENTITY=\"-\"" \
        'SIGNING_IDENTITY\}" == "-"' 'missing=1'
    body_order "${bundle}" verify_bundle \
        "build-serberusd-bundle.sh checks the signed team against the rendered team" \
        'TeamIdentifier=' 'TEAM_ID\}"' 'exit 1'
    local out
    local status=0
    out=$(SIGNING_IDENTITY="-" PROVISION_PROFILE="${FIXTURES}/no-such.provisionprofile" \
        OUTPUT_DIR="${FIXTURES}/bundle-out" DEVELOPMENT_TEAM="ABCDE12345" \
        "${BASH_BIN}" "${bundle}" 2>&1) || status=$?
    assert_eq "1" "${status}" "build-serberusd-bundle.sh: an ad-hoc identity stops the build"
    assert_true "build-serberusd-bundle.sh: the refusal names ad-hoc" \
        "${GREP}" -q 'ad-hoc "-" is refused' <<< "${out}"
    assert_false "build-serberusd-bundle.sh: nothing was written before the refusal" \
        test -e "${FIXTURES}/bundle-out"

    local buildpam="${REPO_DIR}/Support/build-pam.sh"
    body_order "${buildpam}" do_install \
        "build-pam.sh --install: the prebuilt-module check runs before any other check" \
        'require_root' 'require_prebuilt_module' 'load_pam_lib' 'preflight_or_refuse'
    assert_false "build-pam.sh --install never builds" \
        "${GREP}" -Eq '^[[:space:]]+do_build$' <(function_body "${buildpam}" do_install)
    body_order "${buildpam}" require_prebuilt_module \
        "build-pam.sh --install: SIGNING_IDENTITY=\"-\" without --force is refused, with the sudo flow" \
        'SIGNING_IDENTITY\}" == "-" && "\$\{FORCE_INSTALL\}" != "--force"' \
        'sudo SIGNING_IDENTITY=' 'exit 1' 'OUTPUT' 'exit 1'
    body_order "${buildpam}" do_build \
        "build-pam.sh --build refuses to run as root under sudo" \
        'SUDO_USER' 'exit 1' 'MKDIR'
    body_order "${buildpam}" do_install \
        "build-pam.sh --install re-verifies the staged copy before it goes live" \
        'serberus_pam_lock_module "\$\{staged\}"' 'verify --strict "\$\{staged\}"' \
        'require_same_team_module "\$\{staged\}"' 'MV}" -f "\$\{staged\}"'
    body_order "${buildpam}" do_install \
        "build-pam.sh --install removes a stray pam_serberus.so.2 before wiring" \
        'serberus_pam_remove_versioned_module' 'serberus_pam_merge_sudo_local'
}

# ---- teardown details ----
test_teardown_details() {
    local uninstall="${PKG_DIR}/Scripts/uninstall.sh"
    body_order "${uninstall}" unwire_sudo_local \
        "Scripts/uninstall.sh: a failed pam-lib unwire is reported, not a set -e exit" \
        'serberus_pam_remove_sudo_local "\$\{SUDO_LOCAL\}"\) \|\| result="FAILED"'
    body_order "${uninstall}" unwire_sudo_local \
        "Scripts/uninstall.sh: a failed fallback unwire is reported, not a set -e exit" \
        'fallback_remove_sudo_local\) \|\| result="FAILED"'
    body_order "${uninstall}" fallback_remove_sudo_local \
        "Scripts/uninstall.sh: the inline fallback refuses a directory at sudo_local" \
        '-d "\$\{SUDO_LOCAL\}"' 'FAILED'
    local post
    for post in "${PKG_DIR}/Scripts/postinstall" "${GEN_POSTINSTALL}"
    do
        assert_order "${post}" '^if ! remove_versioned_module$' 'wire_sudo_local$' \
            "$(short "${post}"): a stray pam_serberus.so.2 is removed before sudo_local is wired"
    done
    assert_order "${GEN_PAM_POSTINSTALL}" 'serberus_pam_remove_versioned_module' '^if ! wire_sudo_local$' \
        "pam-test postinstall: a stray pam_serberus.so.2 is removed before sudo_local is wired"
    body_order "${GEN_POSTINSTALL}" bootstrap_and_verify_daemon \
        "core postinstall: the freshness mark is retaken right before kickstart -k" \
        'BOOTSTRAP_MARK=\$\(serberus_launchd_bootstrap_mark\)' 'bootstrap system' \
        'BOOTSTRAP_MARK=\$\(serberus_launchd_bootstrap_mark\)' 'kickstart -k'

    # A JIT-only admin is never the admin left behind.
    local tool="${PKG_DIR}/tools/demote-console-user-from-admin.sh"
    body_order "${tool}" admin_account_usable \
        "demote tool: an admin holding an active JIT grant is not counted" \
        'JIT_ADMINS' 'return 1'
    assert_order "${tool}" '^if ! load_jit_admins$' '^other_admins=' \
        "demote tool: JIT grants are read before the other admins are counted"
    local query
    query=$("${AWK}" -F'"' '/^readonly JIT_QUERY=/ { print $2; exit }' "${tool}")
    local db="${FIXTURES}/grants-jit.sqlite"
    "${RM}" -f "${db}"
    /usr/bin/sqlite3 "${db}" "CREATE TABLE grants (grantID TEXT PRIMARY KEY, user TEXT NOT NULL, profileKey TEXT NOT NULL, canonicalPath TEXT NOT NULL, revokedAt TEXT);
INSERT INTO grants VALUES ('1', 'alice', 'jit_admin', 'group:admin', NULL);
INSERT INTO grants VALUES ('2', 'bob', 'jit_admin', 'group:admin', '2026-09-01T00:00:00Z');
INSERT INTO grants VALUES ('3', 'carol', 'prof', '/usr/bin/true', NULL);"
    assert_eq "alice" "$(/usr/bin/sqlite3 -readonly "${db}" "${query}")" \
        "demote tool: the JIT query finds only unrevoked jit_admin rows"
    "${RM}" -f "${db}"
}

# ---- every script carries the information block with ISO dates ----
test_script_headers() {
    local script
    for script in "${PKG_DIR}"/*.sh "${PKG_DIR}"/Scripts/* "${PKG_DIR}"/tools/*.sh \
        "${PKG_DIR}"/tests/*.sh "${REPO_DIR}"/Support/*.sh \
        "${REPO_DIR}"/Support/jamf-extension-attributes/*.sh \
        "${REPO_DIR}"/extras/AuthURIBrowser/Scripts/*.sh \
        "${REPO_DIR}"/extras/*.sh \
        "${REPO_DIR}"/extras/SerberusAuthProbe/*.sh
    do
        local label="${script#"${REPO_DIR}/"}"
        assert_true "${label}: has the script information block" \
            "${GREP}" -q 'Begin Script Information Block' "${script}"
        assert_false "${label}: no MM-DD-YYYY header dates" \
            "${GREP}" -Eq '^# (Date|Modified): [0-9]{2}-[0-9]{2}-[0-9]{4}' "${script}"
    done
}

# ---- the daemon runs as root only after serberus_daemon_trusted ----
# Every script that EXECUTES the daemon (--demote-jit, --restore-authdb)
# checks it first — strict signature, Apple anchor, identifier, pinned team —
# and prints the manual steps instead of running an untrusted binary.
test_daemon_trust_before_oneshots() {
    local file
    local fn
    for file in "${GEN_UNINSTALL}" "${GEN_UNINSTALL_PKG}" "${GEN_TEST_UNINSTALL}"
    do
        for fn in demote_jit_admins restore_authdb restore_authorization_db
        do
            if [[ -z "$(function_body "${file}" "${fn}")" ]]
            then
                continue
            fi
            body_order "${file}" "${fn}" "$(short "${file}"): ${fn} checks daemon_trusted before running the daemon" \
                'daemon_trusted' 'run_daemon_oneshot|serberus_run_bounded'
        done
        body_order "${file}" daemon_trusted \
            "$(short "${file}"): the daemon is pinned to the team recorded in version.plist" \
            'serberus_recorded_team' 'serberus_daemon_trusted "\$1" "\$\{team\}"'
    done
    for fn in demote_jit_admins restore_authorization_db
    do
        body_order "${PKG_DIR}/Scripts/uninstall.sh" "${fn}" \
            "Scripts/uninstall.sh: ${fn} checks daemon_trusted before running the daemon" \
            'daemon_trusted' 'run_bounded'
    done
    body_order "${PKG_DIR}/Scripts/uninstall.sh" daemon_trusted \
        "Scripts/uninstall.sh: the inline fallback pins identifier and team" \
        'serberus_daemon_trusted' 'identifier .* and certificate leaf\[subject.OU\]'
    body_order "${REPO_DIR}/Support/serberusd-devtool.sh" run_daemon_oneshot \
        "serberusd-devtool.sh: run_daemon_oneshot checks serberus_daemon_trusted first" \
        'serberus_daemon_trusted' 'serberus_run_bounded'

    # Postinstall abort paths trust the daemon only through the helper.
    body_order "${PKG_DIR}/Scripts/postinstall" assess_daemon_trust \
        "Scripts/postinstall: assess_daemon_trust uses serberus_daemon_trusted" \
        'serberus_daemon_trusted' 'DAEMON_TRUSTED=1'
    body_order "${GEN_TEST_POSTINSTALL}" assess_daemon_trust \
        "daemon-test postinstall: assess_daemon_trust uses serberus_daemon_trusted" \
        'serberus_daemon_trusted' 'DAEMON_TRUSTED=1'
    body_order "${GEN_POSTINSTALL}" daemon_payload_ok \
        "core postinstall: DAEMON_TRUSTED only after serberus_daemon_trusted" \
        'serberus_daemon_trusted' 'DAEMON_TRUSTED=1'
    assert_false "daemon-test postinstall: a plain codesign --verify no longer trusts the daemon" \
        "${GREP}" -Eq 'CODESIGN}" --verify "\$\{DAEMON_BINARY\}"' "${GEN_TEST_POSTINSTALL}"
    body_order "${GEN_TEST_POSTINSTALL}" install_validation_passes \
        "daemon-test postinstall: an untrusted daemon FAILS validation (the install aborts)" \
        'DAEMON_TRUSTED}" -ne 1' 'ok=1'

    # The legacy com.heath restore runs only for a binary that passes.
    for file in "${GEN_PREINSTALL}" "${FIXTURES}/gen-build-test-pkg/scripts/preinstall"
    do
        body_order "${file}" uninstall_legacy_daemon \
            "$(short "${file}"): the legacy restore is gated on serberus_daemon_trusted" \
            'serberus_daemon_trusted' 'serberus_daemon_manual_steps restore' '--restore-authdb'
    done

    # Every script that runs --demote-jit treats exit 3 (no grant store) as info.
    for file in "${GEN_UNINSTALL}" "${GEN_UNINSTALL_PKG}" "${GEN_TEST_UNINSTALL}" \
        "${GEN_POSTINSTALL}" "${GEN_TEST_POSTINSTALL}" "${GEN_PREINSTALL}" \
        "${FIXTURES}/gen-build-test-pkg/scripts/preinstall" \
        "${PKG_DIR}/Scripts/uninstall.sh" "${PKG_DIR}/Scripts/postinstall" \
        "${PKG_DIR}/Scripts/preinstall" "${REPO_DIR}/Support/serberusd-devtool.sh"
    do
        assert_true "$(short "${file}"): --demote-jit exit 3 is informational" \
            "${GREP}" -Eq '^[[:space:]]+3\)$' "${file}"
        assert_true "$(short "${file}"): exit 3 is reported as no grant store" \
            "${GREP}" -qi 'no grant store' "${file}"
    done
}

# ---- upgrades demote JIT admins with the OLD binary after booting it out ----
test_preinstall_demotes_after_bootout() {
    local file
    for file in "${PKG_DIR}/Scripts/preinstall" "${GEN_PREINSTALL}" \
        "${FIXTURES}/gen-build-test-pkg/scripts/preinstall"
    do
        assert_sequence "${file}" \
            "$(short "${file}"): drop-in -> unwire -> bootout -> demote JIT (old binary) -> drop-in" \
            '^[[:space:]]*remove_sudoers_dropin$' \
            '^[[:space:]]*unwire_sudo_local$' \
            '^[[:space:]]*bootout_daemon$' \
            '^[[:space:]]*demote_jit_with_old_daemon$'
        body_order "${file}" demote_jit_with_old_daemon \
            "$(short "${file}"): the old daemon runs only after serberus_daemon_trusted" \
            'serberus_daemon_trusted' '--demote-jit'
        body_order "${file}" demote_jit_with_old_daemon \
            "$(short "${file}"): a failed demote is loud but never fatal" \
            'FAILED' 'return 0'
        assert_false "$(short "${file}"): the demote never exits the preinstall" \
            "${GREP}" -Eq '^[[:space:]]+exit' <(function_body "${file}" demote_jit_with_old_daemon)
    done

    # Production upgrade over a test ring: the flat daemon, the test helpers
    # and their receipts go after the bootout.
    local pre="${PKG_DIR}/Scripts/preinstall"
    assert_order "${pre}" '^[[:space:]]*bootout_daemon$' '^[[:space:]]*remove_test_ring_leftovers$' \
        "production preinstall: test-ring leftovers removed AFTER the bootout"
    local item
    for item in 'DAEMON_BINARY_FLAT="/Library/PrivilegedHelperTools/com.herojoneslabs.serberus.daemon"' \
        'uninstall-serberus-sentinel-test.sh' 'uninstall-serberusd-test.sh' 'uninstall-serberus-pam-test.sh' \
        '.sentineltestpkg"' '.coretestpkg"' '.testpkg"' '.pamtestpkg"'
    do
        assert_true "production preinstall removes ${item}" "${GREP}" -qF -- "${item}" "${pre}"
    done
    body_order "${pre}" remove_test_ring_leftovers \
        "production preinstall: leftovers = flat daemon, helpers, receipts" \
        'DAEMON_BINARY_FLAT' 'TEST_HELPERS' 'PKGUTIL}" --forget'

    # The PAM test pkg pins to the daemon the LaunchDaemon runs, bundle next.
    local pam_post="${FIXTURES}/gen-build-pam-test-pkg/scripts/postinstall"
    body_order "${pam_post}" resolve_daemon_team \
        "pam-test postinstall: the plist's Program daemon is tried first" \
        'launchd_program_daemon' 'DAEMON_BINARIES'
    assert_true "pam-test postinstall: the production bundle is listed before the flat binary" \
        "${GREP}" -Eq '^readonly DAEMON_BINARIES=\($' "${pam_post}"
    local first
    first=$("${AWK}" '/^readonly DAEMON_BINARIES=\($/{getline; print; exit}' "${pam_post}")
    assert_eq '    "${DAEMON_BUNDLE_PATH}"' "${first}" "pam-test postinstall: bundle first in DAEMON_BINARIES"
}

# ---- a drop-in that survives its removal stops the teardown before the unwire ----
test_dropin_failure_stops_teardown() {
    local file
    for file in "${PKG_DIR}/Scripts/preinstall" "${GEN_PREINSTALL}" \
        "${FIXTURES}/gen-build-test-pkg/scripts/preinstall" \
        "${FIXTURES}/gen-build-pam-test-pkg/scripts/preinstall"
    do
        body_order "${file}" remove_sudoers_dropin \
            "$(short "${file}"): a FAILED drop-in removal exits before the unwire" \
            'serberus_pam_remove_sudoers_dropin' 'FAILED' 'exit 1'
    done
    for file in "${GEN_POSTINSTALL}" "${GEN_TEST_POSTINSTALL}" "${PKG_DIR}/Scripts/postinstall"
    do
        body_order "${file}" abort_install \
            "$(short "${file}"): a surviving drop-in re-arms the daemon and exits BEFORE the unwire" \
            'if ! remove_sudoers_dropin' 'serberus_daemon_rearm_if_wired' 'exit 1' 'if ! unwire_sudo_local'
    done
    body_order "${GEN_PAM_POSTINSTALL}" abort_install \
        "pam-test postinstall: a surviving drop-in exits BEFORE the unwire" \
        'serberus_pam_remove_sudoers_dropin' 'FAILED' 'exit 1' 'serberus_pam_remove_sudo_local'
    for file in "${GEN_UNINSTALL}" "${GEN_UNINSTALL_PKG}" "${GEN_TEST_UNINSTALL}" \
        "${GEN_PAM_UNINSTALL}" "${PKG_DIR}/Scripts/uninstall.sh"
    do
        assert_order "${file}" '^remove_sudoers_dropin_or_stop$' '^unwire_sudo_local$' \
            "$(short "${file}"): the first drop-in removal can stop the teardown before the unwire"
        body_order "${file}" remove_sudoers_dropin_or_stop \
            "$(short "${file}"): remove_sudoers_dropin_or_stop exits when the drop-in survives" \
            'if ! remove_sudoers_dropin' 'exit 1'
        body_order "${file}" remove_sudoers_dropin \
            "$(short "${file}"): the removal result FAILED is checked explicitly" \
            'FAILED' 'return 1'
    done
    body_order "${REPO_DIR}/Support/serberusd-devtool.sh" do_uninstall \
        "serberusd-devtool.sh: a surviving drop-in stops --uninstall before the bootout" \
        'if ! remove_sudoers_dropin' 'return 1' 'bootout_if_loaded'
}

# ---- "up" before wiring: bootstrap mark, fresh state, pid re-check, CLI ----
test_liveness_gate_before_wiring() {
    local post="${PKG_DIR}/Scripts/postinstall"
    assert_sequence "${post}" \
        "production postinstall: mark -> bootstrap -> wait (state.plist + mark) -> pid re-check -> wire" \
        '^BOOTSTRAP_MARK=[$][(]serberus_launchd_bootstrap_mark[)]$' \
        'LAUNCHCTL}" bootstrap system' \
        'serberus_launchd_wait_running .*STATE_PLIST}" "[$][{]BOOTSTRAP_MARK}"' \
        '^if ! serberus_launchd_pid_unchanged' \
        '^if ! wire_sudo_local$'
    assert_true "production postinstall: criterion 10 checks the CLI (755, root, team)" \
        "${GREP}" -q 'criterion 10 FAIL' "${post}"
    body_order "${post}" upgrade_validation_passes \
        "production postinstall: criterion 10 = present, mode 755, root-owned, team-signed" \
        'CLI_BINARY' '755' "%u" 'serberus_codesign_satisfies_team "\$\{CLI_BINARY\}"'
    assert_false "production postinstall: the CLI is passed unconditionally (a missing CLI fails)" \
        "${GREP}" -q 'HEALTH_CLI' "${post}"
    assert_sequence "${GEN_POSTINSTALL}" \
        "core postinstall: pid re-check right before wiring" \
        '^if ! serberus_launchd_pid_unchanged' '^if ! wire_sudo_local$'
    body_order "${GEN_POSTINSTALL}" bootstrap_and_verify_daemon \
        "core postinstall: mark before bootstrap, then wait with the state.plist (kickstart: fresh_job 0)" \
        'BOOTSTRAP_MARK=\$\(serberus_launchd_bootstrap_mark\)' 'bootstrap system' 'kickstart -k' \
        'STATE_PLIST}" "\$\{BOOTSTRAP_MARK\}" 0'
    body_order "${GEN_TEST_POSTINSTALL}" bootstrap_daemon \
        "daemon-test postinstall: mark before bootstrap" \
        'BOOTSTRAP_MARK=\$\(serberus_launchd_bootstrap_mark\)' 'bootstrap system'
    assert_true "daemon-test postinstall: waits with the state.plist and the mark" \
        "${GREP}" -q 'STATE_PLIST}" "${BOOTSTRAP_MARK}"' "${GEN_TEST_POSTINSTALL}"
    body_order "${GEN_TEST_POSTINSTALL}" rewire_if_previously_unwired \
        "daemon-test postinstall: pid re-check before the re-wire merge" \
        'serberus_launchd_pid_unchanged' 'serberus_pam_merge_sudo_local'
    assert_sequence "${GEN_PAM_POSTINSTALL}" \
        "pam-test postinstall: wait -> pid re-check -> wire" \
        '^if ! serberus_launchd_wait_running' '^if ! serberus_launchd_pid_unchanged' '^if ! wire_sudo_local$'

    # Each chown/chmod is checked on its own.
    local file
    for file in "${post}" "${GEN_POSTINSTALL}" "${GEN_PAM_POSTINSTALL}"
    do
        body_order "${file}" wire_sudo_local \
            "$(short "${file}"): a failed chown of sudo_local is not hidden by the chmod" \
            'if ! "\$\{CHOWN\}" -h root:wheel "\$\{SUDO_LOCAL\}"' 'return 1' 'if ! "\$\{CHMOD\}"' 'return 1'
    done
    for file in "${GEN_POSTINSTALL}" "${GEN_TEST_POSTINSTALL}" "${GEN_PAM_POSTINSTALL}"
    do
        assert_false "$(short "${file}"): fix_ownership has no unchecked chown/chmod" \
            "${GREP}" -Eq '^[[:space:]]+"\$\{(CHOWN|CHMOD)\}" [^|]*$' <(function_body "${file}" fix_ownership)
    done
}

# ---- signing identities: no ad-hoc daemon in the daemon test or production pkg ----
test_adhoc_signing_refused() {
    local builder
    for builder in build-test-pkg build-pkg build-core-test-pkg build-pam-test-pkg
    do
        body_order "${PKG_DIR}/${builder}.sh" verify_inputs \
            "${builder}.sh: verify_inputs refuses SIGNING_IDENTITY=\"-\"" \
            'SIGNING_IDENTITY\}" == "-"' 'exit 1'
    done
}

# ---- the Xcode target signs serberusd with the pinned identifier ----
test_xcode_daemon_identifier() {
    local spec="${REPO_DIR}/project.yml"
    assert_true "project.yml: serberusd signs with --identifier com.herojoneslabs.serberus.daemon" \
        "${GREP}" -q 'OTHER_CODE_SIGN_FLAGS: "$(inherited) --identifier com.herojoneslabs.serberus.daemon"' "${spec}"
    assert_false "project.yml: no leftover spike paragraph above SerberusAuth" \
        "${GREP}" -q 'SPIKE (throwaway' "${spec}"
    body_order "${REPO_DIR}/Support/serberusd-devtool.sh" check_presigned_binary \
        "serberusd-devtool.sh: SKIP_DAEMON_SIGN checks the identifier and the team" \
        'Identifier=' 'BUNDLE_ID' 'serberus_daemon_trusted'
}

# ---- dev tools: atomic replace, refusal while wired, wait, re-arm ----
test_dev_tools_safe_replace() {
    local devtool="${REPO_DIR}/Support/serberusd-devtool.sh"
    body_order "${devtool}" do_install \
        "serberusd-devtool.sh --install: refuse while wired -> temp copy -> sign -> mv -> bootstrap+wait" \
        'refuse_if_sudo_wired' 'MKTEMP}" "\$\{install_dir\}' 'CODESIGN}" --force' \
        'MV}" -f "\$\{staged\}" "\$\{INSTALL_BINARY_PATH\}"' 'bootstrap_and_wait'
    assert_false "serberusd-devtool.sh --install never cp's over the live binary" \
        "${GREP}" -q 'CP}" "${SERBERUSD_BINARY}" "${INSTALL_BINARY_PATH}"' "${devtool}"
    body_order "${devtool}" do_restart \
        "serberusd-devtool.sh --restart: refuse while wired -> bootstrap+wait" \
        'refuse_if_sudo_wired' 'bootstrap_and_wait'
    body_order "${devtool}" bootstrap_and_wait \
        "serberusd-devtool.sh: a failed bootstrap is flagged, a good one is waited for" \
        'BOOTSTRAP_FAILED=1' 'serberus_launchd_wait_running'
    body_order "${devtool}" cleanup \
        "serberusd-devtool.sh: the EXIT trap re-arms the daemon after a failed bootstrap" \
        'BOOTSTRAP_FAILED' 'serberus_daemon_rearm_if_wired'

    local buildpam="${REPO_DIR}/Support/build-pam.sh"
    body_order "${buildpam}" do_install \
        "build-pam.sh --install: temp copy in the module dir -> lock -> atomic mv" \
        'MKTEMP}" "\$\{INSTALL_DIR\}' 'serberus_pam_lock_module "\$\{staged\}"' 'MV}" -f "\$\{staged\}" "\$\{INSTALL_PATH\}"'
    assert_false "build-pam.sh --install never cp's over the live module" \
        "${GREP}" -q 'CP}" "${OUTPUT}" "${INSTALL_PATH}"' "${buildpam}"
    body_order "${buildpam}" do_install \
        "build-pam.sh --install: pid re-check before sudo_local is created" \
        'serberus_launchd_pid_unchanged' 'serberus_pam_merge_sudo_local'
}

# ---- no daemon one-shot runs beside a daemon that is still loaded ----
test_oneshots_wait_for_bootout() {
    local file
    local fn
    for file in "${GEN_UNINSTALL}" "${GEN_UNINSTALL_PKG}" "${GEN_TEST_UNINSTALL}" \
        "${PKG_DIR}/Scripts/uninstall.sh"
    do
        fn=$("${GREP}" -Eo '^restore_(authdb|authorization_db)\(\)' "${file}" | head -n 1)
        fn="${fn%()}"
        body_order "${file}" "${fn}" \
            "$(short "${file}"): ${fn} checks DAEMON_GONE before --restore-authdb" \
            'DAEMON_GONE}" -ne 1' 'return 0' '--restore-authdb'
    done
}

# ---- every script logs the version its header states ----
test_script_versions_match_headers() {
    local script
    local header
    local logged
    local -a scripts=()
    while IFS= read -r script
    do
        scripts+=("${script}")
    done < <(generated_root_scripts)
    for script in "${scripts[@]}" \
        "${PKG_DIR}"/Scripts/preinstall "${PKG_DIR}"/Scripts/postinstall \
        "${PKG_DIR}"/Scripts/uninstall.sh "${PKG_DIR}"/verify-uninstall.sh \
        "${PKG_DIR}"/tools/*.sh
    do
        header=$("${AWK}" '/^# Version: [0-9]/ { print $3; exit }' "${script}")
        logged=$("${AWK}" -F'"' '/^readonly SCRIPT_VERSION="/ { print $2; exit }' "${script}")
        if [[ -z "${header}" || -z "${logged}" ]]
        then
            continue
        fi
        assert_eq "${header}" "${logged}" "$(short "${script}"): SCRIPT_VERSION matches the header's Version"
    done
}

# ---- what the uninstallers remove: every endpoint component, never Commander ----
test_uninstallers_scope() {
    assert_false "uninstall pkg: never forgets Commander's receipt" \
        "${GREP}" -Eq '^[[:space:]]*"\$\{ORG\}\.commanderpkg"' "${GEN_UNINSTALL_PKG}"
    assert_false "verify-uninstall.sh: Commander's receipt is not a finding" \
        "${GREP}" -Eq '^[[:space:]]*"\$\{ORG_PLIST_DOMAIN\}\.commanderpkg"' "${PKG_DIR}/verify-uninstall.sh"
    assert_true "uninstall pkg: Commander's Jamf receipt stubs stay" \
        "${GREP}" -q 'SerberusCommander\*)' "${GEN_UNINSTALL_PKG}"
    assert_false "uninstall pkg: Commander's relaunch marker is not deleted" \
        "${GREP}" -q 'commander-relaunch" 2>/dev/null' "${GEN_UNINSTALL_PKG}"
    local component
    for component in DAEMON_PLIST DAEMON_BUNDLE PAM_MODULE CLI_BINARY AUTH_PLUGIN \
        AGENT_PLIST GUARDIAN_PLIST ELECT_PLIST FULLAPP AGENT_APP GUARDIAN_APP
    do
        assert_true "uninstall pkg: removes ${component}" \
            "${GREP}" -Eq "RM\}\" -(r)?f .*\"\\\$\{${component}\}\"" "${GEN_UNINSTALL_PKG}"
    done
    assert_true "uninstall pkg: unregisters the Finder extension" \
        "${GREP}" -q 'PLUGINKIT}" -e ignore -i "${FINDER_EXT_ID}"' "${GEN_UNINSTALL_PKG}"

    # Functional: remove_support_and_logs against a fixture support folder.
    local root="${FIXTURES}/uninstall-scope"
    local support="${root}/Serberus"
    "${RM}" -rf "${root}"
    "${MKDIR_BIN}" -p "${support}/Serberus Guardian.app" "${support}/.install-markers" \
        "${support}/authdb-backups" "${root}/logs"
    : > "${support}/uninstall-serberus-commander.sh"
    : > "${support}/.install-markers/commander-relaunch"
    : > "${support}/.install-markers/fullapp-relaunch"
    : > "${support}/state.plist"
    : > "${support}/uninstall-serberus-sentinel-app.sh"
    local body
    body=$(function_body "${GEN_UNINSTALL_PKG}" remove_support_and_logs)
    (
        SUPPORT_DIR="${support}"
        AUTHDB_BACKUPS="${support}/authdb-backups"
        INSTALL_MARKER_DIR="${support}/.install-markers"
        COMMANDER_HELPER="${support}/uninstall-serberus-commander.sh"
        COMMANDER_MARKER="${support}/.install-markers/commander-relaunch"
        LOG_DIR="${root}/logs"
        RMDIR="/bin/rmdir"
        AUTHDB_RESTORE_OK=0
        log() { :; }
        log_error() { :; }
        eval "${body}"
        remove_support_and_logs
    )
    assert_true "uninstall pkg: Commander's uninstall helper stays" test -f "${support}/uninstall-serberus-commander.sh"
    assert_true "uninstall pkg: Commander's relaunch marker stays" test -f "${support}/.install-markers/commander-relaunch"
    assert_false "uninstall pkg: the Sentinel's relaunch marker goes" test -e "${support}/.install-markers/fullapp-relaunch"
    assert_false "uninstall pkg: the Guardian app goes" test -e "${support}/Serberus Guardian.app"
    assert_false "uninstall pkg: endpoint helpers go" test -e "${support}/uninstall-serberus-sentinel-app.sh"
    assert_false "uninstall pkg: state goes" test -e "${support}/state.plist"
    assert_true "uninstall pkg: authdb-backups stay after a failed restore" test -d "${support}/authdb-backups"
    assert_false "uninstall pkg: logs go" test -e "${root}/logs"
    "${RM}" -rf "${root}"

    # --purge is data only: the apps and helpers in the support folder stay.
    assert_false "uninstall.sh: --purge never removes the whole support folder" \
        "${GREP}" -Eq 'remove_component "\$\{SUPPORT_DIR\}"$' "${PKG_DIR}/Scripts/uninstall.sh"
    body_order "${PKG_DIR}/Scripts/uninstall.sh" purge_data \
        "uninstall.sh: --purge keeps apps, helpers and install markers" \
        'serberus_purge_support_data' '\*\.app \| uninstall\*\.sh \| pam-lib\.sh \| \.install-markers'
    local helper
    for helper in "${GEN_UNINSTALL}" "${GEN_TEST_UNINSTALL}"
    do
        assert_true "$(short "${helper}"): --purge is data only (serberus_purge_support_data)" \
            "${GREP}" -q 'serberus_purge_support_data "${SUPPORT_DIR}" "${keep_backups}"' "${helper}"
        assert_false "$(short "${helper}"): --purge never removes the whole support folder" \
            "${GREP}" -Eq 'RM\}" -rf "\$\{SUPPORT_DIR\}"$' "${helper}"
    done
}

# ---- the Sentinel app helper's --purge: the Sentinel's files, never Commander's ----
test_sentinel_app_purge_scope() {
    local helper="${FIXTURES}/gen-build-sentinel-app-pkg/payload/Library/Application Support/Serberus/uninstall-serberus-sentinel-app.sh"
    local label="${helper##*/}"
    local -a sentinel_files=("rules-cache.json" "elevation-history.json" "pending-route" "jamf-uploads.json")
    local body
    body=$(function_body "${helper}" purge_sentinel_files)
    assert_false "${label}: the per-user folder (Commander's library) is never removed whole (-rf)" \
        "${GREP}" -Eq 'safe_user_remove .*-rf ' "${helper}"
    local file
    for file in "${sentinel_files[@]}"
    do
        assert_true "${label}: --purge removes ${file}" "${GREP}" -qF "\"${file}\"" <<< "${body}"
    done
    assert_false "${label}: --purge never names Commander's files" \
        "${GREP}" -Eq 'policies\.json|capture-reviews\.json' <<< "${body}"
    body_order "${helper}" purge_sentinel_files \
        "${label}: the Sentinel's files go first, then the folder only if it is empty" \
        '-f "Library" "Application Support" "Serberus" "\$\{file\}"' \
        'rmdir "Library" "Application Support" "Serberus"$'
    body_order "${helper}" safe_user_remove \
        "${label}: the empty-folder removal is rmdir, as the user, after the checks" \
        '\[\[ -L "\$\{path\}" \]\]' 'owner' '"\$\{flag\}" == "rmdir"' \
        '/usr/bin/sudo -n -u "\$\{user\}" /bin/rmdir -- "\$\{path\}"'
    assert_true "${label}: the --purge loop purges each account through purge_sentinel_files" \
        "${GREP}" -q 'purge_sentinel_files "\${user_name}" "\${user_home}"$' "${helper}"

    # Functional: only safe_user_remove and purge_sentinel_files, copied into
    # a scratch script with sudo swapped for a mock that drops "-n -u <user>"
    # and runs the command as the caller, against a fake home owned by the
    # current user. The helper itself never runs here: it needs root and
    # deletes real paths.
    local user
    user=$("${ID_BIN}" -un)
    local root="${FIXTURES}/sentinel-app-purge"
    local home="${root}/home/${user}"
    local folder="${home}/Library/Application Support/Serberus"
    local mock="${root}/sudo-mock"
    local scratch="${root}/purge.sh"
    "${RM}" -rf "${root}"
    "${MKDIR_BIN}" -p "${root}"
    printf '#! /bin/bash\n[[ "$1" == "-n" && "$2" == "-u" && "$3" == "%s" ]] || exit 1\nshift 3\nexec "$@"\n' \
        "${user}" > "${mock}"
    /bin/chmod 755 "${mock}"
    local fns
    fns=$("${AWK}" '/^(safe_user_remove|purge_sentinel_files)\(\) \{/{p=1} p{print} p&&/^}/{p=0}' "${helper}" \
        | /usr/bin/sed 's#/usr/bin/sudo #"${SUDO_MOCK}" #')
    if [[ "${fns}" != *'safe_user_remove() {'* || "${fns}" != *'purge_sentinel_files() {'* \
        || "${fns}" == *'/usr/bin/sudo'* ]]
    then
        fail "${label}: could not copy the purge functions with sudo mocked (not run)"
        return 0
    fi
    printf 'SUDO_MOCK="$3"\n%s\npurge_sentinel_files "$1" "$2"\n' "${fns}" > "${scratch}"
    local out

    # A folder shared with Commander: the Sentinel's files go; Commander's
    # files and the folder stay, and that is not reported as a failure.
    "${MKDIR_BIN}" -p "${folder}"
    for file in "${sentinel_files[@]}" "policies.json" "capture-reviews.json"
    do
        printf 'x\n' > "${folder}/${file}"
    done
    out=$("${BASH_BIN}" "${scratch}" "${user}" "${home}" "${mock}" 2>&1) || true
    for file in "${sentinel_files[@]}"
    do
        assert_false "${label} --purge beside Commander's library: ${file} goes" test -e "${folder}/${file}"
    done
    assert_true "${label} --purge: Commander's policies.json stays" test -f "${folder}/policies.json"
    assert_true "${label} --purge: Commander's capture-reviews.json stays" test -f "${folder}/capture-reviews.json"
    assert_true "${label} --purge: the folder stays while Commander's files are in it" test -d "${folder}"
    assert_eq "" "${out}" "${label} --purge: a folder kept for Commander is not reported as a failure"

    # Only the Sentinel's files: the emptied folder goes too.
    "${RM}" -rf "${home}"
    "${MKDIR_BIN}" -p "${folder}"
    for file in "${sentinel_files[@]}"
    do
        printf 'x\n' > "${folder}/${file}"
    done
    "${BASH_BIN}" "${scratch}" "${user}" "${home}" "${mock}" >/dev/null 2>&1 || true
    assert_false "${label} --purge with only the Sentinel's files: the folder goes" test -e "${folder}"
    assert_true "${label} --purge with only the Sentinel's files: Application Support stays" \
        test -d "${home}/Library/Application Support"

    # A symlinked Serberus folder is skipped: nothing is removed through it.
    "${RM}" -rf "${home}"
    local elsewhere="${root}/elsewhere"
    "${MKDIR_BIN}" -p "${home}/Library/Application Support" "${elsewhere}"
    for file in "${sentinel_files[@]}"
    do
        printf 'x\n' > "${elsewhere}/${file}"
    done
    "${LN_BIN}" -s "${elsewhere}" "${folder}"
    "${BASH_BIN}" "${scratch}" "${user}" "${home}" "${mock}" >/dev/null 2>&1 || true
    assert_true "${label} --purge: a symlinked Serberus folder is left in place" test -L "${folder}"
    for file in "${sentinel_files[@]}"
    do
        assert_true "${label} --purge: ${file} behind a symlinked folder stays" test -f "${elsewhere}/${file}"
    done
    "${RM}" -rf "${root}"
}

# ---- the CLI's folder is checked before the daemon starts; installer log ----
test_postinstall_cli_dir_and_install_log() {
    local postinstall="${PKG_DIR}/Scripts/postinstall"
    assert_order "${postinstall}" '^if ! cli_dir_is_root_only' 'LAUNCHCTL}" bootstrap system' \
        "Scripts/postinstall: the CLI's folder chain is checked before the bootstrap"
    body_order "${postinstall}" cli_dir_is_root_only \
        "Scripts/postinstall: a CLI in a folder that is not root-only is removed" \
        'serberus_cli_dir_is_root_only' 'RM}" -f "\$\{CLI_BINARY\}"'
    local script
    for script in "${postinstall}" "${GEN_POSTINSTALL}" "${GEN_TEST_POSTINSTALL}" \
        "${GEN_PAM_POSTINSTALL}" "${GEN_UNINSTALL_PKG}" \
        "${FIXTURES}/gen-build-sentinel-app-pkg/scripts/postinstall" \
        "${FIXTURES}/gen-build-commander-pkg/scripts/postinstall"
    do
        assert_true "$(short "${script}"): logs where the installer log is" \
            "${GREP}" -q 'installer log: /var/log/install.log' "${script}"
    done
}

# ---- every shipped plist, profile and entitlements file is well-formed XML ----
# plutil and launchd accept some malformed XML (a "--" inside a comment);
# xmllint does not, and neither do some MDM consoles.
test_plists_well_formed_xml() {
    local file
    local count=0
    while IFS= read -r file
    do
        count=$((count + 1))
        assert_true "$(short "${file}"): well-formed XML (xmllint)" \
            "${XMLLINT}" --noout "${file}"
    done < <("${FIND}" "${REPO_DIR}/Support" "${REPO_DIR}/extras" "${REPO_DIR}/Sources" -type f \
        \( -name '*.plist' -o -name '*.mobileconfig' -o -name '*.entitlements' \) \
        ! -path '*/.build/*' ! -path '*/build/*' | "${SORT}")
    assert_true "xmllint checked at least the Support LaunchDaemon/Agent plists" test "${count}" -ge 4
}

# ---- a production build without Endpoint Security (ESF=off) ----
test_production_without_esf() {
    local builder="${PKG_DIR}/build-pkg.sh"
    local fns
    fns=$("${AWK}" '/^(resolve_esf_mode|exec_gate_state)\(\) \{/,/^}/' "${builder}")
    local profile="${FIXTURES}/fake.provisionprofile"
    : > "${profile}"
    local result
    # $1 ESF, $2 PROVISION_PROFILE -> "<status> <mode> <gate>"
    esf_case() {
        (
            ESF_REQUESTED="$1"
            PROVISION_PROFILE="$2"
            ESF_MODE=""
            log_info() { :; }
            log_warn() { :; }
            log_error() { :; }
            eval "${fns}"
            local status=0
            resolve_esf_mode || status=$?
            printf '%s %s %s' "${status}" "${ESF_MODE}" "$(exec_gate_state)"
        )
    }
    assert_eq "0 on enabled" "$(esf_case "" "${profile}")" "build-pkg.sh: a profile means ES is on"
    assert_eq "0 off disabled" "$(esf_case "" "")" "build-pkg.sh: no profile builds without ES (exec gate disabled)"
    assert_eq "0 off disabled" "$(esf_case off "${profile}")" "build-pkg.sh: ESF=off ignores a profile"
    result=$(esf_case on "")
    assert_eq "1" "${result%% *}" "build-pkg.sh: ESF=on without a profile is refused"
    result=$(esf_case on "${FIXTURES}/no-such.provisionprofile")
    assert_eq "1" "${result%% *}" "build-pkg.sh: ESF=on with a missing profile is refused"
    result=$(esf_case maybe "")
    assert_eq "1" "${result%% *}" "build-pkg.sh: an unknown ESF value is refused"
    "${RM}" -f "${profile}"

    body_order "${builder}" stage_scripts "build-pkg.sh stages EXEC_GATE beside the postinstall" \
        'exec_gate_state.*SCRIPTS_STAGE_DIR\}/EXEC_GATE"'
    body_order "${builder}" build_and_sign_bundle "build-pkg.sh passes the ESF mode, and no profile when off, to the bundle builder" \
        'ESF_MODE}" != "on"' 'profile=""' 'ESF="\$\{ESF_MODE\}"'
    local bundle="${REPO_DIR}/Support/build-serberusd-bundle.sh"
    body_order "${bundle}" sign_bundle "build-serberusd-bundle.sh: entitlements only with ESF=on" \
        'ESF}" == "on"' 'sign_args\+=\(--entitlements'
    assert_false "build-serberusd-bundle.sh: --entitlements is never passed unconditionally" \
        "${GREP}" -Eq '^[[:space:]]+--entitlements "\$\{RENDERED_ENTITLEMENTS\}" \\$' "${bundle}"
    body_order "${bundle}" verify_bundle "build-serberusd-bundle.sh: an ESF=off bundle must not carry the ES entitlement" \
        'ESF}" == "off"' 'endpoint-security' 'exit 1'
    body_order "${bundle}" assemble_bundle "build-serberusd-bundle.sh: the profile is embedded only with ESF=on" \
        'ESF}" == "on"' 'embedded.provisionprofile'
    local post="${PKG_DIR}/Scripts/postinstall"
    assert_true "postinstall records execGate in version.plist" \
        "${GREP}" -qF '<key>execGate</key><string>${EXEC_GATE}</string>' "${post}"
    assert_true "postinstall reads the staged EXEC_GATE" \
        "${GREP}" -qF 'readonly EXEC_GATE_FILE="${SCRIPT_DIR}/EXEC_GATE"' "${post}"
}

# ---- uninstall.sh's inline gate (no pam-lib.sh) follows the same rules ----
test_uninstall_fallback_gate() {
    local script="${PKG_DIR}/Scripts/uninstall.sh"
    local fns
    fns=$("${AWK}" '/^(authdb_records_pending|authdb_free_of_serberus)\(\) \{/,/^}/' "${script}")
    local query
    query=$("${AWK}" -F'"' '/^readonly FALLBACK_AUTHDB_QUERY=/ { print $2; exit }' "${script}")
    local root="${FIXTURES}/fallback-gate"
    "${RM}" -rf "${root}"
    "${MKDIR_BIN}" -p "${root}/backups"
    local db="${root}/auth.db"
    /usr/bin/sqlite3 "${db}" "CREATE TABLE rules (id INTEGER PRIMARY KEY, name TEXT, comment TEXT); CREATE TABLE mechanisms (id INTEGER PRIMARY KEY, plugin TEXT, param TEXT); CREATE TABLE mechanisms_map (r_id INTEGER, m_id INTEGER, ord INTEGER); CREATE TABLE delegates_map (r_id INTEGER, d_id INTEGER, ord INTEGER); INSERT INTO rules VALUES (1, 'x.custom', 'Managed by serberusd; do not edit.');"
    # $1 expected status, $2 label
    gate_case() {
        local status=0
        (
            PAM_LIB_LOADED=0
            AUTH_DB="${db}"
            AUTHDB_BACKUPS="${root}/backups"
            SQLITE3="/usr/bin/sqlite3"
            FALLBACK_AUTHDB_QUERY="${query}"
            log_error() { :; }
            eval "${fns}"
            authdb_free_of_serberus
        ) || status=$?
        assert_eq "$1" "${status}" "uninstall.sh fallback gate: $2"
    }
    gate_case 0 "a user-created right with the marker comment does not block"
    : > "${root}/backups/system.preferences.standin"
    gate_case 0 "a .standin record does not block"
    : > "${root}/backups/system.preferences.json"
    gate_case 1 "a .json record blocks"
    "${RM}" -f "${root}/backups/system.preferences.json"
    /usr/bin/sqlite3 "${db}" "INSERT INTO rules VALUES (2, 'com.herojoneslabs.serberus.branch.a.b', NULL); INSERT INTO mechanisms VALUES (1, 'SerberusAuth', 'identity'); INSERT INTO mechanisms_map VALUES (2, 1, 0);"
    gate_case 1 "a branch row that invokes SerberusAuth blocks"
    body_order "${script}" restore_authorization_db \
        "uninstall.sh: with no daemon, only pending records (not a .standin) mean something to restore" \
        'if authdb_records_pending' 'print_manual_steps restore'
    local file
    for file in "${GEN_UNINSTALL}" "${GEN_UNINSTALL_PKG}" "${GEN_TEST_UNINSTALL}"
    do
        assert_false "$(short "${file}"): the no-daemon path no longer treats any file in authdb-backups as a backup" \
            "${GREP}" -q 'LS}" -A "${AUTHDB_BACKUPS}"' "${file}"
        assert_true "$(short "${file}"): the no-daemon path checks pending records" \
            "${GREP}" -q 'serberus_authdb_records_pending "${AUTHDB_BACKUPS}"' "${file}"
    done
    "${RM}" -rf "${root}"
}

# ---- per-user purges run AS the user; root pkill patterns are anchored ----
test_user_purge_and_pkill() {
    body_order "${GEN_UNINSTALL_PKG}" purge_user_cache \
        "uninstall pkg: the Sentinel's per-user files are removed as the user, after the checks" \
        '\[\[ -L "\$\{path\}" \]\]' 'owner' 'SUDO}" -n -u "\$\{user\}" "\$\{RM\}" -f -- "\$\{files\[@\]\}"' \
        'SUDO}" -n -u "\$\{user\}" "\$\{RMDIR\}" -- "\$\{path\}"'
    assert_false "uninstall pkg: the per-user folder (Commander's library) is never removed whole" \
        "${GREP}" -Eq 'RM\}" -rf -- "\$\{path\}"' "${GEN_UNINSTALL_PKG}"
    local builder
    for builder in build-sentinel-app-pkg build-commander-pkg
    do
        assert_true "${builder}.sh: safe_user_remove runs rm as the user (sudo -u)" \
            "${GREP}" -qF '/usr/bin/sudo -n -u "${user}" /bin/rm "${flag}" -- "${path}"' "${PKG_DIR}/${builder}.sh"
        assert_false "${builder}.sh: safe_user_remove never runs rm as root" \
            "${GREP}" -qxF '    /bin/rm "${flag}" "${path}"' "${PKG_DIR}/${builder}.sh"
    done

    local script
    local line
    for script in "${GEN_ALL[@]}" "${FIXTURES}"/emit-authuribrowser/scripts/*
    do
        while IFS= read -r line
        do
            if [[ -z "${line}" ]]
            then
                continue
            fi
            if [[ "${line}" =~ -f\ \"\^ ]]
            then
                pass "$(short "${script}"): pkill -f pattern is anchored"
            else
                fail "$(short "${script}"): unanchored pkill -f: ${line}"
            fi
        done < <("${GREP}" -E '(pkill|PKILL\}") -f ' "${script}" | "${GREP}" -v '^[[:space:]]*#' || true)
    done
}

# ---- Sentinel/Commander require_boot_volume: empty $3 only outside Installer ----
test_gui_require_boot_volume() {
    local builder
    local fn
    local status
    for builder in build-sentinel-app-pkg build-commander-pkg
    do
        fn=$("${AWK}" '/^require_boot_volume\(\) \{/{p=1} p{print} p&&/^}/{exit}' "${PKG_DIR}/${builder}.sh")
        status=0
        TARGET_VOLUME="" "${BASH_BIN}" -c "${fn}"$'\nrequire_boot_volume' >/dev/null 2>&1 || status=$?
        assert_eq "0" "${status}" "${builder}.sh: an empty \$3 is accepted for a manual run"
        status=0
        TARGET_VOLUME="" INSTALLER_TEMP="/tmp/x" "${BASH_BIN}" -c "${fn}"$'\nrequire_boot_volume' >/dev/null 2>&1 || status=$?
        assert_eq "1" "${status}" "${builder}.sh: an empty \$3 under Installer is refused"
        status=0
        TARGET_VOLUME="/" PACKAGE_PATH="/tmp/x.pkg" "${BASH_BIN}" -c "${fn}"$'\nrequire_boot_volume' >/dev/null 2>&1 || status=$?
        assert_eq "0" "${status}" "${builder}.sh: \$3 = / under Installer is accepted"
        status=0
        TARGET_VOLUME="/Volumes/X" "${BASH_BIN}" -c "${fn}"$'\nrequire_boot_volume' >/dev/null 2>&1 || status=$?
        assert_eq "1" "${status}" "${builder}.sh: another volume is refused"
    done
}

# ---- packaging names and builder argument handling ----
test_package_names_and_modes() {
    assert_true "combined builder writes SerberusTest-<version>.pkg" \
        "${GREP}" -q 'OUTPUT_PKG="${BUILD_DIR}/SerberusTest-${COMBINED_VERSION}.pkg"' "${PKG_DIR}/build-combined-pkg.sh"
    assert_false "combined builder never writes Serberus-<version>.pkg" \
        "${GREP}" -q 'OUTPUT_PKG="${BUILD_DIR}/Serberus-' "${PKG_DIR}/build-combined-pkg.sh"
    assert_true "README names the combined test package SerberusTest-<version>.pkg" \
        "${GREP}" -q '`build-combined-pkg.sh` → `SerberusTest-<version>.pkg`' "${PKG_DIR}/README.md"
    assert_true "README names the production deliverable PKG/build/Serberus-<version>-signed.pkg" \
        "${GREP}" -q '`PKG/build/Serberus-<version>-signed.pkg`' "${PKG_DIR}/README.md"

    local auth="${PKG_DIR}/build-authuribrowser-pkg.sh"
    assert_true "authuribrowser: --emit-scripts writes the scripts only" \
        test -f "${FIXTURES}/emit-authuribrowser/scripts/preinstall"
    assert_false "authuribrowser: an unknown argument is a usage error" \
        "${BASH_BIN}" "${auth}" --no-such-mode >/dev/null 2>&1
    assert_false "authuribrowser: APP_SCRATCH no longer defaults to /tmp" \
        "${GREP}" -q '/tmp/authuribrowser-build' "${auth}"
    assert_true "authuribrowser: APP_SCRATCH defaults to a per-user cache" \
        "${GREP}" -q 'APP_SCRATCH="${APP_SCRATCH:-${SCRATCH:-${HOME}/Library/Caches/' "${auth}"
}

# ---- the daemon-only and PAM-only payloads carry no bundle ----
# They call pkgbuild without --component-plist; that is only safe while
# nothing in the payload is a bundle PackageKit could relocate.
test_bundle_free_payloads() {
    local builder
    local body
    for builder in build-test-pkg build-pam-test-pkg
    do
        body=$(function_body "${PKG_DIR}/${builder}.sh" assemble_payload)
        assert_true "${builder}.sh: assemble_payload found" test -n "${body}"
        assert_false "${builder}.sh: the payload stages no bundle (.app/.bundle/.appex/.framework/.plugin/.kext)" \
            "${GREP}" -Eq 'PAYLOAD_DIR[^#]*\.(app|bundle|appex|framework|plugin|kext)([/"]|$)' <<< "${body}"
        assert_false "${builder}.sh: no bundle-carrying path variable is copied in" \
            "${GREP}" -Eq 'CP}" -R' <<< "${body}"
        if "${FIND}" "${FIXTURES}/gen-${builder}/payload" -type d \
            \( -name '*.app' -o -name '*.bundle' -o -name '*.appex' -o -name '*.framework' -o -name '*.plugin' -o -name '*.kext' \) \
            2>/dev/null | "${GREP}" -q .
        then
            fail "${builder}.sh: the emitted payload contains a bundle"
        else
            pass "${builder}.sh: the emitted payload contains no bundle"
        fi
    done
}

# ---- uninstall.sh sources only a pam-lib.sh with a root-only path chain ----
test_uninstall_sources_root_only_lib() {
    local un="${PKG_DIR}/Scripts/uninstall.sh"
    body_order "${un}" source_pam_lib_if_present \
        "uninstall.sh: the installed copy first, the sibling second, both chain-checked" \
        'SUPPORT_DIR}/pam-lib.sh' 'sibling_dir' 'path_chain_is_root_only'
    local fns
    fns=$("${AWK}" '/^(path_is_root_locked|path_chain_is_root_only)\(\) \{/{p=1} p{print} p&&/^}/{p=0}' "${un}")
    local status=0
    "${BASH_BIN}" -c "STAT=/usr/bin/stat; ${fns}"$'\npath_chain_is_root_only /bin/ls' || status=$?
    assert_eq "0" "${status}" "uninstall.sh: a root-only chain (/bin/ls) is accepted"
    local copy="${FIXTURES}/sibling/pam-lib.sh"
    "${MKDIR_BIN}" -p "${FIXTURES}/sibling"
    printf '# not sourced\n' > "${copy}"
    status=0
    "${BASH_BIN}" -c "STAT=/usr/bin/stat; ${fns}"$'\npath_chain_is_root_only "$1"' _ "${copy}" || status=$?
    assert_eq "1" "${status}" "uninstall.sh: a pam-lib.sh in a user-owned directory is refused"
}

# ---- upload EAs: a user's ledger is parsed only as a bounded, owned copy ----
test_upload_ea_ledger_guard() {
    local ea
    local fn
    local user
    user=$("${ID_BIN}" -un)
    local home="${FIXTURES}/eahome/${user}"
    local ledger_dir="${home}/Library/Application Support/Serberus"
    "${MKDIR_BIN}" -p "${ledger_dir}"
    for ea in EA_Serberus_Uploads.sh EA_Serberus_Last_Upload.sh
    do
        local path="${REPO_DIR}/Support/jamf-extension-attributes/${ea}"
        assert_false "${ea}: no direct jq read of a user's ledger" \
            "${GREP}" -Eq 'JQ\}".*"\$\{ledger\}"' "${path}"
        assert_true "${ea}: jq parses the bounded root copy" \
            "${GREP}" -q '"${LEDGER_COPY}" 2>/dev/null)' "${path}"
        fn=$("${AWK}" '/^copy_ledger\(\) \{/{p=1} p{print} p&&/^}/{exit}' "${path}")
        local harness="LEDGER_SUBPATH='Library/Application Support/Serberus/jamf-uploads.json'
HEAD=/usr/bin/head; ID=/usr/bin/id; SLEEP=/bin/sleep; STAT=/usr/bin/stat
LEDGER_MAX_BYTES=1048576; LEDGER_COPY_SECONDS=5
LEDGER_COPY=\"\$3\"
${fn}
copy_ledger \"\$1\" \"\$2\""
        local copy="${FIXTURES}/ea-ledger-copy"
        local ledger="${ledger_dir}/jamf-uploads.json"
        local status

        "${RM}" -f "${ledger}"
        printf '[{"kind":"capture","uploadedAt":"2026-09-25T00:00:00Z"}]' > "${ledger}"
        status=0
        "${BASH_BIN}" -c "${harness}" _ "${user}" "${home}" "${copy}" || status=$?
        assert_eq "0" "${status}" "${ea}: a regular ledger owned by the user is copied"

        "${RM}" -f "${ledger}"
        /usr/bin/mkfifo "${ledger}"
        status=0
        "${BASH_BIN}" -c "${harness}" _ "${user}" "${home}" "${copy}" || status=$?
        assert_eq "1" "${status}" "${ea}: a FIFO ledger is refused (no blocking read)"

        "${RM}" -f "${ledger}"
        "${LN_BIN}" -s /dev/zero "${ledger}"
        status=0
        "${BASH_BIN}" -c "${harness}" _ "${user}" "${home}" "${copy}" || status=$?
        assert_eq "1" "${status}" "${ea}: a symlinked ledger (/dev/zero) is refused"

        "${RM}" -f "${ledger}"
        /bin/dd if=/dev/zero of="${ledger}" bs=1024 count=1100 2>/dev/null
        status=0
        "${BASH_BIN}" -c "${harness}" _ "${user}" "${home}" "${copy}" || status=$?
        assert_eq "1" "${status}" "${ea}: a ledger over 1 MiB is refused"

        # A swap between the path check and the open: the stat wrapper
        # answers the check, then replaces the ledger with a symlink to
        # another file. The descriptor check must refuse what the open got.
        "${RM}" -f "${ledger}"
        printf '[{"kind":"capture","uploadedAt":"2026-09-25T00:00:00Z"}]' > "${ledger}"
        local other="${FIXTURES}/ea-other-file"
        printf 'secret' > "${other}"
        local swap_stat="${FIXTURES}/ea-swap-stat"
        "${RM}" -f "${swap_stat}.done"
        printf '#! /bin/bash\nout=$(/usr/bin/stat "$@")\nstatus=$?\nif [[ "${!#}" == "%s" && ! -e "%s.done" ]]\nthen\n    : > "%s.done"\n    /bin/rm -f "%s"\n    /bin/ln -s "%s" "%s"\nfi\nprintf "%%s\\n" "${out}"\nexit ${status}\n' \
            "${ledger}" "${swap_stat}" "${swap_stat}" "${ledger}" "${other}" "${ledger}" > "${swap_stat}"
        /bin/chmod 755 "${swap_stat}"
        status=0
        "${BASH_BIN}" -c "${harness/STAT=\/usr\/bin\/stat/STAT=${swap_stat}}" _ "${user}" "${home}" "${copy}" || status=$?
        assert_true "${ea}: the swap happened after the path check" test -L "${ledger}"
        assert_eq "1" "${status}" "${ea}: a ledger swapped for a symlink after the check is refused (descriptor check)"
        assert_false "${ea}: the swapped-in file was not copied" "${GREP}" -q secret "${copy}"
        "${RM}" -f "${ledger}" "${copy}" "${other}" "${swap_stat}" "${swap_stat}.done"
    done

    # Recent events: the result stays within 64 KiB, measured after XML
    # escaping, and is cut on EVENT boundaries: the newest events that fit
    # (the leading ones; the daemon writes newest first) as a valid JSON
    # array, so Commander never decodes a cut-off value as "no events".
    local events="${FIXTURES}/fleet-events.json"
    /usr/bin/python3 -c 'print("[" + ",".join(["{\"t\":\"AT&T <x> %d\"}" % i for i in range(6000)]) + "]")' > "${events}" 2>/dev/null \
        || { local i; printf '[' > "${events}"; for ((i = 0; i < 6000; i++)); do printf '%s{"t":"AT&T <x> %d"}' "$([[ ${i} -gt 0 ]] && printf ,)" "${i}" >> "${events}"; done; printf ']' >> "${events}"; }
    local ea_copy="${FIXTURES}/EA_Recent_Events_fixture.sh"
    /usr/bin/sed "s#/Library/Application Support/Serberus/fleet-events.json#${events}#" \
        "${REPO_DIR}/Support/jamf-extension-attributes/EA_Serberus_Recent_Events.sh" > "${ea_copy}"
    local out
    out=$("${BASH_BIN}" "${ea_copy}")
    local inner="${out#<result>}"
    inner="${inner%</result>}"
    local bytes
    bytes=$(printf '%s' "${inner}" | /usr/bin/wc -c | /usr/bin/tr -d ' ')
    if [[ "${bytes}" -le 65536 ]]
    then
        pass "EA_Serberus_Recent_Events.sh: result capped at 64 KiB (${bytes} bytes)"
    else
        fail "EA_Serberus_Recent_Events.sh: result is ${bytes} bytes, over 64 KiB"
    fi
    local decoded
    decoded=$(printf '%s' "${inner}" | /usr/bin/sed 's/&lt;/</g; s/&gt;/>/g; s/&amp;/\&/g')
    assert_true "EA_Serberus_Recent_Events.sh: a cut result is still a valid JSON array" \
        /usr/bin/jq -e 'type == "array" and length > 0' <<< "${decoded}"
    assert_eq "AT&T <x> 0" "$(/usr/bin/jq -r '.[0].t' <<< "${decoded}")" \
        "EA_Serberus_Recent_Events.sh: the cut keeps the newest (leading) event"
    local kept
    kept=$(/usr/bin/jq -r 'length' <<< "${decoded}")
    assert_eq "AT&T <x> $((kept - 1))" "$(/usr/bin/jq -r '.[-1].t' <<< "${decoded}")" \
        "EA_Serberus_Recent_Events.sh: whole events are kept in order (${kept} of 6000)"
    assert_false "EA_Serberus_Recent_Events.sh: no truncation marker (it would break the JSON)" \
        "${GREP}" -q 'truncated' <<< "${out}"
    assert_false "EA_Serberus_Recent_Events.sh: never cut inside an XML entity" \
        "${GREP}" -Eq '&[a-z]{0,3}($|[^a-z;])' <<< "${inner}"
    printf '[{"t":"a&b"}]' > "${events}"
    assert_eq '<result>[{"t":"a&amp;b"}]</result>' "$("${BASH_BIN}" "${ea_copy}")" \
        "EA_Serberus_Recent_Events.sh: a small file is escaped and passed through"
    "${RM}" -f "${events}" "${ea_copy}"
}

# ---- bash -n every generated + static script ----
test_scripts_pass_bash_n() {
    local script
    for script in "${GEN_PREINSTALL}" "${GEN_POSTINSTALL}" "${GEN_PAM_LIB}" "${GEN_UNINSTALL}"
    do
        if [[ ! -f "${script}" ]]
        then
            fail "expected generated script missing: ${script}"
        fi
    done
    for script in "${GEN_ALL[@]}"
    do
        if "${BASH_BIN}" -n "${script}"
        then
            pass "bash -n: ${script#"${FIXTURES}/"}"
        else
            fail "bash -n FAILED: ${script}"
        fi
    done

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
# shellcheck source=../../Support/version-lib.sh
source "${REPO_DIR}/Support/version-lib.sh"

# Generate the combined scripts once for the structural ordering assertions.
emit_generated_scripts

test_postinstall_install_order
test_postinstall_wire_is_guarded
test_postinstall_abort_path
test_postinstall_enable_and_running
test_postinstall_module_checks
test_uninstall_teardown_order
test_restore_gates_plugin_removal
test_root_scripts_use_system_path
test_install_markers_not_in_tmp
test_log_functions_defined
test_preinstall_structure
test_preinstall_preflight_warns_and_proceeds
test_sudo_local_requisite_and_upgrade
test_preinstall_teardown_first
test_exit_traps
test_umask
test_abort_keeps_daemon_when_unwire_fails
test_require_boot_volume
test_relocatable_bundles_pinned
test_daemon_codesign_identifier
test_restore_checks_live_authdb
test_core_pkg_naming
test_demote_tool_admin_checks
test_no_which_anywhere
test_script_headers
test_single_version_source
test_install_team_recorded
test_bundle_and_pam_install_guards
test_teardown_details
test_daemon_trust_before_oneshots
test_preinstall_demotes_after_bootout
test_dropin_failure_stops_teardown
test_liveness_gate_before_wiring
test_adhoc_signing_refused
test_xcode_daemon_identifier
test_dev_tools_safe_replace
test_user_purge_and_pkill
test_gui_require_boot_volume
test_package_names_and_modes
test_bundle_free_payloads
test_uninstall_sources_root_only_lib
test_upload_ea_ledger_guard
test_oneshots_wait_for_bootout
test_script_versions_match_headers
test_uninstallers_scope
test_sentinel_app_purge_scope
test_postinstall_cli_dir_and_install_log
test_plists_well_formed_xml
test_production_without_esf
test_uninstall_fallback_gate

# Functional break-glass preflight uses hermetic resolver mocks so it never
# depends on the accounts of the machine running the tests.
install_resolver_mocks
test_breakglass_preflight_functional

test_scripts_pass_bash_n

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
