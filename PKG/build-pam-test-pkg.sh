#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: build-pam-test-pkg.sh
# Author: Heath Jones
# Date: 2026-07-11
# Modified: 2026-09-26
# Purpose: Build the TEST-RING Serberus PAM module PKG for Jamf policy
#          deployment. Packages /usr/local/lib/pam/pam_serberus.so (built via
#          Support/build-pam.sh, Apple Development signed with the
#          com.herojoneslabs.serberus.pam identifier) plus an on-disk
#          uninstall helper and the shared pam-lib.sh. The generated
#          preinstall FAILS CLOSED: it aborts unless a break-glass config
#          (monitor/audit mode or a populated pamBypass) is already effective
#          and a daemon is installed and loaded — pam_serberus is a
#          `requisite` sudo module and enforce-with-no-bypass would brick sudo
#          for everyone — then unwires an existing wiring before the new
#          module lands. The generated postinstall validates the module
#          (signed by the installed daemon's team — no ad-hoc fallback —
#          native arch, root-only directory chain) and waits for a stable
#          daemon BEFORE wiring /etc/pam.d/sudo_local (idempotent line-merge;
#          user lines preserved; Serberus line first among the auth lines).
#          Production endpoints use build-pkg.sh.
# Version: 1.5 - Generated postinstall: its first log line says where the
#          installer log is (/var/log/install.log).
#          1.4 - Generated scripts: the uninstall helper sources pam-lib.sh
#          only through a root-only path chain, removes a stray
#          pam_serberus.so.2 and exits 1 when the drop-in survives; the
#          postinstall removes a stray pam_serberus.so.2 before wiring.
#          1.3 - Generated scripts: the daemon team comes from the daemon the
#          LaunchDaemon plist runs (Program), then the production bundle,
#          then the flat test binary; stricter liveness (8 s window, no
#          restart, pid re-read before wiring); a surviving sudoers drop-in
#          stops every teardown before sudo_local is unwired; each
#          chown/chmod is checked. The payload carries no bundle, so pkgbuild
#          needs no component plist (asserted by test-sentinel-lib.sh).
#          1.2 - Generated scripts: umask 022; EXIT traps; boot volume ($3)
#          required; the preinstall requires an installed + loaded daemon and
#          tears the existing wiring down before the module is replaced; the
#          postinstall refuses a missing or team-less daemon (no --strict
#          fallback), pins the module and an installed SerberusAuth.bundle to
#          the daemon's team, checks the module's directory chain before any
#          chown/chmod (-h), and waits for a stable daemon pid (+ `serberus
#          status`) before wiring. Builder: absolute tool paths.
#          1.1 - Generated scripts: system-only PATH and absolute tools. The
#          postinstall requires the module to be signed by the installed
#          daemon's team (--strict fallback with a warning when the daemon is
#          ad-hoc/absent — test ring only) and to sit in a root-only
#          directory chain; post-merge sanity requires the canonical line.
#          The uninstall helper re-checks the sudoers drop-in after unwiring
#          (the still-running daemon could rewrite it in between).
#          1.0 - Initial Script
#
######################################################################
############## End Script Information Block ##########################
######################################################################

# Usage (run as the LOGGED-IN USER, never sudo — codesign needs the Apple
# Development chain in your login keychain):
#
#   SIGNING_IDENTITY=<Apple Development cert hash or name> ./PKG/build-pam-test-pkg.sh
#
# Optional env:
#   INSTALLER_IDENTITY  "Developer ID Installer: Your Name (YOURTEAMID)"
#                       — signs the .pkg (recommended; unsigned still installs
#                       via Jamf *policy*, but PreStage/InstallApplication and
#                       double-click installs require a signed pkg)
#   PKG_VERSION         package version (default 1.0.0)
#
# Modes:
#   (default)                 build the pkg
#   --self-test               run PKG/tests/test-pam-lib.sh and exit
#   --emit-scripts <dir>      write the generated scripts + payload helpers to
#                             <dir> without building (used by the test harness
#                             for bash -n validation)
#
# ORDERING REQUIREMENT (see PKG/README.md): scope the break-glass
# config profile (Support/sample-profiles/serberus-config-breakglass.mobileconfig)
# and install the daemon test pkg BEFORE this pkg — the preinstall verifies
# both and aborts the install otherwise.
#
# Deploy: upload the built pkg to Jamf, install via policy. Teardown on the
# test machine (or via a Jamf teardown policy):
#   sudo "/Library/Application Support/Serberus/uninstall-serberus-pam-test.sh"

####################################################################
############## Begin Define Variables Block ########################
####################################################################
##############################
### Core Defined Variables ###
### MODIFY AT YOUR OWN RISK ##
##############################

set -euo pipefail

# System directories only; every tool below is called by absolute path.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

readonly AWK="/usr/bin/awk"
readonly BASENAME="/usr/bin/basename"
readonly BASH_BIN="/bin/bash"
readonly CAT="/bin/cat"
readonly CHMOD="/bin/chmod"
readonly CODESIGN="/usr/bin/codesign"
readonly CP="/bin/cp"
readonly DIRNAME="/usr/bin/dirname"
readonly ENV="/usr/bin/env"
readonly ID="/usr/bin/id"
# lipo ships with the Xcode tools; /usr/bin/lipo is the xcrun shim.
readonly LIPO="/usr/bin/lipo"
readonly MKDIR="/bin/mkdir"
readonly PKGBUILD="/usr/bin/pkgbuild"
readonly PRODUCTSIGN="/usr/bin/productsign"
readonly RM="/bin/rm"
readonly XATTR="/usr/bin/xattr"

readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.5"
readonly SCRIPT_DIR=$(cd "$("${DIRNAME}" "$0")" && pwd)
readonly REPO_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

readonly ORG_PLIST_DOMAIN="com.herojoneslabs.serberus"
readonly SUPPORT_DIR="/Library/Application Support/Serberus"
readonly UNINSTALL_HELPER_NAME="uninstall-serberus-pam-test.sh"
readonly PAM_LIB_NAME="pam-lib.sh"
readonly PAM_LIB_SRC="${SCRIPT_DIR}/Scripts/${PAM_LIB_NAME}"

# BundleConfig.pamBundleID. It names the module in codesign output; the daemon
# never checks it — the module runs inside sudo, and the daemon validates sudo
# itself as the XPC caller. Kept stable so every build is identified the same.
readonly PAM_IDENTIFIER="com.herojoneslabs.serberus.pam"

# Distinct identifier from the daemon test pkg (…serberus.testpkg) and the
# production pkg (…serberus.pkg) so receipts never masquerade as either.
readonly PKG_IDENTIFIER="com.herojoneslabs.serberus.pamtestpkg"
readonly PKG_VERSION="${PKG_VERSION:-1.0.0}"

readonly MODE="${1:---build}"
readonly EMIT_DIR="${2:-}"

# --emit-scripts redirects all generated output into the caller's directory;
# a normal build works under PKG/build-test/pam (a SUBDIR of build-test so
# `rm -rf` here can never clobber a daemon test pkg built by
# build-test-pkg.sh, while the artifacts still land under PKG/build-test/).
if [[ "${MODE}" == "--emit-scripts" && -n "${EMIT_DIR}" ]]
then
    readonly BUILD_DIR="${EMIT_DIR}"
else
    readonly BUILD_DIR="${SCRIPT_DIR}/build-test/pam"
fi
readonly PAYLOAD_DIR="${BUILD_DIR}/payload"
readonly SCRIPTS_DIR="${BUILD_DIR}/scripts"
readonly OUTPUT_PKG="${BUILD_DIR}/Serberus-pam-test-${PKG_VERSION}.pkg"
readonly SIGNED_PKG="${BUILD_DIR}/Serberus-pam-test-${PKG_VERSION}-signed.pkg"

# The module is built by Support/build-pam.sh --build (single source of truth
# for the clang + codesign invocation) with OUTPUT pointed here.
readonly PAM_BUILD_SCRIPT="${REPO_DIR}/Support/build-pam.sh"
readonly PAM_SO="${BUILD_DIR}/pam_serberus.so"

# Signing inputs. SIGNING_IDENTITY is REQUIRED and must be a REAL identity
# (Apple Development hash or name) from the daemon's team — the postinstall
# refuses a module that is not signed by the installed daemon's team.
readonly SIGNING_IDENTITY="${SIGNING_IDENTITY:-}"
readonly INSTALLER_IDENTITY="${INSTALLER_IDENTITY:-}"

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

log_warn() {
    printf '[WARN] %s\n' "$*" >&2
}

log_error() {
    printf '[ERROR] %s\n' "$*" >&2
}

##################################
### End Core Defined Functions ###
##################################

########################################
######## User Defined Functions ########
### Place your script functions here ###
########################################

verify_inputs() {
    # Must NOT run as root: `sudo codesign` cannot build the Apple Development
    # chain (the cert lives in the logging-in user's login keychain), and
    # pkgbuild's default `recommended` ownership makes root ownership at
    # install time, so a non-root build is correct.
    if [[ "$("${ID}" -u)" -eq 0 ]]
    then
        log_error "Run as the logged-in user, not root (codesign needs your login keychain)."
        exit 1
    fi

    if [[ -z "${SIGNING_IDENTITY}" || "${SIGNING_IDENTITY}" == "-" ]]
    then
        log_error "SIGNING_IDENTITY is required and must be a REAL identity (Apple Development"
        log_error "cert hash or name) from the daemon's team — the postinstall checks the team."
        log_error "  security find-identity -v -p codesigning   # list identities"
        log_error "  SIGNING_IDENTITY=<hash> ./PKG/${SCRIPT_NAME}"
        exit 1
    fi

    if [[ -z "${INSTALLER_IDENTITY}" ]]
    then
        log_warn "INSTALLER_IDENTITY unset — the installer pkg will be UNSIGNED."
        log_warn "Jamf policy installs accept unsigned pkgs; set INSTALLER_IDENTITY to sign."
    fi

    if [[ ! -f "${PAM_LIB_SRC}" ]]
    then
        log_error "Missing ${PAM_LIB_SRC} — pam-lib.sh ships inside the pkg scripts and payload."
        exit 1
    fi
}

# Build via Support/build-pam.sh --build — do NOT duplicate its clang line.
# It compiles pam_serberus.c + pam_config.c universal (arm64 + x86_64),
# strips xattrs, and signs with --identifier com.herojoneslabs.serberus.pam
# --options runtime.
build_module() {
    log_info "Building pam_serberus.so via Support/build-pam.sh --build"
    # Pass OUTPUT/SIGNING_IDENTITY through `env` rather than a command-prefix
    # assignment: SIGNING_IDENTITY is readonly in this script, and bash rejects
    # `readonly_var=... cmd` as an attempt to modify the readonly binding.
    "${ENV}" OUTPUT="${PAM_SO}" SIGNING_IDENTITY="${SIGNING_IDENTITY}" \
        "${BASH_BIN}" "${PAM_BUILD_SCRIPT}" --build

    if [[ ! -f "${PAM_SO}" ]]
    then
        log_error "build-pam.sh completed but module not found: ${PAM_SO}"
        exit 1
    fi

    # Independent verification — a bad signature in the payload is refused by
    # the postinstall (and a broken seal is a dlopen failure at sudo time).
    if ! "${CODESIGN}" --verify --strict "${PAM_SO}"
    then
        log_error "Built module failed codesign --verify --strict"
        exit 1
    fi

    local identifier
    identifier=$("${CODESIGN}" --display --verbose=2 "${PAM_SO}" 2>&1 \
        | "${AWK}" -F= '/^Identifier=/{print $2}')
    if [[ "${identifier}" != "${PAM_IDENTIFIER}" ]]
    then
        log_error "Module signing identifier is '${identifier}', expected '${PAM_IDENTIFIER}'."
        exit 1
    fi

    log_info "Module archs: $("${LIPO}" -archs "${PAM_SO}" 2>/dev/null || printf 'unknown')"
}

assemble_payload() {
    log_info "Assembling payload at ${PAYLOAD_DIR}"
    # /usr/lib/pam is on the SEALED read-only system snapshot (macOS 11+) —
    # the module MUST live under the /usr/local firmlink, and sudo_local
    # references it by absolute path (pam-lib.sh SERBERUS_PAM_AUTH_LINE).
    "${MKDIR}" -p "${PAYLOAD_DIR}/usr/local/lib/pam"
    "${MKDIR}" -p "${PAYLOAD_DIR}${SUPPORT_DIR}"

    # Payload is the module ONLY plus the on-disk teardown helpers. NEVER ship
    # /etc/pam.d/sudo_local as payload — upgrades would clobber user PAM
    # config and the receipt would own it; the postinstall line-merges it
    # instead.
    "${CP}" "${PAM_SO}" "${PAYLOAD_DIR}/usr/local/lib/pam/pam_serberus.so"
    "${CHMOD}" 755 "${PAYLOAD_DIR}/usr/local/lib/pam"

    "${CP}" "${PAM_LIB_SRC}" "${PAYLOAD_DIR}${SUPPORT_DIR}/${PAM_LIB_NAME}"
    "${CHMOD}" 644 "${PAYLOAD_DIR}${SUPPORT_DIR}/${PAM_LIB_NAME}"

    write_uninstall_helper

    "${CHMOD}" 755 "${PAYLOAD_DIR}${SUPPORT_DIR}"

    # Strip removable extended attributes (a cloud-synced working copy can
    # stamp every file) —
    # a stray com.apple.FinderInfo on the .so invalidates its signature ->
    # dlopen failure inside the `requisite` PAM line -> sudo bricked for
    # everyone including bypass users. This MUST run while the module is still
    # writable: clearing a file's xattrs needs write permission, so the final
    # `chmod 444` lockdown comes AFTER the strip, not before.
    "${XATTR}" -rc "${PAYLOAD_DIR}"

    "${CHMOD}" 444 "${PAYLOAD_DIR}/usr/local/lib/pam/pam_serberus.so"

    if ! "${CODESIGN}" --verify --strict "${PAYLOAD_DIR}/usr/local/lib/pam/pam_serberus.so"
    then
        log_error "Payload module failed codesign --verify --strict after xattr strip"
        exit 1
    fi
}

# On-endpoint teardown helper, shipped in the payload so a Jamf teardown
# policy (or a local admin) can unwire sudo_local and remove the module in
# the ONLY safe order. Fully literal heredoc — it runs on the target.
write_uninstall_helper() {
    local helper_path="${PAYLOAD_DIR}${SUPPORT_DIR}/${UNINSTALL_HELPER_NAME}"
    "${MKDIR}" -p "${PAYLOAD_DIR}${SUPPORT_DIR}"

    "${CAT}" > "${helper_path}" <<'UNINSTALL_EOF'
#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: uninstall-serberus-pam-test.sh
# Author: Heath Jones
# Date: 2026-07-11
# Modified: 2026-09-26
# Purpose: Remove the TEST-RING Serberus PAM module install. ORDER IS
#          SAFETY-CRITICAL and never reversed: (1) remove the coarse
#          /etc/sudoers.d/serberus standard-user allowlist (marker-guarded,
#          that one exact path only, no visudo) — before the fine PAM gate, so
#          the allowlist is never stranded without pam_serberus (fail-open),
#          (2) remove the Serberus line from /etc/pam.d/sudo_local (marker-aware;
#          user lines preserved; file deleted only if Serberus created it),
#          (3) remove the drop-in AGAIN — the daemon (owned by the daemon test
#          pkg, and left running here) could rewrite it until sudo_local was
#          unwired, (4) delete /usr/local/lib/pam/pam_serberus.so (and any
#          stray pam_serberus.so.2, which OpenPAM would load first), (5) forget
#          the pkg receipt, then remove these helpers. Deleting the module
#          first would strand a `requisite` reference in sudo_local and brick
#          sudo for everyone. The daemon teardown (disable, bootout, demote
#          JIT, restore authdb) belongs to the daemon pkg's own helper.
#          An EXIT trap keeps the daemon label enabled (and loaded) whenever
#          the script stops early with sudo_local still wired. A drop-in that
#          survives the re-check does not stop the teardown, but the script
#          exits 1.
# Version: 1.5 - (a) pam-lib.sh is sourced only when it and every directory
#          above it are root-owned and not group/other-writable. (b) Also
#          removes a stray /usr/local/lib/pam/pam_serberus.so.2. (c) A drop-in
#          that survives the re-check makes the script exit 1.
#          1.4 - A sudoers drop-in that survives its removal stops the
#          teardown before sudo_local is unwired (and the module is kept).
#          1.3 - EXIT trap re-arms the daemon while sudo_local is still
#          wired; umask 022; pam-lib.sh is removed only when no other helper
#          still needs it.
#          1.2 - Drop-in re-check after the unwire; system-only PATH and
#          absolute tools.
#          1.1 - Remove the coarse sudoers drop-in first (unconditional,
#          marker-guarded) via pam-lib.sh serberus_pam_remove_sudoers_dropin.
#          1.0 - Initial Script
#
#
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
umask 022

# System directories only: /usr/local/bin can be user-writable.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# Absolute tool paths: this runs as root, so nothing is resolved via PATH.
readonly BASENAME="/usr/bin/basename"
readonly ID="/usr/bin/id"
readonly LOGGER="/usr/bin/logger"
readonly PKGUTIL="/usr/sbin/pkgutil"
readonly RM="/bin/rm"
readonly STAT="/usr/bin/stat"

readonly ORG_PLIST_DOMAIN="com.herojoneslabs.serberus"
readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.5"
readonly LOG_LABEL="${ORG_PLIST_DOMAIN}.pamtest-uninstall"

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

readonly SUPPORT_DIR="/Library/Application Support/Serberus"
readonly PAM_LIB_PATH="${SUPPORT_DIR}/pam-lib.sh"
# Canonical module location (/usr/lib/pam is on the sealed read-only system
# snapshot). A legacy pre-relocation module is removed too if one exists.
readonly PAM_MODULE="/usr/local/lib/pam/pam_serberus.so"
readonly PAM_MODULE_LEGACY="/usr/lib/pam/pam_serberus.so"
readonly SUDO_LOCAL="/etc/pam.d/sudo_local"
# Coarse standard-user sudoers allowlist. Removed FIRST (before sudo_local /
# the module) and unconditionally — pam_serberus is the fine gate, so leaving
# this coarse gate behind would be fail-open. Path + guard live in pam-lib.sh.
readonly SUDOERS_DROPIN="/etc/sudoers.d/serberus"
readonly PKG_IDENTIFIER="com.herojoneslabs.serberus.pamtestpkg"
# The daemon (owned by the daemon / core test pkg) the EXIT trap keeps enabled
# while sudo_local is still wired.
readonly DAEMON_LABEL="com.herojoneslabs.serberus.daemon"
readonly LAUNCHD_PLIST="/Library/LaunchDaemons/com.herojoneslabs.serberus.daemon.plist"
# Other on-disk helpers that source the shared pam-lib.sh. It is removed only
# when none of them remains.
readonly OTHER_HELPERS=(
    "${SUPPORT_DIR}/uninstall-serberusd-test.sh"
    "${SUPPORT_DIR}/uninstall-serberus-sentinel-test.sh"
    "${SUPPORT_DIR}/uninstall.sh"
)

# Success marker; without it the EXIT trap re-arms the daemon behind a wired
# sudo_local.
UNINSTALL_SUCCEEDED=0
# Set when the drop-in is still present at the re-check after the unwire; the
# teardown finishes but the script exits 1.
DROPIN_SURVIVED=0

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
    "${LOGGER}" -t "${LOG_LABEL}" -p user.info "[INFO] $*"
    printf '[INFO] %s\n' "$*"
}

log_error() {
    "${LOGGER}" -t "${LOG_LABEL}" -p user.err "[ERROR] $*"
    printf '[ERROR] %s\n' "$*" >&2
}

require_root() {
    if [[ "$("${ID}" -u)" -ne 0 ]]
    then
        log_error "Must run as root (use sudo)"
        exit 1
    fi
}

##################################
### End Core Defined Functions ###
##################################

########################################
######## User Defined Functions ########
### Place your script functions here ###
########################################

# True when <path> is owned by root, not group/other-writable and not a
# symlink. $1 path.
path_is_root_locked() {
    local path="$1"
    local info
    local uid
    local mode
    [[ -e "${path}" && ! -L "${path}" ]] || return 1
    info=$("${STAT}" -f '%u %Lp' "${path}" 2>/dev/null) || return 1
    read -r uid mode <<< "${info}"
    [[ "${uid}" == "0" && "${mode}" =~ ^[0-7]+$ ]] || return 1
    (( ! ( (8#${mode}) & 8#022 ) ))
}

# True when <file> and EVERY directory above it (up to /) are root-locked, so
# nobody but root can swap the file between this check and the source.
# $1 absolute file path.
path_chain_is_root_only() {
    local file="$1"
    [[ "${file}" == /* && -f "${file}" ]] || return 1
    path_is_root_locked "${file}" || return 1
    local dir="${file%/*}"
    while [[ -n "${dir}" ]]
    do
        path_is_root_locked "${dir}" || return 1
        dir="${dir%/*}"
    done
    path_is_root_locked "/"
}

# The marker-aware sudo_local logic lives in pam-lib.sh (installed alongside
# this helper). Refuse to proceed without it — or when anyone but root could
# have changed it — rather than improvising: a wrong removal order or a
# clobbered user line is how sudo gets bricked.
source_pam_lib() {
    if ! path_chain_is_root_only "${PAM_LIB_PATH}"
    then
        log_error "${PAM_LIB_PATH} is missing, or it or a directory above it is not root-only — cannot unwire sudo safely."
        log_error "Manual teardown (THIS ORDER ONLY):"
        log_error "  1. sudo rm -f ${SUDOERS_DROPIN}"
        log_error "     (only if its first line is the Serberus managed header)."
        log_error "  2. Remove the pam_serberus.so line from ${SUDO_LOCAL}"
        log_error "     (delete the whole file only if Serberus created it)."
        log_error "  3. sudo rm -f ${PAM_MODULE} ${PAM_MODULE}.2"
        log_error "  4. sudo pkgutil --forget ${PKG_IDENTIFIER}"
        exit 1
    fi
    # shellcheck source=/dev/null
    source "${PAM_LIB_PATH}"
}

# EXIT trap: stopping early must never leave sudo_local wired behind a
# disabled or unloaded daemon.
on_exit() {
    local status=$?
    if [[ "${UNINSTALL_SUCCEEDED}" -eq 1 ]]
    then
        return 0
    fi
    set +e
    if ! serberus_daemon_rearm_if_wired "${SUDO_LOCAL}" "${DAEMON_LABEL}" "${LAUNCHD_PLIST}"
    then
        log_error "Stopped early (status ${status}) with ${SUDO_LOCAL} still wired — ${DAEMON_LABEL} kept enabled."
    fi
    exit "${status}"
}

# Remove the coarse Serberus sudoers drop-in (standard-user allowlist) BEFORE
# the fine PAM gate is torn down. UNCONDITIONAL. Marker-guarded and scoped to
# this ONE exact path (serberus_pam_remove_sudoers_dropin: `rm -f`, no glob, no
# visudo, no other /etc/sudoers.d entry touched). Leaving the coarse allowlist
# behind after pam_serberus is gone would grant standard users unmediated sudo
# to the curated command paths — fail-open.
# Returns 1 when the drop-in is STILL there after the rm.
remove_sudoers_dropin() {
    local result
    result=$(serberus_pam_remove_sudoers_dropin "${SUDOERS_DROPIN}") || result="FAILED"
    log_info "sudoers drop-in removal: ${result} (${SUDOERS_DROPIN})"
    if [[ "${result}" == "FAILED" ]]
    then
        log_error "${SUDOERS_DROPIN} is STILL present after its removal (immutable flag, or something re-created it)."
        log_error "Remove it by hand (chflags noschg,nouchg first if set): sudo rm -f ${SUDOERS_DROPIN}"
        return 1
    fi
    return 0
}

# First removal: a surviving drop-in stops the teardown BEFORE sudo_local is
# unwired — the PAM gate must outlive it.
remove_sudoers_dropin_or_stop() {
    if ! remove_sudoers_dropin
    then
        log_error "Stopping: sudo_local stays wired and the module is kept."
        exit 1
    fi
}

unwire_sudo_local() {
    local result
    result=$(serberus_pam_remove_sudo_local "${SUDO_LOCAL}") || result="FAILED"
    log_info "sudo_local unwire: ${result} (${SUDO_LOCAL})"

    # Verify no ACTIVE reference survives before the module is deleted.
    if serberus_pam_sudo_local_has_module "${SUDO_LOCAL}"
    then
        log_error "An active pam_serberus.so line remains in ${SUDO_LOCAL} —"
        log_error "refusing to delete the module (a dangling requisite reference bricks sudo)."
        exit 1
    fi
}

remove_module_and_receipt() {
    if [[ -e "${PAM_MODULE}" ]]
    then
        log_info "Removing ${PAM_MODULE}"
        "${RM}" -f "${PAM_MODULE}"
    fi

    if [[ -e "${SERBERUS_PAM_MODULE_VERSIONED_PATH}" || -L "${SERBERUS_PAM_MODULE_VERSIONED_PATH}" ]]
    then
        log_info "Removing ${SERBERUS_PAM_MODULE_VERSIONED_PATH}"
        "${RM}" -f "${SERBERUS_PAM_MODULE_VERSIONED_PATH}"
    fi

    if [[ -e "${PAM_MODULE_LEGACY}" ]]
    then
        log_info "Removing legacy ${PAM_MODULE_LEGACY}"
        "${RM}" -f "${PAM_MODULE_LEGACY}"
    fi

    "${PKGUTIL}" --forget "${PKG_IDENTIFIER}" >/dev/null 2>&1 || true
}

# pam-lib.sh is shared with the other Serberus helpers; keep it while any of
# them is still installed.
remove_helpers() {
    local helper
    local keep=0
    for helper in "${OTHER_HELPERS[@]}"
    do
        if [[ -e "${helper}" ]]
        then
            log_info "Keeping ${PAM_LIB_PATH} — ${helper} still uses it"
            keep=1
        fi
    done
    if [[ "${keep}" -eq 0 ]]
    then
        log_info "Removing ${PAM_LIB_PATH}"
        "${RM}" -f "${PAM_LIB_PATH}"
    fi
    log_info "Removing this helper"
    "${RM}" -f "${SUPPORT_DIR}/uninstall-serberus-pam-test.sh"
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

log_info "${SCRIPT_NAME} v${SCRIPT_VERSION} starting"

require_root
source_pam_lib
trap on_exit EXIT

# ORDER: coarse sudoers drop-in FIRST (never leave the standard-user allowlist
# without the fine PAM gate), then sudo_local, then the drop-in again (the
# running daemon could rewrite it until sudo_local was unwired; now its own
# guard refuses), then module, then receipt. Never reversed.
remove_sudoers_dropin_or_stop
unwire_sudo_local
if ! remove_sudoers_dropin
then
    log_error "The drop-in outlived the PAM gate — remove it by hand."
    DROPIN_SURVIVED=1
fi
remove_module_and_receipt
remove_helpers

UNINSTALL_SUCCEEDED=1
if [[ "${DROPIN_SURVIVED}" -eq 1 ]]
then
    log_error "${SCRIPT_NAME} finished, but ${SUDOERS_DROPIN} is still present — remove it by hand."
    exit 1
fi
log_info "${SCRIPT_NAME} completed successfully"
exit 0

###########################################################
################## End Script Block #######################
###########################################################
UNINSTALL_EOF

    "${CHMOD}" 755 "${helper_path}"

    if ! "${BASH_BIN}" -n "${helper_path}"
    then
        log_error "Generated uninstall helper failed bash -n: ${helper_path}"
        exit 1
    fi
}

write_preinstall() {
    local preinstall_path="${SCRIPTS_DIR}/preinstall"

    "${CAT}" > "${preinstall_path}" <<'PREINSTALL_EOF'
#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: preinstall
# Author: Heath Jones
# Date: 2026-07-11
# Modified: 2026-09-25
# Purpose: Serberus PAM TEST-RING PKG preinstall.
#            1. Break-glass PREFLIGHT (read-only). pam_serberus FAILS CLOSED
#               (daemon-unreachable = hard deny; in enforce mode any sudo
#               matching no rule = deny), so the install ABORTS unless the
#               effective config is already safe: enforcementMode
#               monitor/audit, or a pamBypass with a RESOLVABLE user/group.
#            2. The Serberus daemon must be INSTALLED and LOADED (this pkg
#               never installs it; the postinstall refuses to wire without a
#               running, team-signed daemon, so refuse up front instead of
#               after laying the module down).
#            3. On an upgrade, TEARDOWN-FIRST before the new module lands:
#               remove the coarse sudoers drop-in, then unwire sudo_local
#               (marker-aware; stop if a line survives). This pkg does not own
#               the daemon, so it is left running. A failed upgrade falls back
#               to native sudo; the postinstall re-wires once the new module
#               validates.
#          Steps 1-2 are read-only and run before anything changes.
# Version: 1.3 - A sudoers drop-in that survives its removal stops the
#          upgrade before sudo_local is unwired. The daemon the LaunchDaemon
#          plist runs (Program) is checked first, then the production bundle,
#          then the flat test binary.
#          1.2 - Daemon installed + loaded is now always required (the
#          postinstall no longer falls back without one); teardown-first
#          upgrade; umask 022; refuses a target volume other than "/" ($3);
#          EXIT trap keeps the daemon enabled while sudo_local is wired.
#          1.1 - System-only PATH and absolute tools.
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
umask 022

# System directories only: /usr/local/bin can be user-writable.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# Absolute tool paths: this runs as root, so nothing is resolved via PATH.
readonly BASENAME="/usr/bin/basename"
readonly DIRNAME="/usr/bin/dirname"
readonly ID="/usr/bin/id"
readonly LAUNCHCTL="/bin/launchctl"
readonly LOGGER="/usr/bin/logger"
readonly PLIST_BUDDY="/usr/libexec/PlistBuddy"

readonly ORG_PLIST_DOMAIN="com.herojoneslabs.serberus"
readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.3"
readonly LOG_LABEL="${ORG_PLIST_DOMAIN}.pamtest-preinstall"

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

readonly DAEMON_LABEL="com.herojoneslabs.serberus.daemon"
readonly LAUNCHD_PLIST="/Library/LaunchDaemons/com.herojoneslabs.serberus.daemon.plist"
# The daemon this module gates for: the one the LaunchDaemon plist's Program
# names, else the production bundle, else the test-ring flat binary.
readonly DAEMON_BUNDLE_PATH="/Library/PrivilegedHelperTools/serberusd.app"
readonly DAEMON_FLAT_PATH="/Library/PrivilegedHelperTools/com.herojoneslabs.serberus.daemon"
readonly DAEMON_BINARIES=(
    "${DAEMON_BUNDLE_PATH}/Contents/MacOS/com.herojoneslabs.serberus.daemon"
    "${DAEMON_FLAT_PATH}"
)
readonly SUDO_LOCAL="/etc/pam.d/sudo_local"
readonly SUDOERS_DROPIN="/etc/sudoers.d/serberus"

# The config the preflight reads: only the MDM-written managed plist, exactly
# as Sources/pam_serberus/pam_config.c does.
readonly MANAGED_CONFIG_PLIST="/Library/Managed Preferences/com.herojoneslabs.serberus.config.plist"

# Installer passes the target volume as $3.
readonly TARGET_VOLUME="${3:-}"

# Success marker; without it the EXIT trap keeps the daemon enabled behind a
# wired sudo_local.
PREINSTALL_SUCCEEDED=0

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
    "${LOGGER}" -t "${LOG_LABEL}" -p user.info "[INFO] $*"
}

log_warn() {
    "${LOGGER}" -t "${LOG_LABEL}" -p user.warning "[WARN] $*"
}

log_error() {
    "${LOGGER}" -t "${LOG_LABEL}" -p user.err "[ERROR] $*"
}

require_root() {
    if [[ "$("${ID}" -u)" -ne 0 ]]
    then
        log_error "preinstall not running as root"
        exit 1
    fi
}

# Serberus rewires THIS Mac's sudo; installing onto any other volume is
# refused before anything is touched.
require_boot_volume() {
    if [[ "${TARGET_VOLUME}" != "/" ]]
    then
        log_error "Target volume is '${TARGET_VOLUME}', not '/'. Serberus must be installed on the running system."
        exit 1
    fi
}

##################################
### End Core Defined Functions ###
##################################

########################################
######## User Defined Functions ########
### Place your script functions here ###
########################################

# pkgbuild ships every file in the scripts dir alongside this script.
source_pam_lib() {
    local lib
    lib="$("${DIRNAME}" "$0")/pam-lib.sh"
    if [[ ! -f "${lib}" ]]
    then
        log_error "pam-lib.sh missing from pkg scripts — aborting install (fail closed)."
        exit 1
    fi
    # shellcheck source=/dev/null
    source "${lib}"
}

# Safety net for an UNEXPECTED exit: a sudo_local that is still wired keeps
# its daemon enabled and loaded.
on_exit() {
    local status=$?
    if [[ "${PREINSTALL_SUCCEEDED}" -eq 1 ]]
    then
        return 0
    fi
    set +e
    serberus_daemon_rearm_if_wired "${SUDO_LOCAL}" "${DAEMON_LABEL}" "${LAUNCHD_PLIST}" \
        2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    exit "${status}"
}

preflight_break_glass() {
    local mode
    mode=$(serberus_pam_effective_mode "${MANAGED_CONFIG_PLIST}")
    local bypass_count
    bypass_count=$(serberus_pam_bypass_count "${MANAGED_CONFIG_PLIST}")
    # Unresolvable entries arrive on stderr, one per line — route them into
    # the unified log so a typo'd break-glass account is visible.
    local resolvable_count
    resolvable_count=$(serberus_pam_resolvable_bypass_count \
        "${MANAGED_CONFIG_PLIST}" \
        2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err))
    log_info "Effective config: enforcementMode=${mode} pamBypass string members=${bypass_count} resolvable=${resolvable_count}"

    if ! serberus_pam_preflight_break_glass "${MANAGED_CONFIG_PLIST}" 2>/dev/null
    then
        log_error "BREAK-GLASS PREFLIGHT FAILED — ABORTING INSTALL."
        log_error "Effective enforcementMode is enforce (or config absent) with NO pamBypass"
        log_error "users or groups that RESOLVE to real accounts (typo'd entries provide zero"
        log_error "bypass). Installing pam_serberus.so now would brick sudo:"
        log_error "the module is 'requisite', fails closed, and in enforce mode denies every"
        log_error "sudo not explicitly allowed by a rule."
        log_error "Scope the break-glass config profile FIRST"
        log_error "(Support/sample-profiles/serberus-config-breakglass.mobileconfig, domain"
        log_error "com.herojoneslabs.serberus.config: enforcementMode=monitor and/or a"
        log_error "populated pamBypass), then re-run this install."
        exit 1
    fi
    log_info "Break-glass preflight passed (mode=${mode}, resolvable bypass=${resolvable_count})"
}

# The daemon the LaunchDaemon plist actually runs (its Program), mapped to the
# path codesign is asked about; nothing when the plist names neither known
# location. It is tried first, so a stale daemon left at the other location
# (e.g. a flat test binary after a production upgrade) never supplies the team.
launchd_program_daemon() {
    local program
    program=$("${PLIST_BUDDY}" -c 'Print :Program' "${LAUNCHD_PLIST}" 2>/dev/null) || return 1
    case "${program}" in
        "${DAEMON_BUNDLE_PATH}"/Contents/MacOS/*)
            printf '%s' "${DAEMON_BUNDLE_PATH}/Contents/MacOS/com.herojoneslabs.serberus.daemon"
            ;;
        "${DAEMON_FLAT_PATH}")
            printf '%s' "${DAEMON_FLAT_PATH}"
            ;;
        *)
            return 1
            ;;
    esac
}

# The module is useless without its daemon, and the postinstall refuses to
# wire sudo_local unless the daemon is running and team-signed — refuse now,
# before the module is laid down.
require_daemon() {
    local binary
    local found=""
    local preferred=""
    preferred=$(launchd_program_daemon) || preferred=""
    for binary in ${preferred:+"${preferred}"} "${DAEMON_BINARIES[@]}"
    do
        if [[ -x "${binary}" ]]
        then
            found="${binary}"
            break
        fi
    done
    if [[ -z "${found}" ]]
    then
        log_error "No Serberus daemon is installed — install the daemon (or core) test pkg FIRST."
        exit 1
    fi
    if ! "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" >/dev/null 2>&1
    then
        log_error "Daemon ${DAEMON_LABEL} is installed (${found}) but NOT loaded — wiring pam_serberus"
        log_error "now would deny every non-bypass sudo. Start it (or reinstall its pkg), then re-run."
        exit 1
    fi
}

# Teardown-first, step 1: the coarse gate before the fine one.
# A drop-in that is still there after the rm stops the upgrade BEFORE
# sudo_local is unwired.
remove_sudoers_dropin() {
    local result
    result=$(serberus_pam_remove_sudoers_dropin "${SUDOERS_DROPIN}") || result="FAILED"
    log_info "sudoers drop-in removal: ${result} (${SUDOERS_DROPIN})"
    if [[ "${result}" == "FAILED" ]]
    then
        log_error "${SUDOERS_DROPIN} is STILL present after its removal (immutable flag, or something re-created it)."
        log_error "Stopping the upgrade before sudo_local is unwired. Remove the file by hand, then reinstall."
        exit 1
    fi
}

# Teardown-first, step 2: unwire before the module file is replaced. A
# surviving active line stops the upgrade (the daemon keeps running).
unwire_sudo_local() {
    local result
    result=$(serberus_pam_remove_sudo_local "${SUDO_LOCAL}") || result="FAILED"
    log_info "sudo_local unwire: ${result} (${SUDO_LOCAL})"
    if serberus_pam_sudo_local_has_module "${SUDO_LOCAL}"
    then
        log_error "An ACTIVE pam_serberus line remains in ${SUDO_LOCAL} — aborting the upgrade."
        log_error "Fix ${SUDO_LOCAL} by hand, then reinstall."
        exit 1
    fi
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

log_info "${SCRIPT_NAME} v${SCRIPT_VERSION} starting"

require_root
require_boot_volume
source_pam_lib
trap on_exit EXIT

# Read-only gates first — nothing changes if either refuses.
preflight_break_glass
require_daemon

# Teardown-first on an upgrade (no-ops on a fresh install). The daemon is not
# this pkg's to boot out.
remove_sudoers_dropin
unwire_sudo_local

PREINSTALL_SUCCEEDED=1
log_info "${SCRIPT_NAME} completed successfully"
exit 0

###########################################################
################## End Script Block #######################
###########################################################
PREINSTALL_EOF

    "${CHMOD}" 755 "${preinstall_path}"

    if ! "${BASH_BIN}" -n "${preinstall_path}"
    then
        log_error "Generated preinstall failed bash -n: ${preinstall_path}"
        exit 1
    fi
}

write_postinstall() {
    local postinstall_path="${SCRIPTS_DIR}/postinstall"

    "${CAT}" > "${postinstall_path}" <<'POSTINSTALL_EOF'
#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: postinstall
# Author: Heath Jones
# Date: 2026-07-11
# Modified: 2026-09-26
# Purpose: Serberus PAM TEST-RING PKG postinstall. ORDER IS SAFETY-CRITICAL:
#          the module's DIRECTORY chain is checked before the module is
#          touched, the module is locked root:wheel 444 (-h, no symlinks),
#          then fully validated (signed by the installed daemon's team — a
#          missing or team-less daemon is refused, no ad-hoc fallback — the
#          SerberusAuth plugin, when installed, pinned to the same team,
#          native arch present, root-only directory chain), and the daemon
#          must be UP (one pid for 8 s with no launchd restart + a healthy `serberus status`)
#          BEFORE /etc/pam.d/sudo_local is touched — wiring an unloadable
#          module, or one with no daemon behind it, into the `requisite` line
#          bricks sudo for everyone. sudo_local is then line-merged
#          idempotently (Serberus line first among the auth lines, user lines
#          preserved; Apple's /etc/pam.d/sudo is never touched — only checked,
#          loudly). On any failure — including an unexpected exit, via the
#          EXIT trap — the sudoers drop-in is removed and any sudo_local line
#          is UNWIRED (marker-aware), exit 1. This pkg never bootstraps the
#          daemon (the daemon/core test pkg does) and never writes sudoers.
# Version: 1.4 - A stray /usr/local/lib/pam/pam_serberus.so.2 (OpenPAM loads
#          it in place of the module) is removed before sudo_local is wired;
#          one that cannot be removed aborts the install.
#          1.3 - (a) The daemon team comes from the daemon the LaunchDaemon
#          plist runs (Program) first, then the production bundle, then the
#          flat test binary — a stale daemon at the other location is never
#          the pin. (b) Liveness: 8 s same-pid window, no launchd restart
#          while waiting; the pid is re-read right before sudo_local is
#          merged. (c) A sudoers drop-in that survives its removal stops the
#          abort path before sudo_local is unwired. (d) Each chown/chmod is
#          checked on its own.
#          1.2 - Refuses to wire with no daemon installed, or a daemon with
#          no Team ID (the --strict fallback is gone); pins the module AND an
#          installed SerberusAuth.bundle to the daemon's team; waits for a
#          stable daemon pid (+ `serberus status`) before wiring; module
#          directory chain checked before chown/chmod (-h); EXIT trap; umask
#          022; refuses a target volume other than "/" ($3); warns when
#          /etc/pam.d/sudo does not include sudo_local first.
#          1.1 - Team-pinned module signature (the daemon's TeamIdentifier;
#          --strict fallback with a warning for an ad-hoc/absent daemon, test
#          ring only), root-only directory-chain check, canonical post-merge
#          sanity, abort path that removes the drop-in and self-heals a prior
#          sudo_local, system-only PATH and absolute tools.
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
umask 022

# System directories only: /usr/local/bin can be user-writable.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# Absolute tool paths: this runs as root, so nothing is resolved via PATH.
readonly BASENAME="/usr/bin/basename"
readonly CHMOD="/bin/chmod"
readonly CHOWN="/usr/sbin/chown"
readonly DIRNAME="/usr/bin/dirname"
readonly FILE="/usr/bin/file"
readonly ID="/usr/bin/id"
readonly LOGGER="/usr/bin/logger"
readonly STAT="/usr/bin/stat"
readonly UNAME="/usr/bin/uname"
readonly PLIST_BUDDY="/usr/libexec/PlistBuddy"

readonly ORG_PLIST_DOMAIN="com.herojoneslabs.serberus"
readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.4"
readonly LOG_LABEL="${ORG_PLIST_DOMAIN}.pamtest-postinstall"

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

# /usr/lib/pam is on the SEALED read-only system snapshot (macOS 11+); the
# module lives under the /usr/local firmlink and sudo_local references it by
# absolute path (pam-lib.sh SERBERUS_PAM_MODULE_PATH — keep in sync).
readonly PAM_MODULE_DIR="/usr/local/lib/pam"
readonly PAM_MODULE="${PAM_MODULE_DIR}/pam_serberus.so"
readonly SUDO_LOCAL="/etc/pam.d/sudo_local"
readonly PAM_SUDO="/etc/pam.d/sudo"
readonly SUPPORT_DIR="/Library/Application Support/Serberus"
readonly UNINSTALL_HELPER="${SUPPORT_DIR}/uninstall-serberus-pam-test.sh"
readonly INSTALLED_PAM_LIB="${SUPPORT_DIR}/pam-lib.sh"
readonly DAEMON_LABEL="com.herojoneslabs.serberus.daemon"
readonly LAUNCHD_PLIST="/Library/LaunchDaemons/com.herojoneslabs.serberus.daemon.plist"
# The installed daemon whose team the module must share: the one the
# LaunchDaemon plist's Program names, else the production bundle, else the
# test-ring flat binary.
readonly DAEMON_BUNDLE_PATH="/Library/PrivilegedHelperTools/serberusd.app"
readonly DAEMON_FLAT_PATH="/Library/PrivilegedHelperTools/com.herojoneslabs.serberus.daemon"
readonly DAEMON_BINARIES=(
    "${DAEMON_BUNDLE_PATH}"
    "${DAEMON_FLAT_PATH}"
)
# Installed by the core / production pkgs, not this one; pinned when present.
readonly AUTH_PLUGIN="/Library/Security/SecurityAgentPlugins/SerberusAuth.bundle"
# `serberus status` joins the "daemon up" check when a trusted CLI exists.
readonly CLI_BINARY="/usr/local/bin/serberus"
# Seconds to wait for a running daemon pid (plus the 8 s stability window).
readonly DAEMON_START_TIMEOUT=10

# Installer passes the target volume as $3.
readonly TARGET_VOLUME="${3:-}"

# Success marker: set right before the final exit 0. The EXIT trap runs the
# abort path whenever the script ends without it.
INSTALL_SUCCEEDED=0
ABORT_IN_PROGRESS=0
DAEMON_TEAM=""

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
    "${LOGGER}" -t "${LOG_LABEL}" -p user.info "[INFO] $*"
}

log_warn() {
    "${LOGGER}" -t "${LOG_LABEL}" -p user.warning "[WARN] $*"
}

log_error() {
    "${LOGGER}" -t "${LOG_LABEL}" -p user.err "[ERROR] $*"
}

require_root() {
    if [[ "$("${ID}" -u)" -ne 0 ]]
    then
        log_error "Must run as root"
        exit 1
    fi
}

# Serberus rewires THIS Mac's sudo; installing onto any other volume is
# refused.
require_boot_volume() {
    if [[ "${TARGET_VOLUME}" != "/" ]]
    then
        log_error "Target volume is '${TARGET_VOLUME}', not '/'. Serberus must be installed on the running system."
        exit 1
    fi
}

##################################
### End Core Defined Functions ###
##################################

########################################
######## User Defined Functions ########
### Place your script functions here ###
########################################

file_mode() {
    "${STAT}" -f '%Lp' "$1" 2>/dev/null || printf 'missing'
}

# pkgbuild ships every file in the scripts dir alongside this script.
source_pam_lib() {
    local lib
    lib="$("${DIRNAME}" "$0")/pam-lib.sh"
    if [[ ! -f "${lib}" ]]
    then
        log_error "pam-lib.sh missing from pkg scripts — NOT wiring sudo_local (fail closed)."
        exit 1
    fi
    # shellcheck source=/dev/null
    source "${lib}"
}

# Any exit without the success marker takes the abort path.
on_exit() {
    local status=$?
    if [[ "${INSTALL_SUCCEEDED}" -eq 1 || "${ABORT_IN_PROGRESS}" -eq 1 ]]
    then
        return 0
    fi
    abort_install "unexpected exit (status ${status}) before the install completed"
}

# Belt and braces: the pkg is built non-root with `recommended` ownership, so
# re-assert ownership/modes explicitly before validating. The module's
# DIRECTORY chain is checked first — root never chowns/chmods inside a
# directory a user controls — and the module is locked with -h (no symlinks).
# Each step is checked on its own (this runs under `if !`, where set -e does
# not apply), so a failed chown is never hidden by a chmod after it.
fix_ownership() {
    if ! serberus_pam_module_dir_is_safe "${PAM_MODULE}" \
        2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    then
        log_error "the module's directory chain is not root-only — NOT touching the module"
        return 1
    fi
    if ! serberus_pam_lock_module "${PAM_MODULE}" \
        2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    then
        log_error "could not lock ${PAM_MODULE} to root:wheel 0444"
        return 1
    fi
    if [[ -f "${UNINSTALL_HELPER}" && ! -L "${UNINSTALL_HELPER}" ]]
    then
        "${CHOWN}" -h root:wheel "${UNINSTALL_HELPER}" || return 1
        "${CHMOD}" -h 755 "${UNINSTALL_HELPER}" || return 1
    fi
    if [[ -f "${INSTALLED_PAM_LIB}" && ! -L "${INSTALLED_PAM_LIB}" ]]
    then
        "${CHOWN}" -h root:wheel "${INSTALLED_PAM_LIB}" || return 1
        "${CHMOD}" -h 644 "${INSTALLED_PAM_LIB}" || return 1
    fi
    return 0
}

# The arch sudo demands on this Mac (sudo runs arm64e on Apple silicon; a
# plain arm64 module slice satisfies it).
native_module_arch() {
    local machine
    machine=$("${UNAME}" -m)
    case "${machine}" in
        arm64|arm64e)
            printf 'arm64'
            ;;
        *)
            printf '%s' "${machine}"
            ;;
    esac
}

# The daemon the LaunchDaemon plist actually runs (its Program), mapped to the
# path codesign is asked about; nothing when the plist names neither known
# location. It is tried first, so a stale daemon left at the other location
# (e.g. a flat test binary after a production upgrade) never supplies the team.
launchd_program_daemon() {
    local program
    program=$("${PLIST_BUDDY}" -c 'Print :Program' "${LAUNCHD_PLIST}" 2>/dev/null) || return 1
    case "${program}" in
        "${DAEMON_BUNDLE_PATH}"/Contents/MacOS/*)
            printf '%s' "${DAEMON_BUNDLE_PATH}"
            ;;
        "${DAEMON_FLAT_PATH}")
            printf '%s' "${DAEMON_FLAT_PATH}"
            ;;
        *)
            return 1
            ;;
    esac
}

# The installed daemon's Team ID. No daemon, or an ad-hoc/team-less one, is
# REFUSED — there is no --strict fallback: the module (and the plugin) must
# be pinned to the daemon's team, exactly like the production postinstall.
resolve_daemon_team() {
    local daemon
    local preferred=""
    preferred=$(launchd_program_daemon) || preferred=""
    for daemon in ${preferred:+"${preferred}"} "${DAEMON_BINARIES[@]}"
    do
        if [[ -e "${daemon}" ]]
        then
            if DAEMON_TEAM=$(serberus_codesign_team_id "${daemon}")
            then
                return 0
            fi
            DAEMON_TEAM=""
            log_error "installed daemon ${daemon} is ad-hoc or carries no Team ID — refusing to wire sudo_local"
            return 1
        fi
    done
    log_error "no Serberus daemon is installed — refusing to wire sudo_local (install the daemon or core test pkg first)"
    return 1
}

# ALL validation runs BEFORE sudo_local is touched. A module that cannot
# dlopen inside sudo's `requisite` line bricks sudo for everyone — including
# bypass users, who are only evaluated once the module loads.
module_validation_passes() {
    local ok=0

    # 1. Module present with mode 444.
    if [[ ! -f "${PAM_MODULE}" ]] || [[ "$(file_mode "${PAM_MODULE}")" != "444" ]]
    then
        log_error "criterion 1 FAIL: PAM module missing or not mode 444"
        ok=1
    fi

    # 2. Signed by the daemon's team (strict verification included — catches
    #    xattr damage from a cloud-synced copy or Finder too; a broken seal is
    #    a dlopen failure).
    if [[ -z "${DAEMON_TEAM}" ]]
    then
        log_error "criterion 2 FAIL: no daemon Team ID to verify the PAM module against"
        ok=1
    elif ! serberus_codesign_satisfies_team "${PAM_MODULE}" "${DAEMON_TEAM}"
    then
        log_error "criterion 2 FAIL: PAM module is not validly signed by the daemon's team ${DAEMON_TEAM}"
        ok=1
    fi

    # 3. The module carries the arch sudo will demand on this Mac. Checked with
    #    file(1), NOT lipo: lipo ships ONLY with the Xcode Command Line Tools,
    #    absent on a managed endpoint, where /usr/bin/lipo is a non-functional
    #    xcrun shim that exits non-zero — failing this criterion on every Mac
    #    without the Command Line Tools. file(1) is base macOS and names every
    #    slice's arch;
    #    criterion 2's codesign --verify --strict already validated the seal.
    local needed
    needed=$(native_module_arch)
    local file_desc
    if ! file_desc=$("${FILE}" -b "${PAM_MODULE}" 2>/dev/null) || [[ -z "${file_desc}" ]]
    then
        log_error "criterion 3 FAIL: file(1) cannot read ${PAM_MODULE}"
        ok=1
    elif [[ "${file_desc}" != *"${needed}"* ]]
    then
        log_error "criterion 3 FAIL: module [${file_desc}] does not cover native ${needed}"
        ok=1
    fi

    # 4. /usr … /usr/local/lib/pam and the module root-owned, not
    #    group/other-writable, no symlinks (an Intel Homebrew layout fails).
    if ! serberus_pam_module_path_is_safe "${PAM_MODULE}" \
        2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    then
        log_error "criterion 4 FAIL: the module's directory chain is not root-only — refusing to wire sudo_local"
        ok=1
    fi

    # 5. An installed SerberusAuth plugin carries the same team pin as the
    #    module (the fleet runs one consistently signed Serberus).
    if [[ -L "${AUTH_PLUGIN}" ]]
    then
        log_error "criterion 5 FAIL: ${AUTH_PLUGIN} is a symlink"
        ok=1
    elif [[ -d "${AUTH_PLUGIN}" ]]
    then
        if [[ -z "${DAEMON_TEAM}" ]] \
            || ! serberus_codesign_satisfies_team "${AUTH_PLUGIN}" "${DAEMON_TEAM}"
        then
            log_error "criterion 5 FAIL: installed authorization plugin is not validly signed by the daemon's team"
            ok=1
        fi
    fi

    return ${ok}
}

# Apple's /etc/pam.d/sudo must include sudo_local as its FIRST auth line, or
# the daemon reports degraded(pam_not_wired). Never edited — warn loudly.
check_pam_sudo_includes_sudo_local() {
    if ! serberus_pam_sudo_includes_sudo_local "${PAM_SUDO}" \
        2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    then
        log_error "!!! ${PAM_SUDO} does not start its auth stack with 'auth include sudo_local' —"
        log_error "!!! pam_serberus will not gate sudo; the daemon reports degraded(pam_not_wired)."
    fi
}

# The abort path: coarse drop-in first, then self-heal a sudo_local this or a
# PREVIOUS install wired (a fresh install is left byte-identical), exit 1.
# This pkg does not own the daemon, which keeps running either way.
abort_install() {
    ABORT_IN_PROGRESS=1
    set +e
    log_error "ABORTING: $*"
    local result
    result=$(serberus_pam_remove_sudoers_dropin) || result="FAILED"
    log_error "abort path: sudoers drop-in removal result=${result}"
    if [[ "${result}" == "FAILED" ]]
    then
        # The PAM gate must outlive the drop-in: sudo_local is left as it is.
        log_error "!!! abort path: the Serberus sudoers drop-in SURVIVED its removal — NOT unwiring ${SUDO_LOCAL}."
        log_error "!!! Remove it by hand (chflags noschg,nouchg first if set): sudo rm -f ${SERBERUS_SUDOERS_PATH}"
        exit 1
    fi
    if serberus_pam_sudo_local_has_module "${SUDO_LOCAL}"
    then
        result=$(serberus_pam_remove_sudo_local "${SUDO_LOCAL}") || result="FAILED"
        log_error "abort path: unwired sudo_local (result=${result})"
        if serberus_pam_sudo_local_has_module "${SUDO_LOCAL}"
        then
            log_error "!!! abort path: an ACTIVE pam_serberus.so line STILL remains in ${SUDO_LOCAL} — the daemon"
            log_error "!!! is left running behind it; remove the line by hand before relying on sudo."
        fi
    fi
    exit 1
}

wire_sudo_local() {
    local merge_result
    merge_result=$(serberus_pam_merge_sudo_local "${SUDO_LOCAL}") || merge_result="FAILED"
    log_info "sudo_local merge: ${merge_result} (${SUDO_LOCAL})"

    # Post-merge sanity: the file must be canonical (one active `requisite`
    # line, FIRST among the auth lines). If it is not, roll back exactly what
    # this run added (marker-aware: the file is deleted only if this run
    # created it) and fail the install.
    if ! serberus_pam_sudo_local_is_canonical "${SUDO_LOCAL}"
    then
        log_error "post-merge sanity FAIL: ${SUDO_LOCAL} is not canonical"
        local rollback
        rollback=$(serberus_pam_remove_sudo_local "${SUDO_LOCAL}") || rollback="FAILED"
        log_error "rolled back sudo_local (${rollback})"
        return 1
    fi

    # A file we created or merged into is written 0444 by pam-lib.sh; assert
    # root:wheel. A pre-existing canonical file ('present') keeps its content
    # and other mode bits, but the daemon only trusts a root-owned sudo_local
    # no group/other can write (it refuses to write the sudoers drop-in
    # otherwise), so that much is asserted either way.
    # Each step is checked on its own: a failed chown must not be hidden by a
    # chmod that succeeds after it.
    local mode="go-w"
    if [[ "${merge_result}" == "created" || "${merge_result}" == "merged" ]]
    then
        mode="444"
    fi
    if ! "${CHOWN}" -h root:wheel "${SUDO_LOCAL}"
    then
        log_error "could not chown ${SUDO_LOCAL} to root:wheel"
        return 1
    fi
    if ! "${CHMOD}" -h "${mode}" "${SUDO_LOCAL}"
    then
        log_error "could not chmod ${mode} ${SUDO_LOCAL}"
        return 1
    fi
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

log_info "${SCRIPT_NAME} v${SCRIPT_VERSION} starting (installer log: /var/log/install.log)"

require_root
require_boot_volume
source_pam_lib
trap on_exit EXIT

if ! fix_ownership
then
    abort_install "module directory chain is not root-only, or the module could not be locked"
fi

if ! resolve_daemon_team
then
    abort_install "no installed, team-signed daemon — sudo_local NOT wired by this run"
fi

if ! module_validation_passes
then
    abort_install "module validation failed — sudo_local NOT wired by this run"
fi

# The daemon must be UP — one pid held for 8 s with no launchd restart, and a
# fresh `serberus status` when another Serberus pkg installed the CLI (this
# pkg does not ship it) — before sudo depends on it. This pkg does not
# bootstrap the daemon, so there is no bootstrap mark: restarts are judged
# against what launchd reported when the wait started.
HEALTH_CLI=""
if [[ -e "${CLI_BINARY}" ]]
then
    HEALTH_CLI="${CLI_BINARY}"
fi
if ! serberus_launchd_wait_running "${DAEMON_LABEL}" "${DAEMON_START_TIMEOUT}" "${HEALTH_CLI}" "${DAEMON_TEAM}" 2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
then
    abort_install "daemon ${DAEMON_LABEL} is not up (no stable pid, a restart, or serberus status failed) — sudo_local NOT wired"
fi

check_pam_sudo_includes_sudo_local

# OpenPAM loads "<module>.2" in preference to the module itself.
VERSIONED_RESULT=$(serberus_pam_remove_versioned_module) || VERSIONED_RESULT="FAILED"
if [[ "${VERSIONED_RESULT}" == "FAILED" ]]
then
    abort_install "could not remove ${SERBERUS_PAM_MODULE_VERSIONED_PATH}, which OpenPAM would load in place of the module"
elif [[ "${VERSIONED_RESULT}" == "removed" ]]
then
    log_info "Removed a stray ${SERBERUS_PAM_MODULE_VERSIONED_PATH}"
fi

# Last look before sudo is gated: still the daemon process confirmed up.
if ! serberus_launchd_pid_unchanged "${DAEMON_LABEL}" 2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
then
    abort_install "daemon ${DAEMON_LABEL} restarted after it was confirmed up — sudo_local NOT wired"
fi
if ! wire_sudo_local
then
    abort_install "sudo_local wiring failed"
fi

INSTALL_SUCCEEDED=1
log_info "pam_serberus.so wired. Verify from a NEW terminal: sudo /usr/bin/true"
log_info "Teardown: sudo \"${UNINSTALL_HELPER}\""
log_info "${SCRIPT_NAME} completed successfully"
exit 0

###########################################################
################## End Script Block #######################
###########################################################
POSTINSTALL_EOF

    "${CHMOD}" 755 "${postinstall_path}"

    if ! "${BASH_BIN}" -n "${postinstall_path}"
    then
        log_error "Generated postinstall failed bash -n: ${postinstall_path}"
        exit 1
    fi
}

# The generated scripts source pam-lib.sh from their own directory
# (pkgbuild ships every file in --scripts alongside them).
stage_pam_lib() {
    "${CP}" "${PAM_LIB_SRC}" "${SCRIPTS_DIR}/${PAM_LIB_NAME}"
    "${CHMOD}" 644 "${SCRIPTS_DIR}/${PAM_LIB_NAME}"

    if ! "${BASH_BIN}" -n "${SCRIPTS_DIR}/${PAM_LIB_NAME}"
    then
        log_error "pam-lib.sh failed bash -n: ${SCRIPTS_DIR}/${PAM_LIB_NAME}"
        exit 1
    fi
}

build_package() {
    # Default `recommended` ownership (no --ownership flag): the pkg is built
    # as the user; Installer maps /usr/local and /Library to root:wheel and the
    # postinstall re-asserts exact ownership/modes.
    log_info "Building component pkg ${OUTPUT_PKG}"
    "${PKGBUILD}" \
        --root "${PAYLOAD_DIR}" \
        --scripts "${SCRIPTS_DIR}" \
        --identifier "${PKG_IDENTIFIER}" \
        --version "${PKG_VERSION}" \
        "${OUTPUT_PKG}"
    log_info "Built ${OUTPUT_PKG}"
}

sign_installer() {
    if [[ -z "${INSTALLER_IDENTITY}" ]]
    then
        return 0
    fi
    log_info "Signing installer with '${INSTALLER_IDENTITY}'"
    "${PRODUCTSIGN}" --sign "${INSTALLER_IDENTITY}" "${OUTPUT_PKG}" "${SIGNED_PKG}"
    log_info "Signed installer: ${SIGNED_PKG}"
}

print_summary() {
    local pkg="${OUTPUT_PKG}"
    if [[ -f "${SIGNED_PKG}" ]]
    then
        pkg="${SIGNED_PKG}"
    fi
    log_info "──────────────────────────────────────────────────────────────"
    log_info "PAM TEST-RING pkg ready: ${pkg}"
    log_info "Contains: /usr/local/lib/pam/pam_serberus.so (identifier ${PAM_IDENTIFIER}),"
    log_info "          ${SUPPORT_DIR}/${UNINSTALL_HELPER_NAME},"
    log_info "          ${SUPPORT_DIR}/${PAM_LIB_NAME}"
    log_info "ORDERING: scope the break-glass config profile AND install the daemon"
    log_info "          test pkg BEFORE this pkg — the preinstall aborts otherwise."
    log_info "Verify:   from a NEW terminal: sudo /usr/bin/true"
    log_info "Teardown: sudo \"${SUPPORT_DIR}/${UNINSTALL_HELPER_NAME}\""
    log_info "Receipt:  pkgutil --pkg-info ${PKG_IDENTIFIER}"
    log_info "Guide:    PKG/README.md"
    log_info "NOT for production — use build-pkg.sh (notarized full payload) instead."
    log_info "──────────────────────────────────────────────────────────────"
}

run_self_test() {
    local test_script="${SCRIPT_DIR}/tests/test-pam-lib.sh"
    if [[ ! -f "${test_script}" ]]
    then
        log_error "Test harness not found: ${test_script}"
        exit 1
    fi
    log_info "Running ${test_script}"
    "${BASH_BIN}" "${test_script}"
}

# Test-harness hook: generate every script (preinstall, postinstall,
# uninstall helper, staged pam-lib) into BUILD_DIR without compiling or
# signing anything, so the harness can bash -n and exercise them.
emit_scripts_only() {
    if [[ -z "${EMIT_DIR}" ]]
    then
        log_error "--emit-scripts requires a target directory argument"
        exit 1
    fi
    "${MKDIR}" -p "${SCRIPTS_DIR}" "${PAYLOAD_DIR}${SUPPORT_DIR}"
    write_preinstall
    write_postinstall
    write_uninstall_helper
    stage_pam_lib
    log_info "Generated scripts written under ${BUILD_DIR}"
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

log_info "${SCRIPT_NAME} v${SCRIPT_VERSION} starting (mode ${MODE})"

case "${MODE}" in
    --build)
        verify_inputs
        run_self_test
        "${RM}" -rf "${BUILD_DIR}"
        "${MKDIR}" -p "${BUILD_DIR}" "${SCRIPTS_DIR}"
        build_module
        assemble_payload
        write_preinstall
        write_postinstall
        stage_pam_lib
        build_package
        sign_installer
        print_summary
        ;;
    --self-test)
        run_self_test
        ;;
    --emit-scripts)
        emit_scripts_only
        ;;
    *)
        printf 'Usage: %s [--build|--self-test|--emit-scripts <dir>]\n' "${SCRIPT_NAME}" >&2
        exit 1
        ;;
esac

log_info "${SCRIPT_NAME} completed successfully"

###########################################################
################## End Script Block #######################
###########################################################
