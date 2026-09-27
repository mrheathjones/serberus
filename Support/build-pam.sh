#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: build-pam.sh
# Author: Heath Jones
# Date: 2026-06-13
# Modified: 2026-09-26
# Purpose: Compile, sign, and (optionally) install the Serberus PAM module
#          pam_serberus.so. Developer tool — local Mac only. The production
#          endpoint install is the PKG.
# Version: 2.5 - (a) --install never builds: it installs the module built
#          beforehand as the logged-in user. sudo drops SIGNING_IDENTITY, so
#          without --force it refuses up front, before any check or change,
#          unless SIGNING_IDENTITY is passed through sudo; it then requires
#          the prebuilt module (a regular file). (b) --build refuses to run
#          under sudo: it would compile as root into the invoking user's
#          home. (c) The staged copy in /usr/local/lib/pam is re-verified
#          (signature, arch, daemon team) before it replaces the live module,
#          since the prebuilt file sits in a user-writable directory. (d) A
#          stray /usr/local/lib/pam/pam_serberus.so.2 (OpenPAM loads it first)
#          is removed before sudo_local can reference the module.
#          2.4 - --install copies the module to a temp file in
#          /usr/local/lib/pam, locks it there and moves it over the live module
#          (atomic), so a concurrent sudo never dlopens a half-written file;
#          the temp file is removed on any failure. Without --force the
#          daemon pid confirmed by serberus_launchd_wait_running must still
#          be the running one right before sudo_local is created. A failed
#          chown of a created sudo_local is no longer hidden by the chmod.
#          2.3 - --install now (a) requires a RUNNING daemon (one stable pid,
#          pam-lib serberus_launchd_wait_running) and a module signed by the
#          installed daemon's team, unless --force; (b) checks the module's
#          directory chain BEFORE copying or chowning anything and locks the
#          module with chown -h / chmod -h (symlinks refused); (c) creates a
#          missing sudo_local through pam-lib (temp file, 0444, atomic mv —
#          a dangling symlink is replaced, never written through); (d) warns
#          loudly when /etc/pam.d/sudo does not include sudo_local as its
#          first auth line. umask 022 (--install runs as root). The output
#          dir advice no longer assumes a cloud-synced working copy.
#          2.2 - --install refuses to wire sudo_local unless the module's
#          directory chain (/usr … /usr/local/lib/pam and the module) is
#          root-owned, not group/other-writable and symlink-free
#          (pam-lib.sh serberus_pam_module_path_is_safe) — an Intel Homebrew
#          /usr/local/lib lets its owner swap the module sudo loads as root.
#          System-only PATH and absolute tool paths (--install runs as root).
#          Comments: the sudo_local control is `requisite`.
#          2.1 - Module relocated to /usr/local/lib/pam/pam_serberus.so
#          (/usr/lib/pam is on the sealed read-only system snapshot on
#          macOS 11+ — nothing can write there); sudo_local now wires the
#          module by ABSOLUTE path; --install runs the same break-glass
#          preflight as the production pkg (enforce-or-absent config with no
#          bypass -> refuse; --force overrides) and warns when the daemon
#          job is not loaded; do_build verifies both lipo slices.
#          2.0 - Universal (arm64 + x86_64) build of pam_serberus.c +
#          pam_config.c; output moved outside any cloud-synced folder (a sync
#          provider's FinderInfo xattrs invalidate signatures -> dlopen
#          failure -> required-module sudo brick); xattr -c before codesign; --install refuses
#          real-identity signing under sudo (root cannot open the login
#          keychain) and hard-fails on arch mismatch with sudo's arch.
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

# System directories only: --install runs as root, and /usr/local/bin can be
# user-writable.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

# Absolute tool paths: nothing is resolved via PATH.
readonly AWK="/usr/bin/awk"
readonly BASENAME="/usr/bin/basename"
readonly CHMOD="/bin/chmod"
readonly CHOWN="/usr/sbin/chown"
readonly CLANG="/usr/bin/clang"
readonly CODESIGN="/usr/bin/codesign"
readonly CP="/bin/cp"
readonly DIRNAME="/usr/bin/dirname"
readonly DSCL="/usr/bin/dscl"
readonly GREP="/usr/bin/grep"
readonly ID="/usr/bin/id"
readonly LAUNCHCTL="/bin/launchctl"
readonly LIPO="/usr/bin/lipo"
readonly MKDIR="/bin/mkdir"
readonly MKTEMP="/usr/bin/mktemp"
readonly MV="/bin/mv"
readonly RM="/bin/rm"
readonly UNAME="/usr/bin/uname"
readonly XATTR="/usr/bin/xattr"

readonly ORG_NAME="Serberus"
readonly ORG_PLIST_DOMAIN="com.herojoneslabs.serberus"

readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="2.5"
readonly SCRIPT_DIR=$(cd "$("${DIRNAME}" "$0")" && pwd)

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

readonly SOURCES=(
    "${SCRIPT_DIR}/../Sources/pam_serberus/pam_serberus.c"
    "${SCRIPT_DIR}/../Sources/pam_serberus/pam_config.c"
    "${SCRIPT_DIR}/../Sources/pam_serberus/sudo_args.c"
)
readonly SHIM_INCLUDE="${SCRIPT_DIR}/../Sources/SerberusXPCShim/include"

# Build outside any cloud-synced folder: a sync provider can stamp a
# com.apple.FinderInfo xattr onto files under it, which invalidates the
# signature -> dlopen fails -> sudo is bricked for EVERYONE (pam_serberus is
# wired `requisite`, and bypass users never get evaluated when the module
# cannot even load). Under sudo, default to the invoking user's home so
# `--build` (as user) and `sudo --install` agree on the artifact path.
resolve_default_live_dir() {
    local sudo_home=""
    if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]
    then
        sudo_home=$("${DSCL}" . -read "/Users/${SUDO_USER}" NFSHomeDirectory 2>/dev/null \
            | "${AWK}" '{print $2}') || sudo_home=""
    fi
    if [[ -n "${sudo_home}" && -d "${sudo_home}" ]]
    then
        printf '%s/serberus-live' "${sudo_home}"
    else
        printf '%s/serberus-live' "${HOME}"
    fi
}

readonly LIVE_DIR="${LIVE_DIR:-$(resolve_default_live_dir)}"
readonly OUTPUT="${OUTPUT:-${LIVE_DIR}/pam_serberus.so}"

# Canonical module home. /usr/lib/pam is on the sealed read-only APFS system
# snapshot (macOS 11+) — nothing, root included, can write there. The module
# therefore lives under /usr/local and sudo_local references it by ABSOLUTE
# path (libpam searches more than one directory for a bare module name, so a
# bare name does not pin which file sudo loads).
readonly INSTALL_DIR="/usr/local/lib/pam"
readonly INSTALL_PATH="${INSTALL_DIR}/pam_serberus.so"
readonly SUDO_LOCAL_SRC="${SCRIPT_DIR}/sudo_local"
readonly SUDO_LOCAL_DST="/etc/pam.d/sudo_local"
readonly PAM_SUDO="/etc/pam.d/sudo"

# Break-glass preflight inputs — the same shared library and managed config
# plist the production pkg postinstall uses.
readonly PAM_LIB_SH="${SCRIPT_DIR}/../PKG/Scripts/pam-lib.sh"
readonly MANAGED_CONFIG_PLIST="/Library/Managed Preferences/com.herojoneslabs.serberus.config.plist"
readonly DAEMON_LABEL="com.herojoneslabs.serberus.daemon"
# The installed daemon whose team the module must share: the test-ring flat
# binary, else the production bundle.
readonly DAEMON_BINARIES=(
    "/Library/PrivilegedHelperTools/com.herojoneslabs.serberus.daemon"
    "/Library/PrivilegedHelperTools/serberusd.app"
)
# Seconds to wait for a running daemon pid (plus the 8 s stability window).
readonly DAEMON_START_TIMEOUT=10

# The module's signing identifier (BundleConfig.pamBundleID). It names the
# module in codesign and notarization output; the daemon never sees it, because
# the module runs inside sudo and the XPC peer is sudo itself (validatePAMHost).
readonly PAM_IDENTIFIER="com.herojoneslabs.serberus.pam"

# Ad-hoc by default; production needs a Developer ID Application identity plus
# notarization.
readonly SIGNING_IDENTITY="${SIGNING_IDENTITY:--}"

readonly MODE="${1:---build}"

# `--install --force` skips the break-glass preflight and the running-daemon
# and same-team requirements (accepting the sudo-brick risk). The directory
# chain check is never skippable. Any other second argument is a usage error.
readonly FORCE_INSTALL="${2:-}"

# The installed daemon's Team ID (require_running_daemon).
DAEMON_TEAM=""
# The temp copy of the module while --install stages it; the EXIT trap
# removes it if the install stops before the mv.
STAGED_MODULE=""

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

# Removes a staged module left by a failed --install (never the live one).
cleanup() {
    local exit_code=$?
    if [[ -n "${STAGED_MODULE}" && -f "${STAGED_MODULE}" && ! -L "${STAGED_MODULE}" ]]
    then
        "${RM}" -f "${STAGED_MODULE}"
    fi
    exit "${exit_code}"
}
trap cleanup EXIT

require_root() {
    if [[ "$("${ID}" -u)" -ne 0 ]]
    then
        log_error "Must run as root (use sudo) for --install"
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

# The machine's native arch as a module-arch name (sudo runs arm64e on Apple
# silicon; a plain arm64 module slice satisfies it).
native_module_arch() {
    local machine
    machine=$("${UNAME}" -m)
    case "${machine}" in
        arm64|arm64e) printf 'arm64' ;;
        *)            printf '%s' "${machine}" ;;
    esac
}

# Hard-fails unless the built module carries the arch sudo will demand on this
# Mac. A wrong-arch module means dlopen fails inside the `requisite` PAM line
# -> sudo bricked for everyone, including bypass users.
verify_module_arch() {
    local module="$1"
    local needed
    needed=$(native_module_arch)
    local archs
    if ! archs=$("${LIPO}" -archs "${module}" 2>/dev/null)
    then
        log_error "Cannot read architectures of ${module} (lipo failed)"
        exit 1
    fi
    local found=""
    local arch
    for arch in ${archs}
    do
        if [[ "${arch}" == "${needed}" ]]
        then
            found="yes"
        fi
    done
    if [[ -z "${found}" ]]
    then
        log_error "Arch mismatch: module has [${archs}] but sudo on this Mac needs ${needed}."
        log_error "Refusing to install — a wrong-arch PAM module wired into sudo bricks it."
        exit 1
    fi
    log_info "Arch check OK: module [${archs}] covers native ${needed}"
}

do_build() {
    # Under sudo the default output is the invoking user's ~/serberus-live:
    # building there as root leaves root-owned files the next --build (as the
    # user) cannot overwrite, and root cannot use the login keychain anyway.
    if [[ "$("${ID}" -u)" -eq 0 && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]
    then
        log_error "Refusing to build as root under sudo (it would write root-owned files into"
        log_error "${SUDO_USER}'s home, and root cannot use the login keychain). Build as yourself:"
        log_error "  SIGNING_IDENTITY=\"Apple Development: Your Name (TEAMID)\" ./Support/${SCRIPT_NAME} --build"
        exit 1
    fi
    "${MKDIR}" -p "$("${DIRNAME}" "${OUTPUT}")"

    log_info "Compiling ${SOURCES[*]}"
    "${CLANG}" -arch arm64 -arch x86_64 -Wall -Wextra -O2 \
        -bundle \
        -o "${OUTPUT}" \
        "${SOURCES[@]}" \
        -I"${SHIM_INCLUDE}" \
        -framework CoreFoundation \
        -framework Security \
        -lpam

    # A sync provider (or a Finder copy) may have stamped xattrs onto the output dir's
    # older artifact; strip them BEFORE signing or the signature is dead on
    # arrival (com.apple.FinderInfo invalidates it -> dlopen failure).
    "${XATTR}" -c "${OUTPUT}" 2>/dev/null || true

    # A flat .so otherwise defaults its signing identifier to the filename
    # ("pam_serberus"); give it the stable BundleConfig.pamBundleID instead so
    # every build is identified the same way. The daemon doesn't check it: the
    # module runs inside sudo, and the daemon validates sudo as the peer.
    log_info "Signing with identity '${SIGNING_IDENTITY}' (identifier ${PAM_IDENTIFIER})"
    "${CODESIGN}" --force --sign "${SIGNING_IDENTITY}" --identifier "${PAM_IDENTIFIER}" \
        --options runtime "${OUTPUT}"

    if [[ "${SIGNING_IDENTITY}" != "-" ]] && ! "${CODESIGN}" --verify --strict "${OUTPUT}"
    then
        log_error "Signature verification failed for ${OUTPUT} (stray xattr?)"
        exit 1
    fi

    # Universal check: BOTH slices must be present. A thin module dlopen-fails
    # inside the `requisite` PAM line on the missing arch -> sudo bricked there.
    local archs
    if ! archs=$("${LIPO}" -archs "${OUTPUT}" 2>/dev/null)
    then
        log_error "Cannot read architectures of ${OUTPUT} (lipo failed)"
        exit 1
    fi
    local needed
    for needed in arm64 x86_64
    do
        case " ${archs} " in
            *" ${needed} "*)
                ;;
            *)
                log_error "Universal check failed: ${OUTPUT} is missing the ${needed} slice (has: [${archs}])"
                exit 1
                ;;
        esac
    done
    log_info "Universal check OK: [${archs}]"

    log_info "Built ${OUTPUT}"
}

# Break-glass preflight (mirrors the production pkg postinstall): pam_serberus
# is a requisite, FAIL-CLOSED module — under enforce mode every sudo not
# explicitly allowed hard-denies, and daemon-unreachable is a hard deny. The
# only safe installs are pass-through modes (audit/monitor) or a populated,
# resolvable pamBypass. Enforce-or-absent config with no bypass would brick
# sudo for everyone on this Mac, so we refuse unless --force is given.
preflight_or_refuse() {
    if [[ "${FORCE_INSTALL}" == "--force" ]]
    then
        log_warn "--force given: SKIPPING the break-glass preflight. If the effective"
        log_warn "config is enforce (or absent) with no bypass, sudo will hard-deny for"
        log_warn "every user on this Mac the moment sudo_local is wired."
        return 0
    fi

    if [[ ! -f "${PAM_LIB_SH}" ]]
    then
        log_error "Cannot run the break-glass preflight: ${PAM_LIB_SH} not found."
        log_error "Refusing to wire pam_serberus into sudo without it (fail closed)."
        log_error "Run from a full repo checkout, or override deliberately with:"
        log_error "  sudo ./Support/${SCRIPT_NAME} --install --force"
        exit 1
    fi

    if serberus_pam_preflight_break_glass "${MANAGED_CONFIG_PLIST}"
    then
        log_info "Break-glass preflight OK (pass-through mode or populated pamBypass)"
        return 0
    fi

    log_error "Break-glass preflight FAILED: the effective config is enforce (or absent)"
    log_error "with no usable pamBypass user/group. pam_serberus fails CLOSED — wiring it"
    log_error "now would hard-deny every sudo on this Mac (daemon unreachable = deny)."
    log_error "Fix one of:"
    log_error "  - deliver ${MANAGED_CONFIG_PLIST}"
    log_error "    (an MDM configuration profile) with a pamBypass users/groups list naming a REAL local admin, or"
    log_error "  - set enforcementMode to audit or monitor in that config."
    log_error "To proceed anyway (you accept the sudo-brick risk):"
    log_error "  sudo ./Support/${SCRIPT_NAME} --install --force"
    exit 1
}

# --install needs the shared library for every safety check (break-glass
# preflight, directory chain, daemon liveness, team pin, sudo_local merge).
load_pam_lib() {
    if [[ ! -f "${PAM_LIB_SH}" ]]
    then
        log_error "${PAM_LIB_SH} not found — refusing to install pam_serberus without its checks."
        log_error "Run from a full repo checkout."
        exit 1
    fi
    # shellcheck source=../PKG/Scripts/pam-lib.sh
    source "${PAM_LIB_SH}"
}

# pam_serberus hard-denies when the daemon is unreachable, and the daemon
# peer is pinned to its team: refuse unless the daemon is RUNNING (one pid
# held 8 s with no launchd restart) and carries a Team ID — --force
# overrides (dev only).
require_running_daemon() {
    local daemon
    for daemon in "${DAEMON_BINARIES[@]}"
    do
        if [[ -e "${daemon}" ]]
        then
            DAEMON_TEAM=$(serberus_codesign_team_id "${daemon}") || DAEMON_TEAM=""
            break
        fi
    done
    if [[ "${FORCE_INSTALL}" == "--force" ]]
    then
        log_warn "--force: NOT requiring a running, team-signed daemon (every non-bypass sudo"
        log_warn "hard-denies while serberusd is down, and a module from another team is rejected)."
        return 0
    fi
    if ! serberus_launchd_wait_running "${DAEMON_LABEL}" "${DAEMON_START_TIMEOUT}"
    then
        log_error "Daemon system/${DAEMON_LABEL} is not running (no stable pid). Wiring pam_serberus"
        log_error "now would deny every non-bypass sudo. Install/start serberusd first, or override:"
        log_error "  sudo ./Support/${SCRIPT_NAME} --install --force"
        exit 1
    fi
    if [[ -z "${DAEMON_TEAM}" ]]
    then
        log_error "The installed daemon carries no Team ID (ad-hoc) — the module cannot be pinned to"
        log_error "its team. Sign both with the same Apple Development identity, or override with --force."
        exit 1
    fi
}

# The module must be signed by the installed daemon's team (sudo loads it as
# root; any valid signature is not enough). --force overrides (dev only).
require_same_team_module() {
    local module="$1"
    if [[ "${FORCE_INSTALL}" == "--force" ]]
    then
        return 0
    fi
    if ! serberus_codesign_satisfies_team "${module}" "${DAEMON_TEAM}"
    then
        log_error "${module} is not validly signed by the daemon's team ${DAEMON_TEAM}."
        log_error "Build it as yourself with the daemon's identity (SIGNING_IDENTITY=… ./Support/${SCRIPT_NAME} --build),"
        log_error "or override with --force."
        exit 1
    fi
    log_info "Module signed by the daemon's team ${DAEMON_TEAM}"
}

# The DIRECTORIES above the module must be root-only BEFORE anything is
# copied or chowned inside them (missing ones are created root:wheel 0755).
require_safe_module_dir() {
    if ! serberus_pam_module_dir_is_safe "${INSTALL_PATH}"
    then
        log_error "Refusing to install into ${INSTALL_DIR}: a directory above it is not root-owned or is"
        log_error "group/other-writable (reasons above). Whoever controls it could replace the module."
        exit 1
    fi
    if [[ -L "${INSTALL_PATH}" ]]
    then
        log_error "${INSTALL_PATH} is a symlink — refusing to copy or chown through it."
        exit 1
    fi
}

# The module's directory chain (/usr, /usr/local, /usr/local/lib,
# /usr/local/lib/pam, the module) must be root-owned, not group/other-writable
# and free of symlinks before sudo_local may reference it. On an Intel Mac
# Homebrew typically owns /usr/local/lib — that is refused, not "fixed".
require_safe_module_path() {
    if ! serberus_pam_module_path_is_safe "${INSTALL_PATH}"
    then
        log_error "Refusing to wire ${INSTALL_PATH} into sudo: a directory above it (or the module)"
        log_error "is not root-owned or is group/other-writable (reasons above). Whoever controls that"
        log_error "directory could replace the module sudo loads as root."
        if [[ -f "${SUDO_LOCAL_DST}" ]] && "${GREP}" -Eq '^[^#]*pam_serberus\.so' "${SUDO_LOCAL_DST}"
        then
            log_error "${SUDO_LOCAL_DST} ALREADY references the module — fix the ownership above, or unwire it."
        fi
        exit 1
    fi
    log_info "Module directory chain OK (root-owned, not group/other-writable)"
}

# --install never builds (a build under sudo would compile as root into the
# user's home). It installs the module the developer built and signed as
# themselves. sudo's env_reset drops SIGNING_IDENTITY, so an install that
# sees "-" was either started without it or is meant to install an ad-hoc
# module; without --force that is refused up front, before any check runs or
# anything changes.
require_prebuilt_module() {
    if [[ "${SIGNING_IDENTITY}" == "-" && "${FORCE_INSTALL}" != "--force" ]]
    then
        log_error "SIGNING_IDENTITY is not set (sudo drops it), so this would install an ad-hoc module,"
        log_error "which the installed daemon's team check refuses. Build as yourself, then pass the"
        log_error "same identity through sudo:"
        log_error "  SIGNING_IDENTITY=\"Apple Development: Your Name (TEAMID)\" ./Support/${SCRIPT_NAME} --build"
        log_error "  sudo SIGNING_IDENTITY=\"Apple Development: Your Name (TEAMID)\" ./Support/${SCRIPT_NAME} --install"
        log_error "Use the identity the installed daemon is signed with. If you built with LIVE_DIR or"
        log_error "OUTPUT set, pass that through sudo as well. --force installs an ad-hoc module anyway."
        exit 1
    fi
    if [[ -L "${OUTPUT}" || ! -f "${OUTPUT}" ]]
    then
        log_error "No prebuilt module at ${OUTPUT} (or it is a symlink). --install does not build."
        log_error "Build it as the logged-in user first:"
        log_error "  SIGNING_IDENTITY=\"Apple Development: Your Name (TEAMID)\" ./Support/${SCRIPT_NAME} --build"
        exit 1
    fi
}

do_install() {
    require_root
    require_prebuilt_module
    load_pam_lib

    # Refuse to brick a dev Mac: the module install itself can activate
    # enforcement (sudo_local may already be wired from a previous run), so
    # the preflight and the daemon checks run BEFORE any system modification.
    preflight_or_refuse
    require_running_daemon

    # Never signed here: `sudo codesign` cannot build an Apple Development /
    # Developer ID chain (those certs live in the logged-in user's LOGIN
    # keychain, which root cannot open). The prebuilt artifact is checked.
    log_info "Using prebuilt module ${OUTPUT} (not re-signing under sudo)"
    if ! "${CODESIGN}" --verify --strict "${OUTPUT}"
    then
        log_error "Prebuilt module fails signature verification — rebuild as the user and retry."
        exit 1
    fi

    verify_module_arch "${OUTPUT}"
    require_same_team_module "${OUTPUT}"

    # Directory chain FIRST (creates a missing /usr/local/lib/pam root:wheel
    # 0755), then copy, then lock the module itself (-h: never through a link).
    require_safe_module_dir
    log_info "Installing to ${INSTALL_PATH}"
    # Copy to a temp file in the SAME directory, lock it there, then mv it over
    # the live module: the rename is atomic, so a sudo running meanwhile loads
    # either the old module or the new one, never a partial file.
    local staged
    staged=$("${MKTEMP}" "${INSTALL_DIR}/.pam_serberus.XXXXXX")
    STAGED_MODULE="${staged}"
    "${CP}" "${OUTPUT}" "${staged}"
    if ! serberus_pam_lock_module "${staged}"
    then
        log_error "Could not lock the staged module to root:wheel 0444"
        exit 1
    fi
    # The prebuilt file sits in a user-writable directory and could have been
    # swapped since it was checked: verify the root-owned copy that will go
    # live.
    if ! "${CODESIGN}" --verify --strict "${staged}"
    then
        log_error "The staged copy of the module fails signature verification — not installing it."
        exit 1
    fi
    verify_module_arch "${staged}"
    require_same_team_module "${staged}"
    if ! "${MV}" -f "${staged}" "${INSTALL_PATH}"
    then
        log_error "Could not move the new module into place at ${INSTALL_PATH}"
        exit 1
    fi
    STAGED_MODULE=""

    # sudo dlopens the module as root on every authentication: refuse to wire
    # (or leave wired) a module whose directory chain someone else can change.
    # Not skippable with --force.
    require_safe_module_path

    # OpenPAM loads "<module>.2" in preference to the module itself, so a
    # stray pam_serberus.so.2 would be what sudo runs.
    local versioned
    versioned=$(serberus_pam_remove_versioned_module) || versioned="FAILED"
    if [[ "${versioned}" == "FAILED" ]]
    then
        log_error "Could not remove ${SERBERUS_PAM_MODULE_VERSIONED_PATH} (OpenPAM would load it instead of the module)."
        exit 1
    elif [[ "${versioned}" == "removed" ]]
    then
        log_info "Removed a stray ${SERBERUS_PAM_MODULE_VERSIONED_PATH}"
    fi

    if ! serberus_pam_sudo_includes_sudo_local "${PAM_SUDO}"
    then
        log_warn "!!! ${PAM_SUDO} does not include sudo_local as its first auth line — pam_serberus"
        log_warn "!!! will not gate sudo (the daemon reports degraded pam_not_wired). Not editing Apple's file."
    fi

    # ! -e is also true for a DANGLING symlink, which the merge replaces.
    if [[ ! -e "${SUDO_LOCAL_DST}" ]]
    then
        # Last look before sudo is gated: still the daemon process that
        # require_running_daemon confirmed up.
        if [[ "${FORCE_INSTALL}" != "--force" ]] && ! serberus_launchd_pid_unchanged "${DAEMON_LABEL}"
        then
            log_error "The daemon restarted after it was confirmed up — NOT creating ${SUDO_LOCAL_DST}."
            exit 1
        fi
        # Created through pam-lib: temp file at 0444, atomic mv, and a dangling
        # symlink is replaced rather than written through. Content comes from
        # Support/sudo_local when it is canonical.
        local merge_result
        merge_result=$(serberus_pam_merge_sudo_local "${SUDO_LOCAL_DST}" "${SUDO_LOCAL_SRC}") \
            || merge_result="FAILED"
        log_info "Creating ${SUDO_LOCAL_DST} (create-if-absent): ${merge_result}"
        if ! "${CHOWN}" -h root:wheel "${SUDO_LOCAL_DST}" || ! "${CHMOD}" -h 444 "${SUDO_LOCAL_DST}"
        then
            log_error "Could not set root:wheel 0444 on ${SUDO_LOCAL_DST}"
            exit 1
        fi
    else
        log_info "${SUDO_LOCAL_DST} already exists — leaving untouched"
        # A legacy BARE-NAME module line: libpam searches more than one
        # directory for a bare name, so it does not pin which file sudo loads,
        # and the daemon never counts it as wired.
        if "${GREP}" -Eq '^[^#]*[[:space:]]pam_serberus\.so([[:space:]]|$)' "${SUDO_LOCAL_DST}"
        then
            log_warn "Legacy bare-name pam_serberus.so line found in ${SUDO_LOCAL_DST}."
            log_warn "libpam searches more than one directory for a bare name, so it does not pin"
            log_warn "which file sudo loads, and the daemon never counts it as wired. Replace it with:"
            log_warn "  auth       requisite      ${INSTALL_PATH} # serberus-managed"
        elif ! "${GREP}" -Eq '^[^#]*pam_serberus\.so' "${SUDO_LOCAL_DST}"
        then
            log_info "No active pam_serberus line in ${SUDO_LOCAL_DST} — module installed but"
            log_info "not wired. To wire it, add as the FIRST auth line:"
            log_info "  auth       requisite      ${INSTALL_PATH} # serberus-managed"
        fi
    fi

    log_info "Install complete. Test with: sudo echo serberus-test"
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

if [[ -n "${FORCE_INSTALL}" ]]
then
    if [[ "${MODE}" != "--install" || "${FORCE_INSTALL}" != "--force" ]]
    then
        printf 'Usage: %s [--build|--install [--force]]\n' "${SCRIPT_NAME}" >&2
        exit 1
    fi
fi

case "${MODE}" in
    --build)
        do_build
        ;;
    --install)
        do_install
        ;;
    *)
        printf 'Usage: %s [--build|--install [--force]]\n' "${SCRIPT_NAME}" >&2
        exit 1
        ;;
esac

log_info "${SCRIPT_NAME} completed successfully"

###########################################################
################## End Script Block #######################
###########################################################
