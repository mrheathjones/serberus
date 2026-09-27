#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: build-core-test-pkg.sh
# Author: Heath Jones
# Date: 2026-07-13
# Modified: 2026-09-26
# Purpose: Build the COMBINED TEST-RING Serberus "Core" PKG for Jamf policy
#          deployment — the daemon, the pam_serberus module, the
#          SerberusAuth authorization plugin and the serberus CLI in ONE
#          installer (SerberusCore-<version>.pkg). This is ADDITIVE: it reuses the
#          proven logic of the two individual test-pkg builders rather than
#          diverging from them —
#            - daemon: build/plist/sign/legacy-uninstall/authdb-restore logic
#              mirrors PKG/build-test-pkg.sh
#            - PAM module: built via Support/build-pam.sh --build (single source
#              of truth), identifier/arch re-verified like PKG/build-pam-test-pkg.sh
#            - sudo_local merge/removal, sudoers-dropin removal and break-glass
#              preflight are SOURCED from PKG/Scripts/pam-lib.sh (never
#              reimplemented)
#          The combined installer enforces a strict, safety-critical order.
#          pam_serberus is a `requisite` sudo module that FAILS CLOSED: if it is
#          wired into sudo while the daemon is down, sudo bricks. Therefore:
#            PREINSTALL  — (a) break-glass PREFLIGHT: READ-ONLY; reports the
#                          effective config, ABORTS in the ONE genuine-brick case
#                          (config PRESENT + enforce + a non-empty pamBypass in
#                          which no entry resolves to an account, whether or not
#                          a last-known-good snapshot exists), and WARNS
#                          + PROCEEDS otherwise — an un-configured Mac installs
#                          INERT (awaitingConfig: PAM passes sudo through, nothing
#                          is mutated) and a de-configured one falls back to the
#                          last-known-good snapshot with its break-glass intact,
#                          so the Jamf enrollment race (pkg before profile) is
#                          survivable instead of fatal;
#                          (b) uninstall any legacy daemon + revert its authdb;
#                          (c) on an upgrade, TEARDOWN-FIRST: sudoers drop-in ->
#                          unwire sudo_local -> bootout (label left enabled;
#                          waits until launchd drops the job) -> drop-in ->
#                          demote JIT -> drop-in, so a failed upgrade falls back to
#                          native sudo, never to blanket denial.
#                          NO daemon-loaded gate here — the daemon installs THIS run.
#            POSTINSTALL — (1) fix ownership/modes (module directory chain
#                          checked BEFORE the module is touched), (2) enable +
#                          bootstrap the DAEMON and VERIFY it is UP (one stable
#                          pid for 8 s with no launchd restart + a healthy `serberus status`), (3)
#                          VALIDATE the PAM module and the SerberusAuth plugin
#                          (both signed by the daemon's team — a daemon with no
#                          Team ID is refused — native arch, root-only
#                          directory chain), (4) ONLY THEN wire
#                          /etc/pam.d/sudo_local. Any failure — including an
#                          unexpected exit, via the EXIT trap — => remove the
#                          sudoers drop-in, unwire sudo_local (a SURVIVING
#                          line keeps the daemon enabled and running, exit 1),
#                          disable + bootout, demote JIT
#                          admins, restore the authdb, exit 1 — sudo is never
#                          left wired to a module without a working daemon,
#                          and a reboot cannot resurrect an ungated one.
#            UNINSTALL   — sudoers drop-in, sudo_local, disable + bootout,
#                          demote JIT, restore authdb, plugin (only if the
#                          restore succeeded), files, then forget + cleanup.
#          The standalone Serberus Intel app is retired (it is now the Intel
#          tab in Serberus Sentinel, shipped by build-sentinel-app-pkg.sh); the
#          preinstall and the uninstall helper remove a previously installed
#          /Applications/SerberusIntel.app. Production endpoints use
#          build-pkg.sh (notarized full payload).
#          The receipt identifier stays com.herojoneslabs.serberus.sentineltestpkg
#          (upgrade compatibility); the preinstall and the uninstall helper
#          also forget the older …coretestpkg receipt.
# Version: 1.8 - Generated scripts: the uninstall helper's --purge removes
#          data only (apps and other helpers stay) and gates the plugin on
#          pam-lib.sh 1.8's records-and-rights check (pending .json,
#          .branches or .projection records, composition rows invoking
#          SerberusAuth, rights delegating to them; never a comment), and
#          with no daemon only those records mean something to restore
#          (a .standin does not); the preinstall writes the
#          upgrade marker for the new daemon and logs the SCRIPT_VERSION its
#          header states; teardowns wait ExitTimeOut plus 5 s after a bootout.
#          1.7 - version.plist carries the PRODUCT version (the repository's
#          VERSION file) in daemonVersion / pamModuleVersion / cliVersion, the
#          package number as packageVersion, and installTeamID (the signing
#          team). Generated scripts: teardowns wait for launchd to drop the
#          job after a bootout before any one-shot and pin the daemon to the
#          recorded team; the disable comes after the unwire; the preinstall
#          re-checks the drop-in right after the bootout and runs the old
#          daemon's --demote-jit whenever its binary exists; the uninstall
#          helper sources pam-lib.sh only through a root-only path chain and
#          exits 1 when the drop-in survives; a stray pam_serberus.so.2 is
#          removed; the state.plist mark is retaken before `kickstart -k`.
#          1.6 - Generated scripts: the daemon is trusted (and executed) only
#          through pam-lib serberus_daemon_trusted; the preinstall demotes
#          JIT admins with the OLD daemon before the upgrade bootout and
#          gates the legacy com.heath restore on the same check; stricter
#          liveness (bootstrap mark, 8 s window, no restart after the
#          kickstart, fresh state.plist, pid re-read before wiring); a
#          surviving sudoers drop-in stops every teardown before sudo_local
#          is unwired; --demote-jit exit 3 is informational; each
#          chown/chmod is checked; neutral wording in the history notes.
#          1.5 - Renamed from build-sentinel-test-pkg.sh; output is now
#          SerberusCore-<version>.pkg (receipt identifier unchanged).
#          Generated scripts: umask 022; EXIT traps (postinstall: an
#          unexpected exit runs the abort path; preinstall/uninstall helper:
#          a wired sudo_local keeps its daemon enabled); teardown-first
#          upgrade in the preinstall; the abort keeps the daemon running when
#          an active pam_serberus line survives the unwire; stable-pid +
#          `serberus status` liveness; module directory chain checked before
#          chown/chmod (-h, no symlinks); no ad-hoc fallback — the daemon must
#          carry a Team ID and pins the module AND the SerberusAuth plugin;
#          bounded one-shots (SERBERUS_DEV_KEY_FALLBACK exported, as the
#          LaunchDaemon sets it); a daemon without a Team ID is never
#          executed by the abort path; plugin + backups removed only when the
#          live AuthorizationDB no longer references Serberus; require the
#          boot volume ($3). Builder: absolute tool paths; the payload's
#          bundles are pinned non-relocatable (component plist).
#          1.4 - Generated scripts: system-only PATH and absolute tools; the
#          postinstall enables the label before bootstrap, waits for a running
#          pid, requires the module to be signed by the daemon's team and to
#          sit in a root-only directory chain, and every abort disables +
#          boots out the daemon and removes the sudoers drop-in; the uninstall
#          helper follows the new teardown order (disable -> drop-in ->
#          unwire -> bootout -> demote JIT -> restore -> plugin only if
#          restored -> files). SCRIPT_VERSION now tracks this history.
#          1.3 - Shipped Serberus Intel in the payload (since retired: the
#          app is now the Sentinel window's Intel tab and is no longer built
#          or shipped here).
#          1.2 - Preinstall break-glass preflight ABORTS again on the genuine
#          brick (config present + enforce + unresolvable pamBypass + no
#          last-known-good) and WARNS + PROCEEDS otherwise; kill switch is now
#          fully inert (pam PAM_IGNORE + daemon clears profiles) and startup
#          restores the authdb identically to reload.
#          1.1 - Preinstall break-glass preflight relaxed from ABORT to WARN +
#          PROCEED (awaiting-config bootstrap + last-known-good fallback).
#          1.0 - Initial Script
#
######################################################################
############## End Script Information Block ##########################
######################################################################

# Usage (run as the LOGGED-IN USER, never sudo — codesign needs the Apple
# Development chain in your login keychain):
#
#   SIGNING_IDENTITY=<Apple Development cert hash or name> ./PKG/build-core-test-pkg.sh
#
# Optional env:
#   INSTALLER_IDENTITY  "Developer ID Installer: Your Name (YOURTEAMID)"
#                       — signs the .pkg (recommended; unsigned still installs
#                       via Jamf *policy*, but PreStage/InstallApplication and
#                       double-click installs require a signed pkg)
#   DAEMON_BIN          path to a prebuilt Release serberusd (skips xcodebuild)
#   PKG_VERSION         package version (see the default below ->
#                       SerberusCore-<version>.pkg)
#   SERBERUS_DEV_KEY_FALLBACK           baked into the LaunchDaemon env (default 1)
#   SERBERUS_DEV_SKIP_SENTINEL_ENTITLEMENT baked into the LaunchDaemon env (default 1)
#
# Modes:
#   (default / --build)       build the pkg
#   --self-test               run PKG/tests/test-sentinel-lib.sh and exit
#   --emit-scripts <dir>      write the generated scripts + payload helpers to
#                             <dir> without building (used by the test harness
#                             for bash -n + ordering validation)
#
# ORDERING: scoping the break-glass config profile
# (Support/sample-profiles/serberus-config-breakglass.mobileconfig, domain
# com.herojoneslabs.serberus.config: enforcementMode and a populated pamBypass)
# BEFORE this pkg is still the intended sequence — but it is no longer a hard
# requirement. Installed on a Mac with NO usable config (and no snapshot),
# Serberus stays INERT (state awaitingConfig; sudo passes through natively; no
# authdb rules, no sudoers drop-in) and adopts the profile on its next ~30s poll,
# with no re-install — so the preinstall WARNS + proceeds rather than aborting.
# The preinstall aborts ONLY on the genuine brick (a config is PRESENT and
# enforce-shaped with a pamBypass that resolves to no account AND no
# last-known-good snapshot to fall back to). That is what makes the Jamf
# enrollment race (APNS delivers the profile after the policy runs the pkg)
# survivable while still refusing a config that would deny every user. The daemon
# does NOT need to be pre-installed either: it is part of this pkg, so the
# daemon-loaded gate lives in the POSTINSTALL.
#
# Deploy: upload the built pkg to Jamf, install via policy. Teardown on the
# test machine (or via a Jamf teardown policy):
#   sudo "/Library/Application Support/Serberus/uninstall-serberus-sentinel-test.sh" [--purge]

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
readonly GREP="/usr/bin/grep"
readonly ID="/usr/bin/id"
# lipo ships with the Xcode tools; /usr/bin/lipo is the xcrun shim.
readonly LIPO="/usr/bin/lipo"
readonly MKDIR="/bin/mkdir"
readonly MKTEMP="/usr/bin/mktemp"
readonly PKGBUILD="/usr/bin/pkgbuild"
readonly PKGUTIL="/usr/sbin/pkgutil"
readonly PLUTIL="/usr/bin/plutil"
readonly PRODUCTSIGN="/usr/bin/productsign"
readonly RM="/bin/rm"
readonly XATTR="/usr/bin/xattr"
# The xcodebuild shim in /usr/bin resolves the selected Xcode.
readonly XCODEBUILD="/usr/bin/xcodebuild"
readonly PLIST_BUDDY="/usr/libexec/PlistBuddy"

readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.8"
readonly SCRIPT_DIR=$(cd "$("${DIRNAME}" "$0")" && pwd)
readonly REPO_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

readonly BUNDLE_ID="com.herojoneslabs.serberus.daemon"
readonly DAEMON_LABEL="${BUNDLE_ID}"
readonly INSTALL_BINARY_PATH="/Library/PrivilegedHelperTools/${BUNDLE_ID}"
readonly ORG_PLIST_DOMAIN="com.herojoneslabs.serberus"
readonly SUPPORT_DIR="/Library/Application Support/Serberus"
readonly LOG_DIR="/Library/Logs/Serberus"
readonly UNINSTALL_HELPER_NAME="uninstall-serberus-sentinel-test.sh"
readonly PAM_LIB_NAME="pam-lib.sh"
readonly PAM_LIB_SRC="${SCRIPT_DIR}/Scripts/${PAM_LIB_NAME}"

# BundleConfig.pamBundleID. It names the module in codesign/notarization
# output; the daemon never checks it — the module runs inside sudo, and the
# daemon validates sudo itself as the XPC caller. Kept stable (and verified
# below) so every build is identified the same way.
readonly PAM_IDENTIFIER="com.herojoneslabs.serberus.pam"

# Distinct identifier from the daemon test pkg (…serberus.testpkg), the PAM
# test pkg (…serberus.pamtestpkg) and the production pkg (…serberus.pkg) so
# receipts never masquerade as any of them. RENAMED from …coretestpkg with the
# Sentinel repackage: the preinstall forgets the old …coretestpkg
# receipt on upgrade so a device that carried the old "Core" pkg ends up with a
# single receipt. KEPT unchanged when the pkg FILE was renamed to
# SerberusCore-<version>.pkg: installed Macs upgrade in place by identifier.
readonly PKG_IDENTIFIER="com.herojoneslabs.serberus.sentineltestpkg"
readonly PKG_VERSION="${PKG_VERSION:-3.8}"
# The PRODUCT version (the repository's VERSION file). PKG_VERSION above only
# numbers this test package and its receipt; version.plist carries this one,
# so `serberus version`, `serberus status` and the version EA report the
# product, not the package.
# shellcheck source=../Support/version-lib.sh
source "${REPO_DIR}/Support/version-lib.sh"
PRODUCT_VERSION=$(serberus_product_version "${REPO_DIR}") || PRODUCT_VERSION=""
readonly PRODUCT_VERSION

readonly MODE="${1:---build}"
readonly EMIT_DIR="${2:-}"

# --emit-scripts redirects all generated output into the caller's directory; a
# normal build works under PKG/build-test/core — its OWN subdir of build-test,
# so `rm -rf` here can never clobber a sibling daemon-only (build-test/) or
# PAM-only (build-test/pam/) test pkg, exactly how build-pam-test-pkg.sh scopes
# build-test/pam/.
if [[ "${MODE}" == "--emit-scripts" && -n "${EMIT_DIR}" ]]
then
    readonly BUILD_DIR="${EMIT_DIR}"
    # Emit mode never signs anything, so the payload can live beside the
    # scripts where the test harness expects to find it.
    readonly STAGING_DIR="${EMIT_DIR}"
else
    readonly BUILD_DIR="${SCRIPT_DIR}/build-test/core"
    # The PAYLOAD is staged outside any cloud-synced folder; only the finished
    # .pkg lands in BUILD_DIR. A sync provider can stamp com.apple.FinderInfo
    # onto everything it manages — continuously, re-adding it within seconds
    # of any `xattr -c` — and codesign rejects that xattr outright ("resource
    # fork, Finder information, or similar detritus not allowed"), so a bundle
    # signed in such a tree cannot pass --verify --strict and AMFI then refuses
    # to spawn it. The daemon and the .so survive it (their signatures are
    # embedded in the Mach-O), but SerberusAuth.bundle is a BUNDLE whose
    # signature seals its resource tree. Same reasoning, and same fix, as
    # build-apps.sh's LIVE_DIR. ~/Library/Caches is never synced and needs no
    # privilege.
    readonly STAGING_DIR="${SERBERUS_PKG_STAGING:-${HOME}/Library/Caches/com.herojoneslabs.serberus/pkg-core}"
fi
readonly PAYLOAD_DIR="${STAGING_DIR}/payload"
readonly SCRIPTS_DIR="${STAGING_DIR}/scripts"
# The CORE component: daemon + pam_serberus + SerberusAuth + CLI — the half
# that gates sudo/authURI. (Shipped as SerberusSentinelAgent-<v>.pkg until the
# rename; the name now says what it installs. The GUI apps are the separate
# SerberusSentinelApp pkg.)
readonly OUTPUT_PKG="${BUILD_DIR}/SerberusCore-${PKG_VERSION}.pkg"
readonly SIGNED_PKG="${BUILD_DIR}/SerberusCore-${PKG_VERSION}-signed.pkg"
# pkgbuild --analyze output, edited so no bundle in the payload is relocatable.
readonly COMPONENT_PLIST="${STAGING_DIR}/component.plist"

# Daemon artifact. Built by build_daemon() unless DAEMON_BIN points elsewhere.
readonly XCODE_PRODUCTS="${REPO_DIR}/.build/xcode/Build/Products/Release"
readonly DAEMON_BIN_OVERRIDE="${DAEMON_BIN:-}"
readonly DAEMON_BIN="${DAEMON_BIN:-${XCODE_PRODUCTS}/serberusd}"

# CLI artifact (`serberus`). Built alongside the daemon and installed to
# /usr/local/bin/serberus so `serberus status` / `serberus version` are
# available for on-endpoint triage wherever the daemon is deployed. Its flat
# Mach-O is signed with an explicit --identifier (flat binaries otherwise derive
# it from the filename).
readonly CLI_BIN="${CLI_BIN:-${XCODE_PRODUCTS}/serberus}"
readonly CLI_INSTALL_PATH="/usr/local/bin/serberus"
readonly CLI_IDENTIFIER="com.herojoneslabs.serberus.cli"

# PAM module built by Support/build-pam.sh --build (single source of truth for
# the clang + codesign invocation) with OUTPUT pointed here.
readonly PAM_BUILD_SCRIPT="${REPO_DIR}/Support/build-pam.sh"
# Intermediate, staged with the payload (outside any cloud-synced folder for
# --build): it is signed here and codesign --verify --strict is run against
# it, so it must not sit anywhere a sync provider can stamp
# com.apple.FinderInfo on it.
readonly PAM_SO="${STAGING_DIR}/pam_serberus.so"

# The authorization mechanism bundle. Per-app identity rules reference
# "SerberusAuth:identity" from auth.db BY NAME, so the bundle filename and the
# mechanism id are FROZEN: a rename would leave every deployed right pointing
# at a mechanism that no longer exists. Installed root-owned under
# /Library/Security/SecurityAgentPlugins.
readonly AUTH_PLUGIN_NAME="SerberusAuth.bundle"
readonly AUTH_PLUGIN_DIR="/Library/Security/SecurityAgentPlugins"
readonly AUTH_PLUGIN_BUILT="${REPO_DIR}/.build/xcode/Build/Products/Release/${AUTH_PLUGIN_NAME}"

# NOTE: the standalone Serberus Intel app was RETIRED — its
# diagnostics UI is now the Serberus Sentinel window's Intel tab. This pkg no
# longer builds or ships SerberusIntel.app; the preinstall REMOVES any
# previously-installed /Applications/SerberusIntel.app so an upgrade cleans it
# up. The path constant lives only in the generated preinstall/uninstall.

# Signing inputs. SIGNING_IDENTITY is REQUIRED and must be a REAL Apple
# Development identity (hash or name): the postinstall requires the PAM module
# to be signed by the same team as the daemon (an ad-hoc module has no team),
# and the daemon pins Team ID on its app callers; un-notarized Developer ID +
# Hardened Runtime is AMFI-killed at launch, and this test pkg never
# notarizes.
readonly SIGNING_IDENTITY="${SIGNING_IDENTITY:-}"
readonly INSTALLER_IDENTITY="${INSTALLER_IDENTITY:-}"

# Dev escape hatches baked into the LaunchDaemon EnvironmentVariables. This is
# a TEST-RING pkg, so BOTH the on-disk HMAC key fallback and the Sentinel
# entitlement skip default ON (the combined pkg is used for end-to-end prompt +
# sudo testing with a locally-signed Sentinel). Both are unset in production.
readonly SERBERUS_DEV_KEY_FALLBACK="${SERBERUS_DEV_KEY_FALLBACK:-1}"
readonly SERBERUS_DEV_SKIP_SENTINEL_ENTITLEMENT="${SERBERUS_DEV_SKIP_SENTINEL_ENTITLEMENT:-1}"

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
        log_error "cert hash or name) — the postinstall requires the module and daemon to share a team."
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

    if [[ -z "${PRODUCT_VERSION}" ]]
    then
        log_error "${REPO_DIR}/VERSION is missing or not MAJOR.MINOR.PATCH."
        exit 1
    fi
}

# Daemon build — mirrors PKG/build-test-pkg.sh build_daemon(). There is no
# separate reusable daemon sub-script (unlike PAM's Support/build-pam.sh), so
# the xcodebuild invocation is replicated faithfully.
build_daemon() {
    if [[ -n "${DAEMON_BIN_OVERRIDE}" ]]
    then
        log_info "Using prebuilt daemon binary: ${DAEMON_BIN}"
        if [[ ! -f "${DAEMON_BIN}" ]]
        then
            log_error "DAEMON_BIN not found: ${DAEMON_BIN}"
            exit 1
        fi
        return 0
    fi

    log_info "Building serberusd + serberus CLI + SerberusAuth (Release) from Serberus.xcodeproj"
    local scheme
    for scheme in serberusd serberus SerberusAuth
    do
        "${XCODEBUILD}" \
            -project "${REPO_DIR}/Serberus.xcodeproj" \
            -scheme "${scheme}" \
            -configuration Release \
            -derivedDataPath "${REPO_DIR}/.build/xcode" \
            CODE_SIGNING_ALLOWED=NO \
            build >/dev/null
    done

    if [[ ! -f "${DAEMON_BIN}" ]]
    then
        log_error "Build completed but daemon binary not found: ${DAEMON_BIN}"
        exit 1
    fi
    if [[ ! -f "${CLI_BIN}" ]]
    then
        log_error "Build completed but CLI binary not found: ${CLI_BIN}"
        exit 1
    fi
    if [[ ! -d "${AUTH_PLUGIN_BUILT}" ]]
    then
        log_error "Build completed but authorization plugin not found: ${AUTH_PLUGIN_BUILT}"
        exit 1
    fi
}

# (The Serberus Intel app build was removed with its retirement — see the note
# in the variables block. Its diagnostics UI now ships inside the Sentinel app.)

# PAM module build — reuse Support/build-pam.sh --build (do NOT duplicate its
# clang/codesign line). It compiles pam_serberus.c + pam_config.c universal
# (arm64 + x86_64), strips xattrs, and signs --identifier
# com.herojoneslabs.serberus.pam --options runtime. Identifier + arch are
# re-verified here exactly like PKG/build-pam-test-pkg.sh build_module().
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

write_entitlements() {
    local entitlements_file="${BUILD_DIR}/serberusd-test.entitlements"
    "${CAT}" > "${entitlements_file}" <<'ENTITLEMENTS_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
</dict>
</plist>
ENTITLEMENTS_EOF
    printf '%s' "${entitlements_file}"
}

# Mirrors PKG/build-test-pkg.sh write_daemon_plist(): the plist lands in the
# payload and the dev env vars are resolved at BUILD time.
write_daemon_plist() {
    local plist_path="${PAYLOAD_DIR}/Library/LaunchDaemons/${BUNDLE_ID}.plist"

    local env_entries=""
    local dev_var
    for dev_var in SERBERUS_DEV_SKIP_SENTINEL_ENTITLEMENT SERBERUS_DEV_KEY_FALLBACK
    do
        local value="${!dev_var:-}"
        if [[ -n "${value}" ]]
        then
            log_info "Daemon env baked into plist: ${dev_var}=${value} (dev)"
            env_entries+="        <key>${dev_var}</key>"$'\n'"        <string>${value}</string>"$'\n'
        fi
    done

    local env_block=""
    if [[ -n "${env_entries}" ]]
    then
        env_block="    <key>EnvironmentVariables</key>"$'\n'"    <dict>"$'\n'"${env_entries}    </dict>"$'\n'
    fi

    "${CAT}" > "${plist_path}" <<DAEMON_PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${DAEMON_LABEL}</string>
    <key>Program</key>
    <string>${INSTALL_BINARY_PATH}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_BINARY_PATH}</string>
    </array>
    <key>MachServices</key>
    <dict>
        <key>${BUNDLE_ID}</key>
        <true/>
    </dict>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>5</integer>
    <key>RunAtLoad</key>
    <true/>
${env_block}    <key>StandardOutPath</key>
    <string>${LOG_DIR}/daemon.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/daemon.stderr.log</string>
</dict>
</plist>
DAEMON_PLIST_EOF

    "${CHMOD}" 644 "${plist_path}"

    if ! "${PLUTIL}" -lint "${plist_path}" >/dev/null 2>&1
    then
        log_error "Generated LaunchDaemon plist failed plutil -lint: ${plist_path}"
        exit 1
    fi
}

assemble_payload() {
    log_info "Assembling combined payload at ${PAYLOAD_DIR}"
    "${MKDIR}" -p "${PAYLOAD_DIR}/Library/PrivilegedHelperTools"
    "${MKDIR}" -p "${PAYLOAD_DIR}/Library/LaunchDaemons"
    # /usr/lib/pam is on the SEALED read-only system snapshot (macOS 11+) — the
    # module MUST live under the /usr/local firmlink, and sudo_local references
    # it by absolute path (pam-lib.sh SERBERUS_PAM_MODULE_PATH).
    "${MKDIR}" -p "${PAYLOAD_DIR}/usr/local/lib/pam"
    "${MKDIR}" -p "${PAYLOAD_DIR}${SUPPORT_DIR}/authdb-backups"
    "${MKDIR}" -p "${PAYLOAD_DIR}${LOG_DIR}"

    # --- Daemon: copy, sign, verify (mirrors build-test-pkg.sh) ---
    "${CP}" "${DAEMON_BIN}" "${PAYLOAD_DIR}${INSTALL_BINARY_PATH}"
    "${CHMOD}" 755 "${PAYLOAD_DIR}${INSTALL_BINARY_PATH}"

    local entitlements_file
    entitlements_file=$(write_entitlements)
    # Explicit --identifier: for a flat binary named com.herojoneslabs.serberus.daemon
    # codesign would derive "com.herojoneslabs.serberus" (it treats ".daemon"
    # as an extension), and the PAM module and the Sentinel/Intel clients pin
    # the daemon peer to `identifier "com.herojoneslabs.serberus.daemon" and
    # anchor apple generic and certificate leaf[subject.OU] = "<team>"` — a
    # wrong identifier makes every sudo deny.
    log_info "Signing daemon binary with identity '${SIGNING_IDENTITY}' (identifier ${BUNDLE_ID})"
    if ! "${CODESIGN}" --force --sign "${SIGNING_IDENTITY}" \
        --identifier "${BUNDLE_ID}" \
        --options runtime \
        --entitlements "${entitlements_file}" \
        "${PAYLOAD_DIR}${INSTALL_BINARY_PATH}"
    then
        log_error "daemon codesign failed"
        exit 1
    fi
    local daemon_identifier
    daemon_identifier=$("${CODESIGN}" --display --verbose=2 "${PAYLOAD_DIR}${INSTALL_BINARY_PATH}" 2>&1 \
        | "${AWK}" -F= '/^Identifier=/{print $2}')
    if [[ "${daemon_identifier}" != "${BUNDLE_ID}" ]]
    then
        log_error "Daemon signing identifier is '${daemon_identifier}', expected '${BUNDLE_ID}' (peers pin it)."
        exit 1
    fi
    if ! "${CODESIGN}" --verify "${PAYLOAD_DIR}${INSTALL_BINARY_PATH}"
    then
        log_error "signed daemon binary failed codesign --verify"
        exit 1
    fi

    write_daemon_plist

    # --- PAM module: copy (locked to 444 AFTER the xattr strip, below) ---
    # NEVER ship /etc/pam.d/sudo_local as payload — the postinstall line-merges
    # it instead; a payload sudo_local would clobber user PAM config on upgrade
    # and the receipt would own it.
    "${CP}" "${PAM_SO}" "${PAYLOAD_DIR}/usr/local/lib/pam/pam_serberus.so"
    "${CHMOD}" 755 "${PAYLOAD_DIR}/usr/local/lib/pam"

    # --- Authorization mechanism bundle: copy, sign, verify. A plug-in takes
    #     NO entitlements ("entitlements only make sense on a main executable,
    #     and plug-ins are not that"); library validation in the Apple host is
    #     satisfied by the host's own clear-library-validation entitlement, not
    #     by anything on our side. Signed as a bundle (deep content), like the
    #     apps rather than the flat Mach-O binaries above. ---
    "${MKDIR}" -p "${PAYLOAD_DIR}${AUTH_PLUGIN_DIR}"
    "${CP}" -R "${AUTH_PLUGIN_BUILT}" "${PAYLOAD_DIR}${AUTH_PLUGIN_DIR}/"
    # Strip xattrs BEFORE signing, not just in the payload-wide sweep below:
    # a working copy in a cloud-synced folder can carry com.apple.FinderInfo
    # on the bundle, and codesign refuses outright ("resource fork, Finder information, or
    # similar detritus not allowed") rather than warning.
    "${XATTR}" -rc "${PAYLOAD_DIR}${AUTH_PLUGIN_DIR}/${AUTH_PLUGIN_NAME}"
    log_info "Signing authorization plugin with identity '${SIGNING_IDENTITY}'"
    if ! "${CODESIGN}" --force --options runtime --sign "${SIGNING_IDENTITY}" \
        "${PAYLOAD_DIR}${AUTH_PLUGIN_DIR}/${AUTH_PLUGIN_NAME}"
    then
        log_error "authorization plugin codesign failed"
        exit 1
    fi
    if ! "${CODESIGN}" --verify --strict "${PAYLOAD_DIR}${AUTH_PLUGIN_DIR}/${AUTH_PLUGIN_NAME}"
    then
        log_error "signed authorization plugin failed codesign --verify"
        exit 1
    fi

    # --- CLI (serberus): copy, sign, verify. Signed BEFORE the xattr strip like
    #     the daemon — a flat Mach-O carries its signature embedded, so the strip
    #     (which protects the .so) leaves the CLI signature intact. Explicit
    #     --identifier: a flat binary otherwise derives it from the filename. ---
    "${MKDIR}" -p "${PAYLOAD_DIR}/usr/local/bin"
    "${CP}" "${CLI_BIN}" "${PAYLOAD_DIR}${CLI_INSTALL_PATH}"
    "${CHMOD}" 755 "${PAYLOAD_DIR}${CLI_INSTALL_PATH}"
    log_info "Signing serberus CLI with identity '${SIGNING_IDENTITY}'"
    if ! "${CODESIGN}" --force --options runtime --sign "${SIGNING_IDENTITY}" \
        --identifier "${CLI_IDENTIFIER}" \
        "${PAYLOAD_DIR}${CLI_INSTALL_PATH}"
    then
        log_error "serberus CLI codesign failed"
        exit 1
    fi
    if ! "${CODESIGN}" --verify "${PAYLOAD_DIR}${CLI_INSTALL_PATH}"
    then
        log_error "signed serberus CLI failed codesign --verify"
        exit 1
    fi

    # (Serberus Intel app payload removed with its retirement — see the note in
    # the variables block. Its UI now ships inside the Sentinel app pkg.)

    # --- Shared pam-lib.sh (payload copy, sourced by the on-disk uninstall helper) ---
    "${CP}" "${PAM_LIB_SRC}" "${PAYLOAD_DIR}${SUPPORT_DIR}/${PAM_LIB_NAME}"
    "${CHMOD}" 644 "${PAYLOAD_DIR}${SUPPORT_DIR}/${PAM_LIB_NAME}"

    # --- version.plist (installed component versions; read by Intel + `serberus
    #     status` via HostProbe) ---
    # Baked into the payload at BUILD time because this pkg's postinstall is a
    # LITERAL ('POSTINSTALL_EOF') heredoc and cannot interpolate PKG_VERSION.
    # Without it, Intel's support-bundle export reported state/version.plist as
    # "not collected" (the file never existed on test-ring installs — only the
    # production PKG/Scripts/postinstall wrote it). 0644 root:wheel so the
    # standard-user Intel app can read it. The component versions are the
    # PRODUCT version; the package number is recorded separately.
    # installTeamID is the team the daemon was just signed by: teardowns pin
    # the installed daemon to it before executing it (pam-lib.sh
    # serberus_recorded_team).
    local install_team
    install_team=$("${CODESIGN}" --display --verbose=2 "${PAYLOAD_DIR}${INSTALL_BINARY_PATH}" 2>&1 \
        | "${AWK}" -F= '/^TeamIdentifier=/{print $2; exit}')
    if [[ ! "${install_team}" =~ ^[A-Z0-9]{10}$ ]]
    then
        log_error "signed daemon carries no Team ID (got '${install_team}') — cannot record installTeamID"
        exit 1
    fi
    "${CAT}" > "${PAYLOAD_DIR}${SUPPORT_DIR}/version.plist" <<VERSION_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>daemonVersion</key><string>${PRODUCT_VERSION}</string>
    <key>pamModuleVersion</key><string>${PRODUCT_VERSION}</string>
    <key>cliVersion</key><string>${PRODUCT_VERSION}</string>
    <key>packageVersion</key><string>${PKG_VERSION}</string>
    <key>installTeamID</key><string>${install_team}</string>
    <key>installedBy</key><string>SerberusCore test pkg (baked in payload)</string>
</dict>
</plist>
VERSION_EOF
    "${CHMOD}" 644 "${PAYLOAD_DIR}${SUPPORT_DIR}/version.plist"

    write_uninstall_helper

    # Payload modes only — ownership comes from pkgbuild's default
    # `recommended` mapping (root:wheel under /Library, /usr/local) and is
    # re-asserted by the postinstall.
    "${CHMOD}" 755 "${PAYLOAD_DIR}${SUPPORT_DIR}"
    "${CHMOD}" 700 "${PAYLOAD_DIR}${SUPPORT_DIR}/authdb-backups"
    "${CHMOD}" 755 "${PAYLOAD_DIR}${LOG_DIR}"

    # Strip removable extended attributes (a cloud-synced working copy can
    # stamp every file). A
    # stray com.apple.FinderInfo on the .so invalidates its signature ->
    # dlopen failure inside the `requisite` PAM line -> sudo bricked for everyone.
    # This MUST run while the module is still writable (444 lockdown comes
    # AFTER). Daemon Mach-O signatures are embedded, not xattr-stored, so the
    # daemon binary is safe across the strip.
    "${XATTR}" -rc "${PAYLOAD_DIR}"

    "${CHMOD}" 444 "${PAYLOAD_DIR}/usr/local/lib/pam/pam_serberus.so"

    if ! "${CODESIGN}" --verify --strict "${PAYLOAD_DIR}/usr/local/lib/pam/pam_serberus.so"
    then
        log_error "Payload module failed codesign --verify --strict after xattr strip"
        exit 1
    fi

    # Same check for the authorization plugin: a bundle seals its resources, so
    # prove the payload-wide strip above did not disturb the signature that
    # SecurityAgentHelper will validate at load time.
    if ! "${CODESIGN}" --verify --strict "${PAYLOAD_DIR}${AUTH_PLUGIN_DIR}/${AUTH_PLUGIN_NAME}"
    then
        log_error "Payload authorization plugin failed codesign --verify --strict after xattr strip"
        exit 1
    fi

    # (Intel app signing removed with its retirement.)
}

# On-endpoint teardown helper, shipped in the payload so a Jamf teardown policy
# (or a local admin) can remove the COMBINED install in the ONLY safe order:
# sudoers drop-in -> sudo_local -> disable + bootout -> demote JIT -> restore
# authdb -> plugin (only if restored) -> files -> forget + cleanup.
# Fully literal heredoc — it runs on the target.
write_uninstall_helper() {
    local helper_path="${PAYLOAD_DIR}${SUPPORT_DIR}/${UNINSTALL_HELPER_NAME}"
    "${MKDIR}" -p "${PAYLOAD_DIR}${SUPPORT_DIR}"

    "${CAT}" > "${helper_path}" <<'UNINSTALL_EOF'
#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: uninstall-serberus-sentinel-test.sh
# Author: Heath Jones
# Date: 2026-07-13
# Modified: 2026-09-26
# Purpose: Remove the COMBINED TEST-RING Serberus Core install (daemon + PAM
#          module + SerberusAuth plugin + CLI; SerberusCore-<v>.pkg). ORDER
#          IS SAFETY-CRITICAL and never rearranged:
#            1. remove the coarse /etc/sudoers.d/serberus standard-user
#               allowlist (marker-guarded, that one exact path only, no visudo)
#               — before the fine PAM gate, so the coarse gate never outlives
#               the fine gate (fail-open);
#            2. unwire the Serberus line from /etc/pam.d/sudo_local
#               (marker-aware; user lines preserved; file deleted only if
#               Serberus created it) while the daemon still runs — on failure
#               the daemon stays enabled and the teardown stops;
#            3. launchctl disable (a reboot cannot bring the daemon back), then
#               launchctl bootout and wait until launchd has dropped the job
#               (then re-check the drop-in: the daemon could rewrite it until
#               it stopped);
#            4. <daemon> --demote-jit (bounded; loud, non-fatal on failure),
#               then the drop-in once more;
#            5. <daemon> --restore-authdb (bounded; flat test binary or bundle);
#            6. remove SerberusAuth.bundle + authdb-backups ONLY if 5 succeeded
#               AND the live AuthorizationDB no longer references Serberus;
#            7. remove the module (+ any stray pam_serberus.so.2 and the legacy
#               /usr/lib/pam copy), plist, CLI, flat binary and bundle; remove
#               the retired Intel app; forget the receipts; remove the on-disk
#               helper files.
#          A drop-in that survives the later re-checks does not stop the
#          teardown, but the script exits 1.
#          An EXIT trap keeps the daemon enabled (and loaded) whenever the
#          script stops early with sudo_local still wired.
#          Pass --purge to also remove daemon data under the support dir
#          (never the apps or the other uninstall helpers; authdb-backups
#          survive a failed restore).
# Version: 1.5 - (a) --purge removes data only: the Sentinel agent and
#          Guardian apps, the other uninstall helpers and the install markers
#          stay. (b) The plugin gate is pam-lib.sh 1.8's: no pending .json,
#          .branches or .projection record, no composition row invoking
#          SerberusAuth and no right delegating to one; never a comment. With
#          no daemon, only those records (not a .standin) mean there is
#          something to restore. (c) The post-bootout wait
#          is the daemon's ExitTimeOut plus 5 s (25 s). (d) With no recorded
#          install team and no signed PAM module, the daemon is not run.
#          1.4 - (a) pam-lib.sh is sourced only when it and every directory
#          above it are root-owned and not group/other-writable. (b) The
#          daemon is disabled after sudo_local is unwired, right before the
#          bootout, and the one-shots run only once launchd has dropped the
#          job (waited for up to its 20 s ExitTimeOut). (c) The daemon is
#          pinned to the Team ID the install recorded in version.plist. (d)
#          The drop-in is re-checked after --demote-jit too, and one that
#          survives a re-check makes the script exit 1. (e) Also removes a
#          stray /usr/local/lib/pam/pam_serberus.so.2.
#          1.3 - A daemon binary runs (--demote-jit, --restore-authdb) only
#          after serberus_daemon_trusted passes (strict signature, Apple
#          anchor, identifier com.herojoneslabs.serberus.daemon, pinned team);
#          otherwise the manual steps are printed. --demote-jit exit 3 (no
#          grant store) is informational. A sudoers drop-in that survives its
#          removal stops the teardown before sudo_local is unwired.
#          1.2 - EXIT trap re-arms the daemon while sudo_local is still
#          wired; umask 022; bounded one-shots (SERBERUS_DEV_KEY_FALLBACK
#          exported, as the LaunchDaemon sets it); plugin removal also needs
#          a clean live AuthorizationDB; pam-lib.sh is removed only when no
#          other Serberus helper still needs it.
#          1.1 - New teardown order (disable -> drop-in -> unwire -> bootout
#          -> demote JIT -> restore -> plugin only if restored -> files);
#          system-only PATH and absolute tools.
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
readonly ENV="/usr/bin/env"
readonly ID="/usr/bin/id"
readonly KILLALL="/usr/bin/killall"
readonly LAUNCHCTL="/bin/launchctl"
readonly LOGGER="/usr/bin/logger"
readonly LS="/bin/ls"
readonly PKGUTIL="/usr/sbin/pkgutil"
readonly RM="/bin/rm"
readonly STAT="/usr/bin/stat"

readonly ORG_PLIST_DOMAIN="com.herojoneslabs.serberus"
readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.5"
readonly LOG_LABEL="${ORG_PLIST_DOMAIN}.sentineltest-uninstall"
# Frozen path: composed rights reference "SerberusAuth:identity" by name.
readonly AUTH_PLUGIN_PATH="/Library/Security/SecurityAgentPlugins/SerberusAuth.bundle"

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

readonly SUPPORT_DIR="/Library/Application Support/Serberus"
readonly AUTHDB_BACKUPS="${SUPPORT_DIR}/authdb-backups"
readonly PAM_LIB_PATH="${SUPPORT_DIR}/pam-lib.sh"
# Other on-disk helpers that source the shared pam-lib.sh. It is removed only
# when none of them remains.
readonly OTHER_HELPERS=(
    "${SUPPORT_DIR}/uninstall-serberusd-test.sh"
    "${SUPPORT_DIR}/uninstall-serberus-pam-test.sh"
    "${SUPPORT_DIR}/uninstall.sh"
)

# Daemon artifacts. This pkg installs the FLAT binary; the production bundle
# is tried (and removed) too, so a Mac that carried both ends up clean.
readonly DAEMON_LABEL="com.herojoneslabs.serberus.daemon"
readonly INSTALL_BINARY_PATH="/Library/PrivilegedHelperTools/com.herojoneslabs.serberus.daemon"
readonly DAEMON_BUNDLE="/Library/PrivilegedHelperTools/serberusd.app"
readonly DAEMON_BUNDLE_BINARY="${DAEMON_BUNDLE}/Contents/MacOS/com.herojoneslabs.serberus.daemon"
readonly PLIST_PATH="/Library/LaunchDaemons/com.herojoneslabs.serberus.daemon.plist"
# Hard deadline for each daemon one-shot (--demote-jit, --restore-authdb).
readonly ONESHOT_TIMEOUT=120

# PAM artifacts. Canonical module location (/usr/lib/pam is on the sealed
# read-only system snapshot); a legacy pre-relocation module is removed too.
readonly PAM_MODULE="/usr/local/lib/pam/pam_serberus.so"
readonly PAM_MODULE_LEGACY="/usr/lib/pam/pam_serberus.so"
# The serberus CLI, installed alongside the daemon at /usr/local/bin/serberus.
readonly CLI_PATH="/usr/local/bin/serberus"
readonly SUDO_LOCAL="/etc/pam.d/sudo_local"
# Coarse standard-user sudoers allowlist. Removed before sudo_local and
# unconditionally — pam_serberus is the fine gate, so leaving this coarse gate
# behind would be fail-open. Path + guard live in pam-lib.sh.
readonly SUDOERS_DROPIN="/etc/sudoers.d/serberus"

# Retired standalone diagnostics app. Outside the sudo chain, so its removal
# order carries no safety weight — but leaving it behind would strand an
# orphaned app pointed at a Serberus that no longer exists.
readonly INTEL_APP_PATH="/Applications/SerberusIntel.app"

# The receipt this pkg registers (unchanged across the SerberusCore rename).
readonly PKG_IDENTIFIER="com.herojoneslabs.serberus.sentineltestpkg"
# Pre-Sentinel-rename receipt. Forgotten too, so uninstalling a device that was
# upgraded from the old "Core" pkg leaves no stale receipt behind.
readonly LEGACY_CORE_RECEIPT="com.herojoneslabs.serberus.coretestpkg"
readonly PURGE_FLAG="${1:-}"

# Set to 1 by restore_authdb once the AuthorizationDB is known to be native
# again. GATES deleting the plugin and the backups.
AUTHDB_RESTORE_OK=0
# Success marker; without it the EXIT trap re-arms a daemon behind a wired
# sudo_local.
UNINSTALL_SUCCEEDED=0
# Set when the drop-in is still present at a re-check after the bootout; the
# teardown finishes but the script exits 1.
DROPIN_SURVIVED=0
# Set to 0 when the booted-out daemon is still loaded after its ExitTimeOut;
# no one-shot runs beside it (manual steps are logged instead).
DAEMON_GONE=1

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

log_warn() {
    "${LOGGER}" -t "${LOG_LABEL}" -p user.warning "[WARN] $*"
    printf '[WARN] %s\n' "$*" >&2
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

# The marker-aware sudo_local / sudoers-dropin logic lives in pam-lib.sh
# (installed alongside this helper). Refuse to proceed without it — or when
# anyone but root could have changed it — rather than improvising: a wrong
# removal order or a clobbered user line is how sudo gets bricked.
source_pam_lib() {
    if ! path_chain_is_root_only "${PAM_LIB_PATH}"
    then
        log_error "${PAM_LIB_PATH} is missing, or it or a directory above it is not root-only — cannot unwire sudo safely."
        log_error "Manual teardown (THIS ORDER ONLY):"
        log_error "  1. sudo rm -f ${SUDOERS_DROPIN}   (only if its first line is the Serberus managed header)."
        log_error "  2. Remove the pam_serberus.so line from ${SUDO_LOCAL} (delete the whole file only if Serberus created it)."
        log_error "  3. sudo launchctl disable system/${DAEMON_LABEL}; sudo launchctl bootout system/${DAEMON_LABEL}"
        log_error "  4. sudo ${INSTALL_BINARY_PATH} --demote-jit"
        log_error "  5. sudo ${INSTALL_BINARY_PATH} --restore-authdb   (only if it succeeds: sudo rm -rf ${AUTH_PLUGIN_PATH})"
        log_error "  6. sudo rm -f ${PAM_MODULE} ${PAM_MODULE}.2 ${INSTALL_BINARY_PATH} ${PLIST_PATH} ${CLI_PATH}"
        log_error "  7. sudo pkgutil --forget ${PKG_IDENTIFIER}"
        exit 1
    fi
    # shellcheck source=/dev/null
    source "${PAM_LIB_PATH}"
}

# EXIT trap: stopping early (a failed step under set -e) must never leave
# sudo_local wired behind a disabled or unloaded daemon.
on_exit() {
    local status=$?
    if [[ "${UNINSTALL_SUCCEEDED}" -eq 1 ]]
    then
        return 0
    fi
    set +e
    if ! serberus_daemon_rearm_if_wired "${SUDO_LOCAL}" "${DAEMON_LABEL}" "${PLIST_PATH}"
    then
        log_error "Stopped early (status ${status}) with ${SUDO_LOCAL} still wired — ${DAEMON_LABEL} re-enabled."
    fi
    exit "${status}"
}

# STEP 3 — disable only once sudo_local is unwired, right before the bootout:
# an interrupted run must never leave sudo_local wired behind a disabled
# daemon. A later install re-enables the label.
disable_daemon() {
    log_info "Disabling ${DAEMON_LABEL}"
    "${LAUNCHCTL}" disable "system/${DAEMON_LABEL}" 2>/dev/null \
        || log_warn "launchctl disable system/${DAEMON_LABEL} failed"
}

# STEP 1 — coarse sudoers drop-in. UNCONDITIONAL, marker-guarded, scoped to
# this ONE exact path (serberus_pam_remove_sudoers_dropin: `rm -f`, no glob,
# no visudo, no other /etc/sudoers.d entry touched). Leaving the coarse
# allowlist behind after pam_serberus is gone would grant standard users
# unmediated sudo to the curated command paths — fail-open. Called again after
# the bootout, since the running daemon could rewrite it until then.
# Returns 1 when the drop-in is STILL there after the rm.
remove_sudoers_dropin() {
    local result
    result=$(serberus_pam_remove_sudoers_dropin "${SUDOERS_DROPIN}") || result="FAILED"
    log_info "sudoers drop-in removal: ${result} (${SUDOERS_DROPIN})"
    if [[ "${result}" == "FAILED" ]]
    then
        log_error "${SUDOERS_DROPIN} is STILL present after its removal (immutable flag, or something re-created it)."
        log_manual_steps sudoers
        return 1
    fi
    return 0
}

# STEP 1: a surviving drop-in stops the teardown BEFORE sudo_local is
# unwired — the PAM gate must outlive it; the daemon stays enabled.
remove_sudoers_dropin_or_stop() {
    if ! remove_sudoers_dropin
    then
        log_error "Stopping: sudo_local stays wired and ${DAEMON_LABEL} stays enabled."
        "${LAUNCHCTL}" enable "system/${DAEMON_LABEL}" 2>/dev/null || true
        exit 1
    fi
}

# Routes serberus_daemon_manual_steps into the log. $1 demote | restore | sudoers
log_manual_steps() {
    local line
    while IFS= read -r line
    do
        log_error "${line}"
    done < <(serberus_daemon_manual_steps "$1" "${AUTHDB_BACKUPS}")
}

# The re-checks after the bootout and after --demote-jit: the PAM gate is
# already gone, so the teardown continues, loudly, and exits 1 at the end.
recheck_sudoers_dropin() {
    if ! remove_sudoers_dropin
    then
        log_error "The drop-in outlived the PAM gate — remove it by hand."
        DROPIN_SURVIVED=1
    fi
}

# STEP 2 — unwire sudo_local while the daemon still runs. If an active line
# survives, keep the daemon enabled and stop: sudo keeps a live daemon behind
# a module that is still there.
unwire_sudo_local() {
    local result
    result=$(serberus_pam_remove_sudo_local "${SUDO_LOCAL}") || result="FAILED"
    log_info "sudo_local unwire: ${result} (${SUDO_LOCAL})"

    if serberus_pam_sudo_local_has_module "${SUDO_LOCAL}"
    then
        log_error "An active pam_serberus.so line remains in ${SUDO_LOCAL} — stopping here."
        log_error "The daemon stays enabled and running and the module is kept (a dangling"
        log_error "reference, or a wired module with no daemon, denies every sudo)."
        "${LAUNCHCTL}" enable "system/${DAEMON_LABEL}" 2>/dev/null || true
        exit 1
    fi
}

# STEP 3 — bootout, then wait (up to the daemon's ExitTimeOut) until launchd
# has dropped the job: no one-shot may run beside a live daemon.
bootout_daemon() {
    if "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" >/dev/null 2>&1
    then
        log_info "Booting out ${DAEMON_LABEL}"
        "${LAUNCHCTL}" bootout "system/${DAEMON_LABEL}" 2>/dev/null || true
        if ! serberus_launchd_wait_gone "${DAEMON_LABEL}" \
            2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
        then
            DAEMON_GONE=0
            log_error "${DAEMON_LABEL} is still loaded after its bootout — no daemon one-shot will run."
        fi
    fi
}

# serberus_daemon_trusted with the team the install recorded in version.plist
# (falls back to the installed module's team; with neither, the daemon is
# refused). $1 daemon path.
daemon_trusted() {
    local team
    team=$(serberus_recorded_team 2>/dev/null) || team=""
    serberus_daemon_trusted "$1" "${team}" 2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
}

# Runs a daemon one-shot with the deadline. SERBERUS_DEV_KEY_FALLBACK=1 is
# what this ring's LaunchDaemon sets, so the one-shot finds the same keys.
# $1 binary, $2 flag.
run_daemon_oneshot() {
    serberus_run_bounded "${ONESHOT_TIMEOUT}" \
        "${ENV}" SERBERUS_DEV_KEY_FALLBACK=1 "$1" "$2"
}

# STEP 4 — demote every JIT admin recorded in the grant store (after the
# bootout, before any binary is removed). A binary runs only when
# serberus_daemon_trusted passes. Loud but non-fatal on failure; exit 3 = no
# grant store, nothing to demote.
demote_jit_admins() {
    local candidate
    local status
    if [[ "${DAEMON_GONE}" -ne 1 ]]
    then
        log_manual_steps demote
        return 0
    fi
    for candidate in "${INSTALL_BINARY_PATH}" "${DAEMON_BUNDLE_BINARY}"
    do
        if [[ ! -x "${candidate}" ]]
        then
            continue
        fi
        if ! daemon_trusted "${candidate}"
        then
            log_error "${candidate} failed its signature check — NOT executing it for --demote-jit"
            continue
        fi
        log_info "Demoting JIT admins (${candidate} --demote-jit)"
        status=0
        run_daemon_oneshot "${candidate}" --demote-jit || status=$?
        case "${status}" in
            0)
                return 0
                ;;
            3)
                log_info "No grant store — no JIT admins to demote"
                return 0
                ;;
        esac
        log_error "--demote-jit FAILED via ${candidate} (exit ${status}; 124 = timed out)"
    done
    log_error "!!! JIT admins could NOT be demoted."
    log_manual_steps demote
    return 0
}

# STEP 5 — restore AuthorizationDB rights with whichever daemon binary exists
# (it performs the restore, so this runs before any binary is removed).
# Otherwise a `deny` authuri rule would survive uninstall and leave a System
# Settings pane (or admin auth) blocked. Exit 0 is not enough on its own: the
# live database must no longer reference Serberus before the plugin may go.
restore_authdb() {
    local binary=""
    local candidate
    if [[ "${DAEMON_GONE}" -ne 1 ]]
    then
        log_manual_steps restore
        return 0
    fi
    for candidate in "${INSTALL_BINARY_PATH}" "${DAEMON_BUNDLE_BINARY}"
    do
        if [[ ! -x "${candidate}" ]]
        then
            continue
        fi
        if daemon_trusted "${candidate}"
        then
            binary="${candidate}"
            break
        fi
        log_error "${candidate} failed its signature check — NOT executing it for --restore-authdb"
    done
    if [[ -z "${binary}" ]]
    then
        # Pending records (.json, .branches, .projection) mean there is
        # something to restore; a .standin alone does not.
        if serberus_authdb_records_pending "${AUTHDB_BACKUPS}" > /dev/null
        then
            log_error "No trusted daemon binary; CANNOT auto-restore the AuthorizationDB."
            log_manual_steps restore
        elif serberus_authdb_free_of_serberus 2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
        then
            AUTHDB_RESTORE_OK=1
        fi
        return 0
    fi
    log_info "Restoring AuthorizationDB rights from snapshots (${binary})"
    local status=0
    run_daemon_oneshot "${binary}" --restore-authdb || status=$?
    if [[ "${status}" -ne 0 ]]
    then
        log_error "AuthorizationDB restore FAILED (exit ${status}; 124 = timed out) — some rights may still be modified."
        log_error "Recover manually: inspect ${AUTHDB_BACKUPS}/*.json and run"
        log_error "  sudo security authorizationdb write <right> < <original>"
        return 0
    fi
    if serberus_authdb_free_of_serberus 2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    then
        AUTHDB_RESTORE_OK=1
    else
        log_error "The restore exited 0 but the AuthorizationDB still references Serberus — keeping the plugin and backups."
    fi
}

# STEP 6 — ORDER IS LOAD-BEARING: only after a SUCCESSFUL restore has
# rewritten every composed right back to its native definition. Deleting the
# bundle while a right still referenced "SerberusAuth:identity" would leave
# that right pointing at a mechanism that cannot be loaded.
remove_auth_plugin_if_restored() {
    if [[ "${AUTHDB_RESTORE_OK}" -ne 1 ]]
    then
        log_warn "Keeping ${AUTH_PLUGIN_PATH} and ${AUTHDB_BACKUPS}: the AuthorizationDB restore did not"
        log_warn "succeed, and rights that still reference SerberusAuth:identity need the plugin."
        return 0
    fi
    if [[ -d "${AUTH_PLUGIN_PATH}" ]]
    then
        log_info "Removing authorization plugin ${AUTH_PLUGIN_PATH}"
        "${RM}" -rf "${AUTH_PLUGIN_PATH}"
        "${KILLALL}" SecurityAgent authorizationhost 2>/dev/null || true
    fi
    "${RM}" -rf "${AUTHDB_BACKUPS}"
}

# STEP 7 — files. The module goes only after STEP 2 verified no reference.
remove_components() {
    local path
    for path in "${PAM_MODULE}" "${SERBERUS_PAM_MODULE_VERSIONED_PATH}" \
        "${PAM_MODULE_LEGACY}" "${PLIST_PATH}" \
        "${CLI_PATH}" "${INSTALL_BINARY_PATH}"
    do
        if [[ -e "${path}" ]]
        then
            log_info "Removing ${path}"
            "${RM}" -f "${path}"
        fi
    done
    if [[ -e "${DAEMON_BUNDLE}" ]]
    then
        log_info "Removing ${DAEMON_BUNDLE}"
        "${RM}" -rf "${DAEMON_BUNDLE}"
    fi
}

# Serberus Intel — best-effort removal. Outside the sudo chain, so a failure
# here must not abort the teardown.
remove_intel_app() {
    if [[ ! -d "${INTEL_APP_PATH}" ]]
    then
        return 0
    fi
    log_info "Removing ${INTEL_APP_PATH}"
    if ! "${RM}" -rf "${INTEL_APP_PATH}"
    then
        log_warn "Could not remove ${INTEL_APP_PATH} — remove it by hand."
    fi
}

# pam-lib.sh is shared with the other Serberus helpers; keep it while any of
# them is still installed.
remove_pam_lib_if_unused() {
    local helper
    for helper in "${OTHER_HELPERS[@]}"
    do
        if [[ -e "${helper}" ]]
        then
            log_info "Keeping ${PAM_LIB_PATH} — ${helper} still uses it"
            return 0
        fi
    done
    "${RM}" -f "${PAM_LIB_PATH}"
}

# Forget the receipts, then remove the on-disk support files.
forget_and_cleanup() {
    "${PKGUTIL}" --forget "${PKG_IDENTIFIER}" >/dev/null 2>&1 || true
    # Also drop the pre-rename "Core" receipt in case this device was upgraded
    # from it rather than installed fresh under the Sentinel identifier.
    "${PKGUTIL}" --forget "${LEGACY_CORE_RECEIPT}" >/dev/null 2>&1 || true

    if [[ "${PURGE_FLAG}" == "--purge" ]]
    then
        # Data only (pam-lib.sh serberus_purge_support_data): the apps, the
        # other uninstall helpers and the install markers stay.
        local keep_backups=1
        if [[ "${AUTHDB_RESTORE_OK}" -eq 1 ]]
        then
            keep_backups=0
            log_info "Purging Serberus data under ${SUPPORT_DIR}"
        else
            log_warn "Purging Serberus data under ${SUPPORT_DIR} EXCEPT ${AUTHDB_BACKUPS} (the restore did not succeed)"
        fi
        serberus_purge_support_data "${SUPPORT_DIR}" "${keep_backups}" > /dev/null
        "${RM}" -f "${SUPPORT_DIR}/${SCRIPT_NAME}"
        remove_pam_lib_if_unused
    else
        # Preserve state.plist, grants.sqlite, and authdb-backups; remove only
        # this helper and — when no other helper needs it — the shared
        # pam-lib.sh (already sourced into memory).
        "${RM}" -f "${SUPPORT_DIR}/${SCRIPT_NAME}"
        remove_pam_lib_if_unused
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
source_pam_lib
trap on_exit EXIT

# ORDER. Never rearranged:
#   sudoers drop-in -> sudo_local unwire -> disable -> bootout (wait until
#   gone) -> drop-in re-check -> demote JIT -> drop-in re-check -> restore
#   authdb -> plugin (only if restored) -> files -> Intel app -> forget +
#   cleanup.
remove_sudoers_dropin_or_stop
unwire_sudo_local
disable_daemon
bootout_daemon
recheck_sudoers_dropin
demote_jit_admins
recheck_sudoers_dropin
restore_authdb
remove_auth_plugin_if_restored
remove_components
remove_intel_app
forget_and_cleanup

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
# Date: 2026-07-13
# Modified: 2026-09-26
# Purpose: Serberus Core TEST-RING PKG preinstall. Three jobs, all BEFORE any
#          new file is laid down, and in THIS ORDER (the order is a safety
#          property, not a convenience):
#            (1) break-glass PREFLIGHT FIRST — READ-ONLY (no daemon needed). It
#                reports the effective config (mode + bypass counts), then ABORTS
#                in the ONE genuine-brick case and WARNS + PROCEEDS in every
#                survivable case. Effective source is computed the SAME way the
#                daemon (EffectiveConfigResolver) and pam_serberus
#                (serberus_config_resolve_source) do:
#                  - no enforceable config AND no last-known-good snapshot ⇒ the
#                    Mac has never been configured ⇒ Serberus stays INERT (state
#                    awaitingConfig; PAM returns PAM_IGNORE, so sudo passes
#                    through natively; the daemon writes no authdb rules and no
#                    sudoers drop-in) until the config profile lands ⇒ WARN + PROCEED.
#                  - no enforceable config BUT a snapshot exists ⇒ BOTH halves
#                    fall back to the last-known-good config, which is
#                    enforceable by construction ⇒ its pamBypass break-glass is
#                    intact ⇒ WARN + PROCEED.
#                  - config PRESENT + enforce + a pamBypass whose every entry is a
#                    TYPO that resolves to NO account ⇒ the daemon and pam treat
#                    it like an empty pamBypass and fall back, but the Mac would
#                    have no working break-glass until the profile is fixed ⇒
#                    ABORT (exit 1).
#                The WARN cases are what make the Jamf ENROLLMENT RACE survivable:
#                APNS queuing routinely lands this pkg BEFORE the config profile,
#                and aborting there just left the Mac un-managed and needing a
#                re-run. It runs FIRST, before any mutation, so its output
#                describes the machine as we found it AND an abort strands nothing
#                (no bootout, no sudo config touched). Sourced from pam-lib.sh.
#            (2) legacy daemon uninstall — fully remove any previous-generation
#                (pre-rename, com.heath) daemon and revert its AuthorizationDB
#                rewrites from ITS OWN snapshots, and boot out a same-prefix
#                running daemon (upgrade case). Mirrors PKG/build-test-pkg.sh.
#                MUTATING, so it runs only AFTER the preflight has reported.
#            (3) upgrade TEARDOWN-FIRST, before the same-prefix daemon is
#                booted out: remove the coarse sudoers drop-in, unwire
#                sudo_local (marker-aware; stop with the old daemon still
#                running if a line survives), bootout (label left ENABLED so a
#                reboot restores the old daemon, which re-provisions only once
#                the gate is back), drop-in re-check. A failed or interrupted
#                upgrade therefore falls back to NATIVE sudo, never to blanket
#                denial; the postinstall re-wires once the new daemon is up.
#          NOTE: this preinstall does NOT gate on "daemon loaded" — the daemon
#          is installed THIS run, so that check lives in the POSTINSTALL.
# Version: 1.7 - (a) On an upgrade, writes the root-only marker
#          /Library/Application Support/Serberus/.upgrade-in-progress before
#          the teardown, so the new daemon ends open JIT sessions at startup.
#          (b) The post-bootout wait is the daemon's ExitTimeOut plus 5 s.
#          (c) SCRIPT_VERSION matches this header.
#          1.6 - (a) After the bootout the script waits (up to the daemon's
#          20 s ExitTimeOut) until launchd no longer lists the job; if it is
#          still loaded --demote-jit is skipped and the manual steps logged.
#          (b) The OLD daemon's --demote-jit now runs whenever its binary is
#          on disk (it used to require the job to still be loaded, which it
#          never is after the bootout). (c) The drop-in is checked straight
#          after the bootout and again after --demote-jit; one that survives
#          once sudo_local is unwired re-bootstraps the old daemon, which
#          removes its own drop-in while the PAM gate is unwired. (d) The old
#          daemon is pinned to the Team ID the last install recorded in
#          version.plist, when there is one. (e) A legacy com.heath daemon
#          is booted out (and waited for) before its --restore-authdb.
#          1.5 - A sudoers drop-in that survives its removal stops the upgrade
#          (before sudo_local is unwired on the first pass). The OLD daemon's
#          --demote-jit runs after the bootout (the old binary is still on disk), only after
#          serberus_daemon_trusted; exit 3 (no grant store) is informational,
#          other failures are loud but not fatal. The legacy com.heath
#          restore runs only for a binary that passes the same check;
#          otherwise the manual steps are logged.
#          1.4 - Teardown-first upgrade (drop-in -> unwire -> bootout ->
#          drop-in); umask 022; refuses a target volume other than "/" ($3);
#          EXIT trap keeps a daemon behind a still-wired sudo_local.
#          1.3 - System-only PATH and absolute tool paths (no `which` as root).
#          1.2 - Break-glass preflight ABORTS again in the ONE genuine-brick case
#          (config PRESENT + enforce + a pamBypass that resolves to no account +
#          NO last-known-good snapshot), and WARNS + PROCEEDS in every survivable
#          case (absent config, or a snapshot to fall back to). 1.1's
#          blanket WARN removed the brick protection; this restores it while
#          keeping the enrollment race survivable. Every other preflight/
#          validation is unchanged.
#          1.1 - Break-glass preflight relaxed from ABORT to WARN + PROCEED
#          (awaiting-config bootstrap + last-known-good fallback make the
#          un-configured install inert rather than bricking). Every other
#          preflight/validation is unchanged.
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
readonly CP="/bin/cp"
readonly DIRNAME="/usr/bin/dirname"
readonly ENV="/usr/bin/env"
readonly ID="/usr/bin/id"
readonly LAUNCHCTL="/bin/launchctl"
readonly LOGGER="/usr/bin/logger"
readonly MKDIR="/bin/mkdir"
readonly MV="/bin/mv"
readonly PKGUTIL="/usr/sbin/pkgutil"
readonly RM="/bin/rm"

readonly ORG_PLIST_DOMAIN="com.herojoneslabs.serberus"
readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.7"
readonly LOG_LABEL="${ORG_PLIST_DOMAIN}.sentineltest-preinstall"

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

readonly DAEMON_LABEL="com.herojoneslabs.serberus.daemon"
readonly LAUNCHD_PLIST="/Library/LaunchDaemons/com.herojoneslabs.serberus.daemon.plist"
readonly SUDO_LOCAL="/etc/pam.d/sudo_local"
readonly SUDOERS_DROPIN="/etc/sudoers.d/serberus"

# The installed (OLD) daemon an upgrade stops: a test ring's flat binary, or a
# production bundle. Its --demote-jit runs after the bootout (the old binary is still on disk).
readonly OLD_DAEMON_BINARY_FLAT="/Library/PrivilegedHelperTools/com.herojoneslabs.serberus.daemon"
readonly OLD_DAEMON_BINARY_BUNDLE="/Library/PrivilegedHelperTools/serberusd.app/Contents/MacOS/com.herojoneslabs.serberus.daemon"
# Hard deadline for the old daemon's --demote-jit and the legacy restore.
readonly ONESHOT_TIMEOUT=120

# Installer passes the target volume as $3.
readonly TARGET_VOLUME="${3:-}"

# Success marker; without it the EXIT trap re-arms a daemon behind a wired
# sudo_local.
PREINSTALL_SUCCEEDED=0
# Set to 1 once sudo_local has been unwired (see remove_sudoers_dropin).
SUDO_LOCAL_UNWIRED=0
# Set to 0 when the booted-out daemon is still loaded after its ExitTimeOut.
DAEMON_GONE=1

# Legacy (pre-rename) footprint. Before the bundle-ID rename the daemon shipped
# under the com.heath.serberus prefix; a test Mac carrying that build must have
# it fully uninstalled — and its AuthorizationDB rewrites reverted from its OWN
# snapshots — before the new-prefix daemon lands.
readonly LEGACY_DAEMON_LABEL="com.heath.serberus.daemon"
readonly LEGACY_BINARY="/Library/PrivilegedHelperTools/com.heath.serberus.daemon"
readonly LEGACY_PLIST="/Library/LaunchDaemons/com.heath.serberus.daemon.plist"
readonly LEGACY_SUPPORT_DIR="/Library/Application Support/com.heath.serberus"
readonly LEGACY_TEST_RECEIPT="com.heath.serberus.testpkg"
readonly LEGACY_PROD_RECEIPT="com.heath.serberus.pkg"

# Application Support + Logs folder rename (com.herojoneslabs.serberus →
# Serberus). The old reverse-DNS folders are migrated in place so grants.sqlite,
# state.plist, the authdb snapshots, the last-known-good config, and the log
# history survive the rename.
readonly SUPPORT_DIR_OLD="/Library/Application Support/com.herojoneslabs.serberus"
readonly SUPPORT_DIR_NEW="/Library/Application Support/Serberus"
readonly LOG_DIR_OLD="/Library/Logs/com.herojoneslabs.serberus"
readonly LOG_DIR_NEW="/Library/Logs/Serberus"

# Orphaned GUI-app bundles from earlier packagings, removed on install so an
# upgraded device matches a fresh one. The SAME-identifier daemon + PAM module
# upgrade in place (identical paths) and are NOT touched here.
#   - Pre-Sentinel-rename: the three old-named apps below.
#   - Intel retirement: /Applications/SerberusIntel.app — the
#     standalone diagnostics app whose UI now lives in the Sentinel window's
#     Intel tab. Removing it avoids a stale duplicate alongside the embedded one.
readonly LEGACY_CORE_RECEIPT="com.herojoneslabs.serberus.coretestpkg"
readonly PRERENAME_APPS=(
    "/Applications/SerberusCapture.app"   # old Serberus Intel (diagnostics), pre-rename
    "/Applications/Serberus.app"          # old Serberus Commander (admin GUI)
    "/Applications/SerberusAgent.app"     # old Serberus Sentinel (menubar GUI)
    "/Applications/SerberusIntel.app"     # retired standalone Intel app (now the Sentinel Intel tab)
)

# The config the preflight reads: only the MDM-written managed plist, exactly
# as Sources/pam_serberus/pam_config.c does.
readonly MANAGED_CONFIG_PLIST="/Library/Managed Preferences/com.herojoneslabs.serberus.config.plist"

# The daemon's last-known-good config snapshot. Its EXISTENCE is the "this Mac
# has been configured" marker: with no enforceable config delivered, both the
# daemon and pam_serberus fall back to it (still enforcing, break-glass intact);
# with neither, both stay INERT (awaitingConfig / PAM_IGNORE). KEEP IN SYNC with
# PrivMgrCore BundleConfig.lastKnownGoodConfigPath and pam_config.h's
# SERBERUS_LKG_CONFIG_PATH.
readonly LKG_CONFIG_PLIST="/Library/Application Support/Serberus/last-known-good-config.plist"

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
        log_warn "preinstall not running as root"
        exit 1
    fi
}

# Serberus rewires THIS Mac's sudo and AuthorizationDB; installing onto any
# other volume is refused before anything is touched.
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

# Fully remove a PREVIOUS-generation (pre-rename, com.heath) daemon if present,
# reverting its AuthorizationDB rewrites from ITS OWN binary + snapshots first.
# Mirrors PKG/build-test-pkg.sh uninstall_legacy_daemon().
uninstall_legacy_daemon() {
    if [[ ! -e "${LEGACY_BINARY}" ]] \
        && [[ ! -e "${LEGACY_PLIST}" ]] \
        && ! "${PKGUTIL}" --pkg-info "${LEGACY_TEST_RECEIPT}" >/dev/null 2>&1 \
        && ! "${PKGUTIL}" --pkg-info "${LEGACY_PROD_RECEIPT}" >/dev/null 2>&1
    then
        log_info "No legacy com.heath.serberus daemon detected"
        return 0
    fi

    log_warn "Legacy com.heath.serberus daemon detected — uninstalling before install"

    # Boot the legacy daemon out FIRST, and wait until launchd has dropped
    # it: its one-shot must not run beside the live daemon.
    local legacy_gone=1
    if "${LAUNCHCTL}" print "system/${LEGACY_DAEMON_LABEL}" >/dev/null 2>&1
    then
        log_info "Booting out legacy daemon ${LEGACY_DAEMON_LABEL}"
        "${LAUNCHCTL}" bootout "system/${LEGACY_DAEMON_LABEL}" 2>/dev/null || true
        serberus_launchd_wait_gone "${LEGACY_DAEMON_LABEL}" \
            2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err) || legacy_gone=0
    fi

    local restore_ok=1
    local line
    if [[ -x "${LEGACY_BINARY}" && "${legacy_gone}" -ne 1 ]]
    then
        log_error "Legacy daemon ${LEGACY_DAEMON_LABEL} is still loaded — NOT running its --restore-authdb; preserving ${LEGACY_SUPPORT_DIR}"
        while IFS= read -r line
        do
            log_error "${line}"
        done < <(serberus_daemon_manual_steps restore "${LEGACY_SUPPORT_DIR}/authdb-backups")
    elif [[ -x "${LEGACY_BINARY}" ]] \
        && ! serberus_daemon_trusted "${LEGACY_BINARY}" 2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    then
        # A pre-rename build may not carry today's identifier or team: it is
        # never executed on trust it cannot prove.
        log_error "Legacy binary ${LEGACY_BINARY} failed its signature check — NOT executing it; preserving ${LEGACY_SUPPORT_DIR}"
        while IFS= read -r line
        do
            log_error "${line}"
        done < <(serberus_daemon_manual_steps restore "${LEGACY_SUPPORT_DIR}/authdb-backups")
    elif [[ -x "${LEGACY_BINARY}" ]]
    then
        log_info "Reverting legacy AuthorizationDB rewrites (${LEGACY_BINARY} --restore-authdb)"
        if serberus_run_bounded "${ONESHOT_TIMEOUT}" "${LEGACY_BINARY}" --restore-authdb
        then
            restore_ok=0
        else
            log_error "Legacy AuthorizationDB restore FAILED (or timed out) — preserving ${LEGACY_SUPPORT_DIR} for manual recovery"
        fi
    else
        log_warn "Legacy binary missing or non-executable — cannot auto-revert its AuthorizationDB rewrites"
    fi

    if [[ -e "${LEGACY_PLIST}" ]]
    then
        "${RM}" -f "${LEGACY_PLIST}"
    fi
    if [[ -e "${LEGACY_BINARY}" ]]
    then
        "${RM}" -f "${LEGACY_BINARY}"
    fi

    "${PKGUTIL}" --forget "${LEGACY_TEST_RECEIPT}" >/dev/null 2>&1 || true
    "${PKGUTIL}" --forget "${LEGACY_PROD_RECEIPT}" >/dev/null 2>&1 || true

    if [[ "${restore_ok}" -eq 0 ]] && [[ -d "${LEGACY_SUPPORT_DIR}" ]]
    then
        log_info "Removing orphaned legacy support dir ${LEGACY_SUPPORT_DIR}"
        "${RM}" -rf "${LEGACY_SUPPORT_DIR}"
    fi

    log_info "Legacy daemon uninstall complete"
}

# Remove pre-Sentinel-rename orphans: the three old-named GUI app bundles and the
# old …coretestpkg receipt. Best-effort and NON-FATAL — these sit outside the
# sudo/authURI chain (the daemon + PAM module upgrade in place under unchanged
# identifiers), so a failure here must never abort the install and strand
# enforcement. Nothing is removed if this Mac never carried the old pkg.
remove_prerename_artifacts() {
    if "${PKGUTIL}" --pkg-info "${LEGACY_CORE_RECEIPT}" >/dev/null 2>&1
    then
        log_info "Forgetting pre-rename receipt ${LEGACY_CORE_RECEIPT}"
        "${PKGUTIL}" --forget "${LEGACY_CORE_RECEIPT}" >/dev/null 2>&1 || true
    fi

    local app
    for app in "${PRERENAME_APPS[@]}"
    do
        if [[ -d "${app}" ]]
        then
            log_info "Removing pre-rename app ${app}"
            "${RM}" -rf "${app}" || log_warn "Could not remove ${app} — remove it by hand"
        fi
    done
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
    log_error "preinstall exiting with status ${status} before completing"
    serberus_daemon_rearm_if_wired "${SUDO_LOCAL}" "${DAEMON_LABEL}" "${LAUNCHD_PLIST}" \
        2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    exit "${status}"
}

# Teardown-first, step 1 (and again after the bootout): the coarse gate goes
# before the fine one. Marker-guarded, that one exact path. A drop-in that is
# still there after the rm stops the upgrade: on the first call that is before
# sudo_local is unwired, so the old daemon keeps running behind both gates.
remove_sudoers_dropin() {
    local result
    result=$(serberus_pam_remove_sudoers_dropin "${SUDOERS_DROPIN}") || result="FAILED"
    log_info "sudoers drop-in removal: ${result} (${SUDOERS_DROPIN})"
    if [[ "${result}" == "FAILED" ]]
    then
        log_error "${SUDOERS_DROPIN} is STILL present after its removal (immutable flag, or something re-created it)."
        if [[ "${SUDO_LOCAL_UNWIRED}" -eq 1 ]]
        then
            # With the PAM gate unwired, the old daemon's provisioning pass
            # removes its own drop-in, so bring it back rather than leave the
            # drop-in with nothing behind it.
            log_error "sudo_local is already unwired — re-bootstrapping the old daemon so it removes its drop-in."
            if ! "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" >/dev/null 2>&1 \
                && [[ -f "${LAUNCHD_PLIST}" ]]
            then
                "${LAUNCHCTL}" bootstrap system "${LAUNCHD_PLIST}" 2>/dev/null \
                    || log_error "launchctl bootstrap ${LAUNCHD_PLIST} failed"
            fi
        fi
        log_error "Stopping the upgrade. Remove the file by hand (chflags noschg,nouchg first if set), then reinstall."
        exit 1
    fi
}

# Teardown-first, step 2, while the OLD daemon still runs. A surviving active
# line stops the upgrade with that daemon still behind it.
unwire_sudo_local() {
    local result
    result=$(serberus_pam_remove_sudo_local "${SUDO_LOCAL}") || result="FAILED"
    log_info "sudo_local unwire: ${result} (${SUDO_LOCAL})"
    if serberus_pam_sudo_local_has_module "${SUDO_LOCAL}"
    then
        log_error "An ACTIVE pam_serberus line remains in ${SUDO_LOCAL} — aborting the upgrade with the"
        log_error "current daemon still running behind it. Fix ${SUDO_LOCAL} by hand, then reinstall."
        exit 1
    fi
    SUDO_LOCAL_UNWIRED=1
}

# Demote JIT admins with the OLD daemon binary once the daemon has been booted
# out: if the upgrade then fails, nothing else would expire their grants. The
# binary runs only when serberus_daemon_trusted passes (strict signature,
# Apple anchor, the daemon identifier, the team the last install recorded).
# Never fatal, but loud: exit 1 means users may still be admins; exit 3 means
# there is no grant store.
demote_jit_with_old_daemon() {
    local binary=""
    local candidate
    for candidate in "${OLD_DAEMON_BINARY_FLAT}" "${OLD_DAEMON_BINARY_BUNDLE}"
    do
        if [[ -x "${candidate}" && ! -L "${candidate}" ]]
        then
            binary="${candidate}"
            break
        fi
    done
    if [[ -z "${binary}" ]]
    then
        log_info "No installed daemon binary — no JIT grants to demote"
        return 0
    fi
    local line
    if [[ "${DAEMON_GONE}" -ne 1 ]]
    then
        log_error "The booted-out daemon is still loaded — NOT running --demote-jit beside it."
        while IFS= read -r line
        do
            log_error "${line}"
        done < <(serberus_daemon_manual_steps demote)
        return 0
    fi
    local team
    team=$(serberus_recorded_team 2>/dev/null) || team=""
    if ! serberus_daemon_trusted "${binary}" "${team}" 2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    then
        log_error "The installed daemon ${binary} failed its signature check — NOT executing it for --demote-jit."
        while IFS= read -r line
        do
            log_error "${line}"
        done < <(serberus_daemon_manual_steps demote)
        return 0
    fi
    log_info "Demoting JIT admins with the installed daemon (${binary} --demote-jit)"
    local status=0
    serberus_run_bounded "${ONESHOT_TIMEOUT}" \
        "${ENV}" SERBERUS_DEV_KEY_FALLBACK=1 "${binary}" --demote-jit \
        2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err) || status=$?
    case "${status}" in
        0)
            log_info "JIT admins demoted"
            ;;
        3)
            log_info "No grant store — no JIT admins to demote"
            ;;
        *)
            log_error "--demote-jit FAILED (exit ${status}; 124 = timed out) — continuing the upgrade"
            while IFS= read -r line
            do
                log_error "${line}"
            done < <(serberus_daemon_manual_steps demote)
            ;;
    esac
    return 0
}

# Teardown-first, step 3: boot out a same-prefix running daemon before new
# binaries are laid down. The label stays ENABLED: a reboot before the
# postinstall brings the old daemon back, and it re-provisions its drop-in
# only once the PAM gate is wired again.
# On an upgrade (the old daemon is loaded or its plist is installed), tell the
# NEW daemon at its first start to end the JIT sessions the old one left open
# (pam-lib.sh serberus_write_upgrade_marker). Never fatal.
write_upgrade_marker() {
    if ! "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" >/dev/null 2>&1 && [[ ! -e "${LAUNCHD_PLIST}" ]]
    then
        return 0
    fi
    if serberus_write_upgrade_marker 2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    then
        log_info "Upgrade marker written (${SERBERUS_UPGRADE_MARKER})"
    else
        log_warn "Could not write the upgrade marker ${SERBERUS_UPGRADE_MARKER}"
    fi
}

bootout_daemon() {
    if "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" >/dev/null 2>&1
    then
        log_info "Booting out running daemon ${DAEMON_LABEL} (label stays enabled)"
        "${LAUNCHCTL}" bootout "system/${DAEMON_LABEL}" 2>/dev/null || true
        if ! serberus_launchd_wait_gone "${DAEMON_LABEL}" \
            2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
        then
            DAEMON_GONE=0
            log_error "${DAEMON_LABEL} is still loaded after its bootout"
        fi
    else
        log_info "Daemon not currently loaded"
    fi
}

# Rename an old com.herojoneslabs.serberus folder ($1) to its Serberus
# replacement ($2), in place, so the contents (grants.sqlite, state.plist,
# authdb snapshots, last-known-good config; or the log history) survive the
# move. Runs AFTER bootout so the daemon holds no open handles during the
# rename. If the old folder is absent this just ensures the new one exists
# (fresh install); if both exist (a partial prior migration) the old contents
# are merged into the new without clobbering newer files, then the old is
# removed. $3 is a human label for the log line.
migrate_dir() {
    local old="$1"
    local new="$2"
    local label="$3"
    if [[ -d "${old}" ]]
    then
        if [[ ! -e "${new}" ]]
        then
            log_info "Renaming ${label}: ${old} -> ${new}"
            "${MV}" "${old}" "${new}"
        else
            log_info "Both old and new ${label} exist — merging ${old} into ${new}"
            # -a preserves modes/timestamps; the trailing /. copies contents.
            # -n keeps any newer file already in the destination.
            "${CP}" -an "${old}/." "${new}/" 2>/dev/null || true
            "${RM}" -rf "${old}"
        fi
    else
        log_info "No legacy ${label} — ensuring ${new} exists"
        "${MKDIR}" -p "${new}"
    fi
}

# Break-glass preflight — READ-ONLY. It ABORTS the install in the ONE genuine
# brick case and WARNS + PROCEEDS in every survivable case. It never modifies
# anything, and it runs FIRST (before the mutating legacy uninstall + bootout),
# so an abort here strands nothing — no daemon has been booted out, no sudo
# config touched.
#
# Effective source is computed the SAME way the daemon (EffectiveConfigResolver)
# and pam_serberus (serberus_config_resolve_source) do — managed config present?
# effective mode? resolvable break-glass? snapshot file present? Decision table:
#
#   managed ABSENT, no LKG            -> BOOTSTRAP: WARN "inert until config lands", PROCEED
#   managed ABSENT, LKG EXISTS        -> LKG fallback: WARN "enforces LKG; break-glass intact", PROCEED
#   managed PRESENT + monitor|audit   -> pass-through mode: PROCEED (preflight passes)
#   managed PRESENT + enforce + resolvable bypass > 0        -> PROCEED (preflight passes)
#   managed PRESENT + enforce + empty pamBypass              -> not enforceable: WARN
#                                (LKG fallback, or inert bootstrap), PROCEED
#   managed PRESENT + enforce + bypass entries, none resolve -> **ABORT**
#
# The daemon and pam treat a config whose every bypass entry fails to resolve
# like an empty pamBypass: they fall back to the last-known-good snapshot or to
# bootstrap. Installing on top of it would still leave the Mac with no working
# break-glass until the profile is fixed, so the preinstall refuses instead of
# warning.
# Unlike the PAM-only preinstall this does NOT require the daemon to be loaded:
# the daemon is part of this same pkg and comes up in the postinstall.
preflight_break_glass() {
    local mode
    mode=$(serberus_pam_effective_mode "${MANAGED_CONFIG_PLIST}")
    local bypass_count
    bypass_count=$(serberus_pam_bypass_count "${MANAGED_CONFIG_PLIST}")
    # Unresolvable entries arrive on stderr, one per line — route them into the
    # unified log so a typo'd break-glass account is visible.
    local resolvable_count
    resolvable_count=$(serberus_pam_resolvable_bypass_count \
        "${MANAGED_CONFIG_PLIST}" \
        2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err))
    log_info "Effective config: enforcementMode=${mode} pamBypass string members=${bypass_count} resolvable=${resolvable_count}"

    # Safely enforceable (pass-through mode, or enforce with a RESOLVABLE
    # break-glass): proceed. Covers the two PRESENT+PROCEED rows.
    if serberus_pam_preflight_break_glass "${MANAGED_CONFIG_PLIST}" 2>/dev/null
    then
        log_info "Break-glass preflight passed (mode=${mode}, resolvable bypass=${resolvable_count})"
        return 0
    fi

    # Not safely enforceable: enforce (or absent config, which resolves to
    # enforce) with no pamBypass entry that RESOLVES to a real account. Split the
    # genuine brick from the survivable cases on config-present + snapshot-present.
    local config_present=1
    if serberus_pam_config_present "${MANAGED_CONFIG_PLIST}"
    then
        config_present=0
    fi

    if [[ "${config_present}" -eq 0 && "${bypass_count}" -gt 0 ]]
    then
        # THE REAL BRICK: a config is PRESENT with enforce mode AND a NON-EMPTY
        # pamBypass (bypass_count > 0), so the daemon's isEnforceable is TRUE and
        # it ADOPTS + ENFORCES this delivered config — but NONE of those bypass
        # entries resolve to a real account (resolvable_count == 0, a typo), so
        # every user is denied. An existing last-known-good snapshot does NOT save
        # you here: because isEnforceable is TRUE the daemon enforces the DELIVERED
        # config (never the snapshot) and OVERWRITES the good snapshot with this
        # typo'd one — so the abort is unconditional on the snapshot. ABORT before
        # mutating anything.
        #
        # NOTE the bypass_count > 0 gate: a PRESENT enforce config with an EMPTY
        # pamBypass is NOT a brick — the daemon reads isEnforceable == false and
        # either falls back to the last-known-good (if any) or sits in
        # awaitingConfig (pam BOOTSTRAP -> PAM_IGNORE), both inert. That case falls
        # through to the survivable WARN below.
        log_error "BREAK-GLASS PREFLIGHT FAILED — ABORTING the install (nothing has been modified)."
        log_error "The delivered config is enforce-shaped (enforcementMode=${mode}) with a"
        log_error "pamBypass that has ${bypass_count} string member(s) but ${resolvable_count} that resolve to a"
        log_error "real account. Because the bypass is non-empty the daemon ENFORCES this"
        log_error "delivered config (and OVERWRITES any last-known-good snapshot with it), with a"
        log_error "break-glass that resolves to NO account — bricking sudo and admin"
        log_error "authentication for EVERY user. Fix the pamBypass user/group names in the"
        log_error "com.herojoneslabs.serberus.config profile (each must resolve via id/"
        log_error "dscacheutil), or set enforcementMode to monitor/audit, then re-run."
        exit 1
    fi

    # Survivable. Proceed — but say exactly what the Mac will do, because the LKG
    # and no-LKG cases behave very differently.
    if [[ -f "${LKG_CONFIG_PLIST}" ]]
    then
        log_warn "BREAK-GLASS PREFLIGHT WARNING — proceeding with the install."
        log_warn "The current config is missing or not safely enforceable (enforce mode with"
        log_warn "no pamBypass user/group that resolves to a real account). This Mac HAS been"
        log_warn "configured before, so the daemon and the PAM module will both fall back to"
        log_warn "the last-known-good config at ${LKG_CONFIG_PLIST}"
        log_warn "— still ENFORCING, with its break-glass pamBypass intact. Re-scope the"
        log_warn "config profile to return the Mac to its delivered configuration."
    else
        log_warn "BREAK-GLASS PREFLIGHT WARNING — proceeding with the install."
        log_warn "No usable configuration on this Mac (no delivered config profile and no"
        log_warn "last-known-good snapshot). Installing un-configured is SAFE: Serberus stays"
        log_warn "INERT — state awaitingConfig, sudo passes through natively (pam_serberus"
        log_warn "returns PAM_IGNORE, denying nothing), no AuthorizationDB rules are written"
        log_warn "and no sudoers drop-in is provisioned — until the config profile lands. This"
        log_warn "is the normal Jamf ENROLLMENT RACE: the pkg installs before APNS delivers"
        log_warn "the profile. The daemon re-checks on its ~30s poll and picks the config up"
        log_warn "with no re-install. If the profile never arrives, Serberus never enforces:"
        log_warn "scope Support/sample-profiles/serberus-config-breakglass.mobileconfig (domain"
        log_warn "com.herojoneslabs.serberus.config) with enforcementMode and a populated"
        log_warn "pamBypass."
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

# Break-glass PREFLIGHT FIRST: it only READS config (no daemon needed). It ABORTS
# (exit 1, nothing modified) in the ONE genuine-brick case — config PRESENT +
# enforce + a non-empty pamBypass in which no entry resolves to an account —
# and WARNS + PROCEEDS otherwise (the daemon and pam_serberus then fall back to
# the last-known-good snapshot, or stay inert if this Mac has never been
# configured). It runs BEFORE the MUTATING legacy uninstall + same-prefix bootout
# precisely so an abort strands nothing: aborting AFTER a bootout would leave a
# wired sudo_local with no daemon behind it → sudo bricked. Only after the
# preflight returns 0 do we uninstall the legacy daemon and boot out a same-prefix
# running daemon.
preflight_break_glass
uninstall_legacy_daemon
remove_prerename_artifacts
# Teardown-first on an upgrade: drop-in -> unwire -> bootout (wait until gone)
# -> drop-in -> demote JIT (old binary, trusted only) -> drop-in. The drop-in
# is checked straight after the bootout (the old daemon could re-provision it
# until then) and again after the demote, which can take up to
# ONESHOT_TIMEOUT. Each step is a no-op on a fresh install.
remove_sudoers_dropin
write_upgrade_marker
unwire_sudo_local
bootout_daemon
remove_sudoers_dropin
demote_jit_with_old_daemon
remove_sudoers_dropin
# Rename com.herojoneslabs.serberus -> Serberus with the daemon stopped, so the
# payload below lands on the migrated folders and the persisted data + logs are
# preserved.
migrate_dir "${SUPPORT_DIR_OLD}" "${SUPPORT_DIR_NEW}" "support dir"
migrate_dir "${LOG_DIR_OLD}" "${LOG_DIR_NEW}" "log dir"

# Intentionally preserved across same-prefix upgrades:
#   /Library/Application Support/Serberus/state.plist
#   /Library/Application Support/Serberus/grants.sqlite

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
# Date: 2026-07-13
# Modified: 2026-09-26
# Purpose: Serberus Core TEST-RING PKG postinstall. ORDER IS THE SAFETY
#          PROPERTY and is never rearranged:
#            1. fix ownership/modes (daemon 755 root:wheel, plist 644; the
#               module's DIRECTORY CHAIN is checked first, then the module is
#               locked root:wheel 444 with -h, symlinks refused) + ensure
#               support dirs;
#            2. enable + bootstrap the DAEMON and VERIFY it is UP — the same
#               pid for 8 s with no launchd restart (a crash/AMFI-kill loop is
#               briefly "running" at every respawn), a state.plist written
#               since the bootstrap, and a healthy `serberus status`;
#            3. VALIDATE the PAM module and the SerberusAuth plugin (present,
#               444, BOTH signed by the daemon's team — a daemon with no Team
#               ID is refused — native arch present, root-only directory
#               chain);
#            4. ONLY IF the daemon runs AND the module validates, wire
#               /etc/pam.d/sudo_local (marker-aware line-merge, Serberus line
#               FIRST among the auth lines, user lines preserved).
#          On ANY failure — including an unexpected `set -e` exit, via the
#          EXIT trap — this run takes the ONE abort path: remove the sudoers
#          drop-in, UNWIRE sudo_local; if an active line SURVIVES, the daemon
#          is kept enabled and running and the script exits 1 loudly;
#          otherwise disable + bootout, demote JIT admins, restore the
#          AuthorizationDB (never by executing a daemon with no Team ID),
#          exit 1. sudo is NEVER left wired to the `requisite` module without
#          a running daemon AND a valid module behind it.
# Version: 1.6 - (a) The abort path disables the daemon after sudo_local is
#          unwired, right before the bootout, and runs the one-shots only
#          once launchd has dropped the job (waited for up to its 20 s
#          ExitTimeOut). (b) The state.plist freshness mark is taken right
#          before `kickstart -k`, so a state the killed first instance wrote
#          never counts. (c) A stray /usr/local/lib/pam/pam_serberus.so.2
#          (OpenPAM loads it in place of the module) is removed before
#          sudo_local is wired; one that cannot be removed aborts.
#          1.5 - (a) The daemon is trusted (and executed by the abort path)
#          only through serberus_daemon_trusted: strict signature, Apple
#          anchor, identifier com.herojoneslabs.serberus.daemon and its Team ID
#          — a TeamIdentifier string alone no longer counts. (b) Liveness adds
#          the bootstrap mark: a fresh state.plist, no restart during the 8 s
#          window; the pid is re-read right before sudo_local is merged. (c) A
#          sudoers drop-in that survives its removal stops the abort path
#          before sudo_local is unwired. (d) fix_ownership and the sudo_local
#          chown/chmod check every step. (e) --demote-jit exit 3 (no grant
#          store) is informational.
#          1.4 - EXIT trap runs the abort path on any exit without the
#          success marker; abort keeps the daemon running when an active
#          pam_serberus line survives the unwire; stable-pid + `serberus
#          status` liveness; module chain checked BEFORE chown/chmod (-h);
#          NO ad-hoc fallback — the daemon must carry a Team ID and pins the
#          module AND SerberusAuth.bundle; a team-less daemon is never
#          executed for --demote-jit/--restore-authdb; one-shots bounded
#          (120 s) with SERBERUS_DEV_KEY_FALLBACK exported as the
#          LaunchDaemon sets it; umask 022; refuses a target volume other
#          than "/" ($3); warns when /etc/pam.d/sudo does not include
#          sudo_local first.
#          1.3 - Enable before bootstrap; "up" means a running pid, not a
#          loaded job; the module must be signed by the daemon's team
#          (falls back to --strict with a warning when the daemon is
#          ad-hoc — TEST ring only) and live in a root-only directory chain;
#          every abort disables + boots out the daemon and removes the
#          sudoers drop-in. System-only PATH, absolute tools.
#          1.2 - best-effort Intel app ownership/verify (STEP 5, since retired)
#          1.1 - Module arch validation (criterion 3) now uses file(1) instead
#          of lipo. lipo ships ONLY with the Xcode Command Line Tools, which a
#          managed endpoint does not carry — /usr/bin/lipo is a non-functional
#          xcrun shim there and exits non-zero, so criterion 3 aborted the
#          install on every Mac without the Command Line Tools (criterion 3
#          failed with "lipo cannot read"). file(1) is base macOS.
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
readonly CODESIGN="/usr/bin/codesign"
readonly DIRNAME="/usr/bin/dirname"
readonly ENV="/usr/bin/env"
readonly FILE="/usr/bin/file"
readonly ID="/usr/bin/id"
readonly KILLALL="/usr/bin/killall"
readonly LAUNCHCTL="/bin/launchctl"
readonly LOGGER="/usr/bin/logger"
readonly MKDIR="/bin/mkdir"
readonly PLUTIL="/usr/bin/plutil"
readonly SLEEP="/bin/sleep"
readonly STAT="/usr/bin/stat"
readonly UNAME="/usr/bin/uname"
readonly PLIST_BUDDY="/usr/libexec/PlistBuddy"

readonly ORG_PLIST_DOMAIN="com.herojoneslabs.serberus"
readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.6"
readonly LOG_LABEL="${ORG_PLIST_DOMAIN}.sentineltest-postinstall"

##################################
### End Core Defined Variables ###
##################################

########################################
######## User Defined Variables ########
### Place your script variables here ###
########################################

readonly DAEMON_LABEL="com.herojoneslabs.serberus.daemon"
readonly DAEMON_BINARY="/Library/PrivilegedHelperTools/com.herojoneslabs.serberus.daemon"
readonly LAUNCHD_PLIST="/Library/LaunchDaemons/com.herojoneslabs.serberus.daemon.plist"
readonly SUPPORT_DIR="/Library/Application Support/Serberus"
readonly LOG_DIR="/Library/Logs/Serberus"
readonly AUTHDB_BACKUPS="${SUPPORT_DIR}/authdb-backups"
readonly UNINSTALL_HELPER="${SUPPORT_DIR}/uninstall-serberus-sentinel-test.sh"
readonly INSTALLED_PAM_LIB="${SUPPORT_DIR}/pam-lib.sh"
# The authorization plugin this pkg ships; pinned to the daemon's team.
readonly AUTH_PLUGIN="/Library/Security/SecurityAgentPlugins/SerberusAuth.bundle"
# The serberus CLI (payload). `serberus status` is part of the "up" check.
readonly CLI_BINARY="/usr/local/bin/serberus"
# Written by the daemon at startup; only a copy newer than the bootstrap mark
# proves THIS daemon came up.
readonly STATE_PLIST="/Library/Application Support/Serberus/state.plist"
# Seconds to wait (each) for the job to load and then to hold a running pid.
readonly DAEMON_START_TIMEOUT=10
# Hard deadline for each daemon one-shot (--demote-jit, --restore-authdb).
readonly ONESHOT_TIMEOUT=120

# /usr/lib/pam is on the SEALED read-only system snapshot (macOS 11+); the
# module lives under the /usr/local firmlink and sudo_local references it by
# absolute path (pam-lib.sh SERBERUS_PAM_MODULE_PATH — keep in sync).
readonly PAM_MODULE_DIR="/usr/local/lib/pam"
readonly PAM_MODULE="${PAM_MODULE_DIR}/pam_serberus.so"
readonly SUDO_LOCAL="/etc/pam.d/sudo_local"
readonly PAM_SUDO="/etc/pam.d/sudo"

# Installer passes the target volume as $3.
readonly TARGET_VOLUME="${3:-}"

# Success marker: set right before the final exit 0. The EXIT trap runs the
# abort path whenever the script ends without it.
INSTALL_SUCCEEDED=0
ABORT_IN_PROGRESS=0
# Set by daemon_payload_ok: the daemon passes serberus_daemon_trusted with
# its Team ID. Until then (and when it does not) the abort path never
# EXECUTES the daemon binary.
DAEMON_TRUSTED=0
DAEMON_TEAM=""
# Epoch seconds taken right before `launchctl bootstrap`.
BOOTSTRAP_MARK=""
# Set to 0 when the booted-out daemon is still loaded after its ExitTimeOut;
# the abort path then skips the one-shots and logs the manual steps.
DAEMON_GONE=1

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

# Serberus rewires THIS Mac's sudo and AuthorizationDB; installing onto any
# other volume is refused.
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

# pkgbuild ships every file in the scripts dir alongside this script. pam-lib.sh
# supplies the safety-critical sudo_local merge/rollback — refuse to wire
# anything without it.
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

# Any exit without the success marker — a failed ensure_directories or
# fix_ownership, or any other `set -e` casualty — takes the abort path.
on_exit() {
    local status=$?
    if [[ "${INSTALL_SUCCEEDED}" -eq 1 || "${ABORT_IN_PROGRESS}" -eq 1 ]]
    then
        return 0
    fi
    abort_install "unexpected exit (status ${status}) before the install completed"
}

ensure_directories() {
    local dir
    for dir in "${SUPPORT_DIR}" "${AUTHDB_BACKUPS}" "${LOG_DIR}"
    do
        "${MKDIR}" -p "${dir}"
    done
    "${CHOWN}" root:wheel "${SUPPORT_DIR}" "${LOG_DIR}"
    "${CHMOD}" 755 "${SUPPORT_DIR}"
    "${CHMOD}" 755 "${LOG_DIR}"
    "${CHMOD}" 700 "${AUTHDB_BACKUPS}"
}

# STEP 1 — belt and braces: the pkg is built non-root with `recommended`
# ownership, so re-assert exact ownership/modes before anything is
# bootstrapped/validated. The module's DIRECTORY chain is checked FIRST and
# the module is then locked with -h — root never chowns/chmods inside a
# directory a user controls, and never through a symlink.
# Each step is checked on its own (this runs under `if !`, where set -e does
# not apply), so a failed chown is never hidden by a chmod after it.
fix_ownership() {
    "${CHOWN}" -h root:wheel "${DAEMON_BINARY}" "${LAUNCHD_PLIST}" || return 1
    "${CHMOD}" -h 755 "${DAEMON_BINARY}" || return 1
    "${CHMOD}" -h 644 "${LAUNCHD_PLIST}" || return 1

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

    local helper
    for helper in "${UNINSTALL_HELPER}" "${INSTALLED_PAM_LIB}"
    do
        if [[ -f "${helper}" && ! -L "${helper}" ]]
        then
            "${CHOWN}" -h root:wheel "${helper}" || return 1
        fi
    done
    if [[ -f "${UNINSTALL_HELPER}" && ! -L "${UNINSTALL_HELPER}" ]]
    then
        "${CHMOD}" -h 755 "${UNINSTALL_HELPER}" || return 1
    fi
    if [[ -f "${INSTALLED_PAM_LIB}" && ! -L "${INSTALLED_PAM_LIB}" ]]
    then
        "${CHMOD}" -h 644 "${INSTALLED_PAM_LIB}" || return 1
    fi
    if [[ -d "${AUTH_PLUGIN}" && ! -L "${AUTH_PLUGIN}" ]]
    then
        # -R without -H/-L never follows symlinks inside the bundle.
        "${CHOWN}" -R root:wheel "${AUTH_PLUGIN}" || return 1
        "${CHMOD}" -R go-w "${AUTH_PLUGIN}" || return 1
    fi
    return 0
}

# Basic daemon payload sanity used before bootstrap (mirrors build-test-pkg.sh),
# plus the Team ID the module and plugin are pinned to. No ad-hoc fallback:
# a daemon without a Team ID is refused, and never executed by the abort path.
daemon_payload_ok() {
    local ok=0
    if [[ ! -f "${DAEMON_BINARY}" ]] || [[ "$(file_mode "${DAEMON_BINARY}")" != "755" ]]
    then
        log_error "daemon binary missing or not mode 755"
        ok=1
    fi
    if [[ ! -f "${LAUNCHD_PLIST}" ]] || ! "${PLUTIL}" -lint "${LAUNCHD_PLIST}" >/dev/null 2>&1
    then
        log_error "LaunchDaemon plist missing or unparseable"
        ok=1
    fi
    if ! "${PLIST_BUDDY}" -c "Print :KeepAlive" "${LAUNCHD_PLIST}" >/dev/null 2>&1 \
        || ! "${PLIST_BUDDY}" -c "Print :ThrottleInterval" "${LAUNCHD_PLIST}" >/dev/null 2>&1
    then
        log_error "plist missing KeepAlive/ThrottleInterval"
        ok=1
    fi
    # The daemon must carry a Team ID AND pass serberus_daemon_trusted with it
    # (strict signature, Apple anchor, identifier
    # com.herojoneslabs.serberus.daemon). A TeamIdentifier string alone is not
    # a verified signature; only a trusted daemon is ever executed.
    if DAEMON_TEAM=$(serberus_codesign_team_id "${DAEMON_BINARY}") \
        && serberus_daemon_trusted "${DAEMON_BINARY}" "${DAEMON_TEAM}" \
            2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    then
        DAEMON_TRUSTED=1
    else
        DAEMON_TEAM=""
        DAEMON_TRUSTED=0
        log_error "daemon is ad-hoc, carries no Team ID, or fails its strict signature/identifier check — refused (the module and the SerberusAuth plugin are pinned to the daemon's team)"
        ok=1
    fi
    return ${ok}
}

# STEP 2 — enable + bootstrap the daemon and VERIFY it is UP. Returns
# nonzero if the payload is bad, bootstrap fails, the job never loads, or no
# pid holds for the stability window / `serberus status` fails.
bootstrap_and_verify_daemon() {
    if ! daemon_payload_ok
    then
        return 1
    fi

    if "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" >/dev/null 2>&1
    then
        "${LAUNCHCTL}" bootout "system/${DAEMON_LABEL}" 2>/dev/null || true
        serberus_launchd_wait_gone "${DAEMON_LABEL}" \
            2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err) || true
    fi

    # An earlier uninstall or abort leaves the label DISABLED, and bootstrap
    # refuses a disabled service — enable first.
    "${LAUNCHCTL}" enable "system/${DAEMON_LABEL}" 2>/dev/null \
        || log_warn "launchctl enable system/${DAEMON_LABEL} failed"

    log_info "Bootstrapping ${DAEMON_LABEL}"
    # Taken BEFORE the bootstrap: only a state.plist written after it counts.
    BOOTSTRAP_MARK=$(serberus_launchd_bootstrap_mark)
    if ! "${LAUNCHCTL}" bootstrap system "${LAUNCHD_PLIST}"
    then
        log_error "launchctl bootstrap failed"
        return 1
    fi

    # VERIFY loaded — poll launchctl print (RunAtLoad + KeepAlive; give launchd
    # a moment to register the job).
    local attempt
    local loaded=1
    for ((attempt = 0; attempt < DAEMON_START_TIMEOUT; attempt++))
    do
        if "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" >/dev/null 2>&1
        then
            loaded=0
            break
        fi
        "${SLEEP}" 1
    done
    if [[ "${loaded}" -ne 0 ]]
    then
        log_error "Daemon ${DAEMON_LABEL} did not appear in launchd after bootstrap"
        return 1
    fi

    # Force the RUNNING instance to be the FRESHLY-INSTALLED binary.
    # `bootout`+`bootstrap` normally suffices, but KeepAlive can relaunch the
    # PRIOR binary in the bootout→payload→bootstrap window, so an upgrade could
    # keep executing old code until a manual `kickstart`. `-k` kills the current instance and relaunches from the
    # on-disk (new) binary, and it also re-reads managed preferences fresh.
    log_info "Kickstarting ${DAEMON_LABEL} onto the freshly-installed binary"
    # A fresh mark right before the kill: a state.plist the first instance
    # wrote before `kickstart -k` ended it must not count as this daemon's.
    BOOTSTRAP_MARK=$(serberus_launchd_bootstrap_mark)
    if ! "${LAUNCHCTL}" kickstart -k "system/${DAEMON_LABEL}" 2>/dev/null
    then
        log_warn "kickstart -k failed; daemon is loaded but may run the prior binary until it is next restarted"
    fi

    # One pid held for 8 s with no launchd restart (a kill loop is briefly
    # "running" at each respawn), a state.plist written since the kickstart,
    # and a fresh `serberus status` (the CLI ships in this pkg, so a missing
    # one fails). The kickstart above ended the first instance itself, so its
    # SIGTERM is not held against the job (last argument 0); a restart after
    # that still is.
    if ! serberus_launchd_wait_running "${DAEMON_LABEL}" "${DAEMON_START_TIMEOUT}" "${CLI_BINARY}" "${DAEMON_TEAM}" \
        "${STATE_PLIST}" "${BOOTSTRAP_MARK}" 0 \
        2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    then
        log_error "Daemon ${DAEMON_LABEL} never came up (no stable pid, a restart, no fresh state.plist, or serberus status failed — crash or AMFI kill loop?)"
        return 1
    fi
    log_info "Daemon ${DAEMON_LABEL} is running (pid ${SERBERUS_LAUNCHD_UP_PID})"
    return 0
}

# The arch sudo demands on this Mac (sudo runs arm64e on Apple silicon; a plain
# arm64 module slice satisfies it).
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

# Criterion 2 — the module must be signed by the SAME team as the installed
# daemon: `--verify --strict` alone accepts anyone's valid signature, and sudo
# loads this module as root. There is no ad-hoc fallback: a team-less daemon
# was already refused by daemon_payload_ok.
module_signature_ok() {
    if [[ -z "${DAEMON_TEAM}" ]]
    then
        log_error "criterion 2 FAIL: no daemon Team ID to verify the PAM module against"
        return 1
    fi
    if serberus_codesign_satisfies_team "${PAM_MODULE}" "${DAEMON_TEAM}"
    then
        return 0
    fi
    log_error "criterion 2 FAIL: PAM module is not validly signed by the daemon's team ${DAEMON_TEAM}"
    return 1
}

# STEP 3 — validate the PAM module (and the SerberusAuth plugin) BEFORE
# sudo_local is touched. A module that cannot dlopen inside sudo's
# `requisite` line bricks sudo for everyone.
module_validation_passes() {
    local ok=0

    if [[ ! -f "${PAM_MODULE}" ]] || [[ "$(file_mode "${PAM_MODULE}")" != "444" ]]
    then
        log_error "criterion 1 FAIL: PAM module missing or not mode 444"
        ok=1
    fi

    if ! module_signature_ok
    then
        ok=1
    fi

    # Arch coverage is checked with file(1), NOT lipo. lipo ships ONLY with the
    # Xcode Command Line Tools, which a managed endpoint (test ring or
    # production) does not have — /usr/bin/lipo is then a non-functional xcrun
    # shim that exits non-zero, so this criterion would FAIL on every Mac
    # without them. file(1) is base macOS (no CLT dependency) and its Mach-O
    # description names every slice's architecture.
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

    # Criterion 4 — /usr … /usr/local/lib/pam and the module root-owned, not
    # group/other-writable, no symlinks (an Intel Homebrew layout fails here).
    if ! serberus_pam_module_path_is_safe "${PAM_MODULE}" \
        2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
    then
        log_error "criterion 4 FAIL: the module's directory chain is not root-only — refusing to wire sudo_local"
        ok=1
    fi

    # Criterion 5 — the SerberusAuth plugin this pkg ships is present and
    # signed by the daemon's team (SecurityAgent loads it into every
    # authorization an identity-scoped rule composes).
    if [[ ! -d "${AUTH_PLUGIN}" ]] || [[ -L "${AUTH_PLUGIN}" ]]
    then
        log_error "criterion 5 FAIL: authorization plugin ${AUTH_PLUGIN} missing (or a symlink)"
        ok=1
    elif [[ -z "${DAEMON_TEAM}" ]] \
        || ! serberus_codesign_satisfies_team "${AUTH_PLUGIN}" "${DAEMON_TEAM}"
    then
        log_error "criterion 5 FAIL: authorization plugin is not validly signed by the daemon's team"
        ok=1
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

# ---- The ONE abort path (same ORDER as the uninstall helper) ----

# Disabled only after sudo_local is unwired, right before the bootout: an
# abort interrupted between a disable and the unwire would leave sudo_local
# wired behind a daemon launchd never starts.
disable_daemon() {
    "${LAUNCHCTL}" disable "system/${DAEMON_LABEL}" 2>/dev/null \
        || log_warn "launchctl disable system/${DAEMON_LABEL} failed"
}

# Returns 1 when the drop-in is STILL there: the caller must not unwire.
remove_sudoers_dropin() {
    local result
    result=$(serberus_pam_remove_sudoers_dropin) || result="FAILED"
    log_error "abort path: sudoers drop-in removal result=${result}"
    [[ "${result}" != "FAILED" ]]
}

# Routes serberus_daemon_manual_steps into the log. $1 demote | restore | sudoers
log_manual_steps() {
    local line
    while IFS= read -r line
    do
        log_error "${line}"
    done < <(serberus_daemon_manual_steps "$1" "${AUTHDB_BACKUPS}")
}

# A PREVIOUS install may have left /etc/pam.d/sudo_local wired to
# pam_serberus.so (the preinstall unwires it on an upgrade, but it can have
# been re-wired by hand or by another pkg since). This run wires sudo_local
# LAST, so on every abort the newly laid module is not known-good or the
# daemon never came up. Marker-aware (pam-lib.sh): user PAM lines survive,
# legacy bare-name lines are stripped too, the file is deleted only if
# Serberus created it, and a FRESH install (nothing wired) is left
# byte-identical. Returns 1 when an ACTIVE line SURVIVES.
unwire_sudo_local() {
    if ! serberus_pam_sudo_local_has_module "${SUDO_LOCAL}"
    then
        log_info "abort path: no active pam_serberus.so line in ${SUDO_LOCAL} — nothing to unwire"
        return 0
    fi
    local result
    # `|| result=FAILED` keeps a failure from short-circuiting the abort path.
    result=$(serberus_pam_remove_sudo_local "${SUDO_LOCAL}") || result="FAILED"
    log_error "abort path: unwired sudo_local (result=${result}, ${SUDO_LOCAL})"
    if serberus_pam_sudo_local_has_module "${SUDO_LOCAL}"
    then
        return 1
    fi
    return 0
}

bootout_daemon() {
    if "${LAUNCHCTL}" print "system/${DAEMON_LABEL}" >/dev/null 2>&1
    then
        "${LAUNCHCTL}" bootout "system/${DAEMON_LABEL}" 2>/dev/null || true
        if ! serberus_launchd_wait_gone "${DAEMON_LABEL}" \
            2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
        then
            DAEMON_GONE=0
            log_error "abort path: ${DAEMON_LABEL} is still loaded after its bootout"
        fi
    fi
}

# OpenPAM loads "<module>.2" in preference to the module itself; a stray
# pam_serberus.so.2 is what sudo would run. Returns 1 when one could not be
# removed.
remove_versioned_module() {
    local result
    result=$(serberus_pam_remove_versioned_module) || result="FAILED"
    if [[ "${result}" != "absent" ]]
    then
        log_info "stray ${SERBERUS_PAM_MODULE_VERSIONED_PATH}: ${result}"
    fi
    [[ "${result}" != "FAILED" ]]
}

# Runs a daemon one-shot with the deadline. SERBERUS_DEV_KEY_FALLBACK=1 is
# what this ring's LaunchDaemon sets, so the one-shot finds the same keys.
run_daemon_oneshot() {
    serberus_run_bounded "${ONESHOT_TIMEOUT}" \
        "${ENV}" SERBERUS_DEV_KEY_FALLBACK=1 "${DAEMON_BINARY}" "$1" \
        2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
}

# With the daemon disabled nothing expires a JIT grant — demote now, but never
# by executing a daemon that failed validation. Exit 3 = no grant store.
demote_jit_admins() {
    if [[ "${DAEMON_GONE}" -ne 1 ]]
    then
        log_error "abort path: the daemon is still loaded — NOT running --demote-jit beside it."
        log_manual_steps demote
        return 0
    fi
    if [[ "${DAEMON_TRUSTED}" -ne 1 || ! -x "${DAEMON_BINARY}" ]]
    then
        log_error "abort path: the daemon failed validation or is missing — NOT executing it."
        log_manual_steps demote
        return 0
    fi
    local status=0
    run_daemon_oneshot --demote-jit || status=$?
    case "${status}" in
        0)
            log_info "abort path: JIT admins demoted"
            ;;
        3)
            log_info "abort path: no grant store — no JIT admins to demote"
            ;;
        *)
            log_error "abort path: --demote-jit FAILED (exit ${status}; 124 = timed out)"
            log_manual_steps demote
            ;;
    esac
}

# Restore the AuthorizationDB from snapshots (the daemon may have applied
# authuri rewrites on a previous run).
restore_authdb() {
    if [[ "${DAEMON_GONE}" -ne 1 ]]
    then
        log_error "abort path: the daemon is still loaded — NOT running --restore-authdb beside it."
        log_manual_steps restore
        return 0
    fi
    if [[ "${DAEMON_TRUSTED}" -ne 1 || ! -x "${DAEMON_BINARY}" ]]
    then
        log_error "abort path: the daemon failed validation or is missing — NOT executing it for --restore-authdb."
        log_manual_steps restore
        return 0
    fi
    local status=0
    run_daemon_oneshot --restore-authdb || status=$?
    if [[ "${status}" -ne 0 ]]
    then
        log_error "abort path: authdb restore FAILED (exit ${status}; 124 = timed out) — review ${AUTHDB_BACKUPS}"
    fi
}

# drop-in (a SURVIVING drop-in re-arms the daemon and stops here, before the
# PAM gate is touched) -> unwire (a SURVIVING line re-arms the daemon and
# stops here) -> disable -> bootout (wait until gone) -> drop-in again ->
# demote JIT -> restore authdb -> exit 1.
# A reboot cannot resurrect an ungated daemon.
abort_install() {
    ABORT_IN_PROGRESS=1
    set +e
    log_error "ABORTING: $*"
    if ! remove_sudoers_dropin
    then
        log_error "!!! The Serberus sudoers drop-in SURVIVED its removal — NOT unwiring ${SUDO_LOCAL}."
        log_manual_steps sudoers
        serberus_daemon_rearm_if_wired "${SUDO_LOCAL}" "${DAEMON_LABEL}" "${LAUNCHD_PLIST}" \
            2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
        exit 1
    fi
    if ! unwire_sudo_local
    then
        log_error "!!! An ACTIVE pam_serberus line SURVIVED the unwire in ${SUDO_LOCAL}."
        log_error "!!! Keeping ${DAEMON_LABEL} ENABLED and RUNNING behind it (a wired module with no"
        log_error "!!! daemon denies every sudo). Remove the line by hand, then run ${UNINSTALL_HELPER}."
        serberus_daemon_rearm_if_wired "${SUDO_LOCAL}" "${DAEMON_LABEL}" "${LAUNCHD_PLIST}" \
            2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
        exit 1
    fi
    disable_daemon
    bootout_daemon
    if ! remove_sudoers_dropin
    then
        log_manual_steps sudoers
    fi
    demote_jit_admins
    restore_authdb
    exit 1
}

# STEP 4 — wire sudo_local. Reached ONLY after the daemon is verified up AND
# the module validates. Marker-aware merge with post-merge sanity + rollback.
wire_sudo_local() {
    local merge_result
    merge_result=$(serberus_pam_merge_sudo_local "${SUDO_LOCAL}") || merge_result="FAILED"
    log_info "sudo_local merge: ${merge_result} (${SUDO_LOCAL})"

    # Post-merge sanity: the file must be canonical (one active `requisite`
    # line, FIRST among the auth lines — what the daemon requires before it
    # writes the sudoers drop-in). If not, roll back exactly what this run
    # added (marker-aware: the file is deleted only if this run created it).
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
ensure_directories

# STEP 1: ownership/modes for daemon + module (directory chain first).
if ! fix_ownership
then
    abort_install "module directory chain is not root-only, or the module could not be locked"
fi

# STEP 2: enable + bootstrap the daemon and verify it is UP. On failure,
# abort: drop-in, unwire (a survivor keeps the daemon running), disable,
# bootout, demote JIT, restore the AuthorizationDB. This run never wires
# sudo_local before this point (it is wired LAST).
if ! bootstrap_and_verify_daemon
then
    abort_install "daemon failed validation, failed to bootstrap, or never came up"
fi

# STEP 3: validate the PAM module + plugin. The daemon is up, but the
# newly-laid module is not known-good: stop the daemon too (never leave a
# daemon a reboot brings back without its gate) and self-heal a prior
# sudo_local.
if ! module_validation_passes
then
    abort_install "PAM module / plugin validation failed — newly-laid module not known-good"
fi

check_pam_sudo_includes_sudo_local

if ! remove_versioned_module
then
    abort_install "could not remove ${SERBERUS_PAM_MODULE_VERSIONED_PATH}, which OpenPAM would load in place of the module"
fi

# STEP 4: both halves are healthy — wire sudo_local (last mutating step of the
# sudo chain, and the last step that can fail this install). Last look first:
# still the daemon process that was confirmed up.
if ! serberus_launchd_pid_unchanged "${DAEMON_LABEL}" 2> >("${LOGGER}" -t "${LOG_LABEL}" -p user.err)
then
    abort_install "${DAEMON_LABEL} restarted after it was confirmed up"
fi
if ! wire_sudo_local
then
    abort_install "sudo_local wiring failed"
fi

# The authorization plugin hosts cache loaded plugin code. They are transient
# (one per evaluation), so killing them simply makes the NEXT authorization map
# the freshly installed bundle instead of a cached copy of the old one. Purely
# best-effort: if they are not running there is nothing to do, and the next
# evaluation spawns them anyway.
"${KILLALL}" SecurityAgent authorizationhost 2>/dev/null || true

INSTALL_SUCCEEDED=1
log_info "pam_serberus.so wired and daemon running. Verify from a NEW terminal: sudo /usr/bin/true"
log_info "Teardown: sudo \"${UNINSTALL_HELPER}\" [--purge]"
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

# The generated scripts source pam-lib.sh from their own directory (pkgbuild
# ships every file in --scripts alongside them).
stage_pam_lib() {
    "${CP}" "${PAM_LIB_SRC}" "${SCRIPTS_DIR}/${PAM_LIB_NAME}"
    "${CHMOD}" 644 "${SCRIPTS_DIR}/${PAM_LIB_NAME}"

    if ! "${BASH_BIN}" -n "${SCRIPTS_DIR}/${PAM_LIB_NAME}"
    then
        log_error "pam-lib.sh failed bash -n: ${SCRIPTS_DIR}/${PAM_LIB_NAME}"
        exit 1
    fi
}

# pkgbuild's default lets PackageKit "relocate" a bundle onto ANY copy of it
# LaunchServices already knows about (a dev build in a working copy, a copy on
# the Desktop…) instead of the payload path — SerberusAuth.bundle would then
# not land in /Library/Security/SecurityAgentPlugins. Pin every bundle
# pkgbuild --analyze finds to BundleIsRelocatable=false (same approach as
# build-authuribrowser-pkg.sh).
write_component_plist() {
    "${PKGBUILD}" --analyze --root "${PAYLOAD_DIR}" "${COMPONENT_PLIST}" >/dev/null
    local index=0
    while "${PLIST_BUDDY}" -c "Print :${index}" "${COMPONENT_PLIST}" >/dev/null 2>&1
    do
        if ! "${PLIST_BUDDY}" -c "Set :${index}:BundleIsRelocatable false" "${COMPONENT_PLIST}" 2>/dev/null
        then
            "${PLIST_BUDDY}" -c "Add :${index}:BundleIsRelocatable bool false" "${COMPONENT_PLIST}"
        fi
        index=$((index + 1))
    done
    if [[ "${index}" -eq 0 ]]
    then
        log_error "pkgbuild --analyze found no bundle in ${PAYLOAD_DIR} (expected ${AUTH_PLUGIN_NAME})"
        exit 1
    fi
    if "${PLIST_BUDDY}" -c 'Print' "${COMPONENT_PLIST}" | "${GREP}" -q 'BundleIsRelocatable = true'
    then
        log_error "Component plist still marks a bundle relocatable: ${COMPONENT_PLIST}"
        exit 1
    fi
    log_info "Component plist: ${index} bundle(s) pinned non-relocatable"
}

build_package() {
    # Default `recommended` ownership (no --ownership flag): the pkg is built as
    # the user; Installer maps /usr/local and /Library to root:wheel and the
    # postinstall re-asserts exact ownership/modes.
    #
    # No xattr strip here: assemble_payload already stripped, PAYLOAD_DIR lives
    # outside any cloud-synced folder so nothing re-stamps it, and the PAM
    # module is 444 by this point — `xattr -c` on a read-only file fails with
    # EACCES.
    write_component_plist
    log_info "Building component pkg ${OUTPUT_PKG}"
    # No --filter for AppleDouble: `._*` entries are not files on disk (the
    # payload tree contains none), they are SYNTHESIZED by pkgbuild from each
    # member's extended attributes — so there is no path for a filter to match.
    # The only way to not ship them is to not have the xattrs, and
    # com.apple.provenance is re-applied by macOS itself and cannot be kept off.
    # That is why the payload is staged outside cloud-synced folders instead:
    # provenance is harmless (codesign permits it; the daemon and .so have
    # always shipped with `._` siblings), whereas a sync provider's FinderInfo
    # is what codesign rejects.
    "${PKGBUILD}" \
        --root "${PAYLOAD_DIR}" \
        --component-plist "${COMPONENT_PLIST}" \
        --scripts "${SCRIPTS_DIR}" \
        --identifier "${PKG_IDENTIFIER}" \
        --version "${PKG_VERSION}" \
        "${OUTPUT_PKG}"
    log_info "Built ${OUTPUT_PKG}"
    # The daemon Mach-O and pam_serberus.so signatures are embedded — not
    # xattr-stored — and are verified inline in assemble_payload together with
    # the SerberusAuth.bundle seal, so nothing here re-checks them.
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
    log_info "COMBINED (Core) TEST-RING pkg ready: ${pkg}"
    log_info "Contains: ${INSTALL_BINARY_PATH} (daemon, Apple-Dev signed),"
    log_info "          /Library/LaunchDaemons/${BUNDLE_ID}.plist,"
    log_info "          /usr/local/lib/pam/pam_serberus.so (identifier ${PAM_IDENTIFIER}),"
    log_info "          ${SUPPORT_DIR}/${PAM_LIB_NAME},"
    log_info "          ${SUPPORT_DIR}/${UNINSTALL_HELPER_NAME}"
    log_info "          (Serberus Intel retired — its UI is now the Sentinel window's Intel tab.)"
    log_info "ORDER:    preinstall break-glass preflight -> postinstall daemon-running ->"
    log_info "          module-validate -> wire sudo_local (never before both are healthy)."
    log_info "ORDERING: scoping the break-glass config profile before this pkg is preferred,"
    log_info "          not required — with no usable config Serberus installs INERT"
    log_info "          (awaitingConfig: sudo passes through, nothing is mutated) and adopts"
    log_info "          the profile on its next poll. The preinstall WARNS, and aborts only"
    log_info "          on a present enforce config whose pamBypass resolves to nobody."
    log_info "Verify:   sudo launchctl print system/${DAEMON_LABEL}"
    log_info "          from a NEW terminal: sudo /usr/bin/true"
    log_info "Teardown: sudo \"${SUPPORT_DIR}/${UNINSTALL_HELPER_NAME}\" [--purge]"
    log_info "Receipt:  pkgutil --pkg-info ${PKG_IDENTIFIER}"
    log_info "NOT for production — use build-pkg.sh (notarized full payload) instead."
    log_info "──────────────────────────────────────────────────────────────"
}

run_self_test() {
    local test_script="${SCRIPT_DIR}/tests/test-sentinel-lib.sh"
    if [[ ! -f "${test_script}" ]]
    then
        log_error "Test harness not found: ${test_script}"
        exit 1
    fi
    log_info "Running ${test_script}"
    "${BASH_BIN}" "${test_script}"
}

# Test-harness hook: generate every script (preinstall, postinstall, uninstall
# helper, staged pam-lib) into BUILD_DIR without compiling or signing anything,
# so the harness can bash -n and exercise the ordering invariants.
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
        # STAGING_DIR (payload + scripts, outside cloud-synced folders) and BUILD_DIR (the
        # finished .pkg) are separate trees for --build, so both are cleaned.
        "${RM}" -rf "${BUILD_DIR}" "${STAGING_DIR}"
        "${MKDIR}" -p "${BUILD_DIR}" "${STAGING_DIR}" "${SCRIPTS_DIR}"
        build_daemon
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
