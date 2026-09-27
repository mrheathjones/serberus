#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: build-pam-target.sh
# Author: Heath Jones
# Date: 2026-07-18
# Modified: 2026-09-25
# Purpose: Build pam_serberus.so for the pam_serberus Xcode target. PAM
#          modules are flat Mach-O bundles (pam_serberus.so), which Xcode's
#          product types don't emit directly, so this target compiles it with
#          clang into the build products directory. Invoked by Xcode with the
#          build settings in the environment (BUILT_PRODUCTS_DIR, SRCROOT,
#          ACTION, ...).
# Version: 1.1 - Standard information block; tools by absolute path (the
#          Xcode tools through their /usr/bin shims); links Security.framework
#          (the module pins the daemon peer's code requirement).
#          1.0 - Initial Script
#
######################################################################
############## End Script Information Block ##########################
######################################################################

set -euo pipefail

# System directories only; every tool below is called by absolute path.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

readonly CLANG="/usr/bin/clang"
readonly CODESIGN="/usr/bin/codesign"
readonly LIPO="/usr/bin/lipo"
readonly MKDIR="/bin/mkdir"
readonly RM="/bin/rm"

SRCROOT="${SRCROOT:-$(pwd)}"
BUILT_PRODUCTS_DIR="${BUILT_PRODUCTS_DIR:-${SRCROOT}/.build/pam}"
OUT="${BUILT_PRODUCTS_DIR}/pam_serberus.so"

if [[ "${ACTION:-build}" == "clean" ]]
then
    "${RM}" -f "${OUT}"
    printf 'cleaned %s\n' "${OUT}"
    exit 0
fi

"${MKDIR}" -p "${BUILT_PRODUCTS_DIR}"
"${CLANG}" -arch arm64 -arch x86_64 -O2 -Wall -Wextra -bundle \
    -o "${OUT}" \
    "${SRCROOT}/Sources/pam_serberus/pam_serberus.c" \
    "${SRCROOT}/Sources/pam_serberus/pam_config.c" \
    "${SRCROOT}/Sources/pam_serberus/sudo_args.c" \
    -I"${SRCROOT}/Sources/SerberusXPCShim/include" \
    -framework CoreFoundation \
    -framework Security \
    -lpam

# Ad-hoc sign for local use; production re-signs with the Developer ID.
# The explicit identifier (BundleConfig.pamBundleID) just keeps every build
# named the same — a flat .so otherwise derives it from the filename. The
# daemon never checks it: the module runs inside sudo, and the daemon
# validates sudo itself as the XPC caller.
"${CODESIGN}" --force --sign - \
    --identifier com.herojoneslabs.serberus.pam \
    "${OUT}" 2>/dev/null || true

# The production pipeline (PKG/build-pkg.sh) packages exactly this artifact.
# A thin module dlopen-fails inside the `requisite` PAM line on the missing
# arch -> sudo bricked fleet-wide on that hardware. Fail the build instead.
archs=$("${LIPO}" -archs "${OUT}")
for needed in arm64 x86_64
do
    case " ${archs} " in
        *" ${needed} "*)
            ;;
        *)
            printf 'error: %s is missing the %s slice (has: %s)\n' "${OUT}" "${needed}" "${archs}" >&2
            exit 1
            ;;
    esac
done
printf 'built %s (%s)\n' "${OUT}" "${archs}"
