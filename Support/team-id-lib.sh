# shellcheck shell=bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: team-id-lib.sh
# Author: Heath Jones
# Date: 2026-09-24
# Modified: 2026-09-24
# Purpose: Sourced library that resolves the Apple Developer Team ID the
#          build scripts sign and verify against, so no script hardcodes one
#          maintainer's team. Resolution order:
#            1. DEVELOPMENT_TEAM in the environment
#            2. DEVELOPMENT_TEAM in <repo>/Config/Local.xcconfig (the same
#               gitignored file Xcode reads through Config/Signing.xcconfig)
#          A value is accepted only if it is exactly 10 uppercase letters or
#          digits (the Apple Team ID format).
#          This file is SOURCED, never executed: it sets no shell options and
#          never exits; callers own set -euo pipefail, logging, and failure.
# Version: 1.0 - Initial Script
######################################################################
############### End Script Information Block #########################
######################################################################

# serberus_team_id <repo_dir>
#   Prints the configured Team ID and returns 0, or prints nothing and
#   returns 1 when none is configured or the value is malformed.
serberus_team_id() {
    local repo_dir="$1"
    local config="${repo_dir}/Config/Local.xcconfig"
    local team="${DEVELOPMENT_TEAM:-}"

    if [[ -z "${team}" && -f "${config}" ]]
    then
        # Last uncommented `DEVELOPMENT_TEAM = VALUE` line wins, as in Xcode.
        team=$(/usr/bin/sed -nE \
            's#^[[:space:]]*DEVELOPMENT_TEAM[[:space:]]*=[[:space:]]*([A-Za-z0-9]*)[[:space:]]*(//.*)?$#\1#p' \
            "${config}" | /usr/bin/tail -n 1)
    fi

    [[ "${team}" =~ ^[A-Z0-9]{10}$ ]] || return 1
    printf '%s\n' "${team}"
}
