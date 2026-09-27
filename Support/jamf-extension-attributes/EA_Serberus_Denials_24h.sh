#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: EA_Serberus_Denials_24h.sh
# Author: Heath Jones
# Date: 2026-08-23
# Modified: 2026-09-25
# Purpose: Extension Attribute — count of elevation decisions Serberus DENIED on this Mac in the last 24h (Integer EA, for "high-denial Macs" smart groups and Commander's Dashboard trend tiles)
# Version: 1.1 - System-only PATH and absolute tool paths (EAs run as
#          root; /usr/local/bin can be user-owned). jq is /usr/bin/jq (base
#          macOS 15+).
#          1.0 - Initial Script
# Data Type: Integer
# Input Type: Script
#
#          Name the EA (your convention; any name containing "Serberus" works) "EA_Serberus_Denials_24h", Data Type INTEGER so smart groups
#          can range-compare (e.g. "> 20"). Empty result when Serberus is not installed / no summary yet.
#
######################################################################
############## End Script Information Block ##########################
######################################################################

# EAs run as root: system directories only (a user can own /usr/local/bin),
# and every tool below is called by absolute path.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

readonly PLIST_BUDDY="/usr/libexec/PlistBuddy"

# The daemon's world-readable fleet telemetry summary, rewritten on each 30s
# reload tick from the signed decision log. Absent => Serberus is not installed
# (or has never run a reload tick). denials24h folds audit-mode would-deny in.
readonly SUMMARY_PLIST="/Library/Application Support/Serberus/fleet-summary.plist"

# EA logic — fast and side-effect-free. No `set -e`: a failure must still
# report a result.

RESULT=""

if [[ -f "${SUMMARY_PLIST}" ]]
then
    value=$("${PLIST_BUDDY}" -c 'Print :denials24h' "${SUMMARY_PLIST}" 2>/dev/null)
    # Only emit a clean integer; anything else stays empty (Jamf Integer EA).
    if [[ "${value}" =~ ^[0-9]+$ ]]
    then
        RESULT="${value}"
    fi
fi

echo "<result>${RESULT}</result>"
