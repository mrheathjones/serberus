#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: EA_Serberus_Last_Decision.sh
# Author: Heath Jones
# Date: 2026-08-23
# Modified: 2026-09-25
# Purpose: Extension Attribute — when Serberus last made ANY elevation decision on this Mac (Date EA, for "silent for > N days" smart groups that surface a mis-scoped or inert policy)
# Version: 1.1 - System-only PATH and absolute tool paths (EAs run as
#          root; /usr/local/bin can be user-owned). jq is /usr/bin/jq (base
#          macOS 15+).
#          1.0 - Initial Script
# Data Type: Date
# Input Type: Script
#
#          Name the EA (your convention; any name containing "Serberus" works) "EA_Serberus_Last_Decision", Data Type DATE (Jamf expects
#          "YYYY-MM-DD hh:mm:ss"). Empty result when Serberus is not installed / has made no decisions yet. This is the genuine newest
#          decision timestamp (even if older than the 24h count window), so a silent Mac reads as silent.
#
######################################################################
############## End Script Information Block ##########################
######################################################################

# EAs run as root: system directories only (a user can own /usr/local/bin),
# and every tool below is called by absolute path.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

readonly PLIST_BUDDY="/usr/libexec/PlistBuddy"
readonly DATE="/bin/date"

# The daemon's world-readable fleet telemetry summary (see EA_Serberus_Denials_24h).
# lastDecisionAt is ISO-8601 (e.g. 2026-08-23T21:00:00Z) and absent when no
# decisions have been made.
readonly SUMMARY_PLIST="/Library/Application Support/Serberus/fleet-summary.plist"

# EA logic — fast and side-effect-free. No `set -e`: a failure must still
# report a result.

RESULT=""

if [[ -f "${SUMMARY_PLIST}" ]]
then
    iso=$("${PLIST_BUDDY}" -c 'Print :lastDecisionAt' "${SUMMARY_PLIST}" 2>/dev/null)
    if [[ -n "${iso}" ]]
    then
        # Jamf DATE EAs want "YYYY-MM-DD hh:mm:ss" (UTC is fine; Jamf stores epoch).
        RESULT=$("${DATE}" -j -u -f '%Y-%m-%dT%H:%M:%SZ' "${iso}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    fi
fi

echo "<result>${RESULT}</result>"
