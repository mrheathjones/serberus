#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: EA_Serberus_Prompts_24h.sh
# Author: Heath Jones
# Date: 2026-08-23
# Modified: 2026-09-25
# Purpose: Extension Attribute — count of Serberus elevation decisions that raised an interactive prompt on this Mac in the last 24h (Integer EA, for prompt-fatigue hotspot smart groups and Commander's Dashboard tiles)
# Version: 1.1 - System-only PATH and absolute tool paths (EAs run as
#          root; /usr/local/bin can be user-owned). jq is /usr/bin/jq (base
#          macOS 15+).
#          1.0 - Initial Script
# Data Type: Integer
# Input Type: Script
#
#          Name the EA (your convention; any name containing "Serberus" works) "EA_Serberus_Prompts_24h", Data Type INTEGER. Empty result
#          when Serberus is not installed / no summary yet.
#
######################################################################
############## End Script Information Block ##########################
######################################################################

# EAs run as root: system directories only (a user can own /usr/local/bin),
# and every tool below is called by absolute path.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

readonly PLIST_BUDDY="/usr/libexec/PlistBuddy"

# The daemon's world-readable fleet telemetry summary (see EA_Serberus_Denials_24h).
readonly SUMMARY_PLIST="/Library/Application Support/Serberus/fleet-summary.plist"

# EA logic — fast and side-effect-free. No `set -e`: a failure must still
# report a result.

RESULT=""

if [[ -f "${SUMMARY_PLIST}" ]]
then
    value=$("${PLIST_BUDDY}" -c 'Print :prompts24h' "${SUMMARY_PLIST}" 2>/dev/null)
    if [[ "${value}" =~ ^[0-9]+$ ]]
    then
        RESULT="${value}"
    fi
fi

echo "<result>${RESULT}</result>"
