#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: EA_Serberus_State.sh
# Author: Heath Jones
# Date: 2026-08-22
# Modified: 2026-09-25
# Purpose: Extension Attribute — the Serberus daemon's state (healthy / degraded (<reason>) / awaiting_config / pending_pppc / pending_profiles / kill_switch), for smart groups and Commander's Fleet Observer posture chips
# Version: 1.1 - System-only PATH and absolute tool paths (EAs run as
#          root; /usr/local/bin can be user-owned). jq is /usr/bin/jq (base
#          macOS 15+).
#          1.0 - Initial Script
# Data Type: String
# Input Type: Script
#
#          Name the EA (your convention; any name containing "Serberus" works) "EA_Serberus_State": Commander shows any EA whose name CONTAINS
#          "Serberus" (any convention) on the device card (first 3 by name) and in the device detail.
#
######################################################################
############## End Script Information Block ##########################
######################################################################

# EAs run as root: system directories only (a user can own /usr/local/bin),
# and every tool below is called by absolute path.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

readonly PLIST_BUDDY="/usr/libexec/PlistBuddy"

# The daemon's world-readable state file (transition-only — updatedAt is the
# last state CHANGE, not a heartbeat). Absent => Serberus is not installed.
readonly STATE_PLIST="/Library/Application Support/Serberus/state.plist"

# EA logic — fast and side-effect-free. No `set -e`: a failure must still
# report a result.

RESULT="not installed"

if [[ -f "${STATE_PLIST}" ]]
then
    state=$("${PLIST_BUDDY}" -c 'Print :state' "${STATE_PLIST}" 2>/dev/null)
    reason=$("${PLIST_BUDDY}" -c 'Print :degradedReason' "${STATE_PLIST}" 2>/dev/null)
    if [[ -n "${state}" ]]
    then
        RESULT="${state}"
        if [[ -n "${reason}" ]]
        then
            RESULT="${state} (${reason})"
        fi
    else
        RESULT="unknown (state.plist unreadable)"
    fi
fi

echo "<result>${RESULT}</result>"
