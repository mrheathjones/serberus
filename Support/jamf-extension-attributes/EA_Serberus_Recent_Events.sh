#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: EA_Serberus_Recent_Events.sh
# Author: Heath Jones
# Date: 2026-08-24
# Modified: 2026-09-26
# Purpose: Extension Attribute — the recent individual DENIAL and PROMPT decisions on this Mac (last 24h, JSON), for Serberus Commander to list on the device record. Populated ONLY while the debug-telemetry profile (com.herojoneslabs.serberus.debug : debugModeEnabled = true) is installed; empty otherwise.
# Version: 1.3 - A file too long for the 64 KiB cap is cut on EVENT
#          boundaries: the newest events that fit are kept (the daemon writes
#          newest first) and the value is still a valid JSON array, so
#          Commander lists them instead of decoding a cut-off value as "no
#          events". No marker is appended (it would break the JSON). Without
#          jq, or when the file is not a JSON array, an oversized file yields
#          an empty array.
#          1.2 - The result is capped at 64 KiB; a longer file is cut (never
#          inside an XML entity) and ends with a truncation marker, so a busy
#          day cannot produce an inventory value Jamf truncates or rejects.
#          1.1 - System-only PATH and absolute tool paths (EAs run as
#          root; /usr/local/bin can be user-owned). jq is /usr/bin/jq (base
#          macOS 15+).
#          1.0 - Initial Script
# Data Type: String
# Input Type: Script
#
#          Name the EA (your convention; any name containing "Serberus" works) "EA_Serberus_Recent_Events", Data Type STRING. The value is a
#          JSON array of {at, kind, target, user, outcome, prompt, reason?, justification?}. Empty when debug mode is off / Serberus not installed. Deploy the
#          com.herojoneslabs.serberus.debug profile (debugModeEnabled = true) to a smart group only while you are actively debugging — the
#          daemon publishes this file only while that profile is present and removes it when the profile is removed.
#
######################################################################
############## End Script Information Block ##########################
######################################################################

# EAs run as root: system directories only (a user can own /usr/local/bin),
# and every tool below is called by absolute path.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

readonly JQ="/usr/bin/jq"
readonly SED="/usr/bin/sed"
readonly WC="/usr/bin/wc"

# The whole <result> stays within 64 KiB, measured AFTER XML escaping.
readonly MAX_RESULT_BYTES=65536

# The daemon writes this world-readable file ONLY while debug mode is enabled;
# it is removed when debug mode is turned off or its profile is removed. Absent
# => nothing to report (debug off, or Serberus not installed).
readonly EVENTS_FILE="/Library/Application Support/Serberus/fleet-events.json"

# JSON does NOT escape &, <, >, and a command path can legitimately contain
# "&" (e.g. an app named "AT&T …"). Those chars would corrupt the Jamf
# <result> XML and blank the EA, so they are XML-escaped (& first). Jamf
# un-escapes on ingest, so Commander receives the original JSON.
xml_escape() {
    "${SED}" 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
}

# The newest events (the array's leading elements: the daemon writes newest
# first) whose compact, XML-escaped form fits in $1 bytes, as one compact
# JSON array; each element is kept whole or dropped. Reads EVENTS_FILE.
# ($e/$l/$add/$budget are jq variables — single quotes are intended.)
# shellcheck disable=SC2016
newest_events_within() {
    "${JQ}" -c --argjson budget "$1" '
        def esc_len:
            tojson
            | (utf8bytelength
               + ([scan("&")] | length) * 4
               + ([scan("[<>]")] | length) * 3);
        if type != "array" then error("not an array") else
            reduce .[] as $e ({out: [], used: 2, full: false};
                if .full then . else
                    ($e | esc_len) as $l
                    | (if (.out | length) == 0 then $l else $l + 1 end) as $add
                    | if .used + $add <= $budget
                      then .out += [$e] | .used += $add
                      else .full = true
                      end
                end)
            | .out
        end' "${EVENTS_FILE}" 2>/dev/null
}

# EA logic — fast and side-effect-free. No `set -e`: a failure must still
# report a result.

RESULT=""

if [[ -r "${EVENTS_FILE}" ]]
then
    RESULT=$(xml_escape < "${EVENTS_FILE}")
    escaped_bytes=$(printf '%s' "${RESULT}" | "${WC}" -c | "${SED}" 's/[^0-9]//g')
    if [[ ! "${escaped_bytes}" =~ ^[0-9]+$ ]] || (( escaped_bytes > MAX_RESULT_BYTES ))
    then
        # Too long: keep whole events only, so the value stays valid JSON.
        if [[ -x "${JQ}" ]] && TRIMMED=$(newest_events_within "${MAX_RESULT_BYTES}") \
            && [[ -n "${TRIMMED}" ]]
        then
            RESULT=$(printf '%s' "${TRIMMED}" | xml_escape)
        else
            RESULT="[]"
        fi
    fi
fi

echo "<result>${RESULT}</result>"
