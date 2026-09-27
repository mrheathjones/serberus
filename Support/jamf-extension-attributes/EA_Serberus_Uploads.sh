#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: EA_Serberus_Uploads.sh
# Author: Heath Jones
# Date: 2026-08-22
# Modified: 2026-09-26
# Purpose: Extension Attribute — files the Sentinel uploaded to this Mac's Jamf record in the last 30 days (captures + Intel bundles), so Jamf can flag devices with something for Commander to harvest
# Version: 1.4 - The ledger is checked again through the descriptor that
#          reads it: after the open, the file behind the descriptor must be
#          the same regular file (inode), still owned by the user and within
#          the size cap, so a symlink or FIFO swapped in between the check and
#          the open is refused instead of read as root.
#          1.3 - Each account is found through its record (dscl short
#          name and NFSHomeDirectory), not the name of a folder under
#          /Users, so a renamed account or a home elsewhere is counted.
#          1.2 - Reads a user's ledger only when it is a regular file (not a
#          symlink, FIFO or device) owned by that user and at most 1 MiB, and
#          parses a bounded root-owned copy (head -c, 5 s deadline), so a
#          planted FIFO or /dev/zero link can no longer stall jq inside
#          `jamf recon`.
#          1.1 - System-only PATH and absolute tool paths (EAs run as
#          root; /usr/local/bin can be user-owned). jq is /usr/bin/jq (base
#          macOS 15+).
#          1.0 - Initial Script
# Data Type: String
# Input Type: Script
#
#          Name the EA e.g. "EA_Serberus_Uploads". Values: "none" or "capture N · intel M · newest YYYY-MM-DD HH:MM".
#          Smart group "Serberus uploads waiting": EA_Serberus_Uploads · is not · none. Needs jq (baseline utility).
#
######################################################################
############## End Script Information Block ##########################
######################################################################

# EAs run as root: system directories only (a user can own /usr/local/bin),
# and every tool below is called by absolute path.
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

readonly JQ="/usr/bin/jq"
readonly DATE="/bin/date"

# The Sentinel writes one ledger per user (world-readable JSON array of
# {kind: capture|intel, fileName, uploadedAt (ISO-8601), computerID,
# serialNumber, sizeBytes}); entries older than 30 days are pruned by the
# writer. A root EA reads every user's ledger. This is the DEVICE-SIDE
# "I uploaded files" signal for smart groups and Commander's posture chips —
# Commander's queue of what is still on the record is the inventory's
# attachments list (it deletes what it has harvested).
readonly LEDGER_NAME="jamf-uploads.json"
readonly LEDGER_SUBPATH="Library/Application Support/Serberus/${LEDGER_NAME}"

readonly DSCL="/usr/bin/dscl"
readonly HEAD="/usr/bin/head"
readonly ID="/usr/bin/id"
readonly MKTEMP="/usr/bin/mktemp"
readonly RM="/bin/rm"
readonly SLEEP="/bin/sleep"
readonly STAT="/usr/bin/stat"

# A ledger larger than this is not read (the Sentinel's own is a few KiB).
readonly LEDGER_MAX_BYTES=1048576
# Seconds a ledger copy may take before it is abandoned.
readonly LEDGER_COPY_SECONDS=5

LEDGER_COPY=$("${MKTEMP}" -t serberus-ea-ledger) || LEDGER_COPY=""
trap '[[ -n "${LEDGER_COPY}" ]] && "${RM}" -f "${LEDGER_COPY}"' EXIT

# Copies <user>'s ledger into the root-owned temp file LEDGER_COPY and
# returns 0 only when it is safe to parse. The ledger sits in a directory the
# user controls, so it must be a regular file (not a symlink, FIFO or device
# — /dev/zero or a FIFO would stall jq, and with it `jamf recon`), owned by
# that user, and no larger than LEDGER_MAX_BYTES. The copy
# is size-bounded (head -c) and time-bounded, so a file swapped for a FIFO
# after the checks cannot block the EA either; jq then parses only the copy.
# The checks are made again on the OPEN descriptor (/dev/fd/3): the file
# read must be the same regular file (inode) the checks passed, still owned
# by the user and within the cap, so a symlink swapped in after the checks
# (to /dev/zero or a root-only file) is refused, never read as root.
#   $1 short name, $2 home (both from the account record)
copy_ledger() {
    local user="$1"
    local user_home="$2"
    local ledger="${user_home}/${LEDGER_SUBPATH}"
    local uid
    local info
    local owner
    local size
    local inode
    [[ -n "${LEDGER_COPY}" ]] || return 1
    [[ -f "${ledger}" && ! -L "${ledger}" ]] || return 1
    uid=$("${ID}" -u "${user}" 2>/dev/null) || return 1
    info=$("${STAT}" -f '%u %z %i' "${ledger}" 2>/dev/null) || return 1
    read -r owner size inode <<< "${info}"
    [[ "${owner}" == "${uid}" && "${size}" =~ ^[0-9]+$ && "${inode}" =~ ^[0-9]+$ ]] || return 1
    (( size <= LEDGER_MAX_BYTES )) || return 1

    : > "${LEDGER_COPY}"
    (
        exec 3< "${ledger}" || exit 1
        [[ -f /dev/fd/3 ]] || exit 1
        read -r owner size fd_inode <<< "$("${STAT}" -f '%u %z %i' /dev/fd/3 2>/dev/null)"
        [[ "${owner}" == "${uid}" && "${fd_inode}" == "${inode}" && "${size}" =~ ^[0-9]+$ ]] || exit 1
        (( size <= LEDGER_MAX_BYTES )) || exit 1
        "${HEAD}" -c "$((LEDGER_MAX_BYTES + 1))" <&3 > "${LEDGER_COPY}"
    ) 2>/dev/null &
    local child=$!
    local waited=0
    while kill -0 "${child}" 2>/dev/null
    do
        if (( waited >= LEDGER_COPY_SECONDS * 5 ))
        then
            kill -KILL "${child}" 2>/dev/null
            wait "${child}" 2>/dev/null
            return 1
        fi
        "${SLEEP}" 0.2
        waited=$((waited + 1))
    done
    wait "${child}" 2>/dev/null || return 1
    size=$("${STAT}" -f '%z' "${LEDGER_COPY}" 2>/dev/null) || return 1
    (( size > 0 && size <= LEDGER_MAX_BYTES ))
}

# 30-day window, enforced HERE: the Sentinel prunes on its next write, but a
# Mac that uploads once and never again would otherwise stay flagged forever.
# Ledger dates are ISO-8601 UTC "YYYY-MM-DDTHH:MM:SSZ" → lexicographic compare
# is safe.
# shellcheck disable=SC2155
readonly CUTOFF=$("${DATE}" -u -v-30d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)

# EA logic — fast and side-effect-free. No `set -e`: a failure must still
# report a result.

if [[ ! -x "${JQ}" ]]
then
    echo "<result>ERROR: jq not installed</result>"
    exit 0
fi

captures=0
intel=0
newest=""

# Every local account with a home, by its record. Service accounts ("_…")
# and homes that are not absolute paths (or /var/empty) are skipped.
while read -r user user_home
do
    if [[ -z "${user}" || "${user}" == _* ]] \
        || [[ "${user_home}" != /* || "${user_home}" == "/var/empty" ]]
    then
        continue
    fi
    if ! copy_ledger "${user}" "${user_home}"
    then
        continue
    fi
    # One jq pass per ledger: counts by kind + the newest upload time, over
    # the entries inside the window. EVERY binding is parenthesised so `.`
    # stays the whole (windowed) array — an unparenthesised
    # `[…] | length as $c | …` rebinds `.` to the captures-only array and
    # zeroes the intel count. Expected: 1 capture + 2 intel → "1 2 <newest>".
    # ($c/$i/$n below are jq variables, not shell — single quotes are intended.)
    # shellcheck disable=SC2016
    summary=$("${JQ}" -r --arg cutoff "${CUTOFF}" '
        [.[] | select((.uploadedAt // "") >= $cutoff)]
        | ([.[] | select(.kind == "capture")] | length) as $c
        | ([.[] | select(.kind == "intel")] | length) as $i
        | ([.[] | .uploadedAt] | sort | last // "") as $n
        | "\($c) \($i) \($n)"' "${LEDGER_COPY}" 2>/dev/null)
    if [[ -z "${summary}" ]]
    then
        continue
    fi
    read -r c i n <<< "${summary}"
    captures=$((captures + c))
    intel=$((intel + i))
    if [[ -n "${n}" && ( -z "${newest}" || "${n}" > "${newest}" ) ]]
    then
        newest="${n}"
    fi
done < <("${DSCL}" . -list /Users NFSHomeDirectory 2>/dev/null)

if [[ $((captures + intel)) -eq 0 ]]
then
    RESULT="none"
else
    RESULT="capture ${captures} · intel ${intel}"
    if [[ -n "${newest}" ]]
    then
        # ISO-8601 UTC from the ledger → local "YYYY-MM-DD HH:MM".
        pretty=$("${DATE}" -j -u -f '%Y-%m-%dT%H:%M:%SZ' "${newest}" '+%Y-%m-%d %H:%M' 2>/dev/null)
        if [[ -n "${pretty}" ]]
        then
            RESULT="${RESULT} · newest ${pretty} UTC"
        fi
    fi
fi

echo "<result>${RESULT}</result>"
