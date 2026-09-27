#! /bin/bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: make-rules-subdomain-schema.sh
# Author: Heath Jones
# Date: 2026-07-16
# Modified: 2026-09-26
# Purpose: Generate a Jamf Custom Schema for a Serberus rules SUB-DOMAIN.
#
#          WHY THIS EXISTS: a native `rules` ARRAY lives under the single
#          `rules` key of one preference domain. TWO configuration profiles
#          cannot both own that key in the SAME domain — macOS keeps one and
#          silently drops the other (the dropped rules never reach
#          /Library/Managed Preferences, so the daemon cannot even see them).
#          The daemon therefore prefix-scans EVERY domain under
#          com.herojoneslabs.serberus.rules and unions them, so the rule is:
#
#              ONE CONFIG PROFILE  ==  ONE SUB-DOMAIN
#
#          Give each profile its own suffix and they all compose. Suffixes may
#          be nested/dotted (e.g. authuri.printers) and are ARBITRARY — the
#          daemon attaches no meaning to them. A domain named ".authuri"
#          does NOT restrict its rules to authURI: every rule carries its own
#          `type` (sudo | authuri), so name domains by PURPOSE, not by type.
# Version: 1.0 - Initial Script
#          1.1 - --authuri: an authorization-right-only form (type locked to
#                authuri, sudo-only fields removed), matching the form
#                Commander exports for an authURI-only policy
#
######################################################################
############## End Script Information Block ##########################
######################################################################

# Usage:
#   ./make-rules-subdomain-schema.sh [--authuri] <suffix> [title]
#
#   --authuri  emit the authorization-right form: `type` is locked to
#              authuri, and the fields an authURI rule never uses (command
#              path, match type, arguments, elevation, argument logging,
#              justification, grant duration, cache, binary pins) are removed.
#
# Examples:
#   ./make-rules-subdomain-schema.sh --authuri authuri.printers "Serberus — Rules (authURI: printers)"
#   ./make-rules-subdomain-schema.sh sudo.jamf
#
# Writes: com.herojoneslabs.serberus.rules.<suffix>.json  (next to this script)
# Then in Jamf: Configuration Profiles → Application & Custom Settings →
#               Custom Schema → paste the JSON → the preference domain is
#               pre-filled from __preferencedomain.

####################################################################
############## Begin Define Variables Block ########################
####################################################################

set -euo pipefail

export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

# shellcheck disable=SC2230 — `which` preferred over `command -v` per style guide
readonly BASENAME=$(which basename)
readonly DIRNAME=$(which dirname)
readonly PYTHON=$(which python3)

readonly SCRIPT_NAME=$("${BASENAME}" "$0")
readonly SCRIPT_VERSION="1.1"
readonly SCRIPT_DIR=$(cd "$("${DIRNAME}" "$0")" && pwd)

readonly BASE_DOMAIN="com.herojoneslabs.serberus.rules"
readonly TEMPLATE="${SCRIPT_DIR}/${BASE_DOMAIN}.json"

FORM="all"
if [[ "${1:-}" == "--authuri" ]]
then
    FORM="authuri"
    shift
fi
readonly FORM

readonly SUFFIX="${1:-}"
readonly TITLE_OVERRIDE="${2:-}"

####################################################################
############## End Define Variables Block ##########################
####################################################################

log_info() { printf '[INFO] %s\n' "$*"; }
log_error() { printf '[ERROR] %s\n' "$*" >&2; }

usage() {
    printf 'Usage: %s [--authuri] <suffix> [title]\n' "${SCRIPT_NAME}" >&2
    printf '  e.g. %s --authuri authuri.printers "Serberus — Rules (authURI: printers)"\n' "${SCRIPT_NAME}" >&2
    exit 1
}

if [[ -z "${SUFFIX}" ]]
then
    usage
fi

# A suffix must be dot-separated reverse-DNS-safe labels: letters, digits,
# hyphens, dots. Anything else would produce a domain macOS will not deliver.
if [[ ! "${SUFFIX}" =~ ^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*)*$ ]]
then
    log_error "Invalid suffix '${SUFFIX}' — use dot-separated alphanumeric/hyphen labels (e.g. authuri.printers)."
    exit 1
fi

if [[ ! -f "${TEMPLATE}" ]]
then
    log_error "Template schema not found: ${TEMPLATE}"
    exit 1
fi

readonly TARGET_DOMAIN="${BASE_DOMAIN}.${SUFFIX}"
readonly OUTPUT="${SCRIPT_DIR}/${TARGET_DOMAIN}.json"

log_info "${SCRIPT_NAME} v${SCRIPT_VERSION}"
log_info "Generating ${FORM} schema for domain: ${TARGET_DOMAIN}"

"${PYTHON}" - "${TEMPLATE}" "${OUTPUT}" "${TARGET_DOMAIN}" "${SUFFIX}" "${TITLE_OVERRIDE}" "${FORM}" <<'PY'
import collections, json, sys

template, output, domain, suffix, title_override, form = sys.argv[1:7]

with open(template) as handle:
    schema = json.load(handle, object_pairs_hook=collections.OrderedDict)

schema["title"] = title_override or f"Serberus — Rules ({suffix})"
schema["description"] = (
    f"Author Serberus rules delivered to the {domain} sub-domain. "
    "The daemon reads every rules sub-domain and unions every com.herojoneslabs.serberus.rules[.suffix] domain. "
    "ONE configuration profile per sub-domain: two profiles cannot share a domain's single 'rules' "
    "array — macOS keeps one and silently drops the other. The suffix is a label only; each rule still "
    "declares its own type (sudo or authuri)."
)
schema["__preferencedomain"] = domain

if form == "authuri":
    # Keep in step with JamfRulesSchema.FieldSet.authuriOnly.
    schema["description"] = (
        f"Author Serberus authorization-right (authURI) rules delivered to the {domain} sub-domain. "
        "The daemon reads every rules sub-domain and unions every com.herojoneslabs.serberus.rules[.suffix] domain. "
        "ONE configuration profile per sub-domain: two profiles cannot share a domain's single 'rules' "
        "array — macOS keeps one and silently drops the other. This form only offers the fields an "
        "authorization-right rule uses; author sudo rules in a sudo sub-domain."
    )
    items = schema["properties"]["rules"]["items"]["properties"]
    for field in ("commandPattern", "matchType", "argPattern", "elevationType", "logArguments",
                  "requireJustification", "maxGrantDurationSeconds", "cacheSeconds",
                  "requiredTeamID", "requiredBinaryHash"):
        items.pop(field, None)
    items["type"]["enum"] = ["authuri"]
    items["type"]["options"] = {"enum_titles": ["Authorization right"]}
    items["type"]["default"] = "authuri"
    items["action"]["description"] = (
        "'Allow' lets the user unlock the authorization right with their OWN password (no Serberus prompt). "
        "'Deny' blocks it. Deny wins over allow at equal priority."
    )

with open(output, "w") as handle:
    json.dump(schema, handle, indent=2)
    handle.write("\n")
PY

# Fail loudly if the emitted file is not valid JSON or lost its domain.
"${PYTHON}" - "${OUTPUT}" "${TARGET_DOMAIN}" <<'PY'
import json, sys
path, expected = sys.argv[1], sys.argv[2]
schema = json.load(open(path))
assert schema["__preferencedomain"] == expected, "domain not set"
assert "rules" in schema["properties"], "rules property missing"
print(f"[INFO] Verified {path}")
print(f"[INFO]   __preferencedomain = {schema['__preferencedomain']}")
print(f"[INFO]   title              = {schema['title']}")
PY

log_info "──────────────────────────────────────────────────────────────"
log_info "Wrote: ${OUTPUT}"
log_info "In Jamf: Configuration Profiles → Application & Custom Settings →"
log_info "         Custom Schema → paste this JSON. Scope ONE profile to it."
log_info "The daemon unions this domain with every other ${BASE_DOMAIN}[.*] domain."
log_info "──────────────────────────────────────────────────────────────"
log_info "${SCRIPT_NAME} completed successfully"
