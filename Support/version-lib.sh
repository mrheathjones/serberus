# shellcheck shell=bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: version-lib.sh
# Author: Heath Jones
# Date: 2026-09-26
# Modified: 2026-09-26
# Purpose: Sourced library that reads the Serberus product version from the
#          single VERSION file at the repository root, so the build scripts
#          never carry their own copy. The Swift constant
#          (DaemonVersion.current) and project.yml MARKETING_VERSION keep
#          literals; PKG/tests/test-sentinel-lib.sh asserts they equal VERSION.
#          A value is accepted only in the form MAJOR.MINOR.PATCH (digits).
#          This file is SOURCED, never executed: it sets no shell options and
#          never exits; callers own set -euo pipefail, logging, and failure.
# Version: 1.0 - Initial Script
######################################################################
############### End Script Information Block #########################
######################################################################

# serberus_version_from_file <path to a VERSION file>
#   Prints the version on its first line and returns 0, or prints nothing and
#   returns 1 when the file is missing, a symlink, or malformed.
serberus_version_from_file() {
    local file="$1"
    local version=""

    [[ -f "${file}" && ! -L "${file}" ]] || return 1
    IFS= read -r version < "${file}" || [[ -n "${version}" ]] || return 1
    version="${version%$'\r'}"
    [[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    printf '%s\n' "${version}"
}

# serberus_product_version <repo_dir>
#   Prints the product version from <repo_dir>/VERSION (see above).
serberus_product_version() {
    serberus_version_from_file "$1/VERSION"
}
