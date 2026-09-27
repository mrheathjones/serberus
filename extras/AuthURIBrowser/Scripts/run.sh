#!/usr/bin/env bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: run.sh
# Author: Heath Jones
# Date: 2026-09-24
# Modified: 2026-09-25
# Purpose: Rebuild, repackage, and relaunch Auth URI Browser (developer
#          convenience; wraps Scripts/package_app.sh).
# Version: 1.1 - Standard script information block.
#          1.0 - Initial Script
#
######################################################################
############## End Script Information Block ##########################
######################################################################

set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
pkill -x AuthURIBrowser 2>/dev/null || true
"$ROOT/Scripts/package_app.sh" "${1:-release}"
open "$ROOT/build/Auth URI Browser.app"
