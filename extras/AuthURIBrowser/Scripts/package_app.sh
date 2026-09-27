#!/usr/bin/env bash

######################################################################
############## Begin Script Information Block ########################
######################################################################
# Name: package_app.sh
# Author: Heath Jones
# Date: 2026-09-24
# Modified: 2026-09-25
# Purpose: Build AuthURIBrowser with SwiftPM and wrap it in a self-contained,
#          ad-hoc-signed (or SIGNING_IDENTITY-signed) .app bundle, assembled
#          in a scratch path and copied to build/Auth URI Browser.app.
#            Scripts/package_app.sh            # release build
#            Scripts/package_app.sh debug      # debug build
#            SIGNING_IDENTITY="Developer ID Application: …" Scripts/package_app.sh
# Version: 1.1 - Standard script information block.
#          1.0 - Initial Script
#
######################################################################
############## End Script Information Block ##########################
######################################################################

set -euo pipefail

CONF=${1:-release}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

EXEC_NAME="AuthURIBrowser"
APP_NAME=${APP_NAME:-Auth URI Browser}
BUNDLE_ID=${BUNDLE_ID:-com.herojoneslabs.authuribrowser}
MACOS_MIN_VERSION=${MACOS_MIN_VERSION:-14.0}
SIGNING_IDENTITY=${SIGNING_IDENTITY:--}
# iCloud Drive stamps xattrs onto anything under it, which breaks code seals;
# build products stay in a local scratch path.
SCRATCH=${SCRATCH:-/tmp/authuribrowser-build}

# shellcheck disable=SC1091
source "$ROOT/version.env"

swift build -c "$CONF" --scratch-path "$SCRATCH" -Xswiftc -disable-cmo
BIN="$(swift build -c "$CONF" --scratch-path "$SCRATCH" --show-bin-path)/$EXEC_NAME"

# The bundle is assembled and signed in the scratch path (outside iCloud, which
# stamps com.apple.FinderInfo onto files and breaks the code seal), then copied
# to build/ for convenience. The scratch copy is the authoritative signed one.
OUT="$ROOT/build"
APP="$SCRATCH/${APP_NAME}.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>${APP_NAME}</string>
    <key>CFBundleDisplayName</key><string>${APP_NAME}</string>
    <key>CFBundleIdentifier</key><string>${BUNDLE_ID}</string>
    <key>CFBundleExecutable</key><string>${EXEC_NAME}</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>${MARKETING_VERSION}</string>
    <key>CFBundleVersion</key><string>${BUILD_NUMBER}</string>
    <key>LSMinimumSystemVersion</key><string>${MACOS_MIN_VERSION}</string>
    <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSHumanReadableCopyright</key><string>Heath Jones</string>
</dict>
</plist>
PLIST

cp "$BIN" "$APP/Contents/MacOS/$EXEC_NAME"
chmod +x "$APP/Contents/MacOS/$EXEC_NAME"

if [[ -f "$ROOT/Icon.icns" ]]; then
    cp "$ROOT/Icon.icns" "$APP/Contents/Resources/Icon.icns"
    /usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string Icon" "$APP/Contents/Info.plist"
fi

xattr -cr "$APP"
find "$APP" -name '._*' -delete

if [[ "$SIGNING_IDENTITY" == "-" ]]; then
    codesign --force --sign - "$APP"
else
    codesign --force --timestamp --options runtime --sign "$SIGNING_IDENTITY" "$APP"
fi

codesign --verify --deep --strict "$APP"
mkdir -p "$OUT"
# Best effort: a mis-relocated installer run can leave a root-owned copy here
# that the user cannot delete. Move it aside rather than fail the build.
if [[ -e "$OUT/${APP_NAME}.app" ]] && ! rm -rf "$OUT/${APP_NAME}.app" 2>/dev/null; then
    STALE="$OUT/${APP_NAME}.stale-$(date +%Y%m%d%H%M%S).app"
    mv "$OUT/${APP_NAME}.app" "$STALE"
    echo "WARNING: could not remove old build copy; moved to $STALE (remove with sudo rm -rf)" >&2
fi
ditto "$APP" "$OUT/${APP_NAME}.app"
echo "Created $APP"
echo "Copied to $OUT/${APP_NAME}.app"
