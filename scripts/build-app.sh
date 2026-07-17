#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
app_name=${APP_NAME:-YubiTouch}
bundle_id=${BUNDLE_ID:-com.github.mofelee.yubitouch}
package=${GO_PACKAGE:-./cmd/yubitouch}
executable=${EXECUTABLE_NAME:-yubitouch}
output=${OUTPUT_DIR:-$root/dist}
app="$output/$app_name.app"
contents="$app/Contents"

mkdir -p "$contents/MacOS" "$contents/Resources"
cp "$root/packaging/Info.plist" "$contents/Info.plist"
cp "$root/assets/YubiTouch-1024.png" "$contents/Resources/YubiTouch-1024.png"
/usr/libexec/PlistBuddy -c "Set :CFBundleDisplayName $app_name" "$contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleName $app_name" "$contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $bundle_id" "$contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleExecutable $executable" "$contents/Info.plist"

cd "$root"
GOCACHE=${GOCACHE:-/tmp/yubitouch-gocache} go build \
  -buildvcs=false \
  -ldflags "-s -w" \
  -o "$contents/MacOS/$executable" \
  "$package"

chmod 0755 "$contents/MacOS/$executable"
echo "$app"
