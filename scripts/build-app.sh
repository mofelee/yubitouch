#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
app_name=${APP_NAME:-YubiTouch}
bundle_id=${BUNDLE_ID:-com.github.mofelee.yubitouch}
bundle_short_version=${BUNDLE_SHORT_VERSION:-0.1.0}
bundle_version=${BUNDLE_VERSION:-1}
package=${GO_PACKAGE:-./cmd/yubitouch}
executable=${EXECUTABLE_NAME:-yubitouch}
output=${OUTPUT_DIR:-$root/dist}
version=${VERSION:-dev}
commit=${COMMIT:-}
goarch=${GOARCH:-$(go env GOARCH)}
app="$output/$app_name.app"
contents="$app/Contents"

if [ -z "$commit" ]; then
  commit=$(git -C "$root" rev-parse --short=12 HEAD 2>/dev/null || printf '%s' unknown)
fi
case "$app_name" in
  ''|*/*)
    echo "app and executable names must be simple path components" >&2
    exit 2
    ;;
esac
case "$executable" in
  ''|*/*)
    echo "app and executable names must be simple path components" >&2
    exit 2
    ;;
esac
case "$version:$commit" in
  *[!A-Za-z0-9._:+-]*)
    echo "version and commit contain unsupported characters" >&2
    exit 2
    ;;
esac
case "$bundle_short_version:$bundle_version" in
  *[!0-9.:]*)
    echo "bundle versions must be numeric" >&2
    exit 2
    ;;
esac

rm -rf "$app"
mkdir -p "$contents/MacOS" "$contents/Resources"
cp "$root/packaging/Info.plist" "$contents/Info.plist"
cp "$root/assets/YubiTouch-1024.png" "$contents/Resources/YubiTouch-1024.png"
/usr/libexec/PlistBuddy -c "Set :CFBundleDisplayName $app_name" "$contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleName $app_name" "$contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $bundle_id" "$contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleExecutable $executable" "$contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $bundle_short_version" "$contents/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $bundle_version" "$contents/Info.plist"

cd "$root"
CGO_ENABLED=1 GOOS=darwin GOARCH="$goarch" GOCACHE=${GOCACHE:-/tmp/yubitouch-gocache} go build \
  -buildvcs=false \
  -trimpath \
  -ldflags "-s -w -X github.com/mofelee/yubitouch/internal/buildinfo.Version=$version -X github.com/mofelee/yubitouch/internal/buildinfo.Commit=$commit" \
  -o "$contents/MacOS/$executable" \
  "$package"

chmod 0755 "$contents/MacOS/$executable"
echo "$app"
