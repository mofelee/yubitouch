#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=${1:-}
version=${version#v}

case "$version" in
  ''|*[!0-9.]*|.*|*.|*..*)
    echo "usage: scripts/release.sh <major.minor.patch>" >&2
    exit 2
    ;;
esac
if [ "$(printf '%s' "$version" | awk -F. '{print NF}')" -ne 3 ]; then
  echo "release version must contain exactly three numeric components" >&2
  exit 2
fi

host_arch=$(go env GOARCH)
goarch=${GOARCH:-$host_arch}
if [ "$goarch" != "$host_arch" ]; then
  echo "CGO app releases must be built on a native $goarch runner (current: $host_arch)" >&2
  exit 2
fi
case "$goarch" in
  arm64|amd64) ;;
  *)
    echo "unsupported release architecture: $goarch" >&2
    exit 2
    ;;
esac

commit=$(git -C "$root" rev-parse HEAD)
short_commit=$(git -C "$root" rev-parse --short=12 HEAD)
if [ "${ALLOW_DIRTY:-0}" != "1" ]; then
  dirty=$(git -C "$root" status --porcelain --untracked-files=normal)
  if [ -n "$dirty" ]; then
    echo "release requires a clean worktree and index; set ALLOW_DIRTY=1 only for local candidates" >&2
    exit 1
  fi
fi

tag="v$version"
if [ "${ALLOW_UNTAGGED:-0}" != "1" ]; then
  tag_commit=$(git -C "$root" rev-list -n 1 "$tag" 2>/dev/null || true)
  if [ -z "$tag_commit" ] || [ "$tag_commit" != "$commit" ]; then
    echo "release requires $tag to point at HEAD; set ALLOW_UNTAGGED=1 only for local candidates" >&2
    exit 1
  fi
fi

if [ -z "${CODESIGN_IDENTITY:-}" ] && [ "${ALLOW_UNSIGNED:-0}" != "1" ]; then
  echo "CODESIGN_IDENTITY is required; set ALLOW_UNSIGNED=1 only for local candidates" >&2
  exit 1
fi
if [ -n "${NOTARY_PROFILE:-}" ] && [ -z "${CODESIGN_IDENTITY:-}" ]; then
  echo "NOTARY_PROFILE requires a Developer ID CODESIGN_IDENTITY" >&2
  exit 1
fi
if [ -n "${CODESIGN_IDENTITY:-}" ] && [ -z "${NOTARY_PROFILE:-}" ] && [ "${ALLOW_UNNOTARIZED:-0}" != "1" ]; then
  echo "NOTARY_PROFILE is required for signed releases; set ALLOW_UNNOTARIZED=1 only for local candidates" >&2
  exit 1
fi

release_dir=${RELEASE_DIR:-$root/dist/release/$version/$goarch}
mkdir -p "$release_dir"
archive_name="YubiTouch-$version-darwin-$goarch.zip"
cli_name="yubitouch-$version-darwin-$goarch"
for name in "$archive_name" "$cli_name" SHA256SUMS release.json RELEASE_NOTES.md; do
  if [ -e "$release_dir/$name" ]; then
    echo "refusing to overwrite existing release artifact: $release_dir/$name" >&2
    exit 1
  fi
done

stage=$(mktemp -d "${TMPDIR:-/tmp}/yubitouch-release.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM

OUTPUT_DIR="$stage" \
VERSION="$version" \
COMMIT="$short_commit" \
BUNDLE_SHORT_VERSION="$version" \
BUNDLE_VERSION="${BUNDLE_VERSION:-1}" \
GOARCH="$goarch" \
"$root/scripts/build-app.sh" >/dev/null

app="$stage/YubiTouch.app"
binary="$app/Contents/MacOS/yubitouch"
if [ -n "${CODESIGN_IDENTITY:-}" ]; then
  codesign --force --options runtime --timestamp --sign "$CODESIGN_IDENTITY" "$app"
  codesign --verify --strict --verbose=2 "$app"
  signed=true
else
  signed=false
fi

normalize_app() {
  find "$app" -exec touch -h -t 198001010000 {} +
}

create_archive() {
  rm -f "$stage/$archive_name"
  normalize_app
  (
    cd "$stage"
    find YubiTouch.app -print | LC_ALL=C sort | zip -q -X "$archive_name" -@
  )
}

create_archive
if [ -n "${NOTARY_PROFILE:-}" ]; then
  xcrun notarytool submit "$stage/$archive_name" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$app"
  xcrun stapler validate "$app"
  spctl --assess --type execute --verbose=2 "$app"
  create_archive
  notarized=true
else
  notarized=false
fi

cp "$binary" "$stage/$cli_name"
chmod 0755 "$stage/$cli_name"
touch -h -t 198001010000 "$stage/$cli_name"

sed \
  -e "s/@VERSION@/$version/g" \
  -e "s/@COMMIT@/$short_commit/g" \
  -e "s/@ARCH@/$goarch/g" \
  "$root/packaging/RELEASE_NOTES.md" > "$stage/RELEASE_NOTES.md"

cat > "$stage/release.json" <<EOF
{
  "version": "$version",
  "commit": "$commit",
  "os": "darwin",
  "arch": "$goarch",
  "minimum_macos": "13.0",
  "signed": $signed,
  "notarized": $notarized
}
EOF

(
  cd "$stage"
  shasum -a 256 "$archive_name" "$cli_name" release.json RELEASE_NOTES.md > SHA256SUMS
)

cp "$stage/$archive_name" "$release_dir/$archive_name"
cp "$stage/$cli_name" "$release_dir/$cli_name"
cp "$stage/release.json" "$release_dir/release.json"
cp "$stage/RELEASE_NOTES.md" "$release_dir/RELEASE_NOTES.md"
cp "$stage/SHA256SUMS" "$release_dir/SHA256SUMS"

echo "$release_dir"
