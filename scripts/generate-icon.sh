#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$root/assets"
source_png="$root/assets/YubiTouch-1024.png"

CLANG_MODULE_CACHE_PATH=${CLANG_MODULE_CACHE_PATH:-/tmp/yubitouch-clang-cache} \
SWIFT_MODULECACHE_PATH=${SWIFT_MODULECACHE_PATH:-/tmp/yubitouch-swift-cache} \
  swift "$root/scripts/generate-icon.swift" "$source_png"
echo "$source_png"
