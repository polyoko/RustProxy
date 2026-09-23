#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
command -v cargo-ndk >/dev/null || { echo "cargo-ndk is required" >&2; exit 1; }
command -v gradle >/dev/null || { echo "Gradle is required" >&2; exit 1; }

cd "$root"
cargo ndk -t arm64-v8a -t armeabi-v7a -o android/app/src/main/jniLibs build --release
gradle -p android assembleRelease
