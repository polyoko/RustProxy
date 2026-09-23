#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
apk="$root/android/app/build/outputs/apk/release/app-release.apk"
if [ "${1:-}" != "" ] && [[ "$1" == *.apk ]]; then
    apk="$1"
    shift
fi
[ -f "$apk" ] || { echo "APK not found: $apk" >&2; exit 1; }

serials=("$@")
if [ "${#serials[@]}" -eq 0 ]; then
    while IFS= read -r serial; do serials+=("$serial"); done < <(adb devices | awk '$2 == "device" { print $1 }')
fi
[ "${#serials[@]}" -gt 0 ] || { echo "No connected ADB devices" >&2; exit 1; }

for serial in "${serials[@]}"; do
    adb -s "$serial" install -r "$apk"
done
