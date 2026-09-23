#!/usr/bin/env bash
set -euo pipefail

serials=("$@")
if [ "${#serials[@]}" -eq 0 ]; then
    while IFS= read -r serial; do serials+=("$serial"); done < <(adb devices | awk '$2 == "device" { print $1 }')
fi
[ "${#serials[@]}" -gt 0 ] || { echo "No connected ADB devices" >&2; exit 1; }

for serial in "${serials[@]}"; do
    adb -s "$serial" uninstall com.barissenel.rustproxy || true
done
