#!/usr/bin/env bash
set -euo pipefail
umask 077

android_dir="$(cd "$(dirname "$0")/.." && pwd)"
key_dir="$android_dir/keystore"
key_file="$key_dir/rustproxy-release.jks"
properties="$android_dir/keystore.properties"

if [ -e "$key_file" ] || [ -e "$properties" ]; then
    echo "Signing material already exists; refusing to overwrite it." >&2
    exit 1
fi

mkdir -p "$key_dir"
read -r -s -p "Keystore password: " store_password
printf '\n'
read -r -s -p "Key password (enter for same): " key_password
printf '\n'
key_password="${key_password:-$store_password}"

keytool -genkeypair -keystore "$key_file" -storetype PKCS12 -alias rustproxy \
    -storepass "$store_password" -keypass "$key_password" -keyalg RSA -keysize 4096 \
    -validity 10000 -dname "CN=RustProxy, OU=Proxy, O=UII, C=TH"

printf 'storeFile=keystore/rustproxy-release.jks\nstorePassword=%s\nkeyAlias=rustproxy\nkeyPassword=%s\n' \
    "$store_password" "$key_password" > "$properties"
echo "Created $key_file. Back up it and its passwords before installing any release."
