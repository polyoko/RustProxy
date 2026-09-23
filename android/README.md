# RustProxy Android

`me.uii.rustproxy` is a separately signed replacement for the legacy Play Store
package `com.barissenel.rustproxy`. It ships arm64-v8a and armeabi-v7a (32-bit phones) and sets minSdk 26.

## Build and sign

Install JDK 17, Android SDK platform 35 / NDK, Gradle, Rust's
`aarch64-linux-android` and `armv7-linux-androideabi` targets, and `cargo-ndk`. Create the signing material once:

```sh
./android/scripts/create-signing-key.sh
./android/scripts/build-release.sh
```

The generated `android/keystore/` directory and `android/keystore.properties` are
ignored by Git. Back up both the `.jks` file and its password in two independent,
encrypted locations. Losing either prevents future updates under this package name.

## Device rollout

Install the new APK first, scan the dashboard QR, select RustProxy as the Assistant,
and verify that the agent appears on the dashboard. Only then remove the legacy app:

```sh
./android/scripts/install-devices.sh path/to/app-release.apk SERIAL1 SERIAL2
./android/scripts/uninstall-legacy.sh SERIAL1 SERIAL2
```

The second command is intentionally separate: an install script cannot know whether
the replacement has connected successfully.
