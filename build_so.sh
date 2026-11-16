#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Android/Sdk}}"
NDK_ROOT="${ANDROID_NDK_HOME:-${NDK_HOME:-}}"

if [[ -z "$NDK_ROOT" ]]; then
    NDK_DIR="$SDK_ROOT/ndk"
    if [[ ! -d "$NDK_DIR" ]]; then
        echo "ERROR: Android NDK not found: $NDK_DIR"
        exit 1
    fi

    NDK_VERSION="$(find "$NDK_DIR" -mindepth 1 -maxdepth 1 \
        -type d -printf '%f\n' | sort -V | tail -n 1)"

    NDK_ROOT="$NDK_DIR/$NDK_VERSION"
fi

NDK_BIN="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin"

if [[ ! -x "$NDK_BIN/clang" ]]; then
    echo "ERROR: NDK compiler not found: $NDK_BIN"
    exit 1
fi

export ANDROID_NDK_HOME="$NDK_ROOT"
export NDK_HOME="$NDK_ROOT"

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NDK_BIN/aarch64-linux-android24-clang"
export CC_aarch64_linux_android="$NDK_BIN/aarch64-linux-android24-clang"
export AR_aarch64_linux_android="$NDK_BIN/llvm-ar"

export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER="$NDK_BIN/armv7a-linux-androideabi21-clang"
export CC_armv7_linux_androideabi="$NDK_BIN/armv7a-linux-androideabi21-clang"
export AR_armv7_linux_androideabi="$NDK_BIN/llvm-ar"

echo "Android NDK: $NDK_ROOT"
echo
echo "[1/2] Building ARM64..."
cargo build --release --locked --target aarch64-linux-android

echo
echo "[2/2] Building ARMv7..."
cargo build --release --locked --target armv7-linux-androideabi

ARM64_SO="target/aarch64-linux-android/release/libtgwsproxy.so"
ARMV7_SO="target/armv7-linux-androideabi/release/libtgwsproxy.so"

test -f "$ARM64_SO"
test -f "$ARMV7_SO"

echo
echo "=== BUILD SUCCESS ==="
file "$ARM64_SO"
file "$ARMV7_SO"

echo
echo "Libraries were NOT copied to jniLibs."
echo "Existing working Android libraries remain untouched."
