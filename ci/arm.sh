#!/usr/bin/env bash
# Cross-compile sparrowd for an ARM target with Ubuntu's cross gcc, then run the unit
# tests, a fuzz smoke run and the 40-router integration test under qemu-user.
# usage: ci/arm.sh aarch64|armv7      (prints one ARM_RESULT line at the end)
set -euo pipefail

target=${1:?usage: ci/arm.sh aarch64|armv7}
case "$target" in
    aarch64) triple=aarch64-linux-gnu;   pkgs="gcc-aarch64-linux-gnu libc6-dev-arm64-cross"; qarch=aarch64 ;;
    armv7)   triple=arm-linux-gnueabihf; pkgs="gcc-arm-linux-gnueabihf libc6-dev-armhf-cross"; qarch=arm ;;
    *) echo "unknown target: $target" >&2; exit 2 ;;
esac

if [[ "${CI:-}" == "true" ]]; then
    sudo apt-get update -qq
    # shellcheck disable=SC2086
    sudo apt-get install -y -qq --no-install-recommends $pkgs file python3 >/dev/null
    sudo apt-get install -y -qq --no-install-recommends qemu-user-static >/dev/null ||
        sudo apt-get install -y -qq --no-install-recommends qemu-user >/dev/null
fi

qemu=$(command -v "qemu-$qarch-static" || command -v "qemu-$qarch")
cc=$triple-gcc
strip="$triple-strip -s"
out=dist/$target
mkdir -p "$out"
echo "toolchain: $($cc --version | head -1)"
echo "emulator:  $qemu ($($qemu --version | head -1))"

# 1) dynamically linked build: what a glibc-based target image would ship
make clean >/dev/null
make all CC="$cc" STRIP="$strip"
cp build/sparrowd.stripped "$out/sparrowd"
dyn_bytes=$(stat -c %s "$out/sparrowd")
read -r text data bss _ < <("$triple-size" build/sparrowd | tail -1)

# 2) statically linked build: runs under qemu-user without a target sysroot
make clean >/dev/null
make all build/test_unit_plain build/fuzz_driver_plain CC="$cc" STRIP="$strip" LDFLAGS=-static
cp build/sparrowd.stripped "$out/sparrowd-static"
static_bytes=$(stat -c %s "$out/sparrowd-static")
file "$out/sparrowd" "$out/sparrowd-static" | tee "$out/file.txt"

# 3) run everything on the emulated ARM CPU (no sanitizers: ASan does not run under qemu-user)
"$qemu" build/test_unit_plain | tee "$out/unit.txt"
"$qemu" build/fuzz_driver_plain 200000 1 | tee "$out/fuzz.txt"
SPARROWD=build/sparrowd SPARROWD_EXEC="$qemu" python3 tests/test_integration.py | tee "$out/integration.txt"

unit=$(grep -o '[0-9]*/[0-9]* checks passed' "$out/unit.txt")
integ=$(grep -c '^ok ' "$out/integration.txt")
integ_fail=$(grep -c '^FAIL' "$out/integration.txt" || true)
echo "ARM_RESULT target=$target triple=$triple dynamic_stripped_bytes=$dyn_bytes static_stripped_bytes=$static_bytes text=$text data=$data bss=$bss unit=\"$unit\" integration_ok=$integ integration_fail=$integ_fail fuzz_inputs=200000"
