#!/usr/bin/env bash
# build.sh FIRMWARE_SRC_DIR GLUE OUT [setup-symbol-needs]
# Compiles the firmware's main.cpp, wifi.c and opendroneid.c for the host.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
src="$1"; glue="$2"; out="$3"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
flags=(-O1 -w -include stddef.h -DARDUINO_ARCH_ESP32 -DESP32 -I"$here/shim" -I"$src" -I"$src/../include")
cd "$work"
gcc "${flags[@]}" -c "$src/opendroneid.c" "$src/wifi.c"
g++ "${flags[@]}" -std=gnu++17 -Dsetup=fw_setup -Dloop=fw_loop -c "$src/main.cpp" -o main.o
g++ "${flags[@]}" -std=gnu++17 -c "$here/harness.cpp" "$here/$glue"
g++ -o "$out" ./*.o -lm
