#!/usr/bin/env bash
# Rebuilds tests/data/spoof/*.pcap from the source of two public Remote ID
# spoofers. No radio is used: each tool's own frame building code runs on
# the host and its frames are written to pcap files.
#
# Needs: git, python3 with scapy 2.6.1 (pip install scapy==2.6.1), g++, gcc.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
out="$root/tests/data/spoof"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

CDC_REPO=https://github.com/cyber-defence-campus/droneRemoteIDSpoofer.git
CDC_COMMIT=61fa6348e3a276cde313060e51ae57fad85b3405
JJ_REPO=https://github.com/jjshoots/RemoteIDSpoofer.git
JJ_COMMIT=c79ab77c7f59af42574ad361b63e6697723d636d

mkdir -p "$out"

git clone -q -c core.autocrlf=false "$CDC_REPO" "$work/cdc"
git -C "$work/cdc" checkout -q "$CDC_COMMIT"
python3 "$here/cdc_harness.py" "$work/cdc" "$out"

git clone -q -c core.autocrlf=false "$JJ_REPO" "$work/jj"
git -C "$work/jj" checkout -q "$JJ_COMMIT"
src="$work/jj/RemoteIDSpoofer"
flags=(-O1 -DARDUINO=10819 -DARDUINO_ARCH_ESP8266 -I"$here/jjshoots" -I"$src" -w)
cd "$work"
gcc "${flags[@]}" -c "$src/opendroneid.c" "$src/wifi.c" "$src/alt_unix_time.c"
g++ "${flags[@]}" -std=c++17 -c "$src/spoofer.cpp" "$src/id_open.cpp" "$src/id_open_beacon.cpp" "$src/utm.cpp" "$here/jjshoots/harness.cpp"
g++ -o harness ./*.o -lm
TZ=UTC ./harness "$out/jjshoots_esp8266_beacon_4drones.pcap" 4 47.3763 8.5312 40
TZ=UTC ./harness "$out/jjshoots_esp8266_beacon_1drone.pcap" 1 47.3763 8.5312 40
