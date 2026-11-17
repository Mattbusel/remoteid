#!/usr/bin/env bash
# Rebuilds tests/data/c_reference_*.jsonl from the reference C library.
# Needs gcc, git and python3. Run from the repository root.
set -euo pipefail
work=$(mktemp -d)
git clone -q https://github.com/opendroneid/opendroneid-core-c.git "$work/core"
git -C "$work/core" checkout -q 849c03adbe0cdd68997a462fafab397edcfe53f3
L="$work/core/libopendroneid"
gcc -O2 -DODID_DISABLE_PRINTF -I"$L" tools/c-reference/ref.c "$L/opendroneid.c" "$L/wifi.c" -lm -o "$work/ref"
python3 tools/c-reference/extract.py "$work"
"$work/ref" < "$work/msgs.hex" > tests/data/c_reference_messages.jsonl
"$work/ref" pack < "$work/packs.hex" > tests/data/c_reference_packs.jsonl
wc -l tests/data/c_reference_*.jsonl
