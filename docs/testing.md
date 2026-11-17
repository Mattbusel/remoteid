# Testing

```text
cargo test --all-features
cargo test --no-default-features --lib
cargo build --no-default-features --target thumbv7em-none-eabihf
cargo build --no-default-features --target wasm32-unknown-unknown
```

## Test data

`tests/data` holds three captures from
[opendroneid/wireshark-dissector](https://github.com/opendroneid/wireshark-dissector)
(commit d12670f, Apache-2.0):

| File | Link type | Content |
|---|---|---|
| `odid_wifi_bcn_sample.pcap` | 127 (radiotap) | 21 Wi-Fi Beacons, each with a full message pack |
| `odid_wifi_sample.pcap` | 127 (radiotap) | 21 NAN action frames, 21 Beacons, NAN sync beacons |
| `odid_bt5_lr_sample.pcapng` | 272 (Nordic BLE) | 274 Bluetooth 5 long range packets from an F3411-19 unit, 28 with bad CRC |

## Reference output from the C library

`tests/data/c_reference_messages.jsonl` and `c_reference_packs.jsonl` are
the output of [opendroneid-core-c](https://github.com/opendroneid/opendroneid-core-c)
at commit 849c03a for every message and pack in the captures, made by the
harness in `tools/c-reference/`. To regenerate (Linux or WSL, needs gcc,
git and python3):

```text
bash tools/c-reference/regenerate.sh
```

CI runs the same script and fails if the output differs from the committed
files, so a change in either library shows up.

`tests/c_reference.rs` then requires every field this crate decodes to
match the C value (floats to the printed precision), and every pack to be
accepted or rejected the same way, with the same number of stored messages
per type.
