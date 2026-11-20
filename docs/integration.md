# Using remoteid inside another project

remoteid is a decoder, not a receiver. It does not open radios, sockets or
threads: your code hands it the bytes your Bluetooth scanner, Wi-Fi monitor
interface, SDR or MAVLink link already produced, and gets typed messages,
a per-aircraft record and a trust verdict back. Time comes from the caller,
so replayed captures and live traffic behave the same.

## Add it

```toml
[dependencies]
remoteid = "0.3"
```

| Feature | Default | Adds | Extra dependencies |
|---|---|---|---|
| `std` | yes | `Tracker` (per-aircraft state, expiry, trust), `std::error::Error`, `aircraft_json`, `capture` (pcap, pcapng, RIDF files), `replay` (scoring receivers against known truth) | none |
| `serde` | no | `Serialize` / `Deserialize` on the decoded types | `serde` (derive, no `std`) |
| `verify` | no | `auth`: DRIP Ed25519 signature checks | `ed25519-dalek`, `sha3` (both `no_std`, default features off) |
| `cli` | no | the `remoteid-replay` binary ([replay.md](replay.md)) and its bundled corpus | none |

With default features the crate has no dependencies. With
`default-features = false` it is `no_std` and never allocates; CI builds it
for `thumbv7em-none-eabihf` and `wasm32-unknown-unknown`.

## The integration in five lines

Wi-Fi monitor mode (radiotap frames from libpcap, an ESP32, a Linux
monitor interface):

```rust
use remoteid::{wifi, Tracker};

fn on_frame(tracker: &mut Tracker, radiotap: &[u8], now_ms: u64) {
    let Ok(rid) = wifi::strip_radiotap(radiotap).and_then(wifi::parse_frame) else { return };
    let uas = tracker.ingest_wifi(&rid, now_ms);
    println!("{:?} at {:?}: {:?}", uas.uas_id(), uas.last_fix(), uas.assessment.verdict);
}
```

Bluetooth is the same with `ble::find_in_advertising_data` and
`Tracker::ingest_ble`. A MAVLink `OPEN_DRONE_ID_*` message carries the same
25 byte payload, so `remoteid::Message::decode(&data)` decodes its data field
directly. For signal strength, a receiver UTC clock and Wi-Fi TSF checks,
use `Tracker::observe` with an `Observation` ([trust.md](trust.md)).

Complete programs: [`examples/pcap_tracker.rs`](../examples/pcap_tracker.rs)
(capture file to aircraft list) and
[`examples/trust_report.rs`](../examples/trust_report.rs) (verdicts with
reasons).

## The surface to depend on

| Item | What it is |
|---|---|
| `Message`, `BasicId`, `Location`, `Auth`, `SelfId`, `System`, `OperatorId`, `MessagePack` | the six message types and packs, `decode` / `encode` |
| `ble::find_in_advertising_data`, `ble::parse_service_data` | Bluetooth 4 and 5 |
| `wifi::strip_radiotap`, `wifi::parse_frame`, `wifi::find_in_elements` | Wi-Fi Beacon and NAN |
| `UasData` | everything heard from one aircraft, merged |
| `Tracker`, `TrackedUas`, `TrackerConfig` | per-transmitter state, counters, expiry (feature `std`) |
| `Verdict`, `Assessment`, `Reason`, `TrustConfig` | trust verdicts with reasons |
| `aircraft_json::to_string` | tar1090 / readsb `aircraft.json` |
| `Error` | one error type for every parser and encoder |

No function panics on input bytes: every parser returns `Result` or
`Option`. That is checked with 200,000 random inputs in the tests and four
`cargo-fuzz` targets in CI.

Python: the same decoder and verdicts as an abi3 wheel
([python.md](python.md)), typed (`py.typed` and `.pyi` stubs).

## Compatibility

- MSRV: Rust 1.70, checked in CI (library without dev-dependencies).
  Edition 2021.
- License: MIT.
- `#![forbid(unsafe_code)]`. CI runs on Linux, Windows and macOS, plus
  the `no_std` targets above.
- Versioning: while the crate is 0.x, a breaking change bumps the minor
  version (0.2 to 0.3) and is listed in [CHANGELOG.md](../CHANGELOG.md).
  Patch releases do not change public signatures. Trust verdicts can change
  in a patch release when a rule is corrected; the changelog says which.
- Decoding is checked field by field against the Open Drone ID reference C
  library on every push ([testing.md](testing.md)).

Maintained by Matt Busel ([github.com/Mattbusel](https://github.com/Mattbusel)).
`uas-cot` builds on it to put Remote ID aircraft on TAK maps. Issues and
pull requests: [github.com/Mattbusel/remoteid](https://github.com/Mattbusel/remoteid/issues).
