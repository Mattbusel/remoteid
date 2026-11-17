# remoteid

[![crates.io](https://img.shields.io/crates/v/remoteid.svg)](https://crates.io/crates/remoteid)
[![docs.rs](https://docs.rs/remoteid/badge.svg)](https://docs.rs/remoteid)
[![CI](https://github.com/Mattbusel/remoteid/actions/workflows/ci.yml/badge.svg)](https://github.com/Mattbusel/remoteid/actions/workflows/ci.yml)

Drone Remote ID for Rust. It decodes and encodes the broadcast messages of
**ASTM F3411-22a** and **ASD-STAN EN 4709-002** (the FAA and EU Remote ID
formats, implemented in C by [Open Drone ID](https://github.com/opendroneid)),
and pulls them out of real radio frames:

| Transport | Function |
|---|---|
| Bluetooth 4 legacy advertising | `ble::find_in_advertising_data`, `ble::parse_service_data` |
| Bluetooth 5 extended / long range | same functions; the payload is a message pack |
| Wi-Fi Beacon vendor element | `wifi::parse_frame`, `wifi::find_in_elements` |
| Wi-Fi NAN service discovery | `wifi::parse_frame`, `wifi::parse_nan_action` |
| Monitor mode captures | `wifi::strip_radiotap` (drops the FCS too) |
| French beacon (pre-EU format) | `france::find_in_elements` |

Pure Rust, no dependencies, `no_std`, no allocation outside the optional
`Tracker`, `#![forbid(unsafe_code)]`. It builds for microcontrollers
(`thumbv7em-none-eabihf`) and for the browser (`wasm32-unknown-unknown`).

## Why

Rust Remote ID receivers on GitHub (detectors, ground stations, SDR
tools) each hand-roll their own decoder, or link the C library through FFI,
which needs a C toolchain and bindgen and does not build for wasm. This
crate is the decoder they can share, checked field by field against the C
reference.

## Use

```toml
[dependencies]
remoteid = "0.1"
```

Bluetooth (for example service data from `btleplug` for UUID `0xFFFA`):

```rust
use remoteid::{ble, Frame, Message};

fn on_service_data(data: &[u8]) {
    let Ok(rid) = ble::parse_service_data(data) else { return };
    match rid.frame() {
        Ok(Frame::Message(Message::Location(loc))) if loc.is_plausible() => {
            println!("{:?} at {:?}, {:?} m", loc.status, loc.position(), loc.altitude_geo);
        }
        Ok(frame) => frame.for_each_message(|m| println!("{m:?}")),
        Err(e) => eprintln!("not decodable: {e}"),
    }
}
```

Wi-Fi monitor mode (radiotap frames from pcap, `libpcap`, or an ESP32):

```rust
use remoteid::{wifi, Tracker};

fn on_packet(tracker: &mut Tracker, radiotap_frame: &[u8], now_ms: u64) {
    let Ok(frame) = wifi::strip_radiotap(radiotap_frame) else { return };
    if let Ok(rid) = wifi::parse_frame(frame) {
        let uas = tracker.ingest_wifi(&rid, now_ms);
        println!("{:?}: {:?}", uas.data.primary_id(), uas.data.location.as_ref().and_then(|l| l.position()));
    }
}
```

Transmitting (for example from a Bluetooth 4 beacon):

```rust
use remoteid::{ble, BasicId, IdType, Message, UaType};

let id = BasicId::new(IdType::SerialNumber, UaType::HelicopterOrMultirotor, "1596F35074529ABCDEFG")?;
let mut adv = [0u8; 31];
let n = ble::write_advertising_data(0, &Message::BasicId(id).encode()?, &mut adv)?;
assert_eq!(n, 31);
# Ok::<(), remoteid::Error>(())
```

A complete program that reads a capture and prints every aircraft is in
[`examples/pcap_tracker.rs`](examples/pcap_tracker.rs):

```text
$ cargo run --example pcap_tracker -- tests/data/odid_wifi_bcn_sample.pcap
Wifi([132, 204, 168, 96, 67, 36])
  id:        Some("MFG1A0123456789")
  operator:  Some("GBR-OP-123ABCD")
  self id:   Some("Recreational")
  status:    Undeclared
  position:  Some((45.5470818, -122.9668346))
  alt geo:   Some(237.0) m, height Some(100.0) m
  speed:     Some(20.5) m/s, track Some(280.0) deg
  operator position: Some((45.5443876, -122.9726866))
  frames:    21 received, 2 est. missed, 0 duplicates, 0 undecodable
```

## What you get

* All six message types (Basic ID, Location, Auth, Self ID, System,
  Operator ID) and message packs, decode and encode. Unknown values
  ("no value" sentinels such as direction 361 or altitude -1000 m) decode to
  `None`; reserved enum codes are kept as `Other(u8)` so nothing is lost.
* `Location::check()` reports out of range values. The decoder accepts any
  bit pattern, as the C library does, so corrupted or spoofed frames still
  decode; call `check()` before you plot them.
* `BasicId::serial_number()` splits and validates ANSI/CTA-2063-A serial
  numbers (manufacturer code, length character, serial).
* `UasData` merges messages into one record per aircraft and joins
  multi-page authentication data (`auth_data`). Signatures are not verified:
  the key scheme is operator specific.
* `Tracker` (with the default `std` feature) keys aircraft by radio address,
  counts duplicate and missed frames from the message counters, and expires
  aircraft that went quiet. It takes timestamps from the caller, so a
  replayed capture behaves the same as a live receiver.
* `serde` feature for `Serialize` / `Deserialize` on the decoded types.

## How it is tested

* **Against the reference C library.** Every distinct message in the three
  public Open Drone ID sample captures (82 messages, some of them corrupted
  in the air) was decoded by `opendroneid-core-c`; the test suite checks
  that this crate produces the same value for every field. Every one of the
  336 message packs is accepted or rejected exactly as the C library does.
  CI rebuilds the C library and regenerates these files on every push.
* **On real captures, end to end.** Wi-Fi Beacon, Wi-Fi NAN and Bluetooth 5
  long range captures go through `strip_radiotap` / `parse_frame` /
  `find_in_advertising_data` into the tracker. In the long range capture,
  the 28 frames the sniffer marked with a bad CRC are exactly the 28 frames
  the tracker reports as missed from counter gaps.
* **Round trips.** Values on the transmitted grid survive encode then
  decode exactly, and the Wi-Fi sample messages re-encode to the bytes that
  were on the air.
* **Random input.** 200,000 random and header-biased buffers through every
  parser, with no panic.

See [docs/testing.md](docs/testing.md) for how to regenerate the reference
data, and [docs/format.md](docs/format.md) for the byte layouts.

## Status

0.1: the message layer and transports are complete and checked against the
reference. Not included yet: MAVLink `OPEN_DRONE_ID_*` conversion (the
MAVLink messages carry the same 25 byte payloads, so `Message::decode` works
on their data fields directly) and Network Remote ID (ASTM F3411 NetRID
JSON).

## License

MIT. The sample captures in `tests/data` come from
[opendroneid/wireshark-dissector](https://github.com/opendroneid/wireshark-dissector)
under the Apache License 2.0 (`tests/data/LICENSE-APACHE-opendroneid`); they
are not part of the published crate.
