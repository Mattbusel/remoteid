# RIDF v0

RIDF is a record format for raw Remote ID frames as a receiver saw them.
Checks that compare receivers (does the signal strength fit the claimed
position, did two receivers hear the same frame, does the arrival time fit)
need more than decoded fields: the raw message, when it arrived, how strong
it was, which link it came on and where the receiver was. One RIDF record
carries exactly that, so receivers written in any language can feed one
trust engine over a file, a pipe or UDP.

Status: version 0, implemented by `remoteid::ridf` (Rust, `no_std`) and
`remoteid.read_ridf` / `remoteid.write_ridf` (Python). Changes that are
not backward compatible will use a new version number.

## Record

All integers are little endian.

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | Record length: bytes after this field (34 + payload + extensions) |
| 2 | 1 | Version, 0 |
| 3 | 1 | Transport: 0 unknown, 1 Bluetooth 4 legacy, 2 Bluetooth 5 extended or long range, 3 Wi-Fi Beacon, 4 Wi-Fi NAN, 5 other |
| 4 | 1 | Flags (below) |
| 5 | 1 | Message counter from the frame |
| 6 | 8 | Receiver time, nanoseconds (u64) |
| 14 | 1 | RSSI, dBm (i8) |
| 15 | 1 | Payload length (0 to 255) |
| 16 | 6 | Transmitter address, as on the air |
| 22 | 2 | Receiver ID (u16), to tell receivers apart |
| 24 | 4 | Receiver latitude, 1e-7 degrees (i32) |
| 28 | 4 | Receiver longitude, 1e-7 degrees (i32) |
| 32 | 4 | Receiver altitude above the WGS84 ellipsoid, millimeters (i32) |
| 36 | n | Payload: the ASTM F3411 message (25 bytes) or message pack, header byte first, no counter |
| 36 + n | ... | Extensions until the end of the record |

Flags:

| Bit | Meaning when set |
|---|---|
| 0x01 | RSSI is valid |
| 0x02 | Receiver position is valid |
| 0x04 | Counter is valid |
| 0x08 | Address is valid |
| 0x10 | Receiver time is UTC (nanoseconds since 1970-01-01); otherwise a monotonic clock with an arbitrary origin |

Fields whose flag is clear are written as zero and ignored by readers.

## Extensions

Type (1 byte), length (1 byte), value. Readers skip unknown types.

| Type | Value |
|---|---|
| 0x01 | Wi-Fi Beacon header: TSF (u64, microseconds), Beacon interval (u16, TU), capability (u16), sequence number (u16), then the SSID bytes |

## Files and streams

A file starts with the 8 byte header `52 49 44 46 00 00 00 00` ("RIDF",
version, three zero bytes) followed by records back to back. A record
travelling on its own, for example one UDP datagram, needs no header.

## Example

```rust
use remoteid::ridf::{Record, ReceiverPosition};
use remoteid::Transport;

let payload = [0x12u8; 25];
let rec = Record {
    transport: Transport::Bluetooth4,
    counter: Some(7),
    rx_time_ns: 1_794_916_800_000_000_000,
    utc: true,
    rssi_dbm: Some(-71),
    address: Some([0xc0, 1, 2, 3, 4, 5]),
    receiver_id: 2,
    receiver: Some(ReceiverPosition { latitude: 46.948, longitude: 7.447, altitude_m: 540.0 }),
    payload: &payload,
    extensions: &[],
};
let mut buf = [0u8; 128];
let n = rec.encode(&mut buf).unwrap();
let (back, _) = Record::decode(&buf[..n]).unwrap();
assert_eq!(back, rec);
// back.observation() feeds Tracker::observe; back.transmitter() is its key.
```
