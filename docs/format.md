# Remote ID byte layouts

All multi-byte numbers are little endian. Every message is 25 bytes. Byte 0
is `type << 4 | protocol_version` (version 0 = F3411-19, 1 = EN 4709-002 P1,
2 = F3411-22a).

| Type | Message | Layout after byte 0 |
|---|---|---|
| 0 | Basic ID | `[1]` ID type (high nibble), UA type (low); `[2..22]` UAS ID; `[22..25]` reserved |
| 1 | Location | `[1]` status (bits 7-4), reserved (3), height type (2), E/W direction (1), speed multiplier (0); `[2]` direction; `[3]` speed; `[4]` vertical speed (i8, 0.5 m/s); `[5..9]` latitude (i32, 1e-7 deg); `[9..13]` longitude; `[13..15]` pressure altitude; `[15..17]` geodetic altitude; `[17..19]` height; `[19]` vertical / horizontal accuracy; `[20]` baro / speed accuracy; `[21..23]` timestamp (0.1 s after the hour, 0xFFFF unknown); `[23]` timestamp accuracy (low nibble) |
| 2 | Auth | `[1]` auth type (high), page (low). Page 0: `[2]` last page index, `[3]` length, `[4..8]` timestamp (s since 2019-01-01), `[8..25]` 17 data bytes. Other pages: `[2..25]` 23 data bytes |
| 3 | Self ID | `[1]` description type; `[2..25]` text |
| 4 | System | `[1]` classification (bits 4-2), operator location type (1-0); `[2..6]` operator latitude; `[6..10]` operator longitude; `[10..12]` area count; `[12]` area radius (10 m); `[13..15]` area ceiling; `[15..17]` area floor; `[17]` EU category / class; `[18..20]` operator altitude; `[20..24]` timestamp (s since 2019-01-01) |
| 5 | Operator ID | `[1]` operator ID type; `[2..22]` operator ID; `[22..25]` reserved |
| 15 | Message pack | `[1]` single message size (25); `[2]` message count (1 to 9); then the messages |

## Encodings

* Altitudes and heights: `raw * 0.5 - 1000` meters; raw 0 (-1000 m) means unknown.
* Direction: `raw + 180` if the E/W bit is set. 361 means unknown.
* Horizontal speed: `raw * 0.25` m/s, or `raw * 0.75 + 63.75` with the multiplier bit. 255 m/s means unknown.
* Vertical speed: `raw * 0.5` m/s. 63 m/s means unknown.
* Latitude and longitude 0, 0 means unknown.

## Transports

| Transport | Framing |
|---|---|
| Bluetooth 4 / 5 | AD structure: length, `0x16`, UUID `FA FF`, app code `0x0D`, counter, payload (one message on BT4, a pack on BT5) |
| Wi-Fi Beacon | Element 221, OUI `FA:0B:BC`, type `0x0D`, counter, pack |
| Wi-Fi NAN | Public action frame to `51:6F:9A:01:00:00`, Wi-Fi Alliance OUI type `0x13`, Service Descriptor Attribute with service ID `88 69 19 9D 92 09`; its service info is counter then pack |
| French beacon | Element 221, OUI `6A:5C:35`, type `0x01`, then TLVs with big-endian values |
