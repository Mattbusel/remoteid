# Changelog

## 0.2.0

From decoding to trust decisions.

* `trust`: per-transmitter verdicts (`Authenticated`, `Plausible`,
  `Suspicious`, `Spoofed`) with reasons and a score, from kinematic
  plausibility, timestamp and counter continuity, Wi-Fi TSF behaviour,
  signal jumps, ANSI/CTA-2063-A serial checks, fingerprints of two public
  spoofers, and DRIP state. `no_std`, no allocation (`TrustState`).
* `Tracker` now assesses every transmitter (`TrackedUas::assessment`),
  takes `Observation`s with UTC clock, RSSI and Beacon header
  (`Tracker::observe`), and compares transmitters: one UAS ID at
  incompatible positions, several addresses sharing one radio clock.
  `TrackerConfig` gained a `trust` field.
* `drip`: DRIP Entity Tags (RFC 9374), the four DRIP SAM formats (RFC
  9575), DRIP FEC with single page recovery, a counter aware page
  assembler for Bluetooth 4, `paginate` for transmitters.
* `auth` (feature `verify`): Ed25519 / cSHAKE128 verification of Links,
  Wrappers (legacy and extended transport), Manifests and Frames, DET to HI
  binding, key stores, the `AuthScheme` trait, and `DripSigner`. Tested
  against the RFC 9575 Appendix B.2.1 example; four places where that
  example differs from the RFC text are documented in `docs/drip.md`.
* `ridf`: RIDF v0, a record format for raw frames with receiver time,
  RSSI, transport and receiver position (`docs/ridf.md`).
* `aircraft_json`: readsb `aircraft.json` so tar1090 shows drones, with
  the operator position left out by default.
* `wifi::beacon_info`, `wifi::parse_vendor_element`; `Transport`;
  `Transmitter` is now available without `std`.
* Python package `remoteid` (PyO3, abi3): `decode`, `Tracker`,
  `Verdict`, `aircraft_json`, RIDF helpers.
* Spoof corpus built from the spoofers' source with no radio
  (`tools/spoof-corpus`, `docs/spoof-corpus.md`), property tests and four
  cargo-fuzz targets.

## 0.1.0

First release: all F3411-22a / EN 4709-002 message types and message packs
(decode and encode), Bluetooth 4 / 5 and Wi-Fi Beacon / NAN framing,
radiotap stripping, the French beacon format, `UasData` with authentication
page joining, and the `std` `Tracker`.
