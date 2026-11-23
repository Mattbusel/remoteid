# Changelog

## 0.4.0

**Why:** a decoded drone is not yet an answer. A security operator standing at
a fence needs three plain facts the raw fields do not spell out on their own:
*where did it launch from*, *who registered it*, and *which way is it going*.
This release turns the bytes the crate already decodes into those three
readouts. Additive; no API change.

* **Where it launched from.** The System message carries the operator
  position with a tag for what that position is. New `System::takeoff_position`
  returns it only when the tag is `Takeoff`, i.e. the point the drone lifted
  off from, so an operator can go to the launch site instead of the aircraft.
  `System::live_operator_position` and `System::fixed_operator_position` return
  the position only for a live pilot fix or a fixed station, each one `None`
  unless the transmitter said so, never a guess. `UasData::takeoff_position`
  and `UasData::pilot_position` are the shortcuts.
* **Who is flying it.** New `operator` module and `OperatorIdentity` resolve
  the Operator ID registration string into a displayable identity: the
  registering country, read from the EN 4709-002 ISO 3166-1 alpha-3 prefix
  (`FIN...` -> Finland, `GBR...` -> United Kingdom), and the clean registration
  body. `OperatorId::identity` and `UasData::operator_identity` return it;
  `operator::country_name` is the bare code-to-name lookup over all 249
  officially assigned codes. It reports only what the bytes say: an unknown
  prefix is left whole, and it never claims the registration is genuine (use
  `trust` for the spoof verdict).
* **Where it is heading.** New `track` module and `Trajectory` build a heading
  and range trend from consecutive Location fixes. `Trajectory::heading_deg`
  gives the ground track bearing, but only once the aircraft has moved more
  than `MIN_MOVE_M` (3 m), so a hovering or static emitter yields `None`
  rather than a heading made of GNSS noise. `range_to_m`, `bearing_to` and
  `trend_to` answer, for any target point (the fence, the crowd, the runway),
  how far and which way the drone is and whether it is `Closing` or `Opening`
  (`RangeTrend`). The std `Tracker` keeps a `Trajectory` per aircraft and
  exposes `TrackedUas::heading_deg`.
* All three stay `no_std` and allocate nothing.
* Tests: the launch point, operator country (United Kingdom) and the real
  flight's heading (about 338 degrees over 277 m of ground track, opening from
  its launch point) are checked against the public Open Drone ID Wi-Fi beacon
  capture; the EN 4709-002 country prefix against the reference operator ID
  vector (Finland).
* The GitHub Action, `remoteid-replay` and the Python package are unchanged
  and stay at their previous versions.

## 0.3.3

**Why:** a Remote ID only receiver misses DJI's own DroneID, which carries
the pilot position on DJI models with and without Remote ID. Additive; no
API change.

* New `dji` module (no_std, no dependencies, always built):
  * `FlightInfo::decode` decodes the 91 byte OcuSync DroneID payload an SDR
    demodulator produces and checks its CRC-16 (`crc16`);
    `decode_unchecked` skips the check. Serial, aircraft, home and pilot
    positions (exact radians to degrees), GPS time, yaw, product type
    (`product_name`) and flight UUID. Altitude, height, velocities and
    state flags are kept raw because their units are not established in
    public sources; `altitude_m` / `height_m` apply the feet reading of
    the NDSS 2023 reference receiver.
  * `find_in_elements` / `parse_vendor_element` read the DJI Wi-Fi beacon
    element (OUI `26:37:12`): flight telemetry (record versions 1 and 2)
    and the user entered flight purpose.
  * `antsdr::next_frame` and `antsdr::Report` read the decoded reports an
    AntSDR with DroneID firmware streams over TCP.
  * `FlightInfo::messages` builds the equivalent Remote ID Basic ID,
    Location and System messages; `FlightInfo::key` gives a stable
    transmitter key from the serial.
* New `Tracker::ingest_dji`: DJI aircraft are tracked, expired and graded
  by `trust` like Remote ID aircraft.
* New `Error::ChecksumMismatch` (the enum is `non_exhaustive`).
* Tests: payloads demodulated from the NDSS 2023 Mini 2 and Mavic Air 2
  sample captures; the CRC verdict matches the reference receiver on all 9
  frames and every field of the Mavic Air 2 frame is checked.
* The GitHub Action, `remoteid-replay` and the Python package are
  unchanged and stay at 0.3.2.

## 0.3.2

Documentation and metadata only; no code change.

* README and crates.io description lead with the result: 10 fake drones
  replayed through the open-source receivers people run, 0 flagged;
  remoteid flags 10 of 10. If a receiver can't say SPOOFED, it amplifies
  the attacker.
* The GitHub Action and docs point at v0.3.2.

## 0.3.1

Documentation and metadata only; no code change.

* README opens with the replay result as a table: eight open-source
  receivers flagged 0 of 10 spoofed transmitters and showed 62 of 80
  receiver and transmitter pairs as real drones; remoteid flagged 10 of 10.
* New "Used by" section (AirHound; the Open Drone ID reference C library
  lists this crate as its Rust implementation).
* crates.io description and keywords say what the crate refuses to do.
* The GitHub Action and docs point at v0.3.1.

## 0.3.0

**Why:** open-source Remote ID receivers believe spoofers. Replayed
through eight of them (14 to 2,479 stars), 10 spoofed Wi-Fi transmitters
from two public tools were flagged 0 times and shown as real drones 62
times out of 80 (docs/receivers.md). Trust verdicts in a library change
nothing until a receiver's CI fails when it accepts a spoofer, so 0.3
ships the gate.

* New `remoteid-replay` binary (feature `cli`): `run` replays the bundled
  corpus (12 spoofed transmitters from cyber-defence-campus/droneRemoteIDSpoofer
  and jjshoots/RemoteIDSpoofer, plus the Open Drone ID sample captures of a
  real transmitter) through any receiver command that prints JSON, and
  exits 1 when a spoofed transmitter is accepted, when a real one is
  flagged, when the receiver crashes, or when it shows nothing at all. A
  report without a verdict counts as accepted. Also `score` (saved
  output), `verdicts` (remoteid's own verdicts for pcap, pcapng or RIDF),
  `frames` (raw frames as JSON lines or RIDF) and `corpus`.
* New GitHub Action (`action.yml`): `uses: Mattbusel/remoteid@v0.3.0`
  with `receiver:`; the table goes to the job summary.
* New `capture` module (std): pcap (both byte orders, micro and
  nanosecond), pcapng (interface timestamp resolution) and RIDF in,
  `CapturedFrame`s and a replayed `Tracker` out; radiotap, bare 802.11,
  BLE link layer (with and without PHDR) and Nordic BLE sniffer link
  types. Malformed files return `CaptureError`, never panic (new fuzz
  target `capture`). `to_ridf` writes frames as RIDF for receivers that do
  not read pcap. The test suite now reads its captures through this module.
* New `replay` module (std): `expected` (transmitters of a capture with
  every UAS ID they sent), `Report::parse` (one receiver output line),
  `score`, `Totals`, `Gate`.
* `tools/receivers`: the adapters that ran each receiver's own decode path
  for docs/receivers.md, including a host build of ESP32 Arduino scanner
  firmware.
* The crate now ships the corpus captures (about 860 KB) for the binary;
  the package uses an `include` list instead of `exclude`.
* Python package: version follows the crate; its API is unchanged.

The `no_std` core is unchanged: `capture`, `replay` and the binary need
`std`.

## 0.2.3

Python package fixes; the Rust crate is unchanged.

* `Tracker.auto_expire` was exposed to Python by mistake (an internal
  helper inside the `#[pymethods]` block). It is private again; expiry
  still runs on its own inside `ingest`, and `Tracker.expire` is the
  public call.
* The type stubs (`py.typed`) now match the module: `Tracker(...)` is
  described by `__new__` (mypy reported every keyword argument as
  unknown), `Tracker` and `Verdict` are `@final`, `__all__` is declared,
  and the `Address` alias, which never existed at runtime, is private
  (`_Address`). CI runs `mypy.stubtest` against the built wheel.

## 0.2.2

Documentation and packaging; no code changes.

* README: the install line said `remoteid = "0.1"`, so projects copying it
  got the release without trust verdicts or DRIP verification. It now says
  0.2, and lists `trust` and the `verify` feature.
* New `docs/integration.md`: features and their dependencies, the API to
  depend on, MSRV, versioning. Its example runs as a doctest.
* `docs/python.md`: install from the GitHub release wheels until the PyPI
  project is published.

## 0.2.1

Fixes from an independent review of 0.2.0. Some verdicts change.

* DRIP: a signature now counts for an aircraft only when its signer DET is
  a DET that aircraft broadcasts. `DripEd25519` returns `Unverifiable` when
  no DET Basic ID has been heard (0.2.0 skipped the check), and
  `TrustState::record_auth` ignores any valid result from another signer.
  In 0.2.0 a spoofer relaying a nearby DRIP aircraft's signed Wrapper under
  its own serial number was shown as authenticated.
* DRIP: `Authenticated` now needs the signature checked against its VNB /
  VNA window with a receiver UTC clock (`TrustConfig::auth_requires_clock`,
  default true); without one a recorded signature can be replayed.
* `TrustState::authenticated_det` and `TrackedUas::uas_id`: the identity
  is the signing DET once an aircraft is verified; `aircraft_json` and the
  Python `Verdict.uas_id` use it.
* Teleport: a single fix off the track that the next fix comes back from
  is dropped as a GNSS outlier and counts half as much as a jump that
  sticks. In 0.2.0 one outlier counted twice (out and back) and made an
  honest aircraft spoofed for five minutes.
* All count and ratio rules count inside a sliding `memory_ms` window
  instead of over the lifetime, so isolated events far apart no longer add
  up.
* Moderate reasons alone now cap at `Suspicious`
  (`TrustConfig::moderate_spoofed`, default `None`; `Some(3)` is the 0.2.0
  rule), until the kinematic and clock checks are measured on real flights.
* Signal strength and Wi-Fi TSF continuity are kept per receiver
  (`Observation::receiver_id`, set from RIDF records).
* A Location timestamp of 0.0 counts as "not provided" only until the
  transmitter has sent a non zero one.
* `Tracker`: at most `TrackerConfig::max_transmitters` entries (default
  4096; the least recently heard is dropped), an index by UAS ID for the
  identity cross-check, `Tracker::remove`, and every received Location
  refreshes the fix used by the cross-check (also when it repeats).
* Python: `Tracker.ingest` raises ValueError for input without a
  transmitter address instead of merging all such frames into one track;
  `use_system_clock` now defaults to False; new `auth_requires_clock` and
  `max_transmitters`; expired transmitters are dropped as frames come in.
* Python wheels also for musllinux (x86_64, aarch64) and manylinux armv7.
* The crate package no longer ships `tests/` (its data files were left
  out, so `cargo test` on the package failed).
* Docs: measured `TrustState` size (7256 bytes with `verify` on x86_64,
  not "about 4 KB"), what the legitimate corpus does and does not cover,
  multi-receiver use of RIDF.

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
