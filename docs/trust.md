# Trust verdicts

Remote ID broadcasts are not authenticated in almost every aircraft flying
today, and public tools put fake drones on any receiver from a laptop or a
microcontroller. `remoteid::trust` turns decoded frames into a judgement per
transmitter:

| Verdict | Meaning |
|---|---|
| `Authenticated` | DRIP signatures verify under a trusted key, the signed content matches what was received, and nothing contradicts it |
| `Plausible` | Nothing contradicts the broadcast (honest, unauthenticated aircraft end up here) |
| `Suspicious` | Physical or protocol inconsistencies a real transmitter rarely shows |
| `Spoofed` | A failed signature, a teleport, two radios sharing one identity, or the fingerprint of a known spoofing tool |

Every verdict carries the reasons behind it and a score from 0 (certainly
fake) to 1 (authenticated and consistent); 0.5 means no evidence either way.
The verdict is advice for a detector: nothing is dropped or blocked.

```rust
use remoteid::{Observation, Tracker, Transmitter, Transport, Verdict};

let mut tracker = Tracker::default();
# let payload = [0u8; 25];
# let (address, counter, now_ms, unix_ms, rssi) = ([1u8; 6], 0u8, 0u64, 0u64, -70i8);
let obs = Observation::new(Transport::Bluetooth4, Some(counter), &payload, now_ms)
    .with_unix_ms(unix_ms) // only if the receiver clock is NTP or GNSS synced
    .with_rssi(rssi);
let uas = tracker.observe(Transmitter::Ble(address), &obs);
if uas.assessment.verdict <= Verdict::Suspicious {
    for r in uas.assessment.reasons.iter() {
        println!("{r}");
    }
}
```

`ingest_ble` and `ingest_wifi` from 0.1 still work and feed the same
checks with what they have (no UTC clock, no signal strength). For Wi-Fi,
pass `wifi::beacon_info(frame)` with `Observation::with_beacon` to enable
the TSF checks.

## Reasons

| Reason | Severity | Fires when |
|---|---|---|
| `known_spoofer` | strong | the fingerprint of a public spoofing tool matches (see below) |
| `auth_failed` | strong | a DRIP signature or DET binding fails for this aircraft (clean failures only, see `drip.md`) |
| `teleport` | strong | two positions further apart than `max_speed_mps` allows, plus both stated accuracies, twice |
| `counter_conflict` | strong | one message counter value carries different content within 3 s, three times: two radios behind one address |
| `identity_clone` | strong | the same UAS ID from another transmitter on the same transport at an incompatible position (tracker) |
| `transport_disagreement` | strong | the same, across transports (Bluetooth 4 / 5, Beacon, NAN) |
| `speed_implausible` | moderate | the track flown over 2 to 15 s windows is faster than `max_speed_mps` in at least half of 3 or more windows |
| `reported_speed_mismatch` | moderate | reported horizontal speed differs from the track by more than 3 m/s + 30 % (+ accuracy slack), in at least half of 3 or more windows |
| `reported_course_mismatch` | moderate | reported direction is more than 45 degrees off the track while moving at 3 m/s or more, same ratio rule |
| `vertical_rate_implausible` | moderate | climb or descent above `max_vertical_mps`, or far from the reported vertical speed, same ratio rule |
| `timestamp_frozen` | moderate | Location timestamps stop while the aircraft moves or several fixes go by, three times |
| `location_clock_drift` | moderate | Location timestamps run at the wrong rate, or (with a UTC clock) sit more than `max_location_drift_s` from it |
| `system_clock_drift` | moderate | System or Auth timestamps are zero in an F3411-22a message, or more than `max_system_drift_s` from the UTC clock, twice |
| `tsf_wall_clock` | moderate | the Wi-Fi Beacon TSF is a Unix wall clock in microseconds (software injectors write `time.time()`; real transmitters count from boot or send 0) |
| `tsf_discontinuity` | moderate | the TSF runs backwards or at the wrong rate against the receiver clock, three times |
| `counter_interleave` | moderate | the counter restarts (jumps back by more than 8) three times |
| `signal_jump` | moderate | RSSI changes by 25 dB or more between frames 500 ms apart, three times |
| `shared_radio` | moderate | identical non-zero TSF values from different addresses within 2 s (tracker), twice |
| `invalid_fields` | moderate | Location fields out of range or reserved codes, three times |
| `serial_format` | weak | a serial number Basic ID that breaks ANSI/CTA-2063-A |
| `no_basic_id` | weak | 15 s and 5 positions without any Basic ID |
| `auth_expired` | weak | a valid DRIP signature outside its VNB / VNA window (possible replay) |

Verdict rules: any strong reason, or three different moderate ones, is
`Spoofed`; one moderate reason or two weak ones is `Suspicious`;
authenticated content with no moderate or strong reason is
`Authenticated`; everything else is `Plausible`. Reasons expire
`memory_ms` (default 300 s) after their last supporting event, except
`known_spoofer`.

A Location timestamp of exactly 0.0 s counts as "not provided": the Open
Drone ID sample transmitters and other units that never fill the field send
it, so it is not treated as a frozen clock.

## Settings (`TrustConfig`)

| Field | Default | |
|---|---|---|
| `max_speed_mps` | 100 | fastest believable ground speed |
| `max_vertical_mps` | 40 | fastest believable climb or descent |
| `default_accuracy_m` | 30 | position slack when the transmitter says "accuracy unknown" |
| `max_location_drift_s` | 30 | Location timestamp against the UTC clock |
| `max_system_drift_s` | 900 | System / Auth timestamp against the UTC clock |
| `memory_ms` | 300 000 | how long reasons stay active |
| `accept_self_certified` | false | count signatures under keys with no trusted parent as authenticated |
| `auth_fresh_ms` | 30 000 | the last validated signature must be this recent for `Authenticated` |
| `auth_skew_s` | 120 | clock skew allowed around DRIP VNB / VNA |
| `min_evaluations` | 3 | windows needed before a ratio rule can fire |
| `fingerprints` | true | match known spoofing tools |

## Spoofer fingerprints

Both were read from the tools' source (pinned commits in
`tools/spoof-corpus/regenerate.sh`):

* **cyber-defence-campus/droneRemoteIDSpoofer**: default serial
  `Spoofed_Serial_<n>`, default Self ID `Spoofing test`, Beacon SSID
  `RID-` followed by the serial, or a Beacon capability field of 0 (neither
  ESS nor IBSS) together with a zero System timestamp.
* **jjshoots/RemoteIDSpoofer**: Beacon SSID equal to its random 16
  character operator ID, or a Beacon interval field of 10 TU with Self ID
  `Recreational`.

A tool author can change any of these defaults; the generic checks are
what remains, and the corpus results below show what they catch alone.

## Measured on the corpus

Legitimate set: the three Open Drone ID sample captures in `tests/data`
(Wi-Fi Beacon, Wi-Fi NAN and Beacon, Bluetooth 5 long range). Spoofed set:
`tests/data/spoof`, built from the two tools' source with no radio (see
`spoof-corpus.md`). Results as of 0.2.0, pinned by `tests/trust_corpus.rs`:

| Capture | Transmitters | Default | Fingerprints off, UTC clock | Fingerprints off, no clock |
|---|---|---|---|---|
| ODID Wi-Fi Beacon sample | 1 | plausible | plausible | plausible |
| ODID Wi-Fi NAN + Beacon sample | 1 | plausible | plausible | plausible |
| ODID Bluetooth 5 LR sample | 1 | plausible (`serial_format`) | plausible | plausible |
| CDC Wi-Fi, 3 random drones | 3 | spoofed | spoofed (teleport, shared radio, TSF, clock) | spoofed |
| CDC Bluetooth 4, 2 random drones | 2 | spoofed | suspicious (course, clock) | suspicious |
| CDC Wi-Fi, two drones on one MAC | 1 | spoofed | spoofed (teleport, counter conflict) | spoofed |
| CDC Wi-Fi, slow waypoint drone | 1 | spoofed | suspicious (TSF, clock) | suspicious |
| jjshoots ESP8266, 1 drone | 1 | spoofed | spoofed (course, TSF, clock) | suspicious |
| jjshoots ESP8266, 4 drones | 4 | spoofed | 1 spoofed, 3 suspicious | suspicious |

So on this corpus: no false alerts on the legitimate captures, every spoofed
transmitter flagged at least suspicious without any tool knowledge, and all
of them spoofed with fingerprints. The legitimate set is small (three
captures from one project's sample units); field captures of more aircraft
models would make the false alert rate meaningful, and contributions of
such captures are welcome.

## What it cannot see

* A spoofer that copies a real aircraft's behaviour, uses its own correct
  clock, real looking identifiers and its own address is only caught by
  DRIP signatures or by comparing receivers (RIDF carries what that needs).
* Receivers that do not report the Wi-Fi TSF, the signal strength or a UTC
  clock lose the checks built on them.
