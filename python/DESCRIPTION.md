# remoteid

Drone Remote ID for Python, backed by the Rust crate
[`remoteid`](https://crates.io/crates/remoteid). It decodes ASTM F3411-22a /
ASD-STAN EN 4709-002 broadcasts (Bluetooth 4 and 5, Wi-Fi Beacon and NAN),
and it judges them: every transmitter gets a verdict of `authenticated`,
`plausible`, `suspicious` or `spoofed`, with the reasons.

```python
import remoteid

# One frame: a whole 802.11 frame, radiotap, a scapy Dot11Elt.info,
# Bluetooth advertising data, or a raw message pack.
frame = remoteid.decode(elt.info, "wifi_vendor_ie")
for m in frame["messages"]:
    if m["type"] == "location":
        print(m["latitude"], m["longitude"], m["altitude_geo"])

# Many frames: a verdict per transmitter.
tracker = remoteid.Tracker()
v = tracker.ingest(adv_data, "ble_adv", address="c4:5e:12:34:56:78", rssi=-71)
if v.is_alert:
    print(v.verdict, v.reasons, v.spoofer)   # e.g. spoofed ['teleport', 'tsf_wall_clock'] None

# tar1090 / readsb aircraft.json (operator position left out by default)
open("aircraft.json", "w").write(tracker.aircraft_json())
```

What the verdict looks at: kinematic plausibility (jumps, impossible
speed, reported speed / course / climb against the track flown), timestamp
and counter continuity, Wi-Fi TSF behaviour, agreement between transports
and transmitters claiming one identity, fingerprints of two public spoofing
tools, and DRIP (RFC 9575) Ed25519 signatures. Pass registry or pinned keys
as `Tracker(trusted_keys={det: public_key})`.

Wheels are abi3 (CPython 3.10 and later) for Linux, macOS and Windows.
Full documentation: <https://github.com/Mattbusel/remoteid/blob/main/docs/python.md>.
