# Python

```text
pip install remoteid --find-links https://github.com/Mattbusel/remoteid/releases/expanded_assets/v0.2.2
```

The wheels are attached to each GitHub release. The PyPI project is not
published yet; once it is, `pip install remoteid` is enough.

abi3 wheels for CPython 3.10 and later on Linux (x86_64, aarch64), macOS
(x86_64, arm64) and Windows (x86_64). The source is `python/` in this
repository.

## decode

```python
remoteid.decode(data: bytes, transport: str = "auto") -> dict
```

`transport` names what `data` is:

| Value | `data` |
|---|---|
| `payload` | a Remote ID message (25 bytes) or message pack, header byte first |
| `wifi_frame` | an 802.11 management frame; a radiotap header in front is stripped |
| `radiotap` | radiotap header plus 802.11 frame |
| `wifi_vendor_ie` | the body of the vendor element, as scapy's `Dot11Elt.info` gives it: OUI `FA:0B:BC`, type `0x0D`, counter, pack |
| `wifi_ies` | an 802.11 element list |
| `nan` | the body of a NAN service discovery action frame |
| `ble_adv` | Bluetooth advertising data (AD structures) |
| `ble_service_data` | service data for UUID 0xFFFA (application code first; a leading `FA FF` is accepted) |
| `auto` | try the above |

Returns `{"transport", "counter", "source", "is_pack", "messages"}`.
Each message is a dict with a `type` of `basic_id`, `location`, `auth`,
`self_id`, `system` or `operator_id`. Location fields are SI units
(`latitude`, `longitude`, `altitude_geo`, `altitude_baro`, `height` in
meters, `speed_horizontal` and `speed_vertical` in m/s, `direction` in
degrees, `timestamp` in seconds after the hour); unknown values are `None`.
Anything that is not Remote ID raises `ValueError`.

With scapy:

```python
from scapy.all import Dot11Elt
import remoteid

def on_packet(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while elt is not None:
        if elt.ID == 221 and elt.info[:4] == b"\xfa\x0b\xbc\x0d":
            frame = remoteid.decode(bytes(elt.info), "wifi_vendor_ie")
            ...
        elt = elt.payload.getlayer(Dot11Elt)
```

## Tracker and verdicts

```python
tracker = remoteid.Tracker(
    max_speed_mps=100.0,
    fingerprints=True,
    accept_self_certified=False,
    trusted_keys=None,          # {DET text or 16 bytes: Ed25519 public key (32 bytes)}
    timeout_ms=10_000,
    use_system_clock=False,
    auth_requires_clock=True,
    max_transmitters=4096,
)
v = tracker.ingest(data, transport="auto", address=None, now_ms=None, unix_ms=None, rssi=None)
```

`ingest` returns a `Verdict` with `verdict` (`authenticated`, `plausible`,
`suspicious`, `spoofed`), `score`, `reasons`, `spoofer`, `auth`,
`address`, `transport`, `uas_id`, `latitude`, `longitude`, `altitude_m`,
`frames`, `is_alert` and `to_dict()`. The reasons are explained in
`trust.md`.

Times: by default a frame is stamped with a monotonic clock only.
`use_system_clock=True` adds the machine's UTC clock, which enables the
absolute timestamp checks and the DRIP validity window. Turn it on only if
the clock is NTP or GNSS synced: on an unsynced clock (a Raspberry Pi with
no RTC and no network) every aircraft would show `system_clock_drift` and
`location_clock_drift`. When replaying a capture, pass `now_ms` (and
`unix_ms` if the capture clock was right) from the packet timestamps.

`auth_requires_clock` (default True): a DRIP signature only makes a
transmitter `authenticated` when it was checked against its validity window
with a UTC clock (from `unix_ms` or `use_system_clock`); without one a
recorded signature could be replayed. `uas_id` is the signing DET once an
aircraft is verified.

`address` is required for every input that does not carry its own
(`ble_adv`, `ble_service_data`, `wifi_vendor_ie`, `wifi_ies`, `nan`,
`payload`, and `auto` when it finds one of those): `ingest` raises
ValueError without it, because frames from different aircraft would
otherwise be merged into one track and judged as one, with false teleport
and counter alerts. Whole Wi-Fi frames carry their own source address.
`ingest_ridf` needs an address in every record for the same reason.

Memory: transmitters not heard for `timeout_ms` are dropped as frames come
in, and at most `max_transmitters` are kept (the least recently heard goes
first), so a flood of frames from random addresses stays bounded.

Other methods: `verdicts()`, `get(address)`, `aircraft_json(...)` (see
`aircraft-json.md`), `ingest_ridf(bytes)`, `expire(now_ms=None)`, `len()`.

## RIDF

`remoteid.write_ridf(payload, transport, rx_time_ns, counter=None, rssi=None,
address=None, receiver_id=0, receiver=None, utc=False, header=False)`
returns one record (with the file header if `header`), and
`remoteid.read_ridf(data)` returns a list of dicts. See `ridf.md`.
