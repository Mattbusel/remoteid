"""Drone Remote ID decoding and trust verdicts.

Python bindings for the Rust crate `remoteid`:

* ``decode(data, transport="auto")``: one Remote ID frame to message dicts
  (ASTM F3411-22a / ASD-STAN EN 4709-002, Bluetooth 4/5, Wi-Fi Beacon/NAN).
* ``Tracker()``: keeps every transmitter and grades it ``authenticated``,
  ``plausible``, ``suspicious`` or ``spoofed``, with the reasons (kinematic
  plausibility, timestamp and counter continuity, Wi-Fi TSF behaviour,
  agreement across transports, known spoofer fingerprints, DRIP RFC 9575
  Ed25519 signatures).
* ``Tracker.aircraft_json()``: readsb ``aircraft.json`` for tar1090.
* ``read_ridf`` / ``write_ridf``: RIDF v0 receiver records.
"""

from ._remoteid import Tracker, Verdict, __version__, decode, read_ridf, write_ridf

TRANSPORTS = (
    "auto",
    "payload",
    "wifi_frame",
    "radiotap",
    "wifi_vendor_ie",
    "wifi_ies",
    "nan",
    "ble_adv",
    "ble_service_data",
)

__all__ = ["Tracker", "Verdict", "decode", "read_ridf", "write_ridf", "TRANSPORTS", "__version__"]
