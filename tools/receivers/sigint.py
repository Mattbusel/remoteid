"""Replay adapter: arall/sigint (WiFi Remote ID parser).

Usage: python sigint.py SRC CAPTURE

SRC is a checkout of https://github.com/arall/sigint. Every packet goes
through WiFiRemoteIDParser.handle_frame (src/parsers/wifi/remote_id.py),
the function the WiFi capture loop calls, with a fresh DroneRegistry and a
logger that records the SignalDetection objects it emits. Every drone the
parser announces (the "[DRONE-WiFi]" line and the registry entry) is
reported with its MAC and drone_id; the parser has no spoof check, so
there is no verdict. The parser's own console output goes to stderr.
"""

import contextlib
import json
import os
import sys

sys.path.insert(0, os.path.join(sys.argv[1], "src"))

import scapy.layers.dot11  # noqa: E402,F401  (registers radiotap and 802.11 link types)
from scapy.utils import rdpcap  # noqa: E402

from parsers.ble.remote_id import DroneRegistry  # noqa: E402
from parsers.wifi.remote_id import WiFiRemoteIDParser  # noqa: E402


class Logger:
    def __init__(self):
        self.detections = []

    def log(self, detection):
        self.detections.append(detection)


seen = {}  # (mac, drone_id) in first-seen order
parser = WiFiRemoteIDParser(Logger(), drone_registry=DroneRegistry())
merge = parser._merge_messages


def recording_merge(messages, mac, rssi, channel):
    info = merge(messages, mac, rssi, channel)
    seen.setdefault((mac, info.get("drone_id", mac or "unknown")), None)
    return info


parser._merge_messages = recording_merge
with contextlib.redirect_stdout(sys.stderr):
    for packet in rdpcap(sys.argv[2]):
        parser.handle_frame((packet, 6))

for mac, drone_id in seen:
    print(json.dumps({"mac": mac, "drone_id": drone_id}))
