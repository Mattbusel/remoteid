"""Replay adapter: smittix/intercept (drone mode, Remote ID over Wi-Fi).

Usage: python intercept.py SRC CAPTURE

SRC is a checkout of https://github.com/smittix/intercept. Every packet goes
through RemoteIDScanner._on_wifi_packet (utils/drone/remote_id.py), the
callback its scapy AsyncSniffer calls, and every RemoteIDObservation it
queues is reported. intercept's correlator marks every Remote ID contact
compliant=True with risk "low" (utils/drone/correlator.py), so that is the
verdict, which the scorer reads as accepted. Observations carry no radio
address; the serial number is the only key.
"""

import json
import queue
import sys

sys.path.insert(0, sys.argv[1])

import scapy.layers.dot11  # noqa: E402,F401  (registers radiotap and 802.11 link types)
from scapy.utils import rdpcap  # noqa: E402

from utils.drone.remote_id import RemoteIDScanner  # noqa: E402

q = queue.Queue()
scanner = RemoteIDScanner(output_queue=q)
for packet in rdpcap(sys.argv[2]):
    scanner._on_wifi_packet(packet)

while not q.empty():
    obs = q.get()
    print(json.dumps({
        "serial_number": obs.serial_number,
        "lat": obs.lat,
        "lon": obs.lon,
        "verdict": "compliant, risk low",
    }))
