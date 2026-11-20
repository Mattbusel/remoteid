"""Replay adapter: bkerler/DroneID (wifi_receiver.py + zmq_decoder.py).

Usage: python droneid.py SRC CAPTURE

SRC is a checkout of https://github.com/bkerler/DroneID. The tool is two
processes joined by ZeroMQ: wifi_receiver.py turns frames into
{"DroneID": {mac: {"AdvData": hex}}} JSON (filter_frames, the function its
pcap and live paths call) and zmq_decoder.py decodes that JSON into Open
Drone ID messages (process_decoded_data). This adapter runs both functions
in one process, with the ZeroMQ sockets replaced by a list. Every MAC the
decoder publishes is reported with its Basic ID; neither stage has a spoof
check, so there is no verdict.
"""

import contextlib
import io
import json
import sys

sys.path.insert(0, sys.argv[1])

import scapy.layers.dot11  # noqa: E402,F401  (registers radiotap and 802.11 link types)
from scapy.utils import rdpcap  # noqa: E402

import wifi_receiver  # noqa: E402
import zmq_decoder  # noqa: E402


class Pub:
    def __init__(self):
        self.sent = []

    def send_string(self, s):
        self.sent.append(s)


wifi_receiver.socket = None
wifi_receiver.verbose = False
zmq_decoder.verbose = False
pub = Pub()
seen = {}  # mac -> ids in first-seen order

for packet in rdpcap(sys.argv[2]):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        try:
            wifi_receiver.filter_frames(packet)  # pcapng_parser swallows errors the same way
        except Exception:
            pass
    for line in out.getvalue().splitlines():
        if not line.startswith("{"):
            continue
        with contextlib.redirect_stdout(sys.stderr):
            zmq_decoder.process_decoded_data(json.loads(line), pub)

for s in pub.sent:
    for msg in json.loads(s):
        mac = msg.get("MAC")
        if mac is None:
            continue
        ids = seen.setdefault(mac, [])
        basic = msg.get("Basic ID")
        if basic and basic.get("id") and basic["id"] not in ids:
            ids.append(basic["id"])

for mac, ids in seen.items():
    if ids:
        for i in ids:
            print(json.dumps({"mac": mac, "uas_id": i}))
    else:
        print(json.dumps({"mac": mac}))
