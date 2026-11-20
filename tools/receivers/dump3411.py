"""Replay adapter: ifnull/dump3411 (Wi-Fi feeder + tracker).

Usage: python dump3411.py SRC CAPTURE

SRC is a checkout of https://github.com/ifnull/dump3411. Every packet's raw
bytes go to WiFiFeeder._on_packet (wifi_feeder.py), the callback its
monitor-mode socket loop calls, with a Tracker attached the way
dump3411.py wires them. The drones in Tracker.snapshot() (the document
behind its /data/remoteid.json feed and dashboard) are reported. The
feeder reads radiotap; bare 802.11 captures (link type 105) get an empty
8 byte radiotap header, which is what the kernel adds on a monitor
interface. dump3411 has no spoof check, so there is no verdict.
"""

import contextlib
import json
import logging
import struct
import sys

sys.path.insert(0, sys.argv[1])
logging.disable(logging.CRITICAL)

from tracker import Tracker  # noqa: E402
from wifi_feeder import WiFiFeeder  # noqa: E402


def packets(path):
    b = open(path, "rb").read()
    assert b[:4] == b"\xd4\xc3\xb2\xa1", "little endian pcap"
    linktype = struct.unpack_from("<I", b, 20)[0]
    off = 24
    while off + 16 <= len(b):
        caplen = struct.unpack_from("<I", b, off + 8)[0]
        data = b[off + 16:off + 16 + caplen]
        off += 16 + caplen
        if linktype == 105:
            data = b"\x00\x00\x08\x00\x00\x00\x00\x00" + data
        yield data


tracker = Tracker(ttl_seconds=1e9)
feeder = WiFiFeeder("replay0", channel=6, tracker=tracker)
with contextlib.redirect_stdout(sys.stderr):
    for data in packets(sys.argv[2]):
        feeder._on_packet(data)

snap = tracker.snapshot()
for d in snap.get("drones", snap.get("aircraft", [])):
    print(json.dumps({"uas_id": d.get("id"), "operator_id": d.get("operator_id")}))
