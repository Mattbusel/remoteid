"""Replay adapter: cyber-defence-campus/RemoteIDReceiver.

Usage: python remoteidreceiver.py SRC CAPTURE

SRC is a checkout of https://github.com/cyber-defence-campus/RemoteIDReceiver.
Every packet of CAPTURE goes through the receiver's own Wi-Fi path, as in
Receiver/backend/dronesniffer/packet_processor.py process_packet: the vendor
element filter, parser.from_wifi and mapper.to_db_models. The database is
replaced by an in-memory "latest message per sender" table, which is what
DroneServiceAds.get_drone_state reads, and the receiver's own spoofing
check (spoofing_detection.is_spoofed) runs on the result. A sender appears
on the map once it has sent a Location message (get_all_drone_senders), so
only those are reported. Prints one JSON line per sender.
"""

import json
import logging
import os
import sys

src = os.path.join(sys.argv[1], "Receiver", "backend", "dronesniffer")
sys.path.insert(0, src)
logging.disable(logging.CRITICAL)

from scapy.layers.dot11 import Dot11EltVendorSpecific  # noqa: E402
from scapy.utils import rdpcap  # noqa: E402

from map.mapping_service import mapper  # noqa: E402
from models import Position  # noqa: E402
from models.direct_remote_id import BasicIdMessage, LocationMessage, SystemMessage  # noqa: E402
from parse.parser import Parser  # noqa: E402
from parse.parser_service import parser  # noqa: E402
from spoofing_detection import is_spoofed  # noqa: E402

latest = {}  # sender -> {type: model}

for packet in rdpcap(sys.argv[2]):
    # packet_processor.process_packet, without the database and websocket
    vendor_spec = packet.getlayer(Dot11EltVendorSpecific) if packet.haslayer(Dot11EltVendorSpecific) else None
    while vendor_spec:
        layer_oui = Parser.dec2hex(vendor_spec.oui)
        if parser.is_supported_protocol(layer_oui):
            parsed = parser.from_wifi(vendor_spec.info, layer_oui)
            if parsed:
                for m in mapper.to_db_models(parsed, packet.addr2) or []:
                    latest.setdefault(m.sender_id, {})[type(m)] = m
            break
        vendor_spec = vendor_spec.payload.getlayer(Dot11EltVendorSpecific)

for sender, msgs in latest.items():
    location = msgs.get(LocationMessage)
    if location is None:
        continue  # not on the map
    basic = msgs.get(BasicIdMessage)
    system = msgs.get(SystemMessage)
    drone = Position(lat=location.latitude, lng=location.longitude)
    pilot = Position(lat=system.pilot_latitude, lng=system.pilot_longitude) if system else None
    # DroneServiceAds.get_drone_state
    spoofed = is_spoofed(drone, pilot) if drone and pilot else None
    out = {"mac": sender, "uas_id": basic.uas_id if basic else None}
    if spoofed is not None:
        out["spoofed"] = bool(spoofed)
    print(json.dumps(out))
