"""Tests for the remoteid wheel, over the same captures as the Rust tests."""

import json
import os
import struct

import pytest

import remoteid

DATA = os.path.join(os.path.dirname(__file__), "..", "..", "tests", "data")


def read_pcap(name):
    with open(os.path.join(DATA, name), "rb") as f:
        b = f.read()
    assert b[:4] == b"\xd4\xc3\xb2\xa1"
    lt = struct.unpack_from("<I", b, 20)[0]
    off = 24
    while off + 16 <= len(b):
        s, us, cl, _ = struct.unpack_from("<IIII", b, off)
        off += 16
        yield lt, s * 1000 + us // 1000, b[off : off + cl]
        off += cl


def ble_ll(pkt):
    pdu = pkt[4:]
    n = pdu[1]
    body = pdu[2 : 2 + n]
    return body[:6], body[6:]


def vendor_info(pkt):
    """The Remote ID vendor element body, as scapy hands over Dot11Elt.info."""
    i = pkt.find(b"\xfa\x0b\xbc\x0d")
    return pkt[i : i + pkt[i - 1]]


def track(name, **kw):
    t = remoteid.Tracker(timeout_ms=10**12, **kw)
    for lt, ms, pkt in read_pcap(name):
        try:
            if lt == 251:
                addr, adv = ble_ll(pkt)
                t.ingest(adv, "ble_adv", address=bytes(addr), now_ms=ms, unix_ms=ms)
            else:
                t.ingest(pkt, "radiotap" if lt == 127 else "wifi_frame", now_ms=ms, unix_ms=ms)
        except ValueError:
            pass  # not Remote ID
    return t


def test_version():
    # The wheel reports the version it was built as, which follows pyproject.toml.
    with open(os.path.join(os.path.dirname(__file__), "..", "pyproject.toml")) as f:
        expected = next(line.split('"')[1] for line in f if line.startswith("version = "))
    assert remoteid.__version__ == expected


def test_decode_frame_and_vendor_element():
    _, _, pkt = next(read_pcap("odid_wifi_bcn_sample.pcap"))
    frame = remoteid.decode(pkt, "radiotap")
    assert frame["transport"] == "wifi_beacon"
    assert frame["source"] == "84:cc:a8:60:43:24"
    types = [m["type"] for m in frame["messages"]]
    assert "location" in types and "basic_id" in types
    loc = next(m for m in frame["messages"] if m["type"] == "location")
    assert loc["latitude"] == pytest.approx(45.5457468)
    assert loc["longitude"] == pytest.approx(-122.9681496)
    assert loc["speed_horizontal"] == pytest.approx(20.5)
    info = vendor_info(pkt)
    assert remoteid.decode(info, "wifi_vendor_ie")["messages"] == frame["messages"]
    assert remoteid.decode(info)["messages"] == frame["messages"]
    assert remoteid.decode(pkt)["messages"] == frame["messages"]


def test_decode_rejects_garbage():
    with pytest.raises(ValueError):
        remoteid.decode(b"\x01\x02", "wifi_vendor_ie")
    with pytest.raises(ValueError):
        remoteid.decode(b"", "payload")
    with pytest.raises(ValueError):
        remoteid.decode(b"x", "carrier_pigeon")


def test_legitimate_capture_is_plausible():
    t = track("odid_wifi_bcn_sample.pcap")
    (v,) = t.verdicts()
    assert v.verdict == "plausible", v
    assert v.reasons == []
    assert v.uas_id == "MFG1A0123456789"
    assert not v.is_alert
    assert t.get("84:cc:a8:60:43:24").uas_id == "MFG1A0123456789"
    with pytest.raises(KeyError):
        t.get("00:00:00:00:00:01")


@pytest.mark.parametrize(
    "name,n,spoofer",
    [
        ("spoof/cdc_wifi_random3.pcap", 3, "cyber-defence-campus/droneRemoteIDSpoofer"),
        ("spoof/cdc_ble_legacy_random2.pcap", 2, "cyber-defence-campus/droneRemoteIDSpoofer"),
        ("spoof/jjshoots_esp8266_beacon_4drones.pcap", 4, "jjshoots/RemoteIDSpoofer"),
    ],
)
def test_spoof_corpus(name, n, spoofer):
    vs = track(name).verdicts()
    assert len(vs) == n
    for v in vs:
        assert v.verdict == "spoofed", v
        assert v.spoofer == spoofer
        assert "known_spoofer" in v.reasons
        assert v.is_alert
        assert v.to_dict()["verdict"] == "spoofed"
    # Without fingerprints the generic checks still raise an alert.
    for v in track(name, fingerprints=False).verdicts():
        assert v.verdict in ("suspicious", "spoofed"), v
        assert "known_spoofer" not in v.reasons


def test_aircraft_json():
    name = "spoof/cdc_wifi_random3.pcap"
    t = track(name)
    last = max(ms for _, ms, _ in read_pcap(name))
    doc = json.loads(t.aircraft_json(now_ms=last))
    assert len(doc["aircraft"]) == 3
    for a in doc["aircraft"]:
        assert a["hex"].startswith("~") and a["category"] == "B6"
        assert a["rid"]["verdict"] == "spoofed"
        assert "operator" not in a["rid"]
    doc = json.loads(t.aircraft_json(now_ms=last, include_operator_position=True))
    assert "operator" in doc["aircraft"][0]["rid"]


def test_ridf_round_trip_and_ingest():
    frames = list(read_pcap("odid_wifi_bcn_sample.pcap"))
    blob = b""
    for i, (_, ms, pkt) in enumerate(frames):
        info = vendor_info(pkt)
        blob += remoteid.write_ridf(
            info[5:],
            "wifi_beacon",
            ms * 1_000_000,
            counter=info[4],
            rssi=-60,
            address="84:cc:a8:60:43:24",
            receiver=(45.5, -122.9, 60.0),
            utc=True,
            header=(i == 0),
        )
    recs = remoteid.read_ridf(blob)
    assert len(recs) == len(frames)
    assert recs[0]["address"] == "84:cc:a8:60:43:24" and recs[0]["rssi"] == -60
    assert recs[0]["receiver"][0] == pytest.approx(45.5)
    vs = remoteid.Tracker().ingest_ridf(blob)
    assert len(vs) == len(frames)
    assert vs[-1].verdict == "plausible", vs[-1]
    assert vs[-1].uas_id == "MFG1A0123456789"


def test_trusted_keys_argument():
    with pytest.raises(ValueError):
        remoteid.Tracker(trusted_keys={"not a det": b"\0" * 32})
    with pytest.raises(ValueError):
        remoteid.Tracker(trusted_keys={"2001:3f:fe00:105:a29b:3ff4:2226:c04e": b"short"})
    hi = bytes.fromhex("b5fef530d450dedb59ebafa18b00d7f5ed0ac08a81975034297bea2b00041813")
    t = remoteid.Tracker(trusted_keys={"2001:3f:fe00:105:a29b:3ff4:2226:c04e": hi})
    assert len(t) == 0


def test_rfc9575_example_is_authenticated_with_pinned_key():
    # RFC 9575 Appendix B.2.1 over Bluetooth 4 (one message per frame).
    msgs = [
        "0240012001003ffe000105a29b3ff42226c04e000000000000",
        "12000000000000000000000000000000000000000060220000",
        "32004578616d706c652053656c662049440000000000000000",
        "420000000000000000000100000000000000000010ea510900",
        "52004578616d706c65204f70657261746f7220494400000000",
    ]
    wrapper = [
        "2250078b10ea510902e0dd7c6560115e671200000000000000",
        "22510000000000000000000000000060220000420000000000",
        "2252000000000100000000000000000010ea5109002001003f",
        "2253fe000105a29b3ff42226c04ef0ecad581a030ca790152a",
        "22542f08df5762a463e24a742d1c530ec977bbe0d113697e2b",
        "2255b909d6c7557bdaf1227ce86154b030daadda4a6b8474de",
        "22569a62f6c375020826000000000000000000000000000000",
        "2257f5e8eebcb04f8c2197526053e66c010d5d7297ff7c1fe0",
    ]
    hi = bytes.fromhex("b5fef530d450dedb59ebafa18b00d7f5ed0ac08a81975034297bea2b00041813")
    # The RFC example's validity window cannot be checked against a clock
    # (see docs/drip.md), so the clock requirement is switched off here.
    t = remoteid.Tracker(
        trusted_keys={"2001:3f:fe00:105:a29b:3ff4:2226:c04e": hi},
        auth_requires_clock=False,
    )
    counters = {}
    now = 1000

    def send(hexmsg):
        nonlocal now
        raw = bytes.fromhex(hexmsg)
        c = counters[raw[0] >> 4] = (counters.get(raw[0] >> 4, 0) + 1) & 0xFF
        adv = bytes([30, 0x16, 0xFA, 0xFF, 0x0D, c]) + raw
        now += 50
        return t.ingest(adv, "ble_adv", address="c0:00:00:00:00:01", now_ms=now)

    for m in msgs:
        send(m)
    v = None
    for p in wrapper:
        v = send(p)
    assert v.auth == "trusted", v
    assert v.verdict == "authenticated", v
    # The identity shown is the signing DET.
    assert v.uas_id == "2001:3f:fe00:105:a29b:3ff4:2226:c04e", v


def _ble_adv(lat_e7):
    loc = bytes([0x12, 0x20, 0, 0, 0]) + lat_e7.to_bytes(4, "little", signed=True)
    loc += (85000000).to_bytes(4, "little", signed=True) + bytes(12)
    return bytes([30, 0x16, 0xFA, 0xFF, 0x0D, 1]) + loc


def test_ingest_without_address_is_refused():
    # Two aircraft 65 km apart must not be merged into one track.
    t = remoteid.Tracker()
    with pytest.raises(ValueError, match="address"):
        t.ingest(_ble_adv(465000000), "ble_adv", now_ms=0)
    a = t.ingest(_ble_adv(465000000), "ble_adv", address="c0:00:00:00:00:01", now_ms=0)
    b = t.ingest(_ble_adv(471000000), "ble_adv", address="c0:00:00:00:00:02", now_ms=0)
    assert len(t) == 2
    assert a.verdict == b.verdict == "plausible"


def test_tracker_expires_and_is_bounded():
    t = remoteid.Tracker(timeout_ms=1000, max_transmitters=3)
    for i in range(10):
        t.ingest(_ble_adv(465000000), "ble_adv", address=bytes([0xC0, 0, 0, 0, 0, i]), now_ms=i)
    assert len(t) == 3
    t.ingest(_ble_adv(465000000), "ble_adv", address="c0:00:00:00:00:63", now_ms=10_000)
    assert len(t) == 1


def test_system_clock_is_off_by_default():
    t = remoteid.Tracker()
    v = t.ingest(_ble_adv(465000000), "ble_adv", address="c0:00:00:00:00:01")
    assert "system_clock_drift" not in v.reasons
