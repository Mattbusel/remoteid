//! End to end over the public Open Drone ID sample captures
//! (github.com/opendroneid/wireshark-dissector, Apache-2.0):
//! raw radio frames in, aircraft out.

mod common;

use remoteid::{ble, wifi, Frame, Message, Tracker, Transmitter, UasData};

#[test]
fn wifi_beacon_capture() {
    let pkts = common::read_pcap("odid_wifi_bcn_sample.pcap");
    assert_eq!(pkts.len(), 21);
    let mut tracker = Tracker::default();
    let mut found = 0;
    for (i, (lt, pkt)) in pkts.iter().enumerate() {
        assert_eq!(*lt, 127, "radiotap");
        let frame = wifi::strip_radiotap(pkt).unwrap();
        let Ok(rid) = wifi::parse_frame(frame) else {
            continue;
        };
        assert_eq!(rid.kind, wifi::WifiKind::Beacon);
        assert_eq!(rid.source, [0x84, 0xcc, 0xa8, 0x60, 0x43, 0x24]);
        found += 1;
        tracker.ingest_wifi(&rid, i as u64 * 100);
    }
    assert_eq!(found, 21);
    assert_eq!(tracker.len(), 1);
    let (_, uas) = tracker.iter().next().unwrap();
    assert_eq!(uas.decode_errors, 0);
    check_sample_aircraft(&uas.data, true);
}

#[test]
fn wifi_nan_and_beacon_capture() {
    let pkts = common::read_pcap("odid_wifi_sample.pcap");
    let (mut beacon, mut nan, mut other) = (0, 0, 0);
    let mut uas = UasData::default();
    for (_, pkt) in &pkts {
        let frame = wifi::strip_radiotap(pkt).unwrap();
        match wifi::parse_frame(frame) {
            Ok(rid) => {
                match rid.kind {
                    wifi::WifiKind::Beacon => beacon += 1,
                    wifi::WifiKind::Nan => nan += 1,
                }
                uas.update_frame(&rid.frame().unwrap());
            }
            Err(_) => other += 1, // NAN sync beacons and other traffic
        }
    }
    assert_eq!(nan, 21);
    assert_eq!(beacon, 21);
    assert_eq!(beacon + nan + other, pkts.len());
    // This capture never sends a Basic ID: one message per frame, rotating.
    check_sample_aircraft(&uas, false);
}

#[test]
fn bluetooth5_long_range_capture() {
    let pkts = common::read_pcapng("odid_bt5_lr_sample.pcapng");
    assert_eq!(pkts.len(), 274);
    let mut tracker = Tracker::default();
    let (mut rid_frames, mut bad_crc, mut rejected) = (0, 0, 0);
    for (i, (lt, pkt)) in pkts.iter().enumerate() {
        assert_eq!(*lt, 272, "LINKTYPE_NORDIC_BLE");
        let Some((addr, adv, crc_ok)) = common::nordic_ble_adv(pkt) else {
            continue;
        };
        let Some(rid) = ble::find_in_advertising_data(&adv) else {
            continue;
        };
        rid_frames += 1;
        if !crc_ok {
            bad_crc += 1;
            continue;
        }
        if rid.frame().is_err() {
            rejected += 1;
        }
        tracker.ingest_ble(addr, &rid, i as u64);
    }
    // 274 packets: 272 carry readable Remote ID service data; the other two
    // failed CRC so badly that the AD structures are garbage.
    assert_eq!(rid_frames, 272);
    // A real long range capture: the radio drops and corrupts packets, and
    // the decoder has to refuse the broken ones rather than invent aircraft.
    println!(
        "BT5: {rid_frames} Remote ID frames, {bad_crc} with bad CRC, {rejected} rejected packs"
    );
    assert_eq!((bad_crc, rejected), (28, 19));
    let tracked: Vec<_> = tracker
        .iter()
        .filter(|(_, u)| u.data.primary_id().is_some())
        .collect();
    assert_eq!(tracked.len(), 1);
    let (tx, uas) = tracked[0];
    assert_eq!(*tx, Transmitter::Ble([0x1c, 0x2f, 0xeb, 0xea, 0x7d, 0xe0]));
    assert_eq!(uas.data.primary_id(), Some("SSEVTFG93700070"));
    // The counter gaps account exactly for the 28 frames dropped for bad CRC.
    assert_eq!(uas.stats.missed, 28);
    assert_eq!(uas.stats.duplicates, 0);
    // An F3411-19 (protocol version 0) unit recorded indoors: airborne
    // status set, but no GNSS fix, so the position is "unknown" (0, 0).
    let loc = uas.data.location.as_ref().unwrap();
    assert_eq!(loc.protocol_version, 0);
    assert_eq!(loc.status, remoteid::Status::Airborne);
    assert_eq!(loc.position(), None);
}

/// The sample transmitter (an Open Drone ID test rig) announces these.
fn check_sample_aircraft(uas: &UasData, has_basic_id: bool) {
    if has_basic_id {
        assert_eq!(uas.primary_id(), Some("MFG1A0123456789"));
    } else {
        assert_eq!(uas.primary_id(), None);
    }
    let serial = uas
        .basic_id
        .iter()
        .flatten()
        .find_map(|b| b.serial_number());
    if let Some(s) = serial {
        assert_eq!(s.manufacturer_code, "MFG1");
        assert_eq!(s.serial, "0123456789");
    }
    let op = uas.operator_id.as_ref().expect("operator id");
    assert_eq!(op.operator_id_str(), Some("GBR-OP-123ABCD"));
    assert_eq!(
        uas.self_id.as_ref().unwrap().description_str(),
        Some("Recreational")
    );
    let loc = uas.location.as_ref().expect("location");
    assert!(loc.is_plausible(), "{:?}", loc.check().collect::<Vec<_>>());
    let (lat, lon) = loc.position().unwrap();
    // Near Hillsboro, Oregon (where the samples were recorded).
    assert!(
        (45.5..45.6).contains(&lat) && (-123.0..-122.9).contains(&lon),
        "{lat} {lon}"
    );
    assert!(uas.system.is_some());
}

#[test]
fn all_frames_reencode_byte_for_byte() {
    // Every valid message decoded from the Wi-Fi captures re-encodes to the
    // exact bytes that were on the air.
    let mut n = 0;
    for name in ["odid_wifi_bcn_sample.pcap", "odid_wifi_sample.pcap"] {
        for (_, pkt) in common::read_pcap(name) {
            let frame = wifi::strip_radiotap(&pkt).unwrap();
            let Ok(rid) = wifi::parse_frame(frame) else {
                continue;
            };
            let Frame::Pack(pack) = rid.frame().unwrap() else {
                panic!("wifi carries packs")
            };
            for raw in pack.raw_messages() {
                let msg = Message::decode(raw).unwrap();
                let back = msg.encode().unwrap();
                // Reserved bytes may hold transmitter garbage; compare the defined ones.
                assert_eq!(mask_reserved(raw), mask_reserved(&back), "{msg:?}");
                n += 1;
            }
        }
    }
    assert!(n > 100, "{n}");
}

fn mask_reserved(m: &[u8; 25]) -> [u8; 25] {
    let mut m = *m;
    match m[0] >> 4 {
        0 | 5 => m[22..25].fill(0),
        1 => {
            m[1] &= !0x08;
            m[23] &= 0x0F;
            m[24] = 0;
        }
        4 => {
            m[1] &= 0x1F;
            m[24] = 0;
        }
        _ => {}
    }
    m
}
