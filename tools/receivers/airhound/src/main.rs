//! Replay adapter: dougborg/AirHound.
//!
//! Every 802.11 frame of a pcap goes through `scanner::try_parse_odid_wifi`
//! (the radio callback's Remote ID path) and then
//! `odid::parse_odid_service_info` (what the filter task in src/main.rs
//! does with each OdidEvent before it reports a drone to the companion
//! app). Every MAC that yields a decoded frame is printed with its Basic
//! ID. AirHound has no spoof check, so there is no verdict.

use std::collections::BTreeMap;

fn main() {
    let path = std::env::args().nth(1).expect("usage: airhound-replay CAPTURE");
    let b = std::fs::read(&path).unwrap();
    assert_eq!(&b[..4], &[0xd4, 0xc3, 0xb2, 0xa1], "little endian pcap");
    let lt = u32::from_le_bytes(b[20..24].try_into().unwrap());
    let mut seen: BTreeMap<[u8; 6], Vec<String>> = BTreeMap::new();
    let mut order: Vec<[u8; 6]> = Vec::new();
    let mut off = 24;
    while off + 16 <= b.len() {
        let cl = u32::from_le_bytes(b[off + 8..off + 12].try_into().unwrap()) as usize;
        let mut pkt = &b[off + 16..off + 16 + cl];
        off += 16 + cl;
        if lt == 127 {
            let h = u16::from_le_bytes([pkt[2], pkt[3]]) as usize;
            pkt = &pkt[h..];
        } else if lt != 105 {
            continue;
        }
        let Some(ev) = airhound::scanner::try_parse_odid_wifi(pkt, -50, 6) else {
            continue;
        };
        let Some(frame) = airhound::odid::parse_odid_service_info(&ev.raw_data) else {
            continue;
        };
        if !frame.has_data() {
            continue;
        }
        let ids = seen.entry(ev.mac).or_insert_with(|| {
            order.push(ev.mac);
            Vec::new()
        });
        if let Some(bid) = frame.basic_id {
            let id = bid.uas_id.as_str().to_string();
            if !id.is_empty() && !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    for mac in order {
        let m = mac.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":");
        let ids = &seen[&mac];
        if ids.is_empty() {
            println!("{{\"mac\":\"{m}\"}}");
        }
        for id in ids {
            println!("{{\"mac\":\"{m}\",\"uas_id\":\"{id}\"}}");
        }
    }
}
