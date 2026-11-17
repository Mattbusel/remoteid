//! Reads a pcap or pcapng capture (Wi-Fi with radiotap, or Nordic BLE
//! sniffer) and prints every aircraft found.
//!
//! ```text
//! cargo run --example pcap_tracker -- tests/data/odid_wifi_bcn_sample.pcap
//! ```

#[path = "../tests/common/mod.rs"]
mod common;

use remoteid::{ble, wifi, Tracker, TrackerConfig};

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: pcap_tracker <capture.pcap|.pcapng>");
    let packets = if path.ends_with(".pcapng") {
        common::read_pcapng(&path)
    } else {
        common::read_pcap(&path)
    };

    let mut tracker = Tracker::new(TrackerConfig {
        timeout: u64::MAX,
        ..TrackerConfig::default()
    });
    for (i, (linktype, pkt)) in packets.iter().enumerate() {
        match linktype {
            127 => {
                let Ok(frame) = wifi::strip_radiotap(pkt) else {
                    continue;
                };
                if let Ok(rid) = wifi::parse_frame(frame) {
                    tracker.ingest_wifi(&rid, i as u64);
                }
            }
            105 => {
                if let Ok(rid) = wifi::parse_frame(pkt) {
                    tracker.ingest_wifi(&rid, i as u64);
                }
            }
            272 => {
                let Some((addr, adv, crc_ok)) = common::nordic_ble_adv(pkt) else {
                    continue;
                };
                if !crc_ok {
                    continue;
                }
                if let Some(rid) = ble::find_in_advertising_data(&adv) {
                    tracker.ingest_ble(addr, &rid, i as u64);
                }
            }
            _ => {}
        }
    }

    for (tx, uas) in tracker.iter() {
        println!("{tx:?}");
        println!("  id:        {:?}", uas.data.primary_id());
        if let Some(op) = &uas.data.operator_id {
            println!("  operator:  {:?}", op.operator_id_str());
        }
        if let Some(s) = &uas.data.self_id {
            println!("  self id:   {:?}", s.description_str());
        }
        if let Some(l) = &uas.data.location {
            println!("  status:    {:?}", l.status);
            println!("  position:  {:?}", l.position());
            println!(
                "  alt geo:   {:?} m, height {:?} m",
                l.altitude_geo, l.height
            );
            println!(
                "  speed:     {:?} m/s, track {:?} deg",
                l.speed_horizontal, l.direction
            );
        }
        if let Some(s) = &uas.data.system {
            println!("  operator position: {:?}", s.operator_position());
        }
        println!(
            "  frames:    {} received, {} est. missed, {} duplicates, {} undecodable",
            uas.stats.received, uas.stats.missed, uas.stats.duplicates, uas.decode_errors
        );
    }
}
