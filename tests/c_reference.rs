//! Differential test against opendroneid-core-c.
//!
//! `tests/data/c_reference_messages.jsonl` holds the output of the reference
//! C library (opendroneid-core-c 849c03a, `decodeOpenDroneID`) for every
//! distinct 25 byte message found in the three public Open Drone ID sample
//! captures, including messages corrupted in the air. The harness that made
//! it is in `docs/testing.md`. Every field must match.
//!
//! `c_reference_packs.jsonl` holds the C result of `odid_message_process_pack`
//! for every pack in the captures: accepted or rejected, and how many
//! messages of each type it stored.

mod common;

use remoteid::{Frame, Message, MessagePack, UasData};
use serde_json::Value;

fn close(a: f64, b: &Value, tol: f64, what: &str, hex: &str) {
    let b = b.as_f64().unwrap();
    assert!((a - b).abs() <= tol, "{what}: rust {a} vs C {b} for {hex}");
}

fn int(v: &Value) -> u64 {
    v.as_u64().unwrap()
}

/// C prints padded strings up to the first NUL with non-printables escaped.
fn c_str(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    bytes[..end]
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                (b as char).to_string()
            } else {
                format!("\\u{:04x}", b)
            }
        })
        .collect()
}

fn json_str(v: &Value) -> String {
    // serde_json already unescaped \uXXXX; re-escape non-printables the same way.
    v.as_str()
        .unwrap()
        .chars()
        .map(|c| {
            if (' '..='~').contains(&c) {
                c.to_string()
            } else {
                format!("\\u{:04x}", c as u32)
            }
        })
        .collect()
}

#[test]
fn every_sample_message_matches_the_c_library() {
    let text = std::fs::read_to_string(common::data("c_reference_messages.jsonl")).unwrap();
    let mut checked = 0;
    for line in text.lines().filter(|l| !l.is_empty()) {
        let g: Value = serde_json::from_str(line).unwrap();
        let hex = g["hex"].as_str().unwrap();
        let raw = common::unhex(hex);
        let t = g["type"].as_i64().unwrap();
        let ours = Message::decode(&raw);
        if t == 255 || t < 0 {
            assert!(ours.is_err(), "C rejected {hex}, we decoded {ours:?}");
            checked += 1;
            continue;
        }
        let m = ours.unwrap_or_else(|e| panic!("C decoded {hex} as type {t}, we failed: {e}"));
        assert_eq!(u8::from(m.message_type()) as i64, t, "{hex}");
        match m {
            Message::BasicId(b) => {
                assert_eq!(u8::from(b.id_type) as u64, int(&g["id_type"]));
                assert_eq!(u8::from(b.ua_type) as u64, int(&g["ua_type"]));
                assert_eq!(c_str(&b.uas_id), json_str(&g["uas_id"]), "{hex}");
            }
            Message::Location(l) => {
                assert_eq!(u8::from(l.status) as u64, int(&g["status"]));
                close(
                    l.direction.unwrap_or(361.0) as f64,
                    &g["direction"],
                    0.006,
                    "direction",
                    hex,
                );
                close(
                    l.speed_horizontal.unwrap_or(255.0) as f64,
                    &g["speed_h"],
                    0.006,
                    "speed_h",
                    hex,
                );
                close(
                    l.speed_vertical.unwrap_or(63.0) as f64,
                    &g["speed_v"],
                    0.006,
                    "speed_v",
                    hex,
                );
                close(l.latitude, &g["lat"], 1e-7, "lat", hex);
                close(l.longitude, &g["lon"], 1e-7, "lon", hex);
                close(
                    l.altitude_baro.unwrap_or(-1000.0) as f64,
                    &g["alt_baro"],
                    0.06,
                    "alt_baro",
                    hex,
                );
                close(
                    l.altitude_geo.unwrap_or(-1000.0) as f64,
                    &g["alt_geo"],
                    0.06,
                    "alt_geo",
                    hex,
                );
                close(
                    l.height.unwrap_or(-1000.0) as f64,
                    &g["height"],
                    0.06,
                    "height",
                    hex,
                );
                assert_eq!(u8::from(l.height_type) as u64, int(&g["height_type"]));
                assert_eq!(l.horizontal_accuracy.0 as u64, int(&g["h_acc"]));
                assert_eq!(l.vertical_accuracy.0 as u64, int(&g["v_acc"]));
                assert_eq!(l.baro_accuracy.0 as u64, int(&g["baro_acc"]));
                assert_eq!(l.speed_accuracy.0 as u64, int(&g["speed_acc"]));
                assert_eq!(l.timestamp_accuracy.0 as u64, int(&g["ts_acc"]));
                close(
                    l.timestamp.unwrap_or(65535.0) as f64,
                    &g["timestamp"],
                    0.06,
                    "timestamp",
                    hex,
                );
            }
            Message::Auth(a) => {
                assert_eq!(a.page as u64, int(&g["page"]));
                assert_eq!(u8::from(a.auth_type) as u64, int(&g["auth_type"]));
                if a.page == 0 {
                    assert_eq!(a.last_page_index as u64, int(&g["last_page"]));
                    assert_eq!(a.length as u64, int(&g["length"]));
                    assert_eq!(a.timestamp as u64, int(&g["auth_ts"]));
                }
            }
            Message::SelfId(s) => {
                assert_eq!(u8::from(s.description_type) as u64, int(&g["desc_type"]));
                assert_eq!(c_str(&s.description), json_str(&g["desc"]), "{hex}");
            }
            Message::System(s) => {
                assert_eq!(
                    u8::from(s.operator_location_type) as u64,
                    int(&g["op_loc_type"])
                );
                assert_eq!(
                    u8::from(s.classification_type) as u64,
                    int(&g["class_type"])
                );
                close(s.operator_latitude, &g["op_lat"], 1e-7, "op_lat", hex);
                close(s.operator_longitude, &g["op_lon"], 1e-7, "op_lon", hex);
                assert_eq!(s.area_count as u64, int(&g["area_count"]));
                assert_eq!(s.area_radius as u64, int(&g["area_radius"]));
                close(
                    s.area_ceiling.unwrap_or(-1000.0) as f64,
                    &g["area_ceiling"],
                    0.06,
                    "ceiling",
                    hex,
                );
                close(
                    s.area_floor.unwrap_or(-1000.0) as f64,
                    &g["area_floor"],
                    0.06,
                    "floor",
                    hex,
                );
                assert_eq!(u8::from(s.category_eu) as u64, int(&g["cat_eu"]));
                assert_eq!(u8::from(s.class_eu) as u64, int(&g["class_eu"]));
                close(
                    s.operator_altitude_geo.unwrap_or(-1000.0) as f64,
                    &g["op_alt_geo"],
                    0.06,
                    "op_alt",
                    hex,
                );
                assert_eq!(s.timestamp as u64, int(&g["sys_ts"]));
            }
            Message::OperatorId(o) => {
                assert_eq!(o.operator_id_type as u64, int(&g["op_id_type"]));
                assert_eq!(c_str(&o.operator_id), json_str(&g["op_id"]), "{hex}");
            }
        }
        checked += 1;
    }
    assert_eq!(checked, 82);
}

#[test]
fn every_sample_pack_is_accepted_or_rejected_like_the_c_library() {
    let text = std::fs::read_to_string(common::data("c_reference_packs.jsonl")).unwrap();
    let (mut accepted, mut rejected) = (0, 0);
    for line in text.lines().filter(|l| !l.is_empty()) {
        let g: Value = serde_json::from_str(line).unwrap();
        let hex = g["hex"].as_str().unwrap();
        let raw = common::unhex(hex);
        let c_ok = g["result"].as_i64().unwrap() >= 0;
        let ours = MessagePack::parse(&raw);
        assert_eq!(ours.is_ok(), c_ok, "pack {hex}: rust {ours:?}");
        if let Ok(pack) = ours {
            accepted += 1;
            assert_eq!(pack.encoded_len() as i64, g["result"].as_i64().unwrap());
            let mut uas = UasData::default();
            uas.update_frame(&Frame::Pack(pack));
            assert_eq!(
                uas.basic_id.iter().flatten().count() as u64,
                int(&g["basic"]),
                "{hex}"
            );
            assert_eq!(uas.location.is_some() as u64, int(&g["location"]));
            assert_eq!(uas.auth.iter().flatten().count() as u64, int(&g["auth"]));
            assert_eq!(uas.self_id.is_some() as u64, int(&g["selfid"]));
            assert_eq!(uas.system.is_some() as u64, int(&g["system"]));
            assert_eq!(uas.operator_id.is_some() as u64, int(&g["operator"]));
        } else {
            rejected += 1;
        }
    }
    assert_eq!(accepted + rejected, 336);
    assert_eq!(rejected, 31);
}
