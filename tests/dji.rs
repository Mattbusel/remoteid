//! DJI DroneID: decoding checked against payloads demodulated from the NDSS
//! 2023 sample captures, plus the Wi-Fi element and AntSDR framing.

use remoteid::dji::{self, antsdr, FlightInfo, WifiDroneId};
use remoteid::{Error, Message, UasData};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// (capture, payload, reference CRC verdict)
fn vectors() -> Vec<(String, Vec<u8>, bool)> {
    include_str!("data/dji_droneid_payloads.txt")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let mut it = l.split_whitespace();
            let name = it.next().unwrap().to_string();
            let payload = hex(it.next().unwrap());
            let ok = it.next().unwrap() == "True";
            (name, payload, ok)
        })
        .collect()
}

#[test]
fn crc_agrees_with_reference_receiver_on_every_frame() {
    let v = vectors();
    assert_eq!(v.len(), 9);
    for (name, payload, ok) in &v {
        assert_eq!(payload.len(), dji::PAYLOAD_LEN);
        let res = FlightInfo::decode(payload);
        assert_eq!(res.is_ok(), *ok, "{name}: {res:?}");
        if !ok {
            assert!(matches!(res, Err(Error::ChecksumMismatch { .. })));
            // Still readable when the caller asks for it.
            assert!(FlightInfo::decode_unchecked(payload).is_ok());
        }
    }
    assert_eq!(v.iter().filter(|x| x.2).count(), 7);
}

#[test]
fn mavic_air_2_frame_decodes_every_field() {
    let (_, payload, _) = vectors()
        .into_iter()
        .find(|v| v.0 == "mavic_air_2")
        .unwrap();
    let f = FlightInfo::decode(&payload).unwrap();
    assert_eq!(f.version, 2);
    assert_eq!(f.sequence, 0x024f);
    assert_eq!(f.state_info, 0x1ff7);
    assert_eq!(f.serial_str(), Some("1WNBH3900201N1"));
    assert_eq!(f.product_type, 58);
    assert_eq!(f.product_name(), Some("Mavic Air 2"));
    assert_eq!(f.uuid_len, 19);
    assert_eq!(f.uuid_str(), Some("1143635532171534336"));
    assert_eq!((f.altitude_raw, f.height_raw), (141, 42));
    assert_eq!((f.v_north, f.v_east, f.v_up), (-2, 2, 26));
    assert_eq!(f.yaw_raw, -13295);
    assert!((f.yaw_deg() - -132.95).abs() < 1e-3);
    assert_eq!(f.gps_time_ms, Some(0x0180_4bf8_9e12));
    assert_eq!(f.pitch_roll_raw, None);

    // The reference receiver prints (51.44633393111904, 7.26721594197086)
    // using the approximation raw / 174533 for radians times 1e7 to degrees;
    // the exact conversion differs by about 2 m at this latitude.
    let (lat, lon) = f.position().unwrap();
    assert!((lat - 51.44633393111904).abs() < 1e-4, "{lat}");
    assert!((lon - 7.26721594197086).abs() < 1e-4, "{lon}");
    let (hlat, hlon) = f.home_position().unwrap();
    assert!((hlat - 51.4463).abs() < 1e-3 && (hlon - 7.2672).abs() < 1e-3);
    let (alat, alon) = f.pilot_position().unwrap();
    assert!((alat - 51.4463).abs() < 1e-3 && (alon - 7.2672).abs() < 1e-3);
    // Height as feet, as the reference receiver prints it (12.8 m).
    assert!((f.height_m() - 12.8).abs() < 0.01);
}

#[test]
fn mini2_frame_without_gps_fix_still_has_pilot_position() {
    let (_, payload, _) = vectors().into_iter().find(|v| v.2).unwrap();
    let f = FlightInfo::decode(&payload).unwrap();
    assert_eq!(f.product_name(), Some("Mini 2"));
    assert_eq!(f.position(), None);
    assert_eq!(f.home_position(), None);
    let (lat, lon) = f.pilot_position().unwrap();
    // Reference receiver: (51.447176178716916, 7.266528392911369)
    assert!((lat - 51.447176178716916).abs() < 1e-4);
    assert!((lon - 7.266528392911369).abs() < 1e-4);
    assert_eq!(f.uuid_str(), None);
}

#[test]
fn messages_feed_uas_data() {
    let (_, payload, _) = vectors()
        .into_iter()
        .find(|v| v.0 == "mavic_air_2")
        .unwrap();
    let f = FlightInfo::decode(&payload).unwrap();
    let msgs: Vec<Message> = f.messages().collect();
    assert_eq!(msgs.len(), 3);
    let mut uas = UasData::default();
    for m in &msgs {
        assert!(uas.update(m));
        // Every generated message is valid Remote ID and survives the wire.
        let raw = m.encode().unwrap();
        assert_eq!(
            Message::decode(&raw).unwrap().message_type(),
            m.message_type()
        );
    }
    assert_eq!(
        uas.basic_id[0].as_ref().unwrap().uas_id_str(),
        Some("1WNBH3900201N1")
    );
    let loc = uas.location.as_ref().unwrap();
    assert_eq!(loc.position(), f.position());
    let ts = loc.timestamp.unwrap();
    let ms = f.gps_time_ms.unwrap();
    assert!((ts - ((ms % 3_600_000) as f32 / 1000.0)).abs() < 0.1);
    let sys = uas.system.as_ref().unwrap();
    assert_eq!(
        sys.unix_timestamp(),
        Some(ms / 1000),
        "System timestamp is the GPS time"
    );
}

#[test]
fn short_and_wrong_input() {
    assert!(matches!(
        FlightInfo::decode(&[0u8; 90]),
        Err(Error::TooShort { need: 91, got: 90 })
    ));
    let mut p = vectors().remove(0).1;
    p[1] = 0x11;
    assert_eq!(FlightInfo::decode_unchecked(&p), Err(Error::NotRemoteId));
    assert_eq!(dji::product_name(0), None);
}

fn vendor_element(subcommand: u8, record: &[u8]) -> Vec<u8> {
    let mut body = dji::WIFI_OUI.to_vec();
    body.extend_from_slice(&[0x10, 0x00, 0x00, subcommand]);
    body.extend_from_slice(record);
    let mut ie = vec![0u8, 4, b'D', b'J', b'I', b'-']; // SSID element first
    ie.push(221);
    ie.push(body.len() as u8);
    ie.extend_from_slice(&body);
    ie
}

#[test]
fn wifi_element_carries_the_same_record() {
    let (_, payload, _) = vectors()
        .into_iter()
        .find(|v| v.0 == "mavic_air_2")
        .unwrap();
    let ies = vendor_element(dji::SUBCOMMAND_FLIGHT_INFO, &payload[2..89]);
    match dji::find_in_elements(&ies) {
        Some(WifiDroneId::FlightInfo(f)) => {
            assert_eq!(f, FlightInfo::decode(&payload).unwrap());
        }
        other => panic!("{other:?}"),
    }
    // Not a DJI element.
    assert!(dji::find_in_elements(&[221, 4, 0xFA, 0x0B, 0xBC, 0x0D]).is_none());
}

#[test]
fn wifi_version_1_record() {
    let mut r = vec![1u8];
    r.extend_from_slice(&7u16.to_le_bytes());
    r.extend_from_slice(&0u16.to_le_bytes());
    r.extend_from_slice(b"0123456789ABCDEF");
    let lon = (7.0f64.to_radians() * 1e7) as i32;
    let lat = (51.0f64.to_radians() * 1e7) as i32;
    r.extend_from_slice(&lon.to_le_bytes());
    r.extend_from_slice(&lat.to_le_bytes());
    for v in [100i16, 30, 1, 2, 3, 150, -250, 9000] {
        r.extend_from_slice(&v.to_le_bytes());
    }
    r.extend_from_slice(&lon.to_le_bytes());
    r.extend_from_slice(&lat.to_le_bytes());
    r.push(21);
    r.push(0);
    r.extend_from_slice(&[0u8; 20]);
    assert_eq!(r.len(), 75);
    let f = FlightInfo::decode_record(&r).unwrap();
    assert_eq!(f.serial_str(), Some("0123456789ABCDEF"));
    assert_eq!(f.pitch_roll_raw, Some((150, -250)));
    assert_eq!(f.yaw_deg(), 90.0);
    assert_eq!(f.gps_time_ms, None);
    assert_eq!(f.pilot_position(), None);
    assert_eq!(f.product_name(), Some("Spark"));
    let (la, lo) = f.position().unwrap();
    assert!((la - 51.0).abs() < 1e-5 && (lo - 7.0).abs() < 1e-5);
    assert!(FlightInfo::decode_record(&r[..74]).is_err());
}

#[test]
fn wifi_flight_purpose() {
    let mut r = b"0123456789ABCDEF".to_vec();
    r.push(6);
    r.extend_from_slice(b"DRONE1\0\0\0\0");
    r.push(40); // longer than what follows: DJI firmware truncates it
    r.extend_from_slice(b"Survey");
    let ies = vendor_element(dji::SUBCOMMAND_FLIGHT_PURPOSE, &r);
    match dji::find_in_elements(&ies) {
        Some(WifiDroneId::FlightPurpose(p)) => {
            assert_eq!(p.serial_str(), Some("0123456789ABCDEF"));
            assert_eq!(p.drone_id_str(), Some("DRONE1"));
            assert_eq!(p.purpose_str(), Some("Survey"));
        }
        other => panic!("{other:?}"),
    }
    let ies = vendor_element(0x42, &[1, 2, 3]);
    assert_eq!(
        dji::find_in_elements(&ies),
        Some(WifiDroneId::Other {
            subcommand: 0x42,
            record: &[1, 2, 3]
        })
    );
}

#[test]
fn antsdr_stream() {
    let mut body = vec![0u8; antsdr::REPORT_LEN];
    body[..10].copy_from_slice(b"1581F45TXX");
    body[64..71].copy_from_slice(b"Mini 3 ");
    body[128] = 63;
    let vals: [f64; 12] = [
        51.1, 7.1, 51.2, 7.2, 30.0, 120.0, 51.3, 7.3, 2414.5, 1.0, -2.0, 0.5,
    ];
    for (i, v) in vals.iter().enumerate() {
        body[129 + i * 8..137 + i * 8].copy_from_slice(&v.to_le_bytes());
    }
    body[225..229].copy_from_slice(&(-70i32 as u32).to_le_bytes());

    let mut stream = vec![0xAB, 0xCD, antsdr::PACKET_DRONEID];
    stream.extend_from_slice(&(body.len() as u16).to_le_bytes());
    stream.extend_from_slice(&body);
    // A second, non DroneID packet right behind it.
    stream.extend_from_slice(&[0xAB, 0xCD, 0x02, 2, 0, 9, 9]);

    // Partial reads ask for more.
    assert!(matches!(
        antsdr::next_frame(&stream[..100]),
        Err(Error::TooShort { .. })
    ));
    let (frame, used) = antsdr::next_frame(&stream).unwrap();
    assert_eq!(used, 5 + antsdr::REPORT_LEN);
    assert_eq!(frame.header, 0xCDAB);
    let r = antsdr::Report::from_frame(&frame).unwrap();
    assert_eq!(r.serial_str(), Some("1581F45TXX"));
    assert_eq!(r.device_type_str(), Some("Mini 3 "));
    assert_eq!(r.device_type_code, 63);
    assert_eq!(
        (
            r.app_latitude,
            r.app_longitude,
            r.drone_latitude,
            r.drone_longitude
        ),
        (51.1, 7.1, 51.2, 7.2)
    );
    assert_eq!((r.height, r.altitude, r.frequency), (30.0, 120.0, 2414.5));
    assert_eq!((r.speed_east, r.speed_north, r.speed_up), (1.0, -2.0, 0.5));
    assert_eq!(r.rssi as i32, -70);

    let (frame2, used2) = antsdr::next_frame(&stream[used..]).unwrap();
    assert_eq!(used2, 7);
    assert_eq!(antsdr::Report::from_frame(&frame2), Err(Error::NotRemoteId));
}

#[test]
fn no_panic_on_random_input() {
    let mut x: u32 = 0x1234_5678;
    let mut buf = [0u8; 300];
    for len in 0..300 {
        for b in buf.iter_mut() {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = x as u8;
        }
        let d = &buf[..len];
        let _ = FlightInfo::decode(d);
        let _ = FlightInfo::decode_unchecked(d);
        let _ = FlightInfo::decode_record(d);
        let _ = dji::parse_vendor_element(d);
        let _ = dji::find_in_elements(d);
        if let Ok((f, _)) = antsdr::next_frame(d) {
            let _ = antsdr::Report::from_frame(&f);
        }
        let mut el = dji::WIFI_OUI.to_vec();
        el.extend_from_slice(d);
        let _ = dji::parse_vendor_element(&el);
    }
}

#[test]
fn tracker_ingests_dji() {
    use remoteid::{Tracker, TrackerConfig, Transmitter};
    let mut t = Tracker::new(TrackerConfig::default());
    let key = Transmitter::Other(0xD1);
    let mut now = 1_000;
    for (name, payload, ok) in vectors() {
        if !ok {
            continue;
        }
        let f = FlightInfo::decode(&payload).unwrap();
        let tracked = t.ingest_dji(key, &f, now).expect("something to track");
        if name == "mavic_air_2" {
            // Remote ID carries 1e-7 degree steps.
            let (a, b) = tracked.data.location.as_ref().unwrap().position().unwrap();
            let (c, d) = f.position().unwrap();
            assert!((a - c).abs() < 1e-6 && (b - d).abs() < 1e-6);
            assert_eq!(tracked.uas_id().as_deref(), Some("1WNBH3900201N1"));
        }
        now += 200;
    }
    assert_eq!(t.len(), 1);
    let a = FlightInfo::decode(&vectors()[0].1).unwrap();
    let b = FlightInfo::decode(&vectors()[1].1).unwrap();
    assert_eq!(a.key(), b.key(), "same aircraft, same key");
    assert_ne!(a.key(), FlightInfo::decode(&vectors()[8].1).unwrap().key());

    // A record with nothing in it is not tracked.
    let mut empty = FlightInfo::decode(&vectors()[0].1).unwrap();
    empty.serial = [0; 16];
    empty.app_latitude_raw = Some(0);
    empty.app_longitude_raw = Some(0);
    assert!(t.ingest_dji(Transmitter::Other(2), &empty, now).is_none());
    assert_eq!(t.len(), 1);
}
