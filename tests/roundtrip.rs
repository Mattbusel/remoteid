//! Encode/decode properties and robustness on random input.

use remoteid::*;

/// xorshift64*: deterministic, no dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn f(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (self.next() >> 11) as f64 / (1u64 << 53) as f64 * (hi - lo)
    }
}

#[test]
fn random_bytes_never_panic() {
    let mut r = Rng(0x9E37_79B9_7F4A_7C15);
    let mut buf = [0u8; 300];
    for _ in 0..200_000 {
        let n = (r.next() % 300) as usize;
        for b in buf[..n].iter_mut() {
            *b = r.next() as u8;
        }
        // Bias towards headers the parsers look for, so they get past the first check.
        if n > 6 && r.next() % 2 == 0 {
            buf[0] = [0xF2, 0x12, 0x22, 0x42, 0x80, 0xD0, 0x00][(r.next() % 7) as usize];
            buf[1] = 25;
            buf[2] = (r.next() % 11) as u8;
        }
        let d = &buf[..n];
        let _ = Frame::decode(d);
        let _ = ble::find_in_advertising_data(d);
        let _ = wifi::parse_frame(d);
        let _ = wifi::strip_radiotap(d);
        let _ = wifi::find_in_elements(d);
        let _ = france::find_in_elements(d);
        let mut uas = UasData::default();
        if let Ok(f) = Frame::decode(d) {
            uas.update_frame(&f);
            let mut out = [0u8; 300];
            let _ = uas.auth_data(&mut out);
        }
        if let Ok(m) = Message::decode(d) {
            let _ = m.encode();
            if let Message::Location(l) = m {
                let _ = l.check().count();
            }
        }
    }
}

#[test]
fn every_message_on_the_grid_roundtrips() {
    let mut r = Rng(42);
    for _ in 0..20_000 {
        let loc = Location {
            status: Status::from((r.next() % 5) as u8),
            height_type: HeightType::from((r.next() % 2) as u8),
            direction: Some((r.next() % 360) as f32),
            speed_horizontal: Some(if r.next() % 2 == 0 {
                (r.next() % 256) as f32 * 0.25
            } else {
                63.75 + (1 + r.next() % 254) as f32 * 0.75
            }),
            speed_vertical: Some((r.next() % 249) as f32 * 0.5 - 62.0),
            latitude: (r.f(-90.0, 90.0) * 1e7).round() / 1e7,
            longitude: (r.f(-180.0, 180.0) * 1e7).round() / 1e7,
            altitude_baro: Some((1 + r.next() % 60000) as f32 * 0.5 - 1000.0),
            altitude_geo: Some((1 + r.next() % 60000) as f32 * 0.5 - 1000.0),
            height: Some((1 + r.next() % 60000) as f32 * 0.5 - 1000.0),
            horizontal_accuracy: HorizontalAccuracy((r.next() % 13) as u8),
            vertical_accuracy: VerticalAccuracy((r.next() % 7) as u8),
            baro_accuracy: VerticalAccuracy((r.next() % 7) as u8),
            speed_accuracy: SpeedAccuracy((r.next() % 5) as u8),
            timestamp_accuracy: TimestampAccuracy((r.next() % 16) as u8),
            timestamp: Some((r.next() % 36001) as f32 / 10.0),
            ..Location::default()
        };
        let m = Message::Location(loc);
        let bytes = m.encode().unwrap();
        let back = Message::decode(&bytes).unwrap();
        assert_eq!(back.encode().unwrap(), bytes);
        if let (Message::Location(a), Message::Location(b)) = (&m, &back) {
            assert!(
                (a.latitude - b.latitude).abs() < 1e-9 && (a.longitude - b.longitude).abs() < 1e-9
            );
            assert_eq!(a.altitude_geo, b.altitude_geo);
            assert_eq!(a.direction, b.direction);
            assert_eq!(a.speed_horizontal, b.speed_horizontal);
            assert_eq!(a.speed_vertical, b.speed_vertical);
            assert_eq!(a.timestamp, b.timestamp);
            assert!(b.is_plausible(), "{:?}", b.check().collect::<Vec<_>>());
        }

        let sys = System {
            operator_location_type: OperatorLocationType::from((r.next() % 3) as u8),
            classification_type: ClassificationType::Eu,
            operator_latitude: (r.f(-90.0, 90.0) * 1e7).round() / 1e7,
            operator_longitude: (r.f(-180.0, 180.0) * 1e7).round() / 1e7,
            area_count: r.next() as u16,
            area_radius: (r.next() % 256) as u16 * 10,
            area_ceiling: Some((1 + r.next() % 60000) as f32 * 0.5 - 1000.0),
            area_floor: None,
            category_eu: CategoryEu::from((r.next() % 4) as u8),
            class_eu: ClassEu::from((r.next() % 8) as u8),
            operator_altitude_geo: Some(120.5),
            timestamp: r.next() as u32,
            ..System::default()
        };
        let back = Message::decode(&Message::System(sys.clone()).encode().unwrap()).unwrap();
        let Message::System(b) = back else {
            panic!("not a system message")
        };
        assert_eq!(b, sys);
    }
}

#[test]
fn unknown_values_encode_as_unknown() {
    let l = Location::default();
    let back = Location::decode(&l.encode().unwrap()).unwrap();
    assert_eq!(back.direction, None);
    assert_eq!(back.speed_horizontal, None);
    assert_eq!(back.speed_vertical, None);
    assert_eq!(back.altitude_geo, None);
    assert_eq!(back.timestamp, None);
    assert_eq!(back.position(), None);
}

#[test]
fn out_of_range_is_refused() {
    let bad = Location {
        latitude: 91.0,
        ..Location::default()
    };
    assert_eq!(bad.encode(), Err(Error::OutOfRange("latitude")));
    let bad = Location {
        speed_horizontal: Some(300.0),
        ..Location::default()
    };
    assert_eq!(bad.encode(), Err(Error::OutOfRange("speed_horizontal")));
    assert!(BasicId::new(
        IdType::SerialNumber,
        UaType::None,
        "THIS-ID-IS-LONGER-THAN-20"
    )
    .is_err());
}

#[test]
fn auth_pages_reassemble() {
    let sig: Vec<u8> = (1..=63u8).collect(); // 17 + 23 + 23 bytes = 3 pages
    let mut page0 = Auth {
        protocol_version: 2,
        auth_type: AuthType::UasIdSignature,
        page: 0,
        last_page_index: 2,
        length: 63,
        timestamp: 1000,
        data: [0; 23],
    };
    page0.data[..17].copy_from_slice(&sig[..17]);
    let mut p1 = Auth {
        page: 1,
        last_page_index: 0,
        length: 0,
        timestamp: 0,
        ..page0.clone()
    };
    p1.data.copy_from_slice(&sig[17..40]);
    let mut p2 = p1.clone();
    p2.page = 2;
    p2.data.copy_from_slice(&sig[40..63]);
    // Through the wire format, out of order.
    let mut b = MessagePackBuilder::new();
    for p in [&p2, &page0, &p1] {
        b.push(&Message::Auth(p.clone())).unwrap();
    }
    let mut uas = UasData::default();
    uas.update_frame(&Frame::decode(b.as_bytes()).unwrap());
    let mut out = [0u8; 255];
    let n = uas.auth_data(&mut out).unwrap();
    assert_eq!(&out[..n], &sig[..]);
    assert_eq!(
        uas.auth[0].as_ref().unwrap().unix_timestamp(),
        1_546_301_800
    );

    let mut partial = UasData::default();
    partial.update(&Message::Auth(page0));
    assert_eq!(partial.auth_data(&mut out), None, "pages 1 and 2 missing");
}

#[test]
fn pack_rules() {
    let loc = Message::Location(Location::default());
    let mut b = MessagePackBuilder::new();
    b.push(&loc).unwrap();
    b.push(&loc).unwrap();
    assert!(matches!(
        MessagePack::parse(b.as_bytes()),
        Err(Error::InvalidPack(_))
    ));
    assert!(MessagePack::parse(&[0xF2, 25, 0]).is_err(), "empty pack");
    let mut full = MessagePackBuilder::new();
    for page in 0..9 {
        let a = Auth {
            protocol_version: 2,
            auth_type: AuthType::None,
            page,
            last_page_index: 8,
            length: 0,
            timestamp: 0,
            data: [0; 23],
        };
        full.push(&Message::Auth(a)).unwrap();
    }
    assert!(full.push(&loc).is_err(), "tenth message");
    assert_eq!(MessagePack::parse(full.as_bytes()).unwrap().len(), 9);
}

#[test]
fn ble_and_wifi_writers_roundtrip() {
    let id = Message::BasicId(
        BasicId::new(
            IdType::SerialNumber,
            UaType::HelicopterOrMultirotor,
            "1596F3507452",
        )
        .unwrap(),
    );
    let raw = id.encode().unwrap();
    let mut adv = [0u8; 31];
    assert_eq!(ble::write_advertising_data(7, &raw, &mut adv).unwrap(), 31);
    let rid = ble::find_in_advertising_data(&adv).unwrap();
    assert_eq!(rid.counter, 7);
    assert_eq!(rid.frame().unwrap(), Frame::Message(id.clone()));

    let mut pack = MessagePackBuilder::new();
    pack.push(&id).unwrap();
    let mut ie = [0u8; 64];
    let n = wifi::write_beacon_element(3, pack.as_bytes(), &mut ie).unwrap();
    let rid = wifi::find_in_elements(&ie[..n]).unwrap();
    assert_eq!(rid.counter, 3);
    let Frame::Pack(p) = rid.frame().unwrap() else {
        panic!("expected a pack")
    };
    assert_eq!(p.messages().next().unwrap().unwrap(), id);
}

#[test]
fn serial_numbers() {
    let s = SerialNumber::parse("1596F35074529ABCDEFG").unwrap();
    assert_eq!(
        (s.manufacturer_code, s.length, s.serial),
        ("1596", 15, "35074529ABCDEFG")
    );
    assert!(SerialNumber::parse("ABCD3XYZ").is_some());
    assert!(
        SerialNumber::parse("ABCD4XYZ").is_none(),
        "length character says 4, 3 follow"
    );
    assert!(
        SerialNumber::parse("ABCO3XYZ").is_none(),
        "O is not allowed"
    );
    assert!(
        SerialNumber::parse("1596F3507452").is_none(),
        "F means 15 characters"
    );
}

#[test]
fn tracker_counts_gaps_and_duplicates() {
    let id = BasicId::new(IdType::SerialNumber, UaType::Aeroplane, "ABCD3XYZ").unwrap();
    let raw = Message::BasicId(id).encode().unwrap();
    let mut t = Tracker::default();
    let tx = Transmitter::Other(1);
    for (c, now) in [(1u8, 0u64), (2, 1), (2, 2), (5, 3), (4, 4), (6, 5)] {
        t.ingest(tx, c, &raw, now);
    }
    let s = t.get(&tx).unwrap().stats;
    assert_eq!(s.received, 6);
    assert_eq!(s.duplicates, 1);
    assert_eq!(s.missed, 1, "3 never arrived; 4 arrived late");
    assert_eq!(s.resets, 0, "4 after 5 is reordering");
    assert_eq!(t.get(&tx).unwrap().data.primary_id(), Some("ABCD3XYZ"));

    let tx2 = Transmitter::Other(2);
    t.ingest(tx2, 254, &raw, 0);
    t.ingest(tx2, 1, &raw, 1);
    assert_eq!(
        t.get(&tx2).unwrap().stats.missed,
        2,
        "255 and 0 across the wrap"
    );
}

#[test]
fn french_beacon() {
    // OUI 6A:5C:35, type 1, then TLVs: version, identifier, lat, lon, altitude, speed, course.
    let mut ie = vec![221u8, 0, 0x6A, 0x5C, 0x35, 0x01, 1, 1, 1, 2, 30];
    let mut id = *b"ILLEGAL_DRONE_APPELI_LA_POLICE";
    id[29] = 0;
    ie.extend_from_slice(&id);
    ie.extend_from_slice(&[4, 4]);
    ie.extend_from_slice(&4_884_000i32.to_be_bytes());
    ie.extend_from_slice(&[5, 4]);
    ie.extend_from_slice(&235_000i32.to_be_bytes());
    ie.extend_from_slice(&[6, 2, 0, 120, 10, 1, 12, 11, 2, 0, 90]);
    ie[1] = (ie.len() - 2) as u8;
    let b = france::find_in_elements(&ie).unwrap();
    assert_eq!(b.version, Some(1));
    assert_eq!(b.identifier_str(), Some("ILLEGAL_DRONE_APPELI_LA_POLIC"));
    assert!((b.latitude.unwrap() - 48.84).abs() < 1e-9);
    assert!((b.longitude.unwrap() - 2.35).abs() < 1e-9);
    assert_eq!(b.altitude, Some(120));
    assert_eq!(b.horizontal_speed, Some(12));
    assert_eq!(b.true_course, Some(90));
}
