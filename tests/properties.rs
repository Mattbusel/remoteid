//! Property tests over untrusted input: every parser and the trust engine
//! must accept arbitrary bytes without panicking, and the encoders must
//! round trip.

use proptest::prelude::*;
use remoteid::drip::{self, AssembledAuth, AuthAssembler, DripAuth, PageSet};
use remoteid::ridf::{self, ReceiverPosition, Record};
use remoteid::{
    ble, france, geo, wifi, Auth, AuthType, Frame, Message, Observation, Tracker, Transmitter,
    Transport, TrustConfig, TrustState,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn parsers_never_panic(data in proptest::collection::vec(any::<u8>(), 0..400)) {
        let _ = Frame::decode(&data);
        let _ = Message::decode(&data);
        let _ = wifi::parse_frame(&data);
        let _ = wifi::strip_radiotap(&data).map(wifi::parse_frame);
        let _ = wifi::beacon_info(&data);
        let _ = wifi::parse_vendor_element(&data);
        let _ = wifi::find_in_elements(&data);
        let _ = wifi::parse_nan_action(&data);
        let _ = ble::find_in_advertising_data(&data);
        let _ = ble::parse_service_data(&data);
        let _ = france::find_in_elements(&data);
        let _ = DripAuth::parse(&data);
        for r in ridf::records(&data).flatten() {
            let _ = r.beacon();
            let _ = r.observation();
        }
    }

    #[test]
    fn trust_never_panics(
        frames in proptest::collection::vec(
            (proptest::collection::vec(any::<u8>(), 0..240), any::<u8>(), 0u64..5_000, 0u8..6, any::<Option<i8>>()),
            1..60,
        ),
        unix in any::<Option<u64>>(),
    ) {
        let cfg = TrustConfig::default();
        let mut st = TrustState::new();
        let mut tracker = Tracker::default();
        let mut now = 0u64;
        for (payload, counter, dt, transport, rssi) in &frames {
            now += dt;
            let mut obs = Observation::new(Transport::from_code(*transport), Some(*counter), payload, now);
            if let Some(u) = unix {
                obs = obs.with_unix_ms(u.saturating_add(now));
            }
            if let Some(r) = rssi {
                obs = obs.with_rssi(*r);
            }
            let a = st.observe(&cfg, &obs);
            prop_assert!((0.0..=1.0).contains(&a.score));
            let a = tracker.observe(Transmitter::Ble([*counter % 3; 6]), &obs).assessment;
            prop_assert!((0.0..=1.0).contains(&a.score));
        }
    }

    #[test]
    fn auth_pages_never_panic(
        pages in proptest::collection::vec((0u8..16, any::<u8>(), any::<u8>(), proptest::array::uniform23(any::<u8>()), any::<u8>()), 0..40),
    ) {
        let mut asm = AuthAssembler::new();
        let mut out = AssembledAuth::default();
        for (page, lpi, len, data, counter) in pages {
            let a = Auth {
                protocol_version: 2,
                auth_type: AuthType::SpecificAuthentication,
                page,
                last_page_index: lpi,
                length: len,
                timestamp: 0,
                data,
            };
            if asm.push_legacy(&a, counter, &mut out) {
                prop_assert!(out.data().len() <= 255);
                let _ = out.drip();
            }
            let mut set = PageSet::default();
            set.put(&a);
            let _ = set.assemble(&mut out);
        }
    }

    #[test]
    fn fec_rebuilds_any_single_lost_page(
        data in proptest::collection::vec(any::<u8>(), 1..=201),
        drop in any::<prop::sample::Index>(),
        ts in any::<u32>(),
    ) {
        let pages = drip::paginate(AuthType::SpecificAuthentication, 2, ts, &data, true).unwrap();
        let mut full = AssembledAuth::default();
        prop_assert!(AuthAssembler::push_pack(&pages, &mut full));
        prop_assert_eq!(full.data(), &data[..]);
        prop_assert!(full.fec);
        prop_assert_eq!(full.timestamp, ts);
        let k = drop.index(pages.len());
        let mut set = PageSet::default();
        for (i, p) in pages.iter().enumerate() {
            if i != k {
                set.put(p);
            }
        }
        let mut out = AssembledAuth::default();
        prop_assert!(set.assemble(&mut out).is_ok());
        prop_assert_eq!(out.data(), &data[..]);
        prop_assert_eq!(out.recovered_page, Some(k as u8));
        // Without FEC the pages fit the standard layout and join back.
        let plain = drip::paginate(AuthType::SpecificAuthentication, 2, ts, &data, false).unwrap();
        prop_assert!(AuthAssembler::push_pack(&plain, &mut out));
        prop_assert_eq!(out.data(), &data[..]);
    }

    #[test]
    fn ridf_round_trips(
        payload in proptest::collection::vec(any::<u8>(), 0..=255),
        ext in proptest::collection::vec(any::<u8>(), 0..64),
        t in any::<u64>(),
        counter in any::<Option<u8>>(),
        rssi in any::<Option<i8>>(),
        addr in any::<Option<[u8; 6]>>(),
        id in any::<u16>(),
        pos in any::<Option<(i32, i32, i32)>>(),
        transport in 0u8..6,
        utc in any::<bool>(),
    ) {
        let rec = Record {
            transport: Transport::from_code(transport),
            counter,
            rx_time_ns: t,
            utc,
            rssi_dbm: rssi,
            address: addr,
            receiver_id: id,
            receiver: pos.map(|(a, b, c)| ReceiverPosition {
                latitude: a as f64 / 1e7,
                longitude: b as f64 / 1e7,
                altitude_m: c as f64 / 1000.0,
            }),
            payload: &payload,
            extensions: &ext,
        };
        let mut buf = vec![0u8; rec.encoded_len()];
        let n = rec.encode(&mut buf).unwrap();
        let (back, used) = Record::decode(&buf).unwrap();
        prop_assert_eq!(used, n);
        prop_assert_eq!(back, rec);
    }

    #[test]
    fn geo_is_sane(lat1 in -89.0f64..89.0, lon1 in -179.0f64..179.0, lat2 in -89.0f64..89.0, lon2 in -179.0f64..179.0) {
        let d = geo::distance_m(lat1, lon1, lat2, lon2);
        prop_assert!((0.0..=20_100_000.0).contains(&d));
        prop_assert!((d - geo::distance_m(lat2, lon2, lat1, lon1)).abs() < 1e-6 * d.max(1.0));
        let b = geo::bearing_deg(lat1, lon1, lat2, lon2);
        prop_assert!((0.0..360.0).contains(&b));
        let a = geo::angle_diff_deg(b, lon1);
        prop_assert!((0.0..=180.0).contains(&a));
    }
}
