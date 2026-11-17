//! Regressions for false alerts on honest aircraft: GNSS outliers, evidence
//! spread over long flights, several receivers, signal fading, and memory
//! bounds of the tracker.

use remoteid::ridf::{ReceiverPosition, Record};
use remoteid::{
    Assessment, BasicId, HorizontalAccuracy, IdType, Location, Message, Observation, Reason,
    Tracker, TrackerConfig, Transmitter, Transport, UaType, Verdict,
};

fn basic_id() -> [u8; 25] {
    Message::BasicId(
        BasicId::new(
            IdType::SerialNumber,
            UaType::HelicopterOrMultirotor,
            "1596F35074529ABCDEFG",
        )
        .unwrap(),
    )
    .encode()
    .unwrap()
}

fn location(lat: f64, lon: f64, speed: f32, dir: f32) -> [u8; 25] {
    Message::Location(Location {
        latitude: lat,
        longitude: lon,
        speed_horizontal: Some(speed),
        direction: Some(dir),
        altitude_geo: Some(500.0),
        horizontal_accuracy: HorizontalAccuracy(11),
        ..Location::default()
    })
    .encode()
    .unwrap()
}

fn tracker() -> Tracker {
    Tracker::new(TrackerConfig {
        timeout: u64::MAX,
        ..TrackerConfig::default()
    })
}

/// A hovering aircraft at 1 Hz with single far-off fixes at `glitches`
/// (seconds). Returns the worst verdict seen and the verdict at the end.
fn hover_with_glitches(glitches: &[u64], seconds: u64) -> (Verdict, Assessment) {
    let mut t = tracker();
    let tx = Transmitter::Ble([1; 6]);
    let id = basic_id();
    let mut worst = Verdict::Authenticated;
    let mut a = Assessment::default();
    let mut c = 0u8;
    for s in 0..seconds {
        let now = s * 1000;
        let lat = if glitches.contains(&s) { 46.52 } else { 46.5 };
        c = c.wrapping_add(1);
        if s % 3 == 0 {
            t.observe(
                tx,
                &Observation::new(Transport::Bluetooth4, Some(c), &id, now),
            );
        }
        let raw = location(lat, 8.5, 0.0, 0.0);
        a = t
            .observe(
                tx,
                &Observation::new(Transport::Bluetooth4, Some(c), &raw, now + 5),
            )
            .assessment;
        worst = worst.min(a.verdict);
    }
    (worst, a)
}

#[test]
fn one_gnss_outlier_is_not_a_teleport() {
    // 2.2 km off for one fix, then back on the track.
    let (worst, a) = hover_with_glitches(&[100], 400);
    assert_eq!(worst, Verdict::Plausible, "{:?}", a.reasons);
    assert!(!a.reasons.contains(Reason::Teleport));
}

#[test]
fn outliers_far_apart_never_add_up() {
    // Two single-fix glitches 20 minutes apart, over 40 minutes.
    let (worst, a) = hover_with_glitches(&[100, 1300], 2400);
    assert_eq!(worst, Verdict::Plausible, "{:?}", a.reasons);
    // Two within a few seconds are still forgiven ...
    let (worst, _) = hover_with_glitches(&[100, 104], 200);
    assert_eq!(worst, Verdict::Plausible);
    // ... three within the memory window are not.
    let (worst, _) = hover_with_glitches(&[100, 104, 108], 200);
    assert_eq!(worst, Verdict::Spoofed);
}

#[test]
fn a_jump_that_sticks_twice_is_a_teleport() {
    let mut t = tracker();
    let tx = Transmitter::Ble([2; 6]);
    let mut a = Assessment::default();
    for s in 0..40u64 {
        // Three places, ten seconds each.
        let lat = 46.5 + 0.05 * (s / 10) as f64;
        let raw = location(lat, 8.5, 0.0, 0.0);
        a = t
            .observe(
                tx,
                &Observation::new(Transport::Bluetooth4, Some(s as u8), &raw, s * 1000),
            )
            .assessment;
    }
    assert!(a.reasons.contains(Reason::Teleport), "{:?}", a.reasons);
    assert_eq!(a.verdict, Verdict::Spoofed);
}

#[test]
fn signal_swings_an_hour_apart_do_not_add_up() {
    // Three 30 dB swings 20 minutes apart (turns, multipath).
    let mut t = tracker();
    let tx = Transmitter::Ble([3; 6]);
    let mut worst = Verdict::Authenticated;
    let mut c = 0u8;
    let raw = location(46.5, 8.5, 0.0, 0.0);
    for s in 0..3600u64 {
        let now = s * 1000;
        let rssi: i8 = if s == 600 || s == 1800 || s == 3000 {
            -95
        } else {
            -65
        };
        c = c.wrapping_add(1);
        for (dt, r) in [(0, rssi), (300, -65)] {
            let obs = Observation::new(Transport::Bluetooth4, Some(c), &raw, now + dt).with_rssi(r);
            worst = worst.min(t.observe(tx, &obs).assessment.verdict);
        }
    }
    assert_eq!(worst, Verdict::Plausible);
}

#[test]
fn two_receivers_at_different_ranges_are_not_a_signal_jump() {
    // One aircraft heard by a near (-50 dBm) and a far (-85 dBm) receiver
    // that share a UTC clock, fed through RIDF into one tracker.
    let id = basic_id();
    let mut t = tracker();
    let mut a = Assessment::default();
    let mut c = 0u8;
    let t0 = 1_794_916_800_000_000_000u64;
    for s in 0..60u64 {
        let loc = location(46.5 + s as f64 * 1e-5, 8.5, 1.1, 0.0);
        for (k, payload) in [&id, &loc].iter().enumerate() {
            c = c.wrapping_add(1);
            for (rid, rssi, lat) in [(1u16, -50i8, 46.5), (2, -85, 46.6)] {
                let rec = Record {
                    transport: Transport::Bluetooth4,
                    counter: Some(c),
                    rx_time_ns: t0 + (s * 1000 + k as u64 * 200 + rid as u64 * 3) * 1_000_000,
                    utc: true,
                    rssi_dbm: Some(rssi),
                    address: Some([0xC0, 1, 2, 3, 4, 5]),
                    receiver_id: rid,
                    receiver: Some(ReceiverPosition {
                        latitude: lat,
                        longitude: 8.5,
                        altitude_m: 500.0,
                    }),
                    payload: &payload[..],
                    extensions: &[],
                };
                a = t.observe(rec.transmitter(), &rec.observation()).assessment;
            }
        }
    }
    assert_eq!(t.len(), 1);
    assert!(!a.reasons.contains(Reason::SignalJump), "{:?}", a.reasons);
    assert_eq!(a.verdict, Verdict::Plausible, "{:?}", a.reasons);
}

/// Small deterministic generator (xorshift) for the noise below.
struct Noise(u64);

impl Noise {
    fn unit(&mut self) -> f64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Roughly normal, mean 0, standard deviation 1.
    fn gauss(&mut self) -> f64 {
        (0..12).map(|_| self.unit()).sum::<f64>() - 6.0
    }
}

#[test]
fn hour_long_noisy_flight_is_never_spoofed() {
    // A synthetic survey flight (not a field capture): 1 Hz, 12 m/s legs
    // with turns, 3 m GNSS noise, reported speed and course with noise, a
    // GNSS outlier every 10 minutes, RSSI fading with occasional deep fades,
    // and 2% frame loss.
    let mut t = tracker();
    let tx = Transmitter::Ble([4; 6]);
    let id = basic_id();
    let mut n = Noise(0x9E37_79B9_7F4A_7C15);
    let (mut lat, mut lon) = (46.5f64, 8.5f64);
    let mut worst = Verdict::Authenticated;
    let mut reasons_seen = remoteid::trust::ReasonSet::default();
    let mut c = 0u8;
    for s in 0..3600u64 {
        let now = s * 1000;
        let heading: f64 = match (s / 120) % 4 {
            0 => 0.0,
            1 => 90.0,
            2 => 180.0,
            _ => 270.0,
        };
        let v = 12.0;
        lat += v * heading.to_radians().cos() / 111_195.0;
        lon += v * heading.to_radians().sin() / (111_195.0 * 46.5f64.to_radians().cos());
        c = c.wrapping_add(1);
        if n.unit() < 0.02 {
            continue;
        }
        let (mut flat, mut flon) = (
            lat + 3.0 * n.gauss() / 111_195.0,
            lon + 3.0 * n.gauss() / 76_500.0,
        );
        if s % 600 == 300 {
            flat += 0.02;
            flon -= 0.01;
        }
        let speed = (v + 0.5 * n.gauss()).max(0.0) as f32;
        let dir = ((heading + 5.0 * n.gauss()).rem_euclid(360.0)) as f32;
        let rssi = (-70.0 + 6.0 * n.gauss() - if n.unit() < 0.01 { 25.0 } else { 0.0 }) as i8;
        if s % 3 == 0 {
            let o = Observation::new(Transport::Bluetooth4, Some(c), &id, now).with_rssi(rssi);
            t.observe(tx, &o);
        }
        let raw = location(flat, flon, speed, dir);
        let o = Observation::new(Transport::Bluetooth4, Some(c), &raw, now + 30).with_rssi(rssi);
        let a = t.observe(tx, &o).assessment;
        worst = worst.min(a.verdict);
        for r in a.reasons.iter() {
            reasons_seen.insert(r);
        }
    }
    assert_eq!(worst, Verdict::Plausible, "{reasons_seen:?}");
}

#[test]
fn tracker_is_bounded() {
    // A flood of frames from random addresses keeps at most
    // `max_transmitters` entries.
    let mut t = Tracker::new(TrackerConfig {
        timeout: u64::MAX,
        max_transmitters: 100,
        ..TrackerConfig::default()
    });
    let raw = location(46.5, 8.5, 0.0, 0.0);
    for i in 0..1000u32 {
        let b = i.to_le_bytes();
        let tx = Transmitter::Ble([b[0], b[1], b[2], b[3], 0, 0]);
        t.observe(
            tx,
            &Observation::new(Transport::Bluetooth4, Some(0), &raw, i as u64),
        );
    }
    assert_eq!(t.len(), 100);
    // The newest stay.
    assert!(t.get(&Transmitter::Ble([0xE7, 3, 0, 0, 0, 0])).is_some());
    assert!(t.get(&Transmitter::Ble([0, 0, 0, 0, 0, 0])).is_none());
}

#[test]
fn identity_index_follows_expiry() {
    // Two transmitters with one identity far apart are clones; after one
    // expires the other is no longer compared with it.
    let mut t = Tracker::new(TrackerConfig {
        timeout: 5_000,
        ..TrackerConfig::default()
    });
    let id = basic_id();
    let (a, b) = (Transmitter::Ble([5; 6]), Transmitter::Ble([6; 6]));
    let mut last = Assessment::default();
    for s in 0..10u64 {
        for (tx, lat) in [(a, 46.5), (b, 46.6)] {
            t.observe(
                tx,
                &Observation::new(Transport::Bluetooth4, Some(s as u8), &id, s * 1000),
            );
            let raw = location(lat, 8.5, 0.0, 0.0);
            last = t
                .observe(
                    tx,
                    &Observation::new(Transport::Bluetooth4, Some(s as u8), &raw, s * 1000 + 5),
                )
                .assessment;
        }
    }
    assert!(
        last.reasons.contains(Reason::IdentityClone),
        "{:?}",
        last.reasons
    );
    assert_eq!(t.expire(30_000), 2);
    assert!(t.is_empty());
}
