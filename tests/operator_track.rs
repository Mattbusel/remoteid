//! The grounded operator readouts: where it launched, who is flying it, and
//! where it is heading. Tested against the public Open Drone ID Wi-Fi beacon
//! capture (github.com/opendroneid/wireshark-dissector, Apache-2.0), which is
//! a real flight near Hillsboro, Oregon, plus the EN 4709-002 operator ID
//! string from the reference vectors.

mod common;

use remoteid::operator::OperatorIdentity;
use remoteid::{
    geo, wifi, OperatorId, OperatorLocationType, RangeTrend, System, Tracker, Trajectory,
};

/// Reads the sample capture into a tracker, returning the one aircraft's
/// state after the whole flight, with 100 ms between frames.
fn sample_aircraft() -> Tracker {
    let mut tracker = Tracker::default();
    let mut t = 0u64;
    for (_, pkt) in common::read_pcap("odid_wifi_bcn_sample.pcap") {
        let frame = wifi::strip_radiotap(&pkt).unwrap();
        if let Ok(rid) = wifi::parse_frame(frame) {
            tracker.ingest_wifi(&rid, t);
            t += 100;
        }
    }
    tracker
}

#[test]
fn launch_point_is_distinct_from_the_sample_operator() {
    let tracker = sample_aircraft();
    let (_, uas) = tracker.iter().next().unwrap();
    let sys = uas.data.system.as_ref().expect("System message");

    // This transmitter tags its operator position as the takeoff point.
    assert_eq!(sys.operator_location_type, OperatorLocationType::Takeoff);
    let launch = sys.takeoff_position().expect("takeoff position");
    // Hillsboro, Oregon, where the sample was flown.
    assert!(
        (45.5..45.6).contains(&launch.0) && (-123.0..-122.9).contains(&launch.1),
        "{launch:?}"
    );
    // Because the tag is Takeoff, the launch point is where the drone lifted
    // off, and the live/fixed operator readouts are empty, not a guess.
    assert_eq!(sys.takeoff_position(), sys.operator_position());
    assert_eq!(sys.live_operator_position(), None);
    assert_eq!(sys.fixed_operator_position(), None);
    assert_eq!(uas.data.takeoff_position(), Some(launch));
    assert_eq!(uas.data.pilot_position(), None);
}

#[test]
fn operator_identity_from_the_capture() {
    let tracker = sample_aircraft();
    let (_, uas) = tracker.iter().next().unwrap();
    let id = uas.data.operator_identity().expect("operator identity");
    // The raw field is "GBR-OP-123ABCD": a registration issued under the GBR
    // (United Kingdom) prefix. An operator reads the country, not the code.
    assert_eq!(id.country_code, Some("GBR"));
    assert_eq!(id.country, Some("United Kingdom"));
    assert_eq!(id.registration, "-OP-123ABCD");
    assert_eq!(id.display, "GBR-OP-123ABCD");
}

#[test]
fn heading_and_range_from_the_real_flight() {
    let tracker = sample_aircraft();
    let (_, uas) = tracker.iter().next().unwrap();
    let launch = uas.data.takeoff_position().unwrap();

    // The drone actually moves across the capture, so a heading is real.
    let heading = uas.heading_deg().expect("heading");
    // The final leg runs north-north-west; computed from the last two fixes.
    assert!(
        geo::angle_diff_deg(heading, 338.5) < 5.0,
        "final heading {heading}"
    );
    // It flew a few hundred meters, not zero and not kilometers.
    let ground = uas.trajectory.ground_distance_m();
    assert!((200.0..350.0).contains(&ground), "ground track {ground} m");

    // Relative to the launch point, the aircraft is downrange to the
    // north-east and moving away from where it took off.
    let range = uas.trajectory.range_to_m(launch.0, launch.1).unwrap();
    assert!((450.0..650.0).contains(&range), "range to launch {range} m");
    let bearing = uas.trajectory.bearing_to(launch.0, launch.1).unwrap();
    // Launch is to the south-west of the aircraft's current position.
    assert!(
        (200.0..270.0).contains(&bearing),
        "bearing to launch {bearing}"
    );
    assert_eq!(
        uas.trajectory.trend_to(launch.0, launch.1, 1.0),
        Some(RangeTrend::Opening)
    );
}

#[test]
fn eu_registration_resolves_to_a_country() {
    // The EN 4709-002 operator registration number from the ODID reference
    // vectors: Finland (FIN), then the registration body.
    let id = OperatorIdentity::parse("FIN87astrdge12kxyz8");
    assert_eq!(id.country_code, Some("FIN"));
    assert_eq!(id.country, Some("Finland"));
    assert_eq!(id.registration, "87astrdge12kxyz8");

    // Built straight from an OperatorId message, NUL padding trimmed.
    let msg = OperatorId::new("DEU1234567890").unwrap();
    let id = msg.identity().unwrap();
    assert_eq!(id.country, Some("Germany"));
    assert_eq!(id.registration, "1234567890");
}

#[test]
fn unknown_prefix_stays_whole() {
    // A prefix that is not a real country code is not split or labelled.
    let id = OperatorIdentity::parse("ZZZ-made-up");
    assert_eq!(id.country_code, None);
    assert_eq!(id.country, None);
    assert_eq!(id.registration, "ZZZ-made-up");

    // A lower case or non-registration string is left as a whole identity.
    let id = OperatorIdentity::parse("my-drone-7");
    assert_eq!(id.country, None);
    assert_eq!(id.display, "my-drone-7");
}

#[test]
fn live_operator_position_is_the_pilot_not_the_launch() {
    // A System that tags its position as a live GNSS fix reports the pilot's
    // current spot, and does not claim a takeoff point.
    let sys = System {
        operator_location_type: OperatorLocationType::LiveGnss,
        operator_latitude: 45.55,
        operator_longitude: -122.95,
        ..System::default()
    };
    assert_eq!(sys.live_operator_position(), Some((45.55, -122.95)));
    assert_eq!(sys.takeoff_position(), None);
    assert_eq!(sys.fixed_operator_position(), None);
}

#[test]
fn country_table_spot_checks() {
    use remoteid::operator::country_name;
    assert_eq!(country_name(b"USA"), Some("United States"));
    assert_eq!(country_name(b"FRA"), Some("France"));
    assert_eq!(country_name(b"JPN"), Some("Japan"));
    assert_eq!(country_name(b"KOR"), Some("South Korea"));
    assert_eq!(country_name(b"ZZZ"), None);
    assert_eq!(country_name(b"US"), None);
}

#[test]
fn stationary_emitter_gives_no_heading() {
    // Feeding the same fix twice (a hovering or spoofed-static emitter) must
    // not invent a heading out of GNSS noise.
    let mut traj = Trajectory::new();
    assert_eq!(traj.update(45.55, -122.95), None);
    assert_eq!(traj.update(45.55, -122.95), None);
    assert_eq!(traj.heading_deg(), None);
}
