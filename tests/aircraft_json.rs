//! aircraft.json output parses as JSON and follows the readsb schema.

mod common;

use remoteid::aircraft_json::{self, Options};

fn last_ms(name: &str) -> u64 {
    common::rid_frames(name).last().unwrap().time_us / 1000
}

#[test]
fn readsb_schema_and_redaction() {
    let name = "spoof/cdc_wifi_random3.pcap";
    let tracker = common::track(name, true);
    let now = last_ms(name);
    let text = aircraft_json::to_string(&tracker, now, now as f64 / 1000.0, &Options::default());
    let v: serde_json::Value = serde_json::from_str(&text).expect(&text);
    assert!(v["now"].as_f64().unwrap() > 1.7e9);
    assert_eq!(v["messages"].as_u64().unwrap(), 1173);
    let ac = v["aircraft"].as_array().unwrap();
    assert_eq!(ac.len(), 3);
    for a in ac {
        let hex = a["hex"].as_str().unwrap();
        assert!(
            hex.starts_with('~') && hex.len() == 7 && u32::from_str_radix(&hex[1..], 16).is_ok(),
            "{hex}"
        );
        assert_eq!(a["type"], "other");
        assert_eq!(a["category"], "B6");
        assert!(a["r"].as_str().unwrap().starts_with("Spoofed_Serial_"));
        assert!(a["flight"].as_str().unwrap().len() <= 8);
        let lat = a["lat"].as_f64().unwrap();
        let lon = a["lon"].as_f64().unwrap();
        assert!((lat - 47.37).abs() < 1.0 && (lon - 8.53).abs() < 1.0);
        assert!(a["alt_geom"].is_number() && a["gs"].is_number() && a["seen"].is_number());
        let rid = &a["rid"];
        assert_eq!(rid["verdict"], "spoofed");
        assert_eq!(rid["spoofer"], "cyber-defence-campus/droneRemoteIDSpoofer");
        assert!(rid["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "known_spoofer"));
        assert_eq!(rid["transport"], "wifi_beacon");
        assert!(
            rid.get("operator").is_none(),
            "operator position must be redacted by default"
        );
    }
    let mut opts = Options::default();
    opts.include_operator_position = true;
    let text = aircraft_json::to_string(&tracker, now, now as f64 / 1000.0, &opts);
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(v["aircraft"][0]["rid"]["operator"]["lat"].is_number());

    // Old aircraft drop out after 60 s, as in readsb.
    let text = aircraft_json::to_string(&tracker, now + 61_000, 0.0, &Options::default());
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["aircraft"].as_array().unwrap().len(), 0);
}

#[test]
fn legitimate_sample_is_plausible_in_json() {
    let name = "odid_wifi_bcn_sample.pcap";
    let tracker = common::track(name, true);
    let now = last_ms(name);
    let text = aircraft_json::to_string(&tracker, now, 0.0, &Options::default());
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let a = &v["aircraft"][0];
    assert_eq!(a["r"], "MFG1A0123456789");
    assert_eq!(a["rid"]["verdict"], "plausible");
    assert_eq!(a["rid"]["reasons"].as_array().unwrap().len(), 0);
}
