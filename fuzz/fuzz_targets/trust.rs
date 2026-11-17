//! The tracker and trust engine fed a stream of arbitrary RIDF records.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remoteid::{aircraft_json, ridf, Tracker};

fuzz_target!(|data: &[u8]| {
    let mut tracker = Tracker::default();
    let mut last = 0;
    for r in ridf::records(data) {
        let Ok(r) = r else { break };
        let obs = r.observation();
        last = obs.now_ms;
        let a = tracker.observe(r.transmitter(), &obs).assessment;
        assert!((0.0..=1.0).contains(&a.score));
    }
    let json = aircraft_json::to_string(&tracker, last, 0.0, &aircraft_json::Options::default());
    assert!(json.starts_with('{') && json.ends_with('}'));
});
