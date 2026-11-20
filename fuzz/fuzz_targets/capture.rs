//! pcap, pcapng and RIDF files on arbitrary bytes: never panics, and every
//! frame read replays through a tracker and scores.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remoteid::{capture, replay, TrackerConfig};

fuzz_target!(|data: &[u8]| {
    let Ok(frames) = capture::frames(data) else {
        return;
    };
    let _ = capture::track(&frames, TrackerConfig::default(), true);
    let _ = replay::expected(&frames, replay::Truth::Spoofed);
    if let Ok(s) = core::str::from_utf8(data) {
        for line in s.lines() {
            let _ = replay::Report::parse(line);
        }
    }
});
