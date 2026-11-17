//! Prints the trust verdict and reasons for every transmitter in a capture.
//!
//! ```text
//! cargo run --example trust_report -- tests/data/spoof/cdc_wifi_random3.pcap
//! ```
//!
//! The capture clock is used as the receiver's UTC clock; pass `--no-utc`
//! for captures whose clock was not set, and `--no-fingerprints` to see
//! what the generic checks find without spoofer fingerprints.

#[path = "../tests/common/mod.rs"]
mod common;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let utc = !args.iter().any(|a| a == "--no-utc");
    let mut cfg = remoteid::TrustConfig::default();
    cfg.fingerprints = !args.iter().any(|a| a == "--no-fingerprints");
    for path in args.iter().filter(|a| !a.starts_with("--")) {
        println!("{path}");
        let tracker = common::track_with(path, utc, cfg);
        let mut all: Vec<_> = tracker.iter().collect();
        all.sort_by_key(|(tx, _)| **tx);
        for (tx, uas) in all {
            let a = &uas.assessment;
            let reasons: Vec<&str> = a.reasons.iter().map(|r| r.name()).collect();
            println!(
                "  {tx:?} id={:?} frames={} verdict={} score={:.2} auth={} spoofer={:?} reasons={reasons:?}",
                uas.data.primary_id(),
                uas.stats.received,
                a.verdict,
                a.score,
                a.auth.name(),
                a.spoofer.map(|s| s.name()),
            );
        }
    }
}
