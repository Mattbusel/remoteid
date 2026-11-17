//! The trust engine against two corpora:
//!
//! * legitimate: the Open Drone ID sample captures (tests/data/odid_*),
//!   recorded from real Remote ID transmitters;
//! * spoofed: tests/data/spoof/*.pcap, synthesized from the source code of
//!   cyber-defence-campus/droneRemoteIDSpoofer and jjshoots/RemoteIDSpoofer
//!   by tools/spoof-corpus (no radio transmission).
//!
//! Each case runs with and without the receiver UTC clock (the capture
//! timestamps), and spoof cases also run with fingerprints switched off to
//! pin down what the generic checks catch on their own.

mod common;

use remoteid::{Reason, TrustConfig, Verdict};

const LEGIT: &[&str] = &[
    "odid_wifi_bcn_sample.pcap",
    "odid_wifi_sample.pcap",
    "odid_bt5_lr_sample.pcapng",
];

fn verdicts(name: &str, utc: bool, fingerprints: bool) -> Vec<(String, Verdict, Vec<Reason>)> {
    let mut cfg = TrustConfig::default();
    cfg.fingerprints = fingerprints;
    let t = common::track_with(name, utc, cfg);
    let mut v: Vec<_> = t
        .iter()
        .map(|(tx, u)| {
            (
                format!("{tx:?}"),
                u.assessment.verdict,
                u.assessment.reasons.iter().collect(),
            )
        })
        .collect();
    v.sort();
    v
}

#[test]
fn legitimate_captures_are_plausible() {
    for name in LEGIT {
        for utc in [true, false] {
            for (tx, verdict, reasons) in verdicts(name, utc, true) {
                assert_eq!(
                    verdict,
                    Verdict::Plausible,
                    "{name} utc={utc} {tx}: {reasons:?}"
                );
                assert!(
                    reasons.iter().all(|r| *r == Reason::SerialFormat),
                    "{name} utc={utc} {tx}: {reasons:?}"
                );
            }
        }
    }
}

/// (capture, transmitters, reasons every transmitter must show with the
/// UTC clock and fingerprints on)
const SPOOF: &[(&str, usize, &[Reason])] = &[
    (
        "spoof/cdc_wifi_random3.pcap",
        3,
        &[
            Reason::KnownSpoofer,
            Reason::Teleport,
            Reason::TsfWallClock,
            Reason::SharedRadio,
            Reason::SystemClockDrift,
        ],
    ),
    (
        "spoof/cdc_ble_legacy_random2.pcap",
        2,
        &[
            Reason::KnownSpoofer,
            Reason::ReportedCourseMismatch,
            Reason::SystemClockDrift,
        ],
    ),
    (
        "spoof/cdc_wifi_same_mac.pcap",
        1,
        &[
            Reason::KnownSpoofer,
            Reason::Teleport,
            Reason::CounterConflict,
            Reason::TsfWallClock,
        ],
    ),
    (
        "spoof/cdc_wifi_slow_forward.pcap",
        1,
        &[
            Reason::KnownSpoofer,
            Reason::TsfWallClock,
            Reason::SystemClockDrift,
        ],
    ),
    (
        "spoof/jjshoots_esp8266_beacon_1drone.pcap",
        1,
        &[
            Reason::KnownSpoofer,
            Reason::TsfWallClock,
            Reason::SystemClockDrift,
            Reason::ReportedCourseMismatch,
        ],
    ),
    (
        "spoof/jjshoots_esp8266_beacon_4drones.pcap",
        4,
        &[
            Reason::KnownSpoofer,
            Reason::TsfWallClock,
            Reason::SystemClockDrift,
        ],
    ),
];

#[test]
fn spoofed_captures_are_spoofed() {
    for (name, n, must) in SPOOF {
        let v = verdicts(name, true, true);
        assert_eq!(v.len(), *n, "{name}");
        for (tx, verdict, reasons) in &v {
            assert_eq!(*verdict, Verdict::Spoofed, "{name} {tx}: {reasons:?}");
            for r in *must {
                assert!(
                    reasons.contains(r),
                    "{name} {tx}: missing {r:?} in {reasons:?}"
                );
            }
        }
        // Without a receiver clock the fingerprints still decide.
        for (tx, verdict, reasons) in verdicts(name, false, true) {
            assert_eq!(verdict, Verdict::Spoofed, "{name} no-utc {tx}: {reasons:?}");
        }
    }
}

#[test]
fn generic_checks_without_fingerprints() {
    // What the physics and protocol checks catch with no tool knowledge.
    // Every transmitter is at least Suspicious; these are Spoofed.
    let spoofed_generic = [
        "spoof/cdc_wifi_random3.pcap",
        "spoof/cdc_wifi_same_mac.pcap",
        "spoof/jjshoots_esp8266_beacon_1drone.pcap",
    ];
    for (name, _, _) in SPOOF {
        for (tx, verdict, reasons) in verdicts(name, true, false) {
            assert!(!reasons.contains(&Reason::KnownSpoofer));
            assert!(
                verdict <= Verdict::Suspicious,
                "{name} {tx}: {verdict:?} {reasons:?}"
            );
            if spoofed_generic.contains(name) {
                assert_eq!(verdict, Verdict::Spoofed, "{name} {tx}: {reasons:?}");
            }
        }
    }
}
