//! The replay gate end to end: the binary against receivers that believe
//! spoofers, receivers that flag them, and receivers that show nothing.
#![cfg(feature = "cli")]

use std::process::Command;

const EXE: &str = env!("CARGO_BIN_EXE_remoteid-replay");

fn replay(args: &[&str]) -> (i32, String) {
    let out = Command::new(EXE).args(args).output().unwrap();
    (
        out.status.code().unwrap(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// A receiver command that runs this binary with `sub`.
fn me(sub: &str) -> String {
    format!("\"{EXE}\" {sub}")
}

fn corpus_dir(tag: &str) -> String {
    std::env::temp_dir()
        .join(format!("remoteid-replay-test-{tag}-{}", std::process::id()))
        .display()
        .to_string()
}

#[test]
fn remoteid_flags_every_spoofed_transmitter() {
    let dir = corpus_dir("builtin");
    let (code, out) = replay(&["run", "--corpus-dir", &dir]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("spoofed: 12 replayed, 12 flagged, 0 ACCEPTED AS REAL"),
        "{out}"
    );
    assert!(
        out.contains("real: 3 replayed, 3 accepted, 0 flagged"),
        "{out}"
    );
    // The generic checks alone (no tool fingerprints) still flag all 12.
    let (code, out) = replay(&["run", "--corpus-dir", &dir, "--no-fingerprints"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("12 flagged, 0 ACCEPTED"), "{out}");
}

#[test]
fn external_receiver_with_verdicts_passes() {
    let dir = corpus_dir("verdicts");
    let rx = me("verdicts {capture}");
    let (code, out) = replay(&["run", "--corpus-dir", &dir, "--receiver", &rx]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("12 flagged, 0 ACCEPTED"), "{out}");
}

#[test]
fn receiver_without_spoof_checks_fails() {
    // `frames` reports every transmitter with no verdict: exactly what a
    // decode-and-display receiver does.
    let dir = corpus_dir("believer");
    let rx = me("frames {capture}");
    let (code, out) = replay(&["run", "--corpus-dir", &dir, "--receiver", &rx]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("FAIL: 12 of 12 spoofed transmitters accepted as real"),
        "{out}"
    );
    let (code, out) = replay(&[
        "run",
        "--corpus-dir",
        &dir,
        "--receiver",
        &rx,
        "--link",
        "wifi",
    ]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("FAIL: 10 of 10 spoofed transmitters accepted as real"),
        "{out}"
    );
    let (_, json) = replay(&["run", "--corpus-dir", &dir, "--receiver", &rx, "--json"]);
    assert!(
        json.contains("\"pass\":false") && json.contains("\"spoofed_accepted\":12"),
        "{json}"
    );
}

#[test]
fn receiver_that_shows_nothing_fails() {
    let dir = corpus_dir("silent");
    let rx = me("--version");
    let (code, out) = replay(&["run", "--corpus-dir", &dir, "--receiver", &rx]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("proves nothing"), "{out}");
}

#[test]
fn saved_reports_and_extra_captures() {
    let dir = corpus_dir("saved");
    let reports = std::path::Path::new(&dir).join("reports.jsonl");
    std::fs::create_dir_all(&dir).unwrap();
    // One spoofed transmitter flagged, the rest never reported.
    std::fs::write(
        &reports,
        "{\"capture\":\"spoof/cdc_wifi_slow_forward.pcap\",\"mac\":\"76:67:6e:af:99:6e\",\"spoofed\":true}\n\
         {\"capture\":\"legit/odid_wifi_bcn_sample.pcap\",\"uas_id\":\"MFG1A0123456789\"}\n\
         not json\n",
    )
    .unwrap();
    let r = reports.display().to_string();
    let (code, out) = replay(&["score", "--corpus-dir", &dir, "--reports", &r]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("spoofed: 12 replayed, 1 flagged, 0 ACCEPTED AS REAL, 11 not shown"),
        "{out}"
    );
    let (code, _) = replay(&[
        "score",
        "--corpus-dir",
        &dir,
        "--reports",
        &r,
        "--fail-on-missed",
    ]);
    assert_eq!(code, 1);
    // A user capture of a spoofer joins the corpus.
    let extra = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/spoof/cdc_wifi_random3.pcap")
        .display()
        .to_string();
    let (code, out) = replay(&["run", "--corpus-dir", &dir, "--spoofed", &extra]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("spoofed: 15 replayed, 15 flagged"), "{out}");
}

#[test]
fn ridf_export_replays_the_same() {
    let dir = corpus_dir("ridf");
    std::fs::create_dir_all(&dir).unwrap();
    let cap = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/spoof/cdc_wifi_random3.pcap")
        .display()
        .to_string();
    let ridf = std::path::Path::new(&dir)
        .join("random3.ridf")
        .display()
        .to_string();
    assert_eq!(replay(&["frames", "--ridf", &ridf, &cap]).0, 0);
    let (_, a) = replay(&["verdicts", &cap]);
    let (_, b) = replay(&["verdicts", &ridf]);
    let strip = |s: &str| -> Vec<String> {
        s.lines()
            .map(|l| l[l.find("\"addr\"").unwrap()..].to_string())
            .collect()
    };
    assert_eq!(strip(&a), strip(&b));
    assert_eq!(strip(&a).len(), 3);
}

#[test]
fn usage_errors() {
    assert_eq!(replay(&["nope"]).0, 2);
    assert_eq!(replay(&["run", "--link", "lora"]).0, 2);
    assert_eq!(replay(&["verdicts"]).0, 2);
    assert_eq!(replay(&["help"]).0, 0);
}
