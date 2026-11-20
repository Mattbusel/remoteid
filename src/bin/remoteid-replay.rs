//! `remoteid-replay`: replay spoofed and real Remote ID captures through a
//! receiver and fail when it believes the spoofers.
//!
//! ```text
//! remoteid-replay run --receiver "python my_receiver.py --pcap {capture}"
//! ```
//!
//! Run `remoteid-replay help` for every command.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use remoteid::capture::{self, CapturedFrame};
use remoteid::replay::{self, CaptureScore, Gate, Outcome, Report, Totals, Truth};
use remoteid::{TrackerConfig, Transmitter, TrustConfig};

/// One bundled capture.
struct Bundled {
    file: &'static str,
    bytes: &'static [u8],
    truth: Truth,
    link: &'static str,
    source: &'static str,
}

macro_rules! data {
    ($f:literal) => {
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/", $f))
    };
}

const CDC: &str = "cyber-defence-campus/droneRemoteIDSpoofer @61fa634, frames built by the tool's own code (tools/spoof-corpus)";
const JJ: &str =
    "jjshoots/RemoteIDSpoofer @c79ab77, ESP8266 sketch built for the host (tools/spoof-corpus)";
const ODID: &str =
    "opendroneid/wireshark-dissector sample capture of a real transmitter (Apache-2.0)";

const CORPUS: &[Bundled] = &[
    Bundled {
        file: "spoof/cdc_wifi_random3.pcap",
        bytes: data!("spoof/cdc_wifi_random3.pcap"),
        truth: Truth::Spoofed,
        link: "wifi",
        source: CDC,
    },
    Bundled {
        file: "spoof/cdc_wifi_same_mac.pcap",
        bytes: data!("spoof/cdc_wifi_same_mac.pcap"),
        truth: Truth::Spoofed,
        link: "wifi",
        source: CDC,
    },
    Bundled {
        file: "spoof/cdc_wifi_slow_forward.pcap",
        bytes: data!("spoof/cdc_wifi_slow_forward.pcap"),
        truth: Truth::Spoofed,
        link: "wifi",
        source: CDC,
    },
    Bundled {
        file: "spoof/jjshoots_esp8266_beacon_1drone.pcap",
        bytes: data!("spoof/jjshoots_esp8266_beacon_1drone.pcap"),
        truth: Truth::Spoofed,
        link: "wifi",
        source: JJ,
    },
    Bundled {
        file: "spoof/jjshoots_esp8266_beacon_4drones.pcap",
        bytes: data!("spoof/jjshoots_esp8266_beacon_4drones.pcap"),
        truth: Truth::Spoofed,
        link: "wifi",
        source: JJ,
    },
    Bundled {
        file: "spoof/cdc_ble_legacy_random2.pcap",
        bytes: data!("spoof/cdc_ble_legacy_random2.pcap"),
        truth: Truth::Spoofed,
        link: "ble",
        source: CDC,
    },
    Bundled {
        file: "legit/odid_wifi_bcn_sample.pcap",
        bytes: data!("odid_wifi_bcn_sample.pcap"),
        truth: Truth::Legitimate,
        link: "wifi",
        source: ODID,
    },
    Bundled {
        file: "legit/odid_wifi_sample.pcap",
        bytes: data!("odid_wifi_sample.pcap"),
        truth: Truth::Legitimate,
        link: "wifi",
        source: ODID,
    },
    Bundled {
        file: "legit/odid_bt5_lr_sample.pcapng",
        bytes: data!("odid_bt5_lr_sample.pcapng"),
        truth: Truth::Legitimate,
        link: "ble",
        source: ODID,
    },
];

const ODID_LICENSE: &[u8] = data!("LICENSE-APACHE-opendroneid");

const HELP: &str = "\
remoteid-replay: does your Remote ID receiver believe spoofers?

Replays captures of two public spoofing tools (12 fake transmitters) and of
real transmitters through a receiver, and fails when a spoofed transmitter
is shown as real.

USAGE
  remoteid-replay run [--receiver CMD] [OPTIONS]
      Replay every capture through CMD and score it. CMD runs once per
      capture with {capture} replaced by the capture's path (appended when
      absent) and prints one JSON object per transmitter or detection:
        {\"mac\": \"aa:bb:cc:dd:ee:ff\", \"uas_id\": \"...\", \"verdict\": \"spoofed\"}
      Address keys: addr, address, mac, sender_id, src. ID keys: id, uas_id,
      basic_id, serial, serial_number, drone_id, uav_id. Verdict keys:
      verdict, trust, status (text) or spoofed, suspicious, flagged (bool).
      A line with no verdict counts as accepted: that is what a receiver
      without spoof checks puts on its map. Other output lines are ignored.
      Without --receiver, remoteid itself is the receiver.
  remoteid-replay score --reports FILE [OPTIONS]
      Score saved receiver output; every line names its \"capture\".
  remoteid-replay verdicts [--no-utc] [--no-fingerprints] CAPTURE...
      remoteid's own verdicts for pcap, pcapng or RIDF files, as JSON lines.
  remoteid-replay frames [--ridf OUT] CAPTURE...
      The Remote ID frames of the captures as JSON lines (hex payloads),
      or as one RIDF file, for receivers that do not read pcap.
  remoteid-replay corpus DIR
      Write the bundled captures and manifest.json to DIR.

OPTIONS (run, score)
  --link wifi|ble|all      captures to replay (default all)
  --spoofed FILE           add your own capture of a spoofer (repeatable)
  --legit FILE             add your own capture of real aircraft (repeatable)
  --corpus-dir DIR         where the captures are written (default: a temp dir)
  --format text|markdown|json   (default text)
  --details                list every transmitter
  --allow-false-alarms     do not fail when a real transmitter is flagged
  --fail-on-missed         fail when a transmitter is not shown at all
  --fail-on-phantom        fail when the receiver reports a transmitter that is not there
  --no-utc, --no-fingerprints   settings of the built-in receiver

EXIT STATUS
  0 the receiver flagged every spoofed transmitter it showed, 1 it accepted
  at least one (or another enabled check failed), 2 usage or I/O error.
";

#[derive(Default)]
struct Opts {
    receiver: Option<String>,
    reports: Option<PathBuf>,
    link: Option<String>,
    extra: Vec<(PathBuf, Truth)>,
    corpus_dir: Option<PathBuf>,
    format: String,
    details: bool,
    gate: Gate,
    utc: bool,
    fingerprints: bool,
    ridf: Option<PathBuf>,
    files: Vec<PathBuf>,
}

fn parse_opts(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        format: "text".into(),
        utc: true,
        fingerprints: true,
        ..Opts::default()
    };
    let mut i = 0;
    let val = |i: &mut usize, name: &str| -> Result<String, String> {
        *i += 1;
        args.get(*i).cloned().ok_or(format!("{name} needs a value"))
    };
    while i < args.len() {
        let a = args[i].as_str();
        match a {
            "--receiver" => o.receiver = Some(val(&mut i, a)?),
            "--reports" => o.reports = Some(val(&mut i, a)?.into()),
            "--link" => o.link = Some(val(&mut i, a)?),
            "--spoofed" => o.extra.push((val(&mut i, a)?.into(), Truth::Spoofed)),
            "--legit" => o.extra.push((val(&mut i, a)?.into(), Truth::Legitimate)),
            "--corpus-dir" => o.corpus_dir = Some(val(&mut i, a)?.into()),
            "--format" => o.format = val(&mut i, a)?,
            "--markdown" => o.format = "markdown".into(),
            "--json" => o.format = "json".into(),
            "--details" => o.details = true,
            "--allow-false-alarms" => o.gate.fail_on_false_alarm = false,
            "--fail-on-missed" => o.gate.fail_on_missed = true,
            "--fail-on-phantom" => o.gate.fail_on_phantom = true,
            "--no-utc" => o.utc = false,
            "--no-fingerprints" => o.fingerprints = false,
            "--ridf" => o.ridf = Some(val(&mut i, a)?.into()),
            _ if a.starts_with("--") => return Err(format!("unknown option {a}")),
            _ => o.files.push(a.into()),
        }
        i += 1;
    }
    if !matches!(o.format.as_str(), "text" | "markdown" | "json") {
        return Err(format!("unknown format {}", o.format));
    }
    if let Some(l) = &o.link {
        if !matches!(l.as_str(), "wifi" | "ble" | "all") {
            return Err(format!("unknown link {l}"));
        }
    }
    Ok(o)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first() else {
        print!("{HELP}");
        return ExitCode::from(2);
    };
    if matches!(cmd.as_str(), "help" | "-h" | "--help") {
        print!("{HELP}");
        return ExitCode::SUCCESS;
    }
    if matches!(cmd.as_str(), "-V" | "--version" | "version") {
        println!("remoteid-replay {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let opts = match parse_opts(&args[1..]) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("remoteid-replay: {e}");
            return ExitCode::from(2);
        }
    };
    let r = match cmd.as_str() {
        "run" => run(&opts),
        "score" => run(&opts),
        "verdicts" => verdicts(&opts).map(|_| true),
        "frames" => frames_cmd(&opts).map(|_| true),
        "corpus" => match opts.files.first() {
            Some(d) => write_corpus(d).map(|_| true),
            None => Err("corpus needs a directory".into()),
        },
        _ => Err(format!("unknown command {cmd}; try remoteid-replay help")),
    };
    match r {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("remoteid-replay: {e}");
            ExitCode::from(2)
        }
    }
}

fn read_frames(path: &Path) -> Result<Vec<CapturedFrame>, String> {
    let b = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    capture::frames(&b).map_err(|e| format!("{}: {e}", path.display()))
}

fn addr_text(t: &Transmitter) -> String {
    match t {
        Transmitter::Wifi(a) => replay::address_text(a),
        Transmitter::Ble(a) => {
            let mut r = *a;
            r.reverse();
            replay::address_text(&r)
        }
        Transmitter::Other(n) => format!("other:{n}"),
    }
}

fn kind(t: &Transmitter) -> &'static str {
    match t {
        Transmitter::Wifi(_) => "wifi",
        Transmitter::Ble(_) => "ble",
        Transmitter::Other(_) => "other",
    }
}

fn js(s: &str) -> String {
    replay::json_string(s)
}

fn verdicts(o: &Opts) -> Result<(), String> {
    if o.files.is_empty() {
        return Err("verdicts needs at least one capture".into());
    }
    let out = std::io::stdout();
    let mut out = out.lock();
    for f in &o.files {
        for line in builtin_lines(f, o)? {
            writeln!(out, "{line}").map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// remoteid as the receiver: one JSON line per transmitter.
fn builtin_lines(path: &Path, o: &Opts) -> Result<Vec<String>, String> {
    let frames = read_frames(path)?;
    let mut trust = TrustConfig::default();
    trust.fingerprints = o.fingerprints;
    let config = TrackerConfig {
        trust,
        ..TrackerConfig::default()
    };
    let tracker = capture::track(&frames, config, o.utc);
    let mut all: Vec<_> = tracker.iter().collect();
    all.sort_by_key(|(tx, _)| **tx);
    Ok(all
        .into_iter()
        .map(|(tx, uas)| {
            let a = &uas.assessment;
            let reasons: Vec<String> = a.reasons.iter().map(|r| js(r.name())).collect();
            format!(
                "{{\"capture\":{},\"addr\":{},\"link\":\"{}\",\"uas_id\":{},\"verdict\":\"{}\",\"score\":{:.3},\"frames\":{},\"spoofer\":{},\"reasons\":[{}]}}",
                js(&path.display().to_string()),
                js(&addr_text(tx)),
                kind(tx),
                uas.data.primary_id().map(js).unwrap_or_else(|| "null".into()),
                a.verdict,
                a.score,
                uas.stats.received,
                a.spoofer.map(|s| js(s.name())).unwrap_or_else(|| "null".into()),
                reasons.join(",")
            )
        })
        .collect())
}

fn frames_cmd(o: &Opts) -> Result<(), String> {
    if o.files.is_empty() {
        return Err("frames needs at least one capture".into());
    }
    if let Some(out) = &o.ridf {
        let mut all = Vec::new();
        for f in &o.files {
            all.extend(read_frames(f)?);
        }
        let b = capture::to_ridf(&all).map_err(|e| e.to_string())?;
        return std::fs::write(out, b).map_err(|e| format!("{}: {e}", out.display()));
    }
    let out = std::io::stdout();
    let mut out = out.lock();
    for f in &o.files {
        for fr in read_frames(f)? {
            let hex: String = fr.payload.iter().map(|b| format!("{b:02x}")).collect();
            writeln!(
                out,
                "{{\"capture\":{},\"time_us\":{},\"addr\":{},\"link\":\"{}\",\"transport\":\"{}\",\"counter\":{},\"payload_hex\":\"{hex}\"}}",
                js(&f.display().to_string()),
                fr.time_us,
                js(&addr_text(&fr.transmitter)),
                kind(&fr.transmitter),
                fr.transport,
                fr.counter.map(|c| c.to_string()).unwrap_or_else(|| "null".into()),
            )
            .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn write_corpus(dir: &Path) -> Result<(), String> {
    let io = |e: std::io::Error| format!("{}: {e}", dir.display());
    std::fs::create_dir_all(dir.join("spoof")).map_err(io)?;
    std::fs::create_dir_all(dir.join("legit")).map_err(io)?;
    let mut caps = Vec::new();
    for c in CORPUS {
        std::fs::write(dir.join(c.file), c.bytes).map_err(io)?;
        let frames = capture::frames(c.bytes).map_err(|e| e.to_string())?;
        let tx: Vec<String> = replay::expected(&frames, c.truth)
            .iter()
            .map(|e| {
                let ids: Vec<String> = e.ids.iter().map(|i| js(i)).collect();
                format!(
                    "{{\"address\":{},\"kind\":\"{}\",\"ids\":[{}]}}",
                    js(&addr_text(&e.transmitter)),
                    kind(&e.transmitter),
                    ids.join(",")
                )
            })
            .collect();
        caps.push(format!(
            "    {{\"file\":{},\"truth\":\"{}\",\"link\":\"{}\",\"source\":{},\"transmitters\":[{}]}}",
            js(c.file),
            c.truth.name(),
            c.link,
            js(c.source),
            tx.join(",")
        ));
    }
    let manifest = format!(
        "{{\n  \"generator\": \"remoteid-replay {}\",\n  \"captures\": [\n{}\n  ]\n}}\n",
        env!("CARGO_PKG_VERSION"),
        caps.join(",\n")
    );
    std::fs::write(dir.join("manifest.json"), manifest).map_err(io)?;
    std::fs::write(dir.join("legit/LICENSE-APACHE-opendroneid"), ODID_LICENSE).map_err(io)?;
    Ok(())
}

/// A capture to replay: display name, path on disk, truth, link.
struct Case {
    name: String,
    path: PathBuf,
    truth: Truth,
}

fn cases(o: &Opts) -> Result<Vec<Case>, String> {
    let link = o.link.as_deref().unwrap_or("all");
    let mut out = Vec::new();
    let dir = match &o.corpus_dir {
        Some(d) => d.clone(),
        None => std::env::temp_dir().join(format!("remoteid-replay-{}", env!("CARGO_PKG_VERSION"))),
    };
    write_corpus(&dir)?;
    for c in CORPUS {
        if link == "all" || link == c.link {
            out.push(Case {
                name: c.file.to_string(),
                path: dir.join(c.file),
                truth: c.truth,
            });
        }
    }
    for (p, t) in &o.extra {
        let p = std::fs::canonicalize(p).map_err(|e| format!("{}: {e}", p.display()))?;
        out.push(Case {
            name: p.display().to_string(),
            path: p,
            truth: *t,
        });
    }
    Ok(out)
}

fn quote(p: &Path) -> String {
    let s = p.display().to_string();
    if cfg!(windows) {
        format!("\"{s}\"")
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

#[cfg(windows)]
fn shell(line: &str) -> Command {
    use std::os::windows::process::CommandExt;
    // cmd.exe strips one pair of outer quotes from what follows /C, so the
    // whole line goes in one more pair, unescaped.
    let mut c = Command::new("cmd");
    c.arg("/D")
        .arg("/S")
        .arg("/C")
        .raw_arg(format!("\"{line}\""));
    c
}

#[cfg(not(windows))]
fn shell(line: &str) -> Command {
    let mut c = Command::new("sh");
    c.arg("-c").arg(line);
    c
}

/// The receiver's stdout lines, and how it ended when it did not exit 0
/// (a crash is a result, not a usage error: it fails the replay).
fn run_receiver(cmd: &str, path: &Path) -> Result<(Vec<String>, Option<String>), String> {
    let q = quote(path);
    let line = if cmd.contains("{capture}") {
        cmd.replace("{capture}", &q)
    } else {
        format!("{cmd} {q}")
    };
    let mut c = shell(&line);
    let child = c
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("cannot start receiver: {e}"))?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let lines = out.stdout.lines().map_while(Result::ok).collect();
    let died = (!out.status.success()).then(|| out.status.to_string());
    Ok((lines, died))
}

fn run(o: &Opts) -> Result<bool, String> {
    let cases = cases(o)?;
    let saved: Option<Vec<Report>> = match &o.reports {
        Some(p) => {
            let f = std::fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
            Some(
                std::io::BufReader::new(f)
                    .lines()
                    .map_while(Result::ok)
                    .filter_map(|l| Report::parse(&l))
                    .collect(),
            )
        }
        None => None,
    };
    let mut scores = Vec::new();
    let mut crashes: Vec<String> = Vec::new();
    for c in &cases {
        let frames = read_frames(&c.path)?;
        let expected = replay::expected(&frames, c.truth);
        let reports: Vec<Report> = match (&saved, &o.receiver) {
            (Some(all), _) => all
                .iter()
                .filter(|r| {
                    r.capture.as_deref().is_some_and(|n| {
                        let n = n.replace('\\', "/");
                        n == c.name || n.ends_with(&format!("/{}", c.name)) || {
                            let base = c.name.rsplit('/').next().unwrap_or(&c.name);
                            n.rsplit('/').next() == Some(base)
                        }
                    })
                })
                .cloned()
                .collect(),
            (None, Some(cmd)) => {
                let (lines, died) = run_receiver(cmd, &c.path)?;
                if let Some(how) = died {
                    crashes.push(format!("the receiver failed on {} ({how})", c.name));
                }
                lines.iter().filter_map(|l| Report::parse(l)).collect()
            }
            (None, None) => builtin_lines(&c.path, o)?
                .iter()
                .filter_map(|l| Report::parse(l))
                .collect(),
        };
        scores.push(replay::score(&c.name, c.truth, &expected, &reports));
    }
    let totals = Totals::of(&scores);
    let mut failures = o.gate.failures(&totals);
    failures.extend(crashes);
    let receiver = match (&o.reports, &o.receiver) {
        (Some(p), _) => p.display().to_string(),
        (None, Some(c)) => c.clone(),
        (None, None) => format!("remoteid {} (built in)", env!("CARGO_PKG_VERSION")),
    };
    let text = match o.format.as_str() {
        "json" => json_report(&receiver, &scores, &totals, &failures),
        "markdown" => markdown_report(&receiver, &scores, &totals, &failures, o.details),
        _ => text_report(&receiver, &scores, &totals, &failures, o.details),
    };
    print!("{text}");
    Ok(failures.is_empty())
}

fn row_counts(s: &CaptureScore) -> (usize, usize, usize, usize, usize) {
    (
        s.judged.len(),
        s.count(Outcome::Flagged),
        s.count(Outcome::Accepted),
        s.count(Outcome::Missed),
        s.phantoms.len(),
    )
}

fn summary(t: &Totals) -> String {
    format!(
        "spoofed: {} replayed, {} flagged, {} ACCEPTED AS REAL, {} not shown | real: {} replayed, {} accepted, {} flagged, {} not shown | phantoms: {}",
        t.spoofed,
        t.spoofed_flagged,
        t.spoofed_accepted,
        t.spoofed_missed,
        t.legit,
        t.legit_accepted,
        t.legit_flagged,
        t.legit_missed,
        t.phantoms
    )
}

fn text_report(
    rx: &str,
    scores: &[CaptureScore],
    t: &Totals,
    fail: &[String],
    details: bool,
) -> String {
    let mut s = format!("receiver: {rx}\n\n");
    s += &format!(
        "{:<44} {:<10} {:>3} {:>8} {:>8} {:>7} {:>8}\n",
        "capture", "truth", "tx", "flagged", "accepted", "missed", "phantoms"
    );
    for c in scores {
        let (n, f, a, m, p) = row_counts(c);
        s += &format!(
            "{:<44} {:<10} {n:>3} {f:>8} {a:>8} {m:>7} {p:>8}\n",
            c.capture,
            c.truth.name()
        );
        if details {
            for j in &c.judged {
                s += &format!(
                    "    {} {:<9} ids={:?} verdicts={:?}\n",
                    addr_text(&j.expected.transmitter),
                    j.outcome.name(),
                    j.expected.ids,
                    j.verdicts
                );
            }
            for p in &c.phantoms {
                s += &format!(
                    "    phantom addr={:?} id={:?} verdict={:?}\n",
                    p.address.map(|a| replay::address_text(&a)),
                    p.id,
                    p.verdict
                );
            }
        }
    }
    s += &format!("\n{}\n", summary(t));
    if fail.is_empty() {
        s += "PASS: every spoofed transmitter the receiver showed was flagged\n";
    } else {
        for f in fail {
            s += &format!("FAIL: {f}\n");
        }
    }
    s
}

fn markdown_report(
    rx: &str,
    scores: &[CaptureScore],
    t: &Totals,
    fail: &[String],
    details: bool,
) -> String {
    let mut s = format!("### Remote ID spoof replay: `{rx}`\n\n");
    s += "| Capture | Truth | Transmitters | Flagged | Accepted as real | Not shown | Phantoms |\n|---|---|---|---|---|---|---|\n";
    for c in scores {
        let (n, f, a, m, p) = row_counts(c);
        s += &format!(
            "| `{}` | {} | {n} | {f} | {a} | {m} | {p} |\n",
            c.capture,
            c.truth.name()
        );
    }
    if details {
        s += "\n| Capture | Transmitter | UAS IDs | Outcome | Receiver said |\n|---|---|---|---|---|\n";
        for c in scores {
            for j in &c.judged {
                s += &format!(
                    "| `{}` | `{}` | {} | {} | {} |\n",
                    c.capture,
                    addr_text(&j.expected.transmitter),
                    j.expected.ids.join(", "),
                    j.outcome.name(),
                    j.verdicts.join(", ")
                );
            }
        }
    }
    s += &format!("\n{}\n\n", summary(t));
    if fail.is_empty() {
        s += "**PASS**: every spoofed transmitter the receiver showed was flagged.\n";
    } else {
        for f in fail {
            s += &format!("**FAIL**: {f}\n\n");
        }
    }
    s
}

fn json_report(rx: &str, scores: &[CaptureScore], t: &Totals, fail: &[String]) -> String {
    let caps: Vec<String> = scores
        .iter()
        .map(|c| {
            let (n, f, a, m, p) = row_counts(c);
            let tx: Vec<String> = c
                .judged
                .iter()
                .map(|j| {
                    let ids: Vec<String> = j.expected.ids.iter().map(|i| js(i)).collect();
                    let vs: Vec<String> = j.verdicts.iter().map(|v| js(v)).collect();
                    format!(
                        "{{\"address\":{},\"ids\":[{}],\"outcome\":\"{}\",\"verdicts\":[{}]}}",
                        js(&addr_text(&j.expected.transmitter)),
                        ids.join(","),
                        j.outcome.name(),
                        vs.join(",")
                    )
                })
                .collect();
            format!(
                "{{\"capture\":{},\"truth\":\"{}\",\"transmitters\":{n},\"flagged\":{f},\"accepted\":{a},\"missed\":{m},\"phantoms\":{p},\"detail\":[{}]}}",
                js(&c.capture),
                c.truth.name(),
                tx.join(",")
            )
        })
        .collect();
    let fails: Vec<String> = fail.iter().map(|f| js(f)).collect();
    format!(
        "{{\"receiver\":{},\"pass\":{},\"failures\":[{}],\"totals\":{{\"spoofed\":{},\"spoofed_flagged\":{},\"spoofed_accepted\":{},\"spoofed_missed\":{},\"legit\":{},\"legit_accepted\":{},\"legit_flagged\":{},\"legit_missed\":{},\"phantoms\":{}}},\"captures\":[{}]}}\n",
        js(rx),
        fail.is_empty(),
        fails.join(","),
        t.spoofed,
        t.spoofed_flagged,
        t.spoofed_accepted,
        t.spoofed_missed,
        t.legit,
        t.legit_accepted,
        t.legit_flagged,
        t.legit_missed,
        t.phantoms,
        caps.join(",")
    )
}
