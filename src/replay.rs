//! Scoring a Remote ID receiver against captures with known truth.
//!
//! A receiver that decodes a spoofed broadcast and shows it with no warning
//! has believed it. This module turns that into a number and a gate:
//!
//! 1. [`expected`] lists the transmitters of a capture (address and every
//!    UAS ID heard), each labelled [`Truth::Spoofed`] or
//!    [`Truth::Legitimate`].
//! 2. The receiver under test reads the same capture and prints one JSON
//!    object per transmitter it shows (or per detection; they are merged),
//!    see [`Report::parse`].
//! 3. [`score`] matches reports to transmitters by address, then by UAS
//!    ID, and counts what the receiver flagged, what it accepted, what it
//!    missed and what it invented.
//! 4. [`Gate`] fails the run when a spoofed transmitter was accepted.
//!
//! **No verdict means accepted.** A report without a verdict field is
//! what a receiver with no spoof checks puts on its map, so it counts as
//! believing the broadcast. Verdict fields read: `verdict`, `trust`,
//! `status` (strings such as `spoofed`, `suspicious`, `plausible`) and
//! `spoofed`, `suspicious`, `flagged` (booleans).

use std::string::String;
use std::vec::Vec;

use crate::capture::CapturedFrame;
use crate::{Frame, Message, Transmitter};

/// What a capture's transmitters really are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Truth {
    /// Made by a spoofing tool.
    Spoofed,
    /// Recorded from a real Remote ID transmitter.
    Legitimate,
}

impl Truth {
    /// Lower case name.
    pub fn name(self) -> &'static str {
        match self {
            Truth::Spoofed => "spoofed",
            Truth::Legitimate => "legitimate",
        }
    }
}

/// One transmitter a receiver should have seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    /// The radio address.
    pub transmitter: Transmitter,
    /// Every UAS ID it broadcast (Basic ID), in the order first heard.
    pub ids: Vec<String>,
    /// What it really is.
    pub truth: Truth,
}

/// The transmitters of a capture, all labelled `truth`, with every UAS ID
/// each one broadcast (a transmitter that changes its Basic ID keeps all
/// of them, so a receiver keyed by UAS ID still matches).
pub fn expected(frames: &[CapturedFrame], truth: Truth) -> Vec<Expected> {
    let mut out: Vec<Expected> = Vec::new();
    for f in frames {
        let i = match out.iter().position(|e| e.transmitter == f.transmitter) {
            Some(i) => i,
            None => {
                out.push(Expected {
                    transmitter: f.transmitter,
                    ids: Vec::new(),
                    truth,
                });
                out.len() - 1
            }
        };
        if let Ok(frame) = Frame::decode(&f.payload) {
            frame.for_each_message(|m| {
                if let Message::BasicId(b) = m {
                    if let Some(id) = b.uas_id_str() {
                        let id = id.trim().to_string();
                        if !id.is_empty() && !out[i].ids.contains(&id) {
                            out[i].ids.push(id);
                        }
                    }
                }
            });
        }
    }
    out.sort_by_key(|e| e.transmitter);
    out
}

/// A JSON value, as far as reports need one.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// A string.
    Str(String),
    /// A number.
    Num(f64),
    /// `true` or `false`.
    Bool(bool),
    /// `null`.
    Null,
    /// An array or object (contents not kept).
    Nested,
}

/// Parses one flat JSON object into its top level fields. Nested arrays and
/// objects are skipped (as [`Json::Nested`]). Returns `None` for anything
/// that is not a single JSON object.
pub fn parse_object(s: &str) -> Option<Vec<(String, Json)>> {
    let mut p = JsonParser {
        b: s.as_bytes(),
        i: 0,
    };
    p.ws();
    if p.peek()? != b'{' {
        return None;
    }
    p.i += 1;
    let mut out = Vec::new();
    p.ws();
    if p.peek()? == b'}' {
        p.i += 1;
    } else {
        loop {
            p.ws();
            let k = p.string()?;
            p.ws();
            if p.next()? != b':' {
                return None;
            }
            p.ws();
            let v = p.value(0)?;
            out.push((k, v));
            p.ws();
            match p.next()? {
                b',' => continue,
                b'}' => break,
                _ => return None,
            }
        }
    }
    p.ws();
    if p.i == p.b.len() {
        Some(out)
    } else {
        None
    }
}

struct JsonParser<'a> {
    b: &'a [u8],
    i: usize,
}

impl JsonParser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn next(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.i += 1;
        Some(c)
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.i += 1;
        }
    }
    fn hex4(&mut self) -> Option<u32> {
        let h = self.b.get(self.i..self.i + 4)?;
        self.i += 4;
        u32::from_str_radix(core::str::from_utf8(h).ok()?, 16).ok()
    }
    fn string(&mut self) -> Option<String> {
        if self.next()? != b'"' {
            return None;
        }
        let mut out: Vec<u8> = Vec::new();
        loop {
            match self.next()? {
                b'"' => return String::from_utf8(out).ok(),
                b'\\' => {
                    let c = match self.next()? {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if self.next()? != b'\\' || self.next()? != b'u' {
                                    return None;
                                }
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return None;
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            char::from_u32(cp).unwrap_or('\u{FFFD}')
                        }
                        _ => return None,
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
                c => out.push(c),
            }
        }
    }
    fn literal(&mut self, word: &[u8]) -> Option<()> {
        if self.b.get(self.i..self.i + word.len())? == word {
            self.i += word.len();
            Some(())
        } else {
            None
        }
    }
    fn value(&mut self, depth: usize) -> Option<Json> {
        if depth > 64 {
            return None;
        }
        match self.peek()? {
            b'"' => self.string().map(Json::Str),
            b't' => self.literal(b"true").map(|_| Json::Bool(true)),
            b'f' => self.literal(b"false").map(|_| Json::Bool(false)),
            b'n' => self.literal(b"null").map(|_| Json::Null),
            b'{' | b'[' => {
                let close = if self.next()? == b'{' { b'}' } else { b']' };
                let is_obj = close == b'}';
                self.ws();
                if self.peek()? == close {
                    self.i += 1;
                    return Some(Json::Nested);
                }
                loop {
                    self.ws();
                    if is_obj {
                        self.string()?;
                        self.ws();
                        if self.next()? != b':' {
                            return None;
                        }
                        self.ws();
                    }
                    self.value(depth + 1)?;
                    self.ws();
                    match self.next()? {
                        b',' => continue,
                        c if c == close => return Some(Json::Nested),
                        _ => return None,
                    }
                }
            }
            _ => {
                let start = self.i;
                while matches!(
                    self.peek(),
                    Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
                ) {
                    self.i += 1;
                }
                let t = core::str::from_utf8(&self.b[start..self.i]).ok()?;
                t.parse::<f64>().ok().map(Json::Num)
            }
        }
    }
}

/// Writes `s` as a JSON string literal.
pub fn json_string(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&std::format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// Parses a MAC or Bluetooth address: six hex bytes, separated by `:` or
/// `-` or not at all.
pub fn parse_address(s: &str) -> Option<[u8; 6]> {
    let hex: Vec<u8> = s
        .bytes()
        .filter(|c| !matches!(c, b':' | b'-' | b'.' | b' '))
        .collect();
    if hex.len() != 12 {
        return None;
    }
    let mut out = [0u8; 6];
    for (i, o) in out.iter_mut().enumerate() {
        let t = core::str::from_utf8(&hex[2 * i..2 * i + 2]).ok()?;
        *o = u8::from_str_radix(t, 16).ok()?;
    }
    Some(out)
}

/// Text form of an address, `aa:bb:cc:dd:ee:ff`.
pub fn address_text(a: &[u8; 6]) -> String {
    std::format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        a[0],
        a[1],
        a[2],
        a[3],
        a[4],
        a[5]
    )
}

/// The address of a transmitter, when it has one.
pub fn transmitter_address(t: &Transmitter) -> Option<[u8; 6]> {
    match t {
        Transmitter::Ble(a) | Transmitter::Wifi(a) => Some(*a),
        Transmitter::Other(_) => None,
    }
}

/// What a receiver said about one transmitter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The capture the report is about, when the line names one.
    pub capture: Option<String>,
    /// Radio address, when the receiver shows it.
    pub address: Option<[u8; 6]>,
    /// UAS ID, when the receiver shows it.
    pub id: Option<String>,
    /// The receiver warned about this transmitter.
    pub flagged: bool,
    /// The verdict text as given (empty when the receiver gave none).
    pub verdict: String,
}

const ADDRESS_KEYS: &[&str] = &[
    "addr",
    "address",
    "mac",
    "sender_id",
    "src",
    "source_address",
];
const ID_KEYS: &[&str] = &[
    "id",
    "uas_id",
    "basic_id",
    "serial",
    "serial_number",
    "drone_id",
    "uav_id",
];
const FLAG_WORDS: &[&str] = &[
    "spoofed",
    "spoof",
    "suspicious",
    "flagged",
    "fake",
    "alert",
    "rejected",
    "reject",
    "untrusted",
];

impl Report {
    /// Reads one line of receiver output. Lines that are not a JSON object
    /// (log lines, banners) give `None` and are ignored by the scorer.
    pub fn parse(line: &str) -> Option<Report> {
        let fields = parse_object(line.trim())?;
        let get = |keys: &[&str]| {
            keys.iter().find_map(|k| {
                fields.iter().find_map(|(fk, v)| match v {
                    Json::Str(s) if fk.eq_ignore_ascii_case(k) && !s.trim().is_empty() => {
                        Some(s.trim().to_string())
                    }
                    _ => None,
                })
            })
        };
        let capture = get(&["capture"]);
        let address = get(ADDRESS_KEYS).and_then(|a| parse_address(&a));
        let id = get(ID_KEYS);
        let mut verdict = get(&["verdict", "trust", "status"]).unwrap_or_default();
        let mut flagged = FLAG_WORDS
            .iter()
            .any(|w| verdict.to_ascii_lowercase().contains(w));
        for k in ["spoofed", "suspicious", "flagged"] {
            if let Some((_, Json::Bool(b))) = fields.iter().find(|(fk, _)| fk == k) {
                if verdict.is_empty() {
                    verdict = std::format!("{k}={b}");
                }
                flagged |= *b;
            }
        }
        Some(Report {
            capture,
            address,
            id,
            flagged,
            verdict,
        })
    }
}

/// How the receiver handled one expected transmitter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// Shown with a warning.
    Flagged,
    /// Shown with no warning.
    Accepted,
    /// Not shown at all.
    Missed,
}

impl Outcome {
    /// Lower case name.
    pub fn name(self) -> &'static str {
        match self {
            Outcome::Flagged => "flagged",
            Outcome::Accepted => "accepted",
            Outcome::Missed => "missed",
        }
    }
}

/// One expected transmitter and what the receiver did with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judged {
    /// The transmitter.
    pub expected: Expected,
    /// What the receiver did.
    pub outcome: Outcome,
    /// The verdicts the receiver gave it (deduplicated).
    pub verdicts: Vec<String>,
}

/// The score of one capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureScore {
    /// Capture name.
    pub capture: String,
    /// What its transmitters really are.
    pub truth: Truth,
    /// Every expected transmitter with its outcome.
    pub judged: Vec<Judged>,
    /// Reports that match no transmitter of the capture: drones the
    /// receiver invented (or could not attribute).
    pub phantoms: Vec<Report>,
}

impl CaptureScore {
    /// Number of transmitters with this outcome.
    pub fn count(&self, o: Outcome) -> usize {
        self.judged.iter().filter(|j| j.outcome == o).count()
    }
}

fn norm_id(s: &str) -> String {
    s.trim().trim_matches('\0').to_ascii_uppercase()
}

/// Matches a receiver's reports for one capture against its transmitters.
pub fn score(
    capture: &str,
    truth: Truth,
    expected: &[Expected],
    reports: &[Report],
) -> CaptureScore {
    let mut hits: Vec<Vec<&Report>> = vec![Vec::new(); expected.len()];
    let mut phantoms = Vec::new();
    for r in reports {
        // Bluetooth addresses are sent least significant byte first and
        // printed the other way round; either order matches.
        let by_addr = r.address.and_then(|a| {
            let mut rev = a;
            rev.reverse();
            expected.iter().position(|e| {
                let t = transmitter_address(&e.transmitter);
                t == Some(a) || (matches!(e.transmitter, Transmitter::Ble(_)) && t == Some(rev))
            })
        });
        let by_id = || {
            let id = norm_id(r.id.as_deref()?);
            expected
                .iter()
                .position(|e| e.ids.iter().any(|x| norm_id(x) == id))
        };
        match by_addr.or_else(by_id) {
            Some(i) => hits[i].push(r),
            None => phantoms.push(r.clone()),
        }
    }
    let judged = expected
        .iter()
        .zip(hits)
        .map(|(e, rs)| {
            let outcome = if rs.is_empty() {
                Outcome::Missed
            } else if rs.iter().any(|r| r.flagged) {
                Outcome::Flagged
            } else {
                Outcome::Accepted
            };
            let mut verdicts: Vec<String> = Vec::new();
            for r in rs {
                let v = if r.verdict.is_empty() {
                    "(none)".to_string()
                } else {
                    r.verdict.clone()
                };
                if !verdicts.contains(&v) {
                    verdicts.push(v);
                }
            }
            Judged {
                expected: e.clone(),
                outcome,
                verdicts,
            }
        })
        .collect();
    CaptureScore {
        capture: capture.to_string(),
        truth,
        judged,
        phantoms,
    }
}

/// Totals over many captures.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Totals {
    /// Spoofed transmitters replayed.
    pub spoofed: usize,
    /// Spoofed transmitters the receiver warned about.
    pub spoofed_flagged: usize,
    /// Spoofed transmitters the receiver showed as real.
    pub spoofed_accepted: usize,
    /// Spoofed transmitters the receiver did not show.
    pub spoofed_missed: usize,
    /// Legitimate transmitters replayed.
    pub legit: usize,
    /// Legitimate transmitters shown with no warning.
    pub legit_accepted: usize,
    /// Legitimate transmitters the receiver warned about (false alarms).
    pub legit_flagged: usize,
    /// Legitimate transmitters the receiver did not show.
    pub legit_missed: usize,
    /// Reports that match no transmitter.
    pub phantoms: usize,
}

impl Totals {
    /// Sums the scores.
    pub fn of(scores: &[CaptureScore]) -> Totals {
        let mut t = Totals::default();
        for s in scores {
            let (f, a, m) = (
                s.count(Outcome::Flagged),
                s.count(Outcome::Accepted),
                s.count(Outcome::Missed),
            );
            match s.truth {
                Truth::Spoofed => {
                    t.spoofed += f + a + m;
                    t.spoofed_flagged += f;
                    t.spoofed_accepted += a;
                    t.spoofed_missed += m;
                }
                Truth::Legitimate => {
                    t.legit += f + a + m;
                    t.legit_flagged += f;
                    t.legit_accepted += a;
                    t.legit_missed += m;
                }
            }
            t.phantoms += s.phantoms.len();
        }
        t
    }

    /// Transmitters the receiver showed at all.
    pub fn decoded(&self) -> usize {
        self.spoofed_flagged + self.spoofed_accepted + self.legit_flagged + self.legit_accepted
    }
}

/// When a replay fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gate {
    /// Fail when a legitimate transmitter is flagged (default `true`).
    pub fail_on_false_alarm: bool,
    /// Fail when any transmitter is missed (default `false`).
    pub fail_on_missed: bool,
    /// Fail when a report matches no transmitter (default `false`).
    pub fail_on_phantom: bool,
}

impl Default for Gate {
    fn default() -> Self {
        Gate {
            fail_on_false_alarm: true,
            fail_on_missed: false,
            fail_on_phantom: false,
        }
    }
}

impl Gate {
    /// The reasons this run fails, empty when it passes. A spoofed
    /// transmitter shown as real always fails, and so does a run in which
    /// the receiver showed nothing at all (it proved nothing).
    pub fn failures(&self, t: &Totals) -> Vec<String> {
        let mut f = Vec::new();
        if t.spoofed_accepted > 0 {
            f.push(std::format!(
                "{} of {} spoofed transmitters accepted as real",
                t.spoofed_accepted,
                t.spoofed
            ));
        }
        if t.decoded() == 0 {
            f.push(
                "the receiver showed no transmitter at all, so the replay proves nothing".into(),
            );
        }
        if self.fail_on_false_alarm && t.legit_flagged > 0 {
            f.push(std::format!(
                "{} of {} legitimate transmitters flagged",
                t.legit_flagged,
                t.legit
            ));
        }
        if self.fail_on_missed && t.spoofed_missed + t.legit_missed > 0 {
            f.push(std::format!(
                "{} transmitters missed",
                t.spoofed_missed + t.legit_missed
            ));
        }
        if self.fail_on_phantom && t.phantoms > 0 {
            f.push(std::format!(
                "{} reports match no transmitter in the capture",
                t.phantoms
            ));
        }
        f
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(addr: u8, id: &str, truth: Truth) -> Expected {
        Expected {
            transmitter: Transmitter::Wifi([2, 0, 0, 0, 0, addr]),
            ids: vec![id.into()],
            truth,
        }
    }

    #[test]
    fn json_objects() {
        let f = parse_object(
            r#" {"a":"x\"yé😀","b":true,"c":-1.5e2,"d":null,"e":[1,{"f":[]}],"g":{}} "#,
        )
        .unwrap();
        assert_eq!(f[0], ("a".into(), Json::Str("x\"y\u{e9}\u{1F600}".into())));
        assert_eq!(f[1].1, Json::Bool(true));
        assert_eq!(f[2].1, Json::Num(-150.0));
        assert_eq!(f[3].1, Json::Null);
        assert_eq!(f[4].1, Json::Nested);
        assert_eq!(f[5].1, Json::Nested);
        assert_eq!(parse_object("{}"), Some(Vec::new()));
        for bad in [
            "",
            "[1]",
            "{",
            "{\"a\"}",
            "{\"a\":1,}",
            "{\"a\":1} x",
            "log line",
            "{\"a\":tru}",
        ] {
            assert_eq!(parse_object(bad), None, "{bad}");
        }
        let deep = "{\"a\":".to_string() + &"[".repeat(100) + &"]".repeat(100) + "}";
        assert_eq!(parse_object(&deep), None);
        assert!(parse_object(&json_string("q\"\\\n\u{1}")).is_none());
        let round = std::format!("{{\"k\":{}}}", json_string("q\"\\\n\u{1}"));
        assert_eq!(
            parse_object(&round).unwrap()[0].1,
            Json::Str("q\"\\\n\u{1}".into())
        );
    }

    #[test]
    fn reports() {
        let r = Report::parse(r#"{"mac":"02-00-00-00-00-01","uas_id":"X1"}"#).unwrap();
        assert_eq!(r.address, Some([2, 0, 0, 0, 0, 1]));
        assert_eq!(r.id.as_deref(), Some("X1"));
        assert!(!r.flagged);
        assert!(
            Report::parse(r#"{"addr":"020000000001","verdict":"Spoofed"}"#)
                .unwrap()
                .flagged
        );
        assert!(
            Report::parse(r#"{"id":"X","spoofed":true}"#)
                .unwrap()
                .flagged
        );
        assert!(
            !Report::parse(r#"{"id":"X","spoofed":false}"#)
                .unwrap()
                .flagged
        );
        assert!(
            !Report::parse(r#"{"id":"X","verdict":"plausible"}"#)
                .unwrap()
                .flagged
        );
        assert_eq!(Report::parse("[DRONE] something"), None);
    }

    #[test]
    fn scoring_and_gate() {
        let spoof = [
            e(1, "S1", Truth::Spoofed),
            e(2, "S2", Truth::Spoofed),
            e(3, "S3", Truth::Spoofed),
        ];
        let legit = [e(9, "L1", Truth::Legitimate)];
        let reports: Vec<Report> = [
            r#"{"mac":"02:00:00:00:00:01"}"#,
            r#"{"uas_id":"s2","verdict":"suspicious"}"#,
            r#"{"mac":"02:00:00:00:00:77","uas_id":"GHOST"}"#,
        ]
        .iter()
        .map(|l| Report::parse(l).unwrap())
        .collect();
        let s = score("spoof.pcap", Truth::Spoofed, &spoof, &reports);
        assert_eq!(
            (
                s.count(Outcome::Accepted),
                s.count(Outcome::Flagged),
                s.count(Outcome::Missed)
            ),
            (1, 1, 1)
        );
        assert_eq!(s.phantoms.len(), 1);
        let l = score(
            "legit.pcap",
            Truth::Legitimate,
            &legit,
            &[Report::parse(r#"{"mac":"02:00:00:00:00:09"}"#).unwrap()],
        );
        let t = Totals::of(&[s, l]);
        assert_eq!(
            (t.spoofed, t.spoofed_accepted, t.legit_accepted, t.phantoms),
            (3, 1, 1, 1)
        );
        let g = Gate::default();
        assert_eq!(g.failures(&t).len(), 1);
        let strict = Gate {
            fail_on_missed: true,
            fail_on_phantom: true,
            ..Gate::default()
        };
        assert_eq!(strict.failures(&t).len(), 3);
        // A receiver that shows nothing proves nothing.
        let none = Totals::of(&[score("spoof.pcap", Truth::Spoofed, &spoof, &[])]);
        assert_eq!(g.failures(&none).len(), 1);
        // Every spoof flagged, the legit one accepted: pass.
        let good = Totals::of(&[
            score(
                "spoof.pcap",
                Truth::Spoofed,
                &spoof,
                &["S1", "S2", "S3"]
                    .iter()
                    .map(|id| {
                        Report::parse(&std::format!("{{\"id\":\"{id}\",\"verdict\":\"spoofed\"}}"))
                            .unwrap()
                    })
                    .collect::<Vec<_>>(),
            ),
            score(
                "legit.pcap",
                Truth::Legitimate,
                &legit,
                &[Report::parse(r#"{"id":"L1","verdict":"plausible"}"#).unwrap()],
            ),
        ]);
        assert!(g.failures(&good).is_empty());
    }
}
