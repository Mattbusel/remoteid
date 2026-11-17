//! `aircraft.json` in the readsb schema, so tar1090 shows drones.
//!
//! [tar1090](https://github.com/wiedehopf/tar1090) draws whatever its
//! `aircraft.json` lists. This writer produces that file from a
//! [`Tracker`], using only fields readsb documents (`README-json.md`):
//!
//! | readsb key | Value |
//! |---|---|
//! | `hex` | `~` and 6 hex digits derived from the transmitter address (the `~` marks a non-ICAO address, as TIS-B uses) |
//! | `type` | `other` |
//! | `flight` | first 8 characters of the UAS ID |
//! | `r` | the full UAS ID (tar1090 shows it as the registration) |
//! | `category` | `B6` (unmanned aerial vehicle) |
//! | `lat`, `lon`, `seen_pos` | position and its age |
//! | `alt_geom`, `alt_baro` | feet; `alt_baro` is `"ground"` when the status says so |
//! | `gs`, `track` | knots, degrees |
//! | `geom_rate` | feet per minute |
//! | `emergency` | `general` for status Emergency |
//! | `messages`, `seen`, `rssi` | frame count, age, last RSSI |
//!
//! Everything Remote ID specific goes in an extra `rid` object, which
//! readsb consumers ignore: ID type, UA type, operator ID, Self ID text,
//! transport, trust verdict, score, reasons, DRIP state. The operator
//! (pilot) position is **left out by default**; set
//! [`Options::include_operator_position`] only where publishing it is
//! lawful and intended.
//!
//! Write the file atomically (to a temporary name, then rename), as readsb
//! does, so tar1090 never reads half a file.

use core::fmt::Write as _;

use crate::{Status, TrackedUas, Tracker, Transmitter};

/// Writer options.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Options {
    /// Include the operator position from System messages (default
    /// `false`).
    pub include_operator_position: bool,
    /// Include aircraft that have no position yet (default `false`;
    /// tar1090 lists them in its table but cannot draw them).
    pub include_without_position: bool,
    /// Drop aircraft not heard for this many milliseconds (default 60 000,
    /// the readsb rule).
    pub max_age_ms: u64,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            include_operator_position: false,
            include_without_position: false,
            max_age_ms: 60_000,
        }
    }
}

const M_TO_FT: f64 = 3.280_839_895;
const MPS_TO_KT: f64 = 1.943_844_492;

/// The `hex` value for a transmitter: `~` and 24 bits of an FNV-1a hash of
/// the address.
pub fn hex_id(tx: &Transmitter) -> String {
    let (tag, bytes): (u8, [u8; 8]) = match tx {
        Transmitter::Ble(a) => (1, [a[0], a[1], a[2], a[3], a[4], a[5], 0, 0]),
        Transmitter::Wifi(a) => (2, [a[0], a[1], a[2], a[3], a[4], a[5], 0, 0]),
        Transmitter::Other(v) => (3, v.to_le_bytes()),
    };
    let mut h: u32 = 0x811C_9DC5;
    for b in core::iter::once(tag).chain(bytes) {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    format!("~{:06x}", (h ^ (h >> 24)) & 0x00FF_FFFF)
}

fn esc(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn num(out: &mut String, v: f64, decimals: usize) {
    if v.is_finite() {
        let _ = write!(out, "{v:.decimals$}");
    } else {
        out.push_str("null");
    }
}

/// Writes one aircraft object. Returns `false` (and writes nothing) when
/// the options leave it out.
pub fn write_aircraft(
    out: &mut String,
    tx: &Transmitter,
    uas: &TrackedUas,
    now_ms: u64,
    opts: &Options,
) -> bool {
    let age = now_ms.saturating_sub(uas.last_seen);
    if age > opts.max_age_ms {
        return false;
    }
    let loc = uas.data.location.as_ref();
    let pos = loc
        .and_then(|l| l.position())
        .filter(|_| loc.is_some_and(|l| l.is_plausible()));
    if pos.is_none() && !opts.include_without_position {
        return false;
    }
    out.push('{');
    out.push_str("\"hex\":");
    esc(out, &hex_id(tx));
    out.push_str(",\"type\":\"other\"");
    let id = uas.data.primary_id();
    if let Some(id) = id {
        out.push_str(",\"flight\":");
        esc(out, &id.chars().take(8).collect::<String>());
        out.push_str(",\"r\":");
        esc(out, id);
    }
    out.push_str(",\"category\":\"B6\"");
    if let (Some((lat, lon)), Some(l)) = (pos, loc) {
        out.push_str(",\"lat\":");
        num(out, lat, 7);
        out.push_str(",\"lon\":");
        num(out, lon, 7);
        let pos_age = uas.last_fix().map_or(age, |f| now_ms.saturating_sub(f.0));
        out.push_str(",\"seen_pos\":");
        num(out, pos_age as f64 / 1000.0, 1);
        if let Some(a) = l.altitude_geo {
            out.push_str(",\"alt_geom\":");
            num(out, (a as f64 * M_TO_FT).round(), 0);
        }
        if l.status == Status::Ground {
            out.push_str(",\"alt_baro\":\"ground\"");
        } else if let Some(a) = l.altitude_baro {
            out.push_str(",\"alt_baro\":");
            num(out, (a as f64 * M_TO_FT).round(), 0);
        }
        if let Some(s) = l.speed_horizontal {
            out.push_str(",\"gs\":");
            num(out, s as f64 * MPS_TO_KT, 1);
        }
        if let Some(d) = l.direction {
            out.push_str(",\"track\":");
            num(out, d as f64, 1);
        }
        if let Some(v) = l.speed_vertical {
            out.push_str(",\"geom_rate\":");
            num(out, (v as f64 * M_TO_FT * 60.0).round(), 0);
        }
        if l.status == Status::Emergency {
            out.push_str(",\"emergency\":\"general\"");
        }
    }
    let _ = write!(out, ",\"messages\":{}", uas.stats.received);
    out.push_str(",\"seen\":");
    num(out, age as f64 / 1000.0, 1);
    if let Some(r) = uas.rssi_dbm {
        let _ = write!(out, ",\"rssi\":{r}");
    }

    // Remote ID extensions.
    let a = &uas.assessment;
    out.push_str(",\"rid\":{");
    let _ = write!(out, "\"transport\":\"{}\"", uas.transport.name());
    if let Some(b) = uas
        .data
        .basic_id
        .iter()
        .flatten()
        .find(|b| b.uas_id_str().is_some_and(|s| !s.is_empty()))
    {
        let _ = write!(
            out,
            ",\"id_type\":{},\"ua_type\":{}",
            u8::from(b.id_type),
            u8::from(b.ua_type)
        );
    }
    if let Some(id) = id {
        out.push_str(",\"id\":");
        esc(out, id);
    }
    if let Some(o) = uas
        .data
        .operator_id
        .as_ref()
        .and_then(|o| o.operator_id_str())
    {
        if !o.is_empty() {
            out.push_str(",\"operator_id\":");
            esc(out, o);
        }
    }
    if let Some(s) = uas.data.self_id.as_ref().and_then(|s| s.description_str()) {
        if !s.is_empty() {
            out.push_str(",\"self_id\":");
            esc(out, s);
        }
    }
    if let Some(l) = loc {
        let _ = write!(out, ",\"status\":{}", u8::from(l.status));
        if let Some(h) = l.height {
            out.push_str(",\"height_m\":");
            num(out, h as f64, 1);
        }
    }
    if opts.include_operator_position {
        if let Some(s) = &uas.data.system {
            if let Some((lat, lon)) = s.operator_position() {
                out.push_str(",\"operator\":{\"lat\":");
                num(out, lat, 7);
                out.push_str(",\"lon\":");
                num(out, lon, 7);
                if let Some(alt) = s.operator_altitude_geo {
                    out.push_str(",\"alt_geom_m\":");
                    num(out, alt as f64, 1);
                }
                out.push('}');
            }
        }
    }
    let _ = write!(out, ",\"verdict\":\"{}\",\"score\":", a.verdict.name());
    num(out, a.score as f64, 2);
    out.push_str(",\"reasons\":[");
    for (i, r) in a.reasons.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "\"{}\"", r.name());
    }
    out.push(']');
    if let Some(s) = a.spoofer {
        out.push_str(",\"spoofer\":");
        esc(out, s.name());
    }
    let _ = write!(out, ",\"auth\":\"{}\"", a.auth.name());
    out.push_str("}}");
    true
}

/// The whole `aircraft.json` document. `now_unix_s` is the file's `now`
/// (Unix seconds); `now_ms` is the tracker clock used for ages.
pub fn to_string(tracker: &Tracker, now_ms: u64, now_unix_s: f64, opts: &Options) -> String {
    let mut out = String::with_capacity(256 + 512 * tracker.len());
    out.push_str("{\"now\":");
    num(&mut out, now_unix_s, 1);
    let total: u64 = tracker.iter().map(|(_, u)| u.stats.received).sum();
    let _ = write!(out, ",\"messages\":{total},\"aircraft\":[");
    let mut entries: Vec<_> = tracker.iter().collect();
    entries.sort_by_key(|(tx, _)| **tx);
    let mut first = true;
    for (tx, uas) in entries {
        let mark = out.len();
        if !first {
            out.push(',');
        }
        if write_aircraft(&mut out, tx, uas, now_ms, opts) {
            first = false;
        } else {
            out.truncate(mark);
        }
    }
    out.push_str("]}");
    out
}
