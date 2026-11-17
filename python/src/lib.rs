//! Python bindings: `remoteid.decode`, `remoteid.Tracker`, RIDF helpers.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use pyo3::exceptions::{PyKeyError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use remoteid::aircraft_json::{self, Options};
use remoteid::drip::Det;
use remoteid::ridf::{self, ReceiverPosition, Record};
use remoteid::trust::Assessment;
use remoteid::wifi::{self, BeaconInfo, WifiKind};
use remoteid::{
    ble, Frame, Message, Observation, Tracker as RTracker, TrackerConfig, Transmitter, Transport,
    TrustConfig,
};

/// A Remote ID payload pulled out of whatever the caller handed us.
struct Extracted<'a> {
    transport: Transport,
    counter: Option<u8>,
    payload: &'a [u8],
    source: Option<[u8; 6]>,
    beacon: Option<BeaconInfo>,
}

fn bad(msg: impl Into<String>) -> PyErr {
    PyValueError::new_err(msg.into())
}

fn looks_like_radiotap(d: &[u8]) -> bool {
    // Version 0; the pad byte is not always zero in real captures.
    d.len() >= 8 && d[0] == 0 && {
        let n = u16::from_le_bytes([d[2], d[3]]) as usize;
        (8..=d.len()).contains(&n)
    }
}

fn extract<'a>(data: &'a [u8], transport: &str) -> PyResult<Extracted<'a>> {
    let raw = |t| Extracted {
        transport: t,
        counter: None,
        payload: data,
        source: None,
        beacon: None,
    };
    let wifi_frame = |frame: &'a [u8]| -> PyResult<Extracted<'a>> {
        let rid = wifi::parse_frame(frame).map_err(|e| bad(e.to_string()))?;
        Ok(Extracted {
            transport: match rid.kind {
                WifiKind::Beacon => Transport::WifiBeacon,
                WifiKind::Nan => Transport::WifiNan,
            },
            counter: Some(rid.counter),
            payload: rid.payload,
            source: Some(rid.source),
            beacon: wifi::beacon_info(frame),
        })
    };
    let ble_rid = |rid: ble::BleRemoteId<'a>| Extracted {
        transport: if rid.payload.first().is_some_and(|b| b >> 4 == 0xF) {
            Transport::Bluetooth5
        } else {
            Transport::Bluetooth4
        },
        counter: Some(rid.counter),
        payload: rid.payload,
        source: None,
        beacon: None,
    };
    match transport {
        "payload" | "message" | "pack" => Ok(raw(Transport::Unknown)),
        "wifi_frame" | "wifi" => {
            if looks_like_radiotap(data) {
                wifi_frame(wifi::strip_radiotap(data).map_err(|e| bad(e.to_string()))?)
            } else {
                wifi_frame(data)
            }
        }
        "radiotap" => wifi_frame(wifi::strip_radiotap(data).map_err(|e| bad(e.to_string()))?),
        "wifi_vendor_ie" | "vendor_ie" => {
            let rid = wifi::parse_vendor_element(data).map_err(|e| bad(e.to_string()))?;
            Ok(Extracted {
                transport: Transport::WifiBeacon,
                counter: Some(rid.counter),
                payload: rid.payload,
                source: None,
                beacon: None,
            })
        }
        "wifi_ies" => {
            let rid = wifi::find_in_elements(data).ok_or_else(|| bad("no Remote ID vendor element"))?;
            Ok(Extracted {
                transport: Transport::WifiBeacon,
                counter: Some(rid.counter),
                payload: rid.payload,
                source: None,
                beacon: None,
            })
        }
        "nan" => {
            let rid = wifi::parse_nan_action(data).map_err(|e| bad(e.to_string()))?;
            Ok(Extracted {
                transport: Transport::WifiNan,
                counter: Some(rid.counter),
                payload: rid.payload,
                source: None,
                beacon: None,
            })
        }
        "ble_adv" | "ble" => {
            let rid = ble::find_in_advertising_data(data).ok_or_else(|| bad("no Remote ID service data (UUID 0xFFFA)"))?;
            Ok(ble_rid(rid))
        }
        "ble_service_data" => {
            // Accept the bytes after the UUID (app code first) or with the
            // UUID in front.
            let d = if data.len() >= 3 && data[..2] == [0xFA, 0xFF] { &data[2..] } else { data };
            Ok(ble_rid(ble::parse_service_data(d).map_err(|e| bad(e.to_string()))?))
        }
        "auto" => {
            if looks_like_radiotap(data) {
                if let Ok(f) = wifi::strip_radiotap(data) {
                    if let Ok(e) = wifi_frame(f) {
                        return Ok(e);
                    }
                }
            }
            if data.len() >= 24 && matches!(data[0], 0x80 | 0x50 | 0xD0 | 0xE0) {
                if let Ok(e) = wifi_frame(data) {
                    return Ok(e);
                }
            }
            if let Ok(rid) = wifi::parse_vendor_element(data) {
                return Ok(Extracted {
                    transport: Transport::WifiBeacon,
                    counter: Some(rid.counter),
                    payload: rid.payload,
                    source: None,
                    beacon: None,
                });
            }
            if let Some(rid) = ble::find_in_advertising_data(data) {
                return Ok(ble_rid(rid));
            }
            if data.first() == Some(&ble::APP_CODE) && data.len() >= 27 {
                if let Ok(rid) = ble::parse_service_data(data) {
                    return Ok(ble_rid(rid));
                }
            }
            // A bare message or pack, only when its size says so.
            let pack_ok = data.first().is_some_and(|b| b >> 4 == 0xF) && remoteid::MessagePack::parse(data).is_ok();
            if data.len() == remoteid::MESSAGE_SIZE || pack_ok {
                Ok(raw(Transport::Unknown))
            } else {
                Err(bad("not recognised as Remote ID; pass transport explicitly"))
            }
        }
        other => Err(bad(format!(
            "unknown transport {other:?}; use auto, payload, wifi_frame, radiotap, wifi_vendor_ie, wifi_ies, nan, ble_adv or ble_service_data"
        ))),
    }
}

fn mac_text(a: &[u8; 6]) -> String {
    a.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn parse_mac(obj: &Bound<'_, PyAny>) -> PyResult<[u8; 6]> {
    if let Ok(b) = obj.cast::<PyBytes>() {
        return b
            .as_bytes()
            .try_into()
            .map_err(|_| bad("address must be 6 bytes"));
    }
    let s: String = obj.extract()?;
    let parts: Vec<&str> = s.split([':', '-']).collect();
    if parts.len() != 6 {
        return Err(bad("address must look like aa:bb:cc:dd:ee:ff"));
    }
    let mut out = [0u8; 6];
    for (o, p) in out.iter_mut().zip(parts) {
        *o = u8::from_str_radix(p, 16).map_err(|_| bad("bad hex in address"))?;
    }
    Ok(out)
}

fn opt_f<T: Into<f64>>(v: Option<T>) -> Option<f64> {
    v.map(Into::into)
}

fn message_dict<'py>(py: Python<'py>, m: &Message) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("protocol_version", m.protocol_version())?;
    match m {
        Message::BasicId(b) => {
            d.set_item("type", "basic_id")?;
            d.set_item("id_type", u8::from(b.id_type))?;
            d.set_item("ua_type", u8::from(b.ua_type))?;
            d.set_item("uas_id", b.uas_id_str())?;
            d.set_item("uas_id_bytes", PyBytes::new(py, &b.uas_id))?;
            d.set_item("det", Det::from_basic_id(b).map(|x| x.to_string()))?;
        }
        Message::Location(l) => {
            d.set_item("type", "location")?;
            d.set_item("status", u8::from(l.status))?;
            let (lat, lon) = l
                .position()
                .map_or((None, None), |(a, b)| (Some(a), Some(b)));
            d.set_item("latitude", lat)?;
            d.set_item("longitude", lon)?;
            d.set_item("altitude_baro", opt_f(l.altitude_baro))?;
            d.set_item("altitude_geo", opt_f(l.altitude_geo))?;
            d.set_item("height", opt_f(l.height))?;
            d.set_item("height_type", u8::from(l.height_type))?;
            d.set_item("speed_horizontal", opt_f(l.speed_horizontal))?;
            d.set_item("speed_vertical", opt_f(l.speed_vertical))?;
            d.set_item("direction", opt_f(l.direction))?;
            d.set_item("timestamp", opt_f(l.timestamp))?;
            d.set_item(
                "horizontal_accuracy_m",
                opt_f(l.horizontal_accuracy.meters()),
            )?;
            d.set_item("vertical_accuracy_m", opt_f(l.vertical_accuracy.meters()))?;
            d.set_item(
                "speed_accuracy_mps",
                opt_f(l.speed_accuracy.meters_per_second()),
            )?;
            d.set_item("plausible", l.is_plausible())?;
        }
        Message::Auth(a) => {
            d.set_item("type", "auth")?;
            d.set_item("auth_type", u8::from(a.auth_type))?;
            d.set_item("page", a.page)?;
            d.set_item("last_page_index", a.last_page_index)?;
            d.set_item("length", a.length)?;
            d.set_item("timestamp", a.timestamp)?;
            d.set_item("data", PyBytes::new(py, a.page_data()))?;
        }
        Message::SelfId(s) => {
            d.set_item("type", "self_id")?;
            d.set_item("description_type", u8::from(s.description_type))?;
            d.set_item("description", s.description_str())?;
        }
        Message::System(s) => {
            d.set_item("type", "system")?;
            let (lat, lon) = s
                .operator_position()
                .map_or((None, None), |(a, b)| (Some(a), Some(b)));
            d.set_item("operator_latitude", lat)?;
            d.set_item("operator_longitude", lon)?;
            d.set_item("operator_altitude_geo", opt_f(s.operator_altitude_geo))?;
            d.set_item("operator_location_type", u8::from(s.operator_location_type))?;
            d.set_item("classification_type", u8::from(s.classification_type))?;
            d.set_item("area_count", s.area_count)?;
            d.set_item("area_radius", s.area_radius)?;
            d.set_item("area_ceiling", opt_f(s.area_ceiling))?;
            d.set_item("area_floor", opt_f(s.area_floor))?;
            d.set_item("category_eu", u8::from(s.category_eu))?;
            d.set_item("class_eu", u8::from(s.class_eu))?;
            d.set_item("timestamp", s.timestamp)?;
        }
        Message::OperatorId(o) => {
            d.set_item("type", "operator_id")?;
            d.set_item("operator_id_type", o.operator_id_type)?;
            d.set_item("operator_id", o.operator_id_str())?;
        }
    }
    Ok(d)
}

/// Decodes one Remote ID frame. `transport` says what `data` is:
/// "payload" (a message or message pack, header byte first), "wifi_frame"
/// (an 802.11 frame, radiotap header optional), "radiotap",
/// "wifi_vendor_ie" (the body of the vendor element as scapy's
/// Dot11Elt.info gives it: OUI FA:0B:BC, type 0x0D, counter, pack),
/// "wifi_ies" (an element list), "nan" (a NAN action frame body),
/// "ble_adv" (Bluetooth advertising data), "ble_service_data" (service
/// data for UUID 0xFFFA), or "auto" to guess. Returns a dict with
/// "transport", "counter", "source" and "messages" (one dict per message,
/// each with a "type"); raises ValueError for anything that is not Remote ID.
#[pyfunction]
#[pyo3(signature = (data, transport = "auto"))]
fn decode<'py>(py: Python<'py>, data: &[u8], transport: &str) -> PyResult<Bound<'py, PyDict>> {
    let e = extract(data, transport)?;
    let frame = Frame::decode(e.payload).map_err(|err| bad(err.to_string()))?;
    let out = PyDict::new(py);
    out.set_item("transport", e.transport.name())?;
    out.set_item("counter", e.counter)?;
    out.set_item("source", e.source.map(|s| mac_text(&s)))?;
    out.set_item("is_pack", matches!(frame, Frame::Pack(_)))?;
    let list = PyList::empty(py);
    let mut err = None;
    frame.for_each_message(|m| {
        if err.is_none() {
            match message_dict(py, &m) {
                Ok(d) => {
                    if let Err(e) = list.append(d) {
                        err = Some(e);
                    }
                }
                Err(e) => err = Some(e),
            }
        }
    });
    if let Some(e) = err {
        return Err(e);
    }
    out.set_item("messages", list)?;
    Ok(out)
}

/// The trust verdict for one transmitter after a frame.
#[pyclass(module = "remoteid", frozen, get_all)]
#[derive(Clone)]
struct Verdict {
    /// "authenticated", "plausible", "suspicious" or "spoofed".
    verdict: String,
    /// 0 (certainly fake) to 1 (authenticated); 0.5 is no evidence either way.
    score: f32,
    /// Reason names, for example ["teleport", "tsf_wall_clock"].
    reasons: Vec<String>,
    /// Spoofing tool, when its fingerprint matched.
    spoofer: Option<String>,
    /// DRIP authentication state (RFC 9575 Appendix A).
    auth: String,
    /// Transmitter address, "aa:bb:cc:dd:ee:ff".
    address: String,
    /// Transport of the latest frame.
    transport: String,
    /// The UAS ID, once a Basic ID has been heard.
    uas_id: Option<String>,
    /// Latest position.
    latitude: Option<f64>,
    /// Latest position.
    longitude: Option<f64>,
    /// Geodetic altitude, meters.
    altitude_m: Option<f64>,
    /// Frames from this transmitter.
    frames: u64,
}

#[pymethods]
impl Verdict {
    fn __repr__(&self) -> String {
        format!(
            "Verdict({:?}, score={:.2}, reasons={:?}, uas_id={:?}, address={:?})",
            self.verdict, self.score, self.reasons, self.uas_id, self.address
        )
    }

    fn __str__(&self) -> String {
        self.verdict.clone()
    }

    /// `True` for "spoofed" or "suspicious".
    #[getter]
    fn is_alert(&self) -> bool {
        matches!(self.verdict.as_str(), "spoofed" | "suspicious")
    }

    /// The fields as a dict.
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        d.set_item("verdict", &self.verdict)?;
        d.set_item("score", self.score)?;
        d.set_item("reasons", &self.reasons)?;
        d.set_item("spoofer", &self.spoofer)?;
        d.set_item("auth", &self.auth)?;
        d.set_item("address", &self.address)?;
        d.set_item("transport", &self.transport)?;
        d.set_item("uas_id", &self.uas_id)?;
        d.set_item("latitude", self.latitude)?;
        d.set_item("longitude", self.longitude)?;
        d.set_item("altitude_m", self.altitude_m)?;
        d.set_item("frames", self.frames)?;
        Ok(d)
    }
}

fn tx_text(tx: &Transmitter) -> String {
    match tx {
        Transmitter::Ble(a) | Transmitter::Wifi(a) => mac_text(a),
        Transmitter::Other(v) => format!("other:{v}"),
    }
}

fn verdict_for(tx: &Transmitter, uas: &remoteid::TrackedUas, a: &Assessment) -> Verdict {
    let loc = uas.data.location.as_ref();
    let pos = loc.and_then(|l| l.position());
    Verdict {
        verdict: a.verdict.name().to_string(),
        score: a.score,
        reasons: a.reasons.iter().map(|r| r.name().to_string()).collect(),
        spoofer: a.spoofer.map(|s| s.name().to_string()),
        auth: a.auth.name().to_string(),
        address: tx_text(tx),
        transport: uas.transport.name().to_string(),
        uas_id: uas.uas_id(),
        latitude: pos.map(|p| p.0),
        longitude: pos.map(|p| p.1),
        altitude_m: loc.and_then(|l| l.altitude_geo).map(f64::from),
        frames: uas.stats.received,
    }
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Keeps every transmitter heard and its trust verdict. `trusted_keys`
/// maps DRIP DETs ("2001:30::..." text or 16 bytes) to Ed25519 public keys
/// (32 bytes): registry or HDA keys, or pinned aircraft keys.
///
/// `use_system_clock` (default False) stamps frames ingested without
/// explicit times with this machine's UTC clock. That enables the absolute
/// timestamp checks and the DRIP validity window, so turn it on only when
/// the clock is NTP or GNSS synced: an unsynced clock (a Raspberry Pi with
/// no RTC and no network) makes every aircraft look like its clock drifts.
/// When replaying captures, pass `now_ms` and `unix_ms` yourself.
///
/// With `auth_requires_clock` (default True) a DRIP signature only makes a
/// transmitter "authenticated" when it was checked against its validity
/// window with a UTC clock; without one a recorded signature could be
/// replayed.
///
/// Transmitters not heard for `timeout_ms` are dropped as frames come in,
/// and at most `max_transmitters` are kept.
#[pyclass(module = "remoteid")]
struct Tracker {
    inner: RTracker,
    start: Instant,
    use_system_clock: bool,
    last_expire: u64,
}

#[pymethods]
impl Tracker {
    #[new]
    #[pyo3(signature = (max_speed_mps = 100.0, fingerprints = true, accept_self_certified = false, trusted_keys = None, timeout_ms = 10_000, use_system_clock = false, auth_requires_clock = true, max_transmitters = 4096))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        max_speed_mps: f64,
        fingerprints: bool,
        accept_self_certified: bool,
        trusted_keys: Option<&Bound<'_, PyDict>>,
        timeout_ms: u64,
        use_system_clock: bool,
        auth_requires_clock: bool,
        max_transmitters: usize,
    ) -> PyResult<Self> {
        if max_transmitters == 0 {
            return Err(bad("max_transmitters must be at least 1"));
        }
        let mut trust = TrustConfig::default();
        trust.max_speed_mps = max_speed_mps;
        trust.fingerprints = fingerprints;
        trust.accept_self_certified = accept_self_certified;
        trust.auth_requires_clock = auth_requires_clock;
        let mut inner = RTracker::new(TrackerConfig {
            timeout: timeout_ms,
            trust,
            max_transmitters,
            ..TrackerConfig::default()
        });
        if let Some(keys) = trusted_keys {
            for (k, v) in keys.iter() {
                let det = if let Ok(b) = k.cast::<PyBytes>() {
                    Det::from_slice(b.as_bytes()).ok_or_else(|| bad("DET must be 16 bytes"))?
                } else {
                    let s: String = k.extract()?;
                    let ip: std::net::Ipv6Addr =
                        s.parse().map_err(|_| bad(format!("bad DET {s:?}")))?;
                    Det(ip.octets())
                };
                let hi: [u8; 32] = v
                    .cast::<PyBytes>()
                    .map_err(|_| bad("key must be bytes"))?
                    .as_bytes()
                    .try_into()
                    .map_err(|_| bad("Ed25519 public key must be 32 bytes"))?;
                inner.keys_mut().trust(det, hi);
            }
        }
        Ok(Tracker {
            inner,
            start: Instant::now(),
            use_system_clock,
            last_expire: 0,
        })
    }

    fn auto_expire(&mut self, now: u64) {
        if now.saturating_sub(self.last_expire) >= 1_000 || now < self.last_expire {
            self.last_expire = now;
            self.inner.expire(now);
        }
    }

    /// ingest(data, transport="auto", address=None, now_ms=None, unix_ms=None, rssi=None)
    /// --
    ///
    /// Adds one frame (see `decode` for `transport`) and returns the
    /// transmitter's `Verdict`. `address` identifies the transmitter
    /// ("aa:bb:..." or 6 bytes) and is required for every input that does
    /// not carry one (Bluetooth advertising or service data, Wi-Fi vendor
    /// elements, element lists, NAN bodies, bare payloads): without it,
    /// frames from different aircraft would be merged into one track and
    /// judged as one. Whole Wi-Fi frames carry their own address. Raises
    /// ValueError when no address is known.
    #[pyo3(signature = (data, transport = "auto", address = None, now_ms = None, unix_ms = None, rssi = None))]
    fn ingest(
        &mut self,
        data: &[u8],
        transport: &str,
        address: Option<&Bound<'_, PyAny>>,
        now_ms: Option<u64>,
        unix_ms: Option<u64>,
        rssi: Option<i8>,
    ) -> PyResult<Verdict> {
        let e = extract(data, transport)?;
        let addr = match address {
            Some(a) => Some(parse_mac(a)?),
            None => e.source,
        };
        let tx = match (addr, e.transport) {
            (Some(a), Transport::Bluetooth4 | Transport::Bluetooth5) => Transmitter::Ble(a),
            (Some(a), _) => Transmitter::Wifi(a),
            (None, _) => {
                return Err(bad(format!(
                    "{transport:?} input carries no transmitter address; pass address= \
                     (the Bluetooth or Wi-Fi source address) so that different aircraft \
                     are not merged into one track"
                )))
            }
        };
        let explicit = now_ms.is_some();
        let now = now_ms.unwrap_or_else(|| self.start.elapsed().as_millis() as u64);
        self.auto_expire(now);
        let mut obs = Observation::new(e.transport, e.counter, e.payload, now);
        let unix = unix_ms.or_else(|| (!explicit && self.use_system_clock).then(unix_now_ms));
        if let Some(u) = unix {
            obs = obs.with_unix_ms(u);
        }
        if let Some(r) = rssi {
            obs = obs.with_rssi(r);
        }
        if let Some(b) = e.beacon {
            obs = obs.with_beacon(b);
        }
        let uas = self.inner.observe(tx, &obs);
        Ok(verdict_for(&tx, uas, &uas.assessment))
    }

    /// Adds every record of a RIDF stream (bytes); returns one Verdict per
    /// record. Records need a transmitter address (ValueError otherwise).
    /// Records from several receivers belong in one Tracker only when their
    /// times are one shared UTC clock (the `utc` flag).
    fn ingest_ridf(&mut self, data: &[u8]) -> PyResult<Vec<Verdict>> {
        let mut out = Vec::new();
        for r in ridf::records(data) {
            let r = r.map_err(|e| bad(e.to_string()))?;
            if r.address.is_none() {
                return Err(bad(
                    "RIDF record without a transmitter address; different aircraft would be merged",
                ));
            }
            self.auto_expire(r.rx_time_ns / 1_000_000);
            let tx = r.transmitter();
            let uas = self.inner.observe(tx, &r.observation());
            out.push(verdict_for(&tx, uas, &uas.assessment));
        }
        Ok(out)
    }

    /// All transmitters with their current verdicts.
    fn verdicts(&self) -> Vec<Verdict> {
        let mut v: Vec<_> = self
            .inner
            .iter()
            .map(|(tx, u)| verdict_for(tx, u, &u.assessment))
            .collect();
        v.sort_by(|a, b| a.address.cmp(&b.address));
        v
    }

    /// The verdict for one address.
    fn get(&self, address: &Bound<'_, PyAny>) -> PyResult<Verdict> {
        let a = parse_mac(address)?;
        for tx in [Transmitter::Ble(a), Transmitter::Wifi(a)] {
            if let Some(u) = self.inner.get(&tx) {
                return Ok(verdict_for(&tx, u, &u.assessment));
            }
        }
        Err(PyKeyError::new_err(mac_text(&a)))
    }

    /// aircraft_json(now_ms=None, include_operator_position=False, include_without_position=False)
    /// --
    ///
    /// The tracker as `aircraft.json` in the readsb schema (for tar1090),
    /// with a `rid` object per aircraft. The operator position is left out
    /// unless asked for.
    #[pyo3(signature = (now_ms = None, include_operator_position = false, include_without_position = false))]
    fn aircraft_json(
        &self,
        now_ms: Option<u64>,
        include_operator_position: bool,
        include_without_position: bool,
    ) -> String {
        let mut opts = Options::default();
        opts.include_operator_position = include_operator_position;
        opts.include_without_position = include_without_position;
        let now = now_ms.unwrap_or_else(|| self.start.elapsed().as_millis() as u64);
        aircraft_json::to_string(&self.inner, now, unix_now_ms() as f64 / 1000.0, &opts)
    }

    /// Drops transmitters not heard for `timeout_ms`; returns how many.
    #[pyo3(signature = (now_ms = None))]
    fn expire(&mut self, now_ms: Option<u64>) -> usize {
        let now = now_ms.unwrap_or_else(|| self.start.elapsed().as_millis() as u64);
        self.inner.expire(now)
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }
}

/// Decodes a RIDF stream (with or without the file header).
#[pyfunction]
fn read_ridf<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyList>> {
    let list = PyList::empty(py);
    for r in ridf::records(data) {
        let r = r.map_err(|e| bad(e.to_string()))?;
        let d = PyDict::new(py);
        d.set_item("transport", r.transport.name())?;
        d.set_item("counter", r.counter)?;
        d.set_item("rx_time_ns", r.rx_time_ns)?;
        d.set_item("utc", r.utc)?;
        d.set_item("rssi", r.rssi_dbm)?;
        d.set_item("address", r.address.map(|a| mac_text(&a)))?;
        d.set_item("receiver_id", r.receiver_id)?;
        d.set_item(
            "receiver",
            r.receiver.map(|p| (p.latitude, p.longitude, p.altitude_m)),
        )?;
        d.set_item("payload", PyBytes::new(py, r.payload))?;
        d.set_item("extensions", PyBytes::new(py, r.extensions))?;
        list.append(d)?;
    }
    Ok(list)
}

/// Encodes one RIDF record. `payload` is the Remote ID message or pack
/// (no counter); `receiver` is (latitude, longitude, altitude_m). With
/// `header` the 8 byte file header is prepended.
#[pyfunction]
#[pyo3(signature = (payload, transport, rx_time_ns, counter = None, rssi = None, address = None, receiver_id = 0, receiver = None, utc = false, header = false))]
#[allow(clippy::too_many_arguments)]
fn write_ridf<'py>(
    py: Python<'py>,
    payload: &[u8],
    transport: &str,
    rx_time_ns: u64,
    counter: Option<u8>,
    rssi: Option<i8>,
    address: Option<&Bound<'_, PyAny>>,
    receiver_id: u16,
    receiver: Option<(f64, f64, f64)>,
    utc: bool,
    header: bool,
) -> PyResult<Bound<'py, PyBytes>> {
    let rec = Record {
        transport: Transport::from_name(transport)
            .ok_or_else(|| bad(format!("unknown transport {transport:?}")))?,
        counter,
        rx_time_ns,
        utc,
        rssi_dbm: rssi,
        address: address.map(parse_mac).transpose()?,
        receiver_id,
        receiver: receiver.map(|(a, b, c)| ReceiverPosition {
            latitude: a,
            longitude: b,
            altitude_m: c,
        }),
        payload,
        extensions: &[],
    };
    let mut buf = vec![0u8; rec.encoded_len() + 8];
    let at = if header {
        buf[..8].copy_from_slice(&ridf::FILE_HEADER);
        8
    } else {
        0
    };
    let n = rec.encode(&mut buf[at..]).map_err(|e| bad(e.to_string()))?;
    Ok(PyBytes::new(py, &buf[..at + n]))
}

#[pymodule]
fn _remoteid(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add_function(wrap_pyfunction!(decode, m)?)?;
    m.add_function(wrap_pyfunction!(read_ridf, m)?)?;
    m.add_function(wrap_pyfunction!(write_ridf, m)?)?;
    m.add_class::<Tracker>()?;
    m.add_class::<Verdict>()?;
    Ok(())
}
