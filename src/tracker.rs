//! Per-transmitter aircraft tracking (needs the `std` feature).

use std::collections::HashMap;

use crate::trust::{Assessment, Observation, Reason, TrustConfig, TrustState};
use crate::wifi::{WifiKind, WifiRemoteId};
use crate::{ble::BleRemoteId, geo, Frame, MessageType, Transmitter, Transport, UasData};

/// Counts derived from the one byte message counters.
///
/// Counters are tracked per message type for single messages (Bluetooth 4
/// keeps one counter per type) and once for packs. A repeat of the last
/// counter value counts as a duplicate; a jump forward of `n` counts `n - 1`
/// missed frames, and a late frame inside the reorder window takes one back.
/// Transmitters may legally repeat a counter when content is
/// unchanged, so `missed` is an estimate of lost frames, not an exact count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CounterStats {
    /// Frames accepted.
    pub received: u64,
    /// Frames whose counter repeated the previous one.
    pub duplicates: u64,
    /// Frames estimated lost from forward counter jumps.
    pub missed: u64,
    /// Times the counter went backwards by more than the reorder window
    /// (treated as a transmitter restart).
    pub resets: u64,
}

impl CounterStats {
    /// `missed / (received + missed)`, or 0 before any frame.
    pub fn loss_ratio(&self) -> f64 {
        let total = self.received + self.missed;
        if total == 0 {
            0.0
        } else {
            self.missed as f64 / total as f64
        }
    }
}

/// One tracked aircraft.
#[derive(Debug, Clone, Default)]
pub struct TrackedUas {
    /// Everything decoded so far.
    pub data: UasData,
    /// Timestamp (caller's clock) of the first frame.
    pub first_seen: u64,
    /// Timestamp of the latest frame.
    pub last_seen: u64,
    /// Counter statistics over all frames.
    pub stats: CounterStats,
    /// Frames that failed to decode.
    pub decode_errors: u64,
    /// Trust evidence for this transmitter.
    pub trust: TrustState,
    /// Latest trust assessment (updated with every frame).
    pub assessment: Assessment,
    /// Latest signal strength, dBm, if the caller gave one.
    pub rssi_dbm: Option<i8>,
    /// Transport of the latest frame.
    pub transport: Transport,
    last_counter: [Option<u8>; 8],
    last_fix: Option<(u64, f64, f64, f64)>,
    /// The identity this entry is filed under in the tracker's index.
    indexed_id: Option<String>,
}

impl TrackedUas {
    /// The identity to show for this aircraft: the DRIP DET that signed its
    /// verified messages when there is one (an unsigned serial number Basic
    /// ID sent beside it proves nothing), else the first Basic ID.
    pub fn uas_id(&self) -> Option<String> {
        #[cfg(feature = "verify")]
        if let Some(det) = self.trust.authenticated_det() {
            return Some(det.to_string());
        }
        self.data.primary_id().map(str::to_owned)
    }

    /// Time, latitude, longitude and horizontal accuracy (m) of the latest
    /// position.
    pub fn last_fix(&self) -> Option<(u64, f64, f64, f64)> {
        self.last_fix
    }
}

/// Tracker settings.
#[derive(Debug, Clone, Copy)]
pub struct TrackerConfig {
    /// Aircraft not heard for this long (in the caller's time unit) are
    /// removed by [`Tracker::expire`].
    pub timeout: u64,
    /// Counter steps backwards up to this size are taken as reordering, not
    /// as a restart.
    pub reorder_window: u8,
    /// Trust check settings. The trust checks need the caller's time unit to
    /// be milliseconds.
    pub trust: TrustConfig,
    /// Most transmitters kept at once (default 4096; each takes several
    /// KB). When a new one arrives with the tracker full, aircraft past
    /// `timeout` are dropped first, then the one heard least recently, so
    /// a flood of frames from random addresses cannot grow memory without
    /// bound.
    pub max_transmitters: usize,
}

impl Default for TrackerConfig {
    fn default() -> Self {
        // Assumes milliseconds: F3411 asks receivers to drop aircraft after
        // about 3 s without a Location; a 10 s default keeps slow
        // Bluetooth 4 transmitters that rotate message types.
        TrackerConfig {
            timeout: 10_000,
            reorder_window: 8,
            trust: TrustConfig::default(),
            max_transmitters: 4096,
        }
    }
}

/// Keeps one [`TrackedUas`] per transmitter, with a trust
/// [`Assessment`] for each.
///
/// Time is whatever monotonic unit the caller passes (milliseconds with the
/// default config); the tracker never reads a clock itself, so replaying a
/// capture gives the same result as live use.
///
/// On top of the per-transmitter checks of [`TrustState`], the tracker
/// compares transmitters: the same UAS ID at incompatible positions
/// ([`Reason::IdentityClone`], or [`Reason::TransportDisagreement`] when the
/// two came over different transports), and identical Wi-Fi TSF values from
/// different addresses ([`Reason::SharedRadio`]). With the `verify` feature
/// it checks DRIP signatures with the keys in `Tracker::keys_mut`.
///
/// ```
/// use remoteid::{ble, Tracker, Transmitter, Verdict};
///
/// let adv = [0x1e, 0x16, 0xfa, 0xff, 0x0d, 0x01, 0x02, 0x12, b'A', b'B', b'C', b'D', b'1', b'X',
///            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// let mut t = Tracker::default();
/// let rid = ble::find_in_advertising_data(&adv).unwrap();
/// let uas = t.ingest_ble([1, 2, 3, 4, 5, 6], &rid, 1_000);
/// assert_eq!(uas.assessment.verdict, Verdict::Plausible);
/// assert_eq!(t.len(), 1);
/// t.expire(20_000);
/// assert!(t.is_empty());
/// ```
#[derive(Debug, Clone, Default)]
pub struct Tracker {
    config: TrackerConfig,
    uas: HashMap<Transmitter, TrackedUas>,
    /// Transmitters by primary UAS ID, for the identity cross-check.
    by_id: HashMap<String, Vec<Transmitter>>,
    tsf_seen: Vec<(u64, Transmitter, u64)>,
    #[cfg(feature = "verify")]
    keys: crate::auth::MemoryKeyStore,
}

impl Tracker {
    /// An empty tracker.
    pub fn new(config: TrackerConfig) -> Self {
        Tracker {
            config,
            ..Tracker::default()
        }
    }

    /// The settings.
    pub fn config(&self) -> &TrackerConfig {
        &self.config
    }

    /// Keys used to verify DRIP signatures. Add trust anchors with
    /// [`crate::auth::MemoryKeyStore::trust`]; aircraft keys learned from
    /// DRIP Links land here too.
    #[cfg(feature = "verify")]
    pub fn keys_mut(&mut self) -> &mut crate::auth::MemoryKeyStore {
        &mut self.keys
    }

    /// Keys known so far.
    #[cfg(feature = "verify")]
    pub fn keys(&self) -> &crate::auth::MemoryKeyStore {
        &self.keys
    }

    /// Records one decoded or undecodable payload.
    ///
    /// Returns the aircraft's entry. A frame that fails to decode still
    /// refreshes `last_seen` and counts as a decode error.
    pub fn ingest(
        &mut self,
        from: Transmitter,
        counter: u8,
        payload: &[u8],
        now: u64,
    ) -> &TrackedUas {
        let obs = Observation::new(Transport::Unknown, Some(counter), payload, now);
        self.observe(from, &obs)
    }

    /// Records a Bluetooth frame (a single message is taken as Bluetooth 4
    /// legacy advertising, a pack as Bluetooth 5).
    pub fn ingest_ble(&mut self, address: [u8; 6], rid: &BleRemoteId<'_>, now: u64) -> &TrackedUas {
        let transport = if rid.payload.first().is_some_and(|b| b >> 4 == 0xF) {
            Transport::Bluetooth5
        } else {
            Transport::Bluetooth4
        };
        let obs = Observation::new(transport, Some(rid.counter), rid.payload, now);
        self.observe(Transmitter::Ble(address), &obs)
    }

    /// Records a Wi-Fi frame, keyed by its source address.
    pub fn ingest_wifi(&mut self, rid: &WifiRemoteId<'_>, now: u64) -> &TrackedUas {
        let transport = match rid.kind {
            WifiKind::Beacon => Transport::WifiBeacon,
            WifiKind::Nan => Transport::WifiNan,
        };
        let obs = Observation::new(transport, Some(rid.counter), rid.payload, now);
        self.observe(Transmitter::Wifi(rid.source), &obs)
    }

    /// Records one frame with everything the receiver knows about it and
    /// updates the transmitter's trust assessment.
    pub fn observe(&mut self, from: Transmitter, obs: &Observation<'_>) -> &TrackedUas {
        let now = obs.now_ms;
        let window = self.config.reorder_window;
        let cfg = self.config.trust;
        if !self.uas.contains_key(&from) && self.uas.len() >= self.config.max_transmitters.max(1) {
            self.make_room(now);
        }
        let entry = self.uas.entry(from).or_insert_with(|| TrackedUas {
            first_seen: now,
            ..TrackedUas::default()
        });
        entry.last_seen = entry.last_seen.max(now);
        entry.transport = obs.transport;
        if obs.rssi_dbm.is_some() {
            entry.rssi_dbm = obs.rssi_dbm;
        }
        entry.assessment = entry.trust.observe(&cfg, obs);
        let frame = match Frame::decode(obs.payload) {
            Ok(f) => f,
            Err(_) => {
                entry.decode_errors += 1;
                return &self.uas[&from];
            }
        };
        if let Some(counter) = obs.counter {
            let slot = match &frame {
                Frame::Pack(_) => 7,
                Frame::Message(m) => match m.message_type() {
                    MessageType::Other(_) | MessageType::MessagePack => 7,
                    t => u8::from(t).min(6) as usize,
                },
            };
            let stats = &mut entry.stats;
            let mut late = false;
            if let Some(prev) = entry.last_counter[slot] {
                let step = counter.wrapping_sub(prev);
                if step == 0 {
                    stats.duplicates += 1;
                } else if step > 128 && (256 - step as u16) <= window as u16 {
                    // A small step backwards is a late frame that an earlier
                    // jump already counted as missed.
                    late = true;
                    stats.missed = stats.missed.saturating_sub(1);
                } else if step > 128 {
                    stats.resets += 1;
                } else {
                    stats.missed += step as u64 - 1;
                }
            }
            if !late {
                entry.last_counter[slot] = Some(counter);
            }
        }
        entry.stats.received += 1;
        // Every received Location refreshes the fix, also when it repeats
        // the previous one (a hovering aircraft, or a clone standing still).
        let has_location = match &frame {
            Frame::Message(m) => m.message_type() == MessageType::Location,
            Frame::Pack(p) => p.raw_messages().any(|m| m[0] >> 4 == 1),
        };
        entry.data.update_frame(&frame);
        let id_now = entry.data.primary_id();
        if id_now != entry.indexed_id.as_deref() {
            let new = id_now.map(str::to_owned);
            let old = core::mem::replace(&mut entry.indexed_id, new.clone());
            if let Some(old) = old {
                Self::unindex(&mut self.by_id, &old, &from);
            }
            if let Some(new) = new {
                self.by_id.entry(new).or_default().push(from);
            }
        }
        let entry = self.uas.get_mut(&from).expect("inserted above");
        let mut new_fix = false;
        if let Some(l) = &entry.data.location {
            if has_location && l.is_plausible() {
                if let Some((lat, lon)) = l.position() {
                    let hacc = l
                        .horizontal_accuracy
                        .meters()
                        .map_or(cfg.default_accuracy_m, |v| v as f64);
                    entry.last_fix = Some((now, lat, lon, hacc));
                    new_fix = true;
                }
            }
        }

        #[cfg(feature = "verify")]
        {
            let mut scheme = crate::auth::DripEd25519;
            while entry
                .trust
                .verify_pending(&cfg, &mut scheme, &mut self.keys, now, obs.unix_ms)
                .is_some()
            {}
            entry.assessment = entry.trust.assessment(&cfg, now);
        }

        if new_fix {
            self.cross_check_identity(from, obs.transport, now);
        }
        if let Some(b) = obs.beacon {
            self.cross_check_tsf(from, b.tsf, now);
        }
        &self.uas[&from]
    }

    fn cross_check_identity(&mut self, from: Transmitter, transport: Transport, now: u64) {
        let cfg = self.config.trust;
        let me = &self.uas[&from];
        let Some(id) = me.data.primary_id().map(str::to_owned) else {
            return;
        };
        let Some((t0, lat0, lon0, acc0)) = me.last_fix else {
            return;
        };
        let mut hits: Vec<(Transmitter, Reason)> = Vec::new();
        let same_id = self.by_id.get(&id).map_or(&[][..], Vec::as_slice);
        for tx in same_id {
            let Some(other) = self.uas.get(tx) else {
                continue;
            };
            if *tx == from {
                continue;
            }
            let Some((t1, lat1, lon1, acc1)) = other.last_fix else {
                continue;
            };
            let dt = t0.abs_diff(t1);
            if dt > 5_000 {
                continue;
            }
            let d = geo::distance_m(lat0, lon0, lat1, lon1);
            let allowed = acc0 + acc1 + 50.0 + cfg.max_speed_mps * dt as f64 / 1000.0;
            if d > allowed {
                let same_transport = other.trust.transports().any(|t| t == transport);
                let r = if same_transport {
                    Reason::IdentityClone
                } else {
                    Reason::TransportDisagreement
                };
                hits.push((*tx, r));
            }
        }
        for (tx, r) in hits {
            for who in [tx, from] {
                if let Some(u) = self.uas.get_mut(&who) {
                    u.trust.note(r, now);
                    u.assessment = u.trust.assessment(&cfg, now);
                }
            }
        }
    }

    fn cross_check_tsf(&mut self, from: Transmitter, tsf: u64, now: u64) {
        if tsf == 0 {
            return;
        }
        let cfg = self.config.trust;
        self.tsf_seen
            .retain(|(_, _, t)| now.saturating_sub(*t) <= 2_000);
        let mut shared: Vec<Transmitter> = self
            .tsf_seen
            .iter()
            .filter(|(v, tx, _)| *v == tsf && *tx != from)
            .map(|e| e.1)
            .collect();
        if !shared.is_empty() {
            shared.push(from);
            shared.sort();
            shared.dedup();
            for who in shared {
                if let Some(u) = self.uas.get_mut(&who) {
                    u.trust.note(Reason::SharedRadio, now);
                    u.assessment = u.trust.assessment(&cfg, now);
                }
            }
        }
        if self.tsf_seen.len() < 4096 {
            self.tsf_seen.push((tsf, from, now));
        }
    }

    /// The assessment of a transmitter re-evaluated at `now` (old evidence
    /// ages out after [`TrustConfig::memory_ms`]).
    pub fn assessment(&self, from: &Transmitter, now: u64) -> Option<Assessment> {
        let u = self.uas.get(from)?;
        Some(u.trust.assessment(&self.config.trust, now))
    }

    /// Removes aircraft not heard since `now - timeout`. Returns how many.
    pub fn expire(&mut self, now: u64) -> usize {
        let timeout = self.config.timeout;
        let gone: Vec<Transmitter> = self
            .uas
            .iter()
            .filter(|(_, u)| now.saturating_sub(u.last_seen) > timeout)
            .map(|(tx, _)| *tx)
            .collect();
        for tx in &gone {
            self.remove(tx);
        }
        gone.len()
    }

    /// Stops tracking one transmitter; returns its entry.
    pub fn remove(&mut self, from: &Transmitter) -> Option<TrackedUas> {
        let u = self.uas.remove(from)?;
        if let Some(id) = &u.indexed_id {
            Self::unindex(&mut self.by_id, id, from);
        }
        Some(u)
    }

    fn unindex(by_id: &mut HashMap<String, Vec<Transmitter>>, id: &str, tx: &Transmitter) {
        if let Some(v) = by_id.get_mut(id) {
            v.retain(|t| t != tx);
            if v.is_empty() {
                by_id.remove(id);
            }
        }
    }

    fn make_room(&mut self, now: u64) {
        if self.expire(now) > 0 {
            return;
        }
        let oldest = self
            .uas
            .iter()
            .min_by_key(|(_, u)| u.last_seen)
            .map(|(tx, _)| *tx);
        if let Some(tx) = oldest {
            self.remove(&tx);
        }
    }

    /// The entry for one transmitter.
    pub fn get(&self, from: &Transmitter) -> Option<&TrackedUas> {
        self.uas.get(from)
    }

    /// All tracked aircraft.
    pub fn iter(&self) -> impl Iterator<Item = (&Transmitter, &TrackedUas)> {
        self.uas.iter()
    }

    /// Number of tracked aircraft.
    pub fn len(&self) -> usize {
        self.uas.len()
    }

    /// `true` when nothing is tracked.
    pub fn is_empty(&self) -> bool {
        self.uas.is_empty()
    }
}
