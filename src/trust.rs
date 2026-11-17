//! Trust decisions: is this Remote ID broadcast plausible, authenticated,
//! or spoofed?
//!
//! Remote ID frames are unauthenticated in almost every aircraft flying
//! today, and public tools broadcast fake drones from a laptop or a five
//! dollar microcontroller. A receiver that only decodes fields trusts all of
//! them. This module keeps per-transmitter evidence and grades it:
//!
//! | Verdict | Meaning |
//! |---|---|
//! | [`Verdict::Authenticated`] | DRIP signatures verify under a trusted key, the signed content matches what was received, and nothing contradicts it |
//! | [`Verdict::Plausible`] | Nothing contradicts the broadcast (the default for honest, unauthenticated aircraft) |
//! | [`Verdict::Suspicious`] | Physical or protocol inconsistencies a real transmitter rarely shows |
//! | [`Verdict::Spoofed`] | Strong evidence: a failed signature, a teleport, two transmitters sharing one identity, or the fingerprint of a known spoofing tool |
//!
//! The verdict is advice. Nothing is dropped, and every verdict comes with
//! the [`Reason`]s behind it and a score between 0 and 1.
//!
//! # What is checked
//!
//! * **Kinematics**: position jumps faster than [`TrustConfig::max_speed_mps`],
//!   sustained impossible speed, reported speed, course and vertical rate
//!   against the track actually flown (all with the transmitted accuracy as
//!   slack).
//! * **Time**: Location timestamps that freeze, run at the wrong rate, or
//!   disagree with the receiver's UTC clock; System and Auth timestamps far
//!   from the receiver's clock or zero in an F3411-22a message.
//! * **Counters**: one counter value reused for different content (two
//!   radios behind one address), repeated counter restarts.
//! * **Wi-Fi**: a TSF that is a Unix wall clock (software injectors write
//!   `time.time()`; real transmitters count microseconds since boot), a TSF
//!   that jumps against the receiver's clock.
//! * **Signal**: repeated large jumps in signal strength between frames.
//! * **Fingerprints** of two public spoofers, read from their source code:
//!   [cyber-defence-campus/droneRemoteIDSpoofer](https://github.com/cyber-defence-campus/droneRemoteIDSpoofer)
//!   and [jjshoots/RemoteIDSpoofer](https://github.com/jjshoots/RemoteIDSpoofer).
//! * **Identity**: serial numbers that break ANSI/CTA-2063-A, no Basic ID at
//!   all.
//! * **DRIP** (RFC 9575): signatures, through [`crate::auth`] with the
//!   `verify` feature; the authentication state follows RFC 9575 Appendix A.
//!
//! The std [`crate::Tracker`] adds checks across transmitters: one UAS ID
//! seen from two places at once, and several addresses sharing one radio
//! clock.
//!
//! # `no_std`
//!
//! [`TrustState`] needs no allocation. Feed it with
//! [`TrustState::observe`]; with the `verify` feature, completed
//! authentication messages are checked by [`TrustState::verify_pending`].

use core::fmt;

use crate::drip::{AssembledAuth, AuthAssembler, Det};
use crate::geo::FloatExt;
use crate::wifi::BeaconInfo;
use crate::{
    geo, Auth, Frame, IdType, Location, Message, SerialNumber, Transport, UasData, MESSAGE_SIZE,
};

/// Overall judgement of one transmitter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Verdict {
    /// Strong evidence the broadcast is fake or hijacked.
    Spoofed,
    /// Inconsistencies a real transmitter rarely shows.
    Suspicious,
    /// Nothing contradicts the broadcast.
    Plausible,
    /// Cryptographically authenticated and consistent.
    Authenticated,
}

impl Verdict {
    /// Lower case name.
    pub fn name(self) -> &'static str {
        match self {
            Verdict::Spoofed => "spoofed",
            Verdict::Suspicious => "suspicious",
            Verdict::Plausible => "plausible",
            Verdict::Authenticated => "authenticated",
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Public spoofing tools with a known fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Spoofer {
    /// cyber-defence-campus/droneRemoteIDSpoofer (Python, scapy, HCI).
    DroneRemoteIdSpoofer,
    /// jjshoots/RemoteIDSpoofer (ESP8266 / ESP32 Arduino).
    RemoteIdSpoofer,
}

impl Spoofer {
    /// Repository name.
    pub fn name(self) -> &'static str {
        match self {
            Spoofer::DroneRemoteIdSpoofer => "cyber-defence-campus/droneRemoteIDSpoofer",
            Spoofer::RemoteIdSpoofer => "jjshoots/RemoteIDSpoofer",
        }
    }
}

/// How much a reason weighs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Severity {
    /// Hint; two of them make a broadcast suspicious.
    Weak,
    /// Makes a broadcast suspicious; three different ones make it spoofed.
    Moderate,
    /// Makes a broadcast spoofed on its own.
    Strong,
}

macro_rules! reasons {
    ($( $(#[$m:meta])* $name:ident = $code:literal, $sev:ident, $label:literal; )*) => {
        /// Evidence behind a verdict.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        #[repr(u8)]
        #[non_exhaustive]
        pub enum Reason { $( $(#[$m])* $name = $code, )* }

        impl Reason {
            /// Every reason, in code order.
            pub const ALL: &'static [Reason] = &[ $( Reason::$name, )* ];
            const COUNT: usize = [ $( $code, )* ].len();

            /// How much the reason weighs.
            pub fn severity(self) -> Severity {
                match self { $( Reason::$name => Severity::$sev, )* }
            }

            /// Stable snake case name (used by the JSON writer and Python).
            pub fn name(self) -> &'static str {
                match self { $( Reason::$name => $label, )* }
            }
        }
    };
}

reasons! {
    /// The fingerprint of a public spoofing tool ([`Assessment::spoofer`] says which).
    KnownSpoofer = 0, Strong, "known_spoofer";
    /// A DRIP signature or DET binding failed for this aircraft.
    AuthFailed = 1, Strong, "auth_failed";
    /// The position jumped further than the speed limit allows.
    Teleport = 2, Strong, "teleport";
    /// One counter value carried different content: two radios share an address.
    CounterConflict = 3, Strong, "counter_conflict";
    /// The same UAS ID is broadcast from another transmitter at an incompatible position.
    IdentityClone = 4, Strong, "identity_clone";
    /// The same UAS ID disagrees across transports (Bluetooth 4/5, Beacon, NAN).
    TransportDisagreement = 5, Strong, "transport_disagreement";
    /// The track flown is faster than any drone, over several windows.
    SpeedImplausible = 6, Moderate, "speed_implausible";
    /// Reported horizontal speed disagrees with the track flown.
    ReportedSpeedMismatch = 7, Moderate, "reported_speed_mismatch";
    /// Reported direction disagrees with the track flown.
    ReportedCourseMismatch = 8, Moderate, "reported_course_mismatch";
    /// Climb or descent rate is impossible or disagrees with the reported vertical speed.
    VerticalRateImplausible = 9, Moderate, "vertical_rate_implausible";
    /// Location timestamps stopped while the receiver clock ran.
    TimestampFrozen = 10, Moderate, "timestamp_frozen";
    /// Location timestamps run at the wrong rate or far from the receiver's UTC clock.
    LocationClockDrift = 11, Moderate, "location_clock_drift";
    /// System or Auth timestamps are zero (F3411-22a) or far from the receiver's UTC clock.
    SystemClockDrift = 12, Moderate, "system_clock_drift";
    /// The Wi-Fi TSF is a Unix wall clock, as software frame injectors write it.
    TsfWallClock = 13, Moderate, "tsf_wall_clock";
    /// The Wi-Fi TSF jumps against the receiver's clock.
    TsfDiscontinuity = 14, Moderate, "tsf_discontinuity";
    /// The message counter keeps restarting.
    CounterInterleave = 15, Moderate, "counter_interleave";
    /// Signal strength keeps jumping between consecutive frames.
    SignalJump = 16, Moderate, "signal_jump";
    /// Several transmitter addresses share one radio clock.
    SharedRadio = 17, Moderate, "shared_radio";
    /// Location fields outside their ranges or reserved codes.
    InvalidFields = 18, Moderate, "invalid_fields";
    /// A serial number Basic ID that breaks ANSI/CTA-2063-A.
    SerialFormat = 19, Weak, "serial_format";
    /// Locations for a while but never a Basic ID.
    NoBasicId = 20, Weak, "no_basic_id";
    /// A valid DRIP signature outside its VNB / VNA window (possible replay).
    AuthExpired = 21, Weak, "auth_expired";
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A set of [`Reason`]s.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ReasonSet(u32);

impl ReasonSet {
    /// Adds a reason.
    pub fn insert(&mut self, r: Reason) {
        self.0 |= 1 << r as u8;
    }

    /// `true` if `r` is in the set.
    pub fn contains(&self, r: Reason) -> bool {
        self.0 & (1 << r as u8) != 0
    }

    /// `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Number of reasons.
    pub fn len(&self) -> usize {
        self.0.count_ones() as usize
    }

    /// The reasons in code order.
    pub fn iter(&self) -> impl Iterator<Item = Reason> + '_ {
        Reason::ALL
            .iter()
            .copied()
            .filter(move |r| self.contains(*r))
    }

    /// Number of reasons of a severity.
    pub fn count(&self, s: Severity) -> usize {
        self.iter().filter(|r| r.severity() == s).count()
    }
}

impl fmt::Debug for ReasonSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

/// DRIP authentication state, following RFC 9575 Appendix A.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AuthState {
    /// No authentication received.
    #[default]
    None,
    /// Pages received, no complete message yet.
    Partial,
    /// Complete messages of a type or scheme this receiver cannot check.
    Unsupported,
    /// Complete messages, but the key or data needed to verify is missing.
    Unverifiable,
    /// Signatures verify and signed content matches what was received.
    Verified,
    /// Verified, and the key chains to a trusted key.
    Trusted,
    /// Every checked message failed.
    Unverified,
    /// Both verified and failed messages.
    Questionable,
    /// Both trusted and failed messages.
    Conflicting,
}

impl AuthState {
    /// Lower case name.
    pub fn name(self) -> &'static str {
        match self {
            AuthState::None => "none",
            AuthState::Partial => "partial",
            AuthState::Unsupported => "unsupported",
            AuthState::Unverifiable => "unverifiable",
            AuthState::Verified => "verified",
            AuthState::Trusted => "trusted",
            AuthState::Unverified => "unverified",
            AuthState::Questionable => "questionable",
            AuthState::Conflicting => "conflicting",
        }
    }
}

/// A verdict with its evidence.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct Assessment {
    /// The graded judgement.
    pub verdict: Verdict,
    /// 0 (certainly fake) to 1 (authenticated and consistent); 0.5 means no
    /// evidence either way.
    pub score: f32,
    /// Why.
    pub reasons: ReasonSet,
    /// Which tool, when [`Reason::KnownSpoofer`] is set.
    pub spoofer: Option<Spoofer>,
    /// DRIP authentication state.
    pub auth: AuthState,
}

impl Default for Assessment {
    fn default() -> Self {
        Assessment {
            verdict: Verdict::Plausible,
            score: 0.5,
            reasons: ReasonSet::default(),
            spoofer: None,
            auth: AuthState::None,
        }
    }
}

/// Settings for the trust checks. Times are milliseconds of the caller's
/// monotonic clock.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct TrustConfig {
    /// Fastest believable ground speed, m/s (default 100, about 360 km/h:
    /// above racing drones, far below what spoofers produce by accident).
    pub max_speed_mps: f64,
    /// Fastest believable climb or descent, m/s (default 40).
    pub max_vertical_mps: f64,
    /// Position accuracy assumed when the transmitter says "unknown", m.
    pub default_accuracy_m: f64,
    /// Largest allowed gap between a Location timestamp and the receiver's
    /// UTC clock, seconds (default 30).
    pub max_location_drift_s: f64,
    /// Largest allowed gap between a System or Auth timestamp and the
    /// receiver's UTC clock, seconds (default 900).
    pub max_system_drift_s: f64,
    /// How long a reason stays active after its last supporting event
    /// (default 300 000 ms). Fingerprints never expire.
    pub memory_ms: u64,
    /// Count DRIP signatures under keys that are only self certified (no
    /// trusted parent) as authenticated. Default `false`: anyone can make a
    /// DET, only a registry endorsement says who owns it.
    pub accept_self_certified: bool,
    /// How recent the last content-validated signature must be for
    /// [`Verdict::Authenticated`] (default 30 000 ms; RFC 9575 asks for one
    /// every 5 s).
    pub auth_fresh_ms: u64,
    /// Clock skew allowed around DRIP VNB / VNA, seconds (default 120).
    pub auth_skew_s: u32,
    /// Evaluations needed before a ratio-based reason can fire (default 3).
    pub min_evaluations: u16,
    /// Match fingerprints of known spoofing tools (default `true`). Turn
    /// off to see what the generic checks find on their own.
    pub fingerprints: bool,
}

impl Default for TrustConfig {
    fn default() -> Self {
        TrustConfig {
            max_speed_mps: 100.0,
            max_vertical_mps: 40.0,
            default_accuracy_m: 30.0,
            max_location_drift_s: 30.0,
            max_system_drift_s: 900.0,
            memory_ms: 300_000,
            accept_self_certified: false,
            auth_fresh_ms: 30_000,
            auth_skew_s: 120,
            min_evaluations: 3,
            fingerprints: true,
        }
    }
}

/// One received Remote ID frame with what the receiver knows about it.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Observation<'a> {
    /// Link it came on.
    pub transport: Transport,
    /// Message counter from the frame, if the transport has one.
    pub counter: Option<u8>,
    /// The message or message pack, header byte first, counter removed.
    pub payload: &'a [u8],
    /// Receiver monotonic clock, milliseconds.
    pub now_ms: u64,
    /// Receiver UTC clock, Unix milliseconds, if it is trustworthy (NTP or
    /// GNSS). Enables the absolute timestamp checks.
    pub unix_ms: Option<u64>,
    /// Signal strength, dBm.
    pub rssi_dbm: Option<i8>,
    /// Wi-Fi Beacon header fields (from [`crate::wifi::beacon_info`]).
    pub beacon: Option<BeaconInfo>,
}

impl<'a> Observation<'a> {
    /// An observation with only the required fields.
    pub fn new(transport: Transport, counter: Option<u8>, payload: &'a [u8], now_ms: u64) -> Self {
        Observation {
            transport,
            counter,
            payload,
            now_ms,
            unix_ms: None,
            rssi_dbm: None,
            beacon: None,
        }
    }

    /// Sets the receiver UTC clock.
    pub fn with_unix_ms(mut self, unix_ms: u64) -> Self {
        self.unix_ms = Some(unix_ms);
        self
    }

    /// Sets the signal strength.
    pub fn with_rssi(mut self, rssi_dbm: i8) -> Self {
        self.rssi_dbm = Some(rssi_dbm);
        self
    }

    /// Sets the Wi-Fi Beacon header fields.
    pub fn with_beacon(mut self, beacon: BeaconInfo) -> Self {
        self.beacon = Some(beacon);
        self
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Tally {
    hits: u16,
    evals: u16,
    last_hit_ms: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct Fix {
    t: u64,
    lat: f64,
    lon: f64,
    alt: Option<f32>,
    speed: Option<f32>,
    dir: Option<f32>,
    vspeed: Option<f32>,
    hacc: f64,
    vacc: f64,
    ts: Option<f32>,
}

const FIXES: usize = 16;
const RECENT: usize = 16;
#[cfg(feature = "verify")]
const HASHES: usize = 48;
const COUNTER_SLOTS: usize = 8;

#[derive(Debug, Clone, Copy, Default)]
struct AuthTally {
    pages: u32,
    complete: u32,
    unsupported: u32,
    unverifiable: u32,
    valid: u32,
    invalid: u32,
    verified_ms: Option<u64>,
    trusted_ms: Option<u64>,
    any_verified: bool,
    any_trusted: bool,
}

/// Per-transmitter trust evidence. No allocation; about 4 KB.
#[derive(Debug, Clone)]
pub struct TrustState {
    data: UasData,
    frames: u64,
    decode_errors: u64,
    first_ms: Option<u64>,
    last_ms: u64,
    tallies: [Tally; Reason::COUNT],
    spoofer: Option<Spoofer>,
    fixes: [Fix; FIXES],
    nfix: usize,
    last_window_ms: Option<u64>,
    locations: u32,
    counters: [[Option<(u8, u32, u64)>; COUNTER_SLOTS]; 6],
    tsf: Option<(u64, u64)>,
    beacon: Option<BeaconInfo>,
    last_rssi: Option<(i8, u64)>,
    system_ts_zero: bool,
    transports: u8,
    recent: [[u8; MESSAGE_SIZE]; RECENT],
    nrecent: usize,
    #[cfg(feature = "verify")]
    hashes: [([u8; 8], u8, bool); HASHES],
    #[cfg(feature = "verify")]
    nhash: usize,
    assembler: AuthAssembler,
    pending: Option<AssembledAuth>,
    pack_msgs: [[u8; MESSAGE_SIZE]; 9],
    npack: usize,
    auth: AuthTally,
}

impl Default for TrustState {
    fn default() -> Self {
        TrustState {
            data: UasData::default(),
            frames: 0,
            decode_errors: 0,
            first_ms: None,
            last_ms: 0,
            tallies: [Tally::default(); Reason::COUNT],
            spoofer: None,
            fixes: [Fix::default(); FIXES],
            nfix: 0,
            last_window_ms: None,
            locations: 0,
            counters: [[None; COUNTER_SLOTS]; 6],
            tsf: None,
            beacon: None,
            last_rssi: None,
            system_ts_zero: false,
            transports: 0,
            recent: [[0; MESSAGE_SIZE]; RECENT],
            nrecent: 0,
            #[cfg(feature = "verify")]
            hashes: [([0; 8], 0, false); HASHES],
            #[cfg(feature = "verify")]
            nhash: 0,
            assembler: AuthAssembler::new(),
            pending: None,
            pack_msgs: [[0; MESSAGE_SIZE]; 9],
            npack: 0,
            auth: AuthTally::default(),
        }
    }
}

fn fnv1a(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811C_9DC5;
    for b in data {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

fn wrap_hour(mut x: f64) -> f64 {
    // Into [-1800, 1800).
    while x >= 1800.0 {
        x -= 3600.0;
    }
    while x < -1800.0 {
        x += 3600.0;
    }
    x
}

fn circular_mean_deg(sum_sin: f64, sum_cos: f64) -> f64 {
    let m = geo::atan2(sum_sin, sum_cos).to_degrees();
    if m < 0.0 {
        m + 360.0
    } else {
        m
    }
}

fn is_alnum16(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|c| c.is_ascii_alphanumeric())
}

impl TrustState {
    /// An empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything decoded so far from this transmitter.
    pub fn data(&self) -> &UasData {
        &self.data
    }

    /// Frames seen.
    pub fn frames(&self) -> u64 {
        self.frames
    }

    /// Frames that failed to decode.
    pub fn decode_errors(&self) -> u64 {
        self.decode_errors
    }

    /// Transports this transmitter was heard on.
    pub fn transports(&self) -> impl Iterator<Item = Transport> + '_ {
        Transport::ALL
            .iter()
            .copied()
            .filter(move |t| self.transports & (1 << t.code()) != 0)
    }

    /// DETs broadcast in Basic ID messages.
    pub fn dets(&self) -> impl Iterator<Item = Det> + '_ {
        self.data
            .basic_id
            .iter()
            .flatten()
            .filter_map(Det::from_basic_id)
    }

    /// Records evidence from outside this transmitter (the std tracker uses
    /// it for [`Reason::IdentityClone`], [`Reason::TransportDisagreement`]
    /// and [`Reason::SharedRadio`]).
    pub fn note(&mut self, reason: Reason, now_ms: u64) {
        self.hit(reason, now_ms);
    }

    fn hit(&mut self, r: Reason, now: u64) {
        let t = &mut self.tallies[r as usize];
        t.hits = t.hits.saturating_add(1);
        t.evals = t.evals.saturating_add(1);
        t.last_hit_ms = now;
    }

    fn eval(&mut self, r: Reason, hit: bool, now: u64) {
        if hit {
            self.hit(r, now);
        } else {
            let t = &mut self.tallies[r as usize];
            t.evals = t.evals.saturating_add(1);
        }
    }

    fn active(&self, r: Reason, cfg: &TrustConfig, now: u64) -> bool {
        let t = &self.tallies[r as usize];
        if t.hits == 0 {
            return false;
        }
        if r != Reason::KnownSpoofer && now.saturating_sub(t.last_hit_ms) > cfg.memory_ms {
            return false;
        }
        let ratio =
            |t: &Tally| t.hits >= cfg.min_evaluations && (t.hits as u32) * 2 >= t.evals as u32;
        match r {
            Reason::KnownSpoofer | Reason::AuthFailed | Reason::TsfWallClock => true,
            Reason::SerialFormat | Reason::NoBasicId | Reason::AuthExpired => true,
            Reason::Teleport | Reason::IdentityClone | Reason::TransportDisagreement => t.hits >= 2,
            Reason::SystemClockDrift | Reason::SharedRadio => t.hits >= 2,
            Reason::CounterConflict
            | Reason::TsfDiscontinuity
            | Reason::CounterInterleave
            | Reason::SignalJump
            | Reason::InvalidFields
            | Reason::TimestampFrozen => t.hits >= 3,
            Reason::SpeedImplausible
            | Reason::ReportedSpeedMismatch
            | Reason::ReportedCourseMismatch
            | Reason::VerticalRateImplausible
            | Reason::LocationClockDrift => ratio(t),
        }
    }

    /// Processes one frame and returns the updated assessment.
    pub fn observe(&mut self, cfg: &TrustConfig, obs: &Observation<'_>) -> Assessment {
        let now = obs.now_ms;
        self.frames += 1;
        self.first_ms.get_or_insert(now);
        self.last_ms = self.last_ms.max(now);
        self.transports |= 1 << obs.transport.code();

        if let Some(rssi) = obs.rssi_dbm {
            if let Some((prev, t)) = self.last_rssi {
                if now.saturating_sub(t) <= 500 {
                    let jump = (rssi as i16 - prev as i16).abs() >= 25;
                    self.eval(Reason::SignalJump, jump, now);
                }
            }
            self.last_rssi = Some((rssi, now));
        }

        if let Some(b) = obs.beacon {
            self.check_beacon(&b, obs.unix_ms, now);
            self.beacon = Some(b);
        }

        let frame = match Frame::decode(obs.payload) {
            Ok(f) => f,
            Err(_) => {
                self.decode_errors += 1;
                return self.assessment(cfg, now);
            }
        };

        if let Some(c) = obs.counter {
            self.check_counter(obs.transport, &frame, c, obs.payload, now);
        }

        let mut auth_pages: [Option<Auth>; 9] = Default::default();
        let mut nauth = 0;
        self.npack = 0;
        let is_pack = matches!(frame, Frame::Pack(_));
        #[cfg(feature = "verify")]
        if is_pack {
            let has_loc =
                matches!(&frame, Frame::Pack(p) if p.raw_messages().any(|m| m[0] >> 4 == 1));
            self.push_hash(crate::auth::auth_hash(obs.payload), 15, has_loc);
        }
        let mut raws: [Option<[u8; MESSAGE_SIZE]>; 9] = [None; 9];
        match &frame {
            Frame::Message(_) => raws[0] = obs.payload[..MESSAGE_SIZE].try_into().ok(),
            Frame::Pack(p) => {
                for (slot, raw) in raws.iter_mut().zip(p.raw_messages()) {
                    *slot = Some(*raw);
                }
            }
        }
        for raw in raws.iter().flatten() {
            let Ok(msg) = Message::decode(raw) else {
                continue;
            };
            if raw[0] >> 4 != 2 {
                self.push_recent(raw);
                if is_pack && self.npack < 9 {
                    self.pack_msgs[self.npack] = *raw;
                    self.npack += 1;
                }
                #[cfg(feature = "verify")]
                if !is_pack {
                    self.push_hash(crate::auth::auth_hash(raw), raw[0] >> 4, false);
                }
            }
            self.data.update(&msg);
            match &msg {
                Message::Location(l) => self.on_location(cfg, l, obs.unix_ms, now),
                Message::System(s) => {
                    if s.protocol_version >= 1 && s.timestamp == 0 {
                        self.system_ts_zero = true;
                        self.hit(Reason::SystemClockDrift, now);
                    } else if let (Some(ts), Some(unix_ms)) = (s.unix_timestamp(), obs.unix_ms) {
                        let drift = (ts as f64 - unix_ms as f64 / 1000.0).fabs();
                        self.eval(
                            Reason::SystemClockDrift,
                            drift > cfg.max_system_drift_s,
                            now,
                        );
                    }
                }
                Message::Auth(a) => {
                    self.auth.pages += 1;
                    if is_pack {
                        if nauth < auth_pages.len() {
                            auth_pages[nauth] = Some(a.clone());
                            nauth += 1;
                        }
                    } else {
                        let mut out = AssembledAuth::default();
                        let counter = obs.counter.unwrap_or(0);
                        if self.assembler.push_legacy(a, counter, &mut out) {
                            self.complete_auth(out, obs.unix_ms, cfg, now);
                        }
                    }
                }
                _ => {}
            }
        }
        if nauth > 0 {
            let mut out = AssembledAuth::default();
            if AuthAssembler::push_pack(auth_pages.iter().flatten(), &mut out) {
                self.complete_auth(out, obs.unix_ms, cfg, now);
            }
        }
        self.check_identity(cfg, now);
        self.assessment(cfg, now)
    }

    fn complete_auth(
        &mut self,
        out: AssembledAuth,
        unix_ms: Option<u64>,
        cfg: &TrustConfig,
        now: u64,
    ) {
        self.auth.complete += 1;
        if let Some(unix_ms) = unix_ms {
            if out.timestamp == 0 && out.protocol_version >= 1 {
                self.hit(Reason::SystemClockDrift, now);
            } else if out.timestamp != 0 {
                let drift = (out.unix_timestamp() as f64 - unix_ms as f64 / 1000.0).fabs();
                self.eval(
                    Reason::SystemClockDrift,
                    drift > cfg.max_system_drift_s,
                    now,
                );
            }
        }
        self.pending = Some(out);
    }

    fn push_recent(&mut self, raw: &[u8; MESSAGE_SIZE]) {
        if self.recent[..self.nrecent.min(RECENT)].contains(raw) {
            return;
        }
        self.recent[self.nrecent % RECENT] = *raw;
        self.nrecent += 1;
    }

    #[cfg(feature = "verify")]
    fn push_hash(&mut self, h: [u8; 8], t: u8, has_loc: bool) {
        if self.hashes[..self.nhash.min(HASHES)]
            .iter()
            .any(|e| e.0 == h)
        {
            return;
        }
        self.hashes[self.nhash % HASHES] = (h, t, has_loc);
        self.nhash += 1;
    }

    fn check_counter(
        &mut self,
        transport: Transport,
        frame: &Frame<'_>,
        counter: u8,
        payload: &[u8],
        now: u64,
    ) {
        let slot = match frame {
            Frame::Pack(_) => 7,
            Frame::Message(m) => (u8::from(m.message_type()) as usize).min(6),
        };
        let hash = fnv1a(payload);
        let entry = &mut self.counters[transport.code() as usize % 6][slot];
        let mut conflict = false;
        let mut restart = false;
        if let Some((prev, prev_hash, t)) = *entry {
            if prev == counter && prev_hash != hash && now.saturating_sub(t) < 3_000 {
                conflict = true;
            }
            let step = counter.wrapping_sub(prev);
            if step > 128 && 256 - step as u16 > 8 {
                restart = true;
            }
        }
        *entry = Some((counter, hash, now));
        if conflict {
            self.hit(Reason::CounterConflict, now);
        }
        if restart {
            self.hit(Reason::CounterInterleave, now);
        }
    }

    fn check_beacon(&mut self, b: &BeaconInfo, unix_ms: Option<u64>, now: u64) {
        // 1e15 us is 31.7 years of uptime: only a wall clock gets there.
        let wall = match unix_ms {
            Some(u) => {
                b.tsf >= 1_000_000_000_000_000 || (b.tsf / 1000).abs_diff(u) < 400 * 86_400_000
            }
            None => b.tsf >= 1_000_000_000_000_000,
        };
        if wall {
            self.hit(Reason::TsfWallClock, now);
        }
        if let Some((prev_tsf, prev_now)) = self.tsf {
            if b.tsf != 0 && prev_tsf != 0 {
                let drx = now.saturating_sub(prev_now) as f64;
                let dtsf = (b.tsf as f64 - prev_tsf as f64) / 1000.0;
                let jump = dtsf < 0.0 || (dtsf - drx).fabs() > 500.0 + 0.05 * drx;
                self.eval(Reason::TsfDiscontinuity, jump, now);
            }
        }
        self.tsf = Some((b.tsf, now));
    }

    fn on_location(&mut self, cfg: &TrustConfig, l: &Location, unix_ms: Option<u64>, now: u64) {
        let issues = l.check().count();
        if issues > 0 {
            self.hit(Reason::InvalidFields, now);
        }
        let Some((lat, lon)) = l.position() else {
            return;
        };
        if issues > 0 {
            return;
        }
        self.locations += 1;
        let acc = |m: Option<f32>| m.map_or(cfg.default_accuracy_m, |v| v as f64);
        let fix = Fix {
            t: now,
            lat,
            lon,
            alt: l.altitude_geo.or(l.altitude_baro),
            speed: l.speed_horizontal,
            dir: l.direction,
            vspeed: l.speed_vertical,
            hacc: acc(l.horizontal_accuracy.meters()),
            vacc: acc(l.vertical_accuracy.meters()),
            // Raw 0 (0.0 s past the hour) is what transmitters that never fill
            // the field send, the Open Drone ID sample units included, so it
            // counts as "not provided" rather than as a frozen clock.
            ts: l.timestamp.filter(|t| *t != 0.0),
        };

        if let (Some(ts), Some(unix_ms)) = (fix.ts, unix_ms) {
            let rx = (unix_ms % 3_600_000) as f64 / 1000.0;
            let drift = wrap_hour(ts as f64 - rx).fabs();
            self.eval(
                Reason::LocationClockDrift,
                drift > cfg.max_location_drift_s,
                now,
            );
        }

        if self.nfix > 0 {
            let prev = self.fixes[(self.nfix - 1) % FIXES];
            let dt = now.saturating_sub(prev.t);
            if dt >= 50 {
                let d = geo::distance_m(prev.lat, prev.lon, lat, lon);
                let allowed = prev.hacc + fix.hacc + cfg.max_speed_mps * dt as f64 / 1000.0;
                self.eval(Reason::Teleport, d > allowed && d > 50.0, now);
            }
        }
        self.fixes[self.nfix % FIXES] = fix;
        self.nfix += 1;

        if self
            .last_window_ms
            .is_some_and(|t| now.saturating_sub(t) < 1000)
        {
            return;
        }
        // Anchor: the newest fix at least 2 s old (and at most 15 s).
        let held = self.nfix.min(FIXES);
        let mut anchor = None;
        for k in 1..held {
            let f = self.fixes[(self.nfix - 1 - k) % FIXES];
            let age = now.saturating_sub(f.t);
            if age > 15_000 {
                break;
            }
            if age >= 2_000 {
                anchor = Some((k, f));
                break;
            }
        }
        let Some((k, a)) = anchor else { return };
        self.last_window_ms = Some(now);
        let dt = now.saturating_sub(a.t) as f64 / 1000.0;
        let d = geo::distance_m(a.lat, a.lon, lat, lon);
        let slack_v = (a.hacc + fix.hacc) / dt;
        let v_obs = d / dt;
        self.eval(
            Reason::SpeedImplausible,
            v_obs - slack_v > cfg.max_speed_mps,
            now,
        );

        // Reported values over the window (fixes newer than the anchor).
        let (mut sp, mut nsp, mut ss, mut sc, mut ndir, mut vs, mut nvs) =
            (0.0, 0, 0.0, 0.0, 0, 0.0, 0);
        for j in 0..k {
            let f = self.fixes[(self.nfix - 1 - j) % FIXES];
            if let Some(s) = f.speed {
                sp += s as f64;
                nsp += 1;
            }
            if let Some(dir) = f.dir {
                ss += geo::sin((dir as f64).to_radians());
                sc += geo::cos((dir as f64).to_radians());
                ndir += 1;
            }
            if let Some(v) = f.vspeed {
                vs += v as f64;
                nvs += 1;
            }
        }
        if nsp > 0 {
            let v_rep = sp / nsp as f64;
            let tol = 3.0 + 0.3 * v_obs.max(v_rep) + slack_v;
            self.eval(
                Reason::ReportedSpeedMismatch,
                (v_obs - v_rep).fabs() > tol,
                now,
            );
            if ndir > 0 && v_rep >= 3.0 && v_obs - slack_v >= 3.0 {
                let course = geo::bearing_deg(a.lat, a.lon, lat, lon);
                let dir = circular_mean_deg(ss, sc);
                self.eval(
                    Reason::ReportedCourseMismatch,
                    geo::angle_diff_deg(course, dir) > 45.0,
                    now,
                );
            }
        }
        if let (Some(h0), Some(h1)) = (a.alt, fix.alt) {
            let rate = (h1 - h0) as f64 / dt;
            let vslack = (a.vacc + fix.vacc) / dt;
            let mut bad = rate.fabs() - vslack > cfg.max_vertical_mps;
            if nvs > 0 {
                let v_rep = vs / nvs as f64;
                bad |= (rate - v_rep).fabs() > 3.0 + 0.5 * rate.fabs().max(v_rep.fabs()) + vslack;
            }
            self.eval(Reason::VerticalRateImplausible, bad, now);
        }
        if let (Some(t0), Some(t1)) = (a.ts, fix.ts) {
            let dts = wrap_hour(t1 as f64 - t0 as f64);
            if dts == 0.0 {
                // Frozen while the aircraft moves or several fixes went by.
                self.eval(Reason::TimestampFrozen, d > 5.0 || k >= 3, now);
            } else if unix_ms.is_none() {
                self.eval(Reason::LocationClockDrift, (dts - dt).fabs() > 5.0, now);
            }
        }
    }

    fn check_identity(&mut self, cfg: &TrustConfig, now: u64) {
        let mut cdc = false;
        let mut jj = false;
        let mut serial_bad = false;
        let mut has_basic = false;
        let mut serial_text: Option<[u8; 20]> = None;
        for b in self.data.basic_id.iter().flatten() {
            if b.id_type == IdType::None {
                continue;
            }
            has_basic = true;
            let id = b.uas_id_str().unwrap_or("");
            if id.starts_with("Spoofed_Serial_") {
                cdc = true;
            }
            if b.id_type == IdType::SerialNumber {
                serial_bad |= SerialNumber::parse(id).is_none();
                serial_text = Some(b.uas_id);
            }
        }
        let self_id = self
            .data
            .self_id
            .as_ref()
            .and_then(|s| s.description_str())
            .unwrap_or("");
        if self_id == "Spoofing test" {
            cdc = true;
        }
        let operator = self
            .data
            .operator_id
            .as_ref()
            .and_then(|o| o.operator_id_str())
            .unwrap_or("");
        if let Some(b) = self.beacon {
            let ssid = b.ssid();
            // cyber-defence-campus: SSID "RID-" + serial, capability 0 (neither ESS nor IBSS).
            if let Some(serial) = serial_text {
                let n = serial.iter().position(|&c| c == 0).unwrap_or(20);
                if ssid.len() == 4 + n && ssid.starts_with(b"RID-") && ssid[4..] == serial[..n] {
                    cdc = true;
                }
            }
            if b.capability == 0 && self.system_ts_zero {
                cdc = true;
            }
            // jjshoots: SSID is the random 16 character operator ID; beacon
            // interval field 10 TU with Self ID "Recreational".
            if !operator.is_empty() && is_alnum16(operator) && ssid == operator.as_bytes() {
                jj = true;
            }
            if b.interval_tu == 10 && self_id == "Recreational" {
                jj = true;
            }
        }
        if !cfg.fingerprints {
            cdc = false;
            jj = false;
        }
        if cdc {
            self.spoofer = Some(Spoofer::DroneRemoteIdSpoofer);
            self.hit(Reason::KnownSpoofer, now);
        } else if jj {
            self.spoofer = Some(Spoofer::RemoteIdSpoofer);
            self.hit(Reason::KnownSpoofer, now);
        }
        if serial_bad && self.tallies[Reason::SerialFormat as usize].hits == 0 {
            self.hit(Reason::SerialFormat, now);
        }
        if !has_basic
            && self.locations >= 5
            && self
                .first_ms
                .is_some_and(|f| now.saturating_sub(f) >= 15_000)
        {
            self.hit(Reason::NoBasicId, now);
        }
    }

    /// The completed authentication message waiting for verification, if
    /// any (taking it clears it).
    pub fn take_pending_auth(&mut self) -> Option<AssembledAuth> {
        self.pending.take()
    }

    /// Records the outcome of verifying a message from
    /// [`TrustState::take_pending_auth`].
    #[cfg(feature = "verify")]
    pub fn record_auth(
        &mut self,
        msg: &AssembledAuth,
        result: crate::auth::AuthResult,
        now_ms: u64,
    ) {
        use crate::auth::{AuthKind, AuthResult};
        match result {
            AuthResult::NotHandled | AuthResult::Unsupported => self.auth.unsupported += 1,
            AuthResult::Unverifiable => self.auth.unverifiable += 1,
            AuthResult::Valid {
                kind,
                trusted,
                content_validated,
                fresh,
                ..
            } => {
                self.auth.valid += 1;
                if fresh == Some(false) {
                    self.hit(Reason::AuthExpired, now_ms);
                    return;
                }
                // A Link proves the key, not this aircraft's live data.
                if kind != AuthKind::Link && content_validated {
                    self.auth.any_verified = true;
                    self.auth.verified_ms = Some(now_ms);
                    if trusted {
                        self.auth.any_trusted = true;
                        self.auth.trusted_ms = Some(now_ms);
                    }
                }
            }
            AuthResult::Invalid(_) => {
                // Pages gathered across seconds over Bluetooth 4 and rebuilt
                // by FEC may mix messages; only count clean failures.
                if msg.from_pack || msg.recovered_page.is_none() {
                    self.auth.invalid += 1;
                    self.hit(Reason::AuthFailed, now_ms);
                }
            }
        }
    }

    /// Verifies the pending authentication message, if any, with `scheme`
    /// and `keys`, and records the result.
    #[cfg(feature = "verify")]
    pub fn verify_pending(
        &mut self,
        cfg: &TrustConfig,
        scheme: &mut dyn crate::auth::AuthScheme,
        keys: &mut dyn crate::auth::KeyStore,
        now_ms: u64,
        unix_ms: Option<u64>,
    ) -> Option<crate::auth::AuthResult> {
        let msg = self.pending.take()?;
        let mut dets = [Det::default(); 2];
        let mut nd = 0;
        for d in self.dets() {
            if nd < 2 {
                dets[nd] = d;
                nd += 1;
            }
        }
        let ctx = crate::auth::AuthContext {
            uas_dets: &dets[..nd],
            recent_messages: &self.recent[..self.nrecent.min(RECENT)],
            recent_hashes: &self.hashes[..self.nhash.min(HASHES)],
            pack_messages: if msg.from_pack {
                &self.pack_msgs[..self.npack]
            } else {
                &[]
            },
            now_unix: unix_ms.map(|u| u / 1000),
            skew_s: cfg.auth_skew_s,
        };
        let result = scheme.verify(&msg, &ctx, keys);
        self.record_auth(&msg, result, now_ms);
        Some(result)
    }

    /// The DRIP authentication state.
    pub fn auth_state(&self) -> AuthState {
        let a = &self.auth;
        if a.invalid > 0 {
            if a.any_trusted {
                AuthState::Conflicting
            } else if a.any_verified {
                AuthState::Questionable
            } else {
                AuthState::Unverified
            }
        } else if a.any_trusted {
            AuthState::Trusted
        } else if a.any_verified {
            AuthState::Verified
        } else if a.unverifiable > 0 || a.valid > 0 || (a.complete > 0 && a.unsupported == 0) {
            AuthState::Unverifiable
        } else if a.unsupported > 0 {
            AuthState::Unsupported
        } else if a.pages > 0 {
            AuthState::Partial
        } else {
            AuthState::None
        }
    }

    /// The current assessment at receiver time `now_ms`.
    pub fn assessment(&self, cfg: &TrustConfig, now_ms: u64) -> Assessment {
        let mut reasons = ReasonSet::default();
        for &r in Reason::ALL {
            if self.active(r, cfg, now_ms) {
                reasons.insert(r);
            }
        }
        let strong = reasons.count(Severity::Strong);
        let moderate = reasons.count(Severity::Moderate);
        let weak = reasons.count(Severity::Weak);
        let auth = self.auth_state();
        let fresh =
            |t: Option<u64>| t.is_some_and(|t| now_ms.saturating_sub(t) <= cfg.auth_fresh_ms);
        let authenticated = match auth {
            AuthState::Trusted => fresh(self.auth.trusted_ms),
            AuthState::Verified => cfg.accept_self_certified && fresh(self.auth.verified_ms),
            _ => false,
        };
        let mut score: f32 =
            0.5 - 0.4 * strong as f32 - 0.15 * moderate as f32 - 0.05 * weak as f32;
        if authenticated {
            score += 0.5;
        } else if matches!(auth, AuthState::Verified | AuthState::Trusted) {
            score += 0.2;
        }
        let verdict = if strong > 0 || moderate >= 3 {
            Verdict::Spoofed
        } else if moderate > 0 || weak >= 2 {
            Verdict::Suspicious
        } else if authenticated {
            Verdict::Authenticated
        } else {
            Verdict::Plausible
        };
        Assessment {
            verdict,
            score: score.clamp(0.0, 1.0),
            reasons,
            spoofer: if reasons.contains(Reason::KnownSpoofer) {
                self.spoofer
            } else {
                None
            },
            auth,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BasicId, Location, MessagePackBuilder, UaType};

    fn loc(lat: f64, lon: f64, speed: f32, dir: f32, ts: f32) -> [u8; 25] {
        Message::Location(Location {
            latitude: lat,
            longitude: lon,
            speed_horizontal: Some(speed),
            direction: Some(dir),
            altitude_geo: Some(100.0),
            timestamp: Some(ts),
            horizontal_accuracy: crate::HorizontalAccuracy(10),
            ..Location::default()
        })
        .encode()
        .unwrap()
    }

    #[test]
    fn steady_flight_is_plausible() {
        let cfg = TrustConfig::default();
        let mut st = TrustState::new();
        let id = Message::BasicId(
            BasicId::new(
                IdType::SerialNumber,
                UaType::HelicopterOrMultirotor,
                "1596F35074529ABCDEFG",
            )
            .unwrap(),
        )
        .encode()
        .unwrap();
        // 10 m/s due north, one fix per second.
        let mut a = Assessment::default();
        for i in 0..30u64 {
            let lat = 47.0 + (10.0 * i as f64) / 111_195.0;
            let mut b = MessagePackBuilder::new();
            b.push_raw(&id).unwrap();
            b.push_raw(&loc(lat, 8.0, 10.0, 0.0, 600.0 + i as f32))
                .unwrap();
            let obs = Observation::new(
                Transport::Bluetooth5,
                Some(i as u8),
                b.as_bytes(),
                1_000 * i,
            );
            a = st.observe(&cfg, &obs);
        }
        assert_eq!(a.verdict, Verdict::Plausible, "{:?}", a.reasons);
        assert!(a.reasons.is_empty(), "{:?}", a.reasons);
    }

    #[test]
    fn teleport_and_lies_are_caught() {
        let cfg = TrustConfig::default();
        let mut st = TrustState::new();
        let mut a = Assessment::default();
        for i in 0..20u64 {
            // Jumps 2 km east every second while claiming 5 m/s north.
            let lon = 8.0 + (2_000.0 * i as f64) / 75_800.0;
            let raw = loc(47.0, lon, 5.0, 0.0, 600.0 + i as f32);
            let obs = Observation::new(Transport::Bluetooth4, Some(i as u8), &raw, 1_000 * i);
            a = st.observe(&cfg, &obs);
        }
        assert_eq!(a.verdict, Verdict::Spoofed);
        assert!(a.reasons.contains(Reason::Teleport));
        assert!(a.reasons.contains(Reason::ReportedSpeedMismatch));
        assert!(a.reasons.contains(Reason::ReportedCourseMismatch));
    }

    #[test]
    fn counter_reuse_with_new_content_is_a_conflict() {
        let cfg = TrustConfig::default();
        let mut st = TrustState::new();
        let mut a = Assessment::default();
        for i in 0..10u64 {
            for (k, lon) in [(0u8, 8.0), (1, 8.001)] {
                let raw = loc(47.0, lon + i as f64 * 1e-5, 1.0, 90.0, 600.0 + i as f32);
                let obs = Observation::new(
                    Transport::Bluetooth4,
                    Some(i as u8),
                    &raw,
                    1_000 * i + k as u64,
                );
                a = st.observe(&cfg, &obs);
            }
        }
        assert!(
            a.reasons.contains(Reason::CounterConflict),
            "{:?}",
            a.reasons
        );
        assert_eq!(a.verdict, Verdict::Spoofed);
    }

    #[test]
    fn reasons_have_unique_names_and_codes() {
        for (i, r) in Reason::ALL.iter().enumerate() {
            assert_eq!(*r as usize, i);
            assert_eq!(
                Reason::ALL.iter().filter(|o| o.name() == r.name()).count(),
                1
            );
        }
    }
}
