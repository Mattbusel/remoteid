//! Drone Remote ID in pure Rust.
//!
//! `remoteid` decodes and encodes the broadcast Remote ID messages defined by
//! ASTM F3411-22a and ASD-STAN EN 4709-002 (the format the
//! [Open Drone ID](https://github.com/opendroneid) project implements in C),
//! and pulls them out of the frames receivers actually see:
//!
//! * Bluetooth 4 legacy advertising and Bluetooth 5 extended / long range
//!   advertising ([`ble`]),
//! * Wi-Fi Beacon vendor elements and Wi-Fi NAN service discovery frames
//!   ([`wifi`]), with or without a radiotap header,
//! * the French "signalement electronique" beacon format ([`france`]).
//!
//! Decoded messages can be merged into one record per aircraft ([`UasData`]),
//! and with the `std` feature a [`Tracker`] keeps those records per
//! transmitter, counts duplicate and missed frames from the message counters,
//! and expires aircraft that went quiet.
//!
//! The crate has no dependencies and works in `no_std` (turn off the default
//! `std` feature). It never allocates outside the `std`-only [`Tracker`].
//!
//! # Example
//!
//! ```
//! use remoteid::{ble, Frame, Message, UasData};
//!
//! // Bluetooth advertising data from a scanner (one AD structure, BT4 legacy).
//! let adv = [
//!     0x1e, 0x16, 0xfa, 0xff, 0x0d, 0x07, // length, service data, UUID 0xFFFA, app code, counter
//!     0x02, 0x12, b'1', b'5', b'9', b'6', b'F', b'3', b'5', b'0', b'7', b'4', b'5', b'2',
//!     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//! ];
//! let rid = ble::find_in_advertising_data(&adv).expect("Remote ID service data");
//! let mut uas = UasData::default();
//! match rid.frame().unwrap() {
//!     Frame::Message(Message::BasicId(id)) => {
//!         assert_eq!(id.uas_id_str(), Some("1596F3507452"));
//!         uas.update(&Message::BasicId(id));
//!     }
//!     other => panic!("unexpected {other:?}"),
//! }
//! assert!(uas.basic_id[0].is_some());
//! ```
//!
//! # Accuracy and limits
//!
//! Decoding follows the reference C library bit for bit; the test suite
//! compares every message in the public Open Drone ID sample captures against
//! that library's output. Encoding quantizes the same way the C library does,
//! so `decode(encode(x))` is exact for values on the transmitted grid.
//! Authentication pages are reassembled for every scheme; the [`drip`]
//! module parses the DRIP formats of RFC 9575 and, with the `verify`
//! feature, [`auth`] checks their Ed25519 signatures. Other schemes plug in
//! through `auth::AuthScheme`.
//!
//! # Trust
//!
//! Remote ID has no authentication in most deployed aircraft, and spoofers
//! are a few lines of Python. [`trust`] turns decoded frames into a graded
//! [`Verdict`] (`Authenticated`, `Plausible`, `Suspicious`, `Spoofed`) with
//! the reasons behind it: kinematic plausibility, timestamp and counter
//! continuity, Wi-Fi TSF behaviour, agreement between transports and
//! transmitters, fingerprints of public spoofing tools, and DRIP
//! signatures. The verdict is advice for a detector, not a filter: nothing
//! is dropped.
//!
//! [`ridf`] defines RIDF v0, a small record format for raw frames with
//! receiver time, signal strength and receiver position, and
//! [`aircraft_json`] writes `aircraft.json` in the readsb schema so tar1090
//! can show drones next to aircraft.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "std")]
pub mod aircraft_json;
#[cfg(feature = "verify")]
pub mod auth;
pub mod ble;
pub mod drip;
mod error;
pub mod france;
pub mod geo;
mod message;
mod pack;
pub mod ridf;
#[cfg(feature = "std")]
mod tracker;
pub mod trust;
mod uas;
pub mod wifi;

pub use error::Error;
pub use message::*;
pub use pack::{MessagePack, MessagePackBuilder, PACK_MAX_MESSAGES};
#[cfg(feature = "std")]
pub use tracker::{CounterStats, TrackedUas, Tracker, TrackerConfig};
pub use trust::{Assessment, Observation, Reason, TrustConfig, TrustState, Verdict};
pub use uas::UasData;

/// Who sent a frame. Receivers key aircraft by the radio address, because
/// that is the only thing every frame of one transmitter shares before its
/// Basic ID has been heard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Transmitter {
    /// Bluetooth advertiser address.
    Ble([u8; 6]),
    /// Wi-Fi transmitter address.
    Wifi([u8; 6]),
    /// Anything else (for example a MAVLink system ID), chosen by the caller.
    Other(u64),
}

/// The radio link a Remote ID frame arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Transport {
    /// Not known.
    #[default]
    Unknown = 0,
    /// Bluetooth 4 legacy advertising (one message per frame).
    Bluetooth4 = 1,
    /// Bluetooth 5 extended or long range advertising (message packs).
    Bluetooth5 = 2,
    /// Wi-Fi Beacon vendor element.
    WifiBeacon = 3,
    /// Wi-Fi NAN service discovery.
    WifiNan = 4,
    /// Another source chosen by the caller (for example a serial dongle).
    Other = 5,
}

impl Transport {
    /// All values, in code order.
    pub const ALL: [Transport; 6] = [
        Transport::Unknown,
        Transport::Bluetooth4,
        Transport::Bluetooth5,
        Transport::WifiBeacon,
        Transport::WifiNan,
        Transport::Other,
    ];

    /// The numeric code used in RIDF records.
    pub fn code(self) -> u8 {
        self as u8
    }

    /// Inverse of [`Transport::code`]; unknown codes map to `Unknown`.
    pub fn from_code(c: u8) -> Transport {
        Transport::ALL
            .get(c as usize)
            .copied()
            .unwrap_or(Transport::Unknown)
    }

    /// Short lower case name (`bt4`, `bt5`, `wifi_beacon`, `wifi_nan`,
    /// `other`, `unknown`).
    pub fn name(self) -> &'static str {
        match self {
            Transport::Unknown => "unknown",
            Transport::Bluetooth4 => "bt4",
            Transport::Bluetooth5 => "bt5",
            Transport::WifiBeacon => "wifi_beacon",
            Transport::WifiNan => "wifi_nan",
            Transport::Other => "other",
        }
    }

    /// Parses [`Transport::name`] output.
    pub fn from_name(s: &str) -> Option<Transport> {
        Transport::ALL.iter().copied().find(|t| t.name() == s)
    }
}

impl core::fmt::Display for Transport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

#[cfg(all(doctest, feature = "std"))]
#[doc = include_str!("../docs/integration.md")]
struct IntegrationDoctests;

/// Size in bytes of every single Remote ID message.
pub const MESSAGE_SIZE: usize = 25;

/// Protocol version this crate writes when encoding (2 = ASTM F3411-22a).
///
/// Decoding accepts every version: the standard keeps newer versions
/// backward compatible, so fields added later simply read as unset.
pub const PROTOCOL_VERSION: u8 = 2;

/// A decoded Remote ID payload: either one message or a message pack.
#[derive(Debug, Clone, PartialEq)]
pub enum Frame<'a> {
    /// A single 25 byte message (Bluetooth 4 legacy advertising carries these).
    Message(Message),
    /// A message pack (Bluetooth 5 and Wi-Fi carry these).
    Pack(MessagePack<'a>),
}

impl<'a> Frame<'a> {
    /// Decodes a Remote ID payload that starts with the message header byte.
    ///
    /// A payload whose header says "message pack" (type 0xF) is parsed as a
    /// pack; anything else must be at least [`MESSAGE_SIZE`] bytes and is
    /// decoded as a single message.
    pub fn decode(payload: &'a [u8]) -> Result<Self, Error> {
        let first = *payload.first().ok_or(Error::TooShort { need: 1, got: 0 })?;
        if first >> 4 == 0xF {
            MessagePack::parse(payload).map(Frame::Pack)
        } else {
            Message::decode(payload).map(Frame::Message)
        }
    }

    /// Calls `f` for every message in this frame (one for a single message,
    /// each valid one for a pack).
    pub fn for_each_message(&self, mut f: impl FnMut(Message)) {
        match self {
            Frame::Message(m) => f(m.clone()),
            Frame::Pack(p) => p.messages().filter_map(Result::ok).for_each(f),
        }
    }
}
