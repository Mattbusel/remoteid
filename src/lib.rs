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
//! Authentication signatures are reassembled but not verified: verification
//! depends on the key scheme the operator uses, which the standard leaves open.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod ble;
mod error;
pub mod france;
mod message;
mod pack;
#[cfg(feature = "std")]
mod tracker;
mod uas;
pub mod wifi;

pub use error::Error;
pub use message::*;
pub use pack::{MessagePack, MessagePackBuilder, PACK_MAX_MESSAGES};
#[cfg(feature = "std")]
pub use tracker::{CounterStats, TrackedUas, Tracker, TrackerConfig, Transmitter};
pub use uas::UasData;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

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
