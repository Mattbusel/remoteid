//! The merged state of one aircraft.

use crate::operator::OperatorIdentity;
use crate::{Auth, BasicId, Frame, IdType, Location, Message, OperatorId, SelfId, System};

/// Basic ID slots kept per aircraft (the reference library keeps 2: for
/// example a serial number and a CAA registration ID).
pub const BASIC_ID_SLOTS: usize = 2;
/// Authentication pages kept per aircraft.
pub const AUTH_PAGES: usize = 16;

/// Everything known about one aircraft, built up from its messages.
///
/// Each message replaces the previous one of its kind. Basic ID messages
/// fill one slot per ID type; Auth pages fill the slot of their page number.
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UasData {
    /// Basic ID messages, one per ID type.
    pub basic_id: [Option<BasicId>; BASIC_ID_SLOTS],
    /// Latest Location message.
    pub location: Option<Location>,
    /// Authentication pages by page number.
    pub auth: [Option<Auth>; AUTH_PAGES],
    /// Latest Self ID message.
    pub self_id: Option<SelfId>,
    /// Latest System message.
    pub system: Option<System>,
    /// Latest Operator ID message.
    pub operator_id: Option<OperatorId>,
}

impl UasData {
    /// Merges one message. Returns `false` only for a Basic ID message that
    /// found no free slot (both slots hold other ID types).
    pub fn update(&mut self, msg: &Message) -> bool {
        match msg {
            Message::BasicId(b) => {
                let slot = self
                    .basic_id
                    .iter()
                    .position(|s| s.as_ref().is_some_and(|s| s.id_type == b.id_type))
                    .or_else(|| {
                        self.basic_id
                            .iter()
                            .position(|s| s.as_ref().map_or(true, |s| s.id_type == IdType::None))
                    });
                match slot {
                    Some(i) => {
                        self.basic_id[i] = Some(b.clone());
                        true
                    }
                    None => false,
                }
            }
            Message::Location(l) => {
                self.location = Some(l.clone());
                true
            }
            Message::Auth(a) => {
                self.auth[a.page as usize & 0x0F] = Some(a.clone());
                true
            }
            Message::SelfId(s) => {
                self.self_id = Some(s.clone());
                true
            }
            Message::System(s) => {
                self.system = Some(s.clone());
                true
            }
            Message::OperatorId(o) => {
                self.operator_id = Some(o.clone());
                true
            }
        }
    }

    /// Merges every message of a frame. Returns how many were merged.
    pub fn update_frame(&mut self, frame: &Frame<'_>) -> usize {
        let mut n = 0;
        frame.for_each_message(|m| n += self.update(&m) as usize);
        n
    }

    /// The first Basic ID that carries a text identifier.
    pub fn primary_id(&self) -> Option<&str> {
        self.basic_id
            .iter()
            .flatten()
            .find_map(|b| b.uas_id_str().filter(|s| !s.is_empty()))
    }

    /// Where the aircraft launched from, when the System message reports its
    /// operator position as the takeoff point. See
    /// [`System::takeoff_position`].
    pub fn takeoff_position(&self) -> Option<(f64, f64)> {
        self.system.as_ref()?.takeoff_position()
    }

    /// The operator's live position (where the pilot is now), when the System
    /// message reports a live GNSS operator position. See
    /// [`System::live_operator_position`].
    pub fn pilot_position(&self) -> Option<(f64, f64)> {
        self.system.as_ref()?.live_operator_position()
    }

    /// The operator identity resolved from the Operator ID message: the
    /// registering country and the clean registration string. See
    /// [`OperatorId::identity`].
    pub fn operator_identity(&self) -> Option<OperatorIdentity<'_>> {
        self.operator_id.as_ref()?.identity()
    }

    /// Joins the authentication pages into `out` once page 0 and every page
    /// up to its last page index have arrived (all with the same auth type).
    ///
    /// Returns the number of bytes written: the announced length, plus any
    /// trailing forward error correction bytes the standard allows after a
    /// length byte, as described in F3411-22a. Returns `None` while pages are
    /// missing or when `out` is too small.
    pub fn auth_data(&self, out: &mut [u8]) -> Option<usize> {
        let first = self.auth[0].as_ref()?;
        let last = first.last_page_index as usize;
        if last >= AUTH_PAGES {
            return None;
        }
        let mut written = 0;
        #[allow(clippy::needless_range_loop)]
        for page in 0..=last {
            let p = self.auth[page].as_ref()?;
            if p.auth_type != first.auth_type {
                return None;
            }
            let data = p.page_data();
            let n = data.len().min(out.len() - written);
            out[written..written + n].copy_from_slice(&data[..n]);
            written += n;
        }
        let length = first.length as usize;
        if written < length {
            return None;
        }
        // Extra (FEC) bytes: the byte after the data says how many follow.
        let extra = out.get(length).copied().unwrap_or(0) as usize;
        let total = if extra > 0 {
            (length + 1 + extra).min(written)
        } else {
            length
        };
        Some(total)
    }

    /// `true` if no message has been merged.
    pub fn is_empty(&self) -> bool {
        self.basic_id.iter().all(Option::is_none)
            && self.location.is_none()
            && self.auth.iter().all(Option::is_none)
            && self.self_id.is_none()
            && self.system.is_none()
            && self.operator_id.is_none()
    }
}
