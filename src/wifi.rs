//! Remote ID over Wi-Fi: Beacon vendor elements and NAN action frames.
//!
//! * **Wi-Fi Beacon** (F3411-22a, EN 4709-002): a vendor specific element
//!   (ID 221) with the ASD-STAN OUI `FA:0B:BC`, OUI type `0x0D`, a message
//!   counter and a message pack. [`find_in_elements`] finds it in an element
//!   list, [`parse_frame`] in a whole management frame.
//! * **Wi-Fi NAN** (Neighbor Awareness Networking): a public action frame to
//!   `51:6F:9A:01:00:00` whose Service Descriptor Attribute has the service
//!   ID of `"org.opendroneid.remoteid"` and carries the counter and pack as
//!   service info. [`parse_frame`] handles it.
//!
//! Captures from monitor mode usually start with a radiotap header; strip it
//! with [`strip_radiotap`] first (it also drops a trailing FCS).

use crate::{Error, Frame};

/// ASD-STAN OUI used in Beacon vendor elements.
pub const ASD_STAN_OUI: [u8; 3] = [0xFA, 0x0B, 0xBC];
/// OUI type of the Remote ID vendor element.
pub const ASD_STAN_OUI_TYPE: u8 = 0x0D;
/// Wi-Fi Alliance OUI used by NAN.
pub const WFA_OUI: [u8; 3] = [0x50, 0x6F, 0x9A];
/// OUI type for NAN.
pub const NAN_OUI_TYPE: u8 = 0x13;
/// NAN service ID for Remote ID (hash of `"org.opendroneid.remoteid"`).
pub const NAN_SERVICE_ID: [u8; 6] = [0x88, 0x69, 0x19, 0x9D, 0x92, 0x09];
/// Element ID of vendor specific elements.
pub const ELEMENT_VENDOR: u8 = 221;

/// How the Remote ID data reached us.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WifiKind {
    /// Beacon (or probe response) vendor element.
    Beacon,
    /// NAN service discovery action frame.
    Nan,
}

/// The Remote ID part of one Wi-Fi frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WifiRemoteId<'a> {
    /// Beacon or NAN.
    pub kind: WifiKind,
    /// Transmitter address (all zero when only an element list was parsed).
    pub source: [u8; 6],
    /// Message counter set by the transmitter.
    pub counter: u8,
    /// The message pack, starting at its header byte.
    pub payload: &'a [u8],
}

impl<'a> WifiRemoteId<'a> {
    /// Decodes the payload.
    pub fn frame(&self) -> Result<Frame<'a>, Error> {
        Frame::decode(self.payload)
    }
}

/// Iterates over 802.11 information elements as `(id, data)`. Stops at an
/// element that runs past the end, so trailing bytes such as an FCS are
/// harmless.
pub fn elements(ies: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut rest = ies;
    core::iter::from_fn(move || {
        if rest.len() < 2 || rest.len() < 2 + rest[1] as usize {
            rest = &[];
            return None;
        }
        let len = rest[1] as usize;
        let item = (rest[0], &rest[2..2 + len]);
        rest = &rest[2 + len..];
        Some(item)
    })
}

/// Finds the ASD-STAN Remote ID vendor element in an element list (the part
/// of a Beacon or probe response after the fixed fields; Linux `nl80211`
/// scan results and ESP32 promiscuous callbacks give you this).
pub fn find_in_elements(ies: &[u8]) -> Option<WifiRemoteId<'_>> {
    elements(ies).find_map(|(id, d)| {
        if id == ELEMENT_VENDOR
            && d.len() >= 6
            && d[..3] == ASD_STAN_OUI
            && d[3] == ASD_STAN_OUI_TYPE
        {
            Some(WifiRemoteId {
                kind: WifiKind::Beacon,
                source: [0; 6],
                counter: d[4],
                payload: &d[5..],
            })
        } else {
            None
        }
    })
}

/// Parses a raw 802.11 management frame (no radiotap header) and returns
/// its Remote ID payload, from either a Beacon / probe response element or
/// a NAN service discovery frame.
pub fn parse_frame(frame: &[u8]) -> Result<WifiRemoteId<'_>, Error> {
    if frame.len() < 24 {
        return Err(Error::TooShort {
            need: 24,
            got: frame.len(),
        });
    }
    let fc = frame[0];
    if (fc >> 2) & 0x03 != 0 {
        return Err(Error::NotRemoteId); // not a management frame
    }
    let mut source = [0u8; 6];
    source.copy_from_slice(&frame[10..16]);
    let body = &frame[24..];
    match fc >> 4 {
        // Beacon (8) and probe response (5): 12 fixed bytes, then elements.
        8 | 5 => {
            if body.len() < 12 {
                return Err(Error::TooShort {
                    need: 36,
                    got: frame.len(),
                });
            }
            let mut rid = find_in_elements(&body[12..]).ok_or(Error::NotRemoteId)?;
            rid.source = source;
            Ok(rid)
        }
        // Action (13) and action no-ack (14).
        13 | 14 => {
            let mut rid = parse_nan_action(body)?;
            rid.source = source;
            Ok(rid)
        }
        _ => Err(Error::NotRemoteId),
    }
}

/// Parses the body of a NAN service discovery public action frame (the part
/// after the 24 byte management header).
pub fn parse_nan_action(body: &[u8]) -> Result<WifiRemoteId<'_>, Error> {
    if body.len() < 6 {
        return Err(Error::TooShort {
            need: 6,
            got: body.len(),
        });
    }
    // Public action (4), vendor specific (9), Wi-Fi Alliance OUI, NAN type.
    if body[0] != 0x04 || body[1] != 0x09 || body[2..5] != WFA_OUI || body[5] != NAN_OUI_TYPE {
        return Err(Error::NotRemoteId);
    }
    let mut rest = &body[6..];
    while rest.len() >= 3 {
        let id = rest[0];
        let len = u16::from_le_bytes([rest[1], rest[2]]) as usize;
        if rest.len() < 3 + len {
            break;
        }
        let attr = &rest[3..3 + len];
        rest = &rest[3 + len..];
        if id != 0x03 || attr.len() < 9 || attr[..6] != NAN_SERVICE_ID {
            continue;
        }
        if let Some(info) = sda_service_info(attr) {
            if info.len() < 2 {
                return Err(Error::TooShort {
                    need: 2,
                    got: info.len(),
                });
            }
            return Ok(WifiRemoteId {
                kind: WifiKind::Nan,
                source: [0; 6],
                counter: info[0],
                payload: &info[1..],
            });
        }
    }
    Err(Error::NotRemoteId)
}

/// Returns the service info field of a Service Descriptor Attribute body.
fn sda_service_info(attr: &[u8]) -> Option<&[u8]> {
    let control = attr[8];
    let mut at = 9;
    if control & 0x40 != 0 {
        at += 2; // binding bitmap
    }
    for bit in [0x04u8, 0x08] {
        // matching filter, service response filter
        if control & bit != 0 {
            let l = *attr.get(at)? as usize;
            at += 1 + l;
        }
    }
    if control & 0x10 == 0 {
        return None;
    }
    let l = *attr.get(at)? as usize;
    attr.get(at + 1..at + 1 + l)
}

/// Strips a radiotap header, and the trailing FCS if radiotap says one is
/// present. Returns the bare 802.11 frame.
pub fn strip_radiotap(data: &[u8]) -> Result<&[u8], Error> {
    if data.len() < 8 {
        return Err(Error::TooShort {
            need: 8,
            got: data.len(),
        });
    }
    if data[0] != 0 {
        return Err(Error::NotRemoteId);
    }
    let hlen = u16::from_le_bytes([data[2], data[3]]) as usize;
    if hlen < 8 || data.len() < hlen {
        return Err(Error::TooShort {
            need: hlen.max(8),
            got: data.len(),
        });
    }
    let present = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    // Skip extended presence words.
    let mut at = 8;
    let mut word = present;
    while word & 0x8000_0000 != 0 && at + 4 <= hlen {
        word = u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]);
        at += 4;
    }
    let mut fcs = false;
    if present & 0x02 != 0 {
        if present & 0x01 != 0 {
            at = (at + 7) & !7; // TSFT is 8 byte aligned
            at += 8;
        }
        if let Some(&flags) = data.get(at).filter(|_| at < hlen) {
            fcs = flags & 0x10 != 0;
        }
    }
    let frame = &data[hlen..];
    if fcs && frame.len() >= 4 {
        Ok(&frame[..frame.len() - 4])
    } else {
        Ok(frame)
    }
}

/// Builds the Beacon vendor element (ID, length, OUI, type, counter, pack)
/// into `out` and returns its length. Add it to the element list of your
/// beacon frame.
pub fn write_beacon_element(counter: u8, pack: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let len = 3 + 1 + 1 + pack.len();
    if len > 255 {
        return Err(Error::OutOfRange("pack"));
    }
    let need = 2 + len;
    if out.len() < need {
        return Err(Error::BufferTooSmall {
            need,
            got: out.len(),
        });
    }
    out[0] = ELEMENT_VENDOR;
    out[1] = len as u8;
    out[2..5].copy_from_slice(&ASD_STAN_OUI);
    out[5] = ASD_STAN_OUI_TYPE;
    out[6] = counter;
    out[7..need].copy_from_slice(pack);
    Ok(need)
}
