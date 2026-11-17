//! The French "signalement electronique" beacon (arrete of 27 December 2019).
//!
//! French law required this Wi-Fi beacon before EU Remote ID; many older
//! modules still send it alongside or instead of ASTM Remote ID. It is a
//! vendor specific element with OUI `6A:5C:35`, type `0x01`, holding
//! type-length-value records with big-endian numbers.

use crate::wifi::{elements, ELEMENT_VENDOR};

/// OUI of the French beacon element.
pub const OUI: [u8; 3] = [0x6A, 0x5C, 0x35];
/// OUI type of the French beacon element.
pub const OUI_TYPE: u8 = 0x01;

/// A decoded French beacon. Fields not present in the frame are `None`.
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FrenchBeacon {
    /// Protocol version (1).
    pub version: Option<u8>,
    /// 30 character French identifier, NUL padded.
    pub identifier: Option<[u8; 30]>,
    /// ANSI/CTA-2063 physical serial number, if sent (at most 32 bytes kept).
    pub serial: Option<([u8; 32], u8)>,
    /// Latitude in degrees (1e-5 degree steps).
    pub latitude: Option<f64>,
    /// Longitude in degrees.
    pub longitude: Option<f64>,
    /// Altitude above mean sea level in meters.
    pub altitude: Option<i16>,
    /// Height above takeoff in meters.
    pub height: Option<i16>,
    /// Takeoff latitude in degrees.
    pub takeoff_latitude: Option<f64>,
    /// Takeoff longitude in degrees.
    pub takeoff_longitude: Option<f64>,
    /// Horizontal speed in m/s.
    pub horizontal_speed: Option<u8>,
    /// True course in degrees.
    pub true_course: Option<u16>,
}

impl FrenchBeacon {
    /// Decodes the element body after the OUI type byte.
    pub fn decode(tlvs: &[u8]) -> Self {
        let mut out = FrenchBeacon::default();
        let mut rest = tlvs;
        while rest.len() >= 2 && rest.len() >= 2 + rest[1] as usize {
            let (t, l) = (rest[0], rest[1] as usize);
            let v = &rest[2..2 + l];
            rest = &rest[2 + l..];
            let be_i32 =
                || (l == 4).then(|| i32::from_be_bytes([v[0], v[1], v[2], v[3]]) as f64 * 1e-5);
            let be_i16 = || (l == 2).then(|| i16::from_be_bytes([v[0], v[1]]));
            match t {
                1 if l == 1 => out.version = Some(v[0]),
                2 if l == 30 => {
                    let mut id = [0u8; 30];
                    id.copy_from_slice(v);
                    out.identifier = Some(id);
                }
                3 => {
                    let mut s = [0u8; 32];
                    let n = l.min(32);
                    s[..n].copy_from_slice(&v[..n]);
                    out.serial = Some((s, n as u8));
                }
                4 => out.latitude = be_i32(),
                5 => out.longitude = be_i32(),
                6 => out.altitude = be_i16(),
                7 => out.height = be_i16(),
                8 => out.takeoff_latitude = be_i32(),
                9 => out.takeoff_longitude = be_i32(),
                10 if l == 1 => out.horizontal_speed = Some(v[0]),
                11 if l == 2 => out.true_course = Some(u16::from_be_bytes([v[0], v[1]])),
                _ => {}
            }
        }
        out
    }

    /// The identifier as text.
    pub fn identifier_str(&self) -> Option<&str> {
        let id = self.identifier.as_ref()?;
        let end = id.iter().position(|&b| b == 0).unwrap_or(id.len());
        core::str::from_utf8(&id[..end]).ok()
    }

    /// The serial number as text.
    pub fn serial_str(&self) -> Option<&str> {
        let (s, n) = self.serial.as_ref()?;
        core::str::from_utf8(&s[..*n as usize]).ok()
    }
}

/// Finds and decodes a French beacon element in an 802.11 element list.
pub fn find_in_elements(ies: &[u8]) -> Option<FrenchBeacon> {
    elements(ies).find_map(|(id, d)| {
        (id == ELEMENT_VENDOR && d.len() >= 4 && d[..3] == OUI && d[3] == OUI_TYPE)
            .then(|| FrenchBeacon::decode(&d[4..]))
    })
}
