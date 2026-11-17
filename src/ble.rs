//! Remote ID over Bluetooth: Service Data with UUID 0xFFFA.
//!
//! Both Bluetooth 4 legacy advertising (one 25 byte message per
//! advertisement) and Bluetooth 5 extended or long range advertising (a
//! message pack) carry Remote ID as an AD structure of type 0x16 (Service
//! Data, 16-bit UUID) with the ASTM UUID 0xFFFA, followed by the application
//! code 0x0D and a one byte message counter.
//!
//! * If your Bluetooth stack hands you the raw advertising data, use
//!   [`find_in_advertising_data`].
//! * If it hands you service data already split by UUID (as `btleplug`,
//!   BlueZ D-Bus and Android do), pass the bytes for UUID 0xFFFA to
//!   [`parse_service_data`].

use crate::{Error, Frame};

/// The ASTM Remote ID 16-bit service UUID.
pub const SERVICE_UUID: u16 = 0xFFFA;
/// Application code that follows the UUID.
pub const APP_CODE: u8 = 0x0D;
/// AD type for Service Data with a 16-bit UUID.
pub const AD_TYPE_SERVICE_DATA_16: u8 = 0x16;

/// The Remote ID part of one advertisement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BleRemoteId<'a> {
    /// Message counter set by the transmitter.
    pub counter: u8,
    /// The message or message pack, starting at its header byte.
    pub payload: &'a [u8],
}

impl<'a> BleRemoteId<'a> {
    /// Decodes the payload.
    pub fn frame(&self) -> Result<Frame<'a>, Error> {
        Frame::decode(self.payload)
    }
}

/// Parses service data for UUID 0xFFFA, starting at the application code.
pub fn parse_service_data(data: &[u8]) -> Result<BleRemoteId<'_>, Error> {
    if data.len() < 3 {
        return Err(Error::TooShort {
            need: 3,
            got: data.len(),
        });
    }
    if data[0] != APP_CODE {
        return Err(Error::NotRemoteId);
    }
    Ok(BleRemoteId {
        counter: data[1],
        payload: &data[2..],
    })
}

/// Iterates over the AD structures of advertising data as `(type, data)`.
/// Stops at a zero length byte or at a structure that runs past the end.
pub fn ad_structures(adv: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    let mut rest = adv;
    core::iter::from_fn(move || {
        let len = *rest.first()? as usize;
        if len == 0 || rest.len() < 1 + len {
            rest = &[];
            return None;
        }
        let item = (rest[1], &rest[2..1 + len]);
        rest = &rest[1 + len..];
        Some(item)
    })
}

/// Finds the Remote ID service data in raw advertising data.
pub fn find_in_advertising_data(adv: &[u8]) -> Option<BleRemoteId<'_>> {
    ad_structures(adv).find_map(|(t, d)| {
        if t == AD_TYPE_SERVICE_DATA_16
            && d.len() >= 2
            && u16::from_le_bytes([d[0], d[1]]) == SERVICE_UUID
        {
            parse_service_data(&d[2..]).ok()
        } else {
            None
        }
    })
}

/// Writes the Remote ID AD structure (length, type, UUID, app code,
/// counter, payload) into `out` and returns its length.
///
/// For Bluetooth 4 legacy advertising, pass one 25 byte message; the
/// result is 31 bytes, the whole legacy advertising payload. For Bluetooth 5
/// pass a message pack.
pub fn write_advertising_data(counter: u8, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let len = 1 + 2 + 1 + 1 + payload.len();
    if len > 255 {
        return Err(Error::OutOfRange("payload"));
    }
    let need = 1 + len;
    if out.len() < need {
        return Err(Error::BufferTooSmall {
            need,
            got: out.len(),
        });
    }
    out[0] = len as u8;
    out[1] = AD_TYPE_SERVICE_DATA_16;
    out[2..4].copy_from_slice(&SERVICE_UUID.to_le_bytes());
    out[4] = APP_CODE;
    out[5] = counter;
    out[6..need].copy_from_slice(payload);
    Ok(need)
}
