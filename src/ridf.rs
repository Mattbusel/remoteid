//! RIDF v0: a record format for raw Remote ID frames as a receiver saw
//! them.
//!
//! Multi-receiver checks (does the signal strength fit the claimed
//! position? did two receivers hear the same frame?) need more than the
//! decoded fields: the raw message, when it arrived, how strong it was,
//! which link it came on, and where the receiver was. RIDF carries exactly
//! that, one record per frame, so receivers written in any language can
//! feed one trust engine. The byte layout is in `docs/ridf.md`; all
//! integers are little endian.
//!
//! ```text
//!  0  u16  record length (bytes after this field)
//!  2  u8   version (0)
//!  3  u8   transport (crate::Transport code)
//!  4  u8   flags
//!  5  u8   message counter
//!  6  u64  receiver time, nanoseconds
//! 14  i8   RSSI, dBm
//! 15  u8   payload length
//! 16  [6]  transmitter address
//! 22  u16  receiver ID
//! 24  i32  receiver latitude, 1e-7 degrees
//! 28  i32  receiver longitude, 1e-7 degrees
//! 32  i32  receiver altitude, millimeters (WGS84)
//! 36  ...  payload: F3411 message or message pack, header byte first
//!     ...  extensions: type u8, length u8, value
//! ```
//!
//! A file is the 8 byte [`FILE_HEADER`] followed by records. A single
//! record (for example one UDP datagram) needs no file header.

use crate::trust::Observation;
use crate::wifi::BeaconInfo;
use crate::{Error, Transmitter, Transport};

/// Format version written by this crate.
pub const VERSION: u8 = 0;
/// Optional start of a RIDF file: `RIDF`, version, three zero bytes.
pub const FILE_HEADER: [u8; 8] = [b'R', b'I', b'D', b'F', VERSION, 0, 0, 0];
/// Size of the fixed part of a record, length field included.
pub const FIXED_SIZE: usize = 36;

/// Flag: the RSSI byte is valid.
pub const FLAG_RSSI: u8 = 0x01;
/// Flag: the receiver position fields are valid.
pub const FLAG_POSITION: u8 = 0x02;
/// Flag: the counter byte is valid.
pub const FLAG_COUNTER: u8 = 0x04;
/// Flag: the address field is valid.
pub const FLAG_ADDRESS: u8 = 0x08;
/// Flag: the receiver time is UTC (nanoseconds since the Unix epoch);
/// otherwise it is a monotonic clock with an arbitrary origin.
pub const FLAG_UTC: u8 = 0x10;

/// Extension type: Wi-Fi Beacon header (TSF u64, interval u16, capability
/// u16, sequence u16, then the SSID).
pub const EXT_BEACON: u8 = 0x01;

/// Where the receiver was.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ReceiverPosition {
    /// Latitude, degrees.
    pub latitude: f64,
    /// Longitude, degrees.
    pub longitude: f64,
    /// Altitude above the WGS84 ellipsoid, meters.
    pub altitude_m: f64,
}

/// One RIDF record.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Record<'a> {
    /// Link the frame came on.
    pub transport: Transport,
    /// Message counter of the frame.
    pub counter: Option<u8>,
    /// Receiver time in nanoseconds (UTC if `utc`).
    pub rx_time_ns: u64,
    /// `rx_time_ns` counts from the Unix epoch.
    pub utc: bool,
    /// Signal strength, dBm.
    pub rssi_dbm: Option<i8>,
    /// Transmitter address as it appears on the air (Bluetooth addresses in
    /// the usual most-significant-first text order).
    pub address: Option<[u8; 6]>,
    /// Which receiver, for multi-receiver setups.
    pub receiver_id: u16,
    /// Receiver position.
    pub receiver: Option<ReceiverPosition>,
    /// The Remote ID payload, header byte first.
    pub payload: &'a [u8],
    /// Raw extension TLVs.
    pub extensions: &'a [u8],
}

impl<'a> Default for Record<'a> {
    fn default() -> Self {
        Record {
            transport: Transport::Unknown,
            counter: None,
            rx_time_ns: 0,
            utc: false,
            rssi_dbm: None,
            address: None,
            receiver_id: 0,
            receiver: None,
            payload: &[],
            extensions: &[],
        }
    }
}

fn e7(v: f64) -> i32 {
    let x = v * 1e7;
    let x = if x >= 0.0 { x + 0.5 } else { x - 0.5 };
    x.clamp(i32::MIN as f64, i32::MAX as f64) as i32
}

impl<'a> Record<'a> {
    /// Decodes one record from the start of `buf`. Returns it and the
    /// number of bytes it used.
    pub fn decode(buf: &'a [u8]) -> Result<(Record<'a>, usize), Error> {
        if buf.len() < FIXED_SIZE {
            return Err(Error::TooShort {
                need: FIXED_SIZE,
                got: buf.len(),
            });
        }
        let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        let total = 2 + len;
        if total < FIXED_SIZE {
            return Err(Error::InvalidPack(
                "RIDF record shorter than its fixed part",
            ));
        }
        if buf.len() < total {
            return Err(Error::TooShort {
                need: total,
                got: buf.len(),
            });
        }
        if buf[2] != VERSION {
            return Err(Error::InvalidPack("unknown RIDF version"));
        }
        let flags = buf[4];
        let plen = buf[15] as usize;
        if FIXED_SIZE + plen > total {
            return Err(Error::InvalidPack("RIDF payload runs past the record"));
        }
        let i32_at = |o: usize| i32::from_le_bytes(buf[o..o + 4].try_into().unwrap());
        let rec = Record {
            transport: Transport::from_code(buf[3]),
            counter: (flags & FLAG_COUNTER != 0).then_some(buf[5]),
            rx_time_ns: u64::from_le_bytes(buf[6..14].try_into().unwrap()),
            utc: flags & FLAG_UTC != 0,
            rssi_dbm: (flags & FLAG_RSSI != 0).then_some(buf[14] as i8),
            address: (flags & FLAG_ADDRESS != 0).then(|| buf[16..22].try_into().unwrap()),
            receiver_id: u16::from_le_bytes([buf[22], buf[23]]),
            receiver: (flags & FLAG_POSITION != 0).then(|| ReceiverPosition {
                latitude: i32_at(24) as f64 / 1e7,
                longitude: i32_at(28) as f64 / 1e7,
                altitude_m: i32_at(32) as f64 / 1000.0,
            }),
            payload: &buf[FIXED_SIZE..FIXED_SIZE + plen],
            extensions: &buf[FIXED_SIZE + plen..total],
        };
        Ok((rec, total))
    }

    /// Bytes [`Record::encode`] writes.
    pub fn encoded_len(&self) -> usize {
        FIXED_SIZE + self.payload.len() + self.extensions.len()
    }

    /// Writes the record into `out` and returns its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len();
        if self.payload.len() > 255 {
            return Err(Error::OutOfRange("payload"));
        }
        if n - 2 > u16::MAX as usize {
            return Err(Error::OutOfRange("extensions"));
        }
        if out.len() < n {
            return Err(Error::BufferTooSmall {
                need: n,
                got: out.len(),
            });
        }
        let mut flags = 0;
        flags |= if self.rssi_dbm.is_some() {
            FLAG_RSSI
        } else {
            0
        };
        flags |= if self.receiver.is_some() {
            FLAG_POSITION
        } else {
            0
        };
        flags |= if self.counter.is_some() {
            FLAG_COUNTER
        } else {
            0
        };
        flags |= if self.address.is_some() {
            FLAG_ADDRESS
        } else {
            0
        };
        flags |= if self.utc { FLAG_UTC } else { 0 };
        out[..2].copy_from_slice(&((n - 2) as u16).to_le_bytes());
        out[2] = VERSION;
        out[3] = self.transport.code();
        out[4] = flags;
        out[5] = self.counter.unwrap_or(0);
        out[6..14].copy_from_slice(&self.rx_time_ns.to_le_bytes());
        out[14] = self.rssi_dbm.unwrap_or(0) as u8;
        out[15] = self.payload.len() as u8;
        out[16..22].copy_from_slice(&self.address.unwrap_or([0; 6]));
        out[22..24].copy_from_slice(&self.receiver_id.to_le_bytes());
        let p = self.receiver.unwrap_or(ReceiverPosition {
            latitude: 0.0,
            longitude: 0.0,
            altitude_m: 0.0,
        });
        out[24..28].copy_from_slice(&e7(p.latitude).to_le_bytes());
        out[28..32].copy_from_slice(&e7(p.longitude).to_le_bytes());
        let mm = p.altitude_m * 1000.0;
        let mm = if mm >= 0.0 { mm + 0.5 } else { mm - 0.5 };
        out[32..36]
            .copy_from_slice(&(mm.clamp(i32::MIN as f64, i32::MAX as f64) as i32).to_le_bytes());
        out[FIXED_SIZE..FIXED_SIZE + self.payload.len()].copy_from_slice(self.payload);
        out[FIXED_SIZE + self.payload.len()..n].copy_from_slice(self.extensions);
        Ok(n)
    }

    /// Iterates over the extension TLVs as `(type, value)`.
    pub fn extension_items(&self) -> impl Iterator<Item = (u8, &'a [u8])> {
        let mut rest: &'a [u8] = self.extensions;
        core::iter::from_fn(move || {
            if rest.len() < 2 || rest.len() < 2 + rest[1] as usize {
                rest = &[];
                return None;
            }
            let item = (rest[0], &rest[2..2 + rest[1] as usize]);
            rest = &rest[2 + rest[1] as usize..];
            Some(item)
        })
    }

    /// The Wi-Fi Beacon extension, if present.
    pub fn beacon(&self) -> Option<BeaconInfo> {
        let (_, v) = self.extension_items().find(|(t, _)| *t == EXT_BEACON)?;
        if v.len() < 14 {
            return None;
        }
        let mut b = BeaconInfo {
            source: self.address.unwrap_or([0; 6]),
            tsf: u64::from_le_bytes(v[0..8].try_into().ok()?),
            interval_tu: u16::from_le_bytes([v[8], v[9]]),
            capability: u16::from_le_bytes([v[10], v[11]]),
            sequence: u16::from_le_bytes([v[12], v[13]]),
            ssid: [0; 32],
            ssid_len: 0,
        };
        let ssid = &v[14..];
        let n = ssid.len().min(32);
        b.ssid[..n].copy_from_slice(&ssid[..n]);
        b.ssid_len = n as u8;
        Some(b)
    }

    /// The transmitter key the tracker uses for this record (Bluetooth for
    /// Bluetooth transports, Wi-Fi otherwise; `Other(receiver_id)` without
    /// an address).
    pub fn transmitter(&self) -> Transmitter {
        match (self.address, self.transport) {
            (Some(a), Transport::Bluetooth4 | Transport::Bluetooth5) => Transmitter::Ble(a),
            (Some(a), _) => Transmitter::Wifi(a),
            (None, _) => Transmitter::Other(self.receiver_id as u64),
        }
    }

    /// An [`Observation`] for the trust engine. The receiver time becomes
    /// `now_ms`; with `utc` it also sets the receiver UTC clock.
    pub fn observation(&self) -> Observation<'a> {
        let ms = self.rx_time_ns / 1_000_000;
        let mut o = Observation::new(self.transport, self.counter, self.payload, ms);
        if self.utc {
            o = o.with_unix_ms(ms);
        }
        if let Some(r) = self.rssi_dbm {
            o = o.with_rssi(r);
        }
        if let Some(b) = self.beacon() {
            o = o.with_beacon(b);
        }
        o
    }
}

/// Writes the [`EXT_BEACON`] extension for `info` into `out`; returns its
/// length.
pub fn write_beacon_extension(info: &BeaconInfo, out: &mut [u8]) -> Result<usize, Error> {
    let ssid = info.ssid();
    let n = 2 + 14 + ssid.len();
    if out.len() < n {
        return Err(Error::BufferTooSmall {
            need: n,
            got: out.len(),
        });
    }
    out[0] = EXT_BEACON;
    out[1] = (14 + ssid.len()) as u8;
    out[2..10].copy_from_slice(&info.tsf.to_le_bytes());
    out[10..12].copy_from_slice(&info.interval_tu.to_le_bytes());
    out[12..14].copy_from_slice(&info.capability.to_le_bytes());
    out[14..16].copy_from_slice(&info.sequence.to_le_bytes());
    out[16..n].copy_from_slice(ssid);
    Ok(n)
}

/// Iterates over the records of a stream, skipping a leading
/// [`FILE_HEADER`]. Stops after the first error.
pub fn records(stream: &[u8]) -> impl Iterator<Item = Result<Record<'_>, Error>> {
    let mut rest = if stream.len() >= 8 && stream[..4] == FILE_HEADER[..4] {
        &stream[8..]
    } else {
        stream
    };
    let mut failed = false;
    core::iter::from_fn(move || {
        if failed || rest.is_empty() {
            return None;
        }
        match Record::decode(rest) {
            Ok((r, n)) => {
                rest = &rest[n..];
                Some(Ok(r))
            }
            Err(e) => {
                failed = true;
                Some(Err(e))
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let payload = [0x12u8; 25];
        let b = BeaconInfo {
            source: [2, 0, 0, 0, 0, 1],
            sequence: 77,
            tsf: 123_456_789,
            interval_tu: 100,
            capability: 0x0421,
            ssid: {
                let mut s = [0u8; 32];
                s[..3].copy_from_slice(b"abc");
                s
            },
            ssid_len: 3,
        };
        let mut ext = [0u8; 64];
        let en = write_beacon_extension(&b, &mut ext).unwrap();
        let rec = Record {
            transport: Transport::WifiBeacon,
            counter: Some(9),
            rx_time_ns: 1_700_000_000_123_456_789,
            utc: true,
            rssi_dbm: Some(-71),
            address: Some(b.source),
            receiver_id: 3,
            receiver: Some(ReceiverPosition {
                latitude: 46.9480,
                longitude: 7.4474,
                altitude_m: 540.25,
            }),
            payload: &payload,
            extensions: &ext[..en],
        };
        let mut buf = [0u8; 256];
        let n = rec.encode(&mut buf).unwrap();
        let (back, used) = Record::decode(&buf[..n]).unwrap();
        assert_eq!(used, n);
        assert_eq!(back, rec);
        assert_eq!(back.beacon(), Some(b));
        let obs = back.observation();
        assert_eq!(obs.unix_ms, Some(1_700_000_000_123));
        assert_eq!(obs.rssi_dbm, Some(-71));
        assert_eq!(back.transmitter(), Transmitter::Wifi(b.source));

        let mut stream = [0u8; 600];
        stream[..8].copy_from_slice(&FILE_HEADER);
        stream[8..8 + n].copy_from_slice(&buf[..n]);
        stream[8 + n..8 + 2 * n].copy_from_slice(&buf[..n]);
        let mut count = 0;
        for r in records(&stream[..8 + 2 * n]) {
            assert_eq!(r.unwrap(), rec);
            count += 1;
        }
        assert_eq!(count, 2);
    }
}
