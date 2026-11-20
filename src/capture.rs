//! Remote ID frames out of capture files: pcap, pcapng and RIDF in,
//! [`CapturedFrame`]s (and trust verdicts) out.
//!
//! A receiver is only as honest as the frames it was tested on. This
//! module reads the files people already have (Wireshark and tcpdump
//! captures, the Open Drone ID sample captures, the spoof corpus, RIDF
//! recordings) so the same bytes can be replayed through [`crate::Tracker`]
//! or through any other receiver.
//!
//! Supported link types:
//!
//! | Link type | Number | Frames read |
//! |---|---|---|
//! | IEEE 802.11 | 105 | Beacon vendor element and NAN service discovery |
//! | Radiotap + 802.11 | 127 | the same, radiotap (and FCS) stripped |
//! | Bluetooth LE link layer | 251 | legacy advertising PDUs |
//! | Bluetooth LE link layer with PHDR | 256 | legacy advertising PDUs |
//! | Nordic BLE sniffer | 272 | legacy and extended advertising, CRC checked |
//!
//! Malformed input never panics: a broken record ends the file with an
//! error, a packet that is not Remote ID is skipped.
//!
//! ```
//! # fn main() -> Result<(), remoteid::capture::CaptureError> {
//! # let bytes = remoteid::capture::pcap_header(105);
//! let frames = remoteid::capture::frames(&bytes)?;
//! let tracker = remoteid::capture::track(&frames, remoteid::TrackerConfig::default(), true);
//! for (tx, uas) in tracker.iter() {
//!     println!("{tx:?} {}", uas.assessment.verdict);
//! }
//! # Ok(())
//! # }
//! ```

use std::fmt;
use std::vec::Vec;

use crate::wifi::{self, BeaconInfo};
use crate::{ble, ridf, Observation, Tracker, TrackerConfig, Transmitter, Transport};

/// One Remote ID frame out of a capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedFrame {
    /// Capture timestamp, microseconds (since the Unix epoch for pcap and
    /// pcapng; whatever the recorder used for RIDF without the UTC flag).
    pub time_us: u64,
    /// Who sent it.
    pub transmitter: Transmitter,
    /// The radio link.
    pub transport: Transport,
    /// The message counter, when the link carries one.
    pub counter: Option<u8>,
    /// F3411 message or message pack, header byte first.
    pub payload: Vec<u8>,
    /// Wi-Fi Beacon header fields (TSF, interval, capability, sequence, SSID).
    pub beacon: Option<BeaconInfo>,
    /// Signal strength, when the capture records it (RIDF only for now).
    pub rssi_dbm: Option<i8>,
    /// `time_us` counts from the Unix epoch (always for pcap and pcapng;
    /// RIDF says so per record).
    pub utc_clock: bool,
}

impl CapturedFrame {
    /// The trust observation for this frame, with the capture clock in
    /// milliseconds as the monotonic clock and, when `utc` is set and the
    /// capture clock is UTC, as the receiver's UTC clock too.
    pub fn observation(&self, utc: bool) -> Observation<'_> {
        let ms = self.time_us / 1000;
        let mut obs = Observation::new(self.transport, self.counter, &self.payload, ms);
        if utc && self.utc_clock {
            obs = obs.with_unix_ms(ms);
        }
        if let Some(b) = self.beacon {
            obs = obs.with_beacon(b);
        }
        if let Some(r) = self.rssi_dbm {
            obs = obs.with_rssi(r);
        }
        obs
    }
}

/// Why a capture file could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CaptureError {
    /// The first bytes are not a pcap, pcapng or RIDF header.
    UnknownFormat,
    /// A record or block runs past the end of the file, or its length
    /// field is impossible. `offset` is where it starts.
    Truncated {
        /// Byte offset of the broken record.
        offset: usize,
    },
    /// A pcapng packet names an interface that was never described.
    UnknownInterface(u32),
    /// A RIDF record failed to decode.
    Ridf(crate::Error),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaptureError::UnknownFormat => f.write_str("not a pcap, pcapng or RIDF file"),
            CaptureError::Truncated { offset } => write!(f, "truncated record at byte {offset}"),
            CaptureError::UnknownInterface(i) => write!(f, "packet on undescribed interface {i}"),
            CaptureError::Ridf(e) => write!(f, "RIDF record: {e}"),
        }
    }
}

impl std::error::Error for CaptureError {}

/// A raw packet out of a pcap or pcapng file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    /// The link type of the interface it was captured on.
    pub linktype: u32,
    /// Timestamp, microseconds since the Unix epoch.
    pub time_us: u64,
    /// The captured bytes.
    pub data: &'a [u8],
}

fn u16_at(b: &[u8], at: usize, be: bool) -> Option<u16> {
    let s: [u8; 2] = b.get(at..at + 2)?.try_into().ok()?;
    Some(if be {
        u16::from_be_bytes(s)
    } else {
        u16::from_le_bytes(s)
    })
}

fn u32_at(b: &[u8], at: usize, be: bool) -> Option<u32> {
    let s: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
    Some(if be {
        u32::from_be_bytes(s)
    } else {
        u32::from_le_bytes(s)
    })
}

/// Every packet of a classic pcap file (either byte order, microsecond or
/// nanosecond timestamps).
pub fn pcap_packets(b: &[u8]) -> Result<Vec<Packet<'_>>, CaptureError> {
    let magic = b.get(..4).ok_or(CaptureError::UnknownFormat)?;
    let (be, nanos) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (false, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (false, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (true, true),
        _ => return Err(CaptureError::UnknownFormat),
    };
    let linktype = u32_at(b, 20, be).ok_or(CaptureError::Truncated { offset: 0 })? & 0x0FFF_FFFF;
    let mut out = Vec::new();
    let mut off = 24;
    while off < b.len() {
        let bad = CaptureError::Truncated { offset: off };
        let s = u32_at(b, off, be).ok_or(bad.clone())? as u64;
        let frac = u32_at(b, off + 4, be).ok_or(bad.clone())? as u64;
        let cl = u32_at(b, off + 8, be).ok_or(bad.clone())? as usize;
        let data = b.get(off + 16..(off + 16).checked_add(cl).ok_or(bad.clone())?);
        let data = data.ok_or(bad)?;
        let us = if nanos { frac / 1000 } else { frac };
        out.push(Packet {
            linktype,
            time_us: s.saturating_mul(1_000_000).saturating_add(us),
            data,
        });
        off += 16 + cl;
    }
    Ok(out)
}

/// Every packet (enhanced and simple packet blocks) of a pcapng file, with
/// each interface's timestamp resolution applied.
pub fn pcapng_packets(b: &[u8]) -> Result<Vec<Packet<'_>>, CaptureError> {
    if b.get(..4) != Some(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        return Err(CaptureError::UnknownFormat);
    }
    // (linktype, units per second)
    let mut ifaces: Vec<(u32, u64)> = Vec::new();
    let mut out = Vec::new();
    let mut be = false;
    let mut off = 0;
    while off < b.len() {
        let bad = CaptureError::Truncated { offset: off };
        let bt_raw = b.get(off..off + 4).ok_or(bad.clone())?;
        if bt_raw == [0x0a, 0x0d, 0x0d, 0x0a] {
            be = match b.get(off + 8..off + 12) {
                Some([0x1a, 0x2b, 0x3c, 0x4d]) => true,
                Some([0x4d, 0x3c, 0x2b, 0x1a]) => false,
                _ => return Err(CaptureError::UnknownFormat),
            };
            ifaces.clear();
        }
        let bt = u32_at(b, off, be).ok_or(bad.clone())?;
        let bl = u32_at(b, off + 4, be).ok_or(bad.clone())? as usize;
        if bl < 12 || bl % 4 != 0 || off.checked_add(bl).map_or(true, |e| e > b.len()) {
            return Err(bad);
        }
        let body = &b[off + 8..off + bl - 4];
        match bt {
            // Interface description: linktype, reserved, snaplen, options.
            1 => {
                let lt = u16_at(body, 0, be).ok_or(bad.clone())? as u32;
                let mut per_sec = 1_000_000u64;
                let mut o = 8;
                while let (Some(code), Some(len)) = (u16_at(body, o, be), u16_at(body, o + 2, be)) {
                    if code == 0 {
                        break;
                    }
                    let len = len as usize;
                    if code == 9 {
                        if let Some(&r) = body.get(o + 4) {
                            let e = (r & 0x7F) as u32;
                            per_sec = if r & 0x80 != 0 {
                                2u64.checked_pow(e).unwrap_or(u64::MAX)
                            } else {
                                10u64.checked_pow(e).unwrap_or(u64::MAX)
                            };
                        }
                    }
                    o += 4 + (len + 3) / 4 * 4;
                }
                ifaces.push((lt, per_sec.max(1)));
            }
            // Enhanced packet block.
            6 => {
                let iface = u32_at(body, 0, be).ok_or(bad.clone())?;
                let hi = u32_at(body, 4, be).ok_or(bad.clone())? as u64;
                let lo = u32_at(body, 8, be).ok_or(bad.clone())? as u64;
                let cl = u32_at(body, 12, be).ok_or(bad.clone())? as usize;
                let data = body.get(20..20usize.saturating_add(cl)).ok_or(bad)?;
                let &(linktype, per_sec) = ifaces
                    .get(iface as usize)
                    .ok_or(CaptureError::UnknownInterface(iface))?;
                let ts = (hi << 32) | lo;
                let time_us = if per_sec == 1_000_000 {
                    ts
                } else {
                    ((ts as u128) * 1_000_000 / per_sec as u128) as u64
                };
                out.push(Packet {
                    linktype,
                    time_us,
                    data,
                });
            }
            // Simple packet block: interface 0, no timestamp.
            3 => {
                let &(linktype, _) = ifaces.first().ok_or(CaptureError::UnknownInterface(0))?;
                let len = u32_at(body, 0, be).ok_or(bad.clone())? as usize;
                let data = body.get(4..4 + len.min(body.len().saturating_sub(4)));
                out.push(Packet {
                    linktype,
                    time_us: 0,
                    data: data.ok_or(bad)?,
                });
            }
            _ => {}
        }
        off += bl;
    }
    Ok(out)
}

/// Advertiser address and advertising data of a BLE link layer
/// advertising PDU (access address first), legacy PDUs only.
fn ble_ll_adv(pkt: &[u8]) -> Option<([u8; 6], &[u8])> {
    let pdu = pkt.get(4..)?;
    let pdu_type = pdu.first()? & 0x0F;
    let len = *pdu.get(1)? as usize;
    let body = pdu.get(2..2 + len)?;
    match pdu_type {
        // ADV_IND, ADV_NONCONN_IND, ADV_SCAN_IND: AdvA then AdvData.
        0 | 2 | 6 => Some((body.get(..6)?.try_into().ok()?, body.get(6..)?)),
        _ => None,
    }
}

/// Advertiser address, advertising data and CRC status of a Nordic BLE
/// sniffer (v3) packet.
fn nordic_ble_adv(pkt: &[u8]) -> Option<([u8; 6], &[u8], bool)> {
    // board(1) length(2) version(1) counter(2) id(1), then header length(1)
    // flags(1) channel(1) rssi(1) event counter(2) delta(4).
    let hdr = 1 + 6;
    let flags = *pkt.get(hdr + 1)?;
    let crc_ok = flags & 0x01 != 0;
    let coded = (flags >> 4) & 0x07 == 2;
    let ble = pkt.get(hdr + 10..)?;
    // access address(4), coding indicator (1, LE Coded PHY only), PDU header(2)
    let h = if coded { 5 } else { 4 };
    let pdu_type = ble.get(h)? & 0x0F;
    let len = *ble.get(h + 1)? as usize;
    let pdu = ble.get(h + 2..h + 2 + len)?;
    match pdu_type {
        0 | 2 | 6 => Some((pdu.get(..6)?.try_into().ok()?, pdu.get(6..)?, crc_ok)),
        // ADV_EXT_IND / AUX_ADV_IND: common extended advertising header.
        7 => {
            let ext_len = (pdu.first()? & 0x3F) as usize;
            let ext = pdu.get(1..1 + ext_len)?;
            let mut addr = [0u8; 6];
            if ext.first().is_some_and(|ehf| ehf & 0x01 != 0) {
                addr.copy_from_slice(ext.get(1..7)?);
            }
            Some((addr, pdu.get(1 + ext_len..)?, crc_ok))
        }
        _ => None,
    }
}

fn ble_frame(time_us: u64, addr: [u8; 6], adv: &[u8]) -> Option<CapturedFrame> {
    let rid = ble::find_in_advertising_data(adv)?;
    Some(CapturedFrame {
        time_us,
        transmitter: Transmitter::Ble(addr),
        transport: if rid.payload.first().is_some_and(|b| b >> 4 == 0xF) {
            Transport::Bluetooth5
        } else {
            Transport::Bluetooth4
        },
        counter: Some(rid.counter),
        payload: rid.payload.to_vec(),
        beacon: None,
        rssi_dbm: None,
        utc_clock: true,
    })
}

/// The Remote ID frame in one captured packet, if it carries one.
pub fn frame_of(p: &Packet<'_>) -> Option<CapturedFrame> {
    match p.linktype {
        105 | 127 => {
            let frame = if p.linktype == 127 {
                wifi::strip_radiotap(p.data).ok()?
            } else {
                p.data
            };
            let rid = wifi::parse_frame(frame).ok()?;
            Some(CapturedFrame {
                time_us: p.time_us,
                transmitter: Transmitter::Wifi(rid.source),
                transport: match rid.kind {
                    wifi::WifiKind::Beacon => Transport::WifiBeacon,
                    wifi::WifiKind::Nan => Transport::WifiNan,
                },
                counter: Some(rid.counter),
                payload: rid.payload.to_vec(),
                beacon: wifi::beacon_info(frame),
                rssi_dbm: None,
                utc_clock: true,
            })
        }
        251 => ble_ll_adv(p.data).and_then(|(a, adv)| ble_frame(p.time_us, a, adv)),
        256 => ble_ll_adv(p.data.get(10..)?).and_then(|(a, adv)| ble_frame(p.time_us, a, adv)),
        272 => match nordic_ble_adv(p.data) {
            Some((a, adv, true)) => ble_frame(p.time_us, a, adv),
            _ => None,
        },
        _ => None,
    }
}

/// Every Remote ID frame of a pcap, pcapng or RIDF file, in file order.
pub fn frames(bytes: &[u8]) -> Result<Vec<CapturedFrame>, CaptureError> {
    if bytes.starts_with(b"RIDF") {
        return ridf_frames(bytes);
    }
    let packets = if bytes.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        pcapng_packets(bytes)?
    } else {
        pcap_packets(bytes)?
    };
    Ok(packets.iter().filter_map(frame_of).collect())
}

fn ridf_frames(bytes: &[u8]) -> Result<Vec<CapturedFrame>, CaptureError> {
    let mut out = Vec::new();
    for r in ridf::records(bytes) {
        let r = r.map_err(CaptureError::Ridf)?;
        out.push(CapturedFrame {
            time_us: r.rx_time_ns / 1000,
            transmitter: r.transmitter(),
            transport: r.transport,
            counter: r.counter,
            payload: r.payload.to_vec(),
            beacon: r.beacon(),
            rssi_dbm: r.rssi_dbm,
            utc_clock: r.utc,
        });
    }
    Ok(out)
}

/// Feeds frames through a new tracker, with the capture clock as the
/// monotonic clock and, when `utc` is set, as the receiver's UTC clock.
/// Nothing expires during the replay (the timeout is ignored), so every
/// transmitter of the file is in the result.
pub fn track(frames: &[CapturedFrame], config: TrackerConfig, utc: bool) -> Tracker {
    let mut tracker = Tracker::new(TrackerConfig {
        timeout: u64::MAX,
        ..config
    });
    for f in frames {
        tracker.observe(f.transmitter, &f.observation(utc));
    }
    tracker
}

/// Encodes frames as a RIDF file (header and one record per frame), the
/// raw frame format for receivers that do not read pcap.
pub fn to_ridf(frames: &[CapturedFrame]) -> Result<Vec<u8>, crate::Error> {
    let mut out = ridf::FILE_HEADER.to_vec();
    let mut buf = [0u8; 600];
    for f in frames {
        let mut ext = [0u8; 64];
        let ext_len = match &f.beacon {
            Some(b) => ridf::write_beacon_extension(b, &mut ext)?,
            None => 0,
        };
        let rec = ridf::Record {
            transport: f.transport,
            counter: f.counter,
            rx_time_ns: f.time_us.saturating_mul(1000),
            utc: f.utc_clock,
            rssi_dbm: f.rssi_dbm,
            address: crate::replay::transmitter_address(&f.transmitter),
            payload: &f.payload,
            extensions: &ext[..ext_len],
            ..ridf::Record::default()
        };
        let n = rec.encode(&mut buf)?;
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

/// A pcap file header with no packets, for building captures by hand.
pub fn pcap_header(linktype: u32) -> Vec<u8> {
    let mut h = Vec::with_capacity(24);
    h.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0]);
    h.extend_from_slice(&[0; 8]);
    h.extend_from_slice(&65535u32.to_le_bytes());
    h.extend_from_slice(&linktype.to_le_bytes());
    h
}

/// Appends one packet record to a pcap file built with [`pcap_header`].
pub fn pcap_push(file: &mut Vec<u8>, time_us: u64, data: &[u8]) {
    file.extend_from_slice(&((time_us / 1_000_000) as u32).to_le_bytes());
    file.extend_from_slice(&((time_us % 1_000_000) as u32).to_le_bytes());
    file.extend_from_slice(&(data.len() as u32).to_le_bytes());
    file.extend_from_slice(&(data.len() as u32).to_le_bytes());
    file.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_garbage() {
        assert_eq!(frames(&pcap_header(105)).unwrap(), Vec::new());
        assert_eq!(frames(b"nope"), Err(CaptureError::UnknownFormat));
        assert_eq!(frames(&[]), Err(CaptureError::UnknownFormat));
        let mut f = pcap_header(105);
        f.extend_from_slice(&[1, 2, 3]);
        assert_eq!(frames(&f), Err(CaptureError::Truncated { offset: 24 }));
        // Captured length past the end of the file.
        let mut f = pcap_header(105);
        f.extend_from_slice(&[0; 8]);
        f.extend_from_slice(&1000u32.to_le_bytes());
        f.extend_from_slice(&1000u32.to_le_bytes());
        assert_eq!(frames(&f), Err(CaptureError::Truncated { offset: 24 }));
    }

    #[test]
    fn pcapng_block_length_checked() {
        let mut f = vec![0x0a, 0x0d, 0x0d, 0x0a];
        f.extend_from_slice(&8u32.to_le_bytes());
        f.extend_from_slice(&[0x4d, 0x3c, 0x2b, 0x1a]);
        assert_eq!(frames(&f), Err(CaptureError::Truncated { offset: 0 }));
    }

    #[test]
    fn beacon_round_trip() {
        let basic = crate::BasicId::new(
            crate::IdType::SerialNumber,
            crate::UaType::HelicopterOrMultirotor,
            "1596F0000TEST01",
        )
        .unwrap();
        let mut b = crate::MessagePackBuilder::new();
        b.push(&crate::Message::BasicId(basic)).unwrap();
        let mut ie = [0u8; 300];
        let ie_len = wifi::write_beacon_element(7, b.as_bytes(), &mut ie).unwrap();
        let src = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut frame = vec![0x80, 0, 0, 0];
        frame.extend_from_slice(&[0xff; 6]);
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&[0; 8]); // TSF
        frame.extend_from_slice(&[100, 0, 0x21, 0]); // interval, capability
        frame.extend_from_slice(&[0, 0]); // empty SSID
        frame.extend_from_slice(&ie[..ie_len]);
        let mut file = pcap_header(105);
        pcap_push(&mut file, 1_763_380_800_000_000, &frame);
        let fr = frames(&file).unwrap();
        assert_eq!(fr.len(), 1);
        assert_eq!(fr[0].transmitter, Transmitter::Wifi(src));
        assert_eq!(fr[0].transport, Transport::WifiBeacon);
        assert_eq!(fr[0].counter, Some(7));
        let t = track(&fr, TrackerConfig::default(), true);
        let uas = t.get(&Transmitter::Wifi(src)).unwrap();
        assert_eq!(uas.data.primary_id(), Some("1596F0000TEST01"));
        // RIDF carries the same frame.
        let back = frames(&to_ridf(&fr).unwrap()).unwrap();
        assert_eq!(back, fr);
    }
}
