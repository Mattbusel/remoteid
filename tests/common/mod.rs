//! Minimal pcap / pcapng readers for the sample captures (test only).
#![allow(dead_code)]

use std::path::PathBuf;

pub fn data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join(name)
}

/// A path as given if it exists, else the file of that name in tests/data.
fn resolve(name: &str) -> PathBuf {
    let p = PathBuf::from(name);
    if p.exists() {
        p
    } else {
        data(name)
    }
}

/// Returns (linktype, packet bytes) for every packet in a classic pcap file.
pub fn read_pcap(name: &str) -> Vec<(u32, Vec<u8>)> {
    let b = std::fs::read(resolve(name)).unwrap();
    assert_eq!(&b[..4], &[0xd4, 0xc3, 0xb2, 0xa1], "little endian pcap");
    let lt = u32::from_le_bytes(b[20..24].try_into().unwrap());
    let mut off = 24;
    let mut out = Vec::new();
    while off + 16 <= b.len() {
        let cl = u32::from_le_bytes(b[off + 8..off + 12].try_into().unwrap()) as usize;
        off += 16;
        out.push((lt, b[off..off + cl].to_vec()));
        off += cl;
    }
    out
}

/// Returns (linktype, packet bytes) for every enhanced packet block in a pcapng file.
pub fn read_pcapng(name: &str) -> Vec<(u32, Vec<u8>)> {
    let b = std::fs::read(resolve(name)).unwrap();
    let mut off = 0;
    let mut linktypes = Vec::new();
    let mut out = Vec::new();
    while off + 12 <= b.len() {
        let bt = u32::from_le_bytes(b[off..off + 4].try_into().unwrap());
        let bl = u32::from_le_bytes(b[off + 4..off + 8].try_into().unwrap()) as usize;
        let body = &b[off + 8..off + bl - 4];
        match bt {
            1 => linktypes.push(u16::from_le_bytes(body[..2].try_into().unwrap()) as u32),
            6 => {
                let iface = u32::from_le_bytes(body[..4].try_into().unwrap()) as usize;
                let cl = u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize;
                out.push((linktypes[iface], body[20..20 + cl].to_vec()));
            }
            _ => {}
        }
        off += bl;
    }
    out
}

/// Extracts the BLE advertising data (AdvData) from a LINKTYPE_NORDIC_BLE (272) packet.
/// Returns (advertiser address, adv data, crc_ok).
pub fn nordic_ble_adv(pkt: &[u8]) -> Option<([u8; 6], Vec<u8>, bool)> {
    // Nordic BLE sniffer v3: board(1) length(2) version(1) counter(2) id(1),
    // then header length(1) flags(1) channel(1) rssi(1) event counter(2) delta(4).
    let hdr = 1 + 6;
    let flags = *pkt.get(hdr + 1)?;
    let crc_ok = flags & 0x01 != 0;
    let coded = (flags >> 4) & 0x07 == 2;
    let ble = &pkt[hdr + 10..];
    // access address(4), coding indicator (1, LE Coded PHY only), PDU header(2)
    let h = if coded { 5 } else { 4 };
    let pdu_type = ble.get(h)? & 0x0F;
    let len = *ble.get(h + 1)? as usize;
    let pdu = ble.get(h + 2..h + 2 + len)?;
    match pdu_type {
        // ADV_IND / ADV_NONCONN_IND / ADV_SCAN_IND: AdvA(6) + AdvData
        0 | 2 | 6 => Some((pdu[..6].try_into().ok()?, pdu[6..].to_vec(), crc_ok)),
        // ADV_EXT_IND / AUX_ADV_IND: common extended header
        7 => {
            let ext_len = (pdu[0] & 0x3F) as usize;
            let ext = &pdu[1..1 + ext_len];
            let mut addr = [0u8; 6];
            if ext_len > 0 {
                let ehf = ext[0];
                if ehf & 0x01 != 0 {
                    addr.copy_from_slice(&ext[1..7]);
                }
            }
            Some((addr, pdu[1 + ext_len..].to_vec(), crc_ok))
        }
        _ => None,
    }
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Like [`read_pcap`] / [`read_pcapng`] but with packet timestamps in
/// microseconds since the Unix epoch.
pub fn read_capture(name: &str) -> Vec<(u32, u64, Vec<u8>)> {
    let b = std::fs::read(resolve(name)).unwrap();
    let mut out = Vec::new();
    if b[..4] == [0xd4, 0xc3, 0xb2, 0xa1] {
        let lt = u32::from_le_bytes(b[20..24].try_into().unwrap());
        let mut off = 24;
        while off + 16 <= b.len() {
            let s = u32::from_le_bytes(b[off..off + 4].try_into().unwrap()) as u64;
            let us = u32::from_le_bytes(b[off + 4..off + 8].try_into().unwrap()) as u64;
            let cl = u32::from_le_bytes(b[off + 8..off + 12].try_into().unwrap()) as usize;
            off += 16;
            out.push((lt, s * 1_000_000 + us, b[off..off + cl].to_vec()));
            off += cl;
        }
    } else {
        let mut off = 0;
        let mut linktypes = Vec::new();
        while off + 12 <= b.len() {
            let bt = u32::from_le_bytes(b[off..off + 4].try_into().unwrap());
            let bl = u32::from_le_bytes(b[off + 4..off + 8].try_into().unwrap()) as usize;
            let body = &b[off + 8..off + bl - 4];
            match bt {
                1 => linktypes.push(u16::from_le_bytes(body[..2].try_into().unwrap()) as u32),
                6 => {
                    let iface = u32::from_le_bytes(body[..4].try_into().unwrap()) as usize;
                    let hi = u32::from_le_bytes(body[4..8].try_into().unwrap()) as u64;
                    let lo = u32::from_le_bytes(body[8..12].try_into().unwrap()) as u64;
                    let cl = u32::from_le_bytes(body[12..16].try_into().unwrap()) as usize;
                    out.push((
                        linktypes[iface],
                        (hi << 32) | lo,
                        body[20..20 + cl].to_vec(),
                    ));
                }
                _ => {}
            }
            off += bl;
        }
    }
    out
}

/// AdvA and AdvData of a LINKTYPE_BLUETOOTH_LE_LL (251) legacy advertising PDU.
pub fn ble_ll_adv(pkt: &[u8]) -> Option<([u8; 6], Vec<u8>)> {
    let pdu = pkt.get(4..)?;
    let pdu_type = pdu.first()? & 0x0F;
    let len = *pdu.get(1)? as usize;
    let body = pdu.get(2..2 + len)?;
    match pdu_type {
        0 | 2 | 6 => Some((body[..6].try_into().ok()?, body[6..].to_vec())),
        _ => None,
    }
}

/// Every Remote ID frame of a capture, read by the library's
/// [`remoteid::capture`] module (the same code the replay CLI uses).
pub fn rid_frames(name: &str) -> Vec<remoteid::capture::CapturedFrame> {
    let bytes = std::fs::read(resolve(name)).unwrap();
    remoteid::capture::frames(&bytes).unwrap()
}

/// Feeds a capture through a tracker, with the capture clock as both the
/// monotonic and the UTC receiver clock.
pub fn track(name: &str, utc: bool) -> remoteid::Tracker {
    track_with(name, utc, remoteid::TrustConfig::default())
}

/// [`track`] with trust settings.
pub fn track_with(name: &str, utc: bool, trust: remoteid::TrustConfig) -> remoteid::Tracker {
    let config = remoteid::TrackerConfig {
        trust,
        ..remoteid::TrackerConfig::default()
    };
    remoteid::capture::track(&rid_frames(name), config, utc)
}
