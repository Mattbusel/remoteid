//! DRIP authentication data: DRIP Entity Tags (RFC 9374) and the DRIP
//! Authentication Formats carried in Remote ID Authentication messages
//! (RFC 9575).
//!
//! This module parses and assembles; it does no cryptography. Signature
//! checks live in [`crate::auth`] behind the `verify` feature.
//!
//! * [`Det`]: a 128-bit DRIP Entity Tag, the identifier a DRIP aircraft
//!   broadcasts as a Specific Session ID in its Basic ID message.
//! * [`DripAuth::parse`]: the four DRIP SAM types (Link, Wrapper, Manifest,
//!   Frame) from the Authentication Data field.
//! * [`assemble`]: joins authentication pages, checks and strips the DRIP
//!   forward error correction page, and rebuilds one lost page from it.
//! * [`AuthAssembler`]: sorts pages that arrive one per frame over
//!   Bluetooth 4 into messages, using the message counter, so that a slow
//!   DRIP Link spread over several seconds and a fast Manifest burst can be
//!   received at the same time.
//!
//! # Deviations found in RFC 9575
//!
//! The raw example in RFC 9575 Appendix B.2.1 is used as a test vector. It
//! verifies, but it differs from the text in four places, and this module
//! accepts both forms:
//!
//! 1. Its DRIP Link uses SAM type `0x04` (DRIP Frame) instead of `0x01`.
//!    The bytes are the same as a Frame whose evidence is the child DET and
//!    HI and whose signer is the parent, so [`DripAuth::parse`] reads a
//!    Frame with that exact shape as a Link (frame type `0x20`, the first
//!    DET byte, is unassigned).
//! 2. Its VNB and VNA timestamps count from the Unix epoch, not from
//!    2019-01-01 as Section 3.2.4.3 requires.
//! 3. Its Current Manifest Hash covers the DRIP Link hash too, which step 4
//!    of Section 4.4.3 leaves out.
//! 4. Its DRIP Link hash covers the Link's authentication data without the
//!    SAM type byte, not the concatenated pages of Section 4.4.3.1.
//!
//! The FEC decode check in Figure 12 is also off by one (it leaves out the
//! Additional Data Length byte itself); [`assemble`] uses the corrected
//! arithmetic, which the example satisfies.

use core::fmt;

use crate::{Auth, AuthType, BasicId, Error, IdType};

/// SAM type of a DRIP Link (Broadcast Endorsement).
pub const SAM_LINK: u8 = 0x01;
/// SAM type of a DRIP Wrapper.
pub const SAM_WRAPPER: u8 = 0x02;
/// SAM type of a DRIP Manifest.
pub const SAM_MANIFEST: u8 = 0x03;
/// SAM type of a DRIP Frame.
pub const SAM_FRAME: u8 = 0x04;
/// Largest Authentication Data length DRIP allows (Section 3.2.4.2).
pub const MAX_AUTH_LENGTH: usize = 201;
/// Specific Session ID type for IETF DRIP in a Basic ID message.
pub const SESSION_ID_TYPE_DRIP: u8 = 0x01;
/// HHIT Suite ID for EdDSA (Ed25519) with cSHAKE128.
pub const SUITE_EDDSA_CSHAKE128: u8 = 5;
/// ORCHID context ID for HHITs (RFC 9374 Section 3).
pub const HHIT_CONTEXT_ID: [u8; 16] = [
    0x00, 0xB5, 0xA6, 0x9C, 0x79, 0x5D, 0xF5, 0xD5, 0xF0, 0x08, 0x7F, 0x56, 0x84, 0x3F, 0x2C, 0x40,
];
/// The 28-bit DET prefix `2001:30::/28`, right aligned.
pub const DET_PREFIX: u32 = 0x0200_1003;
/// Data bytes per authentication page as seen by FEC (the whole 23 byte
/// payload after the page header).
pub const PAGE_PAYLOAD: usize = 23;
/// Maximum number of authentication pages.
pub const MAX_PAGES: usize = 16;
/// Room for the Authentication Data plus Additional Data of 16 pages.
pub const MAX_ASSEMBLED: usize = 17 + 15 * 23;
/// Size of a signature, in bytes.
pub const SIGNATURE_SIZE: usize = 64;
/// Size of an Ed25519 Host Identity (public key), in bytes.
pub const HI_SIZE: usize = 32;

/// A DRIP Entity Tag: a 128-bit Hierarchical Host Identity Tag.
///
/// Layout: 28-bit prefix `2001:30::/28`, 14-bit Registered Assigning
/// Authority, 14-bit HHIT Domain Authority, 8-bit suite ID, 64-bit hash of
/// the Host Identity. Displayed as an IPv6 address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Det(pub [u8; 16]);

impl Det {
    /// Takes the first 16 bytes of `bytes`.
    pub fn from_slice(bytes: &[u8]) -> Option<Det> {
        let b: [u8; 16] = bytes.get(..16)?.try_into().ok()?;
        Some(Det(b))
    }

    /// The DET carried by a Basic ID message: ID type Specific Session ID
    /// with session ID type 1 (IETF DRIP), then the 16 byte DET.
    pub fn from_basic_id(b: &BasicId) -> Option<Det> {
        if b.id_type != IdType::SpecificSessionId || b.uas_id[0] != SESSION_ID_TYPE_DRIP {
            return None;
        }
        let det = Det::from_slice(&b.uas_id[1..17])?;
        det.has_det_prefix().then_some(det)
    }

    fn upper(&self) -> u64 {
        u64::from_be_bytes(self.0[..8].try_into().unwrap())
    }

    /// `true` if the tag starts with the DET prefix `2001:30::/28`.
    pub fn has_det_prefix(&self) -> bool {
        (self.upper() >> 36) as u32 == DET_PREFIX
    }

    /// Registered Assigning Authority (14 bits).
    pub fn raa(&self) -> u16 {
        ((self.upper() >> 22) & 0x3FFF) as u16
    }

    /// HHIT Domain Authority (14 bits).
    pub fn hda(&self) -> u16 {
        ((self.upper() >> 8) & 0x3FFF) as u16
    }

    /// HHIT suite ID (5 = EdDSA / cSHAKE128).
    pub fn suite_id(&self) -> u8 {
        self.0[7]
    }

    /// The 64-bit ORCHID hash of the Host Identity.
    pub fn orchid_hash(&self) -> [u8; 8] {
        self.0[8..].try_into().unwrap()
    }

    /// Prefix, HID and suite ID: the 8 bytes hashed in front of the HI.
    pub fn header(&self) -> [u8; 8] {
        self.0[..8].try_into().unwrap()
    }

    /// Builds the header bytes for a DET with this RAA, HDA and suite.
    pub fn header_for(raa: u16, hda: u16, suite: u8) -> [u8; 8] {
        let v = ((DET_PREFIX as u64) << 36)
            | (((raa & 0x3FFF) as u64) << 22)
            | (((hda & 0x3FFF) as u64) << 8)
            | suite as u64;
        v.to_be_bytes()
    }
}

impl fmt::Display for Det {
    /// RFC 5952 text form (lower case, longest zero run as `::`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut g = [0u16; 8];
        for (i, w) in g.iter_mut().enumerate() {
            *w = u16::from_be_bytes([self.0[2 * i], self.0[2 * i + 1]]);
        }
        // Longest run of zero groups, at least 2 long.
        let (mut best, mut best_len, mut i) = (8usize, 0usize, 0usize);
        while i < 8 {
            if g[i] == 0 {
                let start = i;
                while i < 8 && g[i] == 0 {
                    i += 1;
                }
                if i - start > best_len && i - start >= 2 {
                    best = start;
                    best_len = i - start;
                }
            } else {
                i += 1;
            }
        }
        let mut i = 0;
        while i < 8 {
            if i == best {
                f.write_str("::")?;
                i += best_len;
                continue;
            }
            if i > 0 && i != best + best_len {
                f.write_str(":")?;
            }
            write!(f, "{:x}", g[i])?;
            i += 1;
        }
        Ok(())
    }
}

impl fmt::Debug for Det {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Det({self})")
    }
}

/// A DRIP Link: a Broadcast Endorsement of a child's DET and HI by its
/// parent in the registration hierarchy (for example HDA on UA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link<'a> {
    /// SAM type it arrived with ([`SAM_LINK`], or [`SAM_FRAME`] in the RFC
    /// example form).
    pub sam_type: u8,
    /// Valid Not Before, seconds since 2019-01-01 per the RFC text.
    pub vnb: u32,
    /// Valid Not After.
    pub vna: u32,
    /// DET of the endorsed child.
    pub child_det: Det,
    /// Host Identity (Ed25519 public key) of the child.
    pub child_hi: [u8; HI_SIZE],
    /// DET of the parent that signed.
    pub parent_det: Det,
    /// Parent's signature over VNB, VNA, child DET, child HI, parent DET.
    pub signature: [u8; SIGNATURE_SIZE],
    /// The signed bytes.
    pub signed: &'a [u8],
}

/// The UA-Signed Evidence Structure shared by Wrapper, Manifest and Frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evidence<'a> {
    /// Valid Not Before, set by the UA.
    pub vnb: u32,
    /// Valid Not After.
    pub vna: u32,
    /// The signed evidence (wrapped messages, hashes, or frame data).
    pub evidence: &'a [u8],
    /// DET of the signing UA.
    pub det: Det,
    /// Signature over VNB, VNA, evidence and DET.
    pub signature: [u8; SIGNATURE_SIZE],
    /// The signed bytes as transmitted. For a Wrapper over an extended
    /// transport the evidence is empty on the air and must be rebuilt from
    /// the message pack before verifying.
    pub signed: &'a [u8],
}

impl<'a> Evidence<'a> {
    /// For a Wrapper: the wrapped 25 byte messages.
    pub fn wrapped_messages(&self) -> impl Iterator<Item = &'a [u8; 25]> + 'a {
        let ev: &'a [u8] = self.evidence;
        ev.chunks_exact(25).map(|c| c.try_into().unwrap())
    }

    /// For a Manifest: the Previous Manifest Hash.
    pub fn previous_manifest_hash(&self) -> Option<[u8; 8]> {
        self.hash_at(0)
    }

    /// For a Manifest: the Current Manifest Hash.
    pub fn current_manifest_hash(&self) -> Option<[u8; 8]> {
        self.hash_at(1)
    }

    /// For a Manifest: the hash of the DRIP Link (BE: HDA, UA).
    pub fn link_hash(&self) -> Option<[u8; 8]> {
        self.hash_at(2)
    }

    /// For a Manifest: the hashes of ASTM messages.
    pub fn message_hashes(&self) -> impl Iterator<Item = [u8; 8]> + 'a {
        let ev: &'a [u8] = self.evidence;
        ev.chunks_exact(8).skip(3).map(|c| c.try_into().unwrap())
    }

    fn hash_at(&self, i: usize) -> Option<[u8; 8]> {
        self.evidence.get(8 * i..8 * i + 8)?.try_into().ok()
    }
}

/// One parsed DRIP authentication format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DripAuth<'a> {
    /// Broadcast Endorsement.
    Link(Link<'a>),
    /// Up to four full messages signed by the UA, or (with empty evidence)
    /// a signature over the other messages of the same message pack.
    Wrapper(Evidence<'a>),
    /// Signed hashes of earlier messages.
    Manifest(Evidence<'a>),
    /// Signed data of a registered frame type (first evidence byte).
    Frame(Evidence<'a>),
}

fn read_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().unwrap())
}

impl<'a> DripAuth<'a> {
    /// Parses the Authentication Data field of a SAM (auth type 5)
    /// message: SAM type byte first, `length` bytes in all (no Additional
    /// Data or FEC).
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let sam = *data.first().ok_or(Error::TooShort { need: 1, got: 0 })?;
        if data.len() > MAX_AUTH_LENGTH {
            return Err(Error::InvalidAuthPage("DRIP data longer than 201 bytes"));
        }
        let body = &data[1..];
        match sam {
            SAM_LINK => Self::parse_link(sam, body),
            SAM_WRAPPER | SAM_MANIFEST | SAM_FRAME => {
                let ev = Self::parse_evidence(body)?;
                match sam {
                    SAM_WRAPPER => {
                        let n = ev.evidence.len();
                        if n % 25 != 0 || n / 25 > 4 {
                            return Err(Error::InvalidAuthPage("DRIP Wrapper evidence size"));
                        }
                        for m in ev.wrapped_messages() {
                            if !matches!(m[0] >> 4, 0 | 1 | 3 | 4 | 5) {
                                return Err(Error::InvalidAuthPage("DRIP Wrapper message type"));
                            }
                        }
                        Ok(DripAuth::Wrapper(ev))
                    }
                    SAM_MANIFEST => {
                        let n = ev.evidence.len();
                        if n % 8 != 0 || n < 24 {
                            return Err(Error::InvalidAuthPage("DRIP Manifest evidence size"));
                        }
                        Ok(DripAuth::Manifest(ev))
                    }
                    _ => {
                        // The RFC 9575 Appendix B.2.1 Link is encoded as a
                        // Frame whose evidence is a DET followed by an HI.
                        if ev.evidence.len() == 16 + HI_SIZE
                            && Det::from_slice(ev.evidence).is_some_and(|d| d.has_det_prefix())
                            && ev.det.has_det_prefix()
                        {
                            return Self::parse_link(sam, body);
                        }
                        if ev.evidence.is_empty() {
                            return Err(Error::InvalidAuthPage("DRIP Frame without frame type"));
                        }
                        Ok(DripAuth::Frame(ev))
                    }
                }
            }
            _ => Err(Error::InvalidAuthPage("not a DRIP SAM type")),
        }
    }

    fn parse_link(sam: u8, body: &'a [u8]) -> Result<Self, Error> {
        // VNB 4, VNA 4, child DET 16, child HI 32, parent DET 16, signature 64.
        if body.len() != 136 {
            return Err(Error::InvalidAuthPage("DRIP Link must be 137 bytes"));
        }
        Ok(DripAuth::Link(Link {
            sam_type: sam,
            vnb: read_u32(&body[0..]),
            vna: read_u32(&body[4..]),
            child_det: Det::from_slice(&body[8..24]).unwrap(),
            child_hi: body[24..56].try_into().unwrap(),
            parent_det: Det::from_slice(&body[56..72]).unwrap(),
            signature: body[72..136].try_into().unwrap(),
            signed: &body[..72],
        }))
    }

    fn parse_evidence(body: &'a [u8]) -> Result<Evidence<'a>, Error> {
        const FIXED: usize = 4 + 4 + 16 + SIGNATURE_SIZE;
        if body.len() < FIXED {
            return Err(Error::TooShort {
                need: FIXED + 1,
                got: body.len() + 1,
            });
        }
        let ev_len = body.len() - FIXED;
        if ev_len > 112 + 25 * 4 {
            return Err(Error::InvalidAuthPage("DRIP evidence too long"));
        }
        let det_at = 8 + ev_len;
        Ok(Evidence {
            vnb: read_u32(body),
            vna: read_u32(&body[4..]),
            evidence: &body[8..det_at],
            det: Det::from_slice(&body[det_at..det_at + 16]).unwrap(),
            signature: body[det_at + 16..].try_into().unwrap(),
            signed: &body[..det_at + 16],
        })
    }

    /// The SAM type this was decoded as.
    pub fn sam_type(&self) -> u8 {
        match self {
            DripAuth::Link(l) => l.sam_type,
            DripAuth::Wrapper(_) => SAM_WRAPPER,
            DripAuth::Manifest(_) => SAM_MANIFEST,
            DripAuth::Frame(_) => SAM_FRAME,
        }
    }

    /// `(VNB, VNA)`.
    pub fn validity(&self) -> (u32, u32) {
        match self {
            DripAuth::Link(l) => (l.vnb, l.vna),
            DripAuth::Wrapper(e) | DripAuth::Manifest(e) | DripAuth::Frame(e) => (e.vnb, e.vna),
        }
    }
}

/// A complete authentication message joined from its pages.
#[derive(Clone, PartialEq, Eq)]
pub struct AssembledAuth {
    /// Authentication type of the pages.
    pub auth_type: AuthType,
    /// Protocol version of page 0.
    pub protocol_version: u8,
    /// Last page index from page 0.
    pub last_page_index: u8,
    /// Page 0 timestamp (seconds since 2019-01-01).
    pub timestamp: u32,
    /// Number of Authentication Data bytes (`length` from page 0).
    pub length: u8,
    /// Page restored from the DRIP FEC page, if one was missing.
    pub recovered_page: Option<u8>,
    /// `true` if the message carries a DRIP FEC page that checked out.
    pub fec: bool,
    /// Whether the pages came in one message pack.
    pub from_pack: bool,
    buf: [u8; MAX_ASSEMBLED],
}

impl fmt::Debug for AssembledAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssembledAuth")
            .field("auth_type", &self.auth_type)
            .field("last_page_index", &self.last_page_index)
            .field("timestamp", &self.timestamp)
            .field("length", &self.length)
            .field("recovered_page", &self.recovered_page)
            .field("fec", &self.fec)
            .field("from_pack", &self.from_pack)
            .finish()
    }
}

impl Default for AssembledAuth {
    fn default() -> Self {
        AssembledAuth {
            auth_type: AuthType::None,
            protocol_version: 0,
            last_page_index: 0,
            timestamp: 0,
            length: 0,
            recovered_page: None,
            fec: false,
            from_pack: false,
            buf: [0; MAX_ASSEMBLED],
        }
    }
}

impl AssembledAuth {
    /// The Authentication Data (`length` bytes, no Additional Data).
    pub fn data(&self) -> &[u8] {
        &self.buf[..self.length as usize]
    }

    /// Parses the data as a DRIP format (auth type 5 only).
    pub fn drip(&self) -> Result<DripAuth<'_>, Error> {
        if self.auth_type != AuthType::SpecificAuthentication {
            return Err(Error::InvalidAuthPage("not a SAM authentication message"));
        }
        DripAuth::parse(self.data())
    }

    /// Unix seconds of the page 0 timestamp.
    pub fn unix_timestamp(&self) -> u64 {
        self.timestamp as u64 + crate::EPOCH_2019_UNIX
    }
}

/// A set of received page payloads (23 bytes each, page header removed).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PageSet {
    pages: [Option<[u8; PAGE_PAYLOAD]>; MAX_PAGES],
    auth_type: u8,
    protocol_version: u8,
}

impl Default for PageSet {
    fn default() -> Self {
        PageSet {
            pages: [None; MAX_PAGES],
            auth_type: 0xFF,
            protocol_version: 0,
        }
    }
}

impl fmt::Debug for PageSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut l = f.debug_list();
        for (i, p) in self.pages.iter().enumerate() {
            if p.is_some() {
                l.entry(&i);
            }
        }
        l.finish()
    }
}

/// The 23 payload bytes of a page as FEC sees them.
pub fn page_payload(page: &Auth) -> [u8; PAGE_PAYLOAD] {
    let mut p = [0u8; PAGE_PAYLOAD];
    if page.page == 0 {
        p[0] = page.last_page_index;
        p[1] = page.length;
        p[2..6].copy_from_slice(&page.timestamp.to_le_bytes());
        p[6..].copy_from_slice(&page.data[..17]);
    } else {
        p.copy_from_slice(&page.data);
    }
    p
}

impl PageSet {
    /// Empties the set.
    pub fn clear(&mut self) {
        *self = PageSet::default();
    }

    /// Stores one page. A page of a different auth type than the pages
    /// already held clears the set first.
    pub fn put(&mut self, page: &Auth) {
        let t = u8::from(page.auth_type);
        if t != self.auth_type {
            self.clear();
            self.auth_type = t;
        }
        if page.page == 0 {
            self.protocol_version = page.protocol_version;
        }
        self.pages[page.page as usize & 0x0F] = Some(page_payload(page));
    }

    /// Number of stored pages.
    pub fn len(&self) -> usize {
        self.pages.iter().flatten().count()
    }

    /// `true` when no page is stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Tries to join the pages; see [`assemble`].
    pub fn assemble(&self, out: &mut AssembledAuth) -> Result<(), Error> {
        assemble(&self.pages, self.auth_type, self.protocol_version, out)
    }
}

fn pages_for(length: usize) -> usize {
    // Index of the page holding the last Authentication Data byte.
    if length <= 17 {
        0
    } else {
        1 + (length - 17 - 1) / 23
    }
}

/// Joins authentication pages (payloads as from [`page_payload`], indexed
/// by page number) into `out`.
///
/// Handles DRIP single page FEC (RFC 9575 Section 5): when the last page
/// index leaves room for the Additional Data Length byte, padding and a
/// parity page, the padding and parity are checked, and one missing page
/// (page 0 included) is rebuilt by XOR. Returns
/// [`Error::InvalidAuthPage`] while pages are missing or when the FEC
/// layout does not check out.
pub fn assemble(
    pages: &[Option<[u8; PAGE_PAYLOAD]>; MAX_PAGES],
    auth_type: u8,
    protocol_version: u8,
    out: &mut AssembledAuth,
) -> Result<(), Error> {
    let mut work = *pages;
    let mut recovered = None;
    // Page 0 tells the layout. Without it, assume the highest page held is
    // the FEC page and rebuild page 0 from the rest.
    if work[0].is_none() {
        let hi = (1..MAX_PAGES)
            .rev()
            .find(|&i| work[i].is_some())
            .ok_or(Error::InvalidAuthPage("no pages"))?;
        if (1..=hi).any(|i| work[i].is_none()) {
            return Err(Error::InvalidAuthPage("pages missing"));
        }
        let mut p0 = [0u8; PAGE_PAYLOAD];
        for p in work[1..=hi].iter().flatten() {
            xor_into(&mut p0, p);
        }
        if p0[0] as usize != hi {
            return Err(Error::InvalidAuthPage("pages missing"));
        }
        work[0] = Some(p0);
        recovered = Some(0u8);
    }
    let p0 = work[0].unwrap();
    let lpi = p0[0] as usize;
    let length = p0[1] as usize;
    if lpi >= MAX_PAGES {
        return Err(Error::InvalidAuthPage("last page index above 15"));
    }
    if length > 17 + lpi * 23 {
        return Err(Error::InvalidAuthPage(
            "length does not fit in the announced pages",
        ));
    }
    let data_last = pages_for(length);
    let has_fec = lpi > data_last && length > 0;
    let missing = (0..=lpi).filter(|&i| work[i].is_none()).count();
    if missing > 0 {
        if !has_fec || missing > 1 || recovered.is_some() {
            return Err(Error::InvalidAuthPage("pages missing"));
        }
        let k = (0..=lpi).find(|&i| work[i].is_none()).unwrap();
        let mut p = [0u8; PAGE_PAYLOAD];
        for q in work[..=lpi].iter().flatten() {
            xor_into(&mut p, q);
        }
        work[k] = Some(p);
        recovered = Some(k as u8);
    }
    // Flatten: page 0 data starts at payload byte 6.
    let mut n = 0;
    for (i, p) in work[..=lpi].iter().enumerate() {
        let p = p.as_ref().unwrap();
        let src = if i == 0 { &p[6..] } else { &p[..] };
        out.buf[n..n + src.len()].copy_from_slice(src);
        n += src.len();
    }
    let mut fec_ok = false;
    if has_fec {
        // Additional Data Length right after the data, then null padding up
        // to the page boundary, then exactly one parity page.
        let adl = out.buf[length] as usize;
        if adl == 0 || adl < PAGE_PAYLOAD {
            return Err(Error::InvalidAuthPage("FEC: bad Additional Data Length"));
        }
        if (length + adl - 17) / 23 + 1 != lpi || length + 1 + adl != n {
            return Err(Error::InvalidAuthPage(
                "FEC: last page index does not match",
            ));
        }
        if out.buf[length + 1..n - PAGE_PAYLOAD]
            .iter()
            .any(|&b| b != 0)
        {
            return Err(Error::InvalidAuthPage("FEC: padding is not null"));
        }
        let mut parity = [0u8; PAGE_PAYLOAD];
        for q in work[..=lpi].iter().flatten() {
            xor_into(&mut parity, q);
        }
        if parity != [0u8; PAGE_PAYLOAD] {
            return Err(Error::InvalidAuthPage("FEC: parity does not match"));
        }
        fec_ok = true;
    }
    out.auth_type = AuthType::from(auth_type);
    out.protocol_version = protocol_version;
    out.last_page_index = lpi as u8;
    out.timestamp = u32::from_le_bytes(p0[2..6].try_into().unwrap());
    out.length = length as u8;
    out.recovered_page = recovered;
    out.fec = fec_ok;
    Ok(())
}

fn xor_into(acc: &mut [u8; PAGE_PAYLOAD], p: &[u8; PAGE_PAYLOAD]) {
    for (a, b) in acc.iter_mut().zip(p) {
        *a ^= b;
    }
}

/// Authentication pages made by [`paginate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pages {
    pages: [Auth; MAX_PAGES],
    len: usize,
}

impl Pages {
    /// The pages, page 0 first.
    pub fn as_slice(&self) -> &[Auth] {
        &self.pages[..self.len]
    }

    /// Number of pages.
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` if there are no pages.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::ops::Deref for Pages {
    type Target = [Auth];
    fn deref(&self) -> &[Auth] {
        self.as_slice()
    }
}

impl<'a> IntoIterator for &'a Pages {
    type Item = &'a Auth;
    type IntoIter = core::slice::Iter<'a, Auth>;
    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

/// Splits Authentication Data into pages for transmission, the inverse of
/// [`assemble`]. With `fec`, appends the Additional Data Length byte, null
/// padding and the DRIP parity page (RFC 9575 Section 5.1; use it on
/// Bluetooth 4, never in message packs).
pub fn paginate(
    auth_type: AuthType,
    protocol_version: u8,
    timestamp: u32,
    data: &[u8],
    fec: bool,
) -> Result<Pages, Error> {
    let mut result = Pages {
        pages: core::array::from_fn(|_| Auth {
            protocol_version,
            auth_type,
            page: 0,
            last_page_index: 0,
            length: 0,
            timestamp: 0,
            data: [0; 23],
        }),
        len: 0,
    };
    let out = &mut result.pages;
    let len = data.len();
    if len > 255 {
        return Err(Error::OutOfRange("authentication data length"));
    }
    let mut stream = [0u8; MAX_ASSEMBLED];
    stream[..len].copy_from_slice(data);
    let pages = if fec {
        let used = len + 1;
        let before = if used <= 17 {
            1
        } else {
            1 + (used - 17 + 22) / 23
        };
        let capacity = 17 + 23 * (before - 1);
        let adl = capacity - used + PAGE_PAYLOAD;
        if before + 1 > MAX_PAGES || adl > 255 {
            return Err(Error::OutOfRange("authentication data length"));
        }
        stream[len] = adl as u8;
        before + 1
    } else {
        pages_for(len) + 1
    };
    let lpi = pages - 1;
    for (i, page) in out.iter_mut().enumerate().take(pages) {
        let mut d = [0u8; 23];
        if i == 0 {
            d[..17].copy_from_slice(&stream[..17]);
        } else {
            let at = 17 + 23 * (i - 1);
            d.copy_from_slice(&stream[at..at + 23]);
        }
        *page = Auth {
            protocol_version,
            auth_type,
            page: i as u8,
            last_page_index: if i == 0 { lpi as u8 } else { 0 },
            length: if i == 0 { len as u8 } else { 0 },
            timestamp: if i == 0 { timestamp } else { 0 },
            data: d,
        };
    }
    if fec {
        let mut parity = [0u8; PAGE_PAYLOAD];
        for page in out.iter().take(lpi) {
            xor_into(&mut parity, &page_payload(page));
        }
        out[lpi].data = parity;
    }
    result.len = pages;
    Ok(result)
}

/// Sorts authentication pages into messages.
///
/// Over Bluetooth 4 each page is its own frame. RFC 9575 Appendix B sends
/// a whole Manifest as a burst of consecutive pages every second while a
/// Link or Wrapper trickles in at one page per second, both with auth type
/// 5 and overlapping page numbers. The assembler keeps two page sets:
///
/// * a **burst**: pages whose message counter and page number advance
///   together from page 0 (so frames lost in between keep the burst);
/// * a **slow** set: every other page, reset whenever a page 0 that did not
///   start a burst is seen.
///
/// Message packs (Bluetooth 5, Wi-Fi) carry all pages at once and go
/// through [`AuthAssembler::push_pack`].
#[derive(Debug, Clone, Default)]
pub struct AuthAssembler {
    burst: PageSet,
    burst_last: Option<(u8, u8)>,
    slow: PageSet,
    slow_done: Option<u32>,
    pending0: Option<Auth>,
}

fn fnv(data: &[u8]) -> u32 {
    data.iter().fold(0x811C_9DC5u32, |h, b| {
        (h ^ *b as u32).wrapping_mul(0x0100_0193)
    })
}

impl AuthAssembler {
    /// An empty assembler.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one page received alone (Bluetooth 4) with its message counter.
    /// Returns `true` and fills `out` when a message completed.
    pub fn push_legacy(&mut self, page: &Auth, counter: u8, out: &mut AssembledAuth) -> bool {
        if page.page == 0 {
            if let Some(p0) = self.pending0.take() {
                self.slow.clear();
                self.slow_done = None;
                self.slow.put(&p0);
            }
            self.burst.clear();
            self.burst.put(page);
            self.burst_last = Some((0, counter));
            self.pending0 = Some(page.clone());
            if self.burst.assemble(out).is_ok() {
                out.from_pack = false;
                self.pending0 = None;
                self.burst_last = None;
                return true;
            }
            return false;
        }
        // A burst continues when page number and counter advance by the same
        // amount (frames lost in between move both).
        let continues = self
            .burst_last
            .is_some_and(|(p, c)| page.page > p && counter.wrapping_sub(c) == page.page - p);
        if continues && u8::from(page.auth_type) == self.burst.auth_type {
            self.burst.put(page);
            self.burst_last = Some((page.page, counter));
            self.pending0 = None;
            // Only the last page closes a burst, so FEC never fills in a
            // page that is merely still in flight.
            let last = self.burst.pages[0].map_or(0, |p0| p0[0]);
            if page.page == last && self.burst.assemble(out).is_ok() {
                out.from_pack = false;
                self.burst_last = None;
                return true;
            }
            return false;
        }
        if let Some(p0) = self.pending0.take() {
            self.slow.clear();
            self.slow_done = None;
            self.slow.put(&p0);
        }
        self.slow.put(page);
        if self.slow.assemble(out).is_ok() {
            out.from_pack = false;
            // Report each slow message once, whether FEC completed it early
            // or its last page arrived later.
            let h = fnv(out.data());
            if self.slow_done == Some(h) {
                return false;
            }
            self.slow_done = Some(h);
            return true;
        }
        false
    }

    /// Adds all authentication pages of one message pack. Returns `true`
    /// and fills `out` when they form a complete message.
    pub fn push_pack<'a>(
        pages: impl IntoIterator<Item = &'a Auth>,
        out: &mut AssembledAuth,
    ) -> bool {
        let mut set = PageSet::default();
        for p in pages {
            set.put(p);
        }
        if set.is_empty() {
            return false;
        }
        let ok = set.assemble(out).is_ok();
        out.from_pack = true;
        ok
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    pub(crate) fn hex(s: &str) -> [u8; 25] {
        let mut out = [0u8; 25];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    const LINK: [&str; 8] = [
        "2250078910ea510904314b8564b17e66662001003ffe000105",
        "2251a29b3ff42226c04eb5fef530d450dedb59ebafa18b00d7",
        "2252f5ed0ac08a81975034297bea2b000418132001003ffe00",
        "22530105b82bf1c99d87273103fc83f6ecd9b91842f205c222",
        "2254dd71d8e165ad18ca91daf9299a73eec850c756a7e9be46",
        "2255f51dddfa0f09db7bfdde14eec07c7a6dd1061c1d5ace94",
        "2256d9ad97940d280000000000000000000000000000000000",
        "2257a03b0f7a6feb0d198167045058cfc49f73129917024d22",
    ];

    fn pages(raw: &[&str]) -> [Option<[u8; 23]>; 16] {
        let mut out = [None; 16];
        for r in raw {
            let a = Auth::decode(&hex(r)).unwrap();
            out[a.page as usize] = Some(page_payload(&a));
        }
        out
    }

    #[test]
    fn det_fields_and_text() {
        let det =
            Det::from_slice(&hex("2001003ffe000105a29b3ff42226c04e000000000000000000")).unwrap();
        assert!(det.has_det_prefix());
        assert_eq!(det.suite_id(), 5);
        assert_eq!(format!("{det}"), "2001:3f:fe00:105:a29b:3ff4:2226:c04e");
        assert_eq!(Det::header_for(det.raa(), det.hda(), 5), det.header());
        let z = Det([0x20, 0x01, 0, 0x30, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(format!("{z}"), "2001:30:0:5::1");
        assert_eq!(format!("{}", Det([0; 16])), "::");
    }

    #[test]
    fn rfc_example_link_fec() {
        let mut out = AssembledAuth::default();
        assemble(&pages(&LINK), 5, 2, &mut out).unwrap();
        assert!(out.fec);
        assert_eq!(out.length, 137);
        match out.drip().unwrap() {
            DripAuth::Link(l) => {
                assert_eq!(l.sam_type, SAM_FRAME);
                assert_eq!(
                    format!("{}", l.child_det),
                    "2001:3f:fe00:105:a29b:3ff4:2226:c04e"
                );
                assert_eq!(
                    format!("{}", l.parent_det),
                    "2001:3f:fe00:105:b82b:f1c9:9d87:2731"
                );
                assert_eq!(l.child_hi[0], 0xb5);
            }
            other => panic!("{other:?}"),
        }
        // Every single page, page 0 included, can be dropped and rebuilt.
        for drop in 0..8 {
            let mut p = pages(&LINK);
            p[drop] = None;
            let mut r = AssembledAuth::default();
            assemble(&p, 5, 2, &mut r).unwrap();
            assert_eq!(r.recovered_page, Some(drop as u8));
            assert_eq!(r.data(), out.data());
        }
        // Two missing pages cannot be rebuilt.
        let mut p = pages(&LINK);
        p[2] = None;
        p[5] = None;
        assert!(assemble(&p, 5, 2, &mut out).is_err());
        // A flipped bit breaks the parity check.
        let mut p = pages(&LINK);
        p[3].as_mut().unwrap()[4] ^= 1;
        assert!(assemble(&p, 5, 2, &mut out).is_err());
    }

    #[test]
    fn assembler_separates_burst_and_slow() {
        // A complete Link sent one page at a time between bursts of another
        // message (here: the same Link pages again as a burst).
        let link: Vec<Auth> = LINK
            .iter()
            .map(|r| Auth::decode(&hex(r)).unwrap())
            .collect();
        let mut asm = AuthAssembler::new();
        let mut out = AssembledAuth::default();
        let mut counter = 0u8;
        let mut completed = 0;
        for slow in &link {
            // Burst of a full message.
            for p in &link {
                counter = counter.wrapping_add(1);
                if asm.push_legacy(p, counter, &mut out) {
                    completed += 1;
                }
            }
            counter = counter.wrapping_add(1);
            if asm.push_legacy(slow, counter, &mut out) {
                completed += 1;
            }
        }
        // 8 bursts plus the slow copy.
        assert_eq!(completed, 9);
        assert_eq!(out.length, 137);
    }
}
