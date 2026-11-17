//! Signature checks for DRIP authentication (needs the `verify` feature).
//!
//! * [`det_matches_hi`] / [`det_for_hi`]: the RFC 9374 ORCHID construction
//!   that binds a DET to its Ed25519 Host Identity with cSHAKE128.
//! * [`auth_hash`]: the 8 byte DRIP Manifest hash (RFC 9575 Section 4.4.3).
//! * [`DripEd25519`]: an [`AuthScheme`] that verifies DRIP Links, Wrappers
//!   (legacy and extended transport forms), Manifests and Frames, learns
//!   aircraft keys from Links, and validates signed content against the
//!   messages actually received.
//!
//! Other schemes (for example a national scheme with a MAC) plug in by
//! implementing [`AuthScheme`].
//!
//! Keys come from a [`KeyStore`]. Put the keys you trust (registry or HDA
//! keys from DNS, or pinned aircraft keys) in it marked `trusted`; keys
//! learned from a Link inherit trust only when the parent that signed the
//! Link is trusted.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{CShake128, CShake128Core};

use crate::drip::{AssembledAuth, Det, DripAuth, Evidence, HHIT_CONTEXT_ID, SUITE_EDDSA_CSHAKE128};
use crate::drip::{SAM_FRAME, SAM_LINK, SAM_MANIFEST, SAM_WRAPPER};
use crate::{AuthType, Error, MESSAGE_SIZE};

/// Customization string of the DRIP Manifest hash.
pub const AUTH_HASH_CUSTOMIZATION: &[u8] = b"Remote ID Auth Hash";

/// `cSHAKE128(data, 64, "", "Remote ID Auth Hash")`.
pub fn auth_hash(data: &[u8]) -> [u8; 8] {
    auth_hash_parts(&[data])
}

/// [`auth_hash`] over the concatenation of `parts`.
pub fn auth_hash_parts(parts: &[&[u8]]) -> [u8; 8] {
    let mut h = CShake128::from_core(CShake128Core::new(AUTH_HASH_CUSTOMIZATION));
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 8];
    h.finalize_xof().read(&mut out);
    out
}

/// The 64-bit ORCHID hash for a DET header (prefix, HID, suite) and HI:
/// `cSHAKE128(header | HI, 64, "", context ID)`.
pub fn orchid_hash(header: &[u8; 8], hi: &[u8; 32]) -> [u8; 8] {
    let mut h = CShake128::from_core(CShake128Core::new(&HHIT_CONTEXT_ID));
    h.update(header);
    h.update(hi);
    let mut out = [0u8; 8];
    h.finalize_xof().read(&mut out);
    out
}

/// `true` if `det` is the DET of Host Identity `hi`.
pub fn det_matches_hi(det: &Det, hi: &[u8; 32]) -> bool {
    det.has_det_prefix() && orchid_hash(&det.header(), hi) == det.orchid_hash()
}

/// The EdDSA DET for an HI under the given RAA and HDA.
pub fn det_for_hi(raa: u16, hda: u16, hi: &[u8; 32]) -> Det {
    let header = Det::header_for(raa, hda, SUITE_EDDSA_CSHAKE128);
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&header);
    b[8..].copy_from_slice(&orchid_hash(&header, hi));
    Det(b)
}

/// Strict Ed25519 verification (RFC 8032, rejecting small order keys and
/// non canonical signatures).
pub fn verify_ed25519(hi: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(hi) else {
        return false;
    };
    key.verify_strict(msg, &Signature::from_bytes(sig)).is_ok()
}

/// A key known for a DET.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyInfo {
    /// Ed25519 Host Identity.
    pub hi: [u8; 32],
    /// Trusted: configured as a trust anchor, or endorsed by a trusted
    /// parent through a verified DRIP Link.
    pub trusted: bool,
}

/// Where verifiers look up and record keys.
pub trait KeyStore {
    /// The key for `det`, if known.
    fn key(&self, det: &Det) -> Option<KeyInfo>;
    /// Records a key. Implementations must not downgrade a trusted key to
    /// untrusted, and must not replace a trusted key with a different one.
    fn learn(&mut self, det: Det, info: KeyInfo);
}

/// A fixed size key store for `no_std` use (oldest learned entry is
/// replaced when full; trusted entries are kept).
#[derive(Debug, Clone)]
pub struct FixedKeyStore<const N: usize> {
    entries: [Option<(Det, KeyInfo)>; N],
    next: usize,
}

impl<const N: usize> Default for FixedKeyStore<N> {
    fn default() -> Self {
        FixedKeyStore {
            entries: [None; N],
            next: 0,
        }
    }
}

impl<const N: usize> FixedKeyStore<N> {
    /// Adds a trust anchor.
    pub fn trust(&mut self, det: Det, hi: [u8; 32]) {
        self.learn(det, KeyInfo { hi, trusted: true });
    }
}

impl<const N: usize> KeyStore for FixedKeyStore<N> {
    fn key(&self, det: &Det) -> Option<KeyInfo> {
        self.entries
            .iter()
            .flatten()
            .find(|(d, _)| d == det)
            .map(|e| e.1)
    }

    fn learn(&mut self, det: Det, info: KeyInfo) {
        if N == 0 {
            return;
        }
        if let Some(e) = self.entries.iter_mut().flatten().find(|(d, _)| *d == det) {
            if e.1.trusted && (!info.trusted || info.hi != e.1.hi) {
                return;
            }
            e.1 = info;
            return;
        }
        if let Some(slot) = self.entries.iter_mut().find(|e| e.is_none()) {
            *slot = Some((det, info));
            return;
        }
        for _ in 0..N {
            let i = self.next % N;
            self.next = self.next.wrapping_add(1);
            if !self.entries[i].is_some_and(|e| e.1.trusted) {
                self.entries[i] = Some((det, info));
                return;
            }
        }
    }
}

/// A growable key store (needs `std`).
#[cfg(feature = "std")]
#[derive(Debug, Clone, Default)]
pub struct MemoryKeyStore {
    map: std::collections::HashMap<Det, KeyInfo>,
}

#[cfg(feature = "std")]
impl MemoryKeyStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a trust anchor.
    pub fn trust(&mut self, det: Det, hi: [u8; 32]) {
        self.learn(det, KeyInfo { hi, trusted: true });
    }

    /// Number of keys.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(feature = "std")]
impl KeyStore for MemoryKeyStore {
    fn key(&self, det: &Det) -> Option<KeyInfo> {
        self.map.get(det).copied()
    }

    fn learn(&mut self, det: Det, info: KeyInfo) {
        match self.map.get(&det) {
            Some(old) if old.trusted && (!info.trusted || info.hi != old.hi) => {}
            _ => {
                self.map.insert(det, info);
            }
        }
    }
}

/// What a verifier may use besides the authentication message itself.
#[derive(Debug, Clone, Copy, Default)]
pub struct AuthContext<'a> {
    /// DETs this aircraft broadcasts in its Basic ID messages.
    pub uas_dets: &'a [Det],
    /// Recently received single messages (header byte first, no counter).
    pub recent_messages: &'a [[u8; MESSAGE_SIZE]],
    /// [`auth_hash`] of recently received messages and whole message packs,
    /// with the message type (15 for a pack, then `pack_has_location`).
    pub recent_hashes: &'a [([u8; 8], u8, bool)],
    /// For an authentication message that came in a pack: the pack's other
    /// messages in pack order.
    pub pack_messages: &'a [[u8; MESSAGE_SIZE]],
    /// Receiver UTC clock, Unix seconds, for the VNB / VNA window.
    pub now_unix: Option<u64>,
    /// Clock skew allowed on both ends of the validity window, seconds.
    pub skew_s: u32,
}

/// Which DRIP format a result is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AuthKind {
    /// DRIP Link (Broadcast Endorsement).
    Link,
    /// DRIP Wrapper.
    Wrapper,
    /// DRIP Manifest.
    Manifest,
    /// DRIP Frame.
    Frame,
    /// A scheme outside DRIP.
    Other,
}

/// Why a message failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum InvalidReason {
    /// The signature does not verify under the signer's key.
    BadSignature,
    /// A DET does not match the Host Identity sent with it.
    DetHiMismatch,
    /// The signer DET is not the DET the aircraft broadcasts.
    SignerNotUas,
    /// The Current Manifest Hash does not match the Manifest.
    ManifestChain,
    /// The structure is malformed.
    Malformed,
}

/// Outcome of one verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AuthResult {
    /// This scheme does not handle the message's format.
    NotHandled,
    /// The format is recognised but its algorithm or type is not supported.
    Unsupported,
    /// The key needed to verify is missing.
    Unverifiable,
    /// The signature verified.
    Valid {
        /// Format.
        kind: AuthKind,
        /// Signer DET.
        signer: Det,
        /// The signer's key is trusted (anchor or chain to one).
        trusted: bool,
        /// The signed content matched messages actually received: a wrapped
        /// or hashed Location message, or the pack the signature covers.
        content_validated: bool,
        /// Inside the VNB / VNA window (`None` without a receiver clock).
        fresh: Option<bool>,
    },
    /// Verification failed.
    Invalid(InvalidReason),
}

/// A pluggable authentication scheme.
pub trait AuthScheme {
    /// Verifies one complete authentication message.
    fn verify(
        &mut self,
        msg: &AssembledAuth,
        ctx: &AuthContext<'_>,
        keys: &mut dyn KeyStore,
    ) -> AuthResult;
}

/// DRIP with Ed25519 DETs (RFC 9374 suite 5, RFC 9575 formats).
#[derive(Debug, Clone, Copy, Default)]
pub struct DripEd25519;

fn fresh(vnb: u32, vna: u32, ctx: &AuthContext<'_>) -> Option<bool> {
    let now = ctx.now_unix?;
    let vnb = vnb as u64 + crate::EPOCH_2019_UNIX;
    let vna = vna as u64 + crate::EPOCH_2019_UNIX;
    let skew = ctx.skew_s as u64;
    Some(now + skew >= vnb && now <= vna + skew)
}

impl DripEd25519 {
    fn verify_evidence(
        &self,
        kind: AuthKind,
        ev: &Evidence<'_>,
        signed: &[u8],
        ctx: &AuthContext<'_>,
        keys: &mut dyn KeyStore,
    ) -> Result<(bool, bool), AuthResult> {
        if ev.det.suite_id() != SUITE_EDDSA_CSHAKE128 {
            return Err(AuthResult::Unsupported);
        }
        if !ctx.uas_dets.is_empty() && !ctx.uas_dets.contains(&ev.det) {
            return Err(AuthResult::Invalid(InvalidReason::SignerNotUas));
        }
        let key = keys.key(&ev.det).ok_or(AuthResult::Unverifiable)?;
        if !det_matches_hi(&ev.det, &key.hi) {
            return Err(AuthResult::Invalid(InvalidReason::DetHiMismatch));
        }
        if !verify_ed25519(&key.hi, signed, &ev.signature) {
            return Err(AuthResult::Invalid(InvalidReason::BadSignature));
        }
        let _ = kind;
        Ok((key.trusted, true))
    }
}

impl AuthScheme for DripEd25519 {
    fn verify(
        &mut self,
        msg: &AssembledAuth,
        ctx: &AuthContext<'_>,
        keys: &mut dyn KeyStore,
    ) -> AuthResult {
        if msg.auth_type != AuthType::SpecificAuthentication {
            return AuthResult::NotHandled;
        }
        let Ok(drip) = msg.drip() else {
            return AuthResult::NotHandled;
        };
        match drip {
            DripAuth::Link(l) => {
                if l.child_det.suite_id() != SUITE_EDDSA_CSHAKE128
                    || l.parent_det.suite_id() != SUITE_EDDSA_CSHAKE128
                {
                    return AuthResult::Unsupported;
                }
                if !det_matches_hi(&l.child_det, &l.child_hi) {
                    return AuthResult::Invalid(InvalidReason::DetHiMismatch);
                }
                match keys.key(&l.parent_det) {
                    Some(parent) => {
                        if !det_matches_hi(&l.parent_det, &parent.hi) {
                            return AuthResult::Invalid(InvalidReason::DetHiMismatch);
                        }
                        if !verify_ed25519(&parent.hi, l.signed, &l.signature) {
                            return AuthResult::Invalid(InvalidReason::BadSignature);
                        }
                        let f = fresh(l.vnb, l.vna, ctx);
                        // An expired endorsement does not pass trust on.
                        let trusted = parent.trusted && f != Some(false);
                        keys.learn(
                            l.child_det,
                            KeyInfo {
                                hi: l.child_hi,
                                trusted,
                            },
                        );
                        AuthResult::Valid {
                            kind: AuthKind::Link,
                            signer: l.parent_det,
                            trusted: parent.trusted,
                            content_validated: true,
                            fresh: f,
                        }
                    }
                    None => {
                        // The child key is self certified by its DET; keep it
                        // untrusted so later Wrappers and Manifests can be
                        // checked for consistency.
                        keys.learn(
                            l.child_det,
                            KeyInfo {
                                hi: l.child_hi,
                                trusted: false,
                            },
                        );
                        AuthResult::Unverifiable
                    }
                }
            }
            DripAuth::Wrapper(ev) => {
                let mut buf = [0u8; 8 + 9 * MESSAGE_SIZE + 16];
                let (signed, content_validated): (&[u8], bool) = if ev.evidence.is_empty() {
                    // Extended transport: rebuild the evidence from the pack's
                    // other messages, sorted by message type.
                    if ctx.pack_messages.is_empty() {
                        return AuthResult::Unverifiable;
                    }
                    let mut msgs: [Option<&[u8; MESSAGE_SIZE]>; 9] = [None; 9];
                    let mut n = 0;
                    for m in ctx.pack_messages.iter().filter(|m| m[0] >> 4 != 2) {
                        if n == 9 {
                            break;
                        }
                        msgs[n] = Some(m);
                        n += 1;
                    }
                    msgs[..n].sort_unstable_by_key(|m| m.map(|m| m[0] >> 4));
                    buf[..8].copy_from_slice(&ev.signed[..8]);
                    let mut at = 8;
                    for m in msgs[..n].iter().flatten() {
                        buf[at..at + MESSAGE_SIZE].copy_from_slice(&m[..]);
                        at += MESSAGE_SIZE;
                    }
                    buf[at..at + 16].copy_from_slice(&ev.det.0);
                    (&buf[..at + 16], true)
                } else {
                    let validated = ev
                        .wrapped_messages()
                        .any(|m| m[0] >> 4 == 1 && ctx.recent_messages.iter().any(|r| r == m));
                    (ev.signed, validated)
                };
                match self.verify_evidence(AuthKind::Wrapper, &ev, signed, ctx, keys) {
                    Ok((trusted, _)) => AuthResult::Valid {
                        kind: AuthKind::Wrapper,
                        signer: ev.det,
                        trusted,
                        content_validated,
                        fresh: fresh(ev.vnb, ev.vna, ctx),
                    },
                    Err(r) => r,
                }
            }
            DripAuth::Manifest(ev) => {
                if let Err(r) = self.verify_evidence(AuthKind::Manifest, &ev, ev.signed, ctx, keys)
                {
                    return r;
                }
                let trusted = keys.key(&ev.det).is_some_and(|k| k.trusted);
                // Current Manifest Hash: over previous, a null current, the
                // Link hash and the message hashes (RFC 9575 Appendix B.2.1),
                // or without the Link hash (Section 4.4.3 step 4).
                let e = ev.evidence;
                let zero = [0u8; 8];
                let with_link = auth_hash_parts(&[&e[..8], &zero, &e[16..]]);
                let without_link = auth_hash_parts(&[&e[..8], &zero, &e[24..]]);
                let current = ev.current_manifest_hash().unwrap();
                if current != with_link && current != without_link {
                    return AuthResult::Invalid(InvalidReason::ManifestChain);
                }
                let content_validated = ev.message_hashes().any(|h| {
                    ctx.recent_hashes
                        .iter()
                        .any(|(rh, t, has_loc)| *rh == h && (*t == 1 || (*t == 15 && *has_loc)))
                });
                AuthResult::Valid {
                    kind: AuthKind::Manifest,
                    signer: ev.det,
                    trusted,
                    content_validated,
                    fresh: fresh(ev.vnb, ev.vna, ctx),
                }
            }
            DripAuth::Frame(ev) => {
                match self.verify_evidence(AuthKind::Frame, &ev, ev.signed, ctx, keys) {
                    Ok((trusted, _)) => AuthResult::Valid {
                        kind: AuthKind::Frame,
                        signer: ev.det,
                        trusted,
                        // Frame contents are not defined by any registered type yet.
                        content_validated: false,
                        fresh: fresh(ev.vnb, ev.vna, ctx),
                    },
                    Err(r) => r,
                }
            }
        }
    }
}

/// Hash of a DRIP Link for the Manifest's Link field: [`auth_hash`] of the
/// Link's Authentication Data without its SAM type byte (the form the RFC
/// 9575 Appendix B.2.1 example uses).
pub fn link_hash(link_data: &[u8]) -> [u8; 8] {
    auth_hash(link_data.get(1..).unwrap_or(&[]))
}

/// Builds signed DRIP authentication data (the transmitter side).
///
/// ```
/// use remoteid::auth::{AuthContext, AuthResult, AuthScheme, DripEd25519, DripSigner, MemoryKeyStore};
/// use remoteid::drip::{self, AssembledAuth, AuthAssembler};
/// use remoteid::AuthType;
///
/// let hda = DripSigner::new([7; 32], 16376, 1);
/// let ua = DripSigner::new([9; 32], 16376, 1);
/// let link = hda.link(&ua.det(), &ua.hi(), 0, 600);
///
/// // Page it with FEC, as for Bluetooth 4, and join it again.
/// let pages = drip::paginate(AuthType::SpecificAuthentication, 2, 0, &link, true).unwrap();
/// let mut msg = AssembledAuth::default();
/// assert!(AuthAssembler::push_pack(&pages, &mut msg));
///
/// let mut keys = MemoryKeyStore::new();
/// keys.trust(hda.det(), hda.hi());
/// let r = DripEd25519.verify(&msg, &AuthContext::default(), &mut keys);
/// assert!(matches!(r, AuthResult::Valid { trusted: true, .. }));
/// ```
#[derive(Debug, Clone)]
pub struct DripSigner {
    key: SigningKey,
    det: Det,
}

impl DripSigner {
    /// A signer for the Ed25519 key with this 32 byte secret seed, with its
    /// DET under `raa` and `hda`.
    pub fn new(secret: [u8; 32], raa: u16, hda: u16) -> Self {
        let key = SigningKey::from_bytes(&secret);
        let det = det_for_hi(raa, hda, &key.verifying_key().to_bytes());
        DripSigner { key, det }
    }

    /// The signer's DET.
    pub fn det(&self) -> Det {
        self.det
    }

    /// The signer's Host Identity (public key).
    pub fn hi(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// A DRIP Link endorsing `child_det` / `child_hi` (137 bytes).
    pub fn link(&self, child_det: &Det, child_hi: &[u8; 32], vnb: u32, vna: u32) -> [u8; 137] {
        let mut out = [0u8; 137];
        out[0] = SAM_LINK;
        out[1..5].copy_from_slice(&vnb.to_le_bytes());
        out[5..9].copy_from_slice(&vna.to_le_bytes());
        out[9..25].copy_from_slice(&child_det.0);
        out[25..57].copy_from_slice(child_hi);
        out[57..73].copy_from_slice(&self.det.0);
        let sig = self.key.sign(&out[1..73]).to_bytes();
        out[73..].copy_from_slice(&sig);
        out
    }

    fn evidence(
        &self,
        sam: u8,
        vnb: u32,
        vna: u32,
        evidence: &[u8],
        send_evidence: bool,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let signed_len = 8 + evidence.len() + 16;
        let n = 1 + if send_evidence { signed_len } else { 24 } + 64;
        if n > crate::drip::MAX_AUTH_LENGTH {
            return Err(Error::OutOfRange("evidence"));
        }
        if out.len() < n {
            return Err(Error::BufferTooSmall {
                need: n,
                got: out.len(),
            });
        }
        let mut signed = [0u8; 8 + 9 * MESSAGE_SIZE + 16];
        signed[..4].copy_from_slice(&vnb.to_le_bytes());
        signed[4..8].copy_from_slice(&vna.to_le_bytes());
        signed[8..8 + evidence.len()].copy_from_slice(evidence);
        signed[8 + evidence.len()..signed_len].copy_from_slice(&self.det.0);
        let sig = self.key.sign(&signed[..signed_len]).to_bytes();
        out[0] = sam;
        if send_evidence {
            out[1..1 + signed_len].copy_from_slice(&signed[..signed_len]);
        } else {
            out[1..9].copy_from_slice(&signed[..8]);
            out[9..25].copy_from_slice(&self.det.0);
        }
        out[n - 64..n].copy_from_slice(&sig);
        Ok(n)
    }

    /// A DRIP Wrapper over up to four messages (types 0, 1, 3, 4, 5, in
    /// type order, 25 bytes each without counter).
    pub fn wrapper(
        &self,
        vnb: u32,
        vna: u32,
        messages: &[[u8; MESSAGE_SIZE]],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if messages.is_empty() || messages.len() > 4 {
            return Err(Error::OutOfRange("wrapped message count"));
        }
        let mut ev = [0u8; 4 * MESSAGE_SIZE];
        for (i, m) in messages.iter().enumerate() {
            ev[i * MESSAGE_SIZE..(i + 1) * MESSAGE_SIZE].copy_from_slice(m);
        }
        self.evidence(
            SAM_WRAPPER,
            vnb,
            vna,
            &ev[..messages.len() * MESSAGE_SIZE],
            true,
            out,
        )
    }

    /// A DRIP Wrapper for an extended transport: signs the other messages
    /// of the message pack it will be sent in (in message type order) and
    /// leaves the evidence out of the transmitted form (89 bytes).
    pub fn wrapper_extended(
        &self,
        vnb: u32,
        vna: u32,
        pack_messages: &[[u8; MESSAGE_SIZE]],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if pack_messages.len() > 8 {
            return Err(Error::OutOfRange("pack message count"));
        }
        let mut ev = [0u8; 8 * MESSAGE_SIZE];
        for (i, m) in pack_messages.iter().enumerate() {
            ev[i * MESSAGE_SIZE..(i + 1) * MESSAGE_SIZE].copy_from_slice(m);
        }
        self.evidence(
            SAM_WRAPPER,
            vnb,
            vna,
            &ev[..pack_messages.len() * MESSAGE_SIZE],
            false,
            out,
        )
    }

    /// A DRIP Manifest. `previous` is the last Manifest's current hash (a
    /// random nonce for the first), `link` the [`link_hash`] of the Link
    /// sent with it, `hashes` the [`auth_hash`]es of the messages sent.
    /// Returns the length and this Manifest's current hash.
    pub fn manifest(
        &self,
        vnb: u32,
        vna: u32,
        previous: [u8; 8],
        link: [u8; 8],
        hashes: &[[u8; 8]],
        out: &mut [u8],
    ) -> Result<(usize, [u8; 8]), Error> {
        if hashes.len() > 11 {
            return Err(Error::OutOfRange("manifest hash count"));
        }
        let mut ev = [0u8; 14 * 8];
        ev[..8].copy_from_slice(&previous);
        ev[16..24].copy_from_slice(&link);
        for (i, h) in hashes.iter().enumerate() {
            ev[24 + 8 * i..32 + 8 * i].copy_from_slice(h);
        }
        let n = 24 + 8 * hashes.len();
        let current = auth_hash(&ev[..n]);
        ev[8..16].copy_from_slice(&current);
        Ok((
            self.evidence(SAM_MANIFEST, vnb, vna, &ev[..n], true, out)?,
            current,
        ))
    }

    /// A DRIP Frame of `frame_type` with `data`.
    pub fn frame(
        &self,
        vnb: u32,
        vna: u32,
        frame_type: u8,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if data.len() > 111 {
            return Err(Error::OutOfRange("frame data"));
        }
        let mut ev = [0u8; 112];
        ev[0] = frame_type;
        ev[1..1 + data.len()].copy_from_slice(data);
        self.evidence(SAM_FRAME, vnb, vna, &ev[..1 + data.len()], true, out)
    }
}
