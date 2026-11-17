//! DRIP authentication (RFC 9374 DETs, RFC 9575 formats) end to end.
//!
//! The official vectors are the raw example of RFC 9575 Appendix B.2.1:
//! a DET and its HI, eight ASTM messages, and a Link, a Wrapper and a
//! Manifest, each with FEC. They were also checked independently with
//! pycryptodome (cSHAKE128) and pyca/cryptography (Ed25519) while writing
//! this test; the expected values below are from that check.
#![cfg(feature = "verify")]

mod common;

use remoteid::auth::{
    auth_hash, det_for_hi, det_matches_hi, link_hash, AuthContext, AuthKind, AuthResult,
    AuthScheme, DripEd25519, DripSigner, InvalidReason, KeyStore, MemoryKeyStore,
};
use remoteid::drip::{self, AssembledAuth, AuthAssembler, Det, DripAuth};
use remoteid::trust::AuthState;
use remoteid::{
    Auth, AuthType, BasicId, IdType, Location, Message, MessagePackBuilder, Observation, Tracker,
    TrackerConfig, Transmitter, Transport, UaType, Verdict,
};

/// A receiver UTC clock (2026-11-17), inside the VNB / VNA windows the
/// signer tests use.
const UNIX_MS: u64 = 1_794_916_800_000;
/// The Auth page timestamp for [`UNIX_MS`] (seconds since 2019-01-01).
const AUTH_TS: u32 = (UNIX_MS / 1000 - 1_546_300_800) as u32;

const DET: &str = "2001003ffe000105a29b3ff42226c04e";
const HI: &str = "b5fef530d450dedb59ebafa18b00d7f5ed0ac08a81975034297bea2b00041813";

const MESSAGES: [&str; 8] = [
    "0240012001003ffe000105a29b3ff42226c04e000000000000",
    "12000000000000000000000000000000000000000060220000",
    "32004578616d706c652053656c662049440000000000000000",
    "420000000000000000000100000000000000000010ea510900",
    "52004578616d706c65204f70657261746f7220494400000000",
    "0240012001003ffe000105a29b3ff42226c04e000000000000",
    "12000000000000000000000000000000000000000060220000",
    "420000000000000000000100000000000000000010ea510900",
];

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

const WRAPPER: [&str; 8] = [
    "2250078b10ea510902e0dd7c6560115e671200000000000000",
    "22510000000000000000000000000060220000420000000000",
    "2252000000000100000000000000000010ea5109002001003f",
    "2253fe000105a29b3ff42226c04ef0ecad581a030ca790152a",
    "22542f08df5762a463e24a742d1c530ec977bbe0d113697e2b",
    "2255b909d6c7557bdaf1227ce86154b030daadda4a6b8474de",
    "22569a62f6c375020826000000000000000000000000000000",
    "2257f5e8eebcb04f8c2197526053e66c010d5d7297ff7c1fe0",
];

const MANIFEST: [&str; 9] = [
    "225008b110ea510903e0dd7c6560115e670000000000000000",
    "2251d57594875f8608b4d61dc9224ecf8b842bd4862734ed01",
    "22522ca2e5f2b8a3e61547b81704766ba3eeb651be7eafc928",
    "22538884e3e28a24fd5529bc2bd4862734ed012ca2e5f2b8a3",
    "2254e61547b81704766ba3eeb62001003ffe000105a29b3ff4",
    "22552226c04efb729846e7d110903797066fd96f49a77c5a48",
    "2256c4c3b330be05bc4a958e9641718aaa31aeabad368386a2",
    "22579ed2dce2769120da83edbcdc0858dd1e357755e7860317",
    "2258e7c06a5918ea62a937391cbfe0983539de1b2e688b7c83",
];

fn h(s: &str) -> Vec<u8> {
    common::unhex(s)
}

fn msg25(s: &str) -> [u8; 25] {
    h(s).try_into().unwrap()
}

fn det() -> Det {
    Det::from_slice(&h(DET)).unwrap()
}

fn hi() -> [u8; 32] {
    h(HI).try_into().unwrap()
}

fn pages(raw: &[&str]) -> Vec<Auth> {
    raw.iter()
        .map(|r| Auth::decode(&msg25(r)).unwrap())
        .collect()
}

fn assemble(raw: &[&str]) -> AssembledAuth {
    let mut out = AssembledAuth::default();
    assert!(AuthAssembler::push_pack(&pages(raw), &mut out));
    out
}

#[test]
fn rfc9575_det_binds_hi() {
    assert!(det_matches_hi(&det(), &hi()));
    assert_eq!(det_for_hi(det().raa(), det().hda(), &hi()), det());
    let mut wrong = hi();
    wrong[0] ^= 1;
    assert!(!det_matches_hi(&det(), &wrong));
    // The Basic ID message carries it as a Specific Session ID of type 1.
    let b = match Message::decode(&msg25(MESSAGES[0])).unwrap() {
        Message::BasicId(b) => b,
        m => panic!("{m:?}"),
    };
    assert_eq!(Det::from_basic_id(&b), Some(det()));
}

#[test]
fn rfc9575_manifest_hashes() {
    let expect = [
        "2bd4862734ed012c",
        "a2e5f2b8a3e61547",
        "51be7eafc9288884",
        "b81704766ba3eeb6",
        "e3e28a24fd5529bc",
    ];
    for (m, e) in MESSAGES.iter().zip(expect) {
        assert_eq!(auth_hash(&h(m)), h(e)[..]);
    }
    // The Manifest's Link field is the hash of the Link without its SAM byte.
    let link = assemble(&LINK);
    assert_eq!(link_hash(link.data())[..], h("d61dc9224ecf8b84")[..]);
}

fn ctx_with<'a>(
    recent: &'a [[u8; 25]],
    hashes: &'a [([u8; 8], u8, bool)],
    dets: &'a [Det],
) -> AuthContext<'a> {
    AuthContext {
        uas_dets: dets,
        recent_messages: recent,
        recent_hashes: hashes,
        ..AuthContext::default()
    }
}

#[test]
fn rfc9575_wrapper_and_manifest_verify() {
    let recent: Vec<[u8; 25]> = MESSAGES.iter().map(|m| msg25(m)).collect();
    let hashes: Vec<([u8; 8], u8, bool)> = recent
        .iter()
        .map(|m| (auth_hash(m), m[0] >> 4, false))
        .collect();
    let dets = [det()];
    let ctx = ctx_with(&recent, &hashes, &dets);

    // No key yet: unverifiable.
    let mut keys = MemoryKeyStore::new();
    let wrapper = assemble(&WRAPPER);
    assert_eq!(
        DripEd25519.verify(&wrapper, &ctx, &mut keys),
        AuthResult::Unverifiable
    );

    // The Link carries the UA key; its parent (the HDA) is unknown, so the
    // Link itself cannot be verified but the key is learned, untrusted.
    let link = assemble(&LINK);
    assert!(matches!(link.drip().unwrap(), DripAuth::Link(_)));
    assert_eq!(
        DripEd25519.verify(&link, &ctx, &mut keys),
        AuthResult::Unverifiable
    );
    assert_eq!(
        keys.key(&det()).map(|k| (k.hi, k.trusted)),
        Some((hi(), false))
    );

    for (raw, kind) in [
        (&WRAPPER[..], AuthKind::Wrapper),
        (&MANIFEST[..], AuthKind::Manifest),
    ] {
        let msg = assemble(raw);
        assert!(msg.fec);
        match DripEd25519.verify(&msg, &ctx, &mut keys) {
            AuthResult::Valid {
                kind: k,
                signer,
                trusted,
                content_validated,
                fresh,
            } => {
                assert_eq!(k, kind);
                assert_eq!(signer, det());
                assert!(!trusted);
                assert!(content_validated, "{kind:?}");
                assert_eq!(fresh, None);
            }
            other => panic!("{kind:?}: {other:?}"),
        }
    }

    // Pinned as trusted: the same signatures now count as trusted.
    let mut pinned = MemoryKeyStore::new();
    pinned.trust(det(), hi());
    assert!(matches!(
        DripEd25519.verify(&wrapper, &ctx, &mut pinned),
        AuthResult::Valid { trusted: true, .. }
    ));
}

#[test]
fn rfc9575_tampering_is_caught() {
    let recent: Vec<[u8; 25]> = MESSAGES.iter().map(|m| msg25(m)).collect();
    let dets = [det()];
    let ctx = ctx_with(&recent, &[], &dets);
    let mut keys = MemoryKeyStore::new();
    keys.trust(det(), hi());
    // Change the wrapped Location's latitude (page 1) and fix up the FEC
    // page so only the signature can tell.
    let mut ps = pages(&WRAPPER);
    ps[1].data[10] ^= 0x01;
    ps[7].data[10] ^= 0x01;
    let mut msg = AssembledAuth::default();
    assert!(AuthAssembler::push_pack(&ps, &mut msg));
    assert_eq!(
        DripEd25519.verify(&msg, &ctx, &mut keys),
        AuthResult::Invalid(InvalidReason::BadSignature)
    );
    // A signer that is not the DET the aircraft broadcasts.
    let other = [det_for_hi(1, 1, &[3; 32])];
    let ctx2 = ctx_with(&recent, &[], &other);
    assert_eq!(
        DripEd25519.verify(&assemble(&WRAPPER), &ctx2, &mut keys),
        AuthResult::Invalid(InvalidReason::SignerNotUas)
    );
}

/// The RFC example sent over Bluetooth 4 the way its Appendix B schedule
/// does: the messages every second, the Manifest as a burst of pages, and
/// one page of the Link and of the Wrapper per second.
fn rfc_bt4_stream(tracker: &mut Tracker, addr: [u8; 6]) -> remoteid::Assessment {
    let mut counter = [0u8; 16];
    let mut now = 1_000u64;
    let mut send = |t: &mut Tracker, raw: &[u8; 25], now: u64| {
        let ty = (raw[0] >> 4) as usize;
        counter[ty] = counter[ty].wrapping_add(1);
        let obs = Observation::new(Transport::Bluetooth4, Some(counter[ty]), raw, now);
        t.observe(Transmitter::Ble(addr), &obs).assessment
    };
    let mut a = remoteid::Assessment::default();
    for second in 0..16 {
        for m in MESSAGES {
            send(tracker, &msg25(m), now);
            now += 20;
        }
        for p in MANIFEST {
            send(tracker, &msg25(p), now);
            now += 20;
        }
        let slow = if second < 8 {
            LINK[second]
        } else {
            WRAPPER[second - 8]
        };
        a = send(tracker, &msg25(slow), now);
        now += 1_000 - 20 * 17;
    }
    a
}

#[test]
fn rfc9575_stream_through_tracker() {
    // The stream has no receiver UTC clock, so the signatures cannot be
    // checked against VNB / VNA: they verify, but the verdict stays below
    // Authenticated unless the clock requirement is switched off.
    let mut no_clock = TrackerConfig::default();
    no_clock.trust.auth_requires_clock = false;

    // Key learned from the Link only: self certified.
    let mut t = Tracker::new(no_clock);
    let a = rfc_bt4_stream(&mut t, [1; 6]);
    assert_eq!(a.auth, AuthState::Verified);
    assert_eq!(a.verdict, Verdict::Plausible, "{:?}", a.reasons);

    let mut cfg = no_clock;
    cfg.trust.accept_self_certified = true;
    let mut t = Tracker::new(cfg);
    let a = rfc_bt4_stream(&mut t, [1; 6]);
    assert_eq!(a.verdict, Verdict::Authenticated, "{:?}", a.reasons);

    // The aircraft key pinned as trusted.
    let mut t = Tracker::new(no_clock);
    t.keys_mut().trust(det(), hi());
    let a = rfc_bt4_stream(&mut t, [1; 6]);
    assert_eq!(a.auth, AuthState::Trusted);
    assert_eq!(a.verdict, Verdict::Authenticated, "{:?}", a.reasons);
    assert!(a.score > 0.9);
    // The identity shown is the signing DET.
    let u = t.get(&Transmitter::Ble([1; 6])).unwrap();
    assert_eq!(u.uas_id(), Some(det().to_string()));

    // Default settings: trusted signatures, but no clock, so not Authenticated.
    let mut t = Tracker::default();
    t.keys_mut().trust(det(), hi());
    let a = rfc_bt4_stream(&mut t, [1; 6]);
    assert_eq!(a.auth, AuthState::Trusted);
    assert_eq!(a.verdict, Verdict::Plausible, "{:?}", a.reasons);
}

/// Bluetooth 4 Location with the given latitude.
fn location(lat: f64) -> [u8; 25] {
    Message::Location(Location {
        latitude: lat,
        longitude: 8.5,
        speed_horizontal: Some(0.0),
        direction: Some(0.0),
        altitude_geo: Some(500.0),
        horizontal_accuracy: remoteid::HorizontalAccuracy(11),
        ..Location::default()
    })
    .encode()
    .unwrap()
}

fn det_basic_id(d: &Det) -> [u8; 25] {
    let mut b = BasicId::new(
        IdType::SpecificSessionId,
        UaType::HelicopterOrMultirotor,
        "",
    )
    .unwrap();
    b.uas_id[0] = drip::SESSION_ID_TYPE_DRIP;
    b.uas_id[1..17].copy_from_slice(&d.0);
    Message::BasicId(b).encode().unwrap()
}

#[test]
fn signed_chain_over_extended_transport() {
    // HDA (trust anchor) endorses the UA; the UA signs every pack with an
    // extended-transport Wrapper.
    let hda = DripSigner::new([0x11; 32], 16376, 1025);
    let ua = DripSigner::new([0x22; 32], 16376, 1025);
    let link = hda.link(&ua.det(), &ua.hi(), 0, u32::MAX);
    let mut t = Tracker::default();
    t.keys_mut().trust(hda.det(), hda.hi());
    let id = det_basic_id(&ua.det());
    let mut a = remoteid::Assessment::default();
    for i in 0..10u64 {
        let now = 1_000 + 1_000 * i;
        // Pack 1: the Link.
        let mut b = MessagePackBuilder::new();
        for p in
            &drip::paginate(AuthType::SpecificAuthentication, 2, AUTH_TS, &link, false).unwrap()
        {
            b.push(&Message::Auth(p.clone())).unwrap();
        }
        t.observe(
            Transmitter::Ble([7; 6]),
            &Observation::new(Transport::Bluetooth5, Some(2 * i as u8), b.as_bytes(), now)
                .with_unix_ms(UNIX_MS + now),
        );
        // Pack 2: Basic ID, Location and the Wrapper over both.
        let loc = location(47.0 + i as f64 * 1e-6);
        let mut w = [0u8; 201];
        let n = ua
            .wrapper_extended(0, u32::MAX, &[id, loc], &mut w)
            .unwrap();
        let mut b = MessagePackBuilder::new();
        b.push_raw(&id).unwrap();
        b.push_raw(&loc).unwrap();
        for p in
            &drip::paginate(AuthType::SpecificAuthentication, 2, AUTH_TS, &w[..n], false).unwrap()
        {
            b.push(&Message::Auth(p.clone())).unwrap();
        }
        a = t
            .observe(
                Transmitter::Ble([7; 6]),
                &Observation::new(
                    Transport::Bluetooth5,
                    Some(2 * i as u8 + 1),
                    b.as_bytes(),
                    now + 500,
                )
                .with_unix_ms(UNIX_MS + now + 500),
            )
            .assessment;
    }
    assert_eq!(a.auth, AuthState::Trusted);
    assert_eq!(a.verdict, Verdict::Authenticated, "{:?}", a.reasons);

    // Someone else replays the same identity with their own key: their
    // Wrapper does not verify under the endorsed key.
    let mallory = DripSigner::new([0x33; 32], 16376, 1025);
    let loc = location(47.1);
    let mut w = [0u8; 201];
    let n = mallory
        .wrapper_extended(0, u32::MAX, &[id, loc], &mut w)
        .unwrap();
    // Forge the signer DET field to claim the UA's DET.
    w[9..25].copy_from_slice(&ua.det().0);
    let mut b = MessagePackBuilder::new();
    b.push_raw(&id).unwrap();
    b.push_raw(&loc).unwrap();
    for p in &drip::paginate(AuthType::SpecificAuthentication, 2, AUTH_TS, &w[..n], false).unwrap()
    {
        b.push(&Message::Auth(p.clone())).unwrap();
    }
    let a = t
        .observe(
            Transmitter::Ble([7; 6]),
            &Observation::new(Transport::Bluetooth5, Some(99), b.as_bytes(), 20_000)
                .with_unix_ms(UNIX_MS + 20_000),
        )
        .assessment;
    assert_eq!(a.auth, AuthState::Conflicting);
    assert_eq!(a.verdict, Verdict::Spoofed);
    assert!(a.reasons.contains(remoteid::Reason::AuthFailed));
}

#[test]
fn expired_signature_is_not_authenticated() {
    let ua = DripSigner::new([0x44; 32], 16376, 1025);
    let mut t = Tracker::default();
    t.keys_mut().trust(ua.det(), ua.hi());
    let id = det_basic_id(&ua.det());
    let loc = location(47.0);
    // Valid for two minutes in 2024 (seconds since 2019-01-01).
    let vnb = 170_000_000;
    let mut w = [0u8; 201];
    let n = ua
        .wrapper_extended(vnb, vnb + 120, &[id, loc], &mut w)
        .unwrap();
    let mut b = MessagePackBuilder::new();
    b.push_raw(&id).unwrap();
    b.push_raw(&loc).unwrap();
    for p in &drip::paginate(AuthType::SpecificAuthentication, 2, 0, &w[..n], false).unwrap() {
        b.push(&Message::Auth(p.clone())).unwrap();
    }
    // Received in 2026: a replay.
    let unix_ms = UNIX_MS;
    let obs =
        Observation::new(Transport::Bluetooth5, Some(1), b.as_bytes(), 1_000).with_unix_ms(unix_ms);
    let a = t.observe(Transmitter::Ble([8; 6]), &obs).assessment;
    assert_ne!(a.verdict, Verdict::Authenticated);
    assert!(
        a.reasons.contains(remoteid::Reason::AuthExpired),
        "{:?}",
        a.reasons
    );
}

#[test]
fn legacy_wrapper_and_manifest_from_signer() {
    // Bluetooth 4: messages one per frame, the Manifest as a burst with FEC,
    // and a lost Manifest page rebuilt from the parity page.
    let ua = DripSigner::new([0x55; 32], 100, 200);
    let id = det_basic_id(&ua.det());
    let loc = location(46.5);
    let mut t = Tracker::default();
    t.keys_mut().trust(ua.det(), ua.hi());
    let tx = Transmitter::Ble([9; 6]);
    let mut c = 0u8;
    let mut next = || {
        c = c.wrapping_add(1);
        c
    };
    t.observe(
        tx,
        &Observation::new(Transport::Bluetooth4, Some(next()), &id, 1_000).with_unix_ms(UNIX_MS),
    );
    t.observe(
        tx,
        &Observation::new(Transport::Bluetooth4, Some(next()), &loc, 1_010)
            .with_unix_ms(UNIX_MS + 10),
    );
    let mut out = [0u8; 201];
    let (n, _) = ua
        .manifest(
            0,
            u32::MAX,
            [9; 8],
            [0; 8],
            &[auth_hash(&id), auth_hash(&loc)],
            &mut out,
        )
        .unwrap();
    let ps = drip::paginate(
        AuthType::SpecificAuthentication,
        2,
        AUTH_TS,
        &out[..n],
        true,
    )
    .unwrap();
    let mut a = remoteid::Assessment::default();
    for (i, p) in ps.iter().enumerate() {
        if i == 2 {
            // Lost on the air; the counter still advanced.
            next();
            continue;
        }
        let raw = Message::Auth(p.clone()).encode().unwrap();
        a = t
            .observe(
                tx,
                &Observation::new(Transport::Bluetooth4, Some(next()), &raw, 1_100 + i as u64)
                    .with_unix_ms(UNIX_MS + 100 + i as u64),
            )
            .assessment;
    }
    // Page 2 never arrived; the burst kept going because counter and page
    // number advanced together, and FEC rebuilt page 2.
    assert_eq!(a.auth, AuthState::Trusted, "{a:?}");
    assert_eq!(a.verdict, Verdict::Authenticated);
}

/// One transmitter sending `basic_ids`, a Location replayed from a DRIP
/// aircraft and that aircraft's signed legacy Wrapper over it, five times.
fn obs(raw: &[u8; 25], at: u64) -> Observation<'_> {
    Observation::new(Transport::Bluetooth4, None, raw, at).with_unix_ms(UNIX_MS + at)
}

fn relay(t: &mut Tracker, tx: Transmitter, ua: &DripSigner, basic_ids: &[[u8; 25]]) {
    let mut c = 0u8;
    let mut next = || {
        c = c.wrapping_add(1);
        c
    };
    for i in 0..5u64 {
        let now = 1_000 + i * 1_000;
        for id in basic_ids {
            let mut o = obs(id, now);
            o.counter = Some(next());
            t.observe(tx, &o);
        }
        let loc = location(46.5);
        let mut o = obs(&loc, now + 10);
        o.counter = Some(next());
        t.observe(tx, &o);
        let mut out = [0u8; 201];
        let n = ua.wrapper(0, u32::MAX, &[loc], &mut out).unwrap();
        let ps = drip::paginate(
            AuthType::SpecificAuthentication,
            2,
            AUTH_TS,
            &out[..n],
            false,
        )
        .unwrap();
        for (k, p) in ps.iter().enumerate() {
            let raw = Message::Auth(p.clone()).encode().unwrap();
            let mut o = obs(&raw, now + 100 + k as u64);
            o.counter = Some(next());
            t.observe(tx, &o);
        }
    }
}

#[test]
fn relayed_signature_does_not_authenticate_another_identity() {
    // A spoofer relays a nearby DRIP aircraft's Location and signed Wrapper
    // under its own serial number Basic ID (no DET). The signature is valid
    // and the key trusted, but it says nothing about this identity.
    let ua = DripSigner::new([0x55; 32], 100, 200);
    let serial = Message::BasicId(
        BasicId::new(
            IdType::SerialNumber,
            UaType::HelicopterOrMultirotor,
            "1596F35074529ABCDEFG",
        )
        .unwrap(),
    )
    .encode()
    .unwrap();
    let mut t = Tracker::default();
    t.keys_mut().trust(ua.det(), ua.hi());
    let tx = Transmitter::Ble([0xAA; 6]);
    relay(&mut t, tx, &ua, &[serial]);
    let u = t.get(&tx).unwrap();
    assert_eq!(u.assessment.auth, AuthState::Unverifiable);
    assert_ne!(u.assessment.verdict, Verdict::Authenticated);
    assert_eq!(u.uas_id().as_deref(), Some("1596F35074529ABCDEFG"));

    // With the aircraft's DET broadcast as well, the signature binds to that
    // DET, and the identity shown is the DET, not the unsigned serial.
    let mut t = Tracker::default();
    t.keys_mut().trust(ua.det(), ua.hi());
    relay(&mut t, tx, &ua, &[serial, det_basic_id(&ua.det())]);
    let u = t.get(&tx).unwrap();
    assert_eq!(u.assessment.auth, AuthState::Trusted);
    assert_eq!(u.assessment.verdict, Verdict::Authenticated);
    assert_eq!(u.uas_id(), Some(ua.det().to_string()));
    assert_eq!(u.trust.authenticated_det(), Some(ua.det()));
}

#[test]
fn signer_must_be_broadcast_det_in_auth_scheme() {
    // Standalone verification without any broadcast DET is unverifiable.
    let recent: Vec<[u8; 25]> = MESSAGES.iter().map(|m| msg25(m)).collect();
    let ctx = ctx_with(&recent, &[], &[]);
    let mut keys = MemoryKeyStore::new();
    keys.trust(det(), hi());
    assert_eq!(
        DripEd25519.verify(&assemble(&WRAPPER), &ctx, &mut keys),
        AuthResult::Unverifiable
    );
}
