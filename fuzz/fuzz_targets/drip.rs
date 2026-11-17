//! DRIP parsing, page assembly and signature checks on arbitrary bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remoteid::auth::{AuthContext, AuthScheme, DripEd25519, MemoryKeyStore};
use remoteid::drip::{AssembledAuth, AuthAssembler, DripAuth};
use remoteid::{Auth, Message, MESSAGE_SIZE};

fuzz_target!(|data: &[u8]| {
    let _ = DripAuth::parse(data);
    let mut asm = AuthAssembler::new();
    let mut out = AssembledAuth::default();
    let mut keys = MemoryKeyStore::new();
    for (i, chunk) in data.chunks(MESSAGE_SIZE).enumerate() {
        let Ok(raw) = <[u8; MESSAGE_SIZE]>::try_from(chunk) else {
            break;
        };
        let mut raw = raw;
        raw[0] = 0x22;
        if let Ok(Message::Auth(a)) = Message::decode(&raw) {
            if asm.push_legacy(&a, i as u8, &mut out) {
                let _ = DripEd25519.verify(&out, &AuthContext::default(), &mut keys);
            }
        }
    }
    let pages: Vec<Auth> = data
        .chunks_exact(MESSAGE_SIZE)
        .filter_map(|c| match Message::decode(c) {
            Ok(Message::Auth(a)) => Some(a),
            _ => None,
        })
        .collect();
    if AuthAssembler::push_pack(&pages, &mut out) {
        let _ = DripEd25519.verify(&out, &AuthContext::default(), &mut keys);
    }
});
