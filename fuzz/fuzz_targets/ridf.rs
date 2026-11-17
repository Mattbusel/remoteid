//! RIDF streams on arbitrary bytes, and re-encoding what decodes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remoteid::ridf::{self, Record};

fuzz_target!(|data: &[u8]| {
    for r in ridf::records(data) {
        let Ok(r) = r else { break };
        let _ = r.beacon();
        let _ = r.observation();
        let mut buf = vec![0u8; r.encoded_len()];
        let n = r.encode(&mut buf).expect("decoded records re-encode");
        let (back, used) = Record::decode(&buf).expect("re-encoded records decode");
        assert_eq!(used, n);
        assert_eq!(back, r);
    }
});
