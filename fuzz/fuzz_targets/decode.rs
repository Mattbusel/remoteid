//! Every frame parser on arbitrary bytes.
#![no_main]
use libfuzzer_sys::fuzz_target;
use remoteid::{ble, france, wifi, Frame};

fuzz_target!(|data: &[u8]| {
    if let Ok(f) = Frame::decode(data) {
        f.for_each_message(|m| {
            let _ = m.encode();
        });
    }
    if let Ok(frame) = wifi::strip_radiotap(data) {
        let _ = wifi::parse_frame(frame);
        let _ = wifi::beacon_info(frame);
    }
    let _ = wifi::parse_frame(data);
    let _ = wifi::parse_vendor_element(data);
    if let Some(rid) = ble::find_in_advertising_data(data) {
        let _ = rid.frame();
    }
    let _ = france::find_in_elements(data);
});
