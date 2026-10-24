//! A scanned QR code or a pasted link: otpauth://, Google Authenticator
//! exports (otpauth-migration://, protobuf), Wi-Fi codes, anything else.
#![no_main]

use libfuzzer_sys::fuzz_target;
use verrou_core::{otp_scan, totp::Totp};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = otp_scan::parse_scan(text);
        let _ = Totp::parse(text);
    }
});
