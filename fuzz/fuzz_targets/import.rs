//! A file chosen for import (1Password, Apple Passwords, Proton Pass): any
//! bytes, detected or forced to each format, must give an error, never a
//! panic or a hang.
#![no_main]

use libfuzzer_sys::fuzz_target;
use verrou_core::import::{self, Format};

fuzz_target!(|data: &[u8]| {
    let _ = import::parse(data, None);
    for format in [
        Format::ApplePasswordsCsv,
        Format::OnePassword1pux,
        Format::OnePasswordCsv,
        Format::ProtonPassZip,
        Format::ProtonPassCsv,
    ] {
        let _ = import::parse(data, Some(format));
    }
});
