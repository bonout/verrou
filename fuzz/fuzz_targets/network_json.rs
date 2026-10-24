//! JSON from the network: the 2fa.directory list and the passkeys page a
//! site publishes (/.well-known/passkey-endpoints), from any site.
#![no_main]

use libfuzzer_sys::fuzz_target;
use verrou_core::{passkey_upgrade, watchtower::TwoFactorDirectory};

fuzz_target!(|data: &[u8]| {
    let _ = TwoFactorDirectory::parse(data);
    let _ = passkey_upgrade::parse_endpoints(data, "example.com");
});
