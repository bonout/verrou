//! What any local program can send: SSH agent requests (the agent's
//! socket) and the data to sign (git's SSHSIG header).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = verrou_cli::agent::parse(data);
    let _ = verrou_bridge::ssh::sshsig_namespace(data);
    let _ = verrou_bridge::ssh::is_git_signature(data);
});
