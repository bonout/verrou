//! The Native Messaging host, launched as each browser would: Brave
//! (the extension's origin) or Firefox (the host manifest, the extension's
//! identifier). With no Verrou listening, the accepted host answers
//! `app_unavailable`; launched for another extension, `unknown_extension`.

use std::io::Read as _;
use std::net::TcpListener;
use std::process::{Command, Stdio};

/// The first frame written by the host (u32 LE length + JSON).
fn first_frame(args: &[&str]) -> serde_json::Value {
    // A free port, with nobody listening; Verrou is never opened.
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_verrou-native-host"))
        .args(args)
        .env("VERROU_BRIDGE_PORT", port.to_string())
        .env("VERROU_BRIDGE_NO_LAUNCH", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut out = Vec::new();
    child.stdout.take().unwrap().read_to_end(&mut out).unwrap();
    child.wait().unwrap();
    assert!(out.len() >= 4, "no frame: {out:?}");
    let length = u32::from_le_bytes(out[..4].try_into().unwrap()) as usize;
    serde_json::from_slice(&out[4..4 + length]).unwrap()
}

fn code(args: &[&str]) -> String {
    first_frame(args)["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

#[test]
fn firefox_and_brave_launch_the_host() {
    let manifest =
        "/Users/u/Library/Application Support/Mozilla/NativeMessagingHosts/app.verrou.bridge.json";
    assert_eq!(
        code(&[manifest, verrou_bridge::FIREFOX_EXTENSION_ID]),
        "app_unavailable"
    );
    assert_eq!(
        code(&[&format!(
            "chrome-extension://{}/",
            verrou_bridge::CHROMIUM_EXTENSION_ID
        )]),
        "app_unavailable"
    );
    // Launched by hand (extension tests): accepted too.
    assert_eq!(code(&[]), "app_unavailable");
}

#[test]
fn another_extension_is_refused() {
    let manifest = "/tmp/app.verrou.bridge.json";
    assert_eq!(code(&[manifest, "autre@exemple.org"]), "unknown_extension");
    assert_eq!(
        code(&["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"]),
        "unknown_extension"
    );
}
