//! L'hôte Native Messaging, lancé comme le ferait chaque navigateur : Brave
//! (origine de l'extension) ou Firefox (manifeste de l'hôte, identifiant de
//! l'extension). Sans Verrou à l'écoute, l'hôte accepté répond
//! `app_unavailable` ; lancé pour une autre extension, `unknown_extension`.

use std::io::Read as _;
use std::net::TcpListener;
use std::process::{Command, Stdio};

/// La première trame écrite par l'hôte (longueur u32 LE + JSON).
fn first_frame(args: &[&str]) -> serde_json::Value {
    // Un port libre, sans personne à l'écoute ; Verrou n'est jamais ouvert.
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
    assert!(out.len() >= 4, "aucune trame : {out:?}");
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
    // Lancé à la main (tests de l'extension) : accepté aussi.
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
