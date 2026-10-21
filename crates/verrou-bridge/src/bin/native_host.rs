//! Verrou's Native Messaging host, launched by the browser.
//!
//! It relays frames between the browser (standard input and output) and
//! Verrou (`127.0.0.1`), without reading them: they are end-to-end encrypted
//! between the extension and the app. If Verrou is not running, it opens it in
//! the background and waits for it to listen.
//!
//! Brave and Firefox launch it with different arguments
//! ([`verrou_bridge::Launcher`]); only Verrou's extension is served.

use std::io::{self, Read as _, Write as _};
use std::net::Shutdown;
use std::thread;

/// A message in Native Messaging format, written directly to the browser.
fn tell_browser(json: &str) {
    let mut out = io::stdout().lock();
    let length = u32::try_from(json.len()).unwrap_or(0);
    let _ = out.write_all(&length.to_le_bytes());
    let _ = out.write_all(json.as_bytes());
    let _ = out.flush();
}

fn main() {
    let launcher = verrou_bridge::Launcher::from_args(std::env::args().skip(1));
    if launcher.is_foreign() {
        tell_browser(r#"{"type":"error","code":"unknown_extension"}"#);
        return;
    }
    // Verrou is not open: launch it without bringing it to the foreground.
    let Some(stream) = verrou_bridge::connect_to_app(verrou_bridge::port_from_env(), true) else {
        tell_browser(r#"{"type":"error","code":"app_unavailable"}"#);
        return;
    };
    let Ok(mut to_app) = stream.try_clone() else {
        return;
    };
    let mut from_app = stream;

    // Verrou → browser.
    let downstream = thread::spawn(move || {
        let mut out = io::stdout().lock();
        let mut buffer = [0u8; 16 * 1024];
        loop {
            match from_app.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out
                        .write_all(&buffer[..n])
                        .and_then(|()| out.flush())
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    // Browser → Verrou. The browser closes the input when the extension
    // disconnects: the connection is then closed.
    let mut input = io::stdin().lock();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        match input.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to_app.write_all(&buffer[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = to_app.shutdown(Shutdown::Both);
    let _ = downstream.join();
}
