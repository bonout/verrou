//! Hôte Native Messaging de Verrou, lancé par le navigateur.
//!
//! Il relaie les trames entre le navigateur (entrée et sortie standard) et
//! Verrou (`127.0.0.1`), sans les lire : elles sont chiffrées de bout en bout
//! entre l'extension et l'app. Si Verrou ne tourne pas, il l'ouvre en
//! arrière-plan et attend qu'il écoute.

use std::io::{self, Read as _, Write as _};
use std::net::{Shutdown, TcpStream};
use std::process::Command;
use std::thread;
use std::time::Duration;

const BUNDLE_ID: &str = "app.verrou.mac";

fn connect(port: u16) -> Option<TcpStream> {
    if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
        return Some(stream);
    }
    // Verrou n'est pas ouvert : on le lance sans le mettre au premier plan
    // (sauf dans les tests, qui ne doivent pas ouvrir la vraie app).
    if std::env::var_os("VERROU_BRIDGE_NO_LAUNCH").is_some() {
        return None;
    }
    let _ = Command::new("/usr/bin/open")
        .args(["-g", "-b", BUNDLE_ID])
        .status();
    for _ in 0..40 {
        thread::sleep(Duration::from_millis(250));
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
            return Some(stream);
        }
    }
    None
}

/// Message au format Native Messaging, écrit directement au navigateur.
fn tell_browser(json: &str) {
    let mut out = io::stdout().lock();
    let length = u32::try_from(json.len()).unwrap_or(0);
    let _ = out.write_all(&length.to_le_bytes());
    let _ = out.write_all(json.as_bytes());
    let _ = out.flush();
}

fn main() {
    let Some(stream) = connect(verrou_bridge::port_from_env()) else {
        tell_browser(r#"{"type":"error","code":"app_unavailable"}"#);
        return;
    };
    let Ok(mut to_app) = stream.try_clone() else {
        return;
    };
    let mut from_app = stream;

    // Verrou → navigateur.
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

    // Navigateur → Verrou. Le navigateur ferme l'entrée quand l'extension se
    // déconnecte : on ferme alors la connexion.
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
