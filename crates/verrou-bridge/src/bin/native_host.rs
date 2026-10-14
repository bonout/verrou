//! Hôte Native Messaging de Verrou, lancé par le navigateur.
//!
//! Il relaie les trames entre le navigateur (entrée et sortie standard) et
//! Verrou (`127.0.0.1`), sans les lire : elles sont chiffrées de bout en bout
//! entre l'extension et l'app. Si Verrou ne tourne pas, il l'ouvre en
//! arrière-plan et attend qu'il écoute.
//!
//! Brave et Firefox le lancent avec des arguments différents
//! ([`verrou_bridge::Launcher`]) ; seule l'extension de Verrou est servie.

use std::io::{self, Read as _, Write as _};
use std::net::Shutdown;
use std::thread;

/// Message au format Native Messaging, écrit directement au navigateur.
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
    // Verrou n'est pas ouvert : on le lance sans le mettre au premier plan.
    let Some(stream) = verrou_bridge::connect_to_app(verrou_bridge::port_from_env(), true) else {
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
