//! Pont entre Verrou et ses clients : l'extension de navigateur et le
//! terminal (`verrou`, et son agent SSH).
//!
//! ```text
//! extension ──Native Messaging──▶ verrou-native-host ──TCP 127.0.0.1──▶ Verrou (Bridge)
//! verrou (terminal, agent SSH) ─────────────────────────TCP 127.0.0.1──▶ Verrou (Bridge)
//! ```
//!
//! - L'hôte (`verrou-native-host`) est lancé par le navigateur ; il relaie les
//!   octets sans les lire, et ouvre Verrou s'il ne tourne pas.
//! - Le canal est chiffré de bout en bout entre l'extension et Verrou
//!   ([`crypto`]) ; l'hôte et quiconque écoute le port ne voient que des
//!   messages chiffrés.
//! - Ce que chaque client peut obtenir est borné par [`access`] : pour
//!   l'extension, les identifiants de la page en cours, en HTTPS ; pour le
//!   terminal, des résultats sans secret, et un secret ou une signature SSH
//!   ([`ssh`]) seulement avec l'accord de l'utilisateur dans Verrou.

pub mod access;
mod clients;
pub mod crypto;
pub mod passkeys;
pub mod protocol;
mod server;
pub mod ssh;

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use clients::ClientInfo;
pub use server::{
    APPROVAL_TTL, Backend, BoxFuture, Bridge, Confirmation, PairingRequest, Purpose, WritePlan,
};

/// Identifiant de l'app, pour l'ouvrir (`open -b`).
pub const BUNDLE_ID: &str = "app.verrou.mac";

/// Port d'écoute de Verrou. `VERROU_BRIDGE_PORT` le remplace (tests).
pub const DEFAULT_PORT: u16 = 41_738;

/// Nom de l'hôte Native Messaging, déclaré au navigateur.
pub const HOST_NAME: &str = "app.verrou.bridge";

/// Identifiant de l'extension dans Brave et Chrome, fixé par la clé de
/// `extension/manifest.json` (un test de l'extension vérifie la concordance).
pub const CHROMIUM_EXTENSION_ID: &str = "pmdlgnpbjfdnmpeadbecmgfoojmocibg";

/// Identifiant de l'extension dans Firefox (`browser_specific_settings.gecko.id`,
/// écrit par `scripts/firefox-extension.sh`).
pub const FIREFOX_EXTENSION_ID: &str = "verrou@verrou.app";

/// Qui a lancé l'hôte Native Messaging, d'après ses arguments.
///
/// - Brave, Chrome : un argument, l'origine de l'extension
///   (`chrome-extension://<id>/`) ; sous Windows, s'y ajoute
///   `--parent-window=…`.
/// - Firefox : deux arguments, le chemin du manifeste de l'hôte
///   (`…/NativeMessagingHosts/app.verrou.bridge.json`) puis l'identifiant de
///   l'extension.
/// - Sans argument reconnu (lancé à la main, tests) : inconnu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Launcher {
    Chromium {
        extension: String,
    },
    Firefox {
        manifest: PathBuf,
        extension: String,
    },
    Unknown,
}

impl Launcher {
    /// Les arguments du processus, sans le nom du programme.
    pub fn from_args<I, S>(args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let args: Vec<String> = args
            .into_iter()
            .map(Into::into)
            .filter(|arg| !arg.starts_with("--parent-window="))
            .collect();
        match args.as_slice() {
            [origin, ..] if origin.starts_with("chrome-extension://") => {
                let id = origin["chrome-extension://".len()..].trim_end_matches('/');
                Self::Chromium {
                    extension: id.to_owned(),
                }
            }
            [manifest, extension]
                if Path::new(manifest)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("json"))
                    && !extension.is_empty() =>
            {
                Self::Firefox {
                    manifest: PathBuf::from(manifest),
                    extension: extension.clone(),
                }
            }
            _ => Self::Unknown,
        }
    }

    /// Le navigateur a lancé l'hôte pour une autre extension que celle de
    /// Verrou. Il ne devrait pas (la déclaration de l'hôte n'autorise
    /// qu'elle) : on refuse plutôt que relayer. Inconnu : accepté (le pont
    /// exige de toute façon l'appairage).
    pub fn is_foreign(&self) -> bool {
        match self {
            Self::Chromium { extension } => extension != CHROMIUM_EXTENSION_ID,
            Self::Firefox { extension, .. } => extension != FIREFOX_EXTENSION_ID,
            Self::Unknown => false,
        }
    }
}

/// Le port à utiliser, compte tenu de `VERROU_BRIDGE_PORT`.
pub fn port_from_env() -> u16 {
    std::env::var("VERROU_BRIDGE_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

/// Connexion au pont de Verrou. S'il ne répond pas et que `launch` le
/// permet, Verrou est ouvert sans passer au premier plan, puis attendu une
/// dizaine de secondes. `VERROU_BRIDGE_NO_LAUNCH` interdit de l'ouvrir (les
/// tests ne doivent pas lancer la vraie app).
pub fn connect_to_app(port: u16, launch: bool) -> Option<TcpStream> {
    if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
        return Some(stream);
    }
    if !launch || std::env::var_os("VERROU_BRIDGE_NO_LAUNCH").is_some() {
        return None;
    }
    let _ = std::process::Command::new("/usr/bin/open")
        .args(["-g", "-b", BUNDLE_ID])
        .status();
    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(250));
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
            return Some(stream);
        }
    }
    None
}

/// Version (`"version"`) d'un `manifest.json` d'extension, si elle a la forme
/// qu'accepte Chrome : un à quatre entiers de 0 à 65535, séparés par des points.
pub fn manifest_version(manifest: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(manifest).ok()?;
    let version = value.get("version")?.as_str()?;
    let parts: Vec<&str> = version.split('.').collect();
    let valid = (1..=4).contains(&parts.len())
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 5
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
                && part.parse::<u32>().is_ok_and(|n| n <= 65_535)
        });
    valid.then(|| version.to_owned())
}

/// Version du `manifest.json` au chemin `path` (lu à chaque appel : le
/// fichier change quand l'app est mise à jour).
pub fn extension_version_at(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    manifest_version(&text)
}

/// Le `manifest.json` de l'extension livrée dans le paquet de l'app qui
/// tourne (`Verrou.app/Contents/Resources/extension/`), s'il existe.
pub fn bundled_extension_manifest() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let contents = exe.parent()?.parent()?;
    let path = contents.join("Resources/extension/manifest.json");
    path.is_file().then_some(path)
}

#[cfg(test)]
mod tests {
    use super::{Launcher, manifest_version};
    use std::path::PathBuf;

    #[test]
    fn launched_by_brave_or_firefox() {
        let brave = Launcher::from_args(["chrome-extension://pmdlgnpbjfdnmpeadbecmgfoojmocibg/"]);
        assert_eq!(
            brave,
            Launcher::Chromium {
                extension: "pmdlgnpbjfdnmpeadbecmgfoojmocibg".to_owned()
            }
        );
        assert!(!brave.is_foreign());
        // Windows : la fenêtre parente en plus.
        assert_eq!(
            Launcher::from_args([
                "chrome-extension://pmdlgnpbjfdnmpeadbecmgfoojmocibg/",
                "--parent-window=0"
            ]),
            brave
        );

        let manifest = "/Users/u/Library/Application Support/Mozilla/NativeMessagingHosts/app.verrou.bridge.json";
        let firefox = Launcher::from_args([manifest, "verrou@verrou.app"]);
        assert_eq!(
            firefox,
            Launcher::Firefox {
                manifest: PathBuf::from(manifest),
                extension: "verrou@verrou.app".to_owned()
            }
        );
        assert!(!firefox.is_foreign());

        // Une autre extension : refusée.
        assert!(
            Launcher::from_args(["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"])
                .is_foreign()
        );
        assert!(Launcher::from_args([manifest, "autre@exemple.org"]).is_foreign());

        // À la main, ou autre chose : inconnu, accepté.
        for args in [vec![], vec!["--aide"], vec!["a", "b", "c"], vec![manifest]] {
            let launcher = Launcher::from_args(args.clone());
            assert_eq!(launcher, Launcher::Unknown, "{args:?}");
            assert!(!launcher.is_foreign());
        }
        assert_eq!(Launcher::from_args([manifest, ""]), Launcher::Unknown);
    }

    #[test]
    fn manifest_versions_follow_chrome_rules() {
        let of = |v: &str| manifest_version(&format!(r#"{{"name":"Verrou","version":"{v}"}}"#));
        assert_eq!(of("0.3.0").as_deref(), Some("0.3.0"));
        assert_eq!(of("0.3.0.65535").as_deref(), Some("0.3.0.65535"));
        assert_eq!(of("1").as_deref(), Some("1"));
        for bad in [
            "",
            "0.3.0.65536",
            "1.2.3.4.5",
            "1..2",
            "01.2",
            "1.2a",
            "-1",
            " 1",
        ] {
            assert_eq!(of(bad), None, "{bad:?}");
        }
        assert_eq!(manifest_version("{}"), None);
        assert_eq!(manifest_version("pas du json"), None);
        assert_eq!(manifest_version(r#"{"version": 3}"#), None);
    }
}
