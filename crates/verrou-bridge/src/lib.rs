//! Bridge between Verrou and its clients: the browser extension and the
//! terminal (`verrou`, and its SSH agent).
//!
//! ```text
//! extension ──Native Messaging──▶ verrou-native-host ──TCP 127.0.0.1──▶ Verrou (Bridge)
//! verrou (terminal, agent SSH) ─────────────────────────TCP 127.0.0.1──▶ Verrou (Bridge)
//! ```
//!
//! - The host (`verrou-native-host`) is launched by the browser; it relays the
//!   bytes without reading them, and opens Verrou if it is not running.
//! - The channel is end-to-end encrypted between the extension and Verrou
//!   ([`crypto`]); the host and anyone listening on the port only see
//!   encrypted messages.
//! - What each client can get is bounded by [`access`]: for the
//!   extension, the logins for the current page, over HTTPS; for the
//!   terminal, results without secrets, and a secret or an SSH signature
//!   ([`ssh`]) only with the user's approval in Verrou.

pub mod access;
mod clients;
pub mod crypto;
pub mod ids;
pub mod items;
pub mod passkeys;
pub mod protocol;
mod server;
pub mod ssh;

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub use clients::ClientInfo;
pub use server::{
    APPROVAL_TTL, ApprovalScope, Backend, BoxFuture, Bridge, Confirmation, PairingRequest, Purpose,
    WritePlan,
};

/// The app's identifier, to open it (`open -b`).
pub const BUNDLE_ID: &str = "app.verrou.mac";

/// Verrou's listening port. `VERROU_BRIDGE_PORT` overrides it (tests).
pub const DEFAULT_PORT: u16 = 41_738;

/// Name of the Native Messaging host, declared to the browser.
pub const HOST_NAME: &str = "app.verrou.bridge";

/// The extension's identifier in Brave and Chrome, set by the key in
/// `extension/manifest.json` (an extension test checks they match).
pub const CHROMIUM_EXTENSION_ID: &str = "pmdlgnpbjfdnmpeadbecmgfoojmocibg";

/// The extension's identifier in Firefox (`browser_specific_settings.gecko.id`,
/// written by `scripts/firefox-extension.sh`).
pub const FIREFOX_EXTENSION_ID: &str = "verrou@verrou.app";

/// Who launched the Native Messaging host, according to its arguments.
///
/// - Brave, Chrome: one argument, the extension's origin
///   (`chrome-extension://<id>/`); on Windows, `--parent-window=…` is
///   added.
/// - Firefox: two arguments, the path of the host manifest
///   (`…/NativeMessagingHosts/app.verrou.bridge.json`) then the extension's
///   identifier.
/// - No recognized argument (launched by hand, tests): unknown.
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
    /// The process arguments, without the program name.
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

    /// The browser launched the host for an extension other than Verrou's.
    /// It should not (the host declaration only allows that one): refuse
    /// rather than relay. Unknown: accepted (the bridge requires pairing
    /// anyway).
    pub fn is_foreign(&self) -> bool {
        match self {
            Self::Chromium { extension } => extension != CHROMIUM_EXTENSION_ID,
            Self::Firefox { extension, .. } => extension != FIREFOX_EXTENSION_ID,
            Self::Unknown => false,
        }
    }
}

/// The port to use, taking `VERROU_BRIDGE_PORT` into account.
pub fn port_from_env() -> u16 {
    std::env::var("VERROU_BRIDGE_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

/// Connects to Verrou's bridge. If it does not answer and `launch` allows
/// it, Verrou is opened without coming to the foreground, then waited for
/// about ten seconds. `VERROU_BRIDGE_NO_LAUNCH` forbids opening it (tests
/// must not launch the real app).
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

/// Version (`"version"`) of an extension `manifest.json`, if it has the form
/// Chrome accepts: one to four integers from 0 to 65535, separated by dots.
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

/// Version of the `manifest.json` at `path` (read on every call: the
/// file changes when the app is updated).
pub fn extension_version_at(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    manifest_version(&text)
}

/// The `manifest.json` of the extension shipped in the bundle of the running
/// app (`Verrou.app/Contents/Resources/extension/`), if it exists.
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
        // Windows: the parent window as well.
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

        // Another extension: refused.
        assert!(
            Launcher::from_args(["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"])
                .is_foreign()
        );
        assert!(Launcher::from_args([manifest, "autre@exemple.org"]).is_foreign());

        // By hand, or something else: unknown, accepted.
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
