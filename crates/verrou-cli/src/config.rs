//! The link between this terminal and Verrou: the client id and the
//! channel key, obtained by `verrou link`.
//!
//! File `~/.config/verrou/cli.json` (or `$VERROU_CLI_CONFIG`), mode 600,
//! directory 700. The key only gives what the terminal gives: searching
//! without secrets, and asking for a secret or an SSH signature that the
//! user confirms in Verrou.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use verrou_bridge::crypto::ChannelKey;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    /// Id assigned by Verrou at pairing.
    pub client: String,
    /// Channel key (base64).
    pub key: String,
    /// Unix timestamp of the pairing.
    pub linked: i64,
}

impl Config {
    pub fn channel_key(&self) -> Result<ChannelKey, String> {
        ChannelKey::from_base64(&self.key)
            .map_err(|_| "link file is damaged: run `verrou link` again".to_owned())
    }

    /// File path: `$VERROU_CLI_CONFIG`, otherwise `~/.config/verrou/cli.json`.
    pub fn default_path() -> Result<PathBuf, String> {
        if let Some(path) = std::env::var_os("VERROU_CLI_CONFIG") {
            return Ok(PathBuf::from(path));
        }
        let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
        Ok(PathBuf::from(home).join(".config/verrou/cli.json"))
    }

    /// `Ok(None)`: this terminal is not linked.
    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        match fs::read(path) {
            Ok(data) => serde_json::from_slice(&data)
                .map(Some)
                .map_err(|_| format!("{} is unreadable: run `verrou link` again", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Atomic write, mode 600; a created directory gets 700.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let error = |e: std::io::Error| format!("{}: {e}", path.display());
        if let Some(dir) = path
            .parent()
            .filter(|d| !d.as_os_str().is_empty() && !d.exists())
        {
            fs::create_dir_all(dir).map_err(error)?;
            set_mode(dir, 0o700).map_err(error)?;
        }
        let temp = path.with_extension("tmp");
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let data = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        let mut file = options.open(&temp).map_err(error)?;
        file.write_all(&data)
            .and_then(|()| file.sync_all())
            .map_err(error)?;
        // A temporary file left by an interrupted write may have been
        // created with other permissions.
        set_mode(&temp, 0o600).map_err(error)?;
        fs::rename(&temp, path).map_err(error)
    }

    pub fn remove(path: &Path) -> Result<bool, String> {
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }
}

#[cfg(unix)]
pub(crate) fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
pub(crate) fn set_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_privately_and_read_back() {
        let dir = std::env::temp_dir().join(format!("verrou-cli-{}", std::process::id()));
        let path = dir.join("sous-dossier/cli.json");
        let config = Config {
            client: "abc".to_owned(),
            key: ChannelKey::from_bytes([9; 32]).to_base64(),
            linked: 1,
        };
        config.save(&path).unwrap();
        let loaded = Config::load(&path).unwrap().unwrap();
        assert_eq!(loaded.client, "abc");
        assert!(loaded.channel_key().is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(path.parent().unwrap()), 0o700);
        }
        assert!(Config::remove(&path).unwrap());
        assert!(Config::load(&path).unwrap().is_none());
        let _ = fs::remove_dir_all(dir);
    }
}
