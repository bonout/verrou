//! `verrou git-signing`: have git commits signed by an SSH key from the
//! vault (`gpg.format=ssh`).
//!
//! git calls `ssh-keygen -Y sign -n git`, which asks the `SSH_AUTH_SOCK`
//! agent for the signature: Verrou's (`verrou ssh-agent`), which shows
//! "sign a git commit" in its approval request. The private key does not
//! leave the app; the git configuration only contains the public key.
//!
//! By default, the command prints the settings to apply; `--apply` writes
//! them (global git configuration, or the repository's with `--local`) and
//! adds the key to the `allowed_signers` file, used to verify signatures
//! (`git log --show-signature`, `git verify-commit`).

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use data_encoding::{BASE64, BASE64_NOPAD};
use sha2::{Digest as _, Sha256};
use verrou_bridge::protocol::SshIdentity;

/// An SSH key from the vault, the way git wants it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningKey {
    pub title: String,
    /// OpenSSH line without comment: `ssh-ed25519 AAAA…`.
    pub public_key: String,
    /// `SHA256:…`, like `ssh-keygen -l`.
    pub fingerprint: String,
}

impl SigningKey {
    /// `None`: unreadable binary form.
    pub fn from_identity(identity: &SshIdentity) -> Option<Self> {
        let blob = BASE64.decode(identity.public_key.as_bytes()).ok()?;
        // The binary form starts with the algorithm name (`string`).
        let (length, rest) = blob.split_at_checked(4)?;
        let length = u32::from_be_bytes(length.try_into().ok()?) as usize;
        let algorithm = std::str::from_utf8(rest.get(..length)?).ok()?;
        Some(Self {
            title: identity.title.clone(),
            public_key: format!("{algorithm} {}", identity.public_key),
            fingerprint: format!("SHA256:{}", BASE64_NOPAD.encode(&Sha256::digest(&blob))),
        })
    }
}

/// The key designated by `query` (title, or fingerprint, whole or in
/// part, case-insensitive); without a query, the vault's only key.
pub fn choose<'k>(keys: &'k [SigningKey], query: &str) -> Result<&'k SigningKey, String> {
    let query = query.trim().to_lowercase();
    let found: Vec<&SigningKey> = keys
        .iter()
        .filter(|k| {
            query.is_empty()
                || k.title.to_lowercase().contains(&query)
                || k.fingerprint.to_lowercase().contains(&query)
        })
        .collect();
    let list = |keys: &[&SigningKey]| {
        keys.iter()
            .map(|k| format!("\n  {}  {}", k.fingerprint, k.title))
            .collect::<Vec<_>>()
            .concat()
    };
    match found.as_slice() {
        [key] => Ok(key),
        [] if keys.is_empty() => {
            Err("no SSH key in the vault (Verrou: \"New SSH Key…\")".to_owned())
        }
        [] => Err(format!(
            "no SSH key matches; keys in the vault:{}",
            list(&keys.iter().collect::<Vec<_>>())
        )),
        several => Err(format!(
            "several SSH keys match, be more specific (title or fingerprint):{}",
            list(several)
        )),
    }
}

/// Target git configuration: global (`~/.gitconfig`) or the current repository's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Global,
    Local,
}

impl Scope {
    fn flag(self) -> &'static str {
        match self {
            Self::Global => "--global",
            Self::Local => "--local",
        }
    }
}

/// The settings to write to sign with `key`.
#[derive(Clone, Debug)]
pub struct Plan {
    pub key: SigningKey,
    /// Commit address (`user.email`): the one in `allowed_signers`.
    pub email: String,
    pub allowed_signers: PathBuf,
    pub scope: Scope,
}

impl Plan {
    /// `allowed_signers` line (`ssh-keygen -Y verify` format).
    pub fn allowed_signers_line(&self) -> String {
        format!("{} namespaces=\"git\" {}", self.email, self.key.public_key)
    }

    /// Arguments of each `git config`.
    pub fn git_settings(&self) -> Vec<[String; 4]> {
        let scope = self.scope.flag().to_owned();
        [
            ("gpg.format", "ssh".to_owned()),
            ("user.signingkey", format!("key::{}", self.key.public_key)),
            ("commit.gpgsign", "true".to_owned()),
            ("tag.gpgsign", "true".to_owned()),
            (
                "gpg.ssh.allowedSignersFile",
                self.allowed_signers.to_string_lossy().into_owned(),
            ),
        ]
        .into_iter()
        .map(|(name, value)| ["config".to_owned(), scope.clone(), name.to_owned(), value])
        .collect()
    }

    /// The commands to paste into a shell.
    pub fn script(&self, socket: &Path) -> String {
        let mut lines = vec![format!(
            "# Key \"{}\" ({})",
            self.key.title, self.key.fingerprint
        )];
        for args in self.git_settings() {
            let quoted: Vec<String> = args.iter().map(|a| shell_quote(a)).collect();
            lines.push(format!("git {}", quoted.join(" ")));
        }
        let file = shell_quote(&self.allowed_signers.to_string_lossy());
        if let Some(dir) = self.allowed_signers.parent() {
            lines.push(format!("mkdir -p {}", shell_quote(&dir.to_string_lossy())));
        }
        let line = shell_quote(&self.allowed_signers_line());
        lines.push(format!(
            "grep -qxF {line} {file} 2>/dev/null || echo {line} >> {file}"
        ));
        lines.push("# git signs through Verrou's agent (`verrou ssh-agent`):".to_owned());
        lines.push(format!(
            "export SSH_AUTH_SOCK={}",
            shell_quote(&socket.to_string_lossy())
        ));
        lines.join("\n") + "\n"
    }

    /// Writes the settings: `git config` (through `git`, which builds the
    /// command: tests put their own configuration in it), then the
    /// `allowed_signers` line if it is not there already.
    pub fn apply(&self, git: impl Fn() -> Command) -> Result<(), String> {
        for args in self.git_settings() {
            let status = git()
                .args(&args)
                .status()
                .map_err(|e| format!("git not found: {e}"))?;
            if !status.success() {
                return Err(format!("`git {}` failed", args.join(" ")));
            }
        }
        add_line(&self.allowed_signers, &self.allowed_signers_line())
    }
}

/// Appends `line` to the file (created if needed, with its directory),
/// unless it is already there.
fn add_line(path: &Path, line: &str) -> Result<(), String> {
    let error = |e: std::io::Error| format!("{}: {e}", path.display());
    let current = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(error(e)),
    };
    if current.lines().any(|l| l.trim() == line) {
        return Ok(());
    }
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir).map_err(error)?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(error)?;
    let separator = if current.is_empty() || current.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    writeln!(file, "{separator}{line}").map_err(error)
}

/// `~/.config/verrou/allowed_signers`: next to the terminal's link.
pub fn default_allowed_signers() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config/verrou/allowed_signers"))
}

/// git's `user.email`, if set (read only).
pub fn git_email(git: impl Fn() -> Command) -> Option<String> {
    let output = git().args(["config", "user.email"]).output().ok()?;
    let email = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (output.status.success() && !email.is_empty()).then_some(email)
}

/// In single quotes if needed, to paste the line into a shell.
pub fn shell_quote(text: &str) -> String {
    if !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-~+@:=,".contains(c))
    {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test Ed25519 public key (binary form, base64).
    const ED25519: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIOFNTvDpEWMXDZ5qaNhmyAbLfuAQ3HAPwt+7hyBCPMF+";

    fn identity(title: &str, public_key: &str) -> SshIdentity {
        SshIdentity {
            item: title.to_lowercase(),
            title: title.to_owned(),
            public_key: public_key.to_owned(),
        }
    }

    #[test]
    fn identity_becomes_an_openssh_line_and_fingerprint() {
        let key = SigningKey::from_identity(&identity("Clé du N100", ED25519)).unwrap();
        assert_eq!(key.public_key, format!("ssh-ed25519 {ED25519}"));
        // `ssh-keygen -lf` on this key.
        assert_eq!(
            key.fingerprint,
            "SHA256:77Wl7hE5KZkme+QoJOptP86XOOlFINl0NUDZx6Aq6Gs"
        );
        assert!(SigningKey::from_identity(&identity("x", "not base64")).is_none());
        assert!(SigningKey::from_identity(&identity("x", "AAAA")).is_none());
    }

    #[test]
    fn chooses_by_title_or_fingerprint() {
        let one = SigningKey::from_identity(&identity("GitHub", ED25519)).unwrap();
        let mut two = one.clone();
        two.title = "Serveur".to_owned();
        two.fingerprint = "SHA256:autre".to_owned();
        let keys = vec![one.clone(), two.clone()];
        assert_eq!(choose(&keys, "github").unwrap(), &one);
        assert_eq!(choose(&keys, "sha256:AUTRE").unwrap(), &two);
        assert!(choose(&keys, "").unwrap_err().contains("several"));
        assert!(
            choose(&keys, "gitlab")
                .unwrap_err()
                .contains("no SSH key matches")
        );
        assert_eq!(choose(&keys[..1], "").unwrap(), &one);
        assert!(choose(&[], "").unwrap_err().contains("New SSH Key"));
    }

    #[test]
    fn plan_prints_git_settings_and_allowed_signers() {
        let plan = Plan {
            key: SigningKey::from_identity(&identity("GitHub", ED25519)).unwrap(),
            email: "camille@exemple.fr".to_owned(),
            allowed_signers: PathBuf::from("/Users/camille/.config/verrou/allowed_signers"),
            scope: Scope::Global,
        };
        assert_eq!(
            plan.allowed_signers_line(),
            format!("camille@exemple.fr namespaces=\"git\" ssh-ed25519 {ED25519}")
        );
        let script = plan.script(Path::new("/Users/camille/.verrou/agent.sock"));
        assert!(script.contains("git config --global gpg.format ssh\n"));
        assert!(script.contains(&format!(
            "git config --global user.signingkey 'key::ssh-ed25519 {ED25519}'\n"
        )));
        assert!(script.contains("git config --global commit.gpgsign true\n"));
        assert!(script.contains(
            "git config --global gpg.ssh.allowedSignersFile /Users/camille/.config/verrou/allowed_signers\n"
        ));
        assert!(script.contains("export SSH_AUTH_SOCK=/Users/camille/.verrou/agent.sock\n"));
        let line = format!("'camille@exemple.fr namespaces=\"git\" ssh-ed25519 {ED25519}'");
        let file = "/Users/camille/.config/verrou/allowed_signers";
        assert!(script.contains(&format!(
            "grep -qxF {line} {file} 2>/dev/null || echo {line} >> {file}\n"
        )));
    }

    #[test]
    fn allowed_signers_line_is_added_once() {
        let dir = std::env::temp_dir().join(format!("verrou-signers-{}", std::process::id()));
        let path = dir.join("sous-dossier/allowed_signers");
        add_line(&path, "a@b namespaces=\"git\" ssh-ed25519 AAAA").unwrap();
        add_line(&path, "a@b namespaces=\"git\" ssh-ed25519 AAAA").unwrap();
        fs::write(&path, "x@y ssh-ed25519 BBBB").unwrap();
        add_line(&path, "a@b namespaces=\"git\" ssh-ed25519 AAAA").unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "x@y ssh-ed25519 BBBB\na@b namespaces=\"git\" ssh-ed25519 AAAA\n"
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
