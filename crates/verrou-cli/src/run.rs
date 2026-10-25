//! `verrou run -- <command>`: the command gets its secrets in environment
//! variables, without them going through the terminal, its history, or an
//! agent's context (Claude Code, Codex…).
//!
//! A variable whose value is a reference `verrou://<item>/<field>` (in the
//! environment, or in a `--env-file`) is replaced by the field's value,
//! asked of Verrou with the usual approval (Touch ID, or the paired
//! iPhone). The item is a title or an identifier, percent-encoded if it
//! holds a `/` (`verrou://GitHub%2Fwork/token`); the field is `password`,
//! `username`, `totp` (the current code), `notes`, or a custom field.
//!
//! What the command prints is masked by default: each secret it was given
//! is replaced by `<concealed by Verrou>`, including when it is split
//! across two writes ([`Masker`]). `--no-masking` passes the output as is
//! (an interactive program that needs a terminal).

use std::fmt::Write as _;
use std::io::{self, Read, Write};

use verrou_bridge::protocol::FieldView;
use zeroize::Zeroizing;

pub const SCHEME: &str = "verrou://";
pub const CONCEALED: &str = "<concealed by Verrou>";

/// A field of an item, to resolve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    pub item: String,
    pub field: String,
}

impl Reference {
    /// `verrou://<item>/<field>`; `None` for any other value, which passes
    /// as is.
    pub fn parse(value: &str) -> Option<Result<Self, String>> {
        let rest = value.strip_prefix(SCHEME)?;
        let Some((item, field)) = rest.rsplit_once('/') else {
            return Some(Err(format!("\"{value}\": expected {SCHEME}<item>/<field>")));
        };
        let (Some(item), Some(field)) = (percent_decode(item), percent_decode(field)) else {
            return Some(Err(format!("\"{value}\": invalid percent-encoding")));
        };
        if item.is_empty() || field.is_empty() {
            return Some(Err(format!("\"{value}\": expected {SCHEME}<item>/<field>")));
        }
        Some(Ok(Self { item, field }))
    }
}

impl Reference {
    /// The reference as written in an environment variable: `/` and `%`
    /// (which would be read as a separator or an escape), and whitespace,
    /// are percent-encoded; [`Self::parse`] gives the same reference back.
    pub fn to_uri(&self) -> String {
        format!(
            "{SCHEME}{}/{}",
            percent_encode(&self.item),
            percent_encode(&self.field)
        )
    }
}

fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c == '%' || c == '/' || c.is_whitespace() || c.is_control() {
            let mut buffer = [0; 4];
            for byte in c.encode_utf8(&mut buffer).bytes() {
                let _ = write!(out, "%{byte:02X}");
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The field a reference names: by its id (`password`, `custom-0`), else by
/// the label of the one custom field that has it (`API token`), ignoring
/// case. A custom field never takes the place of a built-in one: a label
/// is only looked at among custom fields, and not at all if a built-in
/// field is called that (by id or by label, case aside).
pub fn find_field<'a>(fields: &'a [FieldView], name: &str) -> Option<&'a FieldView> {
    fields.iter().find(|f| f.id == name).or_else(|| {
        let custom = |f: &&FieldView| f.id.starts_with("custom-");
        let builtin_named = fields
            .iter()
            .filter(|f| !custom(f))
            .any(|f| f.id.eq_ignore_ascii_case(name) || f.label.eq_ignore_ascii_case(name));
        if builtin_named {
            return None;
        }
        let mut by_label = fields
            .iter()
            .filter(custom)
            .filter(|f| f.label.eq_ignore_ascii_case(name));
        // Two fields with the same label: the id must say which.
        by_label.next().filter(|_| by_label.next().is_none())
    })
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `KEY=value` lines of a dotenv file: comments, blank lines and an
/// `export ` prefix allowed, value optionally in single or double quotes.
pub fn parse_env_file(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut vars = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {}: expected KEY=value", number + 1));
        };
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(format!(
                "line {}: invalid variable name \"{key}\"",
                number + 1
            ));
        }
        let value = value.trim();
        let value = ['"', '\'']
            .iter()
            .find_map(|q| value.strip_prefix(*q).and_then(|v| v.strip_suffix(*q)))
            .unwrap_or(value);
        vars.push((key.to_owned(), value.to_owned()));
    }
    Ok(vars)
}

/// The variables to resolve: those of the environment, then the file's (a
/// file's variable wins over the environment's).
pub fn references(
    environment: impl IntoIterator<Item = (String, String)>,
    file: &[(String, String)],
) -> Result<Vec<(String, Reference)>, String> {
    let mut found: Vec<(String, Reference)> = Vec::new();
    let all = environment.into_iter().chain(file.iter().cloned());
    for (name, value) in all {
        found.retain(|(n, _)| *n != name);
        if let Some(reference) = Reference::parse(&value) {
            found.push((name, reference?));
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(found)
}

/// Replaces the secrets in a stream of bytes. Only the end of a write
/// that starts a secret is held back, until the next write tells whether
/// the secret follows: a secret split between two writes is still masked,
/// and the rest of the output (a prompt without a newline) shows at once.
/// [`Masker::finish`] lets out what is held.
pub struct Masker {
    secrets: Vec<Zeroizing<Vec<u8>>>,
    pending: Zeroizing<Vec<u8>>,
}

impl Masker {
    /// Secrets shorter than 3 bytes are not masked: they would hide
    /// ordinary output (a one-digit PIN).
    pub fn new<'a>(secrets: impl IntoIterator<Item = &'a str>) -> Self {
        let mut secrets: Vec<Zeroizing<Vec<u8>>> = secrets
            .into_iter()
            .filter(|s| s.len() >= 3)
            .map(|s| Zeroizing::new(s.as_bytes().to_vec()))
            .collect();
        // Longest first: a secret containing another is masked whole.
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        secrets.dedup_by(|a, b| a.as_slice() == b.as_slice());
        Self {
            secrets,
            pending: Zeroizing::new(Vec::new()),
        }
    }

    /// What can be written now.
    pub fn feed(&mut self, data: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(data);
        self.drain(false)
    }

    /// The end of the stream.
    pub fn finish(&mut self) -> Vec<u8> {
        self.drain(true)
    }

    fn drain(&mut self, last: bool) -> Vec<u8> {
        let data: &[u8] = &self.pending;
        let mut out = Vec::with_capacity(data.len());
        let mut i = 0;
        'scan: while i < data.len() {
            let rest = &data[i..];
            // The rest may be the start of a secret cut by the write: wait
            // for the next one before anything else, even if a shorter
            // secret already matches ("pass" in "password12", while
            // "password123" may follow: masking "pass" at once would let
            // the end of the longer one out).
            if !last
                && self
                    .secrets
                    .iter()
                    .any(|s| s.len() > rest.len() && s.starts_with(rest))
            {
                break;
            }
            for secret in &self.secrets {
                if rest.starts_with(secret) {
                    out.extend_from_slice(CONCEALED.as_bytes());
                    i += secret.len();
                    continue 'scan;
                }
            }
            out.push(data[i]);
            i += 1;
        }
        let kept = data[i..].to_vec();
        *self.pending = kept;
        out
    }
}

/// Copies `from` to `to`, masked, until the end of `from`.
pub fn pump(mut from: impl Read, mut to: impl Write, mut masker: Masker) -> io::Result<()> {
    let mut buffer = Zeroizing::new([0_u8; 8192]);
    loop {
        let n = match from.read(buffer.as_mut()) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let out = masker.feed(&buffer[..n]);
        to.write_all(&out)?;
        // Lines appear as the command writes them.
        to.flush()?;
    }
    to.write_all(&masker.finish())?;
    to.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_are_parsed() {
        assert_eq!(
            Reference::parse("verrou://GitHub/password"),
            Some(Ok(Reference {
                item: "GitHub".into(),
                field: "password".into()
            }))
        );
        assert_eq!(
            Reference::parse("verrou://GitHub%2Fwork%20account/api%20token"),
            Some(Ok(Reference {
                item: "GitHub/work account".into(),
                field: "api token".into()
            }))
        );
        assert_eq!(Reference::parse("hello"), None);
        assert!(matches!(Reference::parse("verrou://GitHub"), Some(Err(_))));
        assert!(matches!(
            Reference::parse("verrou:///password"),
            Some(Err(_))
        ));
        assert!(matches!(Reference::parse("verrou://a%zz/b"), Some(Err(_))));
    }

    #[test]
    fn references_round_trip_through_their_uri() {
        for (item, field) in [
            ("GitHub", "password"),
            ("GitHub/work account", "api token"),
            ("100% sure", "clé secrète"),
        ] {
            let reference = Reference {
                item: item.to_owned(),
                field: field.to_owned(),
            };
            let uri = reference.to_uri();
            assert!(!uri.contains(' '), "{uri}");
            assert_eq!(Reference::parse(&uri), Some(Ok(reference)));
        }
        assert_eq!(
            Reference {
                item: "GitHub/work".to_owned(),
                field: "API token".to_owned()
            }
            .to_uri(),
            "verrou://GitHub%2Fwork/API%20token"
        );
    }

    #[test]
    fn fields_are_found_by_id_then_by_label() {
        let field = |id: &str, label: &str| FieldView {
            id: id.to_owned(),
            label: label.to_owned(),
            kind: verrou_core::FieldKind::Concealed,
            secret: true,
            value: None,
        };
        let fields = [
            field("password", "Password"),
            field("custom-0", "API token"),
            field("custom-1", "Twin"),
            field("custom-2", "Twin"),
        ];
        assert_eq!(find_field(&fields, "password").unwrap().id, "password");
        assert_eq!(find_field(&fields, "api token").unwrap().id, "custom-0");
        assert_eq!(find_field(&fields, "custom-2").unwrap().id, "custom-2");
        assert!(find_field(&fields, "Twin").is_none());
        // A built-in field is only named by its id, and a custom field
        // labelled like one never shadows it.
        assert!(find_field(&fields, "Password").is_none());
        let mut shadow = fields.to_vec();
        shadow.push(field("custom-3", "password"));
        assert_eq!(find_field(&shadow, "password").unwrap().id, "password");
        assert!(find_field(&fields, "missing").is_none());
    }

    #[test]
    fn env_file_is_read() {
        let vars = parse_env_file(
            "# comment\n\nexport TOKEN=\"verrou://GitHub/token\"\nPLAIN='x=y'\nPORT=8080\n",
        )
        .unwrap();
        assert_eq!(
            vars,
            vec![
                ("TOKEN".into(), "verrou://GitHub/token".into()),
                ("PLAIN".into(), "x=y".into()),
                ("PORT".into(), "8080".into()),
            ]
        );
        assert!(parse_env_file("NOEQUALS").is_err());
        assert!(parse_env_file("BAD-NAME=1").is_err());
    }

    #[test]
    fn file_wins_over_environment() {
        let env = vec![
            ("A".to_owned(), "verrou://One/password".to_owned()),
            ("B".to_owned(), "plain".to_owned()),
        ];
        let file = vec![
            ("A".to_owned(), "plain now".to_owned()),
            ("C".to_owned(), "verrou://Two/totp".to_owned()),
        ];
        let found = references(env, &file).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "C");
    }

    #[test]
    fn secrets_are_masked_across_writes() {
        let mut masker = Masker::new(["hunter2-secret", "ab"]);
        let mut out = Vec::new();
        out.extend(masker.feed(b"token=hunter2"));
        out.extend(masker.feed(b"-secret and ab\n"));
        out.extend(masker.finish());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("token={CONCEALED} and ab\n")
        );
    }

    #[test]
    fn longest_secret_wins() {
        let mut masker = Masker::new(["pass", "password123"]);
        let mut out = masker.feed(b"password123 pass");
        out.extend(masker.finish());
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("{CONCEALED} {CONCEALED}")
        );
    }

    #[test]
    fn a_secret_starting_another_doesnt_let_the_longer_one_out() {
        // Found by fuzzing: "password12" arrives first; masking "pass" at
        // once let "word123" out when the rest of "password123" came.
        let mut masker = Masker::new(["pass", "password123"]);
        let mut out = masker.feed(b"password12");
        out.extend(masker.feed(b"3 ok"));
        out.extend(masker.finish());
        assert_eq!(String::from_utf8(out).unwrap(), format!("{CONCEALED} ok"));
    }

    #[test]
    fn only_a_possible_secret_is_held_back() {
        let mut masker = Masker::new(["hunter2"]);
        // A prompt without a newline shows at once.
        assert_eq!(masker.feed(b"Password: "), b"Password: ");
        // "hun" may start the secret: held until the next write.
        assert_eq!(masker.feed(b"ok hun"), b"ok ");
        assert_eq!(masker.feed(b"gry\n"), b"hungry\n");
        assert_eq!(masker.feed(b"hun"), b"");
        assert_eq!(masker.finish(), b"hun");
    }

    #[test]
    fn output_without_secrets_passes_through() {
        let mut out = Vec::new();
        pump(&b"hello\nworld\n"[..], &mut out, Masker::new(["unrelated"])).unwrap();
        assert_eq!(out, b"hello\nworld\n");
    }
}
