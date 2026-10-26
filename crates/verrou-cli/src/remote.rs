//! Dialogue with Verrou through its bridge: TCP `127.0.0.1`, "length (u32
//! little-endian) + JSON" frames, like the ones the Native Messaging host
//! relays for the extension, and a channel encrypted with the key obtained
//! at pairing.

use std::fmt;
use std::io::{self, Read as _, Write as _};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use verrou_bridge::crypto::{ChannelKey, Direction, KeyPair};
use verrou_bridge::protocol::{
    ClientKind, Command, ErrorCode, Incoming, MAX_FRAME, Outgoing, Reply, ReplyResult, Request,
    RunDetail, UnlockIntent,
};
use zeroize::Zeroize as _;

use crate::config::Config;

/// A reply may wait for the user's approval (90 s at most on Verrou's
/// side); a pairing, two minutes.
const READ_TIMEOUT: Duration = Duration::from_secs(150);
/// The time given to the user to unlock the vault.
const UNLOCK_WAIT: Duration = Duration::from_secs(60);

/// Environment variables that say a coding agent runs this process. Set by
/// the agent itself, for what it launches: Claude Code (`CLAUDECODE`,
/// `CLAUDE_CODE_ENTRYPOINT`, and the generic `AI_AGENT`, all seen in its
/// own shell), Cursor's agent (`CURSOR_AGENT`; `CURSOR_TRACE_ID` is set in
/// every terminal of the editor, the user's included: an extra question, not
/// a danger), Codex (`CODEX_SANDBOX`, `CODEX_SANDBOX_NETWORK_DISABLED`,
/// `CODEX_CI`, `CODEX_THREAD_ID`), Gemini CLI (`GEMINI_CLI`), `OpenCode`
/// (`OPENCODE`), and `VERROU_AGENT` for any other (set it in the agent's
/// environment). `CODEX_HOME` is not on the list: it is the user's own
/// setting, often exported everywhere. Only the Claude Code names were
/// checked on a running agent; the others come from the agents' documentation
/// and the `AI_AGENT` convention. A guess at best: an agent can unset these,
/// and a pipe in place of a terminal ([`driven_by_agent`]) is the other sign.
pub const AGENT_VARIABLES: &[&str] = &[
    "AI_AGENT",
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "CURSOR_AGENT",
    "CURSOR_TRACE_ID",
    "CODEX_SANDBOX",
    "CODEX_SANDBOX_NETWORK_DISABLED",
    "CODEX_CI",
    "CODEX_THREAD_ID",
    "GEMINI_CLI",
    "OPENCODE",
    "VERROU_AGENT",
];

/// Does this process look driven by a coding agent: one of
/// [`AGENT_VARIABLES`] set (and not `0` or `false`), or no terminal on its
/// standard input (an agent's shell gives its commands a pipe or nothing; a
/// person types in a terminal)? Then its requests are approved one by one
/// and show the command ([`Remote::ephemeral`]): this only ever adds a
/// question for the user, never removes one. `env` reads a variable.
pub fn driven_by_agent_with(env: impl Fn(&str) -> Option<String>, stdin_is_terminal: bool) -> bool {
    !stdin_is_terminal
        || AGENT_VARIABLES.iter().any(|name| {
            env(name).is_some_and(|value| {
                let value = value.trim();
                !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false")
            })
        })
}

/// [`driven_by_agent_with`], for this process.
pub fn driven_by_agent() -> bool {
    use std::io::IsTerminal as _;
    driven_by_agent_with(|name| std::env::var(name).ok(), io::stdin().is_terminal())
}

/// Where to reach Verrou.
#[derive(Clone, Copy, Debug)]
pub struct Endpoint {
    pub port: u16,
    /// Open Verrou if it does not answer.
    pub launch: bool,
}

impl Endpoint {
    /// Verrou's port (`VERROU_BRIDGE_PORT` overrides it).
    pub fn from_env() -> Self {
        Self {
            port: verrou_bridge::port_from_env(),
            launch: true,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// No link file.
    NotLinked,
    /// Verrou does not answer (closed, or bridge disabled).
    AppUnavailable,
    /// Link revoked in Verrou.
    UnknownClient,
    /// Vault stayed locked.
    Locked,
    /// Refusal by Verrou or the user, with its reason.
    Denied(String),
    Protocol(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotLinked => write!(f, "this terminal is not linked to Verrou: `verrou link`"),
            Self::AppUnavailable => write!(
                f,
                "Verrou does not answer: open the app and turn on \"Brave, Firefox and the terminal\" in its settings"
            ),
            Self::UnknownClient => write!(
                f,
                "this terminal is no longer linked to Verrou (link revoked): `verrou link`"
            ),
            Self::Locked => write!(f, "the vault stayed locked"),
            Self::Denied(reason) => write!(f, "{reason}"),
            Self::Protocol(message) => write!(f, "dialogue with Verrou: {message}"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Protocol(error.to_string())
    }
}

fn write_frame(stream: &mut TcpStream, message: &impl Serialize) -> io::Result<()> {
    let body = serde_json::to_vec(message).map_err(io::Error::other)?;
    let length = u32::try_from(body.len()).map_err(io::Error::other)?;
    stream.write_all(&length.to_le_bytes())?;
    stream.write_all(&body)?;
    stream.flush()
}

fn read_frame(stream: &mut TcpStream) -> Result<Outgoing, Error> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(Error::Protocol("invalid frame".to_owned()));
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|e| Error::Protocol(e.to_string()))
}

fn open_stream(endpoint: Endpoint) -> Result<TcpStream, Error> {
    let stream = verrou_bridge::connect_to_app(endpoint.port, endpoint.launch)
        .ok_or(Error::AppUnavailable)?;
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    Ok(stream)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Links this terminal to Verrou: requests pairing, shows the code through
/// `show_code`, waits for the user's approval in Verrou.
pub fn link(endpoint: Endpoint, name: &str, show_code: impl FnOnce(&str)) -> Result<Config, Error> {
    let mut stream = open_stream(endpoint)?;
    let ours = KeyPair::generate();
    write_frame(
        &mut stream,
        &Incoming::Pair {
            name: name.to_owned(),
            key: ours.public_base64(),
            kind: ClientKind::Cli,
        },
    )?;
    let (client, key) = match read_frame(&mut stream)? {
        Outgoing::Pairing { client, key } => (client, key),
        Outgoing::Error {
            code: ErrorCode::Busy,
        } => {
            return Err(Error::Denied(
                "a pairing is already in progress in Verrou: try again in a few seconds".to_owned(),
            ));
        }
        other => return Err(Error::Protocol(format!("unexpected reply: {other:?}"))),
    };
    let channel = ours
        .agree(&key, false)
        .map_err(|e| Error::Protocol(e.to_string()))?;
    show_code(&channel.pairing_code());
    match read_frame(&mut stream)? {
        Outgoing::Paired => Ok(Config {
            client,
            key: channel.to_base64(),
            linked: now_ms() / 1000,
        }),
        Outgoing::Refused => Err(Error::Denied("pairing refused in Verrou".to_owned())),
        other => Err(Error::Protocol(format!("unexpected reply: {other:?}"))),
    }
}

/// A linked client's connection.
pub struct Remote {
    stream: TcpStream,
    client: String,
    key: ChannelKey,
    next: u64,
    /// Sent with each request: shown in the approval (`--reason`).
    pub reason: Option<String>,
    /// What the next commands read: sent with an unlock request, so that
    /// one approval on the iPhone unlocks and lets this item out.
    pub intent: Option<UnlockIntent>,
    /// An AI agent's requests (`verrou mcp`, or a command line that looks
    /// driven by one, [`driven_by_agent`]): each approval is asked on its own
    /// and never remembered ([`Request::ephemeral_approval`]).
    pub ephemeral: bool,
    /// What the next commands are for, shown in the approval: the command
    /// line and the fields ([`RunDetail`]).
    pub detail: Option<RunDetail>,
}

impl Remote {
    pub fn connect(config: &Config, endpoint: Endpoint) -> Result<Self, Error> {
        let key = config.channel_key().map_err(Error::Protocol)?;
        Ok(Self {
            stream: open_stream(endpoint)?,
            client: config.client.clone(),
            key,
            next: 1,
            reason: None,
            intent: None,
            ephemeral: false,
            detail: None,
        })
    }

    /// Sends a command and returns the reply as is.
    pub fn call(&mut self, command: &Command) -> Result<ReplyResult, Error> {
        let id = self.next;
        self.next += 1;
        let mut payload = serde_json::to_vec(&Request {
            id,
            ts: now_ms(),
            reason: self.reason.clone(),
            ephemeral_approval: self.ephemeral,
            detail: self.detail.clone(),
            command: command.clone(),
        })
        .map_err(|e| Error::Protocol(e.to_string()))?;
        let (iv, data) = self.key.seal(&self.client, Direction::Request, &payload);
        payload.zeroize();
        write_frame(
            &mut self.stream,
            &Incoming::Request {
                client: self.client.clone(),
                iv,
                data,
            },
        )?;
        match read_frame(&mut self.stream)? {
            Outgoing::Response { iv, data } => {
                let mut plain = self
                    .key
                    .open(&self.client, Direction::Response, &iv, &data)
                    .map_err(|e| Error::Protocol(e.to_string()))?;
                let reply = serde_json::from_slice::<Reply>(&plain);
                plain.zeroize();
                let reply = reply.map_err(|e| Error::Protocol(e.to_string()))?;
                if reply.id != id {
                    return Err(Error::Protocol("reply to another request".to_owned()));
                }
                Ok(reply.result)
            }
            Outgoing::Error {
                code: ErrorCode::UnknownClient,
            } => Err(Error::UnknownClient),
            other => Err(Error::Protocol(format!("unexpected reply: {other:?}"))),
        }
    }

    /// Like [`Self::call`], but a refusal becomes an error, and a locked
    /// vault is unlocked first: Verrou asks for Touch ID (or the iPhone),
    /// we wait up to a minute. Twice at most: the vault may lock again
    /// while an approval is being given.
    pub fn ask(&mut self, command: &Command) -> Result<ReplyResult, Error> {
        let mut result = self.call(command)?;
        for _ in 0..2 {
            if result != ReplyResult::Locked {
                break;
            }
            self.unlock()?;
            result = self.call(command)?;
        }
        match result {
            ReplyResult::Locked => Err(Error::Locked),
            ReplyResult::Denied { reason } => Err(Error::Denied(reason)),
            other => Ok(other),
        }
    }

    pub fn unlocked(&mut self) -> Result<bool, Error> {
        match self.call(&Command::Status)? {
            ReplyResult::Status { unlocked, .. } => Ok(unlocked),
            other => Err(Error::Protocol(format!(
                "unexpected reply: {}",
                other.kind()
            ))),
        }
    }

    fn unlock(&mut self) -> Result<(), Error> {
        self.call(&Command::Unlock {
            then: self.intent.clone(),
        })?;
        eprintln!("verrou: vault locked, unlock it in Verrou…");
        let start = Instant::now();
        while start.elapsed() < UNLOCK_WAIT {
            if self.unlocked()? {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err(Error::Locked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(set: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            set.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    #[test]
    fn a_person_at_a_terminal_is_not_an_agent() {
        assert!(!driven_by_agent_with(env(&[]), true));
        // Other variables, and the user's own Codex setting, say nothing.
        assert!(!driven_by_agent_with(
            env(&[("CODEX_HOME", "/home/me/.codex"), ("TERM", "xterm")]),
            true
        ));
        // Set to nothing, or off.
        for off in ["", "0", "false", "FALSE", " "] {
            assert!(
                !driven_by_agent_with(env(&[("CLAUDECODE", off)]), true),
                "{off:?}"
            );
        }
    }

    #[test]
    fn an_agents_variables_or_a_missing_terminal_say_it_is_one() {
        for name in AGENT_VARIABLES {
            assert!(driven_by_agent_with(env(&[(name, "1")]), true), "{name}");
        }
        for (name, value) in [
            ("CLAUDECODE", "1"),
            ("CLAUDE_CODE_ENTRYPOINT", "cli"),
            ("AI_AGENT", "claude-code"),
            ("CURSOR_AGENT", "1"),
            ("CURSOR_TRACE_ID", "abc"),
            ("CODEX_SANDBOX", "seatbelt"),
            ("VERROU_AGENT", "yes"),
        ] {
            assert!(driven_by_agent_with(env(&[(name, value)]), true), "{name}");
        }
        // A pipe in place of a terminal, whatever the environment says.
        assert!(driven_by_agent_with(env(&[]), false));
    }
}
