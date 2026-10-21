use std::fmt;

/// What can go wrong between Verrou and the server.
///
/// The messages are meant for the user: they say what to do, not how the
/// code failed. None contains a secret.
#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error("incorrect master password")]
    WrongPassword,
    #[error("second factor rejected: {0}")]
    TwoFactorRejected(String),
    #[error("security key: {0}")]
    SecurityKey(String),
    #[error("no account is set up")]
    NoAccount,
    #[error("item not found")]
    NotFound,
    #[error("this item cannot be edited from this account")]
    ReadOnly,
    #[error("{0}")]
    Invalid(String),
    #[error("the item changed on the server: sync, then try again")]
    Conflict,
    #[error("the session has expired: sign in again")]
    SessionExpired,
    #[error("invalid server address: {0}")]
    InvalidServer(String),
    #[error("server unreachable: {0}")]
    Network(String),
    #[error("server response: {0}")]
    Server(String),
    #[error("decryption failed: {0}")]
    Crypto(String),
    #[error("local storage: {0}")]
    Storage(String),
}

impl Error {
    pub(crate) fn crypto(error: impl fmt::Display) -> Self {
        Self::Crypto(error.to_string())
    }

    pub(crate) fn storage(error: impl fmt::Display) -> Self {
        Self::Storage(error.to_string())
    }
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        if error.is_decode() {
            Self::Server(format!("unreadable response ({error})"))
        } else if let Some(status) = error.status() {
            Self::Server(status.to_string())
        } else {
            // Without the chain of causes, reqwest doesn't say why the
            // connection failed (DNS, TLS, refused).
            let mut message = error.to_string();
            let mut source = std::error::Error::source(&error);
            while let Some(cause) = source {
                message = format!("{message}: {cause}");
                source = cause.source();
            }
            Self::Network(message)
        }
    }
}
