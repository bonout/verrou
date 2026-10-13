use std::fmt;

/// Ce qui peut mal tourner entre Verrou et le serveur.
///
/// Les messages sont destinés à l'utilisateur : ils disent quoi faire, pas
/// comment le code a échoué. Aucun ne contient de secret.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("mot de passe principal incorrect")]
    WrongPassword,
    #[error("second facteur refusé : {0}")]
    TwoFactorRejected(String),
    #[error("aucun compte n'est configuré")]
    NoAccount,
    #[error("la session a expiré : reconnectez-vous")]
    SessionExpired,
    #[error("adresse du serveur invalide : {0}")]
    InvalidServer(String),
    #[error("serveur injoignable : {0}")]
    Network(String),
    #[error("réponse du serveur : {0}")]
    Server(String),
    #[error("déchiffrement impossible : {0}")]
    Crypto(String),
    #[error("stockage local : {0}")]
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
            Self::Server(format!("réponse illisible ({error})"))
        } else if let Some(status) = error.status() {
            Self::Server(status.to_string())
        } else {
            // Sans la chaîne des causes, reqwest ne dit pas pourquoi la
            // connexion a échoué (DNS, TLS, refus).
            let mut message = error.to_string();
            let mut source = std::error::Error::source(&error);
            while let Some(cause) = source {
                message = format!("{message} : {cause}");
                source = cause.source();
            }
            Self::Network(message)
        }
    }
}
