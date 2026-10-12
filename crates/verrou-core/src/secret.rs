//! Valeurs sensibles : effacées de la mémoire à la libération, jamais affichées
//! par `Debug`.

use std::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Une chaîne secrète (mot de passe, numéro de carte, graine TOTP, note).
///
/// Le contenu est mis à zéro quand la valeur est libérée, et `Debug` ne
/// l'affiche jamais : un `{:?}` oublié dans un journal ne fuit rien.
#[derive(Clone, Default, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Accès explicite au contenu. Le nom rend chaque usage visible en revue.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.chars().count()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(***)")
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_value() {
        let secret = SecretString::new("hunter2");
        assert_eq!(format!("{secret:?}"), "SecretString(***)");
        assert_eq!(secret.expose(), "hunter2");
    }
}
