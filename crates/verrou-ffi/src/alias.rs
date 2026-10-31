use std::sync::PoisonError;

use verrou_core::alias::{AliasDomain, AliasError, AliasSettings};

use crate::{VaultSession, VerrouError};

pub(crate) const ALIAS_FILE: &str = "alias.json";

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct EmailAliasSettings {
    pub domain: Option<String>,
    pub include_site: bool,
}

impl From<&AliasSettings> for EmailAliasSettings {
    fn from(settings: &AliasSettings) -> Self {
        Self {
            domain: settings
                .provider
                .as_ref()
                .map(|provider| provider.domain().to_string()),
            include_site: settings.include_site,
        }
    }
}

impl From<AliasError> for VerrouError {
    fn from(error: AliasError) -> Self {
        Self::Invalid {
            message: error.to_string(),
        }
    }
}

#[uniffi::export]
pub fn normalize_alias_domain(domain: String) -> Result<String, VerrouError> {
    Ok(AliasDomain::parse(&domain)?.to_string())
}

impl VaultSession {
    pub(crate) fn alias_settings(&self) -> AliasSettings {
        match &self.store {
            Some(store) => store
                .read_file(ALIAS_FILE)
                .and_then(|data| serde_json::from_slice(&data).ok())
                .unwrap_or_default(),
            None => self
                .alias
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        }
    }
}

#[uniffi::export]
impl VaultSession {
    pub fn email_alias_settings(&self) -> EmailAliasSettings {
        EmailAliasSettings::from(&self.alias_settings())
    }

    pub fn set_email_alias_settings(
        &self,
        domain: Option<String>,
        include_site: bool,
    ) -> Result<EmailAliasSettings, VerrouError> {
        let settings =
            AliasSettings::catch_all(domain.as_deref().unwrap_or_default(), include_site)?;
        if let Some(store) = &self.store {
            let data = serde_json::to_vec_pretty(&settings).map_err(|e| VerrouError::Storage {
                message: e.to_string(),
            })?;
            store.write_file(ALIAS_FILE, &data)?;
        }
        *self.alias.write().unwrap_or_else(PoisonError::into_inner) = settings.clone();
        Ok(EmailAliasSettings::from(&settings))
    }

    pub fn generate_email_alias(
        &self,
        uri: Option<String>,
        include_site: Option<bool>,
    ) -> Result<String, VerrouError> {
        let uri = uri.filter(|u| !u.trim().is_empty());
        Ok(self
            .alias_settings()
            .generate(uri.as_deref(), include_site)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_persist_in_the_account_folder() {
        let dir = std::env::temp_dir().join(format!("verrou-alias-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let session = VaultSession::with_storage(dir.to_string_lossy().into_owned());
        assert_eq!(
            session.email_alias_settings(),
            EmailAliasSettings {
                domain: None,
                include_site: true
            }
        );
        assert!(matches!(
            session.generate_email_alias(None, None),
            Err(VerrouError::Invalid { .. })
        ));

        let saved = session
            .set_email_alias_settings(Some(" Alias.Example.com ".to_owned()), true)
            .unwrap();
        assert_eq!(saved.domain.as_deref(), Some("alias.example.com"));
        let alias = session
            .generate_email_alias(Some("https://www.netflix.com/signup".to_owned()), None)
            .unwrap();
        assert!(alias.starts_with("netflix.") && alias.ends_with("@alias.example.com"));
        let alias = session
            .generate_email_alias(Some(String::new()), None)
            .unwrap();
        assert!(alias.starts_with("alias."), "{alias}");

        let again = VaultSession::with_storage(dir.to_string_lossy().into_owned());
        assert_eq!(again.email_alias_settings(), saved);
        let file: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join(ALIAS_FILE)).unwrap()).unwrap();
        assert_eq!(file["provider"]["kind"], "catch_all");
        assert_eq!(file["provider"]["domain"], "alias.example.com");

        assert!(matches!(
            session.set_email_alias_settings(Some("not a domain".to_owned()), true),
            Err(VerrouError::Invalid { .. })
        ));
        assert_eq!(session.email_alias_settings(), saved);

        session.set_email_alias_settings(None, false).unwrap();
        assert_eq!(
            again.email_alias_settings(),
            EmailAliasSettings {
                domain: None,
                include_site: false
            }
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_without_storage_stay_in_memory() {
        let session = VaultSession::new();
        session
            .set_email_alias_settings(Some("example.com".to_owned()), false)
            .unwrap();
        let alias = session
            .generate_email_alias(Some("https://netflix.com".to_owned()), None)
            .unwrap();
        let (local, domain) = alias.split_once('@').unwrap();
        assert_eq!(domain, "example.com");
        assert_eq!(local.len(), verrou_core::alias::RANDOM_LEN);
        let alias = session
            .generate_email_alias(Some("https://netflix.com".to_owned()), Some(true))
            .unwrap();
        assert!(alias.starts_with("netflix."));
    }

    #[test]
    fn domains_are_checked_for_the_settings_field() {
        assert_eq!(
            normalize_alias_domain("@Mail.Example.org.".to_owned()).unwrap(),
            "mail.example.org"
        );
        assert!(normalize_alias_domain("example".to_owned()).is_err());
    }
}
