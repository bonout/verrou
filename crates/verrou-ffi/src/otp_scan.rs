//! Reading a two-factor authentication QR code for the iPhone app.
//! See `verrou_core::otp_scan`.
//!
//! Documented exception to the crate's principle: `scan_otp` returns the
//! canonical `otpauth://` link of each account, seed included. The user
//! just scanned it (or pasted it) to save it: it goes straight
//! into the item's encrypted draft, without being logged
//! or copied.

use verrou_core::otp_scan::{self, OtpAccount};
use verrou_core::totp::Totp;

use crate::{TotpView, VaultSession, VerrouError};

/// Existing login, without a code, the scanned account can be added to.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct OtpTarget {
    pub id: String,
    pub title: String,
    /// Displayed username (never a secret).
    pub subtitle: String,
}

/// An account read from the QR code, validated.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ScannedOtp {
    pub issuer: Option<String>,
    pub account: Option<String>,
    /// Suggested title for a new login.
    pub title: String,
    /// Canonical `otpauth://totp` link, seed included: the field's value.
    pub uri: String,
    /// First code, for the preview.
    pub code: TotpView,
    /// Logins without a code for the same service (or the same username), the
    /// most likely first. Empty if the vault is locked.
    pub matches: Vec<OtpTarget>,
}

/// Content of a QR code.
#[derive(Clone, Debug, uniffi::Record)]
pub struct OtpScanResult {
    pub accounts: Vec<ScannedOtp>,
    /// HOTP (counter-based) accounts from a Google Authenticator export, skipped.
    pub skipped: u32,
    /// Export split over several QR codes: position (from 1) and total count.
    pub batch_number: Option<u32>,
    pub batch_count: Option<u32>,
}

fn view(totp: &Totp, unix_time: u64) -> TotpView {
    let code = totp.generate(unix_time);
    TotpView {
        code: code.code,
        period: code.period,
        remaining: code.remaining,
    }
}

fn invalid(error: verrou_core::totp::TotpError) -> VerrouError {
    VerrouError::InvalidTotp {
        message: error.to_string(),
    }
}

/// Current code for a seed or an `otpauth://` link (preview before
/// saving).
#[uniffi::export]
pub fn totp_preview(value: String, unix_time: u64) -> Result<TotpView, VerrouError> {
    let totp = Totp::parse(&value).map_err(invalid)?;
    Ok(view(&totp, unix_time))
}

#[uniffi::export]
impl VaultSession {
    /// Reads the text of a QR code (`otpauth://totp` link, Google Authenticator
    /// `otpauth-migration://` export, bare seed) and looks up,
    /// for each account, the logins without a code to add it to.
    pub fn scan_otp(&self, text: String, unix_time: u64) -> Result<OtpScanResult, VerrouError> {
        let scan = otp_scan::parse_scan(&text).map_err(invalid)?;
        let accounts = scan
            .accounts
            .iter()
            .map(|account| ScannedOtp {
                issuer: account.issuer.clone(),
                account: account.account.clone(),
                title: account.suggested_title(),
                uri: account.uri(),
                code: view(&account.totp(), unix_time),
                matches: self.otp_targets(account),
            })
            .collect();
        Ok(OtpScanResult {
            accounts,
            skipped: scan.skipped as u32,
            batch_number: scan.batch.map(|(index, _)| index + 1),
            batch_count: scan.batch.map(|(_, count)| count),
        })
    }
}

impl VaultSession {
    fn otp_targets(&self, account: &OtpAccount) -> Vec<OtpTarget> {
        self.with_vault(|vault| {
            Ok(otp_scan::matching_logins(vault, account)
                .into_iter()
                .take(5)
                .map(|item| OtpTarget {
                    id: item.id.clone(),
                    title: item.title.clone(),
                    subtitle: item.subtitle.clone(),
                })
                .collect())
        })
        .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_proposes_logins_without_a_code() {
        let session = VaultSession::new();
        session.unlock_mock(0, 42);
        // Netflix has no code in the mock vault, GitHub has one.
        let netflix = session
            .scan_otp(
                "otpauth://totp/Netflix:camille.martin%40exemple.fr?secret=JBSWY3DPEHPK3PXP&issuer=Netflix".into(),
                59,
            )
            .unwrap();
        let account = &netflix.accounts[0];
        assert_eq!(account.title, "Netflix");
        assert_eq!(account.code.code.len(), 6);
        assert_eq!(account.code.remaining, 1);
        assert_eq!(
            account.matches.first().map(|m| m.title.as_str()),
            Some("Netflix")
        );
        let github = session
            .scan_otp(
                "otpauth://totp/GitHub:camille-dev?secret=JBSWY3DPEHPK3PXP".into(),
                59,
            )
            .unwrap();
        assert!(
            github.accounts[0]
                .matches
                .iter()
                .all(|m| m.title != "GitHub")
        );
        assert_eq!(
            totp_preview(account.uri.clone(), 59).unwrap().code,
            account.code.code
        );
    }

    #[test]
    fn scan_reports_batches_and_errors() {
        let session = VaultSession::new();
        let result = session
            .scan_otp(
                "otpauth-migration://offline?data=CjcKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEg9yZmNAZXhhbXBsZS5jb20aCFJGQyA2MjM4IAEoAjACCkIKIDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyEg%2FDiXF1aXBlOmNhbWlsbGUaB8OJcXVpcGUgAigBMAIKMAoKSGVsbG8h3q2%2B7xIQaG90cEBleGFtcGxlLmNvbRoIQ29tcHRldXIgASgBMAE4BxABGAIgACjAxAc%3D".into(),
                59,
            )
            .unwrap();
        assert_eq!(result.accounts.len(), 2);
        assert_eq!(
            (result.skipped, result.batch_number, result.batch_count),
            (1, Some(1), Some(2))
        );
        assert_eq!(result.accounts[0].code.code, "94287082");
        // Locked vault: no suggestion, no error.
        assert_eq!(result.accounts[0].matches, Vec::<OtpTarget>::new());
        assert!(matches!(
            session.scan_otp("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP".into(), 0),
            Err(VerrouError::InvalidTotp { message }) if message.contains("HOTP")
        ));
    }
}
