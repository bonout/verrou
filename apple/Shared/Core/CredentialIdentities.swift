#if os(iOS) || os(macOS)
import AuthenticationServices
import CryptoKit
import Foundation
import os

/// The system's suggestions (QuickType bar above the keyboard, Safari's
/// list): AuthenticationServices' identity store.
///
/// After each unlock, sync or write, the app publishes there the sites
/// (domains) and user names of its logins, the one-time codes (iOS 18) and
/// its passkeys (site, user, credential ID). **Never a secret**: password,
/// code and private key leave the vault only in the extension, after Face ID
/// or the master password. The store is emptied on sign-out; locking keeps
/// it (nothing secret, and the suggestions stay useful).
enum CredentialIdentities {
    private static let log = Logger(subsystem: "app.verrou", category: "autofill")
    /// Digest of the last published list: nothing to redo if it hasn't
    /// changed (most syncs).
    private static let publishedKey = "autofillIdentitiesDigest"

    /// Is Verrou chosen in Settings → General → AutoFill & Passwords?
    static func isEnabled() async -> Bool {
        await ASCredentialIdentityStore.shared.state().isEnabled
    }

    /// Replaces the published identities with the vault's.
    static func publish(_ identities: [AutofillIdentity]) async {
        let store = ASCredentialIdentityStore.shared
        guard await store.state().isEnabled else {
            // Disabled: the system may have emptied the store, republish
            // everything when Verrou is chosen again.
            UserDefaults.standard.removeObject(forKey: publishedKey)
            return
        }
        let digest = digest(of: identities)
        if UserDefaults.standard.string(forKey: publishedKey) == digest { return }
        var converted: [any ASCredentialIdentity] = []
        converted.reserveCapacity(identities.count)
        for identity in identities {
            if let value = convert(identity) { converted.append(value) }
        }
        do {
            try await store.replaceCredentialIdentities(converted)
            UserDefaults.standard.set(digest, forKey: publishedKey)
            log.notice("identities published: \(converted.count, privacy: .public)")
        } catch {
            log.error("could not publish identities: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Sign-out: no suggestion any more.
    static func clear() async {
        UserDefaults.standard.removeObject(forKey: publishedKey)
        try? await ASCredentialIdentityStore.shared.removeAllCredentialIdentities()
    }

    private static func convert(_ identity: AutofillIdentity) -> (any ASCredentialIdentity)? {
        switch identity.kind {
        case .password:
            return ASPasswordCredentialIdentity(
                serviceIdentifier: ASCredentialServiceIdentifier(identifier: identity.service, type: .domain),
                user: identity.user, recordIdentifier: identity.itemId)
        case .passkey:
            return ASPasskeyCredentialIdentity(
                relyingPartyIdentifier: identity.service, userName: identity.user,
                credentialID: Data(identity.credentialId), userHandle: Data(identity.userHandle),
                recordIdentifier: identity.itemId)
        case .oneTimeCode:
            if #available(iOS 18.0, *) {
                return ASOneTimeCodeCredentialIdentity(
                    serviceIdentifier: ASCredentialServiceIdentifier(identifier: identity.service, type: .domain),
                    label: identity.user, recordIdentifier: identity.itemId)
            }
            return nil
        }
    }

    /// Digest (SHA-256) of the list: neither secret nor name is kept in clear.
    private static func digest(of identities: [AutofillIdentity]) -> String {
        var text = ""
        for identity in identities {
            text += "\(identity.kind)|\(identity.itemId)|\(identity.service)|\(identity.user)|"
            text += Data(identity.credentialId).base64EncodedString() + "\n"
        }
        return Data(SHA256.hash(data: Data(text.utf8))).base64EncodedString()
    }
}
#endif
