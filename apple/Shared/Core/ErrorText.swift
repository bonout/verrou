import Foundation

/// The Rust core's errors, as sentences for the user. Shared by the apps
/// and, later, the AutoFill extension.
enum ErrorText {
    /// The device, in messages ("on this Mac", "on this iPhone").
    static var onThisDevice: String {
        #if os(macOS)
        String(localized: "on this Mac")
        #else
        String(localized: "on this iPhone")
        #endif
    }

    static func describe(_ error: Error) -> String {
        guard let error = error as? VerrouError else { return error.localizedDescription }
        switch error {
        case .WrongPassword: return String(localized: "Incorrect master password.")
        case .TwoFactorRejected(let message): return String(localized: "Second factor rejected (\(message)).")
        case .NoAccount: return String(localized: "No account is set up \(onThisDevice).")
        case .SessionExpired: return String(localized: "The session has expired: sign in again.")
        case .InvalidServer(let message): return String(localized: "Invalid server address: \(message)")
        case .Network(let message): return String(localized: "Server unreachable: this action needs the network. \(message)")
        case .Server(let message): return String(localized: "The server replied: \(message)")
        case .Crypto(let message): return String(localized: "Decryption failed: \(message)")
        case .Storage(let message): return String(localized: "Local storage: \(message)")
        case .Locked: return String(localized: "The vault is locked.")
        case .NotFound: return String(localized: "Item not found.")
        case .InvalidTotp(let message): return String(localized: "Invalid one-time code: \(CoreText.message(message))")
        case .NoPendingLogin: return String(localized: "Start the sign-in again.")
        case .SecurityKey(let message): return String(localized: "Security key: \(message).")
        case .ReadOnly: return String(localized: "This item is read-only for your account.")
        case .Invalid(let message):
            let message = CoreText.message(message)
            return message.prefix(1).uppercased() + message.dropFirst() + "."
        case .Conflict: return String(localized: "The item changed on the server: sync, then try again.")
        case .RepromptRequired: return String(localized: "This item is protected: confirm your identity first.")
        case .NewerFormat: return String(localized: "Your accounts were saved by a newer Verrou: update the app.")
        }
    }

    /// A security key request cancelled (by the user or by switching
    /// method): nothing to show.
    static func isCancellation(_ error: Error) -> Bool {
        if case VerrouError.SecurityKey(let message) = error, message == "request cancelled" { return true }
        return false
    }
}
