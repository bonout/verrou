import LocalAuthentication
import os

/// Touch ID (and Apple Watch) on the Mac, Face ID or Touch ID on the iPhone,
/// through LocalAuthentication.
///
/// For the demo vault, a success is enough to open it. With Vaultwarden, it
/// is not this boolean that decides: the vault key is sealed by the Secure
/// Enclave (`BiometricVault`), which only returns it after Touch ID.
enum Biometrics {
    enum Outcome {
        case success
        /// The user chose the master password.
        case fallback
        case failure(String)
    }

    /// Every question to LocalAuthentication goes through another process
    /// (2 ms, 40 ms the first time): the answer is kept until the app's next
    /// activation (`refresh()`), instead of being asked again on every render
    /// of the lock screen.
    private static let cache = OSAllocatedUnfairLock<(available: Bool, type: LABiometryType)?>(initialState: nil)

    private static var state: (available: Bool, type: LABiometryType) {
        if let state = cache.withLock({ $0 }) { return state }
        let state = query()
        cache.withLock { $0 = state }
        return state
    }

    private static func query() -> (available: Bool, type: LABiometryType) {
        let context = LAContext()
        let available = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return (available, context.biometryType)
    }

    static var isAvailable: Bool { state.available }

    static var symbolName: String {
        switch state.type {
        case .faceID: "faceid"
        case .opticID: "opticid"
        default: "touchid"
        }
    }

    /// The sensor's name, for labels ("Unlock with Face ID").
    /// With no sensor detected: the platform's.
    static var name: String {
        switch state.type {
        case .faceID: "Face ID"
        case .opticID: "Optic ID"
        case .touchID: "Touch ID"
        default:
            #if os(macOS)
            "Touch ID"
            #else
            "Face ID"
            #endif
        }
    }

    /// On app activation: a sensor may have appeared or disappeared (Touch ID
    /// keyboard plugged in, Mac closed, Face ID enrolled or removed). The
    /// question is asked again off the main thread; the old answer is used in
    /// the meantime (no synchronous question on the main thread at each
    /// activation, right before asking for Face ID).
    static func refresh() {
        Task.detached(priority: .userInitiated) {
            let state = query()
            cache.withLock { $0 = state }
        }
    }

    static func authenticate(reason: String) async -> Outcome {
        let context = LAContext()
        context.localizedFallbackTitle = String(localized: "Master password")
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .failure(error?.localizedDescription ?? String(localized: "\(name) is not available."))
        }
        do {
            try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
            return .success
        } catch let laError as LAError where laError.code == .userFallback {
            return .fallback
        } catch let laError as LAError where laError.code == .userCancel {
            return .failure("")
        } catch {
            return .failure(error.localizedDescription)
        }
    }

    /// Confirmation of an access requested by the terminal: Touch ID, or the
    /// session password (`.deviceOwnerAuthentication`) when Touch ID is not
    /// available or the user prefers it.
    static func confirm(reason: String) async -> Bool {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { return false }
        return (try? await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)) ?? false
    }
}
