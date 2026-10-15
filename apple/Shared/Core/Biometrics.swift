import LocalAuthentication
import os

/// Touch ID (et Apple Watch) sur le Mac, Face ID ou Touch ID sur l'iPhone,
/// via LocalAuthentication.
///
/// Pour le coffre fictif, un succès suffit à l'ouvrir. Avec Vaultwarden, ce
/// n'est pas ce booléen qui décide : la clé du coffre est scellée par le
/// Secure Enclave (`BiometricVault`), qui ne la rend qu'après Touch ID.
enum Biometrics {
    enum Outcome {
        case success
        /// L'utilisateur a choisi le mot de passe principal.
        case fallback
        case failure(String)
    }

    /// Chaque question à LocalAuthentication passe par un autre processus
    /// (2 ms, 40 ms la première fois) : la réponse est gardée jusqu'à la
    /// prochaine activation de l'app (`refresh()`), au lieu d'être reposée à
    /// chaque rendu de l'écran verrouillé.
    private static let cache = OSAllocatedUnfairLock<(available: Bool, type: LABiometryType)?>(initialState: nil)

    private static var state: (available: Bool, type: LABiometryType) {
        if let state = cache.withLock({ $0 }) { return state }
        let context = LAContext()
        let available = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        let state = (available, context.biometryType)
        cache.withLock { $0 = state }
        return state
    }

    static var isAvailable: Bool { state.available }

    static var symbolName: String {
        switch state.type {
        case .faceID: "faceid"
        case .opticID: "opticid"
        default: "touchid"
        }
    }

    /// Le nom du capteur, pour les libellés (« Déverrouiller avec Face ID »).
    /// Sans capteur détecté : celui de la plateforme.
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

    /// À l'activation de l'app : un capteur a pu apparaître ou disparaître
    /// (clavier Touch ID branché, Mac refermé, Face ID enrôlé ou retiré). La question est reposée hors
    /// du fil principal.
    static func refresh() {
        cache.withLock { $0 = nil }
        Task.detached(priority: .userInitiated) { _ = state }
    }

    static func authenticate(reason: String) async -> Outcome {
        let context = LAContext()
        context.localizedFallbackTitle = "Mot de passe principal"
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .failure(error?.localizedDescription ?? "\(name) n'est pas disponible.")
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

    /// Confirmation d'un accès demandé par le terminal : Touch ID, ou le mot
    /// de passe de la session (`.deviceOwnerAuthentication`) quand Touch ID
    /// n'est pas disponible ou que l'utilisateur le préfère.
    static func confirm(reason: String) async -> Bool {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else { return false }
        return (try? await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)) ?? false
    }
}
