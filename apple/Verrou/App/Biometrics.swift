import LocalAuthentication

/// Touch ID (et Apple Watch) via LocalAuthentication.
///
/// Pour le coffre fictif, un succès suffit à l'ouvrir. Avec Vaultwarden, ce
/// n'est pas ce booléen qui décide : la clé du coffre est scellée par le
/// Secure Enclave (`BiometricVault`), qui ne la rend qu'après Touch ID.
enum Biometrics {
    enum Outcome {
        case success
        case failure(String)
    }

    static var isAvailable: Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    static var symbolName: String {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return context.biometryType == .faceID ? "faceid" : "touchid"
    }

    static func authenticate(reason: String) async -> Outcome {
        let context = LAContext()
        context.localizedFallbackTitle = "Mot de passe principal"
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            return .failure(error?.localizedDescription ?? "Touch ID n'est pas disponible.")
        }
        do {
            try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
            return .success
        } catch let laError as LAError where laError.code == .userCancel || laError.code == .userFallback {
            return .failure("")
        } catch {
            return .failure(error.localizedDescription)
        }
    }
}
