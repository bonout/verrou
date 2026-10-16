import AuthenticationServices
import CryptoKit
import Foundation

// Passage entre les types d'AuthenticationServices (iOS 18, macOS 15) et
// ceux de `PasskeyPrf.swift`. Les sorties sont des clés (`SymmetricKey`) :
// elles vont du cœur Rust au système, sans être gardées.

@available(iOS 18.0, macOS 15.0, *)
extension PrfInputs {
    init(_ values: ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues) {
        self.init(first: values.saltInput1, second: values.saltInput2)
    }
}

@available(iOS 18.0, macOS 15.0, *)
extension PasskeyPrfAssertion {
    /// `nil` si le site ne demande pas la PRF.
    init?(_ input: ASAuthorizationPublicKeyCredentialPRFAssertionInput?) {
        guard let input else { return nil }
        var perCredential: [Data: PrfInputs] = [:]
        for (id, values) in input.perCredentialInputValues ?? [:] {
            perCredential[id] = PrfInputs(values)
        }
        self.init(eval: input.inputValues.map(PrfInputs.init), perCredential: perCredential)
    }

    /// La demande de connexion du système (suggestion touchée).
    init?(request: ASPasskeyCredentialRequest) {
        guard case .assertion(let input) = request.extensionInput else { return nil }
        self.init(input.prf)
    }
}

@available(iOS 18.0, macOS 15.0, *)
extension PasskeyPrfRegistration {
    /// `nil` si le site ne demande pas la PRF.
    init?(request: ASPasskeyCredentialRequest) {
        guard case .registration(let input) = request.extensionInput, let prf = input.prf else { return nil }
        self.init(eval: prf.inputValues.map(PrfInputs.init))
    }
}

@available(iOS 18.0, macOS 15.0, *)
enum PasskeyPrfOutputs {
    static func assertion(_ output: PasskeyPrfOutput) -> ASPasskeyAssertionCredentialExtensionOutput {
        ASPasskeyAssertionCredentialExtensionOutput(prf: ASAuthorizationPublicKeyCredentialPRFAssertionOutput(
            first: SymmetricKey(data: output.first), second: output.second.map { SymmetricKey(data: $0) }))
    }

    /// Création : la passkey sait évaluer la PRF ; les sorties si le site a
    /// donné des entrées.
    static func registration(_ output: PasskeyPrfOutput?) -> ASPasskeyRegistrationCredentialExtensionOutput {
        guard let output else { return ASPasskeyRegistrationCredentialExtensionOutput(prf: .supported) }
        return ASPasskeyRegistrationCredentialExtensionOutput(prf: ASAuthorizationPublicKeyCredentialPRFRegistrationOutput(
            first: SymmetricKey(data: output.first), second: output.second.map { SymmetricKey(data: $0) }))
    }
}
