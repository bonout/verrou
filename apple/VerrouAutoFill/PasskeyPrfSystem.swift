import AuthenticationServices
import CryptoKit
import Foundation

// Bridge between AuthenticationServices' types (iOS 18, macOS 15) and
// those of `PasskeyPrf.swift`. The outputs are keys (`SymmetricKey`): they
// go from the Rust core to the system, without being kept.

@available(iOS 18.0, macOS 15.0, *)
extension PrfInputs {
    init(_ values: ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues) {
        self.init(first: values.saltInput1, second: values.saltInput2)
    }
}

@available(iOS 18.0, macOS 15.0, *)
extension PasskeyPrfAssertion {
    /// `nil` if the site doesn't request PRF.
    init?(_ input: ASAuthorizationPublicKeyCredentialPRFAssertionInput?) {
        guard let input else { return nil }
        var perCredential: [Data: PrfInputs] = [:]
        for (id, values) in input.perCredentialInputValues ?? [:] {
            perCredential[id] = PrfInputs(values)
        }
        self.init(eval: input.inputValues.map(PrfInputs.init), perCredential: perCredential)
    }

    /// The system's sign-in request (suggestion tapped).
    init?(request: ASPasskeyCredentialRequest) {
        guard case .assertion(let input) = request.extensionInput else { return nil }
        self.init(input.prf)
    }
}

@available(iOS 18.0, macOS 15.0, *)
extension PasskeyPrfRegistration {
    /// `nil` if the site doesn't request PRF.
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

    /// Creation: the passkey can evaluate PRF; the outputs if the site gave
    /// inputs.
    static func registration(_ output: PasskeyPrfOutput?) -> ASPasskeyRegistrationCredentialExtensionOutput {
        guard let output else { return ASPasskeyRegistrationCredentialExtensionOutput(prf: .supported) }
        return ASPasskeyRegistrationCredentialExtensionOutput(prf: ASAuthorizationPublicKeyCredentialPRFRegistrationOutput(
            first: SymmetricKey(data: output.first), second: output.second.map { SymmetricKey(data: $0) }))
    }
}
