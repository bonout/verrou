import AuthenticationServices
import SwiftUI

/// Point d'entrée de l'extension de remplissage automatique : le système
/// l'appelle pour une liste (clavier, touche « Mots de passe »), pour une
/// suggestion touchée (barre QuickType), pour une passkey ou un code.
///
/// Le coffre est toujours verrouillé quand une demande arrive (nouveau
/// processus) : les demandes « sans interaction » rendent la main au système
/// (`userInteractionRequired`), qui affiche alors l'interface ci-dessous,
/// où Face ID part tout seul.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private lazy var model = AutoFillModel { [weak self] completion in
        self?.complete(completion)
    }
    private var hosted = false

    override func viewDidLoad() {
        super.viewDidLoad()
        let host = UIHostingController(rootView: AutoFillRootView().environment(model))
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
        hosted = true
    }

    // MARK: Listes

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        model.start(.list(services: serviceIdentifiers, passkeys: nil))
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier],
                                        requestParameters: ASPasskeyCredentialRequestParameters) {
        model.start(.list(services: serviceIdentifiers, passkeys: AutoFillModel.PasskeyQuery(
            rpID: requestParameters.relyingPartyIdentifier, clientDataHash: requestParameters.clientDataHash,
            allowed: requestParameters.allowedCredentials)))
    }

    @available(iOS 18.0, *)
    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        model.start(.oneTimeCodes(services: serviceIdentifiers))
    }

    // MARK: Suggestion touchée

    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        // Coffre verrouillé dans ce nouveau processus : il faut Face ID.
        extensionContext.cancelRequest(withError: NSError(
            domain: ASExtensionErrorDomain, code: ASExtensionError.userInteractionRequired.rawValue))
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        model.start(.provide(credentialRequest))
    }

    // MARK: Création de passkey

    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        guard let request = registrationRequest as? ASPasskeyCredentialRequest else {
            return complete(.failed("demande de création invalide"))
        }
        model.start(.register(request))
    }

    override func prepareInterfaceForExtensionConfiguration() {
        model.start(.none)
    }

    // MARK: Réponse

    private func complete(_ completion: AutoFillModel.Completion) {
        switch completion {
        case .password(let user, let password):
            extensionContext.completeRequest(withSelectedCredential: ASPasswordCredential(user: user, password: password))
        case .assertion(let credential):
            extensionContext.completeAssertionRequest(using: credential)
        case .registration(let credential):
            extensionContext.completeRegistrationRequest(using: credential)
        case .oneTimeCode(let code):
            if #available(iOS 18.0, *) {
                extensionContext.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code))
            } else {
                cancel(.failed)
            }
        case .cancel:
            cancel(.userCanceled)
        case .failed:
            cancel(.failed)
        }
    }

    private func cancel(_ code: ASExtensionError.Code) {
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: code.rawValue))
    }
}
