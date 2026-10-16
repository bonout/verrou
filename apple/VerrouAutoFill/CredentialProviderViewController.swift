#if os(macOS)
import AppKit
#endif
import AuthenticationServices
import os
import SwiftUI

/// Point d'entrée de l'extension de remplissage automatique : le système
/// l'appelle pour une liste (clavier, touche « Mots de passe »), pour une
/// suggestion touchée (barre QuickType), pour une passkey ou un code.
///
/// Le même code sert l'iPhone (`VerrouAutoFill`) et le Mac
/// (`VerrouAutoFillMac`) : seul l'hébergement de l'interface SwiftUI change
/// (`UIHostingController`, `NSHostingController`).
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

    #if os(macOS)
    /// Pas de nib : la vue est créée ici, à la taille de la feuille du système.
    override func loadView() {
        view = NSView(frame: NSRect(origin: .zero, size: Self.macSize))
    }

    static let macSize = NSSize(width: 440, height: 540)
    #endif

    override func viewDidLoad() {
        super.viewDidLoad()
        #if os(macOS)
        let host = NSHostingController(rootView: AutoFillRootView().environment(model))
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.width, .height]
        view.addSubview(host.view)
        preferredContentSize = Self.macSize
        #else
        let host = UIHostingController(rootView: AutoFillRootView().environment(model))
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
        #endif
        hosted = true
    }

    // MARK: Listes

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        model.start(.list(services: serviceIdentifiers, passkeys: nil))
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier],
                                        requestParameters: ASPasskeyCredentialRequestParameters) {
        var query = AutoFillModel.PasskeyQuery(
            rpID: requestParameters.relyingPartyIdentifier, clientDataHash: requestParameters.clientDataHash,
            allowed: requestParameters.allowedCredentials)
        if #available(iOS 18.0, *) {
            query.prf = PasskeyPrfAssertion(requestParameters.extensionInput?.prf)
        }
        model.start(.list(services: serviceIdentifiers, passkeys: query))
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

    // MARK: Création conditionnelle (iOS 18)

    /// Safari demande une passkey en arrière-plan, juste après un mot de
    /// passe rempli par Verrou (`mediation: "conditional"`). Aucune
    /// interface : la clé préparée au remplissage sert, si le site et le
    /// compte sont les mêmes ; sinon refus silencieux. La passkey rejoint
    /// l'élément à la prochaine ouverture de l'app (`conditional.rs`).
    @available(iOS 18.0, *)
    override func performWithoutUserInteractionIfPossible(passkeyRegistration registrationRequest: ASPasskeyCredentialRequest) {
        guard let identity = registrationRequest.credentialIdentity as? ASPasskeyCredentialIdentity,
              registrationRequest.supportedAlgorithms.isEmpty || registrationRequest.supportedAlgorithms.contains(.ES256),
              let session = Self.backgroundSession() else { return cancel(.failed) }
        do {
            let result = try session.conditionalPasskeyRegistration(request: PasskeyCreationRequest(
                rpId: identity.relyingPartyIdentifier, userName: identity.userName,
                userHandle: identity.userHandle, clientDataHash: registrationRequest.clientDataHash,
                userVerified: false, itemId: nil, excludedCredentials: []))
            Self.log.notice("passkey conditionnelle créée pour \(identity.relyingPartyIdentifier, privacy: .public)")
            extensionContext.completeRegistrationRequest(using: ASPasskeyRegistrationCredential(
                relyingParty: identity.relyingPartyIdentifier, clientDataHash: registrationRequest.clientDataHash,
                credentialID: Data(result.credentialId), attestationObject: Data(result.attestationObject)))
        } catch {
            Self.log.notice("passkey conditionnelle refusée : \(String(describing: error), privacy: .public)")
            cancel(.failed)
        }
    }

    // MARK: Signaux des sites (iOS 26)

    // Un site informe le fournisseur (`ASCredentialUpdater`) : l'extension,
    // lancée en arrière-plan, note le signal sans interface ni coffre ouvert
    // (`signals.rs`). Les suggestions du système en tiennent compte à la
    // prochaine publication, et l'audit de l'app les montre ; rien n'est
    // supprimé du coffre automatiquement.

    override func reportPublicKeyCredentialUpdate(forRelyingParty relyingParty: String, userHandle: Data, newName: String) {
        record(.passkeyRenamed(rpId: relyingParty, userHandle: userHandle, name: newName))
    }

    override func reportUnknownPublicKeyCredential(forRelyingParty relyingParty: String, credentialID: Data) {
        record(.unknownPasskey(rpId: relyingParty, credentialId: credentialID))
    }

    override func reportAllAcceptedPublicKeyCredentials(forRelyingParty relyingParty: String, userHandle: Data,
                                                        acceptedCredentialIDs: [Data]) {
        record(.acceptedPasskeys(rpId: relyingParty, userHandle: userHandle, accepted: acceptedCredentialIDs))
    }

    override func reportUnusedPasswordCredential(forDomain domain: String, userName: String) {
        record(.unusedPassword(domain: domain, userName: userName))
    }

    private func record(_ signal: CredentialSignal) {
        do {
            guard let session = Self.backgroundSession() else { return }
            try session.recordCredentialSignal(signal: signal)
            Self.log.notice("signal du site noté")
        } catch {
            Self.log.error("signal du site non noté : \(String(describing: error), privacy: .public)")
        }
    }

    /// Le dossier du compte, sans ouvrir le coffre (demandes d'arrière-plan).
    private static func backgroundSession() -> VaultSession? {
        let location = VerrouStorage.accountLocation()
        guard location.shared else { return nil }
        return VaultSession.forAutofill(dataDir: location.directory.path)
    }

    private static let log = Logger(subsystem: "app.verrou.autofill", category: "extension")

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
