#if os(macOS)
import AppKit
#endif
import AuthenticationServices
import os
import SwiftUI

/// Entry point of the AutoFill extension: the system calls it for a list
/// (keyboard, "Passwords" key), for a tapped suggestion (QuickType bar), for
/// a passkey or a code.
///
/// The same code serves the iPhone (`VerrouAutoFill`) and the Mac
/// (`VerrouAutoFillMac`): only the hosting of the SwiftUI interface changes
/// (`UIHostingController`, `NSHostingController`).
///
/// The vault is always locked when a request arrives (new process): the
/// "without interaction" requests hand control back to the system
/// (`userInteractionRequired`), which then shows the interface below, where
/// Face ID starts on its own.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private lazy var model = AutoFillModel { [weak self] completion in
        self?.complete(completion)
    }
    private var hosted = false

    #if os(macOS)
    /// No nib: the view is created here, at the size of the system's sheet.
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

    // Mac: Face ID as soon as the sheet is on screen. On the iPhone the
    // sheet only accepts it once its presentation ends (about 600 ms after
    // launch, measured): `AutoFillRootView`'s retries cover it.
    #if os(macOS)
    override func viewDidAppear() {
        super.viewDidAppear()
        Task { await model.autoUnlock(appeared: true) }
    }
    #endif

    // MARK: Lists

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

    // MARK: Tapped suggestion

    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        // The second step of a form (password after username): the login
        // filled a moment ago, without Face ID (`RecentFill`).
        if credentialRequest.type == .password,
           let id = credentialRequest.credentialIdentity.recordIdentifier,
           let recent = RecentFill.credential(for: id) {
            Self.log.notice("recent login filled again")
            return extensionContext.completeRequest(
                withSelectedCredential: ASPasswordCredential(user: recent.user, password: recent.password))
        }
        // Within 5 minutes of a Face ID (`AutofillSession`): straight away.
        // Otherwise, vault locked in this new process: Face ID is needed.
        Task {
            if let completion = await model.fillWithoutInteraction(credentialRequest) {
                complete(completion)
            } else {
                cancel(.userInteractionRequired)
            }
        }
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        model.start(.provide(credentialRequest))
    }

    // MARK: Passkey creation

    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        guard let request = registrationRequest as? ASPasskeyCredentialRequest else {
            return complete(.failed("invalid creation request"))
        }
        model.start(.register(request))
    }

    override func prepareInterfaceForExtensionConfiguration() {
        model.start(.none)
    }

    // MARK: Conditional creation (iOS 18)

    /// Safari requests a passkey in the background, right after a password
    /// filled by Verrou (`mediation: "conditional"`). No interface: the key
    /// prepared at fill time is used, if the site and the account are the
    /// same; otherwise a silent refusal. The passkey joins the item the next
    /// time the app opens (`conditional.rs`).
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
            Self.log.notice("conditional passkey created for \(identity.relyingPartyIdentifier, privacy: .public)")
            extensionContext.completeRegistrationRequest(using: ASPasskeyRegistrationCredential(
                relyingParty: identity.relyingPartyIdentifier, clientDataHash: registrationRequest.clientDataHash,
                credentialID: Data(result.credentialId), attestationObject: Data(result.attestationObject)))
        } catch {
            Self.log.notice("conditional passkey refused: \(String(describing: error), privacy: .public)")
            cancel(.failed)
        }
    }

    // MARK: Site signals (iOS 26)

    // A site informs the provider (`ASCredentialUpdater`): the extension,
    // launched in the background, records the signal without an interface
    // or an open vault (`signals.rs`). The system's suggestions take it into
    // account at the next publication, and the app's audit shows them;
    // nothing is removed from the vault automatically.

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
            Self.log.notice("site signal recorded")
        } catch {
            Self.log.error("site signal not recorded: \(String(describing: error), privacy: .public)")
        }
    }

    /// The account folder, without opening the vault (background requests).
    private static func backgroundSession() -> VaultSession? {
        let location = VerrouStorage.accountLocation()
        guard location.shared else { return nil }
        return VaultSession.forAutofill(dataDir: location.directory.path)
    }

    private static let log = Logger(subsystem: "app.verrou.autofill", category: "extension")

    // MARK: Response

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
