import CloudKit
import CryptoKit
import LocalAuthentication
import Observation
import os
import SwiftUI
import UIKit

/// The iPhone side of approving from the iPhone (`RemoteApproval`,
/// `RemoteCloud`): pairing with a Mac by its QR code, then the Mac's
/// requests, read and answered after Face ID.
///
/// The key lives in the Secure Enclave and only works after Face ID
/// (`.biometryCurrentSet`: enrolling another face invalidates it, pair
/// again). Nothing of a request is shown before Face ID: the notification
/// says "a request from your Mac", the Mac's signature is checked, then Face
/// ID opens the content. The vault of the iPhone has nothing to do with it:
/// it may stay locked.
@MainActor
@Observable
final class RemoteApprover {
    struct Mac: Codable, Identifiable, Equatable {
        let id: String
        let name: String
        /// The key the Mac signs its requests with (x9.63).
        let key: Data
        let paired: Date
    }

    private struct Stored: Codable {
        let phone: String
        /// The Secure Enclave key (opaque, usable on this iPhone only).
        let enclaveKey: Data
        var macs: [Mac]
    }

    /// A request shown to the user.
    struct Pending: Identifiable {
        enum State {
            /// Signature checked, content still sealed: Face ID opens it.
            case sealed
            case ready(RemoteApproval.Opened)
            case sending
            case answered(Bool)
            case failed(String)
        }

        let id: String
        let sealed: RemoteApproval.Sealed
        let mac: Mac
        var state: State = .sealed
    }

    /// Face ID stays valid this long while the app is in the foreground: the
    /// unlock and the secret that follows it ask for one Face ID.
    static let contextReuse: TimeInterval = 60

    private(set) var macs: [Mac] = []
    private(set) var current: Pending?
    /// Requests waiting behind the current one.
    private(set) var queue: [Pending] = []
    private(set) var pairingBusy = false
    /// Push notifications: nil while unknown, otherwise ready or the error.
    private(set) var pushStatus: Result<Void, Error>?
    @ObservationIgnored private var subscribed = false

    @ObservationIgnored private var stored: Stored?
    @ObservationIgnored private var context: (LAContext, Date)?
    @ObservationIgnored private var refreshing = false
    /// A check of the requests is due (launch, return to the foreground):
    /// set at once, before its task starts, for `allowsVaultPrompt`.
    @ObservationIgnored private var checkDue = false
    /// After an answer: the next request (the secret after an unlock)
    /// comes a second later, while iCloud's notification may not.
    @ObservationIgnored private var followUp: Task<Void, Never>?
    static let followUpWindow: Duration = .seconds(20)
    @ObservationIgnored private var refreshAgain = false
    /// Answered or refused here: not shown again if the Mac hasn't erased it
    /// yet.
    @ObservationIgnored private var handled: Set<String> = []
    @ObservationIgnored private lazy var presenter = ApprovalWindow(approver: self)
    private let log = Logger(subsystem: "app.verrou", category: "remote-approval")

    private static var file: URL {
        let directory = URL.applicationSupportDirectory
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appending(path: "remote-approval.json")
    }

    init() {
        if let data = try? Data(contentsOf: Self.file), let stored = try? JSONDecoder().decode(Stored.self, from: data) {
            self.stored = stored
            macs = stored.macs
        }
        // Opened for a request: known before the vault asks for Face ID.
        if !macs.isEmpty {
            checkDue = true
            Task { await refresh() }
        }
    }

    /// The vault's own Face ID, at launch or on return: not when the app
    /// opens for a request of the Mac (one Face ID, the request's). Waits
    /// for the check of the requests 1.5 s at most (an iCloud fetch; a
    /// few hundred milliseconds usually).
    func allowsVaultPrompt() async -> Bool {
        guard isPaired else { return true }
        let deadline = ContinuousClock.now + .milliseconds(1500)
        while refreshing || checkDue, current == nil, ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(20))
        }
        return current == nil
    }

    var isPaired: Bool { !macs.isEmpty }

    private func persist(_ value: Stored) throws {
        let data = try JSONEncoder().encode(value)
        try data.write(to: Self.file, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        stored = value
        macs = value.macs
    }

    // MARK: Pairing

    enum PairingError: LocalizedError {
        case noBiometrics
        case noAccount

        var errorDescription: String? {
            switch self {
            case .noBiometrics: String(localized: "Face ID must be set up on this iPhone: it approves each request.")
            case .noAccount: String(localized: "Sign in to iCloud on this iPhone (the same account as the Mac).")
            }
        }
    }

    /// The Mac's QR code: the iPhone answers with its key, authenticated by
    /// the code's secret.
    func pair(qrText: String) async throws -> String {
        let invite = try RemoteApproval.Invite(qrText: qrText)
        pairingBusy = true
        defer { pairingBusy = false }
        guard LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else {
            throw PairingError.noBiometrics
        }
        guard await RemoteCloud.accountAvailable() else { throw PairingError.noAccount }
        var identity = try identity()
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: identity.enclaveKey)
        try await RemoteCloud.ensureZone(RemoteCloud.zone(phone: identity.phone))
        try await subscribe(identity.phone)
        let offer = RemoteApproval.Offer(phone: identity.phone, name: UIDevice.current.name,
                                         key: key.publicKey.x963Representation)
        let (payload, proof) = try RemoteApproval.sealOffer(offer, for: invite)
        try await RemoteCloud.ensureZone(RemoteCloud.pairingZone)
        try await RemoteCloud.save([RemoteCloud.pairingRecord(payload: payload, proof: proof, name: invite.answerName)])
        identity.macs.removeAll { $0.id == invite.mac }
        identity.macs.append(Mac(id: invite.mac, name: invite.name, key: invite.key, paired: Date()))
        try persist(identity)
        _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
        UIApplication.shared.registerForRemoteNotifications()
        log.notice("paired with a Mac")
        return invite.name
    }

    /// The phone's identifier and Secure Enclave key, created once.
    private func identity() throws -> Stored {
        if let stored { return stored }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                           [.privateKeyUsage, .biometryCurrentSet], &error) else {
            throw error!.takeRetainedValue() as Error
        }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(compactRepresentable: false, accessControl: access)
        let created = Stored(phone: UUID().uuidString, enclaveKey: key.dataRepresentation, macs: [])
        try persist(created)
        return created
    }

    /// The subscription, saved again at each launch (its text follows the
    /// iPhone's language).
    private func subscribe(_ phone: String) async throws {
        do {
            try await RemoteCloud.subscribeToRequests(phone: phone, title: String(localized: "remote.approval.title"),
                                                      body: String(localized: "remote.approval.body"))
            subscribed = true
        } catch {
            pushStatus = .failure(error)
            log.error("subscription not saved: \(error.localizedDescription, privacy: .public)")
            throw error
        }
    }

    /// The system's answer to `registerForRemoteNotifications`.
    func pushRegistered(_ error: Error?) {
        if let error {
            pushStatus = .failure(error)
            log.error("push registration failed: \(error.localizedDescription, privacy: .public)")
        } else if subscribed || pushStatus == nil {
            pushStatus = .success(())
        }
    }

    func remove(_ mac: Mac) {
        guard var identity = stored else { return }
        identity.macs.removeAll { $0.id == mac.id }
        try? persist(identity)
        if identity.macs.isEmpty {
            Task { await RemoteCloud.unsubscribe(["requests-\(identity.phone)"]) }
        }
    }

    // MARK: Requests

    /// Notification, or app back in the foreground: the waiting requests.
    func refresh() async {
        guard let stored, !stored.macs.isEmpty else { return }
        guard !refreshing else {
            refreshAgain = true
            return
        }
        refreshing = true
        defer {
            refreshing = false
            checkDue = false
        }
        repeat {
            refreshAgain = false
            guard let records = try? await RemoteCloud.all(in: RemoteCloud.zone(phone: stored.phone)) else { return }
            let answered = Set(records.filter { $0.recordType == RemoteCloud.RecordType.response }
                .map { $0.recordID.recordName })
            var found: [Pending] = []
            for record in records {
                guard let sealed = RemoteCloud.sealed(from: record), !handled.contains(sealed.id),
                      !answered.contains("answer-\(sealed.id)"),
                      let mac = stored.macs.first(where: { $0.id == sealed.mac }),
                      let macKey = try? P256.Signing.PublicKey(x963Representation: mac.key),
                      (try? RemoteApproval.verify(sealed, macKey: macKey)) != nil else { continue }
                found.append(Pending(id: sealed.id, sealed: sealed, mac: mac))
            }
            found.sort { $0.sealed.expires < $1.sealed.expires }
            let ids = Set(found.map(\.id))
            // Withdrawn by the Mac (Touch ID answered there) or expired.
            if let current, !ids.contains(current.id), case .sealed = current.state { self.current = nil }
            if let current, !ids.contains(current.id), case .ready = current.state { self.current = nil }
            queue = found.filter { $0.id != current?.id }
            if current == nil, !queue.isEmpty { current = queue.removeFirst() }
        } while refreshAgain
        presenter.update()
    }

    /// Face ID, then the content. Within `contextReuse` of the last Face
    /// ID, in the foreground: opened right away.
    func open() async {
        guard let pending = current, case .sealed = pending.state, let stored else { return }
        do {
            let context = try await authenticatedContext(reason: String(localized: "see the request from “\(pending.mac.name)”"))
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: stored.enclaveKey,
                                                                     authenticationContext: context)
            let macKey = try P256.Signing.PublicKey(x963Representation: pending.mac.key)
            let opened = try RemoteApproval.open(pending.sealed, macKey: macKey, with: key)
            update(pending.id) { $0.state = .ready(opened) }
        } catch let error as LAError where error.code == .userCancel || error.code == .appCancel || error.code == .systemCancel {
            return
        } catch {
            update(pending.id) { $0.state = .failed(Self.describe(error)) }
        }
    }

    /// The answer, sealed for the Mac. An approved unlock carries K, opened
    /// with the same Face ID.
    func answer(approved: Bool) async {
        guard let pending = current, case .ready(let opened) = pending.state, let stored else { return }
        // Handled from now on: a check running meanwhile mustn't show it
        // again (it would be answered twice, the next one never).
        handled.insert(pending.id)
        update(pending.id) { $0.state = .sending }
        do {
            var k: Data?
            if approved, let escrow = opened.request.escrow {
                let context = try await authenticatedContext(reason: String(localized: "unlock the vault on “\(pending.mac.name)”"))
                let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: stored.enclaveKey,
                                                                         authenticationContext: context)
                k = try RemoteApproval.openEscrow(escrow, mac: pending.mac.id, with: key)
            }
            let box = try RemoteApproval.answer(opened, approved: approved, key: k)
            try await RemoteCloud.save([RemoteCloud.response(box, request: pending.id, phone: stored.phone)])
            update(pending.id) { $0.state = .answered(approved) }
            watchForNext()
            try? await Task.sleep(for: .milliseconds(700))
            next()
        } catch {
            handled.remove(pending.id)
            update(pending.id) { $0.state = .failed(Self.describe(error)) }
        }
    }

    /// Closes the current request (refused by default on the Mac when it
    /// expires) and shows the next one.
    func dismiss() {
        if let current { handled.insert(current.id) }
        next()
    }

    /// Every second for `followUpWindow`, in the foreground, while no
    /// request is shown: the one that follows is fetched without waiting
    /// for its notification.
    private func watchForNext() {
        followUp?.cancel()
        followUp = Task { [weak self] in
            let end = ContinuousClock.now + Self.followUpWindow
            while !Task.isCancelled, ContinuousClock.now < end {
                try? await Task.sleep(for: .seconds(1))
                guard let self, UIApplication.shared.applicationState == .active else { return }
                if self.current == nil || self.isAnswered { await self.refresh() }
            }
        }
    }

    /// The request shown is already answered (its check mark).
    private var isAnswered: Bool {
        if case .answered? = current?.state { return true }
        return false
    }

    private func next() {
        // A queue made before an answer may still hold it.
        queue.removeAll { handled.contains($0.id) }
        current = queue.isEmpty ? nil : queue.removeFirst()
        presenter.update()
    }

    private func update(_ id: String, _ change: (inout Pending) -> Void) {
        guard var pending = current, pending.id == id else { return }
        change(&pending)
        current = pending
    }

    /// The app leaves the foreground: Face ID will be asked again, the
    /// content is sealed again.
    func sceneChanged(to phase: ScenePhase) {
        switch phase {
        case .background:
            followUp?.cancel()
            context?.0.invalidate()
            context = nil
            if var pending = current, case .ready = pending.state {
                pending.state = .sealed
                current = pending
            }
            presenter.update()
        case .active:
            // iCloud's notifications reach the app once registered (each
            // launch: the system keeps the token).
            if isPaired {
                checkDue = true
                UIApplication.shared.registerForRemoteNotifications()
                if !subscribed, let phone = stored?.phone {
                    Task { try? await subscribe(phone) }
                }
            }
            Task { await refresh() }
        default:
            break
        }
    }

    private func authenticatedContext(reason: String) async throws -> LAContext {
        if let (context, at) = context, Date().timeIntervalSince(at) < Self.contextReuse { return context }
        let context = LAContext()
        context.localizedFallbackTitle = ""
        try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        self.context = (context, Date())
        return context
    }

    static func describe(_ error: Error) -> String {
        switch error {
        case RemoteApproval.Failure.expired: String(localized: "This request has expired.")
        case RemoteApproval.Failure.wrongVersion: String(localized: "Update Verrou on the iPhone and on the Mac.")
        case RemoteApproval.Failure.unreadable:
            String(localized: "Unreadable request: Face ID changed since pairing? Pair this iPhone again.")
        case RemoteApproval.Failure.malformed: String(localized: "This is not a Verrou pairing code.")
        default: error.localizedDescription
        }
    }
}

extension RemoteApproval.Request {
    /// "read “GitHub”", in the request's words.
    var action: String {
        switch purpose {
        case "unlock" where title.isEmpty: String(localized: "unlock the vault")
        case "unlock" where field == "totp": String(localized: "unlock the vault and get the code of “\(title)”")
        case "unlock" where field == "password": String(localized: "unlock the vault and read the password of “\(title)”")
        case "unlock": String(localized: "unlock the vault and read “\(field ?? "")” in “\(title)”")
        case "reveal": String(localized: "read “\(title)”")
        case "ssh": String(localized: "use the SSH key “\(title)”")
        case "gitSign": String(localized: "sign a git commit with the key “\(title)”")
        case "passkey": String(localized: "use a passkey for “\(title)”")
        case "linkSite": String(localized: "link the site \(site) to “\(title)”")
        case "card": String(localized: "fill the card “\(title)”")
        case "bulk": String(localized: "release one more item: “\(title)”")
        default: String(localized: "access “\(title)”")
        }
    }
}

/// The approval screen, in its own window above everything (lock screen,
/// sheets): a request may arrive at any time.
@MainActor
private final class ApprovalWindow {
    private weak var approver: RemoteApprover?
    private var window: UIWindow?

    init(approver: RemoteApprover) {
        self.approver = approver
    }

    func update() {
        guard let approver else { return }
        if approver.current == nil {
            window?.isHidden = true
            window = nil
            return
        }
        guard window == nil,
              let scene = UIApplication.shared.connectedScenes
                .compactMap({ $0 as? UIWindowScene })
                .first(where: { $0.activationState != .unattached }) else { return }
        let window = UIWindow(windowScene: scene)
        window.windowLevel = .alert
        let host = UIHostingController(rootView: ApprovalScreen(approver: approver))
        host.view.backgroundColor = .clear
        window.rootViewController = host
        window.makeKeyAndVisible()
        self.window = window
    }
}
