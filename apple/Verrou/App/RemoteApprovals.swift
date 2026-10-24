import AppKit
import CloudKit
import CoreGraphics
import CryptoKit
import LocalAuthentication
import Observation
import os

/// Approving the terminal's requests from the iPhone, when you are away from
/// the Mac (protocol: `RemoteApproval`, transport: `RemoteCloud`, see
/// SECURITY.md, "Approving from the iPhone").
///
/// - **Pairing**: Touch ID (or the session password), then a QR code to scan
///   with Verrou on the iPhone. Paired iPhones are kept in
///   `remote-approval.json` (their public keys), next to the Mac's Secure
///   Enclave key that signs the requests (usable only on this Mac).
/// - **Who answers**: at the Mac (activity in the last minute, screen
///   unlocked), Touch ID as before, and the iPhone after 15 s without an
///   answer; away (screen locked or idle), the iPhone right away. The first
///   answer wins, the other request is withdrawn.
/// - **Unlock**: at each unlock on the Mac (password, Touch ID, security
///   key), the vault key is sealed with a key K and K for each iPhone
///   (`RemoteApproval.escrow`), for 12 hours; kept on disk sealed by the
///   Mac's Secure Enclave, so that an update of Verrou doesn't end it. The terminal
///   finding the vault locked while you are away: the iPhone returns K, the
///   vault opens for the terminal only (the window stays locked) and locks
///   again 5 minutes after the last approval.
@MainActor
@Observable
final class RemoteApprovals {
    struct Phone: Codable, Identifiable, Equatable {
        let id: String
        let name: String
        /// Public key of its Secure Enclave key (x9.63).
        let key: Data
        let paired: Date
    }

    private struct Stored: Codable {
        /// 2: signing key usable with the screen locked (1 wasn't: pair
        /// again).
        static let current = 2
        var version: Int?
        let mac: String
        /// The Secure Enclave signing key (opaque, usable on this Mac only).
        let signingKey: Data
        var phones: [Phone]
        /// Secure Enclave key that seals the escrow on disk
        /// (`remote-escrow.json`); made at the first escrow.
        var sealingKey: Data?
    }

    /// The escrow as kept on disk, sealed by the Mac's Secure Enclave.
    private struct EscrowFile: Codable {
        let box: Data
        let escrows: [String: RemoteApproval.Escrow]
        let until: Date
    }

    private struct SealedFile: Codable {
        let ephemeral: Data
        let box: Data
    }

    enum PairingState: Equatable {
        case waiting
        case failed(String)
    }

    struct Pairing: Equatable {
        let invite: RemoteApproval.Invite
        var state: PairingState = .waiting
    }

    /// Unlock from the iPhone: how long after the last unlock on the Mac.
    static let escrowLifetime: TimeInterval = 12 * 3600
    /// The vault opened by the iPhone locks again this long after the last
    /// approval.
    static let remoteSessionLifetime: TimeInterval = 5 * 60
    /// At the Mac: the iPhone is asked after this long without an answer.
    static let localHeadStart: Duration = .seconds(15)
    /// Away: no keyboard or mouse for this long.
    static let idleThreshold: TimeInterval = 60
    static let unlockKey = "remoteUnlock"

    private(set) var phones: [Phone] = []
    private(set) var pairing: Pairing?
    private(set) var available = false
    /// Why the feature can't be used (no iCloud, ad hoc build…).
    private(set) var unavailableReason: String?
    /// Unlock from the iPhone (the escrow): on by default once an iPhone is
    /// paired.
    var unlockEnabled: Bool = UserDefaults.standard.object(forKey: RemoteApprovals.unlockKey) as? Bool ?? true {
        didSet {
            UserDefaults.standard.set(unlockEnabled, forKey: Self.unlockKey)
            if unlockEnabled { escrowNeeded?() } else { clearEscrow() }
        }
    }
    /// End of the unlock from the iPhone (nil: none prepared).
    private(set) var escrowUntil: Date?
    /// The iPhones changed: the app seals the vault key again if it is open
    /// on the Mac (`AppModel.prepareRemoteEscrow`).
    @ObservationIgnored var escrowNeeded: (() -> Void)?

    @ObservationIgnored private let file: URL
    @ObservationIgnored private let escrowFile: URL
    @ObservationIgnored private var stored: Stored?
    @ObservationIgnored private var vault: RemoteApproval.Vault?
    @ObservationIgnored private var pairingTask: Task<Void, Never>?
    /// An answer arrived (silent notification): fetch without waiting.
    @ObservationIgnored private var poked = false
    @ObservationIgnored private var screenLocked = false
    @ObservationIgnored private var observers: [NSObjectProtocol] = []
    @ObservationIgnored private var deciding: [String: Task<Outcome, Never>] = [:]
    private let log = Logger(subsystem: "app.verrou", category: "remote-approval")

    init(directory: URL) {
        file = directory.appending(path: "remote-approval.json")
        escrowFile = directory.appending(path: "remote-escrow.json")
        if let data = try? Data(contentsOf: file), let stored = try? JSONDecoder().decode(Stored.self, from: data),
           stored.version == Stored.current {
            self.stored = stored
            phones = stored.phones
        }
        loadEscrow()
        let center = DistributedNotificationCenter.default()
        observers.append(center.addObserver(forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.screenLocked = true }
        })
        observers.append(center.addObserver(forName: .init("com.apple.screenIsUnlocked"), object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.screenLocked = false }
        })
        Task { await refreshAvailability() }
    }

    /// iCloud entitlement (team-signed build) and iCloud account.
    func refreshAvailability() async {
        guard RemoteCloud.isEntitled else {
            available = false
            unavailableReason = String(localized: "Needs the Verrou signed by its developer (the iCloud entitlement): this build is signed locally.")
            return
        }
        guard SecureEnclave.isAvailable else {
            available = false
            unavailableReason = String(localized: "This Mac has no Secure Enclave.")
            return
        }
        guard await RemoteCloud.accountAvailable() else {
            available = false
            unavailableReason = String(localized: "Sign in to iCloud on this Mac (the same account as the iPhone).")
            return
        }
        available = true
        unavailableReason = nil
        if !phones.isEmpty { NSApp.registerForRemoteNotifications() }
    }

    var isReady: Bool { available && !phones.isEmpty }

    // MARK: Identity

    /// The signing key works with the screen locked (that is when the
    /// iPhone is asked); it never leaves this Mac and opens nothing.
    private func identity() throws -> Stored {
        if let stored, stored.version == Stored.current { return stored }
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            accessControl: SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                                           .privateKeyUsage, nil)!)
        let created = Stored(version: Stored.current, mac: UUID().uuidString, signingKey: key.dataRepresentation, phones: [])
        try persist(created)
        return created
    }

    private func signer() throws -> SecureEnclave.P256.Signing.PrivateKey {
        try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: identity().signingKey)
    }

    private func persist(_ value: Stored) throws {
        let data = try JSONEncoder().encode(value)
        try data.write(to: file, options: .atomic)
        stored = value
        phones = value.phones
    }

    // MARK: Pairing

    /// Touch ID first: pairing gives an iPhone the power to approve.
    func startPairing() async {
        guard available, pairing == nil else { return }
        guard await Biometrics.confirm(reason: String(localized: "pair an iPhone to approve the terminal's requests")) else { return }
        do {
            let identity = try identity()
            let key = try signer().publicKey.x963Representation
            var secret = Data(count: 32)
            guard secret.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else {
                throw RemoteApproval.Failure.malformed
            }
            let invite = RemoteApproval.Invite(mac: identity.mac, name: Host.current().localizedName ?? "Mac",
                                               key: key, secret: secret)
            try await RemoteCloud.ensureZone(RemoteCloud.pairingZone)
            pairing = Pairing(invite: invite)
            pairingTask = Task { await waitForPhone(invite) }
        } catch {
            pairing = Pairing(invite: RemoteApproval.Invite(mac: "", name: "", key: Data(), secret: Data()),
                              state: .failed(Self.describe(error)))
        }
    }

    func cancelPairing() {
        pairingTask?.cancel()
        pairingTask = nil
        pairing = nil
    }

    /// The iPhone's answer, in the pairing zone, for 5 minutes.
    private func waitForPhone(_ invite: RemoteApproval.Invite) async {
        let id = CKRecord.ID(recordName: invite.answerName, zoneID: RemoteCloud.pairingZone)
        let deadline = Date().addingTimeInterval(300)
        while !Task.isCancelled, Date() < deadline {
            if let record = try? await RemoteCloud.fetch([id])[id] {
                await RemoteCloud.delete([id])
                do {
                    guard let payload = record["payload"] as? Data, let proof = record["proof"] as? Data else {
                        throw RemoteApproval.Failure.malformed
                    }
                    let offer = try RemoteApproval.openOffer(payload: payload, proof: proof, for: invite)
                    try await add(offer)
                    pairing = nil
                } catch {
                    pairing?.state = .failed(Self.describe(error))
                }
                return
            }
            try? await Task.sleep(for: .seconds(1))
        }
        if !Task.isCancelled { pairing?.state = .failed(String(localized: "No iPhone answered in 5 minutes.")) }
    }

    private func add(_ offer: RemoteApproval.Offer) async throws {
        var identity = try identity()
        identity.phones.removeAll { $0.id == offer.phone }
        identity.phones.append(Phone(id: offer.phone, name: offer.name, key: offer.key, paired: Date()))
        try persist(identity)
        try await RemoteCloud.subscribeToResponses(phone: offer.phone)
        NSApp.registerForRemoteNotifications()
        // The escrow now covers the new iPhone too.
        clearEscrow()
        escrowNeeded?()
        log.notice("iPhone paired")
    }

    func remove(_ phone: Phone) {
        guard var identity = stored else { return }
        identity.phones.removeAll { $0.id == phone.id }
        try? persist(identity)
        clearEscrow()
        Task { await RemoteCloud.unsubscribe(["responses-\(phone.id)"]) }
    }

    // MARK: Unlock from the iPhone

    /// After an unlock: the vault key sealed for the iPhones. `local`: on the
    /// Mac (12 more hours); otherwise the iPhone's (same end, new K).
    func prepareEscrow(userKey: String, local: Bool) {
        guard unlockEnabled, isReady, let mac = stored?.mac else {
            log.notice("no unlock from the iPhone (setting \(self.unlockEnabled), ready \(self.isReady))")
            return
        }
        let keys = phones.reduce(into: [String: P256.KeyAgreement.PublicKey]()) { keys, phone in
            keys[phone.id] = try? P256.KeyAgreement.PublicKey(x963Representation: phone.key)
        }
        guard let vault = try? RemoteApproval.escrow(userKey: userKey, mac: mac, phones: keys) else { return }
        self.vault = vault
        log.notice("unlock from the iPhone prepared for \(vault.escrows.count) iPhone(s)")
        if local || escrowUntil == nil { escrowUntil = Date().addingTimeInterval(Self.escrowLifetime) }
        saveEscrow()
    }

    func clearEscrow() {
        vault = nil
        escrowUntil = nil
        try? FileManager.default.removeItem(at: escrowFile)
    }

    // MARK: Escrow on disk

    /// The escrow survives a restart of Verrou (an update), until its
    /// end: both boxes, sealed again by a Secure Enclave key of this Mac
    /// (no biometrics, after the first login). Without the iPhone they
    /// open nothing: K only comes out of it, after Face ID.
    private func saveEscrow() {
        guard let vault, let escrowUntil, var identity = stored else { return }
        do {
            let key: SecureEnclave.P256.KeyAgreement.PrivateKey
            if let data = identity.sealingKey {
                key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: data)
            } else {
                key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                    accessControl: SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                                                   .privateKeyUsage, nil)!)
                identity.sealingKey = key.dataRepresentation
                try persist(identity)
            }
            let plain = try JSONEncoder().encode(EscrowFile(box: vault.box, escrows: vault.escrows, until: escrowUntil))
            let ephemeral = P256.KeyAgreement.PrivateKey()
            let box = try AES.GCM.seal(plain, using: Self.fileKey(try ephemeral.sharedSecretFromKeyAgreement(with: key.publicKey),
                                                                  mac: identity.mac),
                                       authenticating: Data(identity.mac.utf8)).combined ?? Data()
            let sealed = try JSONEncoder().encode(SealedFile(ephemeral: ephemeral.publicKey.x963Representation, box: box))
            try sealed.write(to: escrowFile, options: .atomic)
        } catch {
            log.error("escrow not saved: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// At launch: the escrow left by the previous run, if it is still
    /// valid and made for the iPhones paired now.
    private func loadEscrow() {
        guard let identity = stored, let keyData = identity.sealingKey,
              let data = try? Data(contentsOf: escrowFile) else { return }
        do {
            let sealed = try JSONDecoder().decode(SealedFile.self, from: data)
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyData)
            let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: sealed.ephemeral)
            let plain = try AES.GCM.open(AES.GCM.SealedBox(combined: sealed.box),
                                         using: Self.fileKey(try key.sharedSecretFromKeyAgreement(with: ephemeral),
                                                             mac: identity.mac),
                                         authenticating: Data(identity.mac.utf8))
            let file = try JSONDecoder().decode(EscrowFile.self, from: plain)
            guard file.until > Date(), Set(file.escrows.keys) == Set(phones.map(\.id)) else {
                clearEscrow()
                return
            }
            vault = RemoteApproval.Vault(box: file.box, escrows: file.escrows)
            escrowUntil = file.until
            log.notice("unlock from the iPhone kept from the previous launch")
        } catch {
            log.error("escrow unreadable: \(error.localizedDescription, privacy: .public)")
            clearEscrow()
        }
    }

    private static func fileKey(_ secret: SharedSecret, mac: String) -> SymmetricKey {
        secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(mac.utf8),
                                       sharedInfo: Data("verrou.remote.escrow-file.v1".utf8), outputByteCount: 32)
    }

    var canUnlock: Bool {
        guard unlockEnabled, isReady, vault != nil, let escrowUntil else { return false }
        return escrowUntil > Date()
    }

    /// The vault key, if the iPhone approves.
    func unlock(client: String, reason: String) async -> String? {
        guard canUnlock, let vault, let mac = stored?.mac else { return nil }
        let response = await ask(kind: .unlock, client: client, purpose: "unlock", title: "", site: "",
                                 reason: reason, lifetime: RemoteApproval.unlockLifetime, escrows: vault.escrows)
        guard let response, response.approved, let key = response.key else { return nil }
        return try? RemoteApproval.openVault(vault, key: key, mac: mac)
    }

    // MARK: Approvals

    /// Away from the Mac: screen locked, or no input for a minute.
    var isAway: Bool {
        if isScreenLocked { return true }
        let idle = CGEventSource.secondsSinceLastEventType(.combinedSessionState,
                                                           eventType: CGEventType(rawValue: ~0)!)
        return idle >= Self.idleThreshold
    }

    /// The notification, or the session's state (a notification missed
    /// while the app was busy).
    private var isScreenLocked: Bool {
        if screenLocked { return true }
        guard let session = CGSessionCopyCurrentDictionary() as? [String: Any] else { return false }
        return session["CGSSessionScreenIsLocked"] as? Bool == true
    }

    enum Outcome {
        case local(Bool)
        case remote(Bool)

        var approved: Bool {
            switch self {
            case .local(let value), .remote(let value): value
            }
        }
    }

    /// Touch ID on the Mac, the iPhone, or both: the first answer decides.
    /// `local` gets an `LAContext` that is invalidated if the iPhone answers
    /// first.
    func decide(client: String, purpose: String, title: String, site: String, reason: String,
                local: @escaping @MainActor (LAContext) async -> Bool) async -> Outcome {
        // The bridge may ask the same thing twice in a row: one request, one
        // answer for both.
        let key = [client, purpose, title, site, reason].joined(separator: "\u{1F}")
        if let running = deciding[key] { return await running.value }
        let task = Task {
            await decideOnce(client: client, purpose: purpose, title: title, site: site, reason: reason, local: local)
        }
        deciding[key] = task
        defer { deciding[key] = nil }
        return await task.value
    }

    private func decideOnce(client: String, purpose: String, title: String, site: String, reason: String,
                            local: @escaping @MainActor (LAContext) async -> Bool) async -> Outcome {
        guard isReady else {
            log.notice("approval on the Mac only (available: \(self.available), iPhones: \(self.phones.count))")
            return .local(await local(LAContext()))
        }
        let away = isAway
        let locked = isScreenLocked
        log.notice("approval: away \(away), screen locked \(locked)")
        let context = LAContext()
        return await withCheckedContinuation { continuation in
            let race = Race(continuation)
            // Screen locked: no one to answer on the Mac.
            let localTask: Task<Void, Never>? = locked ? nil : Task {
                let approved = await local(context)
                self.log.notice("answered on the Mac: \(approved)")
                race.finish(.local(approved))
            }
            let remoteTask = Task {
                if !away {
                    try? await Task.sleep(for: Self.localHeadStart)
                    guard !Task.isCancelled else { return }
                }
                let response = await ask(kind: .access, client: client, purpose: purpose, title: title, site: site,
                                         reason: reason, lifetime: RemoteApproval.requestLifetime, escrows: [:])
                if let response {
                    race.finish(.remote(response.approved))
                } else if localTask == nil {
                    race.finish(.remote(false))
                }
            }
            race.onFinish = { outcome in
                switch outcome {
                case .remote:
                    context.invalidate()
                    // The master password window (protected item).
                    if NSApp.modalWindow != nil { NSApp.abortModal() }
                    localTask?.cancel()
                case .local:
                    remoteTask.cancel()
                }
            }
        }
    }

    /// The iPhone's answer for the Mac (nil: none in time, or withdrawn).
    private func ask(kind: RemoteApproval.Kind, client: String, purpose: String, title: String, site: String,
                     reason: String, lifetime: TimeInterval,
                     escrows: [String: RemoteApproval.Escrow]) async -> RemoteApproval.Response? {
        guard let mac = stored?.mac else { return nil }
        let signingKey: SecureEnclave.P256.Signing.PrivateKey
        do {
            signingKey = try signer()
        } catch {
            log.error("request not signed: \(error.localizedDescription, privacy: .public)")
            return nil
        }
        let id = "req-\(UUID().uuidString)"
        let expires = Date().addingTimeInterval(lifetime).wholeSeconds
        var waiting: [(phone: Phone, key: P256.KeyAgreement.PublicKey, ephemeral: P256.KeyAgreement.PrivateKey)] = []
        var records: [CKRecord] = []
        for phone in phones {
            guard let key = try? P256.KeyAgreement.PublicKey(x963Representation: phone.key) else { continue }
            if kind == .unlock, escrows[phone.id] == nil { continue }
            let request = RemoteApproval.Request(id: id, mac: mac, kind: kind, client: client, purpose: purpose,
                                                 title: title, site: site, expires: expires, escrow: escrows[phone.id],
                                                 reason: reason.isEmpty ? nil : reason)
            let sealed: RemoteApproval.Sealed, ephemeral: P256.KeyAgreement.PrivateKey
            do {
                (sealed, ephemeral) = try RemoteApproval.seal(request, to: key, signer: signingKey)
            } catch {
                log.error("request not sealed: \(error.localizedDescription, privacy: .public)")
                continue
            }
            records.append(RemoteCloud.record(sealed, phone: phone.id))
            waiting.append((phone, key, ephemeral))
        }
        guard !records.isEmpty else { return nil }
        let started = Date()
        let clock = ContinuousClock.now
        do {
            try await RemoteCloud.save(records)
        } catch {
            log.error("request not sent: \(error.localizedDescription, privacy: .public)")
            return nil
        }
        Perf.log.notice("iPhone request sent in \(Perf.ms(since: clock)) ms")
        let answers = waiting.map { RemoteCloud.responseID(request: id, phone: $0.phone.id) }
        defer {
            // Answered, withdrawn or expired: nothing stays in iCloud.
            let ids = records.map(\.recordID) + answers
            Task.detached { await RemoteCloud.delete(ids) }
        }
        // Every 250 ms for 20 s, then every second; right away on a
        // notification.
        var lastFetch = Date.distantPast
        while !Task.isCancelled, Date() < expires {
            let interval: TimeInterval = Date().timeIntervalSince(started) < 20 ? 0.25 : 1
            if poked || Date().timeIntervalSince(lastFetch) >= interval {
                poked = false
                lastFetch = Date()
                if let found = try? await RemoteCloud.fetch(answers) {
                    for entry in waiting {
                        guard let record = found[RemoteCloud.responseID(request: id, phone: entry.phone.id)] else { continue }
                        let response: RemoteApproval.Response
                        do {
                            guard let box = record["box"] as? Data else { throw RemoteApproval.Failure.malformed }
                            response = try RemoteApproval.read(answer: box, id: id, ephemeral: entry.ephemeral, phone: entry.key)
                        } catch {
                            log.error("unreadable answer from the iPhone: \(String(describing: error), privacy: .public)")
                            continue
                        }
                        Perf.log.notice("iPhone answered in \(Perf.ms(since: clock)) ms")
                        return response
                    }
                }
            }
            try? await Task.sleep(for: .milliseconds(50))
        }
        return nil
    }

    /// Silent notification: an answer is there.
    func poke() {
        poked = true
    }

    static func describe(_ error: Error) -> String {
        switch error {
        case RemoteApproval.Failure.badSignature: String(localized: "The iPhone's answer doesn't match this QR code.")
        case RemoteApproval.Failure.wrongVersion: String(localized: "Update Verrou on the iPhone and on the Mac.")
        case let error as CKError where error.code == .notAuthenticated:
            String(localized: "Sign in to iCloud on this Mac (the same account as the iPhone).")
        default: error.localizedDescription
        }
    }
}

/// The first of the two answers resumes the waiting request; the other one
/// is ignored.
@MainActor
private final class Race {
    private var continuation: CheckedContinuation<RemoteApprovals.Outcome, Never>?
    var onFinish: ((RemoteApprovals.Outcome) -> Void)?

    init(_ continuation: CheckedContinuation<RemoteApprovals.Outcome, Never>) {
        self.continuation = continuation
    }

    func finish(_ outcome: RemoteApprovals.Outcome) {
        guard let continuation else { return }
        self.continuation = nil
        onFinish?(outcome)
        onFinish = nil
        continuation.resume(returning: outcome)
    }
}
