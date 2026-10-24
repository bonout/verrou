import CryptoKit
import Foundation

/// Approving the Mac's requests from the iPhone: a secret or an SSH
/// signature asked for by the terminal while you are away from the Mac, and
/// the unlock that goes before it. See SECURITY.md, "Approving from the
/// iPhone".
///
/// What crosses iCloud (CloudKit, private database: `RemoteCloud`) is
/// unreadable and unforgeable there:
/// - **pairing**: the Mac shows a QR code (its identifier, the public key it
///   signs requests with, a one-time secret); the iPhone answers in iCloud
///   with its public key, authenticated by an HMAC of that secret. Nobody
///   who didn't see the QR code can slip in a key;
/// - **request**: a P256 key agreement between a key the Mac draws for the
///   request and the iPhone's key, which lives in its Secure Enclave and
///   only works after Face ID. The content (terminal, item, kind) is sealed
///   with AES-GCM; the Mac signs the whole, the iPhone checks it before
///   showing anything;
/// - **response**: sealed with the other half of the same exchange: only the
///   iPhone's Secure Enclave, after Face ID, could have written it. It is
///   bound to the request (its identifier as associated data, and the key
///   drawn for it): replaying it elsewhere gives nothing;
/// - **unlock**: the Mac never sends the vault key. At each unlock on the
///   Mac, it seals the vault key with a key K it draws, seals K for the
///   iPhone, then forgets K: it keeps both boxes in memory only. The iPhone
///   returns K in an approved response; it never sees the vault key, and K
///   is useless without the box that stayed in the Mac's memory.
///
/// Every message carries `version`; a message of another version is
/// refused.
enum RemoteApproval {
    static let version = 1

    /// Time to answer a request (the bridge waits 90 s).
    static let requestLifetime: TimeInterval = 85
    /// Unlock: the terminal waits 60 s.
    static let unlockLifetime: TimeInterval = 55
    /// Clock gap tolerated between the Mac and the iPhone.
    static let clockSkew: TimeInterval = 30

    enum Failure: Error, Equatable {
        case malformed
        case badSignature
        case unreadable
        case expired
        case wrongVersion
        case mismatch
    }

    // MARK: Keys

    /// The iPhone's key: in its Secure Enclave on a device, a software key in
    /// the tests.
    protocol AgreementKey {
        var publicKey: P256.KeyAgreement.PublicKey { get }
        func sharedSecret(with publicKey: P256.KeyAgreement.PublicKey) throws -> SharedSecret
    }

    /// The Mac's key, which signs the requests: in its Secure Enclave
    /// (no biometrics: it signs without asking), software in the tests.
    protocol SigningKey {
        var publicKey: P256.Signing.PublicKey { get }
        func sign(_ data: Data) throws -> P256.Signing.ECDSASignature
    }

    // MARK: Pairing

    /// What the Mac's QR code carries.
    struct Invite: Codable, Equatable {
        var version = RemoteApproval.version
        /// The Mac's identifier (random).
        let mac: String
        /// Its name, to show ("MacBook Pro").
        let name: String
        /// Public key of the requests' signatures (x9.63).
        let key: Data
        /// One-time secret (32 bytes): authenticates the iPhone's answer.
        let secret: Data

        private static let prefix = "verrou-pair:"

        var qrText: String {
            let json = (try? JSONEncoder().encode(self)) ?? Data()
            return Self.prefix + json.base64URL
        }

        init(mac: String, name: String, key: Data, secret: Data) {
            self.mac = mac
            self.name = name
            self.key = key
            self.secret = secret
        }

        init(qrText: String) throws {
            guard qrText.hasPrefix(Self.prefix), qrText.utf8.count < 2048,
                  let json = Data(base64URL: String(qrText.dropFirst(Self.prefix.count))),
                  let invite = try? JSONDecoder().decode(Self.self, from: json) else { throw Failure.malformed }
            guard invite.version == RemoteApproval.version else { throw Failure.wrongVersion }
            guard invite.secret.count == 32, (try? P256.Signing.PublicKey(x963Representation: invite.key)) != nil,
                  !invite.mac.isEmpty else { throw Failure.malformed }
            self = invite
        }

        var signingKey: P256.Signing.PublicKey {
            get throws { try P256.Signing.PublicKey(x963Representation: key) }
        }

        /// Where the iPhone writes its answer: derived from the secret,
        /// unguessable without the QR code.
        var answerName: String {
            "pair-" + SHA256.hash(data: Data("verrou.remote.pair-name.v1".utf8) + secret).hex.prefix(32)
        }
    }

    /// The iPhone's answer to the QR code.
    struct Offer: Codable, Equatable {
        var version = RemoteApproval.version
        /// The iPhone's identifier (random): its iCloud zone is
        /// `approvals-<phone>`.
        let phone: String
        let name: String
        /// Public key of its Secure Enclave key (x9.63).
        let key: Data

        init(phone: String, name: String, key: Data) {
            self.phone = phone
            self.name = name
            self.key = key
        }
    }

    /// The offer, and its proof: HMAC-SHA256 with the QR code's secret.
    static func sealOffer(_ offer: Offer, for invite: Invite) throws -> (payload: Data, proof: Data) {
        let payload = try JSONEncoder().encode(offer)
        return (payload, Data(proof(payload, invite: invite)))
    }

    /// The Mac checks that the answer comes from whoever saw the QR code.
    static func openOffer(payload: Data, proof: Data, for invite: Invite) throws -> Offer {
        guard HMAC<SHA256>.isValidAuthenticationCode(proof, authenticating: transcript(payload, invite),
                                                     using: SymmetricKey(data: invite.secret)) else {
            throw Failure.badSignature
        }
        guard let offer = try? JSONDecoder().decode(Offer.self, from: payload) else { throw Failure.malformed }
        guard offer.version == version else { throw Failure.wrongVersion }
        guard !offer.phone.isEmpty, (try? P256.KeyAgreement.PublicKey(x963Representation: offer.key)) != nil else {
            throw Failure.malformed
        }
        return offer
    }

    private static func proof(_ payload: Data, invite: Invite) -> HashedAuthenticationCode<SHA256> {
        HMAC<SHA256>.authenticationCode(for: transcript(payload, invite), using: SymmetricKey(data: invite.secret))
    }

    private static func transcript(_ payload: Data, _ invite: Invite) -> Data {
        frame([Data("verrou.remote.pair.v1".utf8), Data(invite.mac.utf8), invite.key, payload])
    }

    // MARK: Requests

    enum Kind: String, Codable {
        /// A secret, an SSH or git signature: the terminal waits.
        case access
        /// Unlock the vault for the terminal (the window stays locked).
        case unlock
    }

    /// What the Mac asks, readable by the iPhone only.
    struct Request: Codable, Equatable {
        var version = RemoteApproval.version
        let id: String
        let mac: String
        let kind: Kind
        /// Who asks ("terminal", "Brave").
        let client: String
        /// The bridge's purpose (`reveal`, `ssh`, `gitSign`…), worded by the
        /// iPhone.
        let purpose: String
        /// The item's title (empty for an unlock).
        let title: String
        /// The site, for `linkSite`.
        let site: String
        /// Whole seconds: iCloud keeps dates to the millisecond.
        let expires: Date
        /// Unlock: K sealed for this iPhone.
        let escrow: Escrow?
        /// Why the terminal asks, as it declares it (`verrou --reason`);
        /// absent from older Macs.
        var reason: String? = nil
    }

    /// A request as it travels: the Mac's ephemeral public key, the sealed
    /// content, the Mac's signature over everything.
    struct Sealed: Equatable {
        let id: String
        let mac: String
        let ephemeral: Data
        let box: Data
        let expires: Date
        var signature: Data

        fileprivate var signed: Data {
            frame([Data("verrou.remote.request.v1".utf8), Data(id.utf8), Data(mac.utf8), ephemeral, box,
                   Data(String(expires.milliseconds).utf8)])
        }
    }

    /// The answer, readable by the Mac only.
    struct Response: Codable, Equatable {
        var version = RemoteApproval.version
        let id: String
        let approved: Bool
        /// Unlock approved: K (32 bytes).
        let key: Data?
    }

    /// Mac: seals a request for one iPhone. The ephemeral key is kept, in
    /// memory, to read the answer.
    static func seal(_ request: Request, to phone: P256.KeyAgreement.PublicKey,
                     signer: SigningKey) throws -> (Sealed, P256.KeyAgreement.PrivateKey) {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let keys = Keys(secret: try ephemeral.sharedSecretFromKeyAgreement(with: phone), id: request.id)
        let box = try AES.GCM.seal(JSONEncoder().encode(request), using: keys.request,
                                   authenticating: Data(request.id.utf8)).combined ?? Data()
        var sealed = Sealed(id: request.id, mac: request.mac, ephemeral: ephemeral.publicKey.x963Representation,
                            box: box, expires: request.expires, signature: Data())
        sealed.signature = try signer.sign(sealed.signed).derRepresentation
        return (sealed, ephemeral)
    }

    /// iPhone, before showing anything: does the request come from this Mac,
    /// and is it still valid? No Face ID needed.
    static func verify(_ sealed: Sealed, macKey: P256.Signing.PublicKey, now: Date = Date()) throws {
        guard let signature = try? P256.Signing.ECDSASignature(derRepresentation: sealed.signature),
              macKey.isValidSignature(signature, for: sealed.signed) else { throw Failure.badSignature }
        guard sealed.expires > now.addingTimeInterval(-clockSkew),
              sealed.expires < now.addingTimeInterval(unlockLifetime + requestLifetime + clockSkew) else {
            throw Failure.expired
        }
    }

    /// iPhone, after Face ID: one exchange with the Secure Enclave gives the
    /// keys of the request and of the answer.
    struct Opened {
        let request: Request
        fileprivate let keys: Keys
    }

    static func open(_ sealed: Sealed, macKey: P256.Signing.PublicKey, with key: AgreementKey,
                     now: Date = Date()) throws -> Opened {
        try verify(sealed, macKey: macKey, now: now)
        guard let ephemeral = try? P256.KeyAgreement.PublicKey(x963Representation: sealed.ephemeral) else {
            throw Failure.malformed
        }
        let keys = Keys(secret: try key.sharedSecret(with: ephemeral), id: sealed.id)
        guard let box = try? AES.GCM.SealedBox(combined: sealed.box),
              let json = try? AES.GCM.open(box, using: keys.request, authenticating: Data(sealed.id.utf8)),
              let request = try? JSONDecoder().decode(Request.self, from: json) else { throw Failure.unreadable }
        guard request.version == version else { throw Failure.wrongVersion }
        // What the Mac signed in clear is what it sealed.
        guard request.id == sealed.id, request.mac == sealed.mac,
              request.expires.milliseconds == sealed.expires.milliseconds else {
            throw Failure.mismatch
        }
        return Opened(request: request, keys: keys)
    }

    /// iPhone: the answer, sealed for the Mac. `key`: K, for an approved
    /// unlock.
    static func answer(_ opened: Opened, approved: Bool, key: Data? = nil) throws -> Data {
        let response = Response(id: opened.request.id, approved: approved, key: approved ? key : nil)
        return try AES.GCM.seal(JSONEncoder().encode(response), using: opened.keys.response,
                                authenticating: Data(opened.request.id.utf8)).combined ?? Data()
    }

    /// Mac: reads the answer with the request's ephemeral key.
    static func read(answer: Data, id: String, ephemeral: P256.KeyAgreement.PrivateKey,
                     phone: P256.KeyAgreement.PublicKey) throws -> Response {
        let keys = Keys(secret: try ephemeral.sharedSecretFromKeyAgreement(with: phone), id: id)
        guard let box = try? AES.GCM.SealedBox(combined: answer),
              let json = try? AES.GCM.open(box, using: keys.response, authenticating: Data(id.utf8)),
              let response = try? JSONDecoder().decode(Response.self, from: json) else { throw Failure.unreadable }
        guard response.version == version else { throw Failure.wrongVersion }
        guard response.id == id else { throw Failure.mismatch }
        return response
    }

    /// The two keys of an exchange, one per direction.
    fileprivate struct Keys {
        let request: SymmetricKey
        let response: SymmetricKey

        init(secret: SharedSecret, id: String) {
            let salt = Data(id.utf8)
            request = secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt,
                                                     sharedInfo: Data("verrou.remote.request.v1".utf8), outputByteCount: 32)
            response = secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt,
                                                      sharedInfo: Data("verrou.remote.response.v1".utf8), outputByteCount: 32)
        }
    }

    // MARK: Unlock

    /// K sealed for one iPhone.
    struct Escrow: Codable, Equatable {
        let ephemeral: Data
        let box: Data
    }

    /// Mac, at each unlock: the vault key sealed with a new K, and K sealed
    /// for each iPhone. K is not kept.
    struct Vault {
        let box: Data
        let escrows: [String: Escrow]
    }

    static func escrow(userKey: String, mac: String, phones: [String: P256.KeyAgreement.PublicKey]) throws -> Vault {
        let k = SymmetricKey(size: .bits256)
        let box = try AES.GCM.seal(Data(userKey.utf8), using: k, authenticating: vaultContext(mac)).combined ?? Data()
        let raw = k.withUnsafeBytes { Data($0) }
        var escrows: [String: Escrow] = [:]
        for (phone, key) in phones {
            let ephemeral = P256.KeyAgreement.PrivateKey()
            let wrap = escrowKey(try ephemeral.sharedSecretFromKeyAgreement(with: key), mac: mac)
            escrows[phone] = Escrow(ephemeral: ephemeral.publicKey.x963Representation,
                                    box: try AES.GCM.seal(raw, using: wrap, authenticating: Data(mac.utf8)).combined ?? Data())
        }
        return Vault(box: box, escrows: escrows)
    }

    /// iPhone, after Face ID: K.
    static func openEscrow(_ escrow: Escrow, mac: String, with key: AgreementKey) throws -> Data {
        guard let ephemeral = try? P256.KeyAgreement.PublicKey(x963Representation: escrow.ephemeral) else {
            throw Failure.malformed
        }
        let wrap = escrowKey(try key.sharedSecret(with: ephemeral), mac: mac)
        guard let box = try? AES.GCM.SealedBox(combined: escrow.box),
              let k = try? AES.GCM.open(box, using: wrap, authenticating: Data(mac.utf8)), k.count == 32 else {
            throw Failure.unreadable
        }
        return k
    }

    /// Mac: the vault key, from K returned by the iPhone.
    static func openVault(_ vault: Vault, key: Data, mac: String) throws -> String {
        guard key.count == 32, let box = try? AES.GCM.SealedBox(combined: vault.box),
              let data = try? AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: vaultContext(mac)),
              let userKey = String(data: data, encoding: .utf8) else { throw Failure.unreadable }
        return userKey
    }

    private static func escrowKey(_ secret: SharedSecret, mac: String) -> SymmetricKey {
        secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(mac.utf8),
                                       sharedInfo: Data("verrou.remote.escrow.v1".utf8), outputByteCount: 32)
    }

    private static func vaultContext(_ mac: String) -> Data {
        frame([Data("verrou.remote.vault.v1".utf8), Data(mac.utf8)])
    }

    // MARK: Encoding

    /// Each part preceded by its length: no ambiguity between `ab|c` and
    /// `a|bc`.
    fileprivate static func frame(_ parts: [Data]) -> Data {
        var out = Data()
        for part in parts {
            var length = UInt32(part.count).bigEndian
            out.append(Data(bytes: &length, count: 4))
            out.append(part)
        }
        return out
    }
}

extension P256.KeyAgreement.PrivateKey: RemoteApproval.AgreementKey {
    func sharedSecret(with publicKey: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        try sharedSecretFromKeyAgreement(with: publicKey)
    }
}

extension SecureEnclave.P256.KeyAgreement.PrivateKey: RemoteApproval.AgreementKey {
    func sharedSecret(with publicKey: P256.KeyAgreement.PublicKey) throws -> SharedSecret {
        try sharedSecretFromKeyAgreement(with: publicKey)
    }
}

extension P256.Signing.PrivateKey: RemoteApproval.SigningKey {
    func sign(_ data: Data) throws -> P256.Signing.ECDSASignature { try signature(for: data) }
}

extension SecureEnclave.P256.Signing.PrivateKey: RemoteApproval.SigningKey {
    func sign(_ data: Data) throws -> P256.Signing.ECDSASignature { try signature(for: data) }
}

extension Date {
    /// Whole milliseconds since 1970: what a signature covers.
    var milliseconds: Int64 { Int64((timeIntervalSince1970 * 1000).rounded()) }

    /// Rounded down to the second.
    var wholeSeconds: Date { Date(timeIntervalSince1970: timeIntervalSince1970.rounded(.down)) }
}

extension Data {
    var base64URL: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    init?(base64URL text: String) {
        var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        self.init(base64Encoded: base64)
    }
}

private extension Digest {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
