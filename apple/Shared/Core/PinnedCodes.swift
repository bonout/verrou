import CryptoKit
import Foundation
import Security

/// One-time codes the user chose to see without opening the vault: in the
/// iPhone's widgets (home screen, lock screen, StandBy), in Shortcuts and
/// Siri ("Show the code of…"), and later on the Apple Watch.
///
/// Opt-in, item by item ("Show in widgets and on Apple Watch" on an item's
/// page, iPhone): only a login with a TOTP code, never a protected item
/// ("re-ask for the master password"), never one whose organization hides
/// passwords. For each pinned item, the app writes here its identifier,
/// title, site and the code's parameters (seed, algorithm, digits, period),
/// whenever the vault is open and synced: a changed item is rewritten, a
/// deleted, archived, trashed, protected or unpinned one is removed, and
/// signing out removes everything.
///
/// Storage: one item of this device's keychain (the default access group,
/// `app.verrou.shared`, shared by the app and its extensions),
/// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, never synced. "After
/// first unlock" rather than "when unlocked": WidgetKit asks for the
/// timeline while the iPhone is locked (lock screen, StandBy, a reload in
/// the night), and a "when unlocked" item can't be read then; the codes
/// themselves stay hidden on a locked lock screen (`privacySensitive`).
/// This is the one secret Verrou keeps outside the vault for longer than a
/// few minutes: it holds only what the user pinned, it is a second factor
/// (useless without the password), it never leaves this device (no iCloud
/// Keychain, no backup restored elsewhere), and the vault's keys are never
/// here. See SECURITY.md, "Pinned one-time codes".
///
/// Platform-neutral (Foundation, Security, CryptoKit), without the Rust
/// core: the widget extension and the Apple Watch compute the codes here
/// (RFC 6238). The app checks, when pinning, that this code equals the Rust
/// core's for the same instant; a code Swift reads differently (Steam, a
/// parameter the core doesn't accept) can't be pinned.
///
/// API, for the iPhone app, its widgets and the Apple Watch:
/// - `PinnedCodes.read()`: the codes, or `.unavailable` when the keychain
///   can't be read (before the first unlock after a restart, unsigned
///   build).
/// - `PinnedCodes.code(id:)`: one pinned item.
/// - `PinnedCodes.save(_:)`, `remove(id:)`, `replace(with:)`,
///   `removeAll()`: writes (the iPhone app; the Watch app stores what the
///   iPhone sends it the same way, in its own keychain).
/// - `PinnedCode.code(at:)`: the code valid at an instant, and its window.
struct PinnedCode: Codable, Equatable, Identifiable, Sendable {
    enum Algorithm: String, Codable, Sendable {
        case sha1, sha256, sha512
    }

    /// The vault item's identifier.
    let id: String
    var title: String
    /// The item's first site (`ItemSummary.host`), for the icon and the
    /// subtitle.
    var host: String?
    /// The decoded seed.
    let secret: Data
    let algorithm: Algorithm
    let digits: Int
    /// Seconds.
    let period: Int
    /// The item's revision when the seed was read (`ItemSummary.modified`):
    /// the app reads the seed again only when it changes.
    var revision: Int64

    /// A code and its validity window.
    struct Code: Equatable, Sendable {
        let value: String
        let start: Date
        let end: Date

        /// The code in two halves ("123 456"), as the app shows it.
        var grouped: String {
            let characters = Array(value)
            let half = characters.count / 2
            return String(characters[..<half]) + " " + String(characters[half...])
        }
    }

    /// Parameters read from the item's TOTP field (Base32 seed or
    /// `otpauth://totp` link), with the Rust core's rules
    /// (`verrou_core::totp`): SHA-1, SHA-256 or SHA-512, 6 to 10 digits, a
    /// positive period. `nil` for anything else (HOTP, Steam, unreadable).
    init?(id: String, title: String, host: String?, revision: Int64, totp: String) {
        guard let parameters = Self.parameters(totp) else { return nil }
        self.id = id
        self.title = title
        self.host = host
        self.revision = revision
        secret = parameters.secret
        algorithm = parameters.algorithm
        digits = parameters.digits
        period = parameters.period
    }

    init(id: String, title: String, host: String?, secret: Data, algorithm: Algorithm, digits: Int, period: Int,
         revision: Int64 = 0) {
        self.id = id
        self.title = title
        self.host = host
        self.secret = secret
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
        self.revision = revision
    }

    /// The code valid at `date` (RFC 6238, dynamic truncation of RFC 4226
    /// §5.3).
    func code(at date: Date = Date()) -> Code {
        let period = UInt64(max(1, self.period))
        let now = UInt64(max(0, date.timeIntervalSince1970))
        let counter = now / period
        let message = withUnsafeBytes(of: counter.bigEndian) { Data($0) }
        let key = SymmetricKey(data: secret)
        let digest: [UInt8]
        switch algorithm {
        case .sha1: digest = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        case .sha256: digest = Array(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case .sha512: digest = Array(HMAC<SHA512>.authenticationCode(for: message, using: key))
        }
        let offset = Int(digest[digest.count - 1] & 0x0f)
        let binary = UInt64(digest[offset] & 0x7f) << 24
            | UInt64(digest[offset + 1]) << 16
            | UInt64(digest[offset + 2]) << 8
            | UInt64(digest[offset + 3])
        var modulo: UInt64 = 1
        for _ in 0..<digits { modulo *= 10 }
        let digitsText = String(binary % modulo)
        let value = String(repeating: "0", count: max(0, digits - digitsText.count)) + digitsText
        let start = Date(timeIntervalSince1970: TimeInterval(counter * period))
        return Code(value: value, start: start, end: start.addingTimeInterval(TimeInterval(period)))
    }

    // MARK: Reading the TOTP field

    private struct Parameters {
        var secret: Data
        var algorithm: Algorithm = .sha1
        var digits = 6
        var period = 30
    }

    private static func parameters(_ input: String) -> Parameters? {
        let text = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }
        guard text.lowercased().hasPrefix("otpauth://") else {
            return base32(text).map { Parameters(secret: $0) }
        }
        guard let components = URLComponents(string: text), components.host?.lowercased() == "totp" else { return nil }
        var parameters = Parameters(secret: Data())
        var hasSecret = false
        for item in components.queryItems ?? [] {
            let value = item.value ?? ""
            switch item.name {
            case "secret":
                guard let secret = base32(value) else { return nil }
                parameters.secret = secret
                hasSecret = true
            case "digits":
                guard let digits = Int(value), (6...10).contains(digits) else { return nil }
                parameters.digits = digits
            case "period":
                guard let period = Int(value), period > 0 else { return nil }
                parameters.period = period
            case "algorithm":
                switch value.uppercased() {
                case "SHA1": parameters.algorithm = .sha1
                case "SHA256": parameters.algorithm = .sha256
                case "SHA512": parameters.algorithm = .sha512
                default: return nil
                }
            default:
                break
            }
        }
        return hasSecret ? parameters : nil
    }

    /// RFC 4648 Base32, without padding; spaces and hyphens ignored, any
    /// case (as the Rust core).
    private static func base32(_ text: String) -> Data? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)
        var cleaned = text.uppercased().filter { !$0.isWhitespace && $0 != "-" }
        while cleaned.hasSuffix("=") { cleaned.removeLast() }
        guard !cleaned.isEmpty else { return nil }
        var bytes: [UInt8] = []
        var buffer: UInt32 = 0
        var bits = 0
        for character in cleaned.utf8 {
            guard let index = alphabet.firstIndex(of: character) else { return nil }
            buffer = (buffer << 5) | UInt32(index)
            bits += 5
            if bits >= 8 {
                bits -= 8
                bytes.append(UInt8((buffer >> UInt32(bits)) & 0xff))
            }
        }
        // Leftover bits must be zero, and fewer than 5 (a length that no
        // byte count gives is refused, as by the core's decoder).
        guard bits < 5, buffer & ((1 << UInt32(bits)) - 1) == 0, !bytes.isEmpty else { return nil }
        return Data(bytes)
    }
}

/// The pinned codes, in this device's keychain (see `PinnedCode`).
enum PinnedCodes {
    enum Snapshot: Equatable, Sendable {
        case codes([PinnedCode])
        /// The keychain can't be read: before the first unlock after a
        /// restart, or a build without the keychain entitlement.
        case unavailable
    }

    private static var base: [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "app.verrou.pinned-codes",
            kSecAttrAccount: "codes",
            kSecUseDataProtectionKeychain: true,
        ]
    }

    static func read() -> Snapshot {
        var query = base
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        switch SecItemCopyMatching(query as CFDictionary, &result) {
        case errSecSuccess:
            guard let data = result as? Data, let codes = try? JSONDecoder().decode([PinnedCode].self, from: data) else {
                return .codes([])
            }
            return .codes(codes)
        case errSecItemNotFound:
            return .codes([])
        default:
            return .unavailable
        }
    }

    /// The pinned codes; none when the keychain can't be read.
    static var all: [PinnedCode] {
        if case .codes(let codes) = read() { return codes }
        return []
    }

    static func code(id: String) -> PinnedCode? {
        all.first { $0.id == id }
    }

    /// Adds or replaces an item's code (kept in pinning order).
    @discardableResult
    static func save(_ code: PinnedCode) -> Bool {
        var codes = all
        if let index = codes.firstIndex(where: { $0.id == code.id }) {
            codes[index] = code
        } else {
            codes.append(code)
        }
        return replace(with: codes)
    }

    @discardableResult
    static func remove(id: String) -> Bool {
        let codes = all
        guard codes.contains(where: { $0.id == id }) else { return true }
        return replace(with: codes.filter { $0.id != id })
    }

    /// Writes the whole list (an empty list deletes the keychain item).
    @discardableResult
    static func replace(with codes: [PinnedCode]) -> Bool {
        guard !codes.isEmpty else {
            removeAll()
            return true
        }
        guard let data = try? JSONEncoder().encode(codes) else { return false }
        let status = SecItemUpdate(base as CFDictionary, [kSecValueData: data] as CFDictionary)
        if status == errSecSuccess { return true }
        guard status == errSecItemNotFound else { return false }
        var query = base
        query[kSecValueData] = data
        query[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        query[kSecAttrSynchronizable] = false
        return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
    }

    static func removeAll() {
        SecItemDelete(base as CFDictionary)
    }
}
