import AppIntents
import SwiftUI

// Shortcuts, Siri and Spotlight (App Shortcuts). What needs the vault
// opens the app, which unlocks with Face ID as usual: no intent ever hands a
// password to Shortcuts. Two answer without the vault: the generator (no
// secret of the vault) and the codes the user pinned (`PinnedCodes`, an
// explicit opt-in). Nothing of the vault is indexed in Spotlight: only the
// App Shortcuts show there. See SECURITY.md, "Widgets, Shortcuts and Live
// Activity".

/// The model the intents running in the app look the vault up in (set at
/// launch); its vault is only read while open.
@MainActor
enum IntentVault {
    static weak var model: PhoneModel?

    static func open() throws -> PhoneModel {
        guard let model, model.lockState == .unlocked else { throw IntentFailure.vaultLocked }
        return model
    }
}

enum IntentFailure: Error, CustomLocalizedStringResourceConvertible {
    case vaultLocked
    case codeNotPinned
    case keychainLocked

    var localizedStringResource: LocalizedStringResource {
        switch self {
        case .vaultLocked: "Open Verrou and unlock your vault first."
        case .codeNotPinned: "This code is no longer pinned in Verrou."
        case .keychainLocked: "Unlock your iPhone first."
        }
    }
}

// MARK: Vault items

/// A login of the vault, to pick in Shortcuts ("Copy a password"). Listed
/// only while the vault is open in the app; the shortcut then keeps its
/// identifier and the title shown when it was picked.
struct VaultItemEntity: AppEntity {
    static let typeDisplayRepresentation = TypeDisplayRepresentation(name: "Vault item")
    static let defaultQuery = VaultItemQuery()

    let id: String
    let title: String
    let subtitle: String

    init(id: String, title: String, subtitle: String) {
        self.id = id
        self.title = title
        self.subtitle = subtitle
    }

    init(_ summary: ItemSummary) {
        self.init(id: summary.id, title: summary.title, subtitle: summary.subtitle.isEmpty ? summary.host ?? "" : summary.subtitle)
    }

    var displayRepresentation: DisplayRepresentation {
        DisplayRepresentation(title: "\(title)", subtitle: subtitle.isEmpty ? nil : "\(subtitle)")
    }
}

struct VaultItemQuery: EntityStringQuery {
    /// A saved shortcut, vault locked: the item is known by its identifier
    /// only; running it opens Verrou, which unlocks first.
    @MainActor
    func entities(for identifiers: [String]) async throws -> [VaultItemEntity] {
        guard let model = try? IntentVault.open() else {
            return identifiers.map { VaultItemEntity(id: $0, title: String(localized: "Vault item"), subtitle: "") }
        }
        return identifiers.compactMap { id in
            model.summary(id: model.session.resolveItemId(id: id)).map(VaultItemEntity.init)
        }
    }

    @MainActor
    func entities(matching string: String) async throws -> [VaultItemEntity] {
        let model = try IntentVault.open()
        return model.rows(query: string, filter: .category(category: .login)).prefix(30).map { VaultItemEntity($0.summary) }
    }

    @MainActor
    func suggestedEntities() async throws -> [VaultItemEntity] {
        let model = try IntentVault.open()
        return model.rows(query: "", filter: .category(category: .login), order: .lastUsed).prefix(30)
            .map { VaultItemEntity($0.summary) }
    }
}

// MARK: Intents

/// Copies a login's password: opens Verrou, which unlocks (Face ID as
/// usual), confirms a protected item, then copies with the app's clipboard
/// expiry. The password never goes to Shortcuts.
struct CopyPasswordIntent: AppIntent {
    static let title: LocalizedStringResource = "Copy a password"
    static let description = IntentDescription(
        "Opens Verrou, which unlocks with Face ID, then copies the password of the item. Shortcuts never receives it.")
    static let openAppWhenRun = true
    static let authenticationPolicy = IntentAuthenticationPolicy.requiresAuthentication

    @Parameter(title: "Item")
    var item: VaultItemEntity

    @MainActor
    func perform() async throws -> some IntentResult {
        VerrouLinkCenter.open(.copyPassword(item.id))
        return .result()
    }
}

/// A new random password, without the vault (the Rust core's generator,
/// the app's settings by default).
struct GeneratePasswordIntent: AppIntent {
    static let title: LocalizedStringResource = "Generate a password"
    static let description = IntentDescription("Generates a random password, without opening your vault.")

    @Parameter(title: "Length", default: 20, inclusiveRange: (8, 64))
    var length: Int

    @Parameter(title: "Digits", default: true)
    var digits: Bool

    @Parameter(title: "Symbols", default: true)
    var symbols: Bool

    func perform() async throws -> some IntentResult & ReturnsValue<String> & ShowsSnippetView {
        let password = generatePassword(length: UInt32(min(max(length, 8), 64)), digits: digits, symbols: symbols)
        return .result(value: password, view: SecretSnippet(title: String(localized: "New password"), value: password))
    }
}

/// The current code of a pinned item, without the vault (an explicit
/// opt-in, `PinnedCodes`). The iPhone must be unlocked.
struct ShowOneTimeCodeIntent: AppIntent {
    static let title: LocalizedStringResource = "Show a one-time code"
    static let description = IntentDescription("Shows the current code of an item pinned in Verrou, without opening the vault.")
    static let authenticationPolicy = IntentAuthenticationPolicy.requiresAuthentication

    @Parameter(title: "Code", requestValueDialog: "Which code?")
    var code: PinnedCodeEntity

    func perform() async throws -> some IntentResult & ReturnsValue<String> & ProvidesDialog & ShowsSnippetView {
        guard case .codes(let codes) = PinnedCodes.read() else { throw IntentFailure.keychainLocked }
        guard let pinned = codes.first(where: { ItemID.same($0.id, code.id) }) else { throw IntentFailure.codeNotPinned }
        let current = pinned.code()
        return .result(value: current.value, dialog: IntentDialog("Code for \(pinned.title)"),
                       view: CodeSnippet(code: current))
    }
}

/// Siri phrases and the Shortcuts app's tiles; the same actions in
/// Spotlight. Localized in AppShortcuts.xcstrings.
struct VerrouShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: SearchVaultIntent(),
                    phrases: ["Search in \(.applicationName)", "Search my \(.applicationName) vault"],
                    shortTitle: "Search", systemImageName: "magnifyingglass")
        AppShortcut(intent: GeneratePasswordIntent(),
                    phrases: ["Generate a password with \(.applicationName)", "New \(.applicationName) password"],
                    shortTitle: "Generate a password", systemImageName: "wand.and.stars")
        AppShortcut(intent: ShowOneTimeCodeIntent(),
                    phrases: ["Show the code of \(\.$code) in \(.applicationName)",
                              "Show a one-time code in \(.applicationName)"],
                    shortTitle: "One-time code", systemImageName: "clock")
        AppShortcut(intent: CopyPasswordIntent(),
                    phrases: ["Copy a password with \(.applicationName)"],
                    shortTitle: "Copy a password", systemImageName: "key")
    }
}

// MARK: Snippets

/// A generated password, readable and selectable.
private struct SecretSnippet: View {
    let title: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(.title3, design: .monospaced, weight: .semibold))
                .textSelection(.enabled)
                .lineLimit(3)
                .minimumScaleFactor(0.6)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
    }
}

/// A code and its countdown.
private struct CodeSnippet: View {
    let code: PinnedCode.Code

    var body: some View {
        HStack(spacing: 12) {
            Text(code.grouped)
                .font(.system(size: 34, weight: .semibold, design: .monospaced))
                .accessibilityLabel(Text("Code \(code.value)"))
            Spacer(minLength: 0)
            Text(timerInterval: code.start...code.end, countsDown: true)
                .font(.title3.monospacedDigit())
                .foregroundStyle(.secondary)
        }
        .padding()
    }
}
