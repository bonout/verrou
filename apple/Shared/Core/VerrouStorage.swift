import Foundation

/// Où vivent les fichiers du compte : `account.json`, le cache chiffré du
/// coffre, la file des modifications hors ligne, le scellement de Touch ID /
/// Face ID (`touchid.json`) et les clés de sécurité enrôlées.
///
/// - Mac : `~/Library/Application Support/Verrou`, dans le conteneur de l'app
///   (sandbox), comme avant.
/// - iPhone : le conteneur du groupe d'apps (`appGroupID`), que
///   l'extension de remplissage automatique partage avec l'app.
///   Sans groupe (build du simulateur non signé, ou droit absent), le dossier
///   de l'app sert de repli ; dès que le groupe existe, un compte resté dans
///   le repli y est déplacé une fois.
///
/// Rien n'y est en clair : le cache est la réponse chiffrée du serveur, la
/// file hors ligne est chiffrée avec la clé de l'utilisateur.
enum VerrouStorage {
    /// Groupe d'apps partagé par l'app iPhone et ses extensions : celui de
    /// la signature (`VERROU_APP_GROUP`, recopié dans l'Info.plist), sinon
    /// `group.app.verrou`.
    static let appGroupID = (Bundle.main.object(forInfoDictionaryKey: "VerrouAppGroup") as? String)
        .flatMap { $0.isEmpty || $0.hasPrefix("$(") ? nil : $0 } ?? "group.app.verrou"
    /// Groupe de trousseau partagé (préfixé par l'identifiant de l'équipe à la
    /// signature) : déclaré, inutilisé (l'extension lit les scellements
    /// Face ID du dossier partagé, voir `BiometricVault`).
    static let keychainAccessGroup = "app.verrou.shared"

    struct Location: Equatable {
        /// Dossier du compte.
        let directory: URL
        /// Dans le conteneur du groupe d'apps : visible des extensions.
        let shared: Bool
    }

    /// Le dossier du compte de cet appareil, créé au besoin.
    static func accountLocation(fileManager: FileManager = .default) -> Location {
        let location = resolve(groupContainer: groupContainer(fileManager), fileManager: fileManager)
        try? fileManager.createDirectory(at: location.directory, withIntermediateDirectories: true)
        #if os(iOS)
        excludeFromBackup(location.directory)
        #endif
        return location
    }

    /// Dossier privé de l'app (le repli, et l'unique emplacement sur le Mac).
    static func privateDirectory(fileManager: FileManager = .default) -> URL {
        let support = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return support.appending(path: "Verrou", directoryHint: .isDirectory)
    }

    /// Choisit l'emplacement : le groupe s'il existe (après y avoir déplacé un
    /// compte resté dans le repli), sinon le dossier privé. Séparé pour les tests.
    static func resolve(groupContainer: URL?, fileManager: FileManager = .default) -> Location {
        let fallback = privateDirectory(fileManager: fileManager)
        #if os(macOS)
        return Location(directory: fallback, shared: false)
        #else
        guard let groupContainer else { return Location(directory: fallback, shared: false) }
        let shared = groupContainer
            .appending(path: "Library/Application Support/Verrou", directoryHint: .isDirectory)
        migrate(from: fallback, to: shared, fileManager: fileManager)
        return Location(directory: shared, shared: true)
        #endif
    }

    private static func groupContainer(_ fileManager: FileManager) -> URL? {
        #if os(macOS)
        return nil
        #else
        return fileManager.containerURL(forSecurityApplicationGroupIdentifier: appGroupID)
        #endif
    }

    /// Un compte enregistré avant que le groupe n'existe (build non signé
    /// puis signé) : on le déplace plutôt que de demander une reconnexion.
    private static func migrate(from old: URL, to new: URL, fileManager: FileManager) {
        let oldAccount = old.appending(path: "account.json")
        guard fileManager.fileExists(atPath: oldAccount.path),
              !fileManager.fileExists(atPath: new.appending(path: "account.json").path) else { return }
        try? fileManager.createDirectory(at: new.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? fileManager.removeItem(at: new)
        try? fileManager.moveItem(at: old, to: new)
    }

    #if os(iOS)
    /// Le coffre chiffré ne part pas dans les sauvegardes iCloud ou Finder :
    /// le serveur reste la référence, et le scellement Face ID ne vaut que
    /// sur cet appareil.
    private static func excludeFromBackup(_ directory: URL) {
        var url = directory
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
    }
    #endif
}
