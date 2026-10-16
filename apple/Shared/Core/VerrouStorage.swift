import CryptoKit
import Foundation

/// Où vivent les fichiers du compte : `account.json`, le cache chiffré du
/// coffre, la file des modifications hors ligne, le scellement de Touch ID /
/// Face ID (`touchid.json`) et les clés de sécurité enrôlées.
///
/// - iPhone : le conteneur du groupe d'apps (`appGroupID`), que
///   l'extension de remplissage automatique partage avec l'app.
///   Sans groupe (build du simulateur non signé, ou droit absent), le dossier
///   de l'app sert de repli ; dès que le groupe existe, un compte resté dans
///   le repli y est déplacé une fois.
/// - Mac signé ad hoc (par défaut) : `~/Library/Application Support/Verrou`,
///   dans le conteneur de l'app (sandbox), comme avant. Pas de groupe d'apps :
///   sans équipe de développeur, macOS ne le valide pas.
/// - Mac signé par l'équipe (`VERROU_MAC_TEAM`, avec l'extension de
///   remplissage) : le conteneur du groupe `<équipe>.app.verrou`. Le compte
///   du conteneur de l'app y est **copié** une fois, vérifié, puis l'ancien
///   dossier est renommé (gardé, jamais effacé) : voir `migrateMac`.
///
/// Rien n'y est en clair : le cache est la réponse chiffrée du serveur, la
/// file hors ligne est chiffrée avec la clé de l'utilisateur.
enum VerrouStorage {
    /// Groupe d'apps partagé par l'app et ses extensions : celui de la
    /// signature (`VERROU_APP_GROUP` sur l'iPhone, `VERROU_MAC_APP_GROUP` sur
    /// le Mac, recopié dans l'Info.plist). Sur l'iPhone, `group.app.verrou`
    /// par défaut ; sur le Mac, aucun (build ad hoc).
    static let appGroupID: String? = {
        let declared = (Bundle.main.object(forInfoDictionaryKey: "VerrouAppGroup") as? String)
            .flatMap { $0.isEmpty || $0.hasPrefix("$(") ? nil : $0 }
        #if os(macOS)
        return declared
        #else
        return declared ?? "group.app.verrou"
        #endif
    }()
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

    /// Dossier privé de l'app (le repli, et l'emplacement du Mac ad hoc).
    static func privateDirectory(fileManager: FileManager = .default) -> URL {
        let support = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return support.appending(path: "Verrou", directoryHint: .isDirectory)
    }

    /// Le dossier du compte dans un conteneur de groupe.
    static func sharedDirectory(in groupContainer: URL) -> URL {
        groupContainer.appending(path: "Library/Application Support/Verrou", directoryHint: .isDirectory)
    }

    /// Choisit l'emplacement : le groupe s'il existe (après y avoir déplacé ou
    /// copié un compte resté dans le dossier privé), sinon le dossier privé.
    /// Séparé pour les tests.
    static func resolve(groupContainer: URL?, fileManager: FileManager = .default) -> Location {
        let fallback = privateDirectory(fileManager: fileManager)
        guard let groupContainer else { return Location(directory: fallback, shared: false) }
        let shared = sharedDirectory(in: groupContainer)
        #if os(macOS)
        switch migrateMac(from: fallback, to: shared, fileManager: fileManager) {
        case .refused:
            // Le groupe contient autre chose qu'un compte : on ne touche à
            // rien, l'app garde son dossier privé (l'extension n'aura pas de
            // coffre).
            return Location(directory: fallback, shared: false)
        case .nothingToDo, .migrated, .finished:
            return Location(directory: shared, shared: true)
        }
        #else
        migrate(from: fallback, to: shared, fileManager: fileManager)
        return Location(directory: shared, shared: true)
        #endif
    }

    private static func groupContainer(_ fileManager: FileManager) -> URL? {
        guard let appGroupID else { return nil }
        return fileManager.containerURL(forSecurityApplicationGroupIdentifier: appGroupID)
    }

    #if os(iOS)
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

    // MARK: Migration du Mac (conteneur de l'app → groupe d'apps)

    enum MacMigration: Equatable {
        /// Pas de compte à migrer (aucun, ou déjà dans le groupe).
        case nothingToDo
        /// Compte copié et vérifié ; l'ancien dossier est renommé en `backup`.
        case migrated(backup: URL)
        /// Une migration interrompue après la copie : l'ancien dossier est
        /// renommé maintenant.
        case finished(backup: URL)
        /// Le dossier du groupe existe, sans compte mais pas vide, ou la copie
        /// n'a pas pu être vérifiée : rien n'est touché.
        case refused(String)
    }

    /// Note laissée dans le dossier du groupe : d'où vient le compte.
    static let migrationNote = "migration.json"

    /// Copie le compte du dossier privé de l'app Mac (`old`) dans le groupe
    /// (`new`), une seule fois, sans jamais rien effacer :
    ///
    /// 1. rien à faire s'il n'y a pas de `account.json` dans `old`, ou s'il y
    ///    en a déjà un dans `new` (dans ce cas, une note `migration.json`
    ///    venue de `old` signale une migration interrompue : l'étape 4 est
    ///    reprise) ;
    /// 2. copie de `old` dans un dossier temporaire à côté de `new`, puis
    ///    vérification fichier par fichier (taille et SHA-256) ;
    /// 3. renommage atomique du dossier temporaire en `new` (même volume),
    ///    avec la note `migration.json` ;
    /// 4. renommage de `old` en `Verrou-avant-groupe-<date>` : l'app ne le
    ///    relit plus (une file hors ligne périmée ne repartirait pas), et il
    ///    reste là pour revenir en arrière à la main.
    static func migrateMac(from old: URL, to new: URL, fileManager: FileManager = .default,
                           now: Date = Date()) -> MacMigration {
        let oldAccount = old.appending(path: "account.json")
        let hasOld = fileManager.fileExists(atPath: oldAccount.path)
        if fileManager.fileExists(atPath: new.appending(path: "account.json").path) {
            // Copie faite, renommage de l'ancien dossier pas fait (arrêt
            // brutal entre les étapes 3 et 4) : on le finit.
            guard hasOld, let note = try? Data(contentsOf: new.appending(path: migrationNote)),
                  let source = try? JSONDecoder().decode(MigrationNote.self, from: note),
                  source.from == old.standardizedFileURL.path,
                  let backup = try? retire(old, now: now, fileManager: fileManager) else { return .nothingToDo }
            return .finished(backup: backup)
        }
        guard hasOld else { return .nothingToDo }
        if fileManager.fileExists(atPath: new.path) {
            let contents = (try? fileManager.contentsOfDirectory(atPath: new.path)) ?? []
            guard contents.allSatisfy({ $0 == ".DS_Store" }) else {
                return .refused("le dossier du groupe existe déjà, sans compte : \(contents.sorted())")
            }
            try? fileManager.removeItem(at: new)
        }
        let parent = new.deletingLastPathComponent()
        let staging = parent.appending(path: ".Verrou-migration-\(UUID().uuidString)", directoryHint: .isDirectory)
        do {
            try fileManager.createDirectory(at: parent, withIntermediateDirectories: true)
            try fileManager.copyItem(at: old, to: staging)
            guard try sameFiles(old, staging, fileManager: fileManager) else {
                try? fileManager.removeItem(at: staging)
                return .refused("la copie ne correspond pas à l'original")
            }
            let note = try JSONEncoder().encode(MigrationNote(from: old.standardizedFileURL.path,
                                                              date: ISO8601DateFormatter().string(from: now)))
            try note.write(to: staging.appending(path: migrationNote), options: .atomic)
            try fileManager.moveItem(at: staging, to: new)
        } catch {
            try? fileManager.removeItem(at: staging)
            return .refused("copie impossible : \(error.localizedDescription)")
        }
        guard let backup = try? retire(old, now: now, fileManager: fileManager) else {
            // Le compte est dans le groupe ; l'ancien dossier reste en place,
            // le prochain lancement réessaie de le renommer (étape 1).
            return .migrated(backup: old)
        }
        return .migrated(backup: backup)
    }

    private struct MigrationNote: Codable {
        let from: String
        let date: String
    }

    /// `old` → `old-avant-groupe-<date>` (un suffixe s'il existe déjà).
    private static func retire(_ old: URL, now: Date, fileManager: FileManager) throws -> URL {
        let stamp = ISO8601DateFormatter.string(from: now, timeZone: .gmt, formatOptions: [.withFullDate])
        let base = old.deletingLastPathComponent().appending(path: "\(old.lastPathComponent)-avant-groupe-\(stamp)")
        var backup = base
        var n = 2
        while fileManager.fileExists(atPath: backup.path) {
            backup = URL(fileURLWithPath: base.path + "-\(n)")
            n += 1
        }
        try fileManager.moveItem(at: old, to: backup)
        return backup
    }

    /// Mêmes fichiers (chemins relatifs), mêmes tailles, mêmes SHA-256.
    static func sameFiles(_ a: URL, _ b: URL, fileManager: FileManager = .default) throws -> Bool {
        let left = try fingerprints(a, fileManager: fileManager)
        let right = try fingerprints(b, fileManager: fileManager)
        return !left.isEmpty && left == right
    }

    private static func fingerprints(_ root: URL, fileManager: FileManager) throws -> [String: String] {
        var out: [String: String] = [:]
        let base = root.standardizedFileURL.resolvingSymlinksInPath().path
        guard let walker = fileManager.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey]) else {
            return out
        }
        for case let url as URL in walker {
            guard (try url.resourceValues(forKeys: [.isRegularFileKey])).isRegularFile == true else { continue }
            let path = url.standardizedFileURL.resolvingSymlinksInPath().path
            let relative = path.hasPrefix(base) ? String(path.dropFirst(base.count)) : path
            let data = try Data(contentsOf: url)
            out[relative] = "\(data.count):" + SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        }
        return out
    }
}
