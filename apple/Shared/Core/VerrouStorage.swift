import CryptoKit
import Foundation

/// Where the account's files live: `account.json`, the vault's encrypted
/// cache, the queue of offline changes, the Touch ID / Face ID seal
/// (`touchid.json`) and the enrolled security keys.
///
/// - iPhone: the app group container (`appGroupID`), which the AutoFill
///   extension shares with the app.
///   Without a group (unsigned simulator build, or missing entitlement), the
///   app's folder is the fallback; as soon as the group exists, an account
///   left in the fallback is moved there once.
/// - Mac signed ad hoc (default): `~/Library/Application Support/Verrou`,
///   in the app's container (sandbox), as before. No app group: without a
///   developer team, macOS doesn't validate it.
/// - Mac signed by the team (`VERROU_MAC_TEAM`, with the AutoFill
///   extension): the `<team>.app.verrou` group container. The account in the
///   app's container is **copied** there once, verified, then the old
///   folder is renamed (kept, never erased): see `migrateMac`.
///
/// Nothing in it is in clear: the cache is the server's encrypted response,
/// the offline queue is encrypted with the user's key.
enum VerrouStorage {
    /// App group shared by the app and its extensions: the signing one
    /// (`VERROU_APP_GROUP` on the iPhone, `VERROU_MAC_APP_GROUP` on the Mac,
    /// copied into the Info.plist). On the iPhone, `group.app.verrou` by
    /// default; on the Mac, none (ad hoc build).
    static let appGroupID: String? = {
        let declared = (Bundle.main.object(forInfoDictionaryKey: "VerrouAppGroup") as? String)
            .flatMap { $0.isEmpty || $0.hasPrefix("$(") ? nil : $0 }
        #if os(macOS)
        return declared
        #else
        return declared ?? "group.app.verrou"
        #endif
    }()
    /// Shared keychain group (prefixed with the team identifier at signing):
    /// declared, unused (the extension reads the Face ID seals from the
    /// shared folder, see `BiometricVault`).
    static let keychainAccessGroup = "app.verrou.shared"

    struct Location: Equatable {
        /// The account folder.
        let directory: URL
        /// In the app group container: visible to the extensions.
        let shared: Bool
    }

    /// This device's account folder, created if needed.
    static func accountLocation(fileManager: FileManager = .default) -> Location {
        let location = resolve(groupContainer: groupContainer(fileManager), fileManager: fileManager)
        try? fileManager.createDirectory(at: location.directory, withIntermediateDirectories: true)
        #if os(iOS)
        excludeFromBackup(location.directory)
        #endif
        return location
    }

    /// The app's private folder (the fallback, and the ad hoc Mac's location).
    static func privateDirectory(fileManager: FileManager = .default) -> URL {
        let support = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return support.appending(path: "Verrou", directoryHint: .isDirectory)
    }

    /// The account folder in a group container.
    static func sharedDirectory(in groupContainer: URL) -> URL {
        groupContainer.appending(path: "Library/Application Support/Verrou", directoryHint: .isDirectory)
    }

    /// Picks the location: the group if it exists (after moving or copying
    /// there an account left in the private folder), otherwise the private
    /// folder. Separate for tests.
    static func resolve(groupContainer: URL?, fileManager: FileManager = .default) -> Location {
        let fallback = privateDirectory(fileManager: fileManager)
        guard let groupContainer else { return Location(directory: fallback, shared: false) }
        let shared = sharedDirectory(in: groupContainer)
        #if os(macOS)
        switch migrateMac(from: fallback, to: shared, fileManager: fileManager) {
        case .refused:
            // The group contains something other than an account: we touch
            // nothing, the app keeps its private folder (the extension won't
            // have a vault).
            return Location(directory: fallback, shared: false)
        case .nothingToDo, .migrated, .finished:
            return Location(directory: shared, shared: true)
        }
        #else
        migrate(from: fallback, to: shared, fileManager: fileManager)
        return Location(directory: shared, shared: true)
        #endif
    }

    /// The app group's `Library/Caches` (performance journal of the
    /// extension, `Perf`).
    static func groupCachesDirectory(fileManager: FileManager = .default) -> URL? {
        guard let container = groupContainer(fileManager) else { return nil }
        let caches = container.appending(path: "Library/Caches", directoryHint: .isDirectory)
        try? fileManager.createDirectory(at: caches, withIntermediateDirectories: true)
        return caches
    }

    private static func groupContainer(_ fileManager: FileManager) -> URL? {
        guard let appGroupID else { return nil }
        return fileManager.containerURL(forSecurityApplicationGroupIdentifier: appGroupID)
    }

    #if os(iOS)
    /// An account saved before the group existed (unsigned then signed
    /// build): we move it rather than asking to sign in again.
    private static func migrate(from old: URL, to new: URL, fileManager: FileManager) {
        let oldAccount = old.appending(path: "account.json")
        guard fileManager.fileExists(atPath: oldAccount.path),
              !fileManager.fileExists(atPath: new.appending(path: "account.json").path) else { return }
        try? fileManager.createDirectory(at: new.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? fileManager.removeItem(at: new)
        try? fileManager.moveItem(at: old, to: new)
    }

    /// The encrypted vault doesn't go into iCloud or Finder backups: the
    /// server stays the reference, and the Face ID seal is only valid on
    /// this device.
    private static func excludeFromBackup(_ directory: URL) {
        var url = directory
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
    }
    #endif

    // MARK: Mac migration (app container → app group)

    enum MacMigration: Equatable {
        /// No account to migrate (none, or already in the group).
        case nothingToDo
        /// Account copied and verified; the old folder is renamed to `backup`.
        case migrated(backup: URL)
        /// A migration interrupted after the copy: the old folder is renamed
        /// now.
        case finished(backup: URL)
        /// The group folder exists, without an account but not empty, or the
        /// copy could not be verified: nothing is touched.
        case refused(String)
    }

    /// Note left in the group folder: where the account comes from.
    static let migrationNote = "migration.json"

    /// Copies the account from the Mac app's private folder (`old`) into the
    /// group (`new`), only once, without ever erasing anything:
    ///
    /// 1. nothing to do if there is no `account.json` in `old`, or if there
    ///    already is one in `new` (in that case, a `migration.json` note
    ///    from `old` signals an interrupted migration: step 4 is
    ///    resumed);
    /// 2. copy of `old` into a temporary folder next to `new`, then
    ///    file-by-file verification (size and SHA-256);
    /// 3. atomic rename of the temporary folder to `new` (same volume),
    ///    with the `migration.json` note;
    /// 4. rename of `old` to `Verrou-before-group-<date>`: the app no longer
    ///    reads it (a stale offline queue would not be sent again), and it
    ///    stays there to go back by hand.
    static func migrateMac(from old: URL, to new: URL, fileManager: FileManager = .default,
                           now: Date = Date()) -> MacMigration {
        let oldAccount = old.appending(path: "account.json")
        let hasOld = fileManager.fileExists(atPath: oldAccount.path)
        if fileManager.fileExists(atPath: new.appending(path: "account.json").path) {
            // Copy done, old folder not renamed yet (hard stop between
            // steps 3 and 4): we finish it.
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
                return .refused("the group folder already exists, without an account: \(contents.sorted())")
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
                return .refused("the copy doesn't match the original")
            }
            let note = try JSONEncoder().encode(MigrationNote(from: old.standardizedFileURL.path,
                                                              date: ISO8601DateFormatter().string(from: now)))
            try note.write(to: staging.appending(path: migrationNote), options: .atomic)
            try fileManager.moveItem(at: staging, to: new)
        } catch {
            try? fileManager.removeItem(at: staging)
            return .refused("copy failed: \(error.localizedDescription)")
        }
        guard let backup = try? retire(old, now: now, fileManager: fileManager) else {
            // The account is in the group; the old folder stays in place,
            // the next launch tries again to rename it (step 1).
            return .migrated(backup: old)
        }
        return .migrated(backup: backup)
    }

    private struct MigrationNote: Codable {
        let from: String
        let date: String
    }

    /// `old` → `old-before-group-<date>` (a suffix if it already exists).
    private static func retire(_ old: URL, now: Date, fileManager: FileManager) throws -> URL {
        let stamp = ISO8601DateFormatter.string(from: now, timeZone: .gmt, formatOptions: [.withFullDate])
        let base = old.deletingLastPathComponent().appending(path: "\(old.lastPathComponent)-before-group-\(stamp)")
        var backup = base
        var n = 2
        while fileManager.fileExists(atPath: backup.path) {
            backup = URL(fileURLWithPath: base.path + "-\(n)")
            n += 1
        }
        try fileManager.moveItem(at: old, to: backup)
        return backup
    }

    /// Same files (relative paths), same sizes, same SHA-256.
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
