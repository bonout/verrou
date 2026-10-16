import Foundation
import XCTest

/// Migration du compte du Mac (conteneur de l'app → groupe d'apps), sur des
/// copies jetables avec des données fictives : jamais le vrai conteneur
/// (~/Library/Containers/app.verrou.mac).
final class MacMigrationTests: XCTestCase {
    private var root: URL!
    private let fm = FileManager.default
    private let date = ISO8601DateFormatter().date(from: "2026-10-16T12:00:00Z")!

    override func setUpWithError() throws {
        root = fm.temporaryDirectory.appending(path: "verrou-migration-\(UUID().uuidString)", directoryHint: .isDirectory)
        try fm.createDirectory(at: root, withIntermediateDirectories: true)
        // Garde-fou : les tests n'écrivent que dans le dossier temporaire.
        XCTAssertFalse(root.path.contains("/Library/Containers/app.verrou.mac/"))
    }

    override func tearDownWithError() throws {
        try? fm.removeItem(at: root)
    }

    /// Dossier privé de l'app (fictif) : compte, cache, file, scellement.
    private func makeOld() throws -> URL {
        let old = root.appending(path: "app/Library/Application Support/Verrou", directoryHint: .isDirectory)
        try fm.createDirectory(at: old.appending(path: "keys"), withIntermediateDirectories: true)
        try Data(#"{"email":"camille@exemple.fr","server":"https://vault.exemple.fr"}"#.utf8)
            .write(to: old.appending(path: "account.json"))
        try Data((0..<4096).map { UInt8($0 % 251) }).write(to: old.appending(path: "cache.bin"))
        try Data("file chiffrée".utf8).write(to: old.appending(path: "outbox.json"))
        try Data("scellement".utf8).write(to: old.appending(path: "touchid.json"))
        try Data("clé".utf8).write(to: old.appending(path: "keys/yubikey.json"))
        return old
    }

    private var new: URL {
        VerrouStorage.sharedDirectory(in: root.appending(path: "group", directoryHint: .isDirectory))
    }

    private func backupURL(of old: URL) -> URL {
        old.deletingLastPathComponent().appending(path: "Verrou-avant-groupe-2026-10-16")
    }

    func testCopiesVerifiesAndKeepsTheOldFolder() throws {
        let old = try makeOld()
        let original = root.appending(path: "original")
        try fm.copyItem(at: old, to: original)

        let result = VerrouStorage.migrateMac(from: old, to: new, now: date)

        let backup = backupURL(of: old)
        XCTAssertEqual(result, .migrated(backup: backup))
        XCTAssertFalse(fm.fileExists(atPath: old.path), "l'ancien dossier n'est plus relu")
        XCTAssertTrue(try VerrouStorage.sameFiles(backup, original), "l'ancien dossier est gardé intact")
    }

    func testGroupHasTheSameFilesPlusTheNote() throws {
        let old = try makeOld()
        let original = root.appending(path: "original")
        try fm.copyItem(at: old, to: original)
        _ = VerrouStorage.migrateMac(from: old, to: new, now: date)

        let note = new.appending(path: VerrouStorage.migrationNote)
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: note)) as? [String: String]
        XCTAssertEqual(json?["from"], old.standardizedFileURL.path)
        try fm.removeItem(at: note)
        XCTAssertTrue(try VerrouStorage.sameFiles(new, original))
        // Aucun dossier temporaire laissé à côté.
        let siblings = try fm.contentsOfDirectory(atPath: new.deletingLastPathComponent().path)
        XCTAssertEqual(siblings, ["Verrou"])
    }

    func testRunsOnlyOnce() throws {
        let old = try makeOld()
        _ = VerrouStorage.migrateMac(from: old, to: new, now: date)
        let account = try Data(contentsOf: new.appending(path: "account.json"))
        XCTAssertEqual(VerrouStorage.migrateMac(from: old, to: new, now: date), .nothingToDo)
        XCTAssertEqual(try Data(contentsOf: new.appending(path: "account.json")), account)
    }

    func testNothingToMigrate() throws {
        let old = root.appending(path: "vide/Verrou")
        XCTAssertEqual(VerrouStorage.migrateMac(from: old, to: new, now: date), .nothingToDo)
        XCTAssertFalse(fm.fileExists(atPath: new.path))
    }

    /// Le groupe a déjà un compte (l'extension, ou un autre build) : rien
    /// n'est copié ni renommé.
    func testExistingGroupAccountWins() throws {
        let old = try makeOld()
        try fm.createDirectory(at: new, withIntermediateDirectories: true)
        try Data("autre compte".utf8).write(to: new.appending(path: "account.json"))

        XCTAssertEqual(VerrouStorage.migrateMac(from: old, to: new, now: date), .nothingToDo)
        XCTAssertTrue(fm.fileExists(atPath: old.appending(path: "account.json").path))
        XCTAssertEqual(try String(contentsOf: new.appending(path: "account.json"), encoding: .utf8), "autre compte")
    }

    /// L'extension a pu créer le dossier vide du groupe avant l'app.
    func testEmptyGroupFolderIsReplaced() throws {
        let old = try makeOld()
        try fm.createDirectory(at: new, withIntermediateDirectories: true)
        XCTAssertEqual(VerrouStorage.migrateMac(from: old, to: new, now: date), .migrated(backup: backupURL(of: old)))
        XCTAssertTrue(fm.fileExists(atPath: new.appending(path: "account.json").path))
    }

    /// Des fichiers inconnus dans le groupe, sans compte : on ne touche à rien.
    func testUnknownGroupContentIsRefused() throws {
        let old = try makeOld()
        try fm.createDirectory(at: new, withIntermediateDirectories: true)
        try Data("?".utf8).write(to: new.appending(path: "inconnu.json"))

        guard case .refused = VerrouStorage.migrateMac(from: old, to: new, now: date) else {
            return XCTFail("migration attendue refusée")
        }
        XCTAssertTrue(fm.fileExists(atPath: old.appending(path: "account.json").path))
        XCTAssertTrue(fm.fileExists(atPath: new.appending(path: "inconnu.json").path))
        XCTAssertFalse(fm.fileExists(atPath: new.appending(path: "account.json").path))
    }

    /// Arrêt brutal après la copie, avant le renommage de l'ancien dossier :
    /// le lancement suivant le finit.
    func testInterruptedMigrationIsFinished() throws {
        let old = try makeOld()
        _ = VerrouStorage.migrateMac(from: old, to: new, now: date)
        // État d'une migration interrompue : l'ancien dossier remis en place.
        try fm.moveItem(at: backupURL(of: old), to: old)

        let later = date.addingTimeInterval(86_400)
        let backup = old.deletingLastPathComponent().appending(path: "Verrou-avant-groupe-2026-10-17")
        XCTAssertEqual(VerrouStorage.migrateMac(from: old, to: new, now: later), .finished(backup: backup))
        XCTAssertFalse(fm.fileExists(atPath: old.path))
        XCTAssertTrue(fm.fileExists(atPath: backup.appending(path: "account.json").path))
    }

    /// Un compte dans le groupe sans note venue de ce dossier : l'ancien
    /// dossier n'est pas renommé (ce n'est pas une migration interrompue).
    func testForeignGroupAccountDoesNotRetireTheOldFolder() throws {
        let old = try makeOld()
        try fm.createDirectory(at: new, withIntermediateDirectories: true)
        try Data("autre".utf8).write(to: new.appending(path: "account.json"))
        try JSONSerialization.data(withJSONObject: ["from": "/ailleurs", "date": "x"])
            .write(to: new.appending(path: VerrouStorage.migrationNote))
        XCTAssertEqual(VerrouStorage.migrateMac(from: old, to: new, now: date), .nothingToDo)
        XCTAssertTrue(fm.fileExists(atPath: old.path))
    }

    /// Une sauvegarde du même jour existe déjà : un suffixe, rien d'écrasé.
    func testBackupNameNeverOverwrites() throws {
        let old = try makeOld()
        let taken = backupURL(of: old)
        try fm.createDirectory(at: taken, withIntermediateDirectories: true)
        try Data("ancienne".utf8).write(to: taken.appending(path: "garde.txt"))

        let result = VerrouStorage.migrateMac(from: old, to: new, now: date)
        XCTAssertEqual(result, .migrated(backup: URL(fileURLWithPath: taken.path + "-2")))
        XCTAssertEqual(try String(contentsOf: taken.appending(path: "garde.txt"), encoding: .utf8), "ancienne")
    }

    func testSameFilesDetectsDifferences() throws {
        let a = try makeOld()
        let b = root.appending(path: "b")
        try fm.copyItem(at: a, to: b)
        XCTAssertTrue(try VerrouStorage.sameFiles(a, b))
        try Data("modifiée".utf8).write(to: b.appending(path: "outbox.json"))
        XCTAssertFalse(try VerrouStorage.sameFiles(a, b))
        try fm.removeItem(at: b.appending(path: "outbox.json"))
        XCTAssertFalse(try VerrouStorage.sameFiles(a, b))
    }

    /// `resolve` sans groupe (build ad hoc) : le dossier privé, aucune copie.
    func testResolveWithoutGroupKeepsThePrivateFolder() {
        let location = VerrouStorage.resolve(groupContainer: nil)
        XCTAssertEqual(location, .init(directory: VerrouStorage.privateDirectory(), shared: false))
    }
}
