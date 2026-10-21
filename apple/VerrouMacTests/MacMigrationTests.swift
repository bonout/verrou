import Foundation
import XCTest

/// Migration of the Mac account (app container → app group), on throwaway
/// copies with mock data: never the real container
/// (~/Library/Containers/app.verrou.mac).
final class MacMigrationTests: XCTestCase {
    private var root: URL!
    private let fm = FileManager.default
    private let date = ISO8601DateFormatter().date(from: "2026-10-16T12:00:00Z")!

    override func setUpWithError() throws {
        root = fm.temporaryDirectory.appending(path: "verrou-migration-\(UUID().uuidString)", directoryHint: .isDirectory)
        try fm.createDirectory(at: root, withIntermediateDirectories: true)
        // Safeguard: the tests only write in the temporary folder.
        XCTAssertFalse(root.path.contains("/Library/Containers/app.verrou.mac/"))
    }

    override func tearDownWithError() throws {
        try? fm.removeItem(at: root)
    }

    /// The app's private folder (mock): account, cache, queue, sealing.
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
        old.deletingLastPathComponent().appending(path: "Verrou-before-group-2026-10-16")
    }

    func testCopiesVerifiesAndKeepsTheOldFolder() throws {
        let old = try makeOld()
        let original = root.appending(path: "original")
        try fm.copyItem(at: old, to: original)

        let result = VerrouStorage.migrateMac(from: old, to: new, now: date)

        let backup = backupURL(of: old)
        XCTAssertEqual(result, .migrated(backup: backup))
        XCTAssertFalse(fm.fileExists(atPath: old.path), "the old folder is no longer read")
        XCTAssertTrue(try VerrouStorage.sameFiles(backup, original), "the old folder is kept intact")
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
        // No temporary folder left next to it.
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
        let old = root.appending(path: "empty/Verrou")
        XCTAssertEqual(VerrouStorage.migrateMac(from: old, to: new, now: date), .nothingToDo)
        XCTAssertFalse(fm.fileExists(atPath: new.path))
    }

    /// The group already has an account (the extension, or another build):
    /// nothing is copied or renamed.
    func testExistingGroupAccountWins() throws {
        let old = try makeOld()
        try fm.createDirectory(at: new, withIntermediateDirectories: true)
        try Data("autre compte".utf8).write(to: new.appending(path: "account.json"))

        XCTAssertEqual(VerrouStorage.migrateMac(from: old, to: new, now: date), .nothingToDo)
        XCTAssertTrue(fm.fileExists(atPath: old.appending(path: "account.json").path))
        XCTAssertEqual(try String(contentsOf: new.appending(path: "account.json"), encoding: .utf8), "autre compte")
    }

    /// The extension may have created the group's empty folder before the app.
    func testEmptyGroupFolderIsReplaced() throws {
        let old = try makeOld()
        try fm.createDirectory(at: new, withIntermediateDirectories: true)
        XCTAssertEqual(VerrouStorage.migrateMac(from: old, to: new, now: date), .migrated(backup: backupURL(of: old)))
        XCTAssertTrue(fm.fileExists(atPath: new.appending(path: "account.json").path))
    }

    /// Unknown files in the group, without an account: nothing is touched.
    func testUnknownGroupContentIsRefused() throws {
        let old = try makeOld()
        try fm.createDirectory(at: new, withIntermediateDirectories: true)
        try Data("?".utf8).write(to: new.appending(path: "unknown.json"))

        guard case .refused = VerrouStorage.migrateMac(from: old, to: new, now: date) else {
            return XCTFail("migration expected to be refused")
        }
        XCTAssertTrue(fm.fileExists(atPath: old.appending(path: "account.json").path))
        XCTAssertTrue(fm.fileExists(atPath: new.appending(path: "unknown.json").path))
        XCTAssertFalse(fm.fileExists(atPath: new.appending(path: "account.json").path))
    }

    /// Hard stop after the copy, before the old folder is renamed: the next
    /// launch finishes it.
    func testInterruptedMigrationIsFinished() throws {
        let old = try makeOld()
        _ = VerrouStorage.migrateMac(from: old, to: new, now: date)
        // State of an interrupted migration: the old folder put back in place.
        try fm.moveItem(at: backupURL(of: old), to: old)

        let later = date.addingTimeInterval(86_400)
        let backup = old.deletingLastPathComponent().appending(path: "Verrou-before-group-2026-10-17")
        XCTAssertEqual(VerrouStorage.migrateMac(from: old, to: new, now: later), .finished(backup: backup))
        XCTAssertFalse(fm.fileExists(atPath: old.path))
        XCTAssertTrue(fm.fileExists(atPath: backup.appending(path: "account.json").path))
    }

    /// An account in the group without a note coming from this folder: the
    /// old folder is not renamed (it is not an interrupted migration).
    func testForeignGroupAccountDoesNotRetireTheOldFolder() throws {
        let old = try makeOld()
        try fm.createDirectory(at: new, withIntermediateDirectories: true)
        try Data("autre".utf8).write(to: new.appending(path: "account.json"))
        try JSONSerialization.data(withJSONObject: ["from": "/elsewhere", "date": "x"])
            .write(to: new.appending(path: VerrouStorage.migrationNote))
        XCTAssertEqual(VerrouStorage.migrateMac(from: old, to: new, now: date), .nothingToDo)
        XCTAssertTrue(fm.fileExists(atPath: old.path))
    }

    /// A backup of the same day already exists: a suffix, nothing overwritten.
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

    /// `resolve` without a group (ad hoc build): the private folder, no copy.
    func testResolveWithoutGroupKeepsThePrivateFolder() {
        let location = VerrouStorage.resolve(groupContainer: nil)
        XCTAssertEqual(location, .init(directory: VerrouStorage.privateDirectory(), shared: false))
    }
}
