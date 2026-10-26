import Foundation
import XCTest

/// Migration of the Mac account (app container → app group), and of the
/// iPhone account (private folder → app group), on throwaway copies with
/// mock data: never the real container (~/Library/Containers/app.verrou.mac).
/// Both must recognize the layout of several accounts (`accounts.json`,
/// `accounts/<tag>/`) as well as the single `account.json` of older versions.
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
        // Compare paths: URL(fileURLWithPath:) adds a trailing slash once the folder exists.
        guard case .migrated(let backup) = result else { return XCTFail("\(result)") }
        XCTAssertEqual(backup.standardizedFileURL.path, taken.path + "-2")
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
        XCTAssertEqual(location, .init(root: VerrouStorage.privateDirectory(), shared: false))
    }

    // MARK: Layout of several accounts (accounts.json, accounts/<tag>/)

    /// A folder already moved to the new layout by the Rust core: a registry,
    /// one account folder with its files, no root `account.json`.
    private func makeLayoutFolder(at folder: URL, marker: String) throws {
        let account = folder.appending(path: "accounts/k3f7qa", directoryHint: .isDirectory)
        try fm.createDirectory(at: account, withIntermediateDirectories: true)
        try Data(#"{"version":1,"accounts":[{"tag":"k3f7qa"}],"default":"k3f7qa"}"#.utf8)
            .write(to: folder.appending(path: "accounts.json"))
        try Data(marker.utf8).write(to: account.appending(path: "account.json"))
        try Data("queue \(marker)".utf8).write(to: account.appending(path: "outbox.json"))
        try Data("seal \(marker)".utf8).write(to: account.appending(path: "touchid.json"))
        try Data("pairing".utf8).write(to: folder.appending(path: "bridge-clients.json"))
    }

    private func read(_ url: URL) -> String? {
        try? String(contentsOf: url, encoding: .utf8)
    }

    func testHasAccountRecognizesBothLayouts() throws {
        let single = root.appending(path: "single")
        try fm.createDirectory(at: single, withIntermediateDirectories: true)
        XCTAssertFalse(VerrouStorage.hasAccount(in: single))
        try Data("{}".utf8).write(to: single.appending(path: "account.json"))
        XCTAssertTrue(VerrouStorage.hasAccount(in: single))

        let layout = root.appending(path: "layout")
        try makeLayoutFolder(at: layout, marker: "a")
        XCTAssertFalse(fm.fileExists(atPath: layout.appending(path: "account.json").path))
        XCTAssertTrue(VerrouStorage.hasAccount(in: layout))
        XCTAssertFalse(VerrouStorage.hasAccount(in: root.appending(path: "missing")))
    }

    /// Ad hoc build first (its private folder was already moved to the new
    /// layout), team build later: the private folder is still copied to the
    /// group, whole.
    func testLayoutMigratedPrivateFolderIsCopiedToTheGroup() throws {
        let old = root.appending(path: "app/Library/Application Support/Verrou", directoryHint: .isDirectory)
        try makeLayoutFolder(at: old, marker: "private")
        let original = root.appending(path: "original")
        try fm.copyItem(at: old, to: original)

        let result = VerrouStorage.migrateMac(from: old, to: new, now: date)

        XCTAssertEqual(result, .migrated(backup: backupURL(of: old)))
        XCTAssertEqual(read(new.appending(path: "accounts/k3f7qa/account.json")), "private")
        XCTAssertEqual(read(new.appending(path: "accounts/k3f7qa/touchid.json")), "seal private")
        XCTAssertFalse(fm.fileExists(atPath: old.path))
        XCTAssertTrue(try VerrouStorage.sameFiles(backupURL(of: old), original), "the old folder is kept intact")
    }

    /// A group that already has the registry is not overwritten, nor is the
    /// private folder retired (it is not an interrupted migration).
    func testGroupRegistryWinsOverThePrivateFolder() throws {
        let old = try makeOld()
        try makeLayoutFolder(at: new, marker: "group")

        XCTAssertEqual(VerrouStorage.migrateMac(from: old, to: new, now: date), .nothingToDo)
        XCTAssertTrue(fm.fileExists(atPath: old.appending(path: "account.json").path))
        XCTAssertEqual(read(new.appending(path: "accounts/k3f7qa/account.json")), "group")
    }

    /// Hard stop after the copy of a layout-migrated folder: the next launch
    /// retires the old folder, like for a single account.
    func testInterruptedLayoutMigrationIsFinished() throws {
        let old = root.appending(path: "app/Library/Application Support/Verrou", directoryHint: .isDirectory)
        try makeLayoutFolder(at: old, marker: "private")
        _ = VerrouStorage.migrateMac(from: old, to: new, now: date)
        try fm.moveItem(at: backupURL(of: old), to: old)

        let later = date.addingTimeInterval(86_400)
        let backup = old.deletingLastPathComponent().appending(path: "Verrou-before-group-2026-10-17")
        XCTAssertEqual(VerrouStorage.migrateMac(from: old, to: new, now: later), .finished(backup: backup))
        XCTAssertFalse(fm.fileExists(atPath: old.path))
        XCTAssertEqual(read(new.appending(path: "accounts/k3f7qa/account.json")), "private")
    }

    /// A private folder that only has an empty registry (and the lock file)
    /// holds no account: nothing to copy.
    func testEmptyRegistryPrivateFolderIsNotAnAccount() throws {
        let old = root.appending(path: "app/Library/Application Support/Verrou", directoryHint: .isDirectory)
        try fm.createDirectory(at: old.appending(path: "accounts"), withIntermediateDirectories: true)
        try Data(#"{"version":1,"accounts":[],"default":null}"#.utf8).write(to: old.appending(path: "accounts.json"))
        try Data().write(to: old.appending(path: ".verrou.lock"))
        XCTAssertFalse(VerrouStorage.hasAccount(in: old))
        XCTAssertEqual(VerrouStorage.migrateMac(from: old, to: new, now: date), .nothingToDo)
        XCTAssertFalse(fm.fileExists(atPath: new.path))
    }

    /// A registry that lists an account, or a folder holding one, is an
    /// account; so is a registry that can't be read (never ignored).
    func testHasAccountCountsRegistriesAndFoldersThatHoldOne() throws {
        let listed = root.appending(path: "listed", directoryHint: .isDirectory)
        try fm.createDirectory(at: listed, withIntermediateDirectories: true)
        try Data(#"{"version":1,"accounts":[{"tag":"k3f7qa"}],"default":null}"#.utf8)
            .write(to: listed.appending(path: "accounts.json"))
        XCTAssertTrue(VerrouStorage.hasAccount(in: listed))

        let folder = root.appending(path: "folder", directoryHint: .isDirectory)
        try fm.createDirectory(at: folder.appending(path: "accounts/k3f7qa"), withIntermediateDirectories: true)
        XCTAssertFalse(VerrouStorage.hasAccount(in: folder), "an empty account folder is not an account")
        try Data("{}".utf8).write(to: folder.appending(path: "accounts/k3f7qa/account.json"))
        XCTAssertTrue(VerrouStorage.hasAccount(in: folder), "registry lost, the folder still holds the account")

        let damaged = root.appending(path: "damaged", directoryHint: .isDirectory)
        try fm.createDirectory(at: damaged, withIntermediateDirectories: true)
        try Data("{ not json".utf8).write(to: damaged.appending(path: "accounts.json"))
        XCTAssertTrue(VerrouStorage.hasAccount(in: damaged))
    }

    /// What the AutoFill extension (or the Rust core) leaves in a group with
    /// no account: `.DS_Store`, `.verrou.lock`, an empty `accounts.json`,
    /// `accounts/` with nothing in it, `cache/`.
    private func makeScaffolding(at folder: URL) throws {
        try fm.createDirectory(at: folder.appending(path: "accounts/k3f7qa"), withIntermediateDirectories: true)
        try fm.createDirectory(at: folder.appending(path: "cache"), withIntermediateDirectories: true)
        try Data("public".utf8).write(to: folder.appending(path: "cache/2fa-directory.json"))
        try Data().write(to: folder.appending(path: ".verrou.lock"))
        try Data().write(to: folder.appending(path: ".DS_Store"))
        try Data(#"{"version":1,"accounts":[],"default":null}"#.utf8).write(to: folder.appending(path: "accounts.json"))
    }

    /// The extension opened the group first and left scaffolding there: the
    /// private account is still copied (not skipped because an
    /// `accounts.json` exists), and the user stays signed in.
    func testExtensionOpenedTheGroupFirstThenMigrateMacCopiesThePrivateAccount() throws {
        let old = try makeOld()
        try makeScaffolding(at: new)
        XCTAssertFalse(VerrouStorage.hasAccount(in: new))

        let result = VerrouStorage.migrateMac(from: old, to: new, now: date)

        XCTAssertEqual(result, .migrated(backup: backupURL(of: old)))
        XCTAssertEqual(read(new.appending(path: "account.json")), #"{"email":"camille@exemple.fr","server":"https://vault.exemple.fr"}"#)
        XCTAssertEqual(read(new.appending(path: "outbox.json")), "file chiffrée", "the offline queue comes along")
        XCTAssertEqual(read(new.appending(path: "touchid.json")), "scellement", "and the Touch ID seal")
        XCTAssertFalse(fm.fileExists(atPath: old.path))
    }

    /// The same scaffolding with a registry that does list an account is not
    /// scaffolding: the group wins.
    func testGroupWithARealRegistryIsNeverScaffolding() throws {
        let old = try makeOld()
        try makeScaffolding(at: new)
        try Data(#"{"version":1,"accounts":[{"tag":"k3f7qa"}],"default":"k3f7qa"}"#.utf8)
            .write(to: new.appending(path: "accounts.json"))
        XCTAssertEqual(VerrouStorage.migrateMac(from: old, to: new, now: date), .nothingToDo)
        XCTAssertTrue(fm.fileExists(atPath: old.appending(path: "account.json").path))
    }

    /// Scaffolding plus a file that isn't Verrou's: refused, nothing erased.
    func testScaffoldingWithAnUnknownFileIsRefused() throws {
        let old = try makeOld()
        try makeScaffolding(at: new)
        try Data("?".utf8).write(to: new.appending(path: "unknown.json"))
        guard case .refused = VerrouStorage.migrateMac(from: old, to: new, now: date) else {
            return XCTFail("migration expected to be refused")
        }
        XCTAssertEqual(read(new.appending(path: "unknown.json")), "?")
        XCTAssertEqual(read(new.appending(path: "cache/2fa-directory.json")), "public")
    }

    // MARK: iPhone: private folder → group (`migrate(from:to:)`)

    func testMigrateMovesTheAccountIntoAMissingGroupFolder() throws {
        let old = try makeOld()
        VerrouStorage.migrate(from: old, to: new)
        XCTAssertFalse(fm.fileExists(atPath: old.path))
        XCTAssertEqual(read(new.appending(path: "outbox.json")), "file chiffrée")
    }

    func testMigrateMovesALayoutMigratedFolder() throws {
        let old = root.appending(path: "private", directoryHint: .isDirectory)
        try makeLayoutFolder(at: old, marker: "private")
        VerrouStorage.migrate(from: old, to: new)
        XCTAssertFalse(fm.fileExists(atPath: old.path))
        XCTAssertEqual(read(new.appending(path: "accounts/k3f7qa/account.json")), "private")
    }

    /// The bug the layout would have unleashed: the group root no longer has
    /// an `account.json` (it has `accounts.json`), a stale private folder
    /// still does, and the whole group folder, every account in it, was
    /// removed. Nothing is touched now.
    func testMigrateNeverErasesAGroupFolderThatHasTheRegistry() throws {
        let old = try makeOld()
        try makeLayoutFolder(at: new, marker: "group")
        let before = root.appending(path: "group-before")
        try fm.copyItem(at: new, to: before)

        VerrouStorage.migrate(from: old, to: new)

        XCTAssertTrue(try VerrouStorage.sameFiles(new, before), "the group folder is intact")
        XCTAssertTrue(fm.fileExists(atPath: old.appending(path: "account.json").path), "the stale folder stays")
    }

    func testMigrateNeverErasesAGroupFolderThatHoldsAnything() throws {
        let old = try makeOld()
        try fm.createDirectory(at: new, withIntermediateDirectories: true)
        try Data("?".utf8).write(to: new.appending(path: "unknown.json"))

        VerrouStorage.migrate(from: old, to: new)

        XCTAssertEqual(read(new.appending(path: "unknown.json")), "?")
        XCTAssertTrue(fm.fileExists(atPath: old.appending(path: "account.json").path))
        XCTAssertFalse(fm.fileExists(atPath: new.appending(path: "account.json").path))
    }

    func testMigrateNeverErasesAGroupFolderWithASingleAccount() throws {
        let old = try makeOld()
        try fm.createDirectory(at: new, withIntermediateDirectories: true)
        try Data("group".utf8).write(to: new.appending(path: "account.json"))
        VerrouStorage.migrate(from: old, to: new)
        XCTAssertEqual(read(new.appending(path: "account.json")), "group")
        XCTAssertTrue(fm.fileExists(atPath: old.appending(path: "account.json").path))
    }

    /// The group folder the extension (or `accountLocation`) created empty
    /// makes way for the account.
    func testMigrateReplacesAnEmptyGroupFolder() throws {
        let old = try makeOld()
        try fm.createDirectory(at: new, withIntermediateDirectories: true)
        try Data().write(to: new.appending(path: ".DS_Store"))
        VerrouStorage.migrate(from: old, to: new)
        XCTAssertFalse(fm.fileExists(atPath: old.path))
        XCTAssertEqual(read(new.appending(path: "outbox.json")), "file chiffrée")
    }

    func testMigrateWithoutAnAccountDoesNothing() throws {
        let old = root.appending(path: "empty-private", directoryHint: .isDirectory)
        try fm.createDirectory(at: old, withIntermediateDirectories: true)
        try Data("x".utf8).write(to: old.appending(path: "unrelated.txt"))
        VerrouStorage.migrate(from: old, to: new)
        XCTAssertTrue(fm.fileExists(atPath: old.path))
        XCTAssertFalse(fm.fileExists(atPath: new.path))
    }

    /// iPhone: the extension opened the group first, then the app moves the
    /// private account in.
    func testExtensionOpenedTheGroupFirstThenMigrateMovesThePrivateAccount() throws {
        let old = try makeOld()
        try makeScaffolding(at: new)

        VerrouStorage.migrate(from: old, to: new)

        XCTAssertFalse(fm.fileExists(atPath: old.path))
        XCTAssertEqual(read(new.appending(path: "outbox.json")), "file chiffrée")
        XCTAssertEqual(read(new.appending(path: "touchid.json")), "scellement")
        XCTAssertTrue(fm.fileExists(atPath: new.appending(path: "account.json").path))
    }

    func testMigrateNeverErasesScaffoldingWithAnUnknownFile() throws {
        let old = try makeOld()
        try makeScaffolding(at: new)
        try Data("?".utf8).write(to: new.appending(path: "unknown.json"))
        VerrouStorage.migrate(from: old, to: new)
        XCTAssertEqual(read(new.appending(path: "unknown.json")), "?")
        XCTAssertTrue(fm.fileExists(atPath: old.appending(path: "account.json").path))
    }
}
