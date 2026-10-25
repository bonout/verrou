import XCTest

/// Showcase of the iPhone app on the demo vault (launched by
/// `scripts/ios-showcase.sh`, nothing on the Mac's screen): each screen is
/// reached by real gestures, then the script takes its screenshot
/// (`simctl io screenshot`) when the test asks for it.
///
/// Variables (`TEST_RUNNER_` prefix on the xcodebuild side):
/// `VERROU_SHOWCASE_DIR` (exchange folder with the script: `req/<name>`
/// requests a screenshot, `ack/<name>` confirms it) and
/// `VERROU_SHOWCASE_PAUSE` (seconds of pause between the video's steps).
///
/// The showcase runs in English, on the demo vault's English words
/// (`VERROU_MOCK_LANG=en`): Emily Parker's vault.
@MainActor
final class ShowcaseUITests: XCTestCase {
    private let environment = ProcessInfo.processInfo.environment
    private var app = XCUIApplication()

    override func setUp() async throws {
        continueAfterFailure = false
    }

    // MARK: Tools

    /// Asks the script for the screenshot and waits for it to be taken.
    private func shot(_ name: String) {
        guard let dir = environment["VERROU_SHOWCASE_DIR"] else { return }
        // The screen settles (animations, scrolling).
        usleep(900_000)
        let base = URL(fileURLWithPath: dir)
        try? FileManager.default.createDirectory(at: base.appending(path: "req"), withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: base.appending(path: "req/\(name)").path, contents: nil)
        let ack = base.appending(path: "ack/\(name)").path
        let deadline = Date().addingTimeInterval(20)
        while !FileManager.default.fileExists(atPath: ack), Date() < deadline { usleep(200_000) }
        print("SHOWCASE_SHOT \(name)")
    }

    /// Timestamped marker to cut the video (`SHOWCASE_MARK <name> <seconds>`).
    private func mark(_ name: String) {
        print("SHOWCASE_MARK \(name) \(Date().timeIntervalSince1970)")
    }

    private func pause(_ factor: Double = 1) {
        guard let seconds = environment["VERROU_SHOWCASE_PAUSE"].flatMap(Double.init), seconds > 0 else { return }
        usleep(UInt32(seconds * factor * 1_000_000))
    }

    /// The simulator's language (scripts/ios-showcase.sh, SHOWCASE_LANG): the
    /// labels to look for and the demo vault follow it.
    private let language = String((Locale.preferredLanguages.first ?? "en").prefix(2))

    /// The app's strings (apple/VerrouiOS/Localizable.xcstrings, whose path
    /// the script passes): the label in the simulator's language.
    private static let catalog: [String: Any] = {
        guard let path = ProcessInfo.processInfo.environment["VERROU_CATALOG"],
              let data = FileManager.default.contents(atPath: path),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
        return json["strings"] as? [String: Any] ?? [:]
    }()

    /// The system's own buttons, which the app's catalog doesn't hold.
    private static let system: [String: [String: String]] = [
        "Continue": ["fr": "Continuer", "de": "Fortfahren", "es": "Continuar", "it": "Continua"],
        "Not Now": ["fr": "Plus tard", "de": "Nicht jetzt", "es": "Ahora no", "it": "Non ora"],
    ]

    /// A label in the simulator's language.
    private func L(_ english: String) -> String {
        guard language != "en" else { return english }
        if let text = Self.system[english]?[language] { return text }
        let entry = Self.catalog[english] as? [String: Any]
        let unit = ((entry?["localizations"] as? [String: Any])?[language] as? [String: Any])?["stringUnit"] as? [String: Any]
        return unit?["value"] as? String ?? english
    }

    /// The demo vault's owner (crates/verrou-core/src/mock.rs).
    private var owner: (dev: String, email: String) {
        switch language {
        case "fr": ("camille-dev", "camille.martin@exemple.fr")
        case "de": ("anna-dev", "anna.schneider@beispiel.de")
        case "es": ("lucia-dev", "lucia.garcia@ejemplo.es")
        case "it": ("giulia-dev", "giulia.rossi@esempio.it")
        default: ("emily-dev", "emily.parker@example.com")
        }
    }

    private var devUsername: String { owner.dev }

    /// The new item typed in the showcase.
    private var newItemTitle: String {
        ["fr": "Mon fournisseur d’accès", "de": "Mein Internetanbieter", "es": "Mi proveedor de internet",
         "it": "Il mio provider internet"][language] ?? "My internet provider"
    }

    private func launchMock(size: Int = 60, arguments: [String] = []) {
        app = XCUIApplication()
        app.launchEnvironment = ["VERROU_MOCK": "1", "VERROU_MOCK_SIZE": "\(size)", "VERROU_SHOWCASE": "1",
                                 "VERROU_MOCK_LANG": language]
        // iOS 17 fallbacks forced (TEST_RUNNER_VERROU_LEGACY_UI=1).
        if let legacy = environment["VERROU_LEGACY_UI"] { app.launchEnvironment["VERROU_LEGACY_UI"] = legacy }
        app.launchArguments = arguments
        app.launch()
    }

    /// Unlocks the demo vault with the password (any password works).
    private func unlock(slowly: Bool = false) {
        let field = app.secureTextFields[L("Master password")]
        // Face ID offered first: we choose the password.
        let usePassword = app.buttons["lock-use-password"]
        if !field.waitForExistence(timeout: 3), usePassword.waitForExistence(timeout: 20) {
            pause(0.5)
            usePassword.tap()
        }
        XCTAssertTrue(field.waitForExistence(timeout: 20), "lock screen")
        // The first tap may land during the appearance animation.
        for _ in 0..<4 {
            field.tap()
            if app.keyboards.firstMatch.waitForExistence(timeout: 3) { break }
        }
        if slowly {
            for letter in "verrou" {
                field.typeText(String(letter))
                usleep(120_000)
            }
            pause(0.5)
            field.typeText("\n")
        } else {
            field.typeText("verrou\n")
        }
        XCTAssertTrue(app.navigationBars[L("Vault")].waitForExistence(timeout: 20), "vault open")
    }

    private func openAllItems() {
        let all = app.descendants(matching: .any)[L("All items")].firstMatch
        XCTAssertTrue(all.waitForExistence(timeout: 10))
        all.tap()
        XCTAssertTrue(app.navigationBars[L("All items")].waitForExistence(timeout: 10), "list of all items")
    }

    private func back() {
        app.navigationBars.buttons.element(boundBy: 0).tap()
    }

    /// The whole vault's search field: the Search tab if it exists,
    /// otherwise the home screen's.
    private func searchField() -> XCUIElement {
        let tab = app.tabBars.buttons[L("Search")]
        if tab.exists {
            tab.tap()
        } else if app.buttons[L("Search")].exists, !app.searchFields.firstMatch.exists {
            app.buttons[L("Search")].tap()
        }
        let field = app.searchFields.firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 10), "search field")
        return field
    }

    /// Bilingual keyboard introduction (first use): dismissed.
    private func dismissKeyboardTip() {
        let proceed = app.buttons[L("Continue")].firstMatch
        if proceed.waitForExistence(timeout: 2) { proceed.tap() }
    }

    /// Taps a tab; `title`: expected title of the screen (otherwise no check).
    private func tapTab(_ label: String, title: String? = nil) {
        for _ in 0..<3 {
            let button = app.tabBars.buttons[label]
            if button.exists { button.tap() } else { app.buttons[label].firstMatch.tap() }
            guard let title else { return }
            if app.navigationBars[title].waitForExistence(timeout: 3) { return }
        }
        XCTFail("tab \(label)")
    }

    /// An item's row (exact title).
    private func row(_ title: String) -> XCUIElement {
        app.cells.containing(.staticText, identifier: title).firstMatch
    }

    // MARK: Screens

    func testShowcase() throws {
        // Sign-in: without an account or a demo vault.
        app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.textFields["login-server"].waitForExistence(timeout: 20), "sign-in screen")
        shot("01-sign-in")
        app.terminate()

        // Lock screen, home.
        launchMock()
        XCTAssertTrue(app.buttons["lock-use-password"].waitForExistence(timeout: 20)
                      || app.secureTextFields[L("Master password")].exists)
        shot("02-locked")
        unlock()
        shot("03-vault")

        // List, swipe actions, multiple selection.
        openAllItems()
        shot("04-list")
        let swiped = app.cells.element(boundBy: 2)
        swiped.swipeLeft()
        shot("05-swipe")
        swiped.swipeRight()
        usleep(500_000)
        app.buttons[L("Select")].firstMatch.tap()
        for index in [0, 1, 3] { app.cells.element(boundBy: index).tap() }
        shot("06-selection")
        app.buttons["OK"].firstMatch.tap()
        back()

        // Search.
        let field = searchField()
        field.tap()
        field.typeText("git")
        dismissKeyboardTip()
        XCTAssertTrue(row("GitHub").waitForExistence(timeout: 10), "search result")
        shot("07-search")

        // Item page: header, fields, one-time code; reveal, copy.
        row("GitHub").tap()
        XCTAssertTrue(app.staticTexts[devUsername].waitForExistence(timeout: 10), "item page open")
        if app.keyboards.firstMatch.exists { app.swipeDown() }
        shot("08-item")
        app.buttons[L("Show")].firstMatch.tap()
        app.staticTexts[L("Password")].firstMatch.tap()
        shot("09-item-copy")

        // Creating a login (the demo vault has no server to prepare the
        // edit of an existing item).
        tapTab(L("Vault"))
        usleep(600_000)
        let newItem = app.buttons[L("New item")].firstMatch
        if !newItem.waitForExistence(timeout: 2) {
            // Search still active on the home screen: the toolbar is collapsed.
            print("SHOWCASE_TREE \(app.debugDescription)")
            let cancel = app.buttons[L("Cancel")].firstMatch
            if cancel.exists { cancel.tap() } else if app.buttons[L("Close")].exists { app.buttons[L("Close")].firstMatch.tap() }
        }
        XCTAssertTrue(newItem.waitForExistence(timeout: 5), "New item button")
        newItem.tap()
        let login = app.buttons[L("Login")].firstMatch
        if !login.waitForExistence(timeout: 4) {
            // The menu didn't open (the screen was still moving): try again.
            newItem.tap()
            XCTAssertTrue(login.waitForExistence(timeout: 6), "New item menu")
        }
        login.tap()
        let title = app.textFields["edit-title"]
        XCTAssertTrue(title.waitForExistence(timeout: 10), "creation screen")
        title.typeText(newItemTitle)
        app.textFields[L("email or user name")].firstMatch.tap()
        // Return: the keyboard closes.
        app.typeText(owner.email + "\n")
        shot("10-edit")
        app.buttons[L("Cancel")].firstMatch.tap()
        // iOS offers to save the generated password: not this time.
        let later = app.buttons[L("Not Now")].firstMatch
        if later.waitForExistence(timeout: 3) { later.tap() }

        // Generator, settings, audit.
        tapTab(L("Generator"), title: L("Generator"))
        shot("11-generator")
        tapTab(L("Settings"), title: L("Settings"))
        shot("12-settings")
        let audit = app.buttons["settings-audit"].firstMatch
        for _ in 0..<6 where !(audit.exists && audit.isHittable) { app.swipeUp() }
        audit.tap()
        XCTAssertTrue(app.navigationBars[L("Security audit")].waitForExistence(timeout: 10), "audit")
        shot("13-audit")
        app.terminate()

        // Large text (Dynamic Type): list and item page.
        launchMock(arguments: ["-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityM"])
        unlock()
        openAllItems()
        shot("14-list-large-text")
        let github = row("GitHub")
        for _ in 0..<12 where !github.isHittable { app.swipeUp() }
        github.tap()
        XCTAssertTrue(app.staticTexts[devUsername].waitForExistence(timeout: 10), "item page open")
        shot("15-item-large-text")
    }

    // MARK: Animations (one video per moment, RECORD_TEST=testMotion…)

    /// Opens an item's page through the search.
    private func openItem(_ query: String, title: String) {
        let field = searchField()
        field.tap()
        field.typeText(query)
        dismissKeyboardTip()
        XCTAssertTrue(row(title).waitForExistence(timeout: 10), "result “\(title)”")
        row(title).tap()
        // No swipe to close the keyboard: it would close the item page (zoom).
        XCTAssertTrue(app.staticTexts[devUsername].waitForExistence(timeout: 10), "item page open")
    }

    /// Unlock: the password field, then the screen fading out.
    func testMotionUnlock() throws {
        launchMock(size: 2000)
        pause(1.5)
        mark("start")
        unlock(slowly: true)
        pause(2)
    }

    /// Revealing the password, then hiding and revealing again.
    func testMotionReveal() throws {
        launchMock()
        unlock()
        openItem("git", title: "GitHub")
        pause(1)
        mark("start")
        app.buttons[L("Show")].firstMatch.tap()
        pause(2)
        app.buttons["Hide"].firstMatch.tap()
        pause(1)
        app.buttons[L("Show")].firstMatch.tap()
        pause(2)
    }

    /// Archiving: the page turns to dust, the list comes back without the
    /// item.
    func testMotionArchive() throws {
        launchMock()
        unlock()
        openItem("git", title: "GitHub")
        pause(1)
        mark("start")
        app.buttons[L("Actions")].firstMatch.tap()
        app.buttons[L("Archive")].firstMatch.tap()
        XCTAssertTrue(app.navigationBars["GitHub"].waitForNonExistence(timeout: 5), "back to the list")
        pause(2)
    }

    /// Copy: the icon turns into a checkmark, then comes back.
    func testMotionCopy() throws {
        launchMock()
        unlock()
        openItem("git", title: "GitHub")
        pause(1)
        mark("start")
        app.buttons["quick-copy-password"].firstMatch.tap()
        pause(2.5)
        app.buttons["quick-copy-username"].firstMatch.tap()
        pause(2.5)
    }

    /// One-time code: end of the countdown and renewal.
    func testMotionTotp() throws {
        launchMock()
        unlock()
        openItem("git", title: "GitHub")
        // A whole period: the end of the countdown and the renewal.
        mark("start")
        pause(32)
    }

    /// Generator: new values, strength, length.
    func testMotionGenerator() throws {
        launchMock()
        unlock()
        tapTab(L("Generator"), title: L("Generator"))
        pause(1.5)
        mark("start")
        for _ in 0..<3 {
            app.buttons["Another"].firstMatch.tap()
            pause(1.6)
        }
        app.sliders.firstMatch.adjust(toNormalizedSliderPosition: 0.05)
        pause(1.6)
        app.sliders.firstMatch.adjust(toNormalizedSliderPosition: 0.6)
        pause(2)
    }

    /// The showcase video: unlock, scrolling, search, item page, copy,
    /// one-time code.
    func testRecording() throws {
        launchMock(size: 2000)
        pause(1.5)
        unlock(slowly: true)
        pause()
        openAllItems()
        pause(0.5)
        let list = app.collectionViews.firstMatch
        for _ in 0..<3 { list.swipeUp(velocity: .fast); usleep(400_000) }
        pause(0.5)
        list.swipeDown(velocity: .fast)
        pause(0.3)
        back()
        pause(0.5)
        let field = searchField()
        field.tap()
        for (index, letter) in "github".enumerated() {
            field.typeText(String(letter))
            // The bilingual keyboard introduction opens at the first letter.
            if index == 0 { dismissKeyboardTip() }
            usleep(220_000)
        }
        pause()
        row("GitHub").tap()
        pause(1.2)
        app.staticTexts[L("Password")].firstMatch.tap()
        pause(1.5)
        app.buttons[L("Show")].firstMatch.tap()
        pause(4)
    }
}
