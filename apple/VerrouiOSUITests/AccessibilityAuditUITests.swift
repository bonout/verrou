import XCTest

@MainActor
final class AccessibilityAuditUITests: XCTestCase {
    private var app: XCUIApplication!
    private var issues: [String] = []

    override func setUp() async throws {
        continueAfterFailure = true
        app = XCUIApplication()
        app.launchEnvironment = ["VERROU_MOCK": "1", "VERROU_MOCK_SIZE": "60", "VERROU_SHOWCASE": "1",
                                 "VERROU_MOCK_LANG": "en"]
        app.launch()
    }

    override func tearDown() async throws {
        app.terminate()
    }

    func testMainScreensPassTheAudit() throws {
        let field = app.secureTextFields["Master password"]
        let usePassword = app.buttons["lock-use-password"]
        XCTAssertTrue(field.waitForExistence(timeout: 5) || usePassword.waitForExistence(timeout: 20), "lock screen")
        audit("lock screen")

        if !field.exists, usePassword.exists { usePassword.tap() }
        XCTAssertTrue(field.waitForExistence(timeout: 10), "master password field")
        for _ in 0..<4 {
            field.tap()
            if app.keyboards.firstMatch.waitForExistence(timeout: 3) { break }
        }
        field.typeText("verrou\n")
        XCTAssertTrue(app.navigationBars["Vault"].waitForExistence(timeout: 20), "vault open")
        audit("home")

        let all = app.descendants(matching: .any)["tile-all"].firstMatch
        XCTAssertTrue(all.waitForExistence(timeout: 10), "All items tile")
        all.tap()
        XCTAssertTrue(app.navigationBars["All items"].waitForExistence(timeout: 10), "list of all items")
        let github = app.cells.containing(.staticText, identifier: "GitHub").firstMatch
        for _ in 0..<12 where !github.isHittable { app.swipeUp() }
        github.tap()
        XCTAssertTrue(app.navigationBars["GitHub"].waitForExistence(timeout: 10), "item page")
        audit("item page")

        let edit = app.navigationBars["GitHub"].buttons["Edit"]
        XCTAssertTrue(edit.waitForExistence(timeout: 5), "Edit button")
        edit.tap()
        XCTAssertTrue(app.textFields["edit-title"].waitForExistence(timeout: 10), "edit screen")
        audit("edit screen")
        app.buttons["Cancel"].firstMatch.tap()
        let discard = app.buttons["Discard Changes"].firstMatch
        if discard.waitForExistence(timeout: 2) { discard.tap() }
        XCTAssertTrue(app.navigationBars["GitHub"].waitForExistence(timeout: 10), "edit screen closed")

        tapTab("Generator")
        audit("generator")

        tapTab("Settings")
        audit("settings")

        if !issues.isEmpty {
            XCTFail("\(issues.count) accessibility issues:\n" + issues.joined(separator: "\n"))
        }
    }

    private func tapTab(_ label: String) {
        for _ in 0..<3 {
            let button = app.tabBars.buttons[label]
            if button.exists { button.tap() } else { app.buttons[label].firstMatch.tap() }
            if app.navigationBars[label].waitForExistence(timeout: 3) { return }
        }
        XCTFail("tab \(label)")
    }

    private func audit(_ screen: String) {
        do {
            try app.performAccessibilityAudit { issue in
                let element = issue.element.map { "\($0.elementType.rawValue) “\($0.label)” \($0.identifier)" } ?? "?"
                self.issues.append("[\(screen)] \(issue.auditType): \(issue.compactDescription) — \(element)")
                return true
            }
        } catch {
            issues.append("[\(screen)] audit failed: \(error)")
        }
    }
}
