import XCTest

/// Apple's accessibility audit (VoiceOver descriptions, contrast, hit
/// regions, clipped text…) on the main screens of the Mac app, with the
/// mock vault. Opens the app on screen: run it from Xcode or
/// `xcodebuild test -scheme VerrouMacUITests`.
final class AccessibilityAuditUITests: XCTestCase {
    private var app: XCUIApplication!
    private var issues: [String] = []

    override func setUp() {
        continueAfterFailure = true
        app = XCUIApplication()
        app.launchEnvironment["VERROU_MOCK"] = "1"
        app.launch()
    }

    override func tearDown() {
        app.terminate()
    }

    func testMainScreensPassTheAudit() throws {
        let window = app.windows.firstMatch
        XCTAssertTrue(window.waitForExistence(timeout: 10))
        audit("lock screen")

        let password = window.secureTextFields.firstMatch
        XCTAssertTrue(password.waitForExistence(timeout: 5))
        password.click()
        password.typeText("demo\r")
        XCTAssertTrue(window.outlines.firstMatch.waitForExistence(timeout: 10))
        audit("vault")

        let search = window.textFields.firstMatch
        search.click()
        search.typeText("github")
        audit("search")

        app.typeKey(",", modifierFlags: .command)
        XCTAssertTrue(app.windows.element(boundBy: 0).waitForExistence(timeout: 5))
        audit("settings")

        if !issues.isEmpty {
            XCTFail("\(issues.count) accessibility issues:\n" + issues.joined(separator: "\n"))
        }
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
