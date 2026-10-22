import XCTest

/// *Try the Demo Vault* on the sign-in screen (what App Review sees): opens
/// the demo vault without a server, and leaving it goes back to sign-in.
/// Needs an iPhone with no account (a fresh Simulator), in English.
final class DemoVaultUITests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
    }

    func testTryAndLeaveTheDemoVault() {
        let app = XCUIApplication()
        app.launch()

        let tryDemo = app.buttons["try-demo"]
        XCTAssertTrue(tryDemo.waitForExistence(timeout: 20), "sign-in screen")
        tryDemo.tap()
        XCTAssertTrue(app.navigationBars["Vault"].waitForExistence(timeout: 20), "demo vault open")

        let settings = app.tabBars.buttons["Settings"]
        if settings.exists { settings.tap() } else { app.buttons["Settings"].firstMatch.tap() }
        let leave = app.buttons["Leave the Demo Vault"]
        for _ in 0..<5 where !leave.isHittable { app.swipeUp() }
        leave.tap()
        XCTAssertTrue(tryDemo.waitForExistence(timeout: 20), "back to sign-in")
    }
}
