import XCTest

/// Scrolling the list on a demo vault of 2,000 items (launched by
/// `scripts/ios-bench.sh`): hitches measured by UIKit's scrolling signposts
/// (`XCTOSSignpostMetric.scrollingAndDecelerationMetric`).
@MainActor
final class ScrollPerformanceUITests: XCTestCase {
    override func setUp() async throws {
        continueAfterFailure = false
    }

    func testScrollAllItems() throws {
        let app = XCUIApplication()
        app.launchEnvironment = ["VERROU_MOCK": "1", "VERROU_MOCK_SIZE": "2000"]
        app.launch()
        let field = app.secureTextFields["Master password"]
        XCTAssertTrue(field.waitForExistence(timeout: 20), "lock screen")
        field.tap()
        field.typeText("verrou\n")
        let all = app.descendants(matching: .any)["All items"].firstMatch
        XCTAssertTrue(all.waitForExistence(timeout: 20), "vault open")
        all.tap()
        XCTAssertTrue(app.navigationBars["All items"].waitForExistence(timeout: 10))
        let list = app.collectionViews.firstMatch

        let options = XCTMeasureOptions()
        options.invocationOptions = [.manuallyStop]
        options.iterationCount = 8
        measure(metrics: [XCTOSSignpostMetric.scrollingAndDecelerationMetric], options: options) {
            list.swipeUp(velocity: .fast)
            stopMeasuring()
            list.swipeDown(velocity: .fast)
        }
    }
}
