import XCTest

/// Défilement de la liste sur un coffre fictif de 2 000 éléments (lancé par
/// `scripts/ios-bench.sh`) : saccades mesurées par les signposts de
/// défilement d'UIKit (`XCTOSSignpostMetric.scrollingAndDecelerationMetric`).
final class ScrollPerformanceUITests: XCTestCase {
    override func setUp() {
        continueAfterFailure = false
    }

    func testScrollAllItems() throws {
        let app = XCUIApplication()
        app.launchEnvironment = ["VERROU_MOCK": "1", "VERROU_MOCK_SIZE": "2000"]
        app.launch()
        let field = app.secureTextFields["Mot de passe principal"]
        XCTAssertTrue(field.waitForExistence(timeout: 20), "écran verrouillé")
        field.tap()
        field.typeText("verrou\n")
        let all = app.descendants(matching: .any)["Tous les éléments"].firstMatch
        XCTAssertTrue(all.waitForExistence(timeout: 20), "coffre ouvert")
        all.tap()
        XCTAssertTrue(app.navigationBars["Tous les éléments"].waitForExistence(timeout: 10))
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
