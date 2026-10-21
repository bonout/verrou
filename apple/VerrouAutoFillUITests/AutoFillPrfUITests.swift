import XCTest

/// End-to-end WebAuthn PRF extension (iOS 18+), after tests 1 to 5 of
/// `AutoFillUITests` (app signed in, Verrou chosen as provider): the
/// `prf.html` page creates a passkey with `extensions.prf`, then signs in
/// twice evaluating PRF; it checks itself that the outputs are stable and
/// differ from one input to the other.
extension AutoFillUITests {
    func test6_PrfOutputsAreStableAndDifferPerSalt() throws {
        guard #available(iOS 18.0, *) else { throw XCTSkip("PRF: iOS 18 and later") }
        guard let base = ProcessInfo.processInfo.environment["VERROU_AUTOFILL_E2E_PAGE"] else {
            throw XCTSkip("VERROU_AUTOFILL_E2E_PAGE not set: run scripts/ios-autofill-e2e.sh")
        }
        let safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        func find(_ timeout: TimeInterval, _ query: (XCUIApplication) -> XCUIElement) -> XCUIElement? {
            let deadline = Date().addingTimeInterval(timeout)
            repeat {
                for app in [safari, springboard] where query(app).exists { return query(app) }
                usleep(300_000)
            } while Date() < deadline
            return nil
        }
        func result(_ timeout: TimeInterval, _ prefixes: [String]) -> String? {
            let deadline = Date().addingTimeInterval(timeout)
            repeat {
                let texts = safari.webViews.staticTexts.allElementsBoundByIndex.map(\.label)
                if let hit = texts.first(where: { text in prefixes.contains { text.hasPrefix($0) } }) { return hit }
                usleep(300_000)
            } while Date() < deadline
            return nil
        }
        func dump(_ label: String) {
            print("AUTOFILL_TREE \(label) — Safari:\n\(safari.debugDescription)")
            print("AUTOFILL_TREE \(label) — SpringBoard:\n\(springboard.debugDescription)")
        }
        /// The system sheet, once settled.
        func continueButton() -> XCUIElement? {
            guard let proceed = find(20, { $0.descendants(matching: .any)["ASAuthorizationControllerContinueButton"] })
            else { return nil }
            var frame = CGRect.null
            let deadline = Date().addingTimeInterval(5)
            while proceed.frame != frame, Date() < deadline {
                frame = proceed.frame
                usleep(300_000)
            }
            return proceed
        }

        // PRF page.
        let title = safari.webViews.staticTexts["PRF test bench"]
        for _ in 0..<2 {
            safari.open(URL(string: base + "prf.html")!)
            XCTAssertTrue(safari.wait(for: .runningForeground, timeout: 20))
            if title.waitForExistence(timeout: 15) { break }
        }
        XCTAssertTrue(title.exists, "PRF page")

        // Creation, in Verrou.
        safari.webViews.buttons["Create a PRF passkey"].tap()
        guard let proceed = continueButton() else {
            dump("PRF, creation sheet")
            return XCTFail("no passkey creation sheet")
        }
        if let verrou = find(5, { app in
            app.buttons.matching(NSPredicate(format: "label CONTAINS[c] %@ AND label CONTAINS[c] %@",
                                             "Save", "Verrou")).firstMatch
        }) {
            for _ in 0..<3 where !verrou.isSelected {
                verrou.tap()
                usleep(700_000)
            }
        }
        proceed.tap()
        guard let newLogin = find(60, { $0.buttons["autofill-passkey-new"] }) else {
            dump("PRF, extension")
            return XCTFail("the extension didn't offer to save the passkey")
        }
        newLogin.tap()
        let created = result(60, ["PRF_CREATED", "PRF_CREATE_ERROR"])
        print("AUTOFILL_PRF creation: \(created ?? "timed out")")
        XCTAssertEqual(created?.hasPrefix("PRF_CREATED ok enabled=true"), true, created ?? "timed out")

        // Two sign-ins: `eval` (A, B), then `evalByCredential` (A).
        for (button, prefix) in [("PRF sign-in", "PRF_SIGNED"), ("PRF sign-in by passkey", "PRF_BYCRED")] {
            safari.webViews.buttons[button].tap()
            if let proceed = continueButton() { proceed.tap() } else { dump("PRF, feuille de connexion") }
            let signed = result(60, ["\(prefix) ok", "\(prefix)_ERROR", "PRF_GET_ERROR"])
            print("AUTOFILL_PRF \(button): \(signed ?? "timed out")")
            XCTAssertEqual(signed?.hasPrefix("\(prefix) ok stable=true"), true, signed ?? "timed out")
            if prefix == "PRF_SIGNED" {
                XCTAssertEqual(signed?.contains("differ=true"), true, signed ?? "")
            }
            // The next result must not be confused with this one.
            sleep(2)
        }
        let screenshot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        screenshot.lifetime = .keepAlways
        add(screenshot)
    }
}
