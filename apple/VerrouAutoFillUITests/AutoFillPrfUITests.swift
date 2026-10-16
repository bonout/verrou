import XCTest

/// Extension PRF de WebAuthn de bout en bout (iOS 18+), après les tests 1 à
/// 5 d'`AutoFillUITests` (app connectée, Verrou choisi comme fournisseur) :
/// la page `prf.html` crée une passkey avec `extensions.prf`, puis se
/// connecte deux fois en évaluant la PRF ; elle vérifie elle-même que les
/// sorties sont stables et diffèrent d'une entrée à l'autre.
extension AutoFillUITests {
    func test6_PrfOutputsAreStableAndDifferPerSalt() throws {
        guard #available(iOS 18.0, *) else { throw XCTSkip("PRF : iOS 18 et plus") }
        guard let base = ProcessInfo.processInfo.environment["VERROU_AUTOFILL_E2E_PAGE"] else {
            throw XCTSkip("VERROU_AUTOFILL_E2E_PAGE absent : lancer scripts/ios-autofill-e2e.sh")
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
        /// La feuille du système, une fois posée.
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

        // Page PRF.
        let title = safari.webViews.staticTexts["Banc d'essai PRF"]
        for _ in 0..<2 {
            safari.open(URL(string: base + "prf.html")!)
            XCTAssertTrue(safari.wait(for: .runningForeground, timeout: 20))
            if title.waitForExistence(timeout: 15) { break }
        }
        XCTAssertTrue(title.exists, "page PRF")

        // Création, dans Verrou.
        safari.webViews.buttons["Créer une passkey PRF"].tap()
        guard let proceed = continueButton() else {
            dump("PRF, feuille de création")
            return XCTFail("pas de feuille de création de passkey")
        }
        if let verrou = find(5, { app in
            app.buttons.matching(NSPredicate(format: "label CONTAINS[c] %@ AND label CONTAINS[c] %@",
                                             "Enregistrer", "Verrou")).firstMatch
        }) {
            for _ in 0..<3 where !verrou.isSelected {
                verrou.tap()
                usleep(700_000)
            }
        }
        proceed.tap()
        guard let newLogin = find(60, { $0.buttons["autofill-passkey-new"] }) else {
            dump("PRF, extension")
            return XCTFail("l'extension n'a pas proposé d'enregistrer la passkey")
        }
        newLogin.tap()
        let created = result(60, ["PRF_CREATED", "PRF_CREATE_ERROR"])
        print("AUTOFILL_PRF création : \(created ?? "délai dépassé")")
        XCTAssertEqual(created?.hasPrefix("PRF_CREATED ok enabled=true"), true, created ?? "délai dépassé")

        // Deux connexions : `eval` (A, B), puis `evalByCredential` (A).
        for (button, prefix) in [("Connexion PRF", "PRF_SIGNED"), ("Connexion PRF par passkey", "PRF_BYCRED")] {
            safari.webViews.buttons[button].tap()
            if let proceed = continueButton() { proceed.tap() } else { dump("PRF, feuille de connexion") }
            let signed = result(60, ["\(prefix) ok", "\(prefix)_ERROR", "PRF_GET_ERROR"])
            print("AUTOFILL_PRF \(button) : \(signed ?? "délai dépassé")")
            XCTAssertEqual(signed?.hasPrefix("\(prefix) ok stable=true"), true, signed ?? "délai dépassé")
            if prefix == "PRF_SIGNED" {
                XCTAssertEqual(signed?.contains("differ=true"), true, signed ?? "")
            }
            // Le résultat suivant ne doit pas être confondu avec celui-ci.
            sleep(2)
        }
        let screenshot = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        screenshot.lifetime = .keepAlways
        add(screenshot)
    }
}
