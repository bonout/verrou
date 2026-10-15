import CryptoKit
import XCTest

/// Remplissage automatique de bout en bout, dans Safari du simulateur
/// (lancé par `scripts/ios-autofill-e2e.sh`, rien à l'écran du Mac) :
///
/// 1. l'app se connecte au Vaultwarden de test et publie ses identités ;
/// 2. un identifiant se remplit depuis la suggestion du clavier (Face ID
///    simulé, accepté en continu par le script) ;
/// 3. un code à usage unique se remplit (iOS 18+) ;
/// 4. une passkey est créée sur la page de test, qui vérifie l'attestation ;
/// 5. puis utilisée pour se connecter : la page vérifie la signature ES256.
///
/// Les tests s'enchaînent dans l'ordre de leur nom et partagent l'état du
/// simulateur. Variables (préfixe `TEST_RUNNER_` côté xcodebuild) :
/// `VERROU_AUTOFILL_E2E_*` (voir `AutoFillSetupDriver`), `_PAGE` (adresse de
/// la page de test), `_SHOTS` (dossier des captures, sur le Mac) et `_PAUSE`
/// (secondes d'arrêt aux étapes clés, pour une vidéo qu'on puisse suivre).
final class AutoFillUITests: XCTestCase {
    private let environment = ProcessInfo.processInfo.environment
    private lazy var safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")
    private let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")

    override func setUp() {
        continueAfterFailure = false
    }

    private func value(_ name: String) throws -> String {
        guard let value = environment["VERROU_AUTOFILL_E2E_\(name)"] else {
            throw XCTSkip("VERROU_AUTOFILL_E2E_\(name) absent : lancer scripts/ios-autofill-e2e.sh")
        }
        return value
    }

    private func shot(_ name: String) {
        guard let dir = environment["VERROU_AUTOFILL_E2E_SHOTS"] else { return }
        let data = XCUIScreen.main.screenshot().pngRepresentation
        try? data.write(to: URL(fileURLWithPath: dir).appending(path: "\(name).png"))
    }

    /// Arrêt aux étapes clés quand le script enregistre une vidéo
    /// (`VERROU_RECORD`) ; aucun sinon.
    private func pause() {
        guard let seconds = environment["VERROU_AUTOFILL_E2E_PAUSE"].flatMap(Double.init), seconds > 0 else { return }
        usleep(UInt32(seconds * 1_000_000))
    }

    /// Repère horodaté dans le journal, pour découper la vidéo.
    private func mark(_ name: String) {
        print("AUTOFILL_E2E_MARK \(name) \(Date().timeIntervalSince1970)")
    }

    /// Les arbres d'accessibilité, pour comprendre un échec.
    private func dump(_ label: String) {
        print("AUTOFILL_TREE \(label) — Safari:\n\(safari.debugDescription)")
        print("AUTOFILL_TREE \(label) — SpringBoard:\n\(springboard.debugDescription)")
    }

    /// Premier élément trouvé dans Safari ou SpringBoard (feuilles du
    /// système, interface de l'extension).
    private func find(_ timeout: TimeInterval, _ query: (XCUIApplication) -> XCUIElement) -> XCUIElement? {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            for app in [safari, springboard] {
                let element = query(app)
                if element.exists { return element }
            }
            usleep(300_000)
        } while Date() < deadline
        return nil
    }

    private func waitFor(_ timeout: TimeInterval, _ condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() {
            if Date() > deadline { return false }
            usleep(300_000)
        }
        return true
    }

    private func openPage() throws {
        let page = URL(string: try value("PAGE"))!
        let title = safari.webViews.staticTexts["Banc d'essai Verrou"]
        // Rechargée à chaque test (état de la page remis à zéro) ; une
        // seconde fois si le premier lancement de Safari l'a retardée.
        for _ in 0..<2 {
            safari.open(page)
            XCTAssertTrue(safari.wait(for: .runningForeground, timeout: 20))
            if title.waitForExistence(timeout: 15) { break }
        }
        XCTAssertTrue(title.exists, "page de test")
    }

    /// Touche le champ jusqu'à ce que le clavier s'ouvre (la page peut
    /// encore se poser).
    private func focus(_ field: XCUIElement) {
        for _ in 0..<4 {
            field.tap()
            if safari.keyboards.firstMatch.waitForExistence(timeout: 3) { return }
        }
    }

    private func pageText(_ prefix: String) -> String? {
        let texts = safari.webViews.staticTexts.allElementsBoundByIndex.map(\.label)
        return texts.first { $0.hasPrefix(prefix) }
    }

    // MARK: 1. L'app

    func test1_AppSignsInAndPublishes() throws {
        let ack = URL(fileURLWithPath: try value("ACK"))
        let app = XCUIApplication()
        for key in ["SERVER", "EMAIL", "PASSWORD", "TOTP", "SITE", "ACK"] {
            app.launchEnvironment["VERROU_AUTOFILL_E2E_\(key)"] = try value(key)
        }
        app.launch()
        let ready = waitFor(180) {
            FileManager.default.fileExists(atPath: ack.appending(path: "app-ready").path)
                || FileManager.default.fileExists(atPath: ack.appending(path: "app-failed").path)
        }
        let failure = try? String(contentsOf: ack.appending(path: "app-failed"), encoding: .utf8)
        XCTAssertTrue(ready && failure == nil, "préparation de l'app : \(failure ?? "délai dépassé")")
        let status = app.descendants(matching: .any)["autofill-status"]
        if !status.isHittable { app.swipeUp() }
        sleep(1)
        shot("01-app-reglages-remplissage")
        XCTAssertTrue(app.staticTexts["Activé"].waitForExistence(timeout: 10), "Verrou activé comme fournisseur")
    }

    // MARK: 2. Mot de passe

    func test2_PasswordFillsFromTheKeyboardSuggestion() throws {
        try openPage()
        mark("password")
        pause()
        let field = safari.webViews.textFields["Identifiant"]
        XCTAssertTrue(field.waitForExistence(timeout: 10))
        focus(field)
        let suggestion = find(20) { app in
            let fill = app.buttons["FillPasswordButton"]
            if fill.exists { return fill }
            return app.buttons.matching(NSPredicate(format: "label CONTAINS[c] %@", "camille@verrou.test")).firstMatch
        }
        shot("02-suggestion-clavier")
        guard let suggestion else {
            dump("suggestion")
            return XCTFail("aucune suggestion de Verrou au-dessus du clavier")
        }
        pause()
        suggestion.tap()
        // Face ID du système puis de Verrou (le script les accepte).
        sleep(3)
        shot("03-extension-deverrouillage")
        let filled = waitFor(60) {
            let field = self.safari.webViews.textFields["Identifiant"]
            return field.exists && (field.value as? String) == "camille@verrou.test"
        }
        if !filled { dump("remplissage") }
        XCTAssertTrue(filled, "identifiant rempli")
        shot("04-identifiant-rempli")
        pause()
        safari.webViews.buttons["Se connecter"].tap()
        XCTAssertTrue(waitFor(10) { self.pageText("user=") != nil })
        pause()
        XCTAssertEqual(pageText("user="), "user=camille@verrou.test pass=Verrou-AutoFill-42")
    }

    // MARK: 4–5. Passkey

    func test4_PasskeyIsCreatedInVerrou() throws {
        try openPage()
        mark("passkey-create")
        pause()
        safari.webViews.buttons["Créer une passkey"].tap()
        // Feuille du système : choisir « Enregistrer dans Verrou » (Mots de
        // passe d'Apple est coché par défaut), puis continuer.
        let proceed = find(20) { $0.descendants(matching: .any)["ASAuthorizationControllerContinueButton"] }
        guard let proceed else {
            dump("feuille de création")
            return XCTFail("pas de feuille de création de passkey")
        }
        // La feuille monte encore : attendre qu'elle ne bouge plus, sinon le
        // toucher tombe à côté et Mots de passe reste choisi.
        var frame = CGRect.null
        _ = waitFor(5) {
            defer { frame = proceed.frame }
            return proceed.frame == frame
        }
        let verrou = find(5) { app in
            app.buttons.matching(NSPredicate(format: "label CONTAINS[c] %@ AND label CONTAINS[c] %@",
                                             "Enregistrer", "Verrou")).firstMatch
        }
        guard let verrou else {
            dump("choix du fournisseur")
            return XCTFail("Verrou n'est pas proposé pour enregistrer la passkey")
        }
        for _ in 0..<3 {
            verrou.tap()
            if waitFor(2, { verrou.isSelected }) { break }
        }
        print("AUTOFILL_ROW \(verrou.debugDescription)")
        sleep(1)
        shot("05-passkey-feuille-systeme")
        pause()
        proceed.tap()
        // L'extension : Face ID, puis « Nouvel identifiant ».
        let newLogin = find(60) { $0.buttons["autofill-passkey-new"] }
        shot("06-passkey-extension")
        guard let newLogin else {
            dump("extension, création")
            return XCTFail("l'extension n'a pas proposé d'enregistrer la passkey")
        }
        pause()
        newLogin.tap()
        let created = waitFor(60) { self.pageText("CREATED ok") != nil || self.pageText("CREATE_ERROR") != nil }
        shot("07-passkey-creee")
        pause()
        if !created { dump("création") }
        XCTAssertNotNil(pageText("CREATED ok"), pageText("CREATE_ERROR") ?? "délai dépassé")
    }

    func test5_PasskeySignsInAndThePageVerifiesIt() throws {
        try openPage()
        mark("passkey-get")
        pause()
        safari.webViews.buttons["Se connecter avec la passkey"].tap()
        let proceed = find(20) { $0.descendants(matching: .any)["ASAuthorizationControllerContinueButton"] }
        if let proceed {
            // La feuille monte encore : la capturer une fois posée.
            var frame = CGRect.null
            _ = waitFor(5) {
                defer { frame = proceed.frame }
                return proceed.frame == frame
            }
        }
        shot("08-passkey-connexion-feuille")
        pause()
        if let proceed { proceed.tap() } else { dump("feuille de connexion") }
        let signed = waitFor(60) { self.pageText("SIGNED ok") != nil || self.pageText("GET_ERROR") != nil }
        // Le résultat s'affiche une fois la feuille refermée.
        _ = waitFor(5) { !self.safari.keyboards.firstMatch.exists && self.find(0) { $0.descendants(matching: .any)["ASAuthorizationControllerContinueButton"] } == nil }
        sleep(1)
        shot("09-passkey-signature-verifiee")
        pause()
        pause()
        mark("end")
        if !signed { dump("connexion") }
        let result = pageText("SIGNED ok")
        XCTAssertNotNil(result, pageText("GET_ERROR") ?? "délai dépassé")
        XCTAssertTrue(result?.contains("verified=true") == true && result?.contains("counter=1") == true, result ?? "")
    }

    // MARK: 3. Code à usage unique

    func test3_OneTimeCodeFills() throws {
        guard #available(iOS 18.0, *) else { throw XCTSkip("codes à usage unique : iOS 18 et plus") }
        try openPage()
        mark("otp")
        pause()
        let field = safari.webViews.textFields["Code"]
        XCTAssertTrue(field.waitForExistence(timeout: 10))
        focus(field)
        let suggestion = find(15) { app in
            // Pas « Verrou » seul : le bouton de retour à l'app de la barre
            // d'état porte aussi ce nom.
            // Un élément « Other » de la barre QuickType, pas un bouton.
            app.descendants(matching: .any)
                .matching(NSPredicate(format: "label CONTAINS[c] %@", "camille@verrou.test")).firstMatch
        }
        shot("10-code-suggestion")
        guard let suggestion else {
            dump("code")
            throw XCTSkip("aucune suggestion de code à usage unique dans ce simulateur")
        }
        pause()
        suggestion.tap()
        sleep(3)
        shot("10b-code-extension")
        // Pendant la feuille de l'extension, la page n'est pas lisible.
        let currentCode = { () -> String in
            let field = self.safari.webViews.textFields["Code"]
            return field.exists ? (field.value as? String ?? "") : ""
        }
        let filled = waitFor(60) { currentCode().count == 6 && currentCode().allSatisfy(\.isNumber) }
        shot("11-code-rempli")
        pause()
        if !filled { dump("code rempli") }
        XCTAssertTrue(filled, "code rempli : \(currentCode())")
        let code = currentCode()
        let now = Date().timeIntervalSince1970
        let expected = [-30.0, 0, 30].map { Self.totp("JBSWY3DPEHPK3PXP", at: now + $0) }
        XCTAssertTrue(expected.contains(code), "code \(code) ≠ \(expected)")
    }

    /// TOTP (RFC 6238, SHA-1, 6 chiffres, 30 s).
    static func totp(_ secret: String, at time: TimeInterval) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var bits = 0, value = 0
        var key = [UInt8]()
        for char in secret.uppercased() where char != "=" {
            guard let index = alphabet.firstIndex(of: char) else { continue }
            value = (value << 5) | index
            bits += 5
            if bits >= 8 {
                key.append(UInt8((value >> (bits - 8)) & 0xFF))
                bits -= 8
            }
        }
        var counter = UInt64(time / 30).bigEndian
        let message = Data(bytes: &counter, count: 8)
        let mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: key)))
        let offset = Int(mac[19] & 0x0F)
        let code = (UInt32(mac[offset] & 0x7F) << 24 | UInt32(mac[offset + 1]) << 16
            | UInt32(mac[offset + 2]) << 8 | UInt32(mac[offset + 3])) % 1_000_000
        return String(format: "%06u", code)
    }
}
