import XCTest

/// Vitrine de l'app iPhone sur le coffre fictif (lancée par
/// `scripts/ios-showcase.sh`, rien à l'écran du Mac) : chaque écran est
/// atteint par de vrais gestes, puis le script en prend la capture
/// (`simctl io screenshot`) quand le test la demande.
///
/// Variables (préfixe `TEST_RUNNER_` côté xcodebuild) :
/// `VERROU_SHOWCASE_DIR` (dossier d'échange avec le script : `req/<nom>`
/// demande une capture, `ack/<nom>` la confirme) et `VERROU_SHOWCASE_PAUSE`
/// (secondes d'arrêt entre les étapes de la vidéo).
final class ShowcaseUITests: XCTestCase {
    private let environment = ProcessInfo.processInfo.environment
    private var app = XCUIApplication()

    override func setUp() {
        continueAfterFailure = false
    }

    // MARK: Outils

    /// Demande la capture au script et attend qu'elle soit prise.
    private func shot(_ name: String) {
        guard let dir = environment["VERROU_SHOWCASE_DIR"] else { return }
        // L'écran se pose (animations, défilement).
        usleep(900_000)
        let base = URL(fileURLWithPath: dir)
        try? FileManager.default.createDirectory(at: base.appending(path: "req"), withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: base.appending(path: "req/\(name)").path, contents: nil)
        let ack = base.appending(path: "ack/\(name)").path
        let deadline = Date().addingTimeInterval(20)
        while !FileManager.default.fileExists(atPath: ack), Date() < deadline { usleep(200_000) }
        print("SHOWCASE_SHOT \(name)")
    }

    /// Repère horodaté pour découper la vidéo (`SHOWCASE_MARK <nom> <secondes>`).
    private func mark(_ name: String) {
        print("SHOWCASE_MARK \(name) \(Date().timeIntervalSince1970)")
    }

    private func pause(_ factor: Double = 1) {
        guard let seconds = environment["VERROU_SHOWCASE_PAUSE"].flatMap(Double.init), seconds > 0 else { return }
        usleep(UInt32(seconds * factor * 1_000_000))
    }

    private func launchMock(size: Int = 60, arguments: [String] = []) {
        app = XCUIApplication()
        app.launchEnvironment = ["VERROU_MOCK": "1", "VERROU_MOCK_SIZE": "\(size)", "VERROU_SHOWCASE": "1"]
        // Replis d'iOS 17 forcés (TEST_RUNNER_VERROU_LEGACY_UI=1).
        if let legacy = environment["VERROU_LEGACY_UI"] { app.launchEnvironment["VERROU_LEGACY_UI"] = legacy }
        app.launchArguments = arguments
        app.launch()
    }

    /// Déverrouille le coffre fictif par le mot de passe (tout mot de passe convient).
    private func unlock(slowly: Bool = false) {
        let field = app.secureTextFields["Mot de passe principal"]
        // Face ID proposé d'abord : on choisit le mot de passe.
        let usePassword = app.buttons["lock-use-password"]
        if !field.waitForExistence(timeout: 3), usePassword.waitForExistence(timeout: 20) {
            pause(0.5)
            usePassword.tap()
        }
        XCTAssertTrue(field.waitForExistence(timeout: 20), "écran verrouillé")
        // Le premier appui peut tomber pendant l'animation d'apparition.
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
        XCTAssertTrue(app.navigationBars["Coffre"].waitForExistence(timeout: 20), "coffre ouvert")
    }

    private func openAllItems() {
        let all = app.descendants(matching: .any)["Tous les éléments"].firstMatch
        XCTAssertTrue(all.waitForExistence(timeout: 10))
        all.tap()
        XCTAssertTrue(app.navigationBars["Tous les éléments"].waitForExistence(timeout: 10), "liste de tous les éléments")
    }

    private func back() {
        app.navigationBars.buttons.element(boundBy: 0).tap()
    }

    /// Le champ de recherche de tout le coffre : l'onglet Rechercher s'il
    /// existe, sinon celui de l'accueil.
    private func searchField() -> XCUIElement {
        let tab = app.tabBars.buttons["Rechercher"]
        if tab.exists {
            tab.tap()
        } else if app.buttons["Rechercher"].exists, !app.searchFields.firstMatch.exists {
            app.buttons["Rechercher"].tap()
        }
        let field = app.searchFields.firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 10), "champ de recherche")
        return field
    }

    /// Touche un onglet ; `title` : titre attendu de l'écran (sinon pas de vérification).
    /// Présentation du clavier bilingue (premier usage) : écartée.
    private func dismissKeyboardTip() {
        let proceed = app.buttons["Continue"].firstMatch
        if proceed.waitForExistence(timeout: 2) { proceed.tap() }
    }

    private func tapTab(_ label: String, title: String? = nil) {
        for _ in 0..<3 {
            let button = app.tabBars.buttons[label]
            if button.exists { button.tap() } else { app.buttons[label].firstMatch.tap() }
            guard let title else { return }
            if app.navigationBars[title].waitForExistence(timeout: 3) { return }
        }
        XCTFail("onglet \(label)")
    }

    /// La ligne d'un élément (titre exact).
    private func row(_ title: String) -> XCUIElement {
        app.cells.containing(.staticText, identifier: title).firstMatch
    }

    // MARK: Écrans

    func testShowcase() throws {
        // Connexion : sans compte ni coffre fictif.
        app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.textFields["login-server"].waitForExistence(timeout: 20), "écran de connexion")
        shot("01-connexion")
        app.terminate()

        // Écran verrouillé, accueil.
        launchMock()
        XCTAssertTrue(app.buttons["lock-use-password"].waitForExistence(timeout: 20)
                      || app.secureTextFields["Mot de passe principal"].exists)
        shot("02-verrouille")
        unlock()
        shot("03-coffre")

        // Liste, actions par balayage, sélection multiple.
        openAllItems()
        shot("04-liste")
        let swiped = app.cells.element(boundBy: 2)
        swiped.swipeLeft()
        shot("05-balayage")
        swiped.swipeRight()
        usleep(500_000)
        app.buttons["Choisir"].firstMatch.tap()
        for index in [0, 1, 3] { app.cells.element(boundBy: index).tap() }
        shot("06-selection")
        app.buttons["OK"].firstMatch.tap()
        back()

        // Recherche.
        let field = searchField()
        field.tap()
        field.typeText("git")
        dismissKeyboardTip()
        XCTAssertTrue(row("GitHub").waitForExistence(timeout: 10), "résultat de la recherche")
        shot("07-recherche")

        // Fiche : en-tête, champs, code à usage unique ; révélation, copie.
        row("GitHub").tap()
        XCTAssertTrue(app.staticTexts["camille-dev"].waitForExistence(timeout: 10), "fiche ouverte")
        if app.keyboards.firstMatch.exists { app.swipeDown() }
        shot("08-fiche")
        app.buttons["Afficher"].firstMatch.tap()
        app.staticTexts["Mot de passe"].firstMatch.tap()
        shot("09-fiche-copie")

        // Création d'un identifiant (le coffre fictif n'a pas de serveur pour
        // préparer la modification d'un élément existant).
        tapTab("Coffre")
        usleep(600_000)
        let newItem = app.buttons["Nouvel élément"].firstMatch
        if !newItem.waitForExistence(timeout: 2) {
            // Recherche encore active sur l'accueil : la barre d'outils est repliée.
            print("SHOWCASE_TREE \(app.debugDescription)")
            let cancel = app.buttons["Annuler"].firstMatch
            if cancel.exists { cancel.tap() } else if app.buttons["Fermer"].exists { app.buttons["Fermer"].firstMatch.tap() }
        }
        XCTAssertTrue(newItem.waitForExistence(timeout: 5), "bouton Nouvel élément")
        newItem.tap()
        let login = app.buttons["Identifiant"].firstMatch
        if !login.waitForExistence(timeout: 4) {
            // Le menu ne s'est pas ouvert (l'écran bougeait encore) : nouvel essai.
            newItem.tap()
            XCTAssertTrue(login.waitForExistence(timeout: 6), "menu Nouvel élément")
        }
        login.tap()
        let title = app.textFields["edit-title"]
        XCTAssertTrue(title.waitForExistence(timeout: 10), "écran de création")
        title.typeText("Mon fournisseur d'accès")
        app.textFields["e-mail ou nom d'utilisateur"].firstMatch.tap()
        // Retour : le clavier se ferme.
        app.typeText("camille.martin@exemple.fr\n")
        shot("10-modification")
        app.buttons["Annuler"].firstMatch.tap()
        // iOS propose d'enregistrer le mot de passe généré : pas cette fois.
        let later = app.buttons["Plus tard"].firstMatch
        if later.waitForExistence(timeout: 3) { later.tap() }

        // Générateur, réglages, audit.
        tapTab("Générateur", title: "Générateur")
        shot("11-generateur")
        tapTab("Réglages", title: "Réglages")
        shot("12-reglages")
        let audit = app.buttons["settings-audit"].firstMatch
        for _ in 0..<6 where !(audit.exists && audit.isHittable) { app.swipeUp() }
        audit.tap()
        XCTAssertTrue(app.navigationBars["Audit de sécurité"].waitForExistence(timeout: 10), "audit")
        shot("13-audit")
        app.terminate()

        // Grand texte (Dynamic Type) : liste et fiche.
        launchMock(arguments: ["-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityM"])
        unlock()
        openAllItems()
        shot("14-liste-grand-texte")
        let github = row("GitHub")
        for _ in 0..<12 where !github.isHittable { app.swipeUp() }
        github.tap()
        XCTAssertTrue(app.staticTexts["camille-dev"].waitForExistence(timeout: 10), "fiche ouverte")
        shot("15-fiche-grand-texte")
    }

    // MARK: Animations (une vidéo par moment, RECORD_TEST=testMotion…)

    /// Ouvre la fiche d'un élément par la recherche.
    private func openItem(_ query: String, title: String) {
        let field = searchField()
        field.tap()
        field.typeText(query)
        dismissKeyboardTip()
        XCTAssertTrue(row(title).waitForExistence(timeout: 10), "résultat « \(title) »")
        row(title).tap()
        // Pas de balayage pour fermer le clavier : il refermerait la fiche (zoom).
        XCTAssertTrue(app.staticTexts["camille-dev"].waitForExistence(timeout: 10), "fiche ouverte")
    }

    /// Déverrouillage : le champ du mot de passe, puis l'écran qui s'efface.
    func testMotionUnlock() throws {
        launchMock(size: 2000)
        pause(1.5)
        mark("start")
        unlock(slowly: true)
        pause(2)
    }

    /// Révélation du mot de passe, puis masquage et nouvelle révélation.
    func testMotionReveal() throws {
        launchMock()
        unlock()
        openItem("git", title: "GitHub")
        pause(1)
        mark("start")
        app.buttons["Afficher"].firstMatch.tap()
        pause(2)
        app.buttons["Masquer"].firstMatch.tap()
        pause(1)
        app.buttons["Afficher"].firstMatch.tap()
        pause(2)
    }

    /// Copie : l'icône passe à la coche, puis revient.
    func testMotionCopy() throws {
        launchMock()
        unlock()
        openItem("git", title: "GitHub")
        pause(1)
        mark("start")
        app.buttons["quick-copy-Mot de passe"].firstMatch.tap()
        pause(2.5)
        app.buttons["quick-copy-Identifiant"].firstMatch.tap()
        pause(2.5)
    }

    /// Code à usage unique : fin du décompte et renouvellement.
    func testMotionTotp() throws {
        launchMock()
        unlock()
        openItem("git", title: "GitHub")
        // Une période entière : la fin du décompte et le renouvellement.
        mark("start")
        pause(32)
    }

    /// Générateur : nouvelles valeurs, robustesse, longueur.
    func testMotionGenerator() throws {
        launchMock()
        unlock()
        tapTab("Générateur", title: "Générateur")
        pause(1.5)
        mark("start")
        for _ in 0..<3 {
            app.buttons["Autre"].firstMatch.tap()
            pause(1.6)
        }
        app.sliders.firstMatch.adjust(toNormalizedSliderPosition: 0.05)
        pause(1.6)
        app.sliders.firstMatch.adjust(toNormalizedSliderPosition: 0.6)
        pause(2)
    }

    /// La vidéo de la vitrine : déverrouillage, défilement, recherche, fiche,
    /// copie, code à usage unique.
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
            // La présentation du clavier bilingue s'ouvre à la première lettre.
            if index == 0 { dismissKeyboardTip() }
            usleep(220_000)
        }
        pause()
        row("GitHub").tap()
        pause(1.2)
        app.staticTexts["Mot de passe"].firstMatch.tap()
        pause(1.5)
        app.buttons["Afficher"].firstMatch.tap()
        pause(4)
    }
}
