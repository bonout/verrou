#if DEBUG
import AppKit
import SwiftUI

/// Revue visuelle hors écran (`VERROU_REVIEW=1`, builds Debug) : chaque écran
/// de l'app, rendu sur le coffre fictif dans une fenêtre jamais affichée, en
/// clair et en sombre, puis écrit en PNG. Ni ScreenCaptureKit, ni activation :
/// l'app n'a pas le droit d'avoir de fenêtre à l'écran (`.prohibited`), et
/// la revue échoue si l'une d'elles devient visible.
///
/// Annonce `REVIEW_OUT <dossier>`, `REVIEW_SNAP <nom>` par image,
/// `REVIEW_OK`/`REVIEW_FAIL` pour l'audit de mise en page de chaque écran
/// (`LayoutAudit`), puis `REVIEW_DONE`. Lancée par `scripts/review-capture.sh`.
///
/// Ne lit ni n'écrit le compte : le coffre fictif vit en mémoire, et les
/// préférences des vues (`@AppStorage`) vont dans un domaine à part, effacé
/// à la fin.
@MainActor
final class ReviewDriver: NSObject, NSApplicationDelegate {
    private static var current: ReviewDriver?

    static func run() {
        let app = NSApplication.shared
        // Ni Dock, ni fenêtre, ni activation.
        app.setActivationPolicy(.prohibited)
        let driver = ReviewDriver()
        current = driver
        app.delegate = driver
        app.run()
    }

    private static let defaultsSuite = "app.verrou.review"
    private let model = AppModel()
    private let defaults = UserDefaults(suiteName: ReviewDriver.defaultsSuite) ?? .standard
    private let output = FileManager.default.temporaryDirectory.appending(path: "verrou-review")
    /// Fenêtre principale : 1280 × 800, comme les captures de la démonstration.
    private let mainSize = NSSize(width: 1280, height: 800)
    /// Zone de contenu de la fenêtre principale : la hauteur permise d'une feuille.
    private var sheetLimit: CGFloat = 740
    private var failures = 0

    func applicationDidFinishLaunching(_ notification: Notification) {
        Task {
            await run()
            defaults.removePersistentDomain(forName: Self.defaultsSuite)
            // Le fichier vide du domaine reste sinon dans le conteneur.
            try? FileManager.default.removeItem(at: URL.libraryDirectory
                .appending(path: "Preferences/\(Self.defaultsSuite).plist"))
            log(failures == 0 ? "REVIEW_DONE" : "REVIEW_DONE \(failures) écran(s) en échec")
            exit(failures == 0 ? 0 : 1)
        }
    }

    private func log(_ line: String) {
        print(line)
        fflush(stdout)
    }

    // MARK: Parcours

    private func run() async {
        try? FileManager.default.removeItem(at: output)
        try? FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        log("REVIEW_OUT \(output.path)")
        defaults.removePersistentDomain(forName: Self.defaultsSuite)
        // Ni demande d'autorisation ni notification réelle pendant la revue.
        ActivityNotifier.shared.silent = true

        // Écrans d'avant le coffre.
        await screen("01-verrouille", root: RootView(), expect: .init(identifiers: ["lock-title"]))
        model.loginEmail = "camille.martin@exemple.fr"
        model.reviewLogin(true)
        await screen("02-connexion", root: RootView(), expect: .init(identifiers: ["login-title"]))
        model.reviewLogin(true, twoFactor: [.authenticator, .email])
        await screen("03-second-facteur", root: RootView(), expect: .init(identifiers: ["login-title"]))
        model.reviewLogin(false)
        // « Créer un compte », lien d'invitation collé (lu hors ligne).
        let registration = RegistrationFlow(server: "", email: "")
        registration.link = Self.mockInviteLink
        registration.name = "Léa Martin"
        registration.password = "fixe-pivoine-monceaux-couteau"
        registration.confirmation = registration.password
        await screen("04-creer-un-compte", root: LoginView(registration: registration),
                     expect: .init(identifiers: ["login-title"]))
        registration.reset()

        // Coffre : une fiche de chaque sorte.
        model.openVault()
        let vault = LayoutAudit.Expectation(identifiers: ["search", "detail-title", "sidebar-footer"], columns: 3)
        let items: [(String, SidebarFilter, String, String)] = [
            ("10-identifiant", .all, "", "GitHub"),
            ("11-carte", .category(category: .card), "", "Visa Boursorama"),
            ("12-identite", .category(category: .identity), "", "Camille Martin"),
            ("13-wifi", .template(template: .wifi), "", "Wi-Fi maison"),
            ("14-cle-ssh", .category(category: .sshKey), "", ""),
            ("15-coffre-partage", .all, "famille", "Google — famille"),
        ]
        for (name, filter, query, title) in items {
            model.filter = filter
            model.query = query
            select(title)
            await screen(name, root: RootView(), expect: vault)
        }
        model.query = ""
        model.filter = .all
        select("GitHub")

        // Volets de la barre latérale.
        let pane = LayoutAudit.Expectation(identifiers: ["pane-title", "sidebar-footer", "detail-title"], columns: 3)
        model.openAudit()
        await screen("20-audit", root: RootView(), expect: pane)
        model.sends.set(Self.mockSends())
        model.pane = .sends
        await screen("21-envois", root: RootView(), expect: pane)
        model.emergency.set(Self.mockEmergency())
        model.pane = .emergency
        await screen("22-urgence", root: RootView(), expect: pane)
        if let organization = model.organizations.first {
            model.members.preview = true
            model.openMembers(organization.id)
            model.members.set(Self.mockMembers(collection: organization.collections.first?.id ?? ""),
                              organizationID: organization.id)
            model.members.selection = "mb-lea"
            await screen("23-membres-a-confirmer", root: RootView(), expect: pane)
            model.members.selection = "mb-alex"
            await screen("24-membre-confirme", root: RootView(), expect: pane)
            // Invitation envoyée : « Et ensuite ? » (e-mail, réseau, confirmation).
            model.members.selection = "mb-tom"
            var invited = pane
            invited.identifiers.append("invitation-next-steps")
            await screen("24b-membre-invite", root: RootView(), expect: invited)
        } else {
            fail("23-membres-a-confirmer", "pas d'organisation dans le coffre fictif")
        }
        // Coffres partagés : une invitation acceptée en attente de
        // confirmation, et des membres à confirmer dans l'organisation.
        if let organization = model.organizations.first {
            model.organizationAdmin.preview = true
            model.organizationAdmin.pending = [PendingMembershipView(organizationId: "org-escalade", name: "Club d'escalade")]
            model.organizationAdmin.toConfirm = [organization.id: 1]
            model.filter = .organization(id: organization.id)
            select("")
            // Fenêtre plus haute : la section est sous les dossiers.
            await screen("16-coffres-partages", root: RootView(), size: NSSize(width: 1280, height: 1400), expect: vault)
        }
        model.filter = .all

        // Feuilles, rendues seules à leur taille (comme posées sur la fenêtre).
        await sheets()

        // Accès rapide.
        model.quickQuery = "net"
        await screen("40-acces-rapide", root: QuickAccessView(autofill: nil, close: {}), size: nil,
                     expect: .init(), chrome: false)
        model.quickQuery = ""
        model.lock()
    }

    private func sheets() async {
        let sheet = LayoutAudit.Expectation(identifiers: ["sheet-primary"], maxHeight: sheetLimit)
        // Le coffre fictif est en lecture seule : brouillon composé ici, comme
        // celui que le serveur donnerait pour GitHub.
        if let github = id(of: "GitHub") {
            let draft = ItemDraft(name: "GitHub", folderId: nil, favorite: true, notes: "Codes de secours dans le coffre.",
                                  login: LoginFields(username: "camille-dev", password: "hunter2-hunter2-hunter2",
                                                     totp: "JBSWY3DPEHPK3PXP", urls: ["https://github.com"]),
                                  fields: [], template: nil)
            await screen("30-modification-identifiant",
                         root: EditItemView(editor: .init(itemID: github, draft: draft)),
                         size: nil, expect: withTitle(sheet, "edit-title"), chrome: false)
            var custom = draft
            custom.fields += [
                CustomField(name: "Code PIN", value: "1234", fieldType: .hidden, linkedId: nil),
                CustomField(name: "Question secrète", value: "Le nom du premier chat", fieldType: .text, linkedId: nil),
                CustomField(name: "Double authentification", value: "true", fieldType: .boolean, linkedId: nil),
            ]
            await screen("31-modification-champs",
                         root: EditItemView(editor: .init(itemID: github, draft: custom)),
                         size: nil, expect: withTitle(sheet, "edit-title"), chrome: false)
        } else {
            fail("30-modification-identifiant", "GitHub introuvable dans le coffre fictif")
        }
        await screen("32-generateur", root: GeneratorView(use: { _, _ in }), size: nil, expect: .init(), chrome: false)

        let tabs: [(String, SettingsTab)] = [
            ("33-reglages-general", .general), ("34-reglages-securite", .security),
            ("35-reglages-compte", .account), ("36-reglages-navigateurs", .integrations),
        ]
        for (name, tab) in tabs {
            defaults.set(tab.rawValue, forKey: "settingsTab")
            await screen(name, root: SettingsView(), size: nil, expect: .init(), chrome: false)
        }

        // Membres : invitation, puis modification d'un membre.
        if model.membersOrganization != nil {
            let collection = model.membersOrganization?.collections.first?.id ?? ""
            await screen("39-inviter-membres",
                         root: MemberEditorView(draft: MemberDraft(member: nil, emails: "tom@exemple.fr, sam@exemple.fr",
                                                                   role: .user, access: [collection: .edit])),
                         size: nil, expect: withTitle(sheet, "sheet-title"), chrome: false)
            if let alex = model.members.members.first(where: { $0.id == "mb-alex" }) {
                model.editMember(alex)
                if let draft = model.members.draft {
                    await screen("39-modifier-membre", root: MemberEditorView(draft: draft), size: nil,
                                 expect: withTitle(sheet, "sheet-title"), chrome: false)
                }
                model.members.draft = nil
            }
        }

        await sharingSheets(sheet)

        // Doublons fictifs (imports d'Apple, de 1Password, de Proton Pass) :
        // le coffre fictif n'en a pas.
        let duplicates = DuplicatesFlow(defaults: defaults)
        duplicates.load(demoDuplicates())
        await screen("37-doublons", root: DuplicatesView(flow: duplicates), size: nil,
                     expect: withTitle(sheet, "sheet-title"), chrome: false)
        // Un groupe ignoré, un élément gardé à la main.
        if let google = duplicates.visible.first(where: { $0.label == "google.com" }),
           let routeur = duplicates.visible.first(where: { $0.members.count == 2 && $0.confidence == .probable }) {
            duplicates.ignore(routeur)
            duplicates.keep(google.members[2].item.id, in: google)
            // Cocher l'élément gardé : il part à la corbeille, un autre est gardé.
            let first = google.members[2].item.id
            let before = duplicates.selected
            duplicates.toggle(first, true, in: google)
            if !duplicates.selected.contains(first) || duplicates.keptID(google) == first
                || duplicates.selected.contains(duplicates.keptID(google)) {
                fail("37b-doublons-ignores", "cocher l'élément gardé n'en garde pas un autre")
            }
            // Tout cocher : le dernier élément non coché reste gardé.
            for member in google.members { duplicates.toggle(member.item.id, true, in: google) }
            if google.members.allSatisfy({ duplicates.selected.contains($0.item.id) }) {
                fail("37b-doublons-ignores", "tous les éléments d'un groupe sont cochés")
            }
            duplicates.selected = before
            duplicates.keep(first, in: google)
        }
        await screen("37b-doublons-ignores", root: DuplicatesView(flow: duplicates), size: nil,
                     expect: withTitle(sheet, "sheet-title"), chrome: false)
        duplicates.clearIgnored()

        // Import : un export d'Apple fictif, comparé au coffre fictif.
        let csv = output.appending(path: "export-fictif.csv")
        let lines = [
            "Title,URL,Username,Password,Notes,OTPAuth",
            "GitHub,https://github.com,camille.martin@exemple.fr,un-autre-mot-de-passe,,",
            "Mastodon,https://mastodon.social,camille,correct-cheval-pile,,",
            "Strava,https://www.strava.com,camille.martin@exemple.fr,velo-annecy-2026,,",
            "Strava,https://www.strava.com,camille.martin@exemple.fr,velo-annecy-2027,,",
            "Impots,https://www.impots.gouv.fr,1234567890123,motdepasse,,",
        ]
        try? lines.joined(separator: "\n").write(to: csv, atomically: true, encoding: .utf8)
        let flow = ImportFlow(url: csv)
        model.importFlow = flow
        await model.readImport(flow)
        model.importFlow = nil
        try? FileManager.default.removeItem(at: csv)
        if flow.review != nil {
            await screen("38-import", root: ImportView(flow: flow), size: nil,
                         expect: withTitle(sheet, "sheet-title"), chrome: false)
        } else {
            fail("38-import", "l'export fictif n'a pas été lu")
        }
        model.session.cancelImport()
    }

    /// Partage : plusieurs éléments, nouvelle organisation, collection et
    /// ses accès, groupes, invitation collée.
    private func sharingSheets(_ sheet: LayoutAudit.Expectation) async {
        guard let organization = model.organizations.first,
              let collection = organization.collections.first else {
            fail("41-partager-plusieurs", "pas d'organisation dans le coffre fictif")
            return
        }
        let titled = withTitle(sheet, "sheet-title")
        let personal = model.summaries.filter { $0.sharing == nil && $0.state == .active }.prefix(3).map(\.id)
        let flow = SharingFlow(itemIDs: Array(personal), title: "\(personal.count) éléments", current: nil,
                               organizationID: organization.id, collectionIDs: [collection.id])
        await screen("41-partager-plusieurs", root: SharingView(flow: flow), size: nil, expect: titled, chrome: false)
        await screen("42-nouvelle-organisation", root: NewOrganizationView(), size: nil, expect: titled, chrome: false)
        let members = Self.mockMembers(collection: collection.id)
        var draft = CollectionDraft(organizationID: organization.id, collectionID: collection.id, name: collection.name)
        draft.members = members
        draft.memberAccess = ["mb-alex": .edit, "mb-lea": .viewExceptPasswords, "mb-tom": .view]
        draft.loading = false
        await screen("43-collection", root: CollectionEditorView(draft: draft), size: nil, expect: titled, chrome: false)
        let groups = [
            OrganizationGroup(id: "gr-parents", name: "Parents", members: ["mb-camille", "mb-alex"],
                              collections: [MemberCollectionAccess(collectionId: collection.id, readOnly: false,
                                                                   hidePasswords: false, manage: true)]),
            OrganizationGroup(id: "gr-enfants", name: "Enfants", members: ["mb-lea"],
                              collections: [MemberCollectionAccess(collectionId: collection.id, readOnly: true,
                                                                   hidePasswords: true, manage: false)]),
        ]
        let groupsDraft = GroupsDraft(organizationID: organization.id, groups: groups, members: members, loading: false)
        await screen("44-groupes", root: GroupsView(draft: groupsDraft), size: nil, expect: titled, chrome: false)
        await screen("44b-groupe", root: GroupsView(draft: groupsDraft, editing: GroupDraft(groups[1])), size: nil,
                     expect: titled, chrome: false)
        await screen("45-rejoindre", root: JoinOrganizationView(link: Self.mockInviteLink), size: nil,
                     expect: titled, chrome: false)
        // Rien de collé : où trouver le lien, et pourquoi l'invitation n'est
        // pas listée avant d'être acceptée.
        await screen("45b-rejoindre-vide", root: JoinOrganizationView(), size: nil, expect: titled, chrome: false)
        await screen("46-renommer", root: RenameOrganizationView(organization: organization), size: nil,
                     expect: titled, chrome: false)
    }

    private func withTitle(_ base: LayoutAudit.Expectation, _ identifier: String) -> LayoutAudit.Expectation {
        var expectation = base
        expectation.identifiers.insert(identifier, at: 0)
        return expectation
    }

    private func id(of title: String) -> String? {
        model.summaries.first { $0.title == title }?.id
    }

    /// Sélectionne l'élément de ce titre parmi les résultats (le premier si vide).
    private func select(_ title: String) {
        model.selection = title.isEmpty
            ? model.results.first?.id
            : model.results.first { model.summary(for: $0)?.title == title }?.id
    }

    private func fail(_ name: String, _ message: String) {
        failures += 1
        log("REVIEW_FAIL \(name) : \(message)")
    }

    // MARK: Rendu

    /// Rend `root` en clair puis en sombre. `size` : taille de la fenêtre
    /// (`nil` : celle que demande la vue, comme une feuille) ; `chrome` :
    /// fenêtre à barre d'outils, comme la principale.
    private func screen<V: View>(_ name: String, root: V, size: NSSize? = nil, expect: LayoutAudit.Expectation,
                                 chrome: Bool = true) async {
        for dark in [false, true] {
            let window = makeWindow(chrome: chrome)
            window.appearance = NSAppearance(named: dark ? .darkAqua : .aqua)
            let host = NSHostingController(rootView: AnyView(
                root.environment(model).defaultAppStorage(defaults)))
            host.sceneBridgingOptions = chrome ? [.toolbars, .title] : []
            if size == nil && !chrome { host.sizingOptions = .preferredContentSize }
            window.contentViewController = host
            let frame = chrome ? NSRect(origin: Self.offscreen, size: size ?? mainSize) : nil
            if let frame { window.setFrame(frame, display: false) }
            // SwiftUI met à jour au tour de boucle suivant (tâches, `onAppear`).
            for _ in 0..<6 {
                window.contentView?.layoutSubtreeIfNeeded()
                try? await Task.sleep(for: .milliseconds(150))
            }
            if !chrome {
                window.setContentSize(size ?? host.view.fittingSize)
                window.contentView?.layoutSubtreeIfNeeded()
                try? await Task.sleep(for: .milliseconds(100))
            }
            if chrome, size == nil { sheetLimit = window.contentLayoutRect.height }

            let visible = NSApp.windows.filter(\.isVisible)
            if !visible.isEmpty {
                fail(name, "une fenêtre est apparue à l'écran ("
                    + visible.map { "\(type(of: $0)) \(Int($0.frame.minX)),\(Int($0.frame.minY)) \(Int($0.frame.width))×\(Int($0.frame.height))" }
                        .joined(separator: ", ") + ")")
                visible.forEach { $0.orderOut(nil) }
            }
            if !dark {
                var expectation = expect
                if chrome { expectation.size = frame?.size }
                let problems = LayoutAudit.problems(in: window, expectation)
                if problems.isEmpty {
                    log("REVIEW_OK \(name) : mise en page")
                } else {
                    fail(name, "mise en page cassée : " + problems.joined(separator: " ; "))
                }
            }
            write(window, chrome: chrome, to: "\(name)-\(dark ? "sombre" : "clair")")
            window.contentViewController = nil
            window.close()
        }
    }

    private static let offscreen = NSPoint(x: -30_000, y: -30_000)

    private func makeWindow(chrome: Bool) -> NSWindow {
        let style: NSWindow.StyleMask = chrome
            ? [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView]
            : [.borderless]
        let window = ReviewWindow(contentRect: NSRect(origin: Self.offscreen, size: mainSize), styleMask: style,
                                  backing: .buffered, defer: true)
        window.isReleasedWhenClosed = false
        window.animationBehavior = .none
        if chrome {
            window.toolbarStyle = .unified
            window.titleVisibility = .hidden
        }
        return window
    }

    /// Dessin de la fenêtre par AppKit (`cacheDisplay`), sans passer par
    /// l'écran : barre de titre et barre d'outils comprises si `chrome`. Les
    /// matériaux translucides (barre latérale) sont rendus opaques.
    private func write(_ window: NSWindow, chrome: Bool, to name: String) {
        guard let content = window.contentView else { return }
        let view = chrome ? (content.superview ?? content) : content
        view.layoutSubtreeIfNeeded()
        guard let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
            fail(name, "rendu impossible")
            return
        }
        // Bords de défilement (flou, miroir du contenu) : `cacheDisplay` ne
        // sait pas les dessiner, on les retire le temps du rendu.
        var hidden: [NSView] = []
        func hideEffects(_ inner: NSView) {
            let name = String(describing: type(of: inner))
            if !inner.isHidden, name == "NSScrollPocket" || name == "BackdropView" || name == "PortalView" {
                inner.isHidden = true
                hidden.append(inner)
                return
            }
            inner.subviews.forEach(hideEffects)
        }
        hideEffects(view)
        defer { hidden.forEach { $0.isHidden = false } }
        view.cacheDisplay(in: view.bounds, to: rep)
        compositeGlass(in: view, onto: rep)
        guard let data = rep.representation(using: .png, properties: [:]) else { return }
        do {
            try data.write(to: output.appending(path: "\(name).png"))
            log("REVIEW_SNAP \(name)")
        } catch {
            fail(name, "écriture : \(error.localizedDescription)")
        }
    }

    /// `cacheDisplay` ne dessine ni les effets de verre (barre latérale,
    /// groupes de la barre d'outils) ni ce qu'ils contiennent : on peint un
    /// fond opaque à leur place, puis leur contenu par-dessus.
    private func compositeGlass(in root: NSView, onto rep: NSBitmapImageRep) {
        var glasses: [NSView] = []
        func visit(_ view: NSView) {
            if view.isHidden { return }
            // Vue transparente (le coffre monté derrière l'écran verrouillé) : rien à peindre.
            if view.alphaValue < 0.01 || (view.layer?.opacity ?? 1) < 0.01 { return }
            if String(describing: type(of: view)).contains("GlassEffectView") {
                glasses.append(view)
                return
            }
            view.subviews.forEach(visit)
        }
        visit(root)
        guard !glasses.isEmpty, let context = NSGraphicsContext(bitmapImageRep: rep) else { return }
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = context
        // Le contexte du bitmap est déjà en points (`rep.size`).
        if root.isFlipped {
            context.cgContext.translateBy(x: 0, y: root.bounds.height)
            context.cgContext.scaleBy(x: 1, y: -1)
        }
        let dark = root.effectiveAppearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
        for glass in glasses {
            let frame = glass.convert(glass.bounds, to: root)
            let radius = min(14, frame.height / 2)
            (dark ? NSColor(white: 0.16, alpha: 1) : NSColor(white: 0.95, alpha: 1)).setFill()
            NSBezierPath(roundedRect: frame, xRadius: radius, yRadius: radius).fill()
            for content in drawable(in: glass) {
                // Seulement la partie visible : une cellule défilée hors de la
                // liste ne doit pas recouvrir le pied de la barre latérale.
                let shown = content.visibleRect
                guard !shown.isEmpty,
                      let image = content.bitmapImageRepForCachingDisplay(in: content.bounds) else { continue }
                content.cacheDisplay(in: content.bounds, to: image)
                NSGraphicsContext.saveGraphicsState()
                NSBezierPath(rect: content.convert(shown, to: root)).setClip()
                // …ni passer sous le pied (dessiné sur un matériau que
                // `cacheDisplay` laisse transparent) : la zone utile de la liste.
                if let scroll = content.enclosingScrollView, content !== scroll {
                    let insets = scroll.contentInsets
                    var useful = scroll.bounds
                    useful.size.height -= insets.top + insets.bottom
                    useful.origin.y += scroll.isFlipped ? insets.top : insets.bottom
                    NSBezierPath(rect: scroll.convert(useful, to: root)).addClip()
                }
                image.draw(in: content.convert(content.bounds, to: root), from: .zero, operation: .sourceOver,
                           fraction: 1, respectFlipped: true, hints: nil)
                NSGraphicsContext.restoreGraphicsState()
            }
        }
        context.flushGraphics()
        NSGraphicsContext.restoreGraphicsState()
    }

    /// Fenêtre de rendu : jamais clé, jamais de champ actif. Un champ de mot
    /// de passe actif ferait apparaître le panneau de remplissage automatique
    /// du système, une vraie fenêtre à l'écran.
    private final class ReviewWindow: NSWindow {
        override var canBecomeKey: Bool { false }
        override var canBecomeMain: Bool { false }
        override func makeFirstResponder(_ responder: NSResponder?) -> Bool {
            responder == nil || responder === self ? super.makeFirstResponder(responder) : false
        }
    }

    /// Ce qu'un effet de verre contient et que `cacheDisplay` sait dessiner :
    /// les vues SwiftUI et les éléments de la barre d'outils.
    private func drawable(in glass: NSView) -> [NSView] {
        var found: [NSView] = []
        func visit(_ view: NSView) {
            if view.isHidden { return }
            let name = String(describing: type(of: view))
            if name.hasPrefix("NSHostingView") || name.hasPrefix("CellHostingView") || view is NSControl {
                found.append(view)
                // Les listes (tables AppKit) ne se dessinent pas avec la vue
                // qui les porte : leurs cellules, par-dessus.
                var tables: [NSView] = []
                func findTables(_ inner: NSView) {
                    if inner is NSTableView { tables.append(inner); return }
                    inner.subviews.forEach(findTables)
                }
                view.subviews.forEach(findTables)
                tables.forEach { $0.subviews.forEach(visit) }
                return
            }
            view.subviews.forEach(visit)
        }
        glass.subviews.forEach(visit)
        return found
    }

    // MARK: Données fictives

    private static func mockSends() -> [SendSummary] {
        let now = Int64(Date().timeIntervalSince1970)
        let day: Int64 = 86_400
        return [
            SendSummary(id: "send-wifi", name: "Wi-Fi du chalet", content: .text, fileName: nil, fileSize: nil,
                        hasPassword: true, accessCount: 2, maxAccessCount: 5, disabled: false, hideEmail: false,
                        deletionDate: now + 6 * day, expirationDate: now + 2 * day, revisionDate: now - 3_600,
                        available: true),
            SendSummary(id: "send-bail", name: "Bail de l'appartement signé.pdf", content: .file,
                        fileName: "Bail de l'appartement signé.pdf", fileSize: 1_482_000, hasPassword: false,
                        accessCount: 1, maxAccessCount: nil, disabled: false, hideEmail: true,
                        deletionDate: now + 13 * day, expirationDate: nil, revisionDate: now - 2 * day,
                        available: true),
            SendSummary(id: "send-porte", name: "Code de la porte", content: .text, fileName: nil, fileSize: nil,
                        hasPassword: false, accessCount: 3, maxAccessCount: 3, disabled: false, hideEmail: false,
                        deletionDate: now + day, expirationDate: now - day, revisionDate: now - 5 * day,
                        available: false),
        ]
    }

    private static let mockInviteLink = "https://vault.exemple.fr/#/accept-organization/?email=lea.martin%40exemple.fr"
        + "&organizationName=Famille%20Martin&organizationId=8e2d4f1a-0000-4000-8000-000000000001"
        + "&organizationUserId=8e2d4f1a-0000-4000-8000-000000000002&token=eyJ0eXAiOiJKV1QifQ.e30.c2lnbmF0dXJl"
        + "&initOrganization=false&orgUserHasExistingUser=false"

    private static func mockMembers(collection: String) -> [OrganizationMember] {
        let access = { (readOnly: Bool, hide: Bool) in
            [MemberCollectionAccess(collectionId: collection, readOnly: readOnly, hidePasswords: hide, manage: false)]
        }
        return [
            OrganizationMember(id: "mb-camille", userId: "u-camille", name: "Camille Martin",
                               email: "camille.martin@exemple.fr", role: .owner, status: .confirmed, accessAll: true,
                               collections: [], twoFactorEnabled: true, hasAccount: true),
            OrganizationMember(id: "mb-alex", userId: "u-alex", name: "Alex Martin", email: "alex.martin@exemple.fr",
                               role: .user, status: .confirmed, accessAll: false, collections: access(false, false),
                               twoFactorEnabled: true, hasAccount: true),
            OrganizationMember(id: "mb-lea", userId: "u-lea", name: "Léa Martin", email: "lea.martin@exemple.fr",
                               role: .user, status: .accepted, accessAll: false, collections: access(true, true),
                               twoFactorEnabled: false, hasAccount: true),
            OrganizationMember(id: "mb-tom", userId: "u-tom", name: nil, email: "tom@exemple.fr",
                               role: .user, status: .invited, accessAll: false, collections: access(true, false),
                               twoFactorEnabled: false, hasAccount: false),
            OrganizationMember(id: "mb-sam", userId: "u-sam", name: "Sam Bernard", email: "sam@exemple.fr",
                               role: .manager, status: .revoked, accessAll: false, collections: access(false, false),
                               twoFactorEnabled: false, hasAccount: true),
        ]
    }

    private static func mockEmergency() -> EmergencyOverview {
        EmergencyOverview(
            trusted: [
                EmergencyContact(id: "em-alex", userId: "u-alex", name: "Alex Martin", email: "alex.martin@exemple.fr",
                                 accessType: .view, state: .confirmed, waitTimeDays: 7),
                EmergencyContact(id: "em-sam", userId: "u-sam", name: nil, email: "sam@exemple.fr",
                                 accessType: .takeover, state: .accepted, waitTimeDays: 14),
            ],
            granted: [
                EmergencyContact(id: "em-lou", userId: "u-lou", name: "Lou Bernard", email: "lou.bernard@exemple.fr",
                                 accessType: .view, state: .recoveryInitiated, waitTimeDays: 3),
            ])
    }
}
#endif
