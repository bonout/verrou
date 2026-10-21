#if DEBUG
import AppKit
import SwiftUI

/// Offscreen visual review (`VERROU_REVIEW=1`, Debug builds): each screen of
/// the app, rendered on the mock vault in a window never shown, in light and
/// dark mode, then written as PNG. Neither ScreenCaptureKit nor activation:
/// the app is not allowed to have a window on screen (`.prohibited`), and
/// the review fails if one of them becomes visible.
///
/// Announces `REVIEW_OUT <folder>`, `REVIEW_SNAP <name>` per image,
/// `REVIEW_OK`/`REVIEW_FAIL` for the layout audit of each screen
/// (`LayoutAudit`), then `REVIEW_DONE`. Launched by `scripts/review-capture.sh`.
///
/// Neither reads nor writes the account: the mock vault lives in memory, and
/// the views' preferences (`@AppStorage`) go to a separate domain, erased at
/// the end.
@MainActor
final class ReviewDriver: NSObject, NSApplicationDelegate {
    private static var current: ReviewDriver?

    static func run() {
        let app = NSApplication.shared
        // No Dock, no window, no activation.
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
    /// Main window: 1280 × 800, like the demo's captures.
    private let mainSize = NSSize(width: 1280, height: 800)
    /// Content area of the main window: the allowed height of a sheet.
    private var sheetLimit: CGFloat = 740
    private var failures = 0

    func applicationDidFinishLaunching(_ notification: Notification) {
        Task {
            await run()
            defaults.removePersistentDomain(forName: Self.defaultsSuite)
            // Otherwise the domain's empty file stays in the container.
            try? FileManager.default.removeItem(at: URL.libraryDirectory
                .appending(path: "Preferences/\(Self.defaultsSuite).plist"))
            log(failures == 0 ? "REVIEW_DONE" : "REVIEW_DONE \(failures) failing screen(s)")
            exit(failures == 0 ? 0 : 1)
        }
    }

    private func log(_ line: String) {
        print(line)
        fflush(stdout)
    }

    // MARK: Walk

    private func run() async {
        try? FileManager.default.removeItem(at: output)
        try? FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
        log("REVIEW_OUT \(output.path)")
        defaults.removePersistentDomain(forName: Self.defaultsSuite)
        // No permission request and no real notification during the review.
        ActivityNotifier.shared.silent = true

        // Screens before the vault.
        await screen("01-locked", root: RootView(), expect: .init(identifiers: ["lock-title"]))
        model.loginEmail = "camille.martin@exemple.fr"
        model.reviewLogin(true)
        await screen("02-login", root: RootView(), expect: .init(identifiers: ["login-title"]))
        model.reviewLogin(true, twoFactor: [.authenticator, .email])
        await screen("03-second-factor", root: RootView(), expect: .init(identifiers: ["login-title"]))
        model.reviewLogin(false)
        // "Create an Account", invitation link pasted (read offline).
        let registration = RegistrationFlow(server: "", email: "")
        registration.link = Self.mockInviteLink
        registration.name = "Léa Martin"
        registration.password = "fixe-pivoine-monceaux-couteau"
        registration.confirmation = registration.password
        await screen("04-create-account", root: LoginView(registration: registration),
                     expect: .init(identifiers: ["login-title"]))
        registration.reset()

        // Vault: a detail of each kind.
        model.openVault()
        let vault = LayoutAudit.Expectation(identifiers: ["search", "detail-title", "sidebar-footer"], columns: 3)
        let items: [(String, SidebarFilter, String, String)] = [
            ("10-login", .all, "", "GitHub"),
            ("11-card", .category(category: .card), "", "Visa Boursorama"),
            ("12-identity", .category(category: .identity), "", "Camille Martin"),
            ("13-wifi", .template(template: .wifi), "", "Wi-Fi maison"),
            ("14-ssh-key", .category(category: .sshKey), "", ""),
            ("15-shared-vault", .all, "famille", "Google — famille"),
        ]
        for (name, filter, query, title) in items {
            model.filter = filter
            model.query = query
            select(title)
            await screen(name, root: RootView(), expect: vault)
        }
        model.query = ""
        // Passkeys: the filtered view, site and user of each passkey.
        model.filter = .passkeys
        select("GitHub")
        await screen("17-passkeys", root: RootView(), expect: vault)
        // Sort by last use (this Mac's log).
        model.filter = .all
        for title in ["Netflix", "GitHub", "Impôts"] {
            if let id = id(of: title) { model.session.recordItemUse(id: id) }
        }
        model.afterWrite(select: id(of: "Netflix"))
        model.sort = .lastUsed
        select("Netflix")
        await screen("18-sort-last-used", root: RootView(), expect: vault)
        model.sort = .relevance
        select("GitHub")

        // Sidebar panes.
        let pane = LayoutAudit.Expectation(identifiers: ["pane-title", "sidebar-footer", "detail-title"], columns: 3)
        model.openAudit()
        await model.watchtower.loadPasskeys(model.session)
        await screen("20-audit", root: RootView(), expect: pane)
        // "Passkey available": the section at the top of the pane.
        if model.watchtower.passkeys?.candidates.isEmpty ?? true {
            fail("20b-audit-passkeys", "no passkey available in the mock vault")
        }
        model.watchtower.focus = "passkeys"
        await screen("20b-audit-passkeys", root: RootView(),
                     expect: .init(identifiers: ["create-passkey", "sidebar-footer", "detail-title"], columns: 3))
        model.watchtower.focus = nil
        model.sends.set(Self.mockSends())
        model.pane = .sends
        await screen("21-sends", root: RootView(), expect: pane)
        model.emergency.set(Self.mockEmergency())
        model.pane = .emergency
        await screen("22-emergency", root: RootView(), expect: pane)
        if let organization = model.organizations.first {
            model.members.preview = true
            model.openMembers(organization.id)
            model.members.set(Self.mockMembers(collection: organization.collections.first?.id ?? ""),
                              organizationID: organization.id)
            model.members.selection = "mb-lea"
            await screen("23-members-to-confirm", root: RootView(), expect: pane)
            model.members.selection = "mb-alex"
            await screen("24-member-confirmed", root: RootView(), expect: pane)
            // Invitation sent: "What's next?" (email, network, confirmation).
            model.members.selection = "mb-tom"
            var invited = pane
            invited.identifiers.append("invitation-next-steps")
            await screen("24b-member-invited", root: RootView(), expect: invited)
        } else {
            fail("23-members-to-confirm", "no organization in the mock vault")
        }
        // Shared vaults: an accepted invitation waiting for confirmation,
        // and members to confirm in the organization.
        if let organization = model.organizations.first {
            model.organizationAdmin.preview = true
            model.organizationAdmin.pending = [PendingMembershipView(organizationId: "org-escalade", name: "Club d'escalade")]
            model.organizationAdmin.toConfirm = [organization.id: 1]
            model.filter = .organization(id: organization.id)
            select("")
            // Taller window: the section is under the folders.
            await screen("16-shared-vaults", root: RootView(), size: NSSize(width: 1280, height: 1400), expect: vault)
        }
        model.filter = .all

        // Sheets, rendered alone at their size (as if attached to the window).
        await sheets()

        // Quick access.
        model.quickQuery = "net"
        await screen("40-quick-access", root: QuickAccessView(autofill: nil, close: {}), size: nil,
                     expect: .init(), chrome: false)
        model.quickQuery = ""
        // Device preferences put back to their initial value.
        model.sort = .relevance
        model.defaultFilter = .all
        model.lock()
    }

    private func sheets() async {
        let sheet = LayoutAudit.Expectation(identifiers: ["sheet-primary"], maxHeight: sheetLimit)
        // The mock vault is read-only: draft composed here, like the one the
        // server would give for GitHub.
        if let github = id(of: "GitHub") {
            let draft = ItemDraft(name: "GitHub", folderId: nil, favorite: true, notes: "Codes de secours dans le coffre.",
                                  login: LoginFields(username: "camille-dev", password: "hunter2-hunter2-hunter2",
                                                     totp: "JBSWY3DPEHPK3PXP", urls: ["https://github.com"]),
                                  fields: [], template: nil)
            await screen("30-edit-login",
                         root: EditItemView(editor: .init(itemID: github, draft: draft)),
                         size: nil, expect: withTitle(sheet, "edit-title"), chrome: false)
            var custom = draft
            custom.fields += [
                CustomField(name: "Code PIN", value: "1234", fieldType: .hidden, linkedId: nil),
                CustomField(name: "Question secrète", value: "Le nom du premier chat", fieldType: .text, linkedId: nil),
                CustomField(name: "Double authentification", value: "true", fieldType: .boolean, linkedId: nil),
            ]
            await screen("31-edit-fields",
                         root: EditItemView(editor: .init(itemID: github, draft: custom)),
                         size: nil, expect: withTitle(sheet, "edit-title"), chrome: false)
        } else {
            fail("30-edit-login", "GitHub not found in the mock vault")
        }
        if let github = id(of: "GitHub") {
            // One rule per site: host for the site, never for the old address.
            let draft = ItemDraft(name: "GitHub", folderId: "dossier-travail", favorite: true, notes: nil,
                                  login: LoginFields(username: "camille-dev", password: "hunter2-hunter2-hunter2",
                                                     totp: nil,
                                                     urls: ["https://github.com/login", "https://old.github.com",
                                                            "^https://([a-z]+\\.)?github\\.com/sso"],
                                                     urlMatches: [.host, .never, .regularExpression]),
                                  fields: [], template: nil)
            await screen("30b-edit-matching",
                         root: EditItemView(editor: .init(itemID: github, draft: draft)),
                         size: nil, expect: withTitle(sheet, "edit-title"), chrome: false)
        }
        await screen("32-generator", root: GeneratorView(use: { _, _ in }), size: nil, expect: .init(), chrome: false)

        // Per-folder rule (Work: host), for the filling tab.
        model.setFolderMatchRule("dossier-travail", .host)
        let tabs: [(String, SettingsTab)] = [
            ("33-settings-general", .general), ("34-settings-security", .security),
            ("35-settings-account", .account), ("36-settings-browsers", .integrations),
            ("36b-settings-filling", .filling),
        ]
        for (name, tab) in tabs {
            defaults.set(tab.rawValue, forKey: "settingsTab")
            await screen(name, root: SettingsView(), size: nil, expect: .init(), chrome: false)
        }

        // Members: invitation, then edit of a member.
        if model.membersOrganization != nil {
            let collection = model.membersOrganization?.collections.first?.id ?? ""
            await screen("39-invite-members",
                         root: MemberEditorView(draft: MemberDraft(member: nil, emails: "tom@exemple.fr, sam@exemple.fr",
                                                                   role: .user, access: [collection: .edit])),
                         size: nil, expect: withTitle(sheet, "sheet-title"), chrome: false)
            if let alex = model.members.members.first(where: { $0.id == "mb-alex" }) {
                model.editMember(alex)
                if let draft = model.members.draft {
                    await screen("39-edit-member", root: MemberEditorView(draft: draft), size: nil,
                                 expect: withTitle(sheet, "sheet-title"), chrome: false)
                }
                model.members.draft = nil
            }
        }

        await sharingSheets(sheet)

        // Remove from sharing: the confirmation, with what is going to happen.
        if let family = id(of: "Google — famille") {
            let request = UnshareRequest(itemIDs: [family], title: "Google — famille", organizations: ["Famille Martin"])
            await screen("47-remove-from-sharing", root: UnshareView(request: request), size: nil,
                         expect: withTitle(sheet, "sheet-title"), chrome: false)
        } else {
            fail("47-remove-from-sharing", "shared item not found in the mock vault")
        }

        // Mock duplicates (imports from Apple, 1Password, Proton Pass): the
        // mock vault has none.
        let duplicates = DuplicatesFlow(defaults: defaults)
        duplicates.load(demoDuplicates())
        await screen("37-duplicates", root: DuplicatesView(flow: duplicates), size: nil,
                     expect: withTitle(sheet, "sheet-title"), chrome: false)
        // An ignored group, an item kept by hand.
        if let google = duplicates.visible.first(where: { $0.label == "google.com" }),
           let routeur = duplicates.visible.first(where: { $0.members.count == 2 && $0.confidence == .probable }) {
            duplicates.ignore(routeur)
            duplicates.keep(google.members[2].item.id, in: google)
            // Checking the kept item: it goes to the trash, another one is kept.
            let first = google.members[2].item.id
            let before = duplicates.selected
            duplicates.toggle(first, true, in: google)
            if !duplicates.selected.contains(first) || duplicates.keptID(google) == first
                || duplicates.selected.contains(duplicates.keptID(google)) {
                fail("37b-duplicates-ignored", "checking the kept item doesn't keep another one")
            }
            // Checking everything: the last unchecked item stays kept.
            for member in google.members { duplicates.toggle(member.item.id, true, in: google) }
            if google.members.allSatisfy({ duplicates.selected.contains($0.item.id) }) {
                fail("37b-duplicates-ignored", "all the items of a group are checked")
            }
            duplicates.selected = before
            duplicates.keep(first, in: google)
        }
        await screen("37b-duplicates-ignored", root: DuplicatesView(flow: duplicates), size: nil,
                     expect: withTitle(sheet, "sheet-title"), chrome: false)
        duplicates.clearIgnored()

        // Import: a mock Apple export, compared to the mock vault.
        let csv = output.appending(path: "mock-export.csv")
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
            fail("38-import", "the mock export was not read")
        }
        model.session.cancelImport()
    }

    /// Sharing: several items, new organization, collection and its access,
    /// groups, pasted invitation.
    private func sharingSheets(_ sheet: LayoutAudit.Expectation) async {
        guard let organization = model.organizations.first,
              let collection = organization.collections.first else {
            fail("41-share-several", "no organization in the mock vault")
            return
        }
        let titled = withTitle(sheet, "sheet-title")
        let personal = model.summaries.filter { $0.sharing == nil && $0.state == .active }.prefix(3).map(\.id)
        let flow = SharingFlow(itemIDs: Array(personal), title: String(localized: "\(personal.count) items"), current: nil,
                               organizationID: organization.id, collectionIDs: [collection.id])
        await screen("41-share-several", root: SharingView(flow: flow), size: nil, expect: titled, chrome: false)
        await screen("42-new-organization", root: NewOrganizationView(), size: nil, expect: titled, chrome: false)
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
        await screen("44-groups", root: GroupsView(draft: groupsDraft), size: nil, expect: titled, chrome: false)
        await screen("44b-group", root: GroupsView(draft: groupsDraft, editing: GroupDraft(groups[1])), size: nil,
                     expect: titled, chrome: false)
        await screen("45-join", root: JoinOrganizationView(link: Self.mockInviteLink), size: nil,
                     expect: titled, chrome: false)
        // Nothing pasted: where to find the link, and why the invitation is
        // not listed before being accepted.
        await screen("45b-join-empty", root: JoinOrganizationView(), size: nil, expect: titled, chrome: false)
        await screen("46-rename", root: RenameOrganizationView(organization: organization), size: nil,
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

    /// Selects the item with this title among the results (the first if empty).
    private func select(_ title: String) {
        model.selection = title.isEmpty
            ? model.results.first?.id
            : model.results.first { model.summary(for: $0)?.title == title }?.id
    }

    private func fail(_ name: String, _ message: String) {
        failures += 1
        log("REVIEW_FAIL \(name): \(message)")
    }

    // MARK: Rendering

    /// Renders `root` in light then dark mode. `size`: window size (`nil`:
    /// the one the view asks for, like a sheet); `chrome`: window with a
    /// toolbar, like the main one.
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
            // SwiftUI updates on the next run loop turn (tasks, `onAppear`).
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
                fail(name, "a window appeared on screen ("
                    + visible.map { "\(type(of: $0)) \(Int($0.frame.minX)),\(Int($0.frame.minY)) \(Int($0.frame.width))×\(Int($0.frame.height))" }
                        .joined(separator: ", ") + ")")
                visible.forEach { $0.orderOut(nil) }
            }
            if !dark {
                var expectation = expect
                if chrome { expectation.size = frame?.size }
                let problems = LayoutAudit.problems(in: window, expectation)
                if problems.isEmpty {
                    log("REVIEW_OK \(name): layout")
                } else {
                    fail(name, "broken layout: " + problems.joined(separator: "; "))
                }
            }
            write(window, chrome: chrome, to: "\(name)-\(dark ? "dark" : "light")")
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

    /// Drawing of the window by AppKit (`cacheDisplay`), without going through
    /// the screen: title bar and toolbar included if `chrome`. The translucent
    /// materials (sidebar) are rendered opaque.
    private func write(_ window: NSWindow, chrome: Bool, to name: String) {
        guard let content = window.contentView else { return }
        let view = chrome ? (content.superview ?? content) : content
        view.layoutSubtreeIfNeeded()
        guard let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
            fail(name, "couldn't render")
            return
        }
        // Scroll edges (blur, mirror of the content): `cacheDisplay` can't
        // draw them, they are removed for the time of the rendering.
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
            fail(name, "writing: \(error.localizedDescription)")
        }
    }

    /// `cacheDisplay` draws neither the glass effects (sidebar, toolbar
    /// groups) nor what they contain: an opaque background is painted in
    /// their place, then their content on top.
    private func compositeGlass(in root: NSView, onto rep: NSBitmapImageRep) {
        var glasses: [NSView] = []
        func visit(_ view: NSView) {
            if view.isHidden { return }
            // Transparent view (the vault mounted behind the lock screen): nothing to paint.
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
        // The bitmap's context is already in points (`rep.size`).
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
                // Only the visible part: a cell scrolled out of the list must
                // not cover the footer of the sidebar.
                let shown = content.visibleRect
                guard !shown.isEmpty,
                      let image = content.bitmapImageRepForCachingDisplay(in: content.bounds) else { continue }
                content.cacheDisplay(in: content.bounds, to: image)
                NSGraphicsContext.saveGraphicsState()
                NSBezierPath(rect: content.convert(shown, to: root)).setClip()
                // …nor go under the footer (drawn on a material that
                // `cacheDisplay` leaves transparent): the useful area of the list.
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

    /// Rendering window: never key, never an active field. An active password
    /// field would bring up the system's autofill panel, a real window on
    /// screen.
    private final class ReviewWindow: NSWindow {
        override var canBecomeKey: Bool { false }
        override var canBecomeMain: Bool { false }
        override func makeFirstResponder(_ responder: NSResponder?) -> Bool {
            responder == nil || responder === self ? super.makeFirstResponder(responder) : false
        }
    }

    /// What a glass effect contains and `cacheDisplay` can draw: the SwiftUI
    /// views and the toolbar items.
    private func drawable(in glass: NSView) -> [NSView] {
        var found: [NSView] = []
        func visit(_ view: NSView) {
            if view.isHidden { return }
            let name = String(describing: type(of: view))
            if name.hasPrefix("NSHostingView") || name.hasPrefix("CellHostingView") || view is NSControl {
                found.append(view)
                // Lists (AppKit tables) are not drawn with the view that carries
                // them: their cells, on top.
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

    // MARK: Mock data

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
