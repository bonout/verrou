import SwiftUI

struct MainView: View {
    @Environment(AppModel.self) private var model
    @FocusState private var searchFocused: Bool
    @State private var columns: NavigationSplitViewVisibility = .all

    var body: some View {
        @Bindable var model = model
        NavigationSplitView(columnVisibility: $columns) {
            SidebarView()
                .navigationSplitViewColumnWidth(min: 190, ideal: 220, max: 280)
        } content: {
            Group {
                switch model.pane {
                case .audit: AuditView()
                case .sends: SendsListView()
                case .emergency: EmergencyListView()
                case .members: MembersListView()
                case nil: ItemListView(searchFocused: $searchFocused)
                }
            }
            .navigationSplitViewColumnWidth(min: 280, ideal: 330, max: 440)
        } detail: {
            switch model.pane {
            case .sends:
                if let send = model.sends.selected {
                    SendDetailView(send: send)
                        .id(send.id)
                } else {
                    EmptyPaneDetailView(title: "Aucun envoi sélectionné", symbol: "paperplane")
                }
            case .emergency:
                if let selected = model.emergency.selected {
                    EmergencyDetailView(contact: selected.contact, trusted: selected.trusted)
                        .id(selected.contact.id)
                } else {
                    EmptyPaneDetailView(title: "Aucun accès sélectionné", symbol: "person.2.badge.key")
                }
            case .members:
                if let member = model.members.selected {
                    MemberDetailView(member: member)
                        .id(member.id)
                } else {
                    EmptyPaneDetailView(title: "Aucun membre sélectionné", symbol: "person.3")
                }
            case .audit, nil:
                if model.isMultiSelection {
                    MultiSelectionView()
                } else if let detail = model.displayedDetail {
                    ItemDetailView(detail: detail)
                        .id(detail.summary.id)
                } else {
                    EmptyDetailView()
                }
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                switch model.pane {
                case .sends:
                    NewSendMenu()
                case .emergency:
                    Button {
                        model.emergency.inviteNew()
                    } label: {
                        Label("Inviter un contact", systemImage: "plus")
                    }
                    .help("Inviter un contact d'urgence")
                case .members:
                    Button {
                        model.inviteMembers()
                    } label: {
                        Label("Inviter", systemImage: "person.badge.plus")
                    }
                    .help("Inviter des personnes dans l'organisation")
                    .disabled(model.membersOrganization?.canManageMembers != true)
                case .audit, nil:
                    Menu {
                        Button("Nouvel identifiant") { model.newItem(login: true) }
                        Button("Nouvelle note sécurisée") { model.newItem(login: false) }
                        Button("Nouvelle clé SSH…") { model.newSshKey() }
                        Button("Nouveau document…") { model.newDocument() }
                        Divider()
                        ForEach(ItemTemplate.menuOrder, id: \.self) { template in
                            Button(template.menuTitle) { model.newItem(template: template) }
                        }
                    } label: {
                        Label("Nouvel élément", systemImage: "plus")
                    } primaryAction: {
                        model.newItem(login: true)
                    }
                    .disabled(!model.canEdit)
                    .help(model.canEdit ? "Nouvel identifiant (⌘N)" : "Coffre fictif : lecture seule")
                }
            }
            ToolbarItem(placement: .primaryAction) {
                Button {
                    model.lock()
                } label: {
                    Label("Verrouiller", systemImage: "lock")
                }
                .help("Verrouiller le coffre (⌃⌘L)")
                .keyboardShortcut("l", modifiers: [.command, .control])
            }
            // Actions de l'élément sélectionné : toujours les mêmes boutons,
            // grisés quand ils ne s'appliquent pas. Ici plutôt que dans la
            // fiche, recréée à chaque sélection : la barre ne clignote plus.
            // Absentes des volets des envois et des accès d'urgence, qui
            // n'affichent pas d'élément du coffre.
            ToolbarItemGroup(placement: .primaryAction) {
                if model.pane != .sends && model.pane != .emergency && model.pane != .members {
                    ItemToolbarActions()
                }
            }
        }
        .overlay(alignment: .bottom) {
            if let toast = model.toast {
                ToastView(toast: toast)
                    .padding(.bottom, 22)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                    .task(id: toast.id) {
                        try? await Task.sleep(for: .seconds(toast.seconds))
                        withAnimation(.snappy) { if model.toast?.id == toast.id { model.toast = nil } }
                    }
            }
        }
        .modifier(SendsPresentations())
        .modifier(EmergencyPresentations())
        .modifier(MembersPresentations())
        .modifier(OrganizationPresentations())
        .sheet(item: $model.editor) { editor in
            EditItemView(editor: editor)
                .environment(model)
        }
        .sheet(item: $model.importFlow, onDismiss: { model.closeImport() }) { flow in
            ImportView(flow: flow)
                .environment(model)
                .interactiveDismissDisabled()
        }
        .sheet(item: $model.duplicatesFlow) { flow in
            DuplicatesView(flow: flow)
                .environment(model)
        }
        .sheet(item: $model.sshKeyGenerator) { generator in
            NewSshKeyView(generator: generator)
                .environment(model)
        }
        .sheet(item: $model.unshareRequest) { request in
            UnshareView(request: request)
                .environment(model)
                .interactiveDismissDisabled(model.unshareBusy)
        }
        .sheet(item: $model.moveRequest) { request in
            MoveToFolderView(request: request)
                .environment(model)
        }
        .sheet(item: $model.sharingFlow) { flow in
            SharingView(flow: flow)
                .environment(model)
        }
        // La vue reste montée derrière l'écran verrouillé (voir RootView) :
        // c'est le déverrouillage qui lui rend la main.
        .onAppear { searchFocused = model.lockState == .unlocked }
        .onChange(of: model.lockState) { _, state in
            searchFocused = state == .unlocked
            guard state == .unlocked, let start = model.unlockStartedAt else { return }
            model.unlockStartedAt = nil
            // Prochain tour de boucle : la liste est dessinée.
            DispatchQueue.main.async {
                Perf.log.notice("coffre affiché à +\(Perf.ms(since: start)) ms de la clé reçue")
            }
        }
        .onKeyPress(.escape) {
            if !model.query.isEmpty { model.query = ""; return .handled }
            return .ignored
        }
    }
}

/// Actions de l'élément sélectionné, dans la barre d'outils.
private struct ItemToolbarActions: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        // Plusieurs éléments sélectionnés : l'archivage vaut pour tous, le
        // reste (une seule fiche) est grisé.
        let multi = model.isMultiSelection
        let item = multi ? nil : model.selectedSummary
        Button {
            if multi {
                let ids = model.selectedIDs
                Task { await model.performBulk(.archive, on: ids) }
            } else if let item {
                Task { await model.setArchived(item.id, true) }
            }
        } label: {
            Label("Archiver", systemImage: "archivebox")
        }
        .help(multi ? "Archiver les \(model.selectedIDs.count) éléments sélectionnés"
                    : "Archiver : garder l'élément hors du chemin")
        .disabled(multi ? !model.canEdit || model.availability(of: model.selectedIDs).active == 0
                        : !model.canModify(item) || item?.state != .active)
        Button {
            if let item { Task { await model.edit(item.id) } }
        } label: {
            Label("Modifier", systemImage: "pencil")
        }
        .help(item?.sharing?.readOnly == true ? "Partagé en lecture seule" : "Modifier (⌘E)")
        .keyboardShortcut("e", modifiers: .command)
        .disabled(!model.canModify(item) || item == nil || item?.state == .trashed)
        Button {
            if let item { model.openSharing(item.id) }
        } label: {
            Label("Partager", systemImage: "person.2")
        }
        .help(item?.sharing == nil ? "Partager dans un coffre partagé…" : "Collections…")
        .disabled(!model.canModify(item) || item?.state != .active
                  || (item?.sharing == nil && model.writableOrganizations.isEmpty))
        Button {
            if let item { model.copyPassword(of: item.id) }
        } label: {
            Label("Copier le mot de passe", systemImage: "key")
        }
        .help("Copier le mot de passe (⇧⌘C)")
        .keyboardShortcut("c", modifiers: [.command, .shift])
        .disabled(item?.category != .login)
        Button {
            if let host = item?.host, let url = URL(string: "https://\(host)") {
                NSWorkspace.shared.open(url)
            }
        } label: {
            Label("Ouvrir le site", systemImage: "safari")
        }
        .help(item?.host.map { "Ouvrir \($0)" } ?? "Ouvrir le site")
        .disabled(item?.host == nil)
    }
}

// MARK: Barre latérale

struct SidebarView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        // Un volet ouvert (audit, envois…) : aucun filtre en surbrillance, et
        // un clic sur n'importe lequel ramène à la liste.
        List(selection: Binding(get: { model.pane == nil ? model.filter : nil },
                                set: { if let f = $0 { model.filter = f } })) {
            Section {
                row(.all, "Tous les éléments", "square.grid.2x2", count: model.counts?.all)
                row(.favorites, "Favoris", "star.fill", count: model.counts?.favorites, tint: .yellow)
                row(.withTotp, "Codes à usage unique", "clock.badge.checkmark", count: model.counts?.withTotp, tint: .teal)
                row(.passkeys, "Passkeys", "person.badge.key.fill", count: model.counts?.passkeys, tint: .purple)
            }
            Section("Catégories") {
                ForEach(model.counts?.categories ?? [], id: \.category) { entry in
                    row(.category(category: entry.category), entry.category.label, entry.category.symbol,
                        count: entry.count, tint: entry.category.tint)
                }
                // Modèles (Wi-Fi, passeport…) : seulement ceux qui ont des éléments.
                ForEach(model.counts?.templates ?? [], id: \.template) { entry in
                    row(.template(template: entry.template), entry.template.label, entry.template.symbol,
                        count: entry.count, tint: entry.template.tint)
                }
            }
            if let folders = model.counts?.folders, !folders.isEmpty {
                Section("Dossiers") {
                    ForEach(folders, id: \.name) { folder in
                        row(.folder(name: folder.name), folder.name, "folder", count: folder.count, tint: .secondary)
                    }
                }
            }
            SharedVaultsSection()
            if let counts = model.counts, counts.archived + counts.trashed > 0 {
                Section("Rangement") {
                    row(.archived, "Archives", "archivebox", count: counts.archived, tint: .secondary)
                    row(.trash, "Corbeille", "trash", count: counts.trashed, tint: .secondary)
                }
            }
            // Vaultwarden n'a pas d'étiquettes : la section n'apparaît qu'avec le coffre fictif.
            if let tags = model.counts?.tags, !tags.isEmpty {
                Section("Étiquettes") {
                    ForEach(tags, id: \.name) { tag in
                        row(.tag(name: tag.name), tag.name, "number", count: tag.count, tint: .secondary)
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) {
            // Sans fond, les dernières lignes de la liste défilent sous les
            // boutons et le pied.
            VStack(spacing: 0) {
                Divider()
                    .padding(.bottom, 6)
                AuditSidebarButton()
                DuplicatesSidebarButton()
                if model.showsAccountPanes { EmergencySidebarButton() }
                if model.showsAccountPanes { SendsSidebarButton() }
                VaultFooter()
            }
            .background(.bar)
        }
    }

    private func row(_ filter: SidebarFilter, _ title: String, _ symbol: String, count: UInt32?, tint: Color = Theme.accent) -> some View {
        Label {
            HStack {
                Text(title).lineLimit(1)
                Spacer()
                if let count {
                    Text("\(count)").monospacedDigit().foregroundStyle(.secondary).font(.callout)
                }
            }
        } icon: {
            Image(systemName: symbol).foregroundStyle(tint)
        }
        .tag(filter)
    }
}

/// Entrée du bas de la barre latérale (audit, doublons, envois, accès
/// d'urgence) : un bouton plutôt qu'une ligne de la liste, en surbrillance
/// quand son volet occupe la colonne centrale.
struct SidebarPaneButton: View {
    let title: String
    let symbol: String
    var tint: Color = Theme.accent
    var active = false
    var badge: Int?
    var badgeTint: Color = .secondary
    var help: String?
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Label {
                HStack {
                    Text(title)
                    Spacer()
                    if let badge {
                        Text("\(badge)").monospacedDigit().foregroundStyle(badgeTint).font(.callout)
                    }
                }
            } icon: {
                Image(systemName: symbol).foregroundStyle(tint)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(active ? Color.primary.opacity(0.08) : .clear,
                        in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 10)
        .padding(.bottom, 6)
        .help(help ?? "")
    }
}

/// En-tête d'un volet de la colonne centrale : titre, explication, action,
/// et le dernier message (réussite ou erreur).
struct PaneHeader<Action: View>: View {
    let title: String
    let caption: String
    var busy = false
    var notice: String?
    var error: String?
    @ViewBuilder var action: Action

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(title).font(.title3.weight(.semibold))
                    .layoutMark("pane-title")
                Spacer()
                if busy { ProgressView().controlSize(.small) }
                action
            }
            Text(caption)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
            if let notice {
                Label(notice, systemImage: "checkmark.circle.fill")
                    .font(.callout)
                    .foregroundStyle(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(.horizontal, 16)
        .padding(.top, 12)
        .padding(.bottom, 10)
    }
}

/// Compte et état de la synchronisation. Un clic relance la synchronisation.
struct VaultFooter: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        HStack(spacing: 8) {
            if model.syncState == .syncing {
                ProgressView().controlSize(.mini).frame(width: 7, height: 7)
            } else {
                Circle().fill(dotColor).frame(width: 7, height: 7)
            }
            VStack(alignment: .leading, spacing: 0) {
                Text(title).font(.caption.weight(.semibold)).lineLimit(1)
                    .layoutMark("sidebar-footer")
                Text(status).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
        }
        .contentShape(Rectangle())
        .onTapGesture { Task { await model.syncNow() } }
        .help(model.mode == .vaultwarden
              ? (model.pendingLabel.map { "\($0) : envoyées au retour du serveur. Synchroniser (⌘R)" } ?? "Synchroniser (⌘R)")
              : "")
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    private var title: String {
        model.mode == .demo ? "Coffre fictif" : model.account?.email ?? "Vaultwarden"
    }

    private var dotColor: Color {
        // Des modifications attendent le serveur.
        if model.pendingChanges > 0, model.syncState != .syncing, model.syncState != .offline { return .orange }
        return switch model.syncState {
        case .idle: .green
        case .syncing: .secondary
        case .offline: .orange
        case .failed: .red
        }
    }

    private var status: String {
        if model.mode == .demo { return "Hors ligne · données locales" }
        let last = model.account?.syncedAt.map { synced in
            Date(timeIntervalSince1970: TimeInterval(synced)).formatted(date: .omitted, time: .shortened)
        }
        if let pending = model.pendingLabel, model.syncState != .syncing {
            // « Hors ligne · 3 modifications en attente »
            return model.syncState == .offline ? "Hors ligne · \(pending)" : pending
        }
        switch model.syncState {
        case .syncing: return "Synchronisation…"
        case .offline: return "Hors ligne · état de \(last ?? "—")"
        case .failed(let message): return message
        case .idle: return last.map { "Synchronisé à \($0)" } ?? "Jamais synchronisé"
        }
    }
}

// MARK: Liste

struct ItemListView: View {
    @Environment(AppModel.self) private var model
    var searchFocused: FocusState<Bool>.Binding
    // Un clic sur une ligne donne le focus à la liste : les flèches font
    // alors défiler les éléments, pas la barre latérale.
    @FocusState private var listFocused: Bool

    var body: some View {
        @Bindable var model = model
        VStack(spacing: 0) {
            SearchField(text: $model.query, focused: searchFocused)
                .padding(.horizontal, 12)
                .padding(.top, 10)
                .padding(.bottom, 8)
            HStack {
                Text(resultCaption)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
                Spacer()
                if model.filter == .category(category: .sshKey) && model.canEdit {
                    Button("Nouvelle clé SSH…", systemImage: "plus") { model.newSshKey() }
                        .buttonStyle(.borderless)
                        .font(.caption)
                        .help("Générer une clé SSH dans le coffre")
                }
                Menu {
                    Picker("Trier", selection: $model.sort) {
                        ForEach(ResultOrder.menu, id: \.self) { order in
                            Text(order.label).tag(order)
                        }
                    }
                    .pickerStyle(.inline)
                } label: {
                    Image(systemName: "arrow.up.arrow.down")
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .help("Trier : \(model.sort.label)")
                .layoutMark("sort-menu")
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 6)
            Divider()

            if model.rows.isEmpty {
                NoResultsView(query: model.query)
            } else {
                // Pile paresseuse plutôt que `List` : la liste de macOS calcule la
                // hauteur de toutes ses lignes, donc les construit toutes (et
                // demande toutes les icônes) dès que les résultats changent.
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(spacing: 2) {
                            ForEach(model.rows) { row in
                                ListRow(row: row, selected: model.selectedSet.contains(row.id),
                                        showsPasskey: model.showsPasskeyLines) {
                                    listFocused = true
                                }
                                .equatable()
                                .id(row.id)
                            }
                        }
                        .padding(.horizontal, 8)
                        .padding(.vertical, 6)
                    }
                    .focusable()
                    .focusEffectDisabled()
                    .focused($listFocused)
                    .onKeyPress(keys: [.downArrow, .upArrow]) { press in arrow(press) }
                    // Échap : retour à l'élément actif seul (sinon, comme
                    // avant, Échap efface la recherche).
                    .onKeyPress(.escape) {
                        guard model.isMultiSelection else { return .ignored }
                        model.applySelection(.collapse)
                        return .handled
                    }
                    .onChange(of: model.selection) { _, id in
                        if let id { proxy.scrollTo(id) }
                    }
                    // ⌘A : tous les résultats, quand la liste a le focus
                    // (dans le champ de recherche, ⌘A sélectionne le texte).
                    .background(
                        Button("") { model.applySelection(.selectAll) }
                            .keyboardShortcut("a", modifiers: .command)
                            .disabled(!listFocused)
                            .opacity(0)
                            .accessibilityHidden(true)
                    )
                }
            }
        }
        .background(Color(nsColor: .controlBackgroundColor))
        .onKeyPress(keys: [.downArrow, .upArrow]) { press in arrow(press) }
    }

    /// ↑/↓ : élément voisin ; avec ⇧, étend la sélection depuis l'ancre.
    private func arrow(_ press: KeyPress) -> KeyPress.Result {
        let offset: Int32 = press.key == .downArrow ? 1 : -1
        if press.modifiers.contains(.shift) {
            model.applySelection(.step(offset: offset, extend: true))
        } else {
            model.moveSelection(by: Int(offset))
        }
        return .handled
    }

    private var resultCaption: String {
        let n = model.results.count
        let micro = Double(model.lastSearchDuration.components.attoseconds) / 1e12
            + Double(model.lastSearchDuration.components.seconds) * 1e6
        let time = micro < 1000 ? String(format: "%.0f µs", micro) : String(format: "%.1f ms", micro / 1000)
        return "\(n) élément\(n > 1 ? "s" : "") · \(time)"
    }
}

/// Une ligne de la liste : surbrillance au survol (sans animation, état
/// propre à la ligne : seules les deux lignes concernées se redessinent),
/// sélection dès l'appui du bouton, comme le Finder.
///
/// Comparée par son contenu (`equatable`) : un changement de sélection ne
/// redessine que les lignes dont l'état change, pas toutes les visibles.
private struct ListRow: View, Equatable {
    @Environment(AppModel.self) private var model
    let row: ResultRow
    let selected: Bool
    /// Vue des passkeys : site et utilisateur de la passkey.
    var showsPasskey = false
    /// Donne le focus à la liste (les flèches font alors défiler les éléments).
    let focusList: () -> Void
    @State private var hovered = false
    @State private var pressed = false

    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.selected == rhs.selected && lhs.row.summary == rhs.row.summary
            && lhs.row.highlights == rhs.row.highlights && lhs.showsPasskey == rhs.showsPasskey
    }

    var body: some View {
        ItemRow(summary: row.summary, highlights: row.highlights, selected: selected, showsPasskey: showsPasskey)
            .padding(.horizontal, 8)
            .background(selected ? Theme.accent : hovered ? Color.primary.opacity(0.07) : .clear,
                        in: RoundedRectangle(cornerRadius: 7, style: .continuous))
            .contentShape(Rectangle())
            .onHover { hovered = $0 }
            // À l'appui, pas au relâchement : la surbrillance suit le clic
            // sans attendre. ⌃-clic : seulement le menu contextuel.
            .gesture(
                DragGesture(minimumDistance: 0)
                    .onChanged { _ in
                        guard !pressed else { return }
                        pressed = true
                        let modifiers = NSEvent.modifierFlags
                        guard !modifiers.contains(.control) else { return }
                        model.click(row.id, modifiers: modifiers)
                        focusList()
                    }
                    .onEnded { _ in pressed = false }
            )
            .contextMenu { RowMenu(summary: row.summary) }
    }
}

struct SearchField: View {
    @Binding var text: String
    var focused: FocusState<Bool>.Binding

    var body: some View {
        HStack(spacing: 7) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField("Rechercher dans Verrou", text: $text)
                .textFieldStyle(.plain)
                .focused(focused)
                .layoutMark("search")
            if !text.isEmpty {
                Button { text = "" } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(.tertiary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Effacer la recherche")
            } else {
                Text("⌘F").font(.caption2.weight(.semibold)).foregroundStyle(.tertiary)
            }
        }
        .padding(.horizontal, 10)
        .frame(height: 32)
        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(focused.wrappedValue ? Theme.accent.opacity(0.7) : Color.secondary.opacity(0.2), lineWidth: focused.wrappedValue ? 1.5 : 1))
        .background(
            Button("") { focused.wrappedValue = true }
                .keyboardShortcut("f", modifiers: .command)
                .opacity(0)
        )
    }
}

struct ItemRow: View {
    let summary: ItemSummary
    let highlights: [UInt32]
    /// Sur fond d'accent : texte blanc.
    var selected = false
    var showsPasskey = false

    var body: some View {
        #if DEBUG || BENCH
        let _ = BenchDriver.rowsBuilt += 1
        #endif
        ItemRowContent(summary: summary, highlights: highlights, selected: selected, showsPasskey: showsPasskey) {
            ItemIcon(summary: summary, size: 34)
        }
        .padding(.vertical, 6)
        .contentShape(Rectangle())
    }
}

struct RowMenu: View {
    @Environment(AppModel.self) private var model
    let summary: ItemSummary

    var body: some View {
        // Clic droit sur une ligne de la sélection : l'action vaut pour toute
        // la sélection ; sur une autre ligne, pour cette ligne seule.
        if model.isMultiSelection && model.selectedSet.contains(summary.id) {
            BulkActions(ids: model.selectedIDs, style: .menu)
        } else {
            single
        }
    }

    @ViewBuilder private var single: some View {
        if summary.category == .login {
            Button("Copier l'identifiant") {
                model.session.recordItemUse(id: summary.id)
                model.copy(summary.subtitle, label: "Identifiant", secret: false)
            }
            Button("Copier le mot de passe") { model.copyPassword(of: summary.id) }
        }
        if summary.category == .sshKey {
            Button("Copier la clé publique") { model.copyPublicKey(of: summary.id) }
        }
        if let host = summary.host, let url = URL(string: "https://\(host)") {
            Button("Ouvrir \(host)") { NSWorkspace.shared.open(url) }
        }
        if summary.canChangePassword {
            Button("Changer le mot de passe") { Task { await model.changePassword(of: summary) } }
                .disabled(model.changingPassword != nil)
        }
        if model.sendsAvailable, summary.state != .trashed,
           summary.category == .login || summary.category == .secureNote {
            Button("Envoyer de façon sécurisée…") {
                model.composeSend(from: summary)
            }
        }
        if model.canEdit, !model.canModify(summary) {
            Divider()
            // Collection en lecture seule : rien à modifier depuis ce compte.
            Text("Partagé en lecture seule")
        } else if model.canEdit {
            Divider()
            if summary.state == .active, summary.sharing != nil || !model.writableOrganizations.isEmpty {
                Button(summary.sharing == nil ? "Partager…" : "Collections…") { model.openSharing(summary.id) }
            }
            if summary.canUnshare {
                Button("Retirer du partage…") { model.requestUnshare([summary.id]) }
            }
            switch summary.state {
            case .active:
                Button("Modifier…") { Task { await model.edit(summary.id) } }
                Button(summary.favorite ? "Retirer des favoris" : "Ajouter aux favoris") {
                    Task { await model.setFavorite(summary.id, !summary.favorite) }
                }
                Button("Archiver") { Task { await model.setArchived(summary.id, true) } }
                Button("Mettre à la corbeille") { Task { await model.trash(summary.id) } }
            case .archived:
                Button("Sortir des archives") { Task { await model.setArchived(summary.id, false) } }
                Button("Mettre à la corbeille") { Task { await model.trash(summary.id) } }
            case .trashed:
                Button("Restaurer") { Task { await model.restore(summary.id) } }
            }
        }
    }
}

struct NoResultsView: View {
    let query: String

    var body: some View {
        ContentUnavailableView {
            Label(query.isEmpty ? "Aucun élément" : "Aucun résultat", systemImage: "magnifyingglass")
        } description: {
            if !query.isEmpty {
                Text("Rien ne correspond à « \(query) ».\nEssayez `tag:banque`, `type:carte` ou `!mot` pour exclure.")
            }
        }
        .frame(maxHeight: .infinity)
    }
}

struct EmptyDetailView: View {
    var body: some View {
        VStack(spacing: 12) {
            AppMark(size: 56).opacity(0.85)
            Text("Sélectionnez un élément").font(.title3.weight(.semibold))
            HStack(spacing: 16) {
                KeyHint(keys: "⌘F", label: "Rechercher")
                KeyHint(keys: "↑↓", label: "Parcourir")
                KeyHint(keys: "⌘⇧Espace", label: "Accès rapide")
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// Colonne de droite d'un volet, rien de sélectionné.
struct EmptyPaneDetailView: View {
    let title: String
    let symbol: String

    var body: some View {
        ContentUnavailableView(title, systemImage: symbol)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// « Retirer du partage… » : ce qui va se passer, et la confirmation (la
/// copie de l'organisation est supprimée définitivement).
struct UnshareView: View {
    @Environment(AppModel.self) private var model
    let request: UnshareRequest

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "person.2.slash.fill")
                    .font(.system(size: 24))
                    .foregroundStyle(.indigo)
                VStack(alignment: .leading, spacing: 4) {
                    Text(request.question)
                        .font(.title3.weight(.semibold))
                        .layoutMark("sheet-title")
                    Text(request.message)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
            .padding(16)
            Divider()
            Form {
                Section("Éléments") {
                    ForEach(request.itemIDs.prefix(6), id: \.self) { id in
                        if let summary = model.summary(id: id) {
                            HStack(spacing: 10) {
                                ItemIcon(summary: summary, size: 22)
                                Text(summary.title).lineLimit(1)
                                Spacer()
                                Text(summary.sharing?.organization ?? "")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    if request.itemIDs.count > 6 {
                        Text("et \(request.itemIDs.count - 6) autres").foregroundStyle(.secondary)
                    }
                }
                Section {
                    Label("Rechiffré avec votre clé et une nouvelle clé d'élément : l'organisation ne peut plus le lire.",
                          systemImage: "lock.rotation")
                    Label("Les autres membres le perdent, sur tous leurs appareils.", systemImage: "person.2.slash")
                }
                .font(.callout)
                .foregroundStyle(.secondary)
                if let error = model.unshareError {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack(spacing: 10) {
                Spacer()
                if let progress = model.bulkProgress, model.unshareBusy {
                    ProgressView(value: Double(progress.done), total: Double(max(progress.total, 1)))
                        .frame(width: 120)
                    Text("\(progress.done) sur \(progress.total)").font(.caption).monospacedDigit()
                }
                Button("Annuler") { model.unshareRequest = nil }
                    .keyboardShortcut(.cancelAction)
                    .disabled(model.unshareBusy)
                Button(request.itemIDs.count == 1 ? "Retirer du partage" : "Retirer \(request.itemIDs.count) éléments",
                       role: .destructive) {
                    Task { await model.performUnshare(request) }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .tint(.red)
                .layoutMark("sheet-primary")
                .disabled(model.unshareBusy)
            }
            .padding(16)
        }
        .frame(width: 500)
        .background(Color(nsColor: .windowBackgroundColor))
    }
}
