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
                if model.showAudit {
                    AuditView()
                } else {
                    ItemListView(searchFocused: $searchFocused)
                }
            }
            .navigationSplitViewColumnWidth(min: 280, ideal: 330, max: 440)
        } detail: {
            if let detail = model.selectedDetail {
                ItemDetailView(detail: detail)
                    .id(detail.summary.id)
            } else {
                EmptyDetailView()
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
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
            ToolbarItemGroup(placement: .primaryAction) {
                let item = model.selectedSummary
                Button {
                    if let item { Task { await model.setArchived(item.id, true) } }
                } label: {
                    Label("Archiver", systemImage: "archivebox")
                }
                .help("Archiver : garder l'élément hors du chemin")
                .disabled(!model.canModify(item) || item?.state != .active)
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
        .overlay(alignment: .bottom) {
            if let toast = model.toast {
                ToastView(toast: toast)
                    .padding(.bottom, 22)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                    .task(id: toast.id) {
                        try? await Task.sleep(for: .seconds(2.2))
                        withAnimation(.snappy) { if model.toast?.id == toast.id { model.toast = nil } }
                    }
            }
        }
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

// MARK: Barre latérale

struct SidebarView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        List(selection: Binding(get: { model.filter }, set: { if let f = $0 { model.filter = f } })) {
            Section {
                row(.all, "Tous les éléments", "square.grid.2x2", count: model.counts?.all)
                row(.favorites, "Favoris", "star.fill", count: model.counts?.favorites, tint: .yellow)
                row(.withTotp, "Codes à usage unique", "clock.badge.checkmark", count: model.counts?.withTotp, tint: .teal)
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
            VStack(spacing: 0) {
                AuditSidebarButton()
                DuplicatesSidebarButton()
                if model.mode == .vaultwarden { EmergencySidebarButton() }
                if model.mode == .vaultwarden { SendsSidebarButton() }
                VaultFooter()
            }
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
                Text(status).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
        }
        .contentShape(Rectangle())
        .onTapGesture { Task { await model.syncNow() } }
        .help(model.mode == .vaultwarden ? "Synchroniser (⌘R)" : "")
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        // Sans fond, les dernières lignes de la liste défilent sous le pied.
        .background(.bar)
    }

    private var title: String {
        model.mode == .demo ? "Coffre fictif" : model.account?.email ?? "Vaultwarden"
    }

    private var dotColor: Color {
        switch model.syncState {
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
                        Text("Pertinence").tag(ResultOrder.relevance)
                        Text("Titre").tag(ResultOrder.title)
                        Text("Modifié récemment").tag(ResultOrder.recentlyModified)
                    }
                    .pickerStyle(.inline)
                } label: {
                    Image(systemName: "arrow.up.arrow.down")
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .help("Trier")
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
                                let selected = row.id == model.selection
                                ItemRow(summary: row.summary, highlights: row.highlights, selected: selected)
                                    .padding(.horizontal, 8)
                                    .background(selected ? Theme.accent : .clear,
                                                in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                                    .contentShape(Rectangle())
                                    .onTapGesture {
                                        model.selection = row.id
                                        listFocused = true
                                    }
                                    .contextMenu { RowMenu(summary: row.summary) }
                                    .id(row.id)
                            }
                        }
                        .padding(.horizontal, 8)
                        .padding(.vertical, 6)
                    }
                    .focusable()
                    .focusEffectDisabled()
                    .focused($listFocused)
                    .onKeyPress(.downArrow) { model.moveSelection(by: 1); return .handled }
                    .onKeyPress(.upArrow) { model.moveSelection(by: -1); return .handled }
                    .onChange(of: model.selection) { _, id in
                        if let id { proxy.scrollTo(id) }
                    }
                }
            }
        }
        .background(Color(nsColor: .controlBackgroundColor))
        .onKeyPress(.downArrow) { model.moveSelection(by: 1); return .handled }
        .onKeyPress(.upArrow) { model.moveSelection(by: -1); return .handled }
    }

    private var resultCaption: String {
        let n = model.results.count
        let micro = Double(model.lastSearchDuration.components.attoseconds) / 1e12
            + Double(model.lastSearchDuration.components.seconds) * 1e6
        let time = micro < 1000 ? String(format: "%.0f µs", micro) : String(format: "%.1f ms", micro / 1000)
        return "\(n) élément\(n > 1 ? "s" : "") · \(time)"
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
                .accessibilityIdentifier("search")
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

    var body: some View {
        #if DEBUG || BENCH
        let _ = BenchDriver.rowsBuilt += 1
        #endif
        HStack(spacing: 11) {
            ItemIcon(summary: summary, size: 34)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 5) {
                    HighlightedText(text: summary.title, highlights: highlights,
                                    tint: selected ? nil : Theme.accent)
                        .lineLimit(1)
                    if summary.favorite {
                        Image(systemName: "star.fill").font(.system(size: 9)).foregroundStyle(.yellow)
                    }
                    if let sharing = summary.sharing {
                        Image(systemName: "person.2.fill")
                            .font(.system(size: 9))
                            .foregroundStyle(selected ? AnyShapeStyle(.white.opacity(0.8)) : AnyShapeStyle(.indigo))
                            .help(sharing.label)
                    }
                }
                Text(summary.subtitle)
                    .font(.callout)
                    .foregroundStyle(selected ? AnyShapeStyle(.white.opacity(0.8)) : AnyShapeStyle(.secondary))
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
            if summary.hasTotp {
                Image(systemName: "clock.badge.checkmark")
                    .font(.caption)
                    .foregroundStyle(selected ? .white : .teal)
                    .help("Code à usage unique")
            }
        }
        .padding(.vertical, 6)
        .foregroundStyle(selected ? Color.white : Color.primary)
        .contentShape(Rectangle())
    }
}

struct RowMenu: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow
    let summary: ItemSummary

    var body: some View {
        if summary.category == .login {
            Button("Copier l'identifiant") { model.copy(summary.subtitle, label: "Identifiant", secret: false) }
            Button("Copier le mot de passe") { model.copyPassword(of: summary.id) }
        }
        if summary.category == .sshKey {
            Button("Copier la clé publique") { model.copyPublicKey(of: summary.id) }
        }
        if let host = summary.host, let url = URL(string: "https://\(host)") {
            Button("Ouvrir \(host)") { NSWorkspace.shared.open(url) }
        }
        if model.sendsAvailable, summary.state != .trashed,
           summary.category == .login || summary.category == .secureNote {
            Button("Envoyer de façon sécurisée…") {
                model.composeSend(from: summary) { openWindow(id: $0) }
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
