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
            ItemListView(searchFocused: $searchFocused)
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
                Button {
                    model.lock()
                } label: {
                    Label("Verrouiller", systemImage: "lock")
                }
                .help("Verrouiller le coffre (⌃⌘L)")
                .keyboardShortcut("l", modifiers: [.command, .control])
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
        .onAppear { searchFocused = true }
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
            }
            Section("Dossiers") {
                ForEach(model.counts?.folders ?? [], id: \.name) { folder in
                    row(.folder(name: folder.name), folder.name, "folder", count: folder.count, tint: .secondary)
                }
            }
            Section("Étiquettes") {
                ForEach(model.counts?.tags ?? [], id: \.name) { tag in
                    row(.tag(name: tag.name), tag.name, "number", count: tag.count, tint: .secondary)
                }
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) { VaultFooter() }
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

struct VaultFooter: View {
    var body: some View {
        HStack(spacing: 8) {
            Circle().fill(.green).frame(width: 7, height: 7)
            VStack(alignment: .leading, spacing: 0) {
                Text("Coffre fictif").font(.caption.weight(.semibold))
                Text("Hors ligne · données locales").font(.caption2).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        // Sans fond, les dernières lignes de la liste défilent sous le pied.
        .background(.bar)
    }
}

// MARK: Liste

struct ItemListView: View {
    @Environment(AppModel.self) private var model
    var searchFocused: FocusState<Bool>.Binding

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

            if model.results.isEmpty {
                NoResultsView(query: model.query)
            } else {
                ScrollViewReader { proxy in
                    List(selection: $model.selection) {
                        ForEach(model.results, id: \.position) { hit in
                            let summary = model.summary(for: hit)
                            ItemRow(summary: summary, highlights: hit.highlights)
                                .tag(summary.id)
                                .id(summary.id)
                                .contextMenu { RowMenu(summary: summary) }
                        }
                    }
                    .listStyle(.inset)
                    .scrollContentBackground(.hidden)
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

    var body: some View {
        HStack(spacing: 11) {
            ItemIcon(summary: summary, size: 34)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 5) {
                    HighlightedText(text: summary.title, highlights: highlights)
                        .lineLimit(1)
                    if summary.favorite {
                        Image(systemName: "star.fill").font(.system(size: 9)).foregroundStyle(.yellow)
                    }
                }
                Text(summary.subtitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
            if summary.hasTotp {
                Image(systemName: "clock.badge.checkmark")
                    .font(.caption)
                    .foregroundStyle(.teal)
                    .help("Code à usage unique")
            }
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
    }
}

struct RowMenu: View {
    @Environment(AppModel.self) private var model
    let summary: ItemSummary

    var body: some View {
        if summary.category == .login {
            Button("Copier l'identifiant") { model.copy(summary.subtitle, label: "Identifiant", secret: false) }
            Button("Copier le mot de passe") { model.copyPassword(of: summary.id) }
        }
        if let host = summary.host, let url = URL(string: "https://\(host)") {
            Button("Ouvrir \(host)") { NSWorkspace.shared.open(url) }
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
