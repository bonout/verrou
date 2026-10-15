import SwiftUI

/// L'onglet Coffre : l'accueil (recherche, catégories, dossiers, coffres
/// partagés, rangement), puis les listes et les fiches.
struct VaultTab: View {
    @Environment(PhoneModel.self) private var model

    var body: some View {
        @Bindable var model = model
        NavigationStack(path: $model.vaultPath) {
            VaultHomeView()
                .navigationDestination(for: PhoneModel.Route.self) { route in
                    switch route {
                    case .list(let filter): ItemListView(filter: filter)
                    case .item(let id): ItemDetailView(itemID: id)
                    case .audit: AuditView()
                    }
                }
        }
    }
}

// MARK: Accueil

struct VaultHomeView: View {
    @Environment(PhoneModel.self) private var model

    var body: some View {
        @Bindable var model = model
        List {
            if model.searchQuery.isEmpty {
                browseSections
            } else {
                searchResults
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Coffre")
        .searchable(text: $model.searchQuery, placement: .navigationBarDrawer(displayMode: .always),
                    prompt: "Rechercher dans le coffre")
        .autocorrectionDisabled()
        .textInputAutocapitalization(.never)
        .refreshable { await model.syncNow() }
        .toolbar {
            ToolbarItem(placement: .topBarLeading) { SyncStatusButton() }
            ToolbarItem(placement: .topBarTrailing) { NewItemMenu() }
        }
    }

    @ViewBuilder private var searchResults: some View {
        let rows = model.rows(query: model.searchQuery, filter: .all)
        if rows.isEmpty {
            ContentUnavailableView.search(text: model.searchQuery)
                .listRowBackground(Color.clear)
        } else {
            Section {
                ForEach(rows) { row in
                    ItemRowLink(row: row)
                }
            } footer: {
                Text(rows.count == 1 ? "1 résultat" : "\(rows.count) résultats")
            }
        }
    }

    @ViewBuilder private var browseSections: some View {
        let counts = model.counts
        if let pending = model.pendingLabel {
            Section {
                Label(pending, systemImage: "arrow.triangle.2.circlepath")
                    .foregroundStyle(.orange)
                    .font(.callout)
            } footer: {
                Text("Modifiées hors ligne : envoyées dès que le serveur répondra.")
            }
        }
        Section {
            FilterLink(title: "Tous les éléments", symbol: "square.grid.2x2.fill", tint: Theme.accent,
                       count: counts?.all, filter: .all)
            FilterLink(title: "Favoris", symbol: "star.fill", tint: .yellow, count: counts?.favorites, filter: .favorites)
            FilterLink(title: "Codes à usage unique", symbol: "clock.badge.checkmark.fill", tint: .teal,
                       count: counts?.withTotp, filter: .withTotp)
        }
        if let categories = counts?.categories.filter({ $0.count > 0 }), !categories.isEmpty {
            Section("Types") {
                ForEach(categories, id: \.category) { entry in
                    FilterLink(title: entry.category.label, symbol: entry.category.symbol, tint: entry.category.tint,
                               count: entry.count, filter: .category(category: entry.category))
                }
                ForEach(counts?.templates.filter { $0.count > 0 } ?? [], id: \.template) { entry in
                    FilterLink(title: entry.template.label, symbol: entry.template.symbol, tint: entry.template.tint,
                               count: entry.count, filter: .template(template: entry.template))
                }
            }
        }
        if let folders = counts?.folders, !folders.isEmpty {
            Section("Dossiers") {
                ForEach(folders, id: \.name) { folder in
                    FilterLink(title: folder.name, symbol: "folder.fill", tint: .blue, count: folder.count,
                               filter: .folder(name: folder.name))
                }
            }
        }
        if !model.organizations.isEmpty {
            Section("Coffres partagés") {
                ForEach(model.organizations, id: \.id) { org in
                    FilterLink(title: org.name, symbol: "person.2.fill", tint: .indigo, count: org.count,
                               filter: .organization(id: org.id))
                    ForEach(org.collections, id: \.id) { collection in
                        FilterLink(title: collection.name, symbol: "tray.full.fill", tint: .indigo.opacity(0.7),
                                   count: collection.count, filter: .collection(id: collection.id))
                            .padding(.leading, 18)
                    }
                }
            }
        }
        if let tags = counts?.tags, !tags.isEmpty {
            Section("Étiquettes") {
                ForEach(tags, id: \.name) { tag in
                    FilterLink(title: "#\(tag.name)", symbol: "number", tint: .gray, count: tag.count,
                               filter: .tag(name: tag.name))
                }
            }
        }
        Section("Rangement") {
            NavigationLink(value: PhoneModel.Route.audit) {
                HomeRow(title: "Audit de sécurité", symbol: "checkmark.shield.fill", tint: .green, count: nil)
            }
            FilterLink(title: "Archives", symbol: "archivebox.fill", tint: .brown, count: counts?.archived, filter: .archived)
            FilterLink(title: "Corbeille", symbol: "trash.fill", tint: .gray, count: counts?.trashed, filter: .trash)
        }
    }
}

/// Une entrée de l'accueil vers une liste filtrée.
private struct FilterLink: View {
    let title: String
    let symbol: String
    let tint: Color
    let count: UInt32?
    let filter: SidebarFilter

    var body: some View {
        NavigationLink(value: PhoneModel.Route.list(filter)) {
            HomeRow(title: title, symbol: symbol, tint: tint, count: count)
        }
    }
}

private struct HomeRow: View {
    let title: String
    let symbol: String
    let tint: Color
    let count: UInt32?

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(.white)
                .frame(width: 30, height: 30)
                .background(tint.gradient, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            Text(title)
            Spacer()
            if let count {
                Text("\(count)").foregroundStyle(.secondary).monospacedDigit()
            }
        }
    }
}

/// État de la synchronisation, en haut à gauche ; un appui synchronise.
private struct SyncStatusButton: View {
    @Environment(PhoneModel.self) private var model

    var body: some View {
        if model.mode == .vaultwarden {
            Button {
                Task { await model.syncNow() }
            } label: {
                switch model.syncState {
                case .syncing: ProgressView()
                case .offline: Image(systemName: "wifi.slash").foregroundStyle(.orange)
                case .failed: Image(systemName: "exclamationmark.arrow.triangle.2.circlepath").foregroundStyle(.red)
                case .idle: Image(systemName: "arrow.triangle.2.circlepath")
                }
            }
            .accessibilityLabel(label)
            .disabled(model.syncState == .syncing)
        }
    }

    private var label: String {
        switch model.syncState {
        case .syncing: "Synchronisation en cours"
        case .offline: "Hors ligne : synchroniser"
        case .failed(let message): "Échec de la synchronisation (\(message)) : réessayer"
        case .idle: "Synchroniser"
        }
    }
}

/// « + » : nouvel identifiant, note, carte, identité ou modèle.
struct NewItemMenu: View {
    @Environment(PhoneModel.self) private var model
    var folderID: String?
    var destination: SharedDestination?

    var body: some View {
        Menu {
            Button("Identifiant", systemImage: ItemCategory.login.symbol) { new(.login) }
            Button("Note sécurisée", systemImage: ItemCategory.secureNote.symbol) { new(.note) }
            Button("Carte bancaire", systemImage: ItemCategory.card.symbol) { new(.card) }
            Button("Identité", systemImage: ItemCategory.identity.symbol) { new(.identity) }
            Menu("Autres modèles") {
                ForEach(ItemTemplate.menuOrder, id: \.self) { template in
                    Button(template.menuTitle, systemImage: template.symbol) { new(.template(template)) }
                }
            }
        } label: {
            Image(systemName: "plus")
        }
        .accessibilityLabel("Nouvel élément")
        .disabled(!model.canEdit)
    }

    private func new(_ kind: PhoneModel.NewItemKind) {
        model.newItem(kind, folderID: folderID, destination: destination)
    }
}

// MARK: Listes

/// Les éléments d'une catégorie, d'un dossier, d'un coffre partagé… avec
/// recherche, actions par balayage et sélection multiple (mode édition).
struct ItemListView: View {
    @Environment(PhoneModel.self) private var model
    let filter: SidebarFilter
    @State private var query = ""
    @State private var order = ResultOrder.relevance
    @State private var selection = Set<String>()
    @State private var editMode = EditMode.inactive
    @State private var confirmTrash: [String]?

    var body: some View {
        let rows = model.rows(query: query, filter: filter, order: order)
        List(selection: $selection) {
            if rows.isEmpty {
                emptyState
                    .listRowBackground(Color.clear)
            }
            ForEach(rows) { row in
                ItemRowLink(row: row)
                    .tag(row.id)
            }
        }
        .listStyle(.plain)
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.large)
        .searchable(text: $query, prompt: "Rechercher")
        .autocorrectionDisabled()
        .textInputAutocapitalization(.never)
        .refreshable { await model.syncNow() }
        .environment(\.editMode, $editMode)
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                if !editMode.isEditing {
                    Menu {
                        Picker("Trier", selection: $order) {
                            Text("Pertinence").tag(ResultOrder.relevance)
                            Text("Titre").tag(ResultOrder.title)
                            Text("Modifiés récemment").tag(ResultOrder.recentlyModified)
                        }
                    } label: {
                        Image(systemName: "arrow.up.arrow.down")
                    }
                    .accessibilityLabel("Trier")
                    NewItemMenu(folderID: folderID, destination: destination)
                }
                if model.canEdit, !rows.isEmpty {
                    Button(editMode.isEditing ? "OK" : "Choisir") {
                        withAnimation {
                            editMode = editMode.isEditing ? .inactive : .active
                            selection.removeAll()
                        }
                    }
                }
            }
            if editMode.isEditing {
                ToolbarItemGroup(placement: .bottomBar) {
                    BulkActionsBar(ids: Array(selection), filter: filter, all: rows.map(\.id),
                                   selection: $selection, confirmTrash: $confirmTrash)
                }
            }
        }
        .toolbar(editMode.isEditing ? .hidden : .automatic, for: .tabBar)
        .confirmationDialog(trashTitle, isPresented: Binding(get: { confirmTrash != nil }, set: { if !$0 { confirmTrash = nil } }),
                            titleVisibility: .visible) {
            Button("Mettre à la corbeille", role: .destructive) {
                let ids = confirmTrash ?? []
                confirmTrash = nil
                Task {
                    await model.performBulk(.trash, on: ids)
                    endEditing()
                }
            }
        } message: {
            Text("Restaurables depuis la corbeille pendant 30 jours.")
        }
        .onChange(of: model.revision) {
            // Les éléments qui ont quitté la liste quittent la sélection.
            let shown = Set(model.rows(query: query, filter: filter, order: order).map(\.id))
            selection.formIntersection(shown)
        }
    }

    private var trashTitle: String {
        let count = confirmTrash?.count ?? 0
        return count == 1 ? "Mettre 1 élément à la corbeille ?" : "Mettre \(count) éléments à la corbeille ?"
    }

    private func endEditing() {
        withAnimation {
            selection.removeAll()
            editMode = .inactive
        }
    }

    @ViewBuilder private var emptyState: some View {
        if !query.isEmpty {
            ContentUnavailableView.search(text: query)
        } else {
            switch filter {
            case .trash:
                ContentUnavailableView("Corbeille vide", systemImage: "trash",
                                       description: Text("Les éléments supprimés y restent 30 jours."))
            case .archived:
                ContentUnavailableView("Aucune archive", systemImage: "archivebox",
                                       description: Text("Archivez un élément pour le garder hors de la liste et de la recherche."))
            default:
                ContentUnavailableView("Aucun élément", systemImage: "tray",
                                       description: Text("Touchez + pour en créer un."))
            }
        }
    }

    /// Dossier proposé pour un nouvel élément créé depuis cette liste.
    private var folderID: String? {
        guard case .folder(let name) = filter else { return nil }
        return model.folders.first { $0.name == name }?.id
    }

    /// Collection proposée pour un nouvel élément créé depuis un coffre partagé.
    private var destination: SharedDestination? {
        switch filter {
        case .organization(let id):
            guard let org = model.writableOrganizations.first(where: { $0.id == id }),
                  let collection = org.collections.first(where: { !$0.readOnly }) else { return nil }
            return SharedDestination(organizationID: org.id, collectionIDs: [collection.id])
        case .collection(let id):
            guard let org = model.writableOrganizations.first(where: { $0.collections.contains { $0.id == id && !$0.readOnly } })
            else { return nil }
            return SharedDestination(organizationID: org.id, collectionIDs: [id])
        default:
            return nil
        }
    }

    private var title: String {
        switch filter {
        case .all: "Tous les éléments"
        case .favorites: "Favoris"
        case .withTotp: "Codes à usage unique"
        case .category(let category): category.label
        case .template(let template): template.label
        case .folder(let name): name
        case .tag(let name): "#\(name)"
        case .archived: "Archives"
        case .trash: "Corbeille"
        case .organization(let id): model.organizations.first { $0.id == id }?.name ?? "Coffre partagé"
        case .collection(let id):
            model.organizations.flatMap(\.collections).first { $0.id == id }?.name ?? "Collection"
        }
    }
}

/// Barre du bas en mode sélection : actions sur les éléments choisis.
private struct BulkActionsBar: View {
    @Environment(PhoneModel.self) private var model
    let ids: [String]
    let filter: SidebarFilter
    let all: [String]
    @Binding var selection: Set<String>
    @Binding var confirmTrash: [String]?

    var body: some View {
        Button(selection.count == all.count ? "Aucun" : "Tout") {
            selection = selection.count == all.count ? [] : Set(all)
        }
        Spacer()
        Text(selection.isEmpty ? "Aucune sélection" : "\(selection.count) sélectionné\(selection.count > 1 ? "s" : "")")
            .font(.footnote)
            .foregroundStyle(.secondary)
        Spacer()
        Menu {
            switch filter {
            case .trash:
                Button("Restaurer", systemImage: "arrow.uturn.backward") { run(.restore) }
            case .archived:
                Button("Sortir des archives", systemImage: "tray.and.arrow.up") { run(.unarchive) }
                Button("Mettre à la corbeille", systemImage: "trash", role: .destructive) { confirmTrash = ids }
            default:
                Button("Ajouter aux favoris", systemImage: "star") { run(.favorite(favorite: true)) }
                Button("Retirer des favoris", systemImage: "star.slash") { run(.favorite(favorite: false)) }
                Button("Déplacer vers un dossier…", systemImage: "folder") {
                    model.moveRequest = PhoneModel.MoveRequest(itemIDs: ids)
                }
                Button("Archiver", systemImage: "archivebox") { run(.archive) }
                Button("Mettre à la corbeille", systemImage: "trash", role: .destructive) { confirmTrash = ids }
            }
        } label: {
            Label("Actions", systemImage: "ellipsis.circle")
        }
        .disabled(ids.isEmpty || model.editorBusy)
    }

    private func run(_ action: BulkItemAction) {
        let targets = ids
        Task {
            await model.performBulk(action, on: targets)
            selection.removeAll()
        }
    }
}

// MARK: Lignes

/// Une ligne d'élément qui ouvre sa fiche, avec ses actions rapides.
struct ItemRowLink: View {
    @Environment(PhoneModel.self) private var model
    let row: ResultRow

    var body: some View {
        let summary = row.summary
        NavigationLink(value: PhoneModel.Route.item(summary.id)) {
            ItemRow(row: row)
        }
        .swipeActions(edge: .leading, allowsFullSwipe: true) {
            if summary.state == .active, model.canModify(summary) {
                Button {
                    Task { await model.setFavorite(summary.id, !summary.favorite) }
                } label: {
                    Label(summary.favorite ? "Retirer des favoris" : "Favori",
                          systemImage: summary.favorite ? "star.slash.fill" : "star.fill")
                }
                .tint(.yellow)
            }
        }
        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
            if model.canModify(summary) {
                switch summary.state {
                case .active:
                    Button(role: .destructive) {
                        Task { await model.trash(summary.id) }
                    } label: {
                        Label("Corbeille", systemImage: "trash")
                    }
                    Button {
                        Task { await model.setArchived(summary.id, true) }
                    } label: {
                        Label("Archiver", systemImage: "archivebox")
                    }
                    .tint(.brown)
                case .archived:
                    Button {
                        Task { await model.setArchived(summary.id, false) }
                    } label: {
                        Label("Désarchiver", systemImage: "tray.and.arrow.up")
                    }
                    .tint(.brown)
                case .trashed:
                    Button {
                        Task { await model.restore(summary.id) }
                    } label: {
                        Label("Restaurer", systemImage: "arrow.uturn.backward")
                    }
                    .tint(.green)
                }
            }
        }
        .contextMenu {
            if summary.category == .login {
                Button("Copier l'identifiant", systemImage: "person") { model.copyUsername(of: summary.id) }
                Button("Copier le mot de passe", systemImage: "key") { model.copyPassword(of: summary.id) }
            }
            if summary.hasTotp {
                Button("Copier le code", systemImage: "clock") { model.copyCode(of: summary.id) }
            }
        }
    }
}

/// Icône, titre (caractères trouvés surlignés), sous-titre et indicateurs.
struct ItemRow: View {
    let row: ResultRow

    var body: some View {
        let summary = row.summary
        HStack(spacing: 12) {
            ItemIcon(summary: summary, size: 38)
            VStack(alignment: .leading, spacing: 2) {
                HighlightedText(text: summary.title, highlights: row.highlights)
                    .lineLimit(1)
                if !summary.subtitle.isEmpty {
                    Text(summary.subtitle)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 4)
            HStack(spacing: 6) {
                if summary.pendingSync {
                    Image(systemName: "arrow.triangle.2.circlepath").foregroundStyle(.orange)
                        .accessibilityLabel("En attente de synchronisation")
                }
                if summary.reprompt {
                    Image(systemName: "lock.shield").foregroundStyle(.orange)
                        .accessibilityLabel("Protégé")
                }
                if summary.sharing != nil {
                    Image(systemName: "person.2.fill").foregroundStyle(.indigo)
                        .accessibilityLabel("Partagé")
                }
                if summary.favorite {
                    Image(systemName: "star.fill").foregroundStyle(.yellow)
                        .accessibilityLabel("Favori")
                }
            }
            .font(.caption)
        }
        .padding(.vertical, 2)
    }
}

/// Icône d'un élément, avec celle du site servie par le Vaultwarden du compte.
struct ItemIcon: View {
    @Environment(PhoneModel.self) private var model
    let summary: ItemSummary
    var size: CGFloat = 36

    var body: some View {
        ItemIconContent(summary: summary, image: siteImage, size: size)
    }

    private var siteImage: PlatformImage? {
        guard summary.category == .login, summary.template == nil, let host = summary.host else { return nil }
        return model.siteIcons.image(for: host)
    }
}
