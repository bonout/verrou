import SwiftUI

/// L'onglet Coffre : l'accueil (raccourcis, catégories, dossiers, coffres
/// partagés, rangement), puis les listes et les fiches.
struct VaultTab: View {
    @Environment(PhoneModel.self) private var model
    @Namespace private var zoom

    var body: some View {
        @Bindable var model = model
        NavigationStack(path: $model.vaultPath) {
            VaultHomeView()
                .navigationDestination(for: PhoneModel.Route.self) { RouteDestination(route: $0) }
        }
        .environment(\.zoomNamespace, zoom)
    }
}

/// L'onglet Rechercher : tout le coffre, avec ses propres fiches empilées.
struct SearchTab: View {
    @Environment(PhoneModel.self) private var model
    @Namespace private var zoom

    var body: some View {
        @Bindable var model = model
        NavigationStack(path: $model.searchPath) {
            SearchResultsView()
                .navigationDestination(for: PhoneModel.Route.self) { RouteDestination(route: $0) }
        }
        .environment(\.zoomNamespace, zoom)
    }
}

/// Écran d'une étape de navigation ; la fiche s'ouvre en zoomant depuis sa
/// ligne (iOS 18+).
private struct RouteDestination: View {
    @Environment(\.zoomNamespace) private var zoom
    let route: PhoneModel.Route

    var body: some View {
        switch route {
        case .list(let filter): ItemListView(filter: filter)
        case .item(let id): ItemDetailView(itemID: id).zoomDestination(id: id, in: zoom)
        case .audit: AuditView()
        case .organization(let id): OrganizationScreen(organizationID: id)
        case .members(let id): MembersScreen(organizationID: id)
        case .groups(let id): GroupsScreen(organizationID: id)
        case .sends: SendsScreen()
        }
    }
}

// MARK: Accueil

struct VaultHomeView: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.dynamicTypeSize) private var typeSize
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        List {
            browseSections
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Coffre")
        .refreshable { await model.syncNow() }
        .toolbar {
            ToolbarItem(placement: .topBarLeading) { SyncStatusButton() }
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    model.lock()
                } label: {
                    Image(systemName: "lock.fill")
                }
                .accessibilityLabel("Verrouiller")
            }
            ToolbarSpacerIfAvailable()
            ToolbarItem(placement: .topBarTrailing) { NewItemMenu(showsSharing: true) }
        }
        .onAppear { if model.lockState == .unlocked { Perf.homeAppeared() } }
        // Construit d'avance sous l'écran verrouillé : affiché au déverrouillage.
        .onChange(of: model.lockState) { _, state in
            if state == .unlocked { Perf.homeAppeared() }
        }
        #if DEBUG
        .onAppear { PhoneBenchDriver.homeShown = true }
        #endif
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
        SharingBanners()
        // Sans favori, la tuile n'est pas affichée : les deux autres se
        // partagent la largeur ; elle apparaît au premier favori.
        let hasFavorites = (counts?.favorites ?? 0) > 0
        Section {
            let tiles = Group {
                SmartTile(title: "Tous les éléments", symbol: "square.grid.2x2.fill", tint: Theme.accent,
                          count: counts?.all, filter: .all)
                if hasFavorites {
                    SmartTile(title: "Favoris", symbol: "star.fill", tint: .yellow, count: counts?.favorites,
                              filter: .favorites)
                        .transition(reduceMotion ? .identity : .opacity.combined(with: .scale(scale: 0.92)))
                }
                SmartTile(title: "Codes à usage unique", symbol: "clock.badge.checkmark.fill", tint: .teal,
                          count: counts?.withTotp, filter: .withTotp)
            }
            Group {
                if typeSize.isAccessibilitySize {
                    VStack(spacing: 10) { tiles }
                } else {
                    HStack(spacing: 10) { tiles }
                }
            }
            .animation(reduceMotion ? nil : .snappy(duration: 0.3), value: hasFavorites)
        }
        .listRowBackground(Color.clear)
        .listRowInsets(EdgeInsets(top: 4, leading: 0, bottom: 4, trailing: 0))
        if let categories = counts?.categories.filter({ $0.count > 0 }), !categories.isEmpty {
            Section {
                ForEach(categories, id: \.category) { entry in
                    FilterLink(title: entry.category.label, symbol: entry.category.symbol, tint: entry.category.tint,
                               count: entry.count, filter: .category(category: entry.category))
                }
                ForEach(counts?.templates.filter { $0.count > 0 } ?? [], id: \.template) { entry in
                    FilterLink(title: entry.template.label, symbol: entry.template.symbol, tint: entry.template.tint,
                               count: entry.count, filter: .template(template: entry.template))
                }
            } header: {
                SectionHeader("Catégories")
            }
        }
        if let folders = counts?.folders, !folders.isEmpty {
            Section {
                ForEach(folders, id: \.name) { folder in
                    FilterLink(title: folder.name, symbol: "folder.fill", tint: .blue, count: folder.count,
                               filter: .folder(name: folder.name))
                }
            } header: {
                SectionHeader("Dossiers")
            }
        }
        SharedVaultsHomeSection()
        if let tags = counts?.tags, !tags.isEmpty {
            Section {
                ForEach(tags, id: \.name) { tag in
                    FilterLink(title: "#\(tag.name)", symbol: "number", tint: .gray, count: tag.count,
                               filter: .tag(name: tag.name))
                }
            } header: {
                SectionHeader("Étiquettes")
            }
        }
        Section {
            NavigationLink(value: PhoneModel.Route.audit) {
                HomeRow(title: "Audit de sécurité", symbol: "checkmark.shield.fill", tint: .green, count: nil)
            }
            if model.mode == .vaultwarden {
                NavigationLink(value: PhoneModel.Route.sends) {
                    HomeRow(title: "Envois", symbol: "paperplane.fill", tint: .indigo, count: nil)
                }
                .accessibilityIdentifier("home-sends")
            }
            FilterLink(title: "Archives", symbol: "archivebox.fill", tint: .brown, count: counts?.archived, filter: .archived)
            FilterLink(title: "Corbeille", symbol: "trash.fill", tint: .gray, count: counts?.trashed, filter: .trash)
        } header: {
            SectionHeader("Rangement")
        } footer: {
            VaultStatusFooter()
        }
    }
}

/// Raccourci de l'accueil : symbole, nombre et titre, sur une carte.
private struct SmartTile: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let title: String
    let symbol: String
    let tint: Color
    let count: UInt32?
    let filter: SidebarFilter
    /// Nombre affiché : part de 0 à la première apparition et roule jusqu'au
    /// vrai nombre, puis suit ses changements.
    @State private var shown: UInt32?

    var body: some View {
        Button {
            model.vaultPath.append(.list(filter))
        } label: {
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .top) {
                    Image(systemName: symbol)
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(.white)
                        .frame(width: 32, height: 32)
                        .background(tint.gradient, in: Circle())
                    Spacer(minLength: 4)
                    Text(shown.map { "\($0)" } ?? "–")
                        .font(.system(.title2, design: .rounded, weight: .bold))
                        .monospacedDigit()
                        .lineLimit(1)
                        .minimumScaleFactor(0.6)
                        .contentTransition(reduceMotion ? .opacity : .numericText(value: Double(shown ?? 0)))
                        .animation(reduceMotion ? .easeOut(duration: 0.2) : .snappy(duration: 0.7), value: shown)
                        .foregroundStyle(.primary)
                }
                Text(title)
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .lineLimit(2, reservesSpace: true)
                    .multilineTextAlignment(.leading)
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(.secondarySystemGroupedBackground),
                        in: RoundedRectangle(cornerRadius: Theme.cardRadius, style: .continuous))
            .contentShape(RoundedRectangle(cornerRadius: Theme.cardRadius, style: .continuous))
        }
        .buttonStyle(TileButtonStyle())
        .task {
            // Première apparition : de 0 au nombre, à l'image suivante.
            guard shown == nil, let count else { return }
            shown = 0
            try? await Task.sleep(for: .milliseconds(30))
            shown = count
        }
        .onChange(of: count) { old, new in
            // Construite d'avance, coffre fermé : le nombre roule de 0 à
            // l'ouverture, comme à la première apparition.
            guard old == nil, let new, !reduceMotion else {
                shown = new
                return
            }
            shown = 0
            Task {
                try? await Task.sleep(for: .milliseconds(30))
                if count == new { shown = new }
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(title)
        .accessibilityValue(count.map { "\($0)" } ?? "")
        .accessibilityAddTraits(.isButton)
        .accessibilityIdentifier("tile-\(title)")
    }
}

/// Une carte qui s'enfonce légèrement sous le doigt.
private struct TileButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.96 : 1)
            .opacity(configuration.isPressed ? 0.85 : 1)
            .animation(.snappy(duration: 0.2), value: configuration.isPressed)
    }
}

/// État du coffre en pied de l'accueil, comme le pied de la barre latérale
/// du Mac : pastille, mode et compte.
private struct VaultStatusFooter: View {
    @Environment(PhoneModel.self) private var model

    var body: some View {
        HStack(spacing: 8) {
            Circle().fill(dot).frame(width: 8, height: 8)
            VStack(alignment: .leading, spacing: 1) {
                Text(title).font(.footnote.weight(.semibold)).foregroundStyle(.primary)
                Text(detail).font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.top, 10)
        .accessibilityElement(children: .combine)
    }

    private var dot: Color {
        switch model.syncState {
        case .offline: .orange
        case .failed: .red
        default: Theme.online
        }
    }

    private var title: String {
        guard model.mode == .vaultwarden, let account = model.account else { return "Coffre fictif" }
        return account.email
    }

    private var detail: String {
        guard model.mode == .vaultwarden, let account = model.account else { return "Hors ligne · données locales" }
        let host = URL(string: account.server)?.host() ?? account.server
        switch model.syncState {
        case .syncing: return "\(host) · synchronisation…"
        case .offline: return "\(host) · hors ligne"
        case .failed: return "\(host) · échec de la synchronisation"
        case .idle: return host
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
            TintedSymbol(symbol: symbol, tint: tint)
            Text(title)
            Spacer()
            if let count {
                Text("\(count)").foregroundStyle(.secondary).monospacedDigit()
            }
        }
    }
}

/// Séparation des groupes de boutons de la barre (iOS 26) ; rien avant.
private struct ToolbarSpacerIfAvailable: ToolbarContent {
    var body: some ToolbarContent {
        #if compiler(>=6.2)
        if #available(iOS 26, *) {
            ToolbarSpacer(.fixed, placement: .topBarTrailing)
        }
        #endif
    }
}

// MARK: Recherche

/// Recherche dans tout le coffre (cœur Rust, à chaque frappe) ; sans saisie,
/// les favoris.
struct SearchResultsView: View {
    @Environment(PhoneModel.self) private var model
    /// Champ de recherche actif, clavier ouvert : dès que l'onglet est choisi.
    @State private var searching = false

    var body: some View {
        @Bindable var model = model
        List {
            if model.searchQuery.isEmpty {
                suggestions
            } else {
                results
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Rechercher")
        .modifier(VaultSearchField(query: $model.searchQuery, presented: $searching))
        .autocorrectionDisabled()
        .textInputAutocapitalization(.never)
        .onAppear { if model.tab == .search { searching = true } }
        .onChange(of: model.tab) { _, tab in
            if tab == .search, model.searchPath.isEmpty {
                searching = true
                if let at = model.searchChosenAt { Perf.mark("recherche : champ activé à +\(Perf.ms(since: at)) ms") }
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: UIResponder.keyboardWillShowNotification)) { _ in
            guard model.tab == .search, let at = model.searchChosenAt else { return }
            Perf.mark("recherche : le clavier commence à monter à +\(Perf.ms(since: at)) ms")
        }
        .onReceive(NotificationCenter.default.publisher(for: UIResponder.keyboardDidShowNotification)) { _ in
            guard model.tab == .search, let at = model.searchChosenAt else { return }
            Perf.mark("recherche : clavier affiché à +\(Perf.ms(since: at)) ms du choix de l'onglet")
            model.searchChosenAt = nil
        }
    }

    @ViewBuilder private var results: some View {
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

    @ViewBuilder private var suggestions: some View {
        let favorites = model.rows(query: "", filter: .favorites)
        if favorites.isEmpty {
            ContentUnavailableView("Rechercher dans le coffre", systemImage: "magnifyingglass",
                                   description: Text("Titres, identifiants, sites, étiquettes : sans majuscules ni accents."))
                .listRowBackground(Color.clear)
        } else {
            Section {
                ForEach(favorites) { row in
                    ItemRowLink(row: row)
                }
            } header: {
                SectionHeader("Favoris")
            }
        }
    }
}

/// Le champ de recherche : sous le titre, toujours visible.
private struct VaultSearchField: ViewModifier {
    @Binding var query: String
    @Binding var presented: Bool

    func body(content: Content) -> some View {
        // En haut de l'écran, toujours visible, iOS 26 compris : le clavier
        // monte aussitôt, sans attendre que la barre d'onglets se transforme
        // en champ (une animation de plus, environ 0,3 s).
        content.searchable(text: $query, isPresented: $presented,
                           placement: .navigationBarDrawer(displayMode: .always),
                           prompt: "Rechercher dans le coffre")
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
                case .syncing:
                    Image(systemName: "arrow.triangle.2.circlepath")
                        .spinning(true)
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
    /// Accueil : créer ou rejoindre un coffre partagé, dans le même menu.
    var showsSharing = false

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
            if showsSharing {
                Divider()
                Button("Nouvelle organisation…", systemImage: "person.2.badge.plus") {
                    model.sharing.sheet = .newOrganization
                }
                Button("Rejoindre une organisation…", systemImage: "envelope.open") {
                    model.sharing.sheet = .join("")
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
        .navigationSubtitleIfAvailable(rows.count == 1 ? "1 élément" : "\(rows.count) éléments")
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
            }
            ToolbarSpacerIfAvailable()
            ToolbarItemGroup(placement: .topBarTrailing) {
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
        #if DEBUG
        .onAppear { PhoneBenchDriver.listShown = true }
        #endif
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
            .fixedSize()
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
                if !model.writableOrganizations.isEmpty, !model.shareableIDs(ids).isEmpty {
                    Button("Partager…", systemImage: "person.2") { model.openSharing(items: ids) }
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
    @Environment(\.zoomNamespace) private var zoom
    let row: ResultRow

    var body: some View {
        let summary = row.summary
        NavigationLink(value: PhoneModel.Route.item(summary.id)) {
            ItemRow(row: row)
                .equatable()
                .zoomSource(id: summary.id, in: zoom)
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
                if !model.writableOrganizations.isEmpty, summary.sharing == nil {
                    Button {
                        model.openSharing(summary.id)
                    } label: {
                        Label("Partager", systemImage: "person.2.fill")
                    }
                    .tint(.indigo)
                }
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
                    .tint(.red)
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

/// Icône, titre (caractères trouvés surlignés), sous-titre et indicateurs :
/// la ligne du Mac (`ItemRowContent`). Comparée avant d'être recalculée :
/// une ligne inchangée n'est pas reconstruite pendant la frappe.
struct ItemRow: View, Equatable {
    let row: ResultRow

    static func == (lhs: ItemRow, rhs: ItemRow) -> Bool {
        lhs.row.summary == rhs.row.summary && lhs.row.highlights == rhs.row.highlights
    }

    var body: some View {
        #if DEBUG
        let _ = PhoneBenchDriver.rowsBuilt += 1
        #endif
        ItemRowContent(summary: row.summary, highlights: row.highlights, spacing: 12,
                       subtitleFont: .subheadline, showsProtection: true) {
            ItemIcon(summary: row.summary, size: 40)
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
        ItemIconContent(summary: summary, image: siteImage, size: size, initialShadow: false)
    }

    private var siteImage: PlatformImage? {
        guard summary.category == .login, summary.template == nil, let host = summary.host else { return nil }
        return model.siteIcons.image(for: host)
    }
}
