import SwiftUI

/// The Vault tab: the home screen (shortcuts, categories, folders, shared
/// vaults, storage), then the lists and the item pages.
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

/// The Search tab: the whole vault, with its own stacked item pages.
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

/// Screen of a navigation step; the item page opens by zooming from its
/// row (iOS 18+).
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

// MARK: Home

struct VaultHomeView: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.dynamicTypeSize) private var typeSize
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        List {
            browseSections
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Vault")
        .refreshable { await model.syncNow() }
        .toolbar {
            ToolbarItem(placement: .topBarLeading) { SyncStatusButton() }
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    model.lock()
                } label: {
                    Image(systemName: "lock.fill")
                }
                .accessibilityLabel("Lock")
            }
            ToolbarSpacerIfAvailable()
            ToolbarItem(placement: .topBarTrailing) { NewItemMenu(showsSharing: true) }
        }
        .onAppear { if model.lockState == .unlocked { Perf.homeAppeared() } }
        // Built ahead under the lock screen: shown on unlock.
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
                PendingLabel(text: pending)
                    .font(.callout)
            } footer: {
                Text("Changed offline: sent as soon as the server responds.")
            }
        }
        SharingBanners()
        // Without a favorite, the tile isn't shown: the two others share the
        // width; it appears with the first favorite.
        let hasFavorites = (counts?.favorites ?? 0) > 0
        Section {
            let tiles = Group {
                SmartTile(title: String(localized: "All items"), id: "all", symbol: "square.grid.2x2.fill", tint: Theme.accent,
                          count: counts?.all, filter: .all)
                if hasFavorites {
                    SmartTile(title: String(localized: "Favorites"), id: "favorites", symbol: "star.fill", tint: .yellow, count: counts?.favorites,
                              filter: .favorites)
                        .transition(reduceMotion ? .identity : .opacity.combined(with: .scale(scale: 0.92)))
                }
                SmartTile(title: String(localized: "One-time codes"), id: "codes", symbol: "clock.badge.checkmark.fill", tint: .teal,
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
                FilterLink(title: String(localized: "Passkeys"), symbol: "person.badge.key.fill", tint: .purple,
                           count: counts?.passkeys, filter: .passkeys)
                    .accessibilityIdentifier("home-passkeys")
                ForEach(categories, id: \.category) { entry in
                    FilterLink(title: entry.category.label, symbol: entry.category.symbol, tint: entry.category.tint,
                               count: entry.count, filter: .category(category: entry.category))
                }
                ForEach(counts?.templates.filter { $0.count > 0 } ?? [], id: \.template) { entry in
                    FilterLink(title: entry.template.label, symbol: entry.template.symbol, tint: entry.template.tint,
                               count: entry.count, filter: .template(template: entry.template))
                }
            } header: {
                SectionHeader("Categories")
            }
        }
        if let folders = counts?.folders, !folders.isEmpty {
            Section {
                // Top-level folders only ("Work/Clients" is inside "Work"),
                // counted with their subfolders: a folder's screen lists
                // its subfolders above its items, like Files.
                ForEach(model.folderTree) { folder in
                    FilterLink(title: folder.name, symbol: "folder.fill", tint: .blue, count: folder.count,
                               filter: .folder(name: folder.path))
                }
            } header: {
                SectionHeader("Folders")
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
                SectionHeader("Tags")
            }
        }
        Section {
            NavigationLink(value: PhoneModel.Route.audit) {
                HomeRow(title: String(localized: "Security audit"), symbol: "checkmark.shield.fill", tint: .green, count: nil)
            }
            if model.mode == .vaultwarden {
                NavigationLink(value: PhoneModel.Route.sends) {
                    HomeRow(title: String(localized: "Sends"), symbol: "paperplane.fill", tint: .indigo, count: nil)
                }
                .accessibilityIdentifier("home-sends")
            }
            FilterLink(title: String(localized: "Archived items"), symbol: "archivebox.fill", tint: .brown, count: counts?.archived, filter: .archived)
            FilterLink(title: String(localized: "Trash"), symbol: "trash.fill", tint: .gray, count: counts?.trashed, filter: .trash)
        } header: {
            SectionHeader("Storage")
        } footer: {
            VaultStatusFooter()
        }
    }
}

/// Home shortcut: symbol, number and title, on a card.
private struct SmartTile: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let title: String
    /// Accessibility identifier suffix (`tile-<id>`).
    let id: String
    let symbol: String
    let tint: Color
    let count: UInt32?
    let filter: SidebarFilter
    /// Number shown: starts from 0 on first appearance and rolls up to the
    /// real number, then follows its changes.
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
            .overlay(RoundedRectangle(cornerRadius: Theme.cardRadius, style: .continuous).strokeBorder(Theme.cardBorder))
            .contentShape(RoundedRectangle(cornerRadius: Theme.cardRadius, style: .continuous))
        }
        .buttonStyle(TileButtonStyle())
        .task {
            // First appearance: from 0 to the number, on the next frame.
            guard shown == nil, let count else { return }
            shown = 0
            try? await Task.sleep(for: .milliseconds(30))
            shown = count
        }
        .onChange(of: count) { old, new in
            // Built ahead, vault closed: the number rolls from 0 on opening,
            // as on first appearance.
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
        .accessibilityIdentifier("tile-\(id)")
    }
}

/// A card that sinks slightly under the finger.
private struct TileButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.96 : 1)
            .opacity(configuration.isPressed ? 0.85 : 1)
            .animation(.snappy(duration: 0.2), value: configuration.isPressed)
    }
}

/// Vault state at the foot of the home screen, like the foot of the Mac's
/// sidebar: dot, mode and account.
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
        guard model.mode == .vaultwarden, let account = model.account else { return String(localized: "Demo vault") }
        return account.email
    }

    private var detail: String {
        guard model.mode == .vaultwarden, let account = model.account else { return String(localized: "Read-only · sample data") }
        let host = URL(string: account.server)?.host() ?? account.server
        switch model.syncState {
        case .syncing: return String(localized: "\(host) · syncing…")
        case .offline: return String(localized: "\(host) · offline")
        case .failed: return String(localized: "\(host) · sync failed")
        case .idle: return host
        }
    }
}

/// A home entry leading to a filtered list.
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

/// Separates the bar's button groups (iOS 26); nothing before.
private struct ToolbarSpacerIfAvailable: ToolbarContent {
    var body: some ToolbarContent {
        #if compiler(>=6.2)
        if #available(iOS 26, *) {
            ToolbarSpacer(.fixed, placement: .topBarTrailing)
        }
        #endif
    }
}

// MARK: Search

/// Search across the whole vault (Rust core, at each keystroke); with no
/// input, the favorites.
struct SearchResultsView: View {
    @Environment(PhoneModel.self) private var model
    /// Search field active, keyboard open: as soon as the tab is chosen.
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
        .navigationTitle("Search")
        .modifier(VaultSearchField(query: $model.searchQuery, presented: $searching))
        .autocorrectionDisabled()
        .textInputAutocapitalization(.never)
        .onAppear { if model.tab == .search { searching = true } }
        .onChange(of: model.tab) { _, tab in
            if tab == .search, model.searchPath.isEmpty {
                searching = true
                if let at = model.searchChosenAt { Perf.mark("search: field activated at +\(Perf.ms(since: at)) ms") }
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: UIResponder.keyboardWillShowNotification)) { _ in
            guard model.tab == .search, let at = model.searchChosenAt else { return }
            Perf.mark("search: the keyboard starts rising at +\(Perf.ms(since: at)) ms")
        }
        .onReceive(NotificationCenter.default.publisher(for: UIResponder.keyboardDidShowNotification)) { _ in
            guard model.tab == .search, let at = model.searchChosenAt else { return }
            Perf.mark("search: keyboard shown at +\(Perf.ms(since: at)) ms after choosing the tab")
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
                Text(rows.count == 1 ? "1 result" : "\(rows.count) results")
            }
        }
    }

    @ViewBuilder private var suggestions: some View {
        let favorites = model.rows(query: "", filter: .favorites)
        if favorites.isEmpty {
            ContentUnavailableView("Search the vault", systemImage: "magnifyingglass",
                                   description: Text("Titles, usernames, sites, tags: no need for capitals or accents."))
                .listRowBackground(Color.clear)
        } else {
            Section {
                ForEach(favorites) { row in
                    ItemRowLink(row: row)
                }
            } header: {
                SectionHeader("Favorites")
            }
        }
    }
}

/// The search field: under the title, always visible.
private struct VaultSearchField: ViewModifier {
    @Binding var query: String
    @Binding var presented: Bool

    func body(content: Content) -> some View {
        // At the top of the screen, always visible, iOS 26 included: the
        // keyboard rises right away, without waiting for the tab bar to
        // morph into a field (one more animation, about 0.3 s).
        content.searchable(text: $query, isPresented: $presented,
                           placement: .navigationBarDrawer(displayMode: .always),
                           prompt: "Search the vault")
    }
}

/// Sync state, at the top left; a tap syncs.
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
        case .syncing: String(localized: "Sync in progress")
        case .offline: String(localized: "Offline: sync")
        case .failed(let message): String(localized: "Sync failed (\(message)): try again")
        case .idle: String(localized: "Sync")
        }
    }
}

/// "+": new login, note, card, identity or template.
struct NewItemMenu: View {
    @Environment(PhoneModel.self) private var model
    var folderID: String?
    var destination: SharedDestination?
    /// Home: create or join a shared vault, in the same menu.
    var showsSharing = false

    var body: some View {
        if model.mode == .demo, !model.canEdit {
            Button {
                model.toast = Toast(message: String(localized: "Read-only demo"),
                                    detail: String(localized: "Sign in to your server to create and edit items."))
            } label: {
                Image(systemName: "plus")
            }
            .accessibilityLabel("New item")
            .accessibilityHint("The demo vault is read-only")
        } else {
            menu
        }
    }

    private var menu: some View {
        Menu {
            Button("Login", systemImage: ItemCategory.login.symbol) { new(.login) }
            Button("Secure note", systemImage: ItemCategory.secureNote.symbol) { new(.note) }
            Button("Card", systemImage: ItemCategory.card.symbol) { new(.card) }
            Button("Identity", systemImage: ItemCategory.identity.symbol) { new(.identity) }
            Menu("Other templates") {
                ForEach(ItemTemplate.menuOrder, id: \.self) { template in
                    Button(template.menuTitle, systemImage: template.symbol) { new(.template(template)) }
                }
            }
            if showsSharing {
                Divider()
                Button("New organization…", systemImage: "person.2.badge.plus") {
                    model.sharing.sheet = .newOrganization
                }
                Button("Join an organization…", systemImage: "envelope.open") {
                    model.sharing.sheet = .join("")
                }
            }
        } label: {
            Image(systemName: "plus")
        }
        .accessibilityLabel("New item")
        .disabled(!model.canEdit)
    }

    private func new(_ kind: PhoneModel.NewItemKind) {
        model.newItem(kind, folderID: folderID, destination: destination)
    }
}

// MARK: Lists

/// The items of a category, a folder, a shared vault… with search, swipe
/// actions and multiple selection (edit mode).
struct ItemListView: View {
    @Environment(PhoneModel.self) private var model
    let filter: SidebarFilter
    @State private var query = ""
    /// Chosen order, kept on the iPhone (`PhoneModel.sortOrder`).
    private var order: ResultOrder { model.sortOrder }
    @State private var selection = Set<String>()
    @State private var editMode = EditMode.inactive
    @State private var confirmTrash: [String]?

    var body: some View {
        @Bindable var model = model
        let rows = shown(model.rows(query: query, filter: filter, order: order))
        let subfolders = editMode.isEditing ? [] : self.subfolders
        List(selection: $selection) {
            if rows.isEmpty, subfolders.isEmpty {
                emptyState
                    .listRowBackground(Color.clear)
            }
            ForEach(subfolders) { folder in
                NavigationLink(value: PhoneModel.Route.list(.folder(name: folder.path))) {
                    HomeRow(title: folder.name, symbol: "folder.fill", tint: .blue, count: folder.count)
                }
            }
            ForEach(rows) { row in
                ItemRowLink(row: row, showsPasskey: showsPasskey)
                    .tag(row.id)
            }
        }
        .listStyle(.plain)
        .navigationTitle(title)
        .navigationBarTitleDisplayMode(.large)
        .navigationSubtitleIfAvailable(rows.count == 1 ? String(localized: "1 item") : String(localized: "\(rows.count) items"))
        .searchable(text: $query, prompt: "Search")
        .autocorrectionDisabled()
        .textInputAutocapitalization(.never)
        .refreshable { await model.syncNow() }
        .environment(\.editMode, $editMode)
        .toolbar {
            ToolbarItemGroup(placement: .topBarTrailing) {
                if !editMode.isEditing {
                    Menu {
                        Picker("Sort", selection: $model.sortOrder) {
                            ForEach(ResultOrder.menu, id: \.self) { order in
                                Text(order.label).tag(order)
                            }
                        }
                    } label: {
                        Image(systemName: "arrow.up.arrow.down")
                    }
                    .accessibilityLabel("Sort")
                    .accessibilityIdentifier("sort-menu")
                    NewItemMenu(folderID: folderID, destination: destination)
                }
            }
            ToolbarSpacerIfAvailable()
            ToolbarItemGroup(placement: .topBarTrailing) {
                if model.canEdit, !rows.isEmpty {
                    Button(editMode.isEditing ? "OK" : "Select") {
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
            Button("Move to Trash", role: .destructive) {
                let ids = confirmTrash ?? []
                confirmTrash = nil
                Task {
                    await model.performBulk(.trash, on: ids)
                    endEditing()
                }
            }
        } message: {
            Text("Can be restored from the trash")
        }
        .onChange(of: model.revision) {
            // The items that left the list leave the selection.
            let ids = Set(shown(model.rows(query: query, filter: filter, order: order)).map(\.id))
            selection.formIntersection(ids)
        }
        #if DEBUG
        .onAppear { PhoneBenchDriver.listShown = true }
        #endif
    }

    /// Passkeys view: site and user of each passkey.
    private var showsPasskey: Bool {
        if filter == .passkeys { return true }
        let words = query.lowercased().split(separator: " ")
        return words.contains { $0.hasPrefix("passkey:") || $0 == "has:passkey" }
    }

    private var trashTitle: String {
        let count = confirmTrash?.count ?? 0
        return count == 1 ? String(localized: "Move 1 item to the trash?") : String(localized: "Move \(count) items to the trash?")
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
                ContentUnavailableView("Trash is empty", systemImage: "trash",
                                       description: Text("Deleted items stay here until you restore them, or until the server deletes them for good."))
            case .archived:
                ContentUnavailableView("No archived items", systemImage: "archivebox",
                                       description: Text("Archive an item to keep it out of the list and the search."))
            default:
                ContentUnavailableView("No items", systemImage: "tray",
                                       description: Text("Tap + to create one."))
            }
        }
    }

    /// The open folder's subfolders, above its items, like Files; not while
    /// searching, which covers the whole folder, subfolders included.
    private var subfolders: [FolderNode] {
        guard case .folder(let path) = filter, query.isEmpty else { return [] }
        return FolderNode.find(path, in: model.folderTree)?.children ?? []
    }

    /// The rows listed: a folder with subfolders only lists its own items
    /// (the core's filter includes its subfolders', reached by their rows).
    private func shown(_ rows: [ResultRow]) -> [ResultRow] {
        guard case .folder(let path) = filter, !subfolders.isEmpty else { return rows }
        return rows.filter { $0.summary.folder.map(FolderNode.path(of:)) == path }
    }

    /// Folder offered for a new item created from this list.
    private var folderID: String? {
        guard case .folder(let name) = filter else { return nil }
        return model.folders.first { $0.name == name }?.id
    }

    /// Collection offered for a new item created from a shared vault.
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
        case .all: String(localized: "All items")
        case .favorites: String(localized: "Favorites")
        case .withTotp: String(localized: "One-time codes")
        case .passkeys: String(localized: "Passkeys")
        case .category(let category): category.label
        case .template(let template): template.label
        // The last part of the name: the screen above is its parent.
        case .folder(let name): String(name.split(separator: "/").last ?? Substring(name))
        case .tag(let name): "#\(name)"
        case .archived: String(localized: "Archived items")
        case .trash: String(localized: "Trash")
        case .organization(let id): model.organizations.first { $0.id == id }?.name ?? String(localized: "Shared vault")
        case .collection(let id):
            model.organizations.flatMap(\.collections).first { $0.id == id }?.name ?? String(localized: "Collection")
        }
    }
}

/// Bottom bar in selection mode: actions on the chosen items.
private struct BulkActionsBar: View {
    @Environment(PhoneModel.self) private var model
    let ids: [String]
    let filter: SidebarFilter
    let all: [String]
    @Binding var selection: Set<String>
    @Binding var confirmTrash: [String]?

    var body: some View {
        Button(selection.count == all.count ? "None" : "All") {
            selection = selection.count == all.count ? [] : Set(all)
        }
        Spacer()
        Text(selection.isEmpty ? "No selection" : selection.count > 1 ? "\(selection.count) selected" : "\(selection.count) item selected")
            .font(.footnote)
            .foregroundStyle(.secondary)
            .fixedSize()
        Spacer()
        Menu {
            switch filter {
            case .trash:
                Button("Restore", systemImage: "arrow.uturn.backward") { run(.restore) }
            case .archived:
                Button("Unarchive", systemImage: "tray.and.arrow.up") { run(.unarchive) }
                Button("Move to Trash", systemImage: "trash", role: .destructive) { confirmTrash = ids }
            default:
                Button("Add to favorites", systemImage: "star") { run(.favorite(favorite: true)) }
                Button("Remove from favorites", systemImage: "star.slash") { run(.favorite(favorite: false)) }
                Button("Move to folder…", systemImage: "folder") {
                    model.moveRequest = PhoneModel.MoveRequest(itemIDs: ids)
                }
                if !model.writableOrganizations.isEmpty, !model.shareableIDs(ids).isEmpty {
                    Button("Share…", systemImage: "person.2") { model.openSharing(items: ids) }
                }
                if !model.unshareableIDs(ids).isEmpty {
                    Button("Remove from sharing…", systemImage: "person.2.slash") { model.requestUnshare(ids) }
                }
                Button("Archive", systemImage: "archivebox") { run(.archive) }
                Button("Move to Trash", systemImage: "trash", role: .destructive) { confirmTrash = ids }
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

// MARK: Rows

/// An item row that opens its page, with its quick actions.
struct ItemRowLink: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.zoomNamespace) private var zoom
    let row: ResultRow
    /// Passkeys view: the passkey's site and user.
    var showsPasskey = false

    var body: some View {
        let summary = row.summary
        NavigationLink(value: PhoneModel.Route.item(summary.id)) {
            ItemRow(row: row, showsPasskey: showsPasskey)
                .equatable()
                .zoomSource(id: summary.id, in: zoom)
        }
        .swipeActions(edge: .leading, allowsFullSwipe: true) {
            if summary.state == .active, model.canModify(summary) {
                Button {
                    Task { await model.setFavorite(summary.id, !summary.favorite) }
                } label: {
                    Label(summary.favorite ? "Remove from favorites" : "Favorite",
                          systemImage: summary.favorite ? "star.slash.fill" : "star.fill")
                }
                .tint(.yellow)
                if !model.writableOrganizations.isEmpty, summary.sharing == nil {
                    Button {
                        model.openSharing(summary.id)
                    } label: {
                        Label("Share", systemImage: "person.2.fill")
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
                        Label("Trash", systemImage: "trash")
                    }
                    .tint(.red)
                    Button {
                        Task { await model.setArchived(summary.id, true) }
                    } label: {
                        Label("Archive", systemImage: "archivebox")
                    }
                    .tint(.brown)
                case .archived:
                    Button {
                        Task { await model.setArchived(summary.id, false) }
                    } label: {
                        Label("Unarchive", systemImage: "tray.and.arrow.up")
                    }
                    .tint(.brown)
                case .trashed:
                    Button {
                        Task { await model.restore(summary.id) }
                    } label: {
                        Label("Restore", systemImage: "arrow.uturn.backward")
                    }
                    .tint(.green)
                }
            }
        }
        .contextMenu {
            if summary.category == .login {
                Button("Copy username", systemImage: "person") { model.copyUsername(of: summary.id) }
                Button("Copy password", systemImage: "key") { model.copyPassword(of: summary.id) }
            }
            if summary.hasTotp {
                Button("Copy code", systemImage: "clock") { model.copyCode(of: summary.id) }
            }
        }
    }
}

/// Icon, title (found characters highlighted), subtitle and indicators: the
/// Mac's row (`ItemRowContent`). Compared before being recomputed: an
/// unchanged row isn't rebuilt while typing.
struct ItemRow: View, Equatable {
    let row: ResultRow
    var showsPasskey = false

    nonisolated static func == (lhs: ItemRow, rhs: ItemRow) -> Bool {
        lhs.row.summary == rhs.row.summary && lhs.row.highlights == rhs.row.highlights
            && lhs.showsPasskey == rhs.showsPasskey
    }

    var body: some View {
        #if DEBUG
        let _ = PhoneBenchDriver.rowsBuilt += 1
        #endif
        ItemRowContent(summary: row.summary, highlights: row.highlights, spacing: 12,
                       subtitleFont: .subheadline, showsProtection: true, showsPasskey: showsPasskey) {
            ItemIcon(summary: row.summary, size: 40)
        }
        .padding(.vertical, 2)
    }
}

/// An item's icon, with the site's served by the account's Vaultwarden.
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

extension Color {
    static let warningText = Color(light: Color(red: 0.66, green: 0.30, blue: 0.0), dark: .orange)
}
