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
                    EmptyPaneDetailView(title: String(localized: "No Send selected"), symbol: "paperplane")
                }
            case .emergency:
                if let selected = model.emergency.selected {
                    EmergencyDetailView(contact: selected.contact, trusted: selected.trusted)
                        .id(selected.contact.id)
                } else {
                    EmptyPaneDetailView(title: String(localized: "No access selected"), symbol: "person.2.badge.key")
                }
            case .members:
                if let member = model.members.selected {
                    MemberDetailView(member: member)
                        .id(member.id)
                } else {
                    EmptyPaneDetailView(title: String(localized: "No member selected"), symbol: "person.3")
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
                        Label("Invite a Contact", systemImage: "plus")
                    }
                    .help("Invite an emergency contact")
                case .members:
                    Button {
                        model.inviteMembers()
                    } label: {
                        Label("Invite", systemImage: "person.badge.plus")
                    }
                    .help("Invite people to the organization")
                    .disabled(model.membersOrganization?.canManageMembers != true)
                case .audit, nil:
                    Menu {
                        Button("New Login") { model.newItem(login: true) }
                        Button("New Secure Note") { model.newItem(login: false) }
                        Button("New SSH Key…") { model.newSshKey() }
                        Button("New Document…") { model.newDocument() }
                        Divider()
                        ForEach(ItemTemplate.menuOrder, id: \.self) { template in
                            Button(template.menuTitle) { model.newItem(template: template) }
                        }
                    } label: {
                        Label("New Item", systemImage: "plus")
                    } primaryAction: {
                        model.newItem(login: true)
                    }
                    .disabled(!model.canEdit)
                    .help(model.canEdit ? "New login (⌘N)" : "Mock vault: read-only")
                }
            }
            // Actions of the selected item: always the same buttons, dimmed
            // when they don't apply. Here rather than in the detail, rebuilt
            // on each selection: the toolbar no longer flickers. Absent from
            // the sends and emergency access panes, which don't display a
            // vault item.
            ToolbarItemGroup(placement: .primaryAction) {
                if model.pane != .sends && model.pane != .emergency && model.pane != .members {
                    ItemToolbarActions()
                }
            }
            ToolbarItem(placement: .primaryAction) {
                Button {
                    model.lock()
                } label: {
                    Label("Lock", systemImage: "lock")
                }
                .help("Lock the vault (⌃⌘L)")
            }
        }
        .overlay(alignment: .bottom) {
            if let toast = model.toast {
                ToastView(toast: toast)
                    .padding(.bottom, 24)
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
        // The view stays mounted behind the lock screen (see RootView):
        // unlocking is what hands control back to it.
        .onAppear { searchFocused = model.lockState == .unlocked }
        .onChange(of: model.lockState) { _, state in
            searchFocused = state == .unlocked
            guard state == .unlocked, let start = model.unlockStartedAt else { return }
            model.unlockStartedAt = nil
            // Next run loop turn: the list is drawn.
            DispatchQueue.main.async {
                Perf.log.notice("vault displayed at +\(Perf.ms(since: start)) ms after the key was received")
            }
        }
        .onKeyPress(.escape) {
            if !model.query.isEmpty { model.query = ""; return .handled }
            return .ignored
        }
        .onChange(of: model.searchRequests) {
            DispatchQueue.main.async { searchFocused = true }
        }
    }
}

/// Actions of the selected item, in the toolbar.
private struct ItemToolbarActions: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        // Several items selected: archiving applies to all of them, the rest
        // (a single detail) is dimmed.
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
            Label("Archive", systemImage: "archivebox")
        }
        .help(multi ? "Archive the \(model.selectedIDs.count) selected items"
                    : "Archive: keep the item out of the way")
        .disabled(multi ? !model.canEdit || model.availability(of: model.selectedIDs).active == 0
                        : !model.canModify(item) || item?.state != .active)
        Button {
            if let item { Task { await model.edit(item.id) } }
        } label: {
            Label("Edit", systemImage: "pencil")
        }
        .help(item?.sharing?.readOnly == true ? "Shared read-only" : "Edit (⌘E)")
        .disabled(!model.canModify(item) || item == nil || item?.state == .trashed)
        Button {
            if let item { model.openSharing(item.id) }
        } label: {
            Label("Share", systemImage: "person.2")
        }
        .help(item?.sharing == nil ? "Share in a shared vault…" : "Collections…")
        .disabled(!model.canModify(item) || item?.state != .active
                  || (item?.sharing == nil && model.writableOrganizations.isEmpty))
        Button {
            if let item { model.copyPassword(of: item.id) }
        } label: {
            Label("Copy Password", systemImage: "key")
        }
        .help("Copy the password (⇧⌘C)")
        .disabled(item?.category != .login)
        Button {
            if let host = item?.host, let url = URL(string: "https://\(host)") {
                NSWorkspace.shared.open(url)
            }
        } label: {
            Label("Open Website", systemImage: "safari")
        }
        .help(item?.host.map { String(localized: "Open \($0)") } ?? String(localized: "Open the website"))
        .disabled(item?.host == nil)
    }
}

// MARK: Sidebar

struct SidebarView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        // A pane open (audit, sends…): no filter highlighted, and a click on
        // any of them goes back to the list.
        List(selection: Binding(get: { model.pane == nil ? model.filter : nil },
                                set: { if let f = $0 { model.filter = f } })) {
            Section {
                row(.all, String(localized: "All items"), "square.grid.2x2", count: model.counts?.all)
                row(.favorites, String(localized: "Favorites"), "star.fill", count: model.counts?.favorites, tint: .yellow)
                row(.withTotp, String(localized: "One-time codes"), "clock.badge.checkmark", count: model.counts?.withTotp, tint: .teal)
                row(.passkeys, String(localized: "Passkeys"), "person.badge.key.fill", count: model.counts?.passkeys, tint: .purple)
            }
            Section("Categories") {
                ForEach(model.counts?.categories ?? [], id: \.category) { entry in
                    row(.category(category: entry.category), entry.category.label, entry.category.symbol,
                        count: entry.count, tint: entry.category.tint)
                }
                // Templates (Wi-Fi, passport…): only those that have items.
                ForEach(model.counts?.templates ?? [], id: \.template) { entry in
                    row(.template(template: entry.template), entry.template.label, entry.template.symbol,
                        count: entry.count, tint: entry.template.tint)
                }
            }
            let folders = model.counts?.folders ?? []
            if !folders.isEmpty || model.canManageFolders {
                Section {
                    // Nested by name ("Work/Clients"); items dropped on a
                    // folder move into it.
                    OutlineGroup(FolderNode.tree(folders.map { ($0.name, $0.count) }), children: \.children) { node in
                        row(.folder(name: node.path), node.name, "folder", count: node.count, tint: .secondary)
                            .modifier(FolderDropTarget(path: node.path))
                            .contextMenu { folderMenu(node.path) }
                    }
                } header: {
                    HStack {
                        Text("Folders")
                        Spacer()
                        if model.canManageFolders {
                            Button {
                                model.promptNewFolder()
                            } label: {
                                Image(systemName: "plus")
                                    .accessibilityLabel("New Folder…")
                            }
                            .buttonStyle(.borderless)
                            .help("New Folder…")
                        }
                    }
                }
            }
            SharedVaultsSection()
            if let counts = model.counts, counts.archived + counts.trashed > 0 {
                Section("Storage") {
                    row(.archived, String(localized: "Archived"), "archivebox", count: counts.archived, tint: .secondary)
                    row(.trash, String(localized: "Trash"), "trash", count: counts.trashed, tint: .secondary)
                }
            }
            // Vaultwarden has no tags: the section only appears with the mock vault.
            if let tags = model.counts?.tags, !tags.isEmpty {
                Section("Tags") {
                    ForEach(tags, id: \.name) { tag in
                        row(.tag(name: tag.name), tag.name, "number", count: tag.count, tint: .secondary)
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) {
            // Without a background, the last rows of the list scroll under the
            // buttons and the footer.
            VStack(spacing: 0) {
                Divider()
                    .padding(.bottom, 8)
                AuditSidebarButton()
                DuplicatesSidebarButton()
                if model.showsAccountPanes { EmergencySidebarButton() }
                if model.showsAccountPanes { SendsSidebarButton() }
                VaultFooter()
            }
            .background(.bar)
        }
        .alert(model.folderPrompt?.folder == nil ? "New Folder" : "Rename Folder",
               isPresented: Binding(get: { model.folderPrompt != nil }, set: { if !$0 { model.folderPrompt = nil } })) {
            TextField("Name", text: Binding(get: { model.folderPrompt?.name ?? "" },
                                            set: { model.folderPrompt?.name = $0 }))
            Button(model.folderPrompt?.folder == nil ? "Create" : "Rename") {
                Task { await model.submitFolderPrompt() }
            }
            .disabled((model.folderPrompt?.name ?? "").trimmingCharacters(in: .whitespaces).isEmpty)
            Button("Cancel", role: .cancel) { model.folderPrompt = nil }
        } message: {
            Text("Use “/” to nest it, for example “Work/Clients”.")
        }
        .confirmationDialog("Delete the folder “\(model.folderToDelete?.name ?? "")”?",
                            isPresented: Binding(get: { model.folderToDelete != nil },
                                                 set: { if !$0 { model.folderToDelete = nil } })) {
            Button("Delete Folder", role: .destructive) {
                if let folder = model.folderToDelete { Task { await model.deleteFolder(folder) } }
                model.folderToDelete = nil
            }
        } message: {
            Text("Its items stay in the vault, without a folder.")
        }
    }

    @ViewBuilder
    private func folderMenu(_ path: String) -> some View {
        if model.canManageFolders {
            Button("New Folder…") { model.promptNewFolder() }
            if let folder = model.folder(at: path) {
                Button("Rename Folder…") { model.promptRenameFolder(folder) }
                Button("Delete Folder…", role: .destructive) { model.folderToDelete = folder }
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

/// Entry at the bottom of the sidebar (audit, duplicates, sends, emergency
/// access): a button rather than a list row, highlighted when its pane
/// occupies the middle column.
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
            .padding(.horizontal, 8)
            .padding(.vertical, 8)
            .background(active ? Theme.wash(0.08) : ContrastStyle(Color.clear),
                        in: RoundedRectangle(cornerRadius: Theme.radiusMedium, style: .continuous))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 8)
        .padding(.bottom, 8)
        .help(help ?? "")
    }
}

/// Header of a pane of the middle column: title, explanation, action, and
/// the last message (success or error).
struct PaneHeader<Action: View>: View {
    let title: String
    let caption: String
    var busy = false
    var notice: String?
    var error: String?
    @ViewBuilder var action: Action

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
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
        .padding(.bottom, 8)
    }
}

/// Account and sync status. A click starts the sync again.
struct VaultFooter: View {
    @Environment(AppModel.self) private var model
    @State private var showError = false

    var body: some View {
        HStack(spacing: 4) {
            Button {
                Task { await model.syncNow() }
            } label: {
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
                    Spacer(minLength: 0)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .disabled(model.mode != .vaultwarden)
            .help(help)
            .accessibilityElement(children: .combine)
            .accessibilityHint(model.mode == .vaultwarden ? "Syncs now" : "")
            if let failure {
                Button {
                    showError = true
                } label: {
                    Image(systemName: "exclamationmark.circle")
                        .foregroundStyle(.red)
                        .accessibilityLabel("Show the sync error")
                }
                .buttonStyle(.borderless)
                .help("Show the sync error")
                .popover(isPresented: $showError, arrowEdge: .top) {
                    Text(failure)
                        .font(.callout)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(width: 300, alignment: .leading)
                        .padding(16)
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
    }

    private var failure: String? {
        if case .failed(let message) = model.syncState { message } else { nil }
    }

    private var help: String {
        guard model.mode == .vaultwarden else { return "" }
        if let failure { return String(localized: "\(failure). Sync (⌘R)") }
        return model.pendingLabel.map { String(localized: "\($0): sent when the server is back. Sync (⌘R)") }
            ?? String(localized: "Sync (⌘R)")
    }

    private var title: String {
        model.mode == .demo ? String(localized: "Mock vault") : model.account?.email ?? "Vaultwarden"
    }

    private var dotColor: Color {
        if model.mode == .demo { return .secondary }
        // Changes are waiting for the server.
        if model.pendingChanges > 0, model.syncState != .syncing, model.syncState != .offline { return .orange }
        return switch model.syncState {
        case .idle: .green
        case .syncing: .secondary
        case .offline: .orange
        case .failed: .red
        }
    }

    private var status: String {
        if model.mode == .demo { return String(localized: "Offline · local data") }
        let last = model.account?.syncedAt.map { synced in
            Date(timeIntervalSince1970: TimeInterval(synced)).formatted(date: .omitted, time: .shortened)
        }
        if let pending = model.pendingLabel, model.syncState != .syncing {
            // "Offline · 3 pending changes"
            return model.syncState == .offline ? String(localized: "Offline · \(pending)") : pending
        }
        switch model.syncState {
        case .syncing: return String(localized: "Syncing…")
        case .offline: return String(localized: "Offline · as of \(last ?? "—")")
        case .failed(let message): return message
        case .idle: return last.map { String(localized: "Synced at \($0)") } ?? String(localized: "Never synced")
        }
    }
}

// MARK: List

struct ItemListView: View {
    @Environment(AppModel.self) private var model
    var searchFocused: FocusState<Bool>.Binding
    // A click on a row gives focus to the list: the arrows then scroll
    // through the items, not the sidebar.
    @FocusState private var listFocused: Bool

    var body: some View {
        @Bindable var model = model
        VStack(spacing: 0) {
            SearchField(text: $model.query, focused: searchFocused, submit: model.copySelectedPassword)
                .padding(.horizontal, 12)
                .padding(.top, 8)
                .padding(.bottom, 8)
            HStack {
                Text(resultCaption)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
                Spacer()
                if model.filter == .category(category: .sshKey) && model.canEdit {
                    Button("New SSH Key…", systemImage: "plus") { model.newSshKey() }
                        .buttonStyle(.borderless)
                        .font(.caption)
                        .help("Generate an SSH key in the vault")
                }
                Menu {
                    Picker("Sort", selection: $model.sort) {
                        ForEach(ResultOrder.menu, id: \.self) { order in
                            Text(order.label).tag(order)
                        }
                    }
                    .pickerStyle(.inline)
                } label: {
                    Image(systemName: "arrow.up.arrow.down")
                        .accessibilityLabel("Sort")
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
                .help("Sort: \(model.sort.label)")
                .layoutMark("sort-menu")
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 8)
            Divider()

            if model.rows.isEmpty {
                NoResultsView(query: model.query,
                              emptyVault: model.query.isEmpty && model.filter == .all && model.counts?.all == 0)
            } else {
                // Lazy stack rather than `List`: the macOS list computes the
                // height of all its rows, so builds them all (and requests all
                // the icons) as soon as the results change.
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
                        .padding(.vertical, 8)
                    }
                    .focusable()
                    .focusEffectDisabled()
                    .focused($listFocused)
                    .onKeyPress(keys: [.downArrow, .upArrow]) { press in arrow(press) }
                    // Esc: back to the active item alone (otherwise, as
                    // before, Esc clears the search).
                    .onKeyPress(.escape) {
                        guard model.isMultiSelection else { return .ignored }
                        model.applySelection(.collapse)
                        return .handled
                    }
                    .onChange(of: model.selection) { _, id in
                        if let id { proxy.scrollTo(id) }
                    }
                    // ⌘A: all the results, when the list has focus (in the
                    // search field, ⌘A selects the text).
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

    /// ↑/↓: neighboring item; with ⇧, extends the selection from the anchor.
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
        let count = n > 1 ? String(localized: "\(n) items") : String(localized: "\(n) item")
        #if DEBUG
        let micro = Double(model.lastSearchDuration.components.attoseconds) / 1e12
            + Double(model.lastSearchDuration.components.seconds) * 1e6
        let time = micro < 1000 ? String(format: "%.0f µs", micro) : String(format: "%.1f ms", micro / 1000)
        return "\(count) · \(time)"
        #else
        return count
        #endif
    }
}

/// A list row: highlight on hover (without animation, state specific to the
/// row: only the two rows concerned redraw), selection as soon as the
/// button is pressed, like the Finder.
///
/// Compared by its content (`equatable`): a selection change only redraws
/// the rows whose state changes, not all the visible ones.
private struct ListRow: View, Equatable {
    @Environment(AppModel.self) private var model
    let row: ResultRow
    let selected: Bool
    /// Passkeys view: site and user of the passkey.
    var showsPasskey = false
    /// Gives focus to the list (the arrows then scroll through the items).
    let focusList: () -> Void
    @State private var hovered = false
    @State private var pressed = false
    @State private var deferredClick = false

    nonisolated static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.selected == rhs.selected && lhs.row.summary == rhs.row.summary
            && lhs.row.highlights == rhs.row.highlights && lhs.showsPasskey == rhs.showsPasskey
    }

    var body: some View {
        ItemRow(summary: row.summary, highlights: row.highlights, selected: selected, showsPasskey: showsPasskey)
            .padding(.horizontal, 8)
            .background(selected ? ContrastStyle(Theme.selection) : hovered ? Theme.wash(0.07) : ContrastStyle(Color.clear),
                        in: RoundedRectangle(cornerRadius: Theme.radiusMedium, style: .continuous))
            .contentShape(Rectangle())
            .onHover { hovered = $0 }
            // On press, not on release: the highlight follows the click
            // without waiting. ⌃-click: only the context menu. A plain press
            // on a row of a multiple selection waits for the release, like
            // the Finder: dragging carries the whole selection.
            .simultaneousGesture(
                DragGesture(minimumDistance: 0)
                    .onChanged { _ in
                        guard !pressed else { return }
                        pressed = true
                        let modifiers = NSEvent.modifierFlags
                        guard !modifiers.contains(.control) else { return }
                        if modifiers.intersection([.command, .shift]).isEmpty,
                           model.isMultiSelection, model.selectedSet.contains(row.id) {
                            deferredClick = true
                        } else {
                            model.click(row.id, modifiers: modifiers)
                        }
                        focusList()
                    }
                    .onEnded { _ in
                        if deferredClick { model.click(row.id, modifiers: []) }
                        deferredClick = false
                        pressed = false
                    }
            )
            // To a sidebar folder (FolderDropTarget).
            .onDrag {
                deferredClick = false
                return ItemDrag.provider(model.dragIDs(from: row.id))
            }
            .contextMenu { RowMenu(summary: row.summary) }
            .accessibilityElement(children: .combine)
            .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
            .accessibilityAction { model.click(row.id, modifiers: []) }
            .accessibilityActions {
                if row.summary.category == .login {
                    Button("Copy Password") { model.copyPassword(of: row.summary.id) }
                    Button("Copy Username") { model.copyUsername(of: row.summary.id) }
                }
            }
    }
}

struct SearchField: View {
    @Binding var text: String
    var focused: FocusState<Bool>.Binding
    var submit: () -> Void = {}

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                .accessibilityHidden(true)
            TextField("Search Verrou", text: $text)
                .textFieldStyle(.plain)
                .focused(focused)
                .onSubmit(submit)
                .accessibilityHint("Return copies the selected login's password")
                .layoutMark("search")
            if !text.isEmpty {
                Button { text = "" } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(.tertiary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Clear the search")
            } else {
                Text("⌘F").font(.caption2.weight(.semibold)).foregroundStyle(.tertiary)
            }
        }
        .padding(.horizontal, 8)
        .frame(height: 32)
        .background(Color(nsColor: .textBackgroundColor), in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(focused.wrappedValue ? Theme.focusRing(0.7) : Theme.border(0.2), lineWidth: focused.wrappedValue ? 1.5 : 1))
    }
}

struct ItemRow: View {
    let summary: ItemSummary
    let highlights: [UInt32]
    /// On an accent background: white text.
    var selected = false
    var showsPasskey = false

    var body: some View {
        #if DEBUG || BENCH
        let _ = BenchDriver.rowsBuilt += 1
        #endif
        ItemRowContent(summary: summary, highlights: highlights, selected: selected, showsPasskey: showsPasskey) {
            ItemIcon(summary: summary, size: 34)
        }
        .padding(.vertical, 8)
        .contentShape(Rectangle())
    }
}

struct RowMenu: View {
    @Environment(AppModel.self) private var model
    let summary: ItemSummary

    var body: some View {
        // Right-click on a row of the selection: the action applies to the
        // whole selection; on another row, to this row alone.
        if model.isMultiSelection && model.selectedSet.contains(summary.id) {
            BulkActions(ids: model.selectedIDs, style: .menu)
        } else {
            single
        }
    }

    @ViewBuilder private var single: some View {
        if summary.category == .login {
            Button("Copy Username") { model.copyUsername(of: summary.id) }
            Button("Copy Password") { model.copyPassword(of: summary.id) }
        }
        if summary.category == .sshKey {
            Button("Copy Public Key") { model.copyPublicKey(of: summary.id) }
        }
        if let host = summary.host, let url = URL(string: "https://\(host)") {
            Button("Open \(host)") { NSWorkspace.shared.open(url) }
        }
        if summary.canChangePassword {
            Button("Change Password") { Task { await model.changePassword(of: summary) } }
                .disabled(model.changingPassword != nil)
        }
        if model.sendsAvailable, summary.state != .trashed,
           summary.category == .login || summary.category == .secureNote {
            Button("Send Securely…") {
                model.composeSend(from: summary)
            }
        }
        if model.canEdit, !model.canModify(summary) {
            Divider()
            // Read-only collection: nothing to edit from this account.
            Text("Shared read-only")
        } else if model.canEdit {
            Divider()
            if summary.state == .active, summary.sharing != nil || !model.writableOrganizations.isEmpty {
                Button(summary.sharing == nil ? "Share…" : "Collections…") { model.openSharing(summary.id) }
            }
            if summary.canUnshare {
                Button("Remove from Sharing…") { model.requestUnshare([summary.id]) }
            }
            switch summary.state {
            case .active:
                Button("Edit…") { Task { await model.edit(summary.id) } }
                Button(summary.favorite ? "Remove from Favorites" : "Add to Favorites") {
                    Task { await model.setFavorite(summary.id, !summary.favorite) }
                }
                Button("Move to Folder…") { model.moveRequest = MoveRequest(itemIDs: [summary.id]) }
                Button("Archive") { Task { await model.setArchived(summary.id, true) } }
                Button("Move to Trash") { Task { await model.trash(summary.id) } }
            case .archived:
                Button("Move to Folder…") { model.moveRequest = MoveRequest(itemIDs: [summary.id]) }
                Button("Unarchive") { Task { await model.setArchived(summary.id, false) } }
                Button("Move to Trash") { Task { await model.trash(summary.id) } }
            case .trashed:
                Button("Restore") { Task { await model.restore(summary.id) } }
            }
        }
    }
}

struct NoResultsView: View {
    @Environment(AppModel.self) private var model
    let query: String
    var emptyVault = false

    var body: some View {
        if emptyVault {
            ContentUnavailableView {
                Label("Your vault is empty", systemImage: "key.horizontal")
            } description: {
                Text("Add your first login, or import the ones of another password manager.")
            } actions: {
                if model.canEdit {
                    Button("New Login") { model.newItem(login: true) }
                        .buttonStyle(.borderedProminent)
                    Button("Import…") { model.startImport() }
                }
            }
            .frame(maxHeight: .infinity)
        } else {
            ContentUnavailableView {
                Label(query.isEmpty ? "No items" : "No results", systemImage: "magnifyingglass")
            } description: {
                if !query.isEmpty {
                    if model.mode == .demo {
                        Text("Nothing matches “\(query)”.\nTry `tag:bank`, `type:card` or `!word` to exclude.")
                    } else {
                        Text("Nothing matches “\(query)”.\nTry `type:card` or `!word` to exclude.")
                    }
                }
            }
            .frame(maxHeight: .infinity)
        }
    }
}

struct EmptyDetailView: View {
    var body: some View {
        VStack(spacing: 12) {
            AppMark(size: 56).opacity(0.85)
            Text("Select an item").font(.title3.weight(.semibold))
            HStack(spacing: 16) {
                KeyHint(keys: "⌘F", label: "Search")
                KeyHint(keys: "↑↓", label: "Browse")
                KeyHint(keys: "↩", label: "Copy Password")
                KeyHint(keys: String(localized: "⌘⇧Space"), label: "Quick Access")
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// Right column of a pane, nothing selected.
struct EmptyPaneDetailView: View {
    let title: String
    let symbol: String

    var body: some View {
        ContentUnavailableView(title, systemImage: symbol)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// "Remove from Sharing…": what is going to happen, and the confirmation
/// (the organization's copy is permanently deleted).
struct UnshareView: View {
    @Environment(AppModel.self) private var model
    let request: UnshareRequest

    var body: some View {
        VStack(spacing: 0) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "person.2.slash.fill")
                    .accessibilityHidden(true)
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
                Section("Items") {
                    ForEach(request.itemIDs.prefix(6), id: \.self) { id in
                        if let summary = model.summary(id: id) {
                            HStack(spacing: 8) {
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
                        Text("and \(request.itemIDs.count - 6) more").foregroundStyle(.secondary)
                    }
                }
                Section {
                    Label("Re-encrypted with your key and a new item key: the organization can no longer read it.",
                          systemImage: "lock.rotation")
                    Label("The other members lose it, on all their devices.", systemImage: "person.2.slash")
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
            HStack(spacing: 8) {
                Spacer()
                if let progress = model.bulkProgress, model.unshareBusy {
                    ProgressView(value: Double(progress.done), total: Double(max(progress.total, 1)))
                        .frame(width: 120)
                    Text("\(progress.done) of \(progress.total)").font(.caption).monospacedDigit()
                }
                Button("Cancel") { model.unshareRequest = nil }
                    .keyboardShortcut(.cancelAction)
                    .disabled(model.unshareBusy)
                Button(request.itemIDs.count == 1 ? String(localized: "Remove from Sharing")
                                                   : String(localized: "Remove \(request.itemIDs.count) Items"),
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
