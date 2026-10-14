import SwiftUI

/// Section « Coffres partagés » de la barre latérale : chaque organisation,
/// puis ses collections, avec leurs effectifs.
struct SharedVaultsSection: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if !model.organizations.isEmpty {
            Section("Coffres partagés") {
                ForEach(model.organizations, id: \.id) { org in
                    row(.organization(id: org.id), org.name, "person.2.fill", count: org.count, tint: .indigo)
                        .contextMenu {
                            if org.manageUrl != nil {
                                Button("Gérer dans le coffre web") { model.openWebVault(organizationID: org.id) }
                            }
                        }
                    ForEach(org.collections, id: \.id) { collection in
                        row(.collection(id: collection.id), collection.name,
                            collection.readOnly ? "eye" : "square.stack",
                            count: collection.count, tint: .secondary)
                            .padding(.leading, 14)
                            .help(help(for: collection))
                    }
                    if org.canViewMembers && model.showsAccountPanes {
                        MembersSidebarRow(organization: org)
                    }
                }
                if model.organizations.contains(where: { $0.manageUrl != nil }) {
                    Button {
                        model.openWebVault(organizationID: currentOrganization)
                    } label: {
                        Label("Gérer dans le coffre web", systemImage: "arrow.up.forward.square")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.plain)
                    .help("Membres, collections et droits : dans le coffre web de Vaultwarden")
                }
            }
        }
    }

    /// L'organisation affichée (elle-même ou une de ses collections).
    private var currentOrganization: String? {
        switch model.filter {
        case .organization(let id): return id
        case .collection(let id): return model.organizations.first { $0.collections.contains { $0.id == id } }?.id
        default: return model.organizations.first?.id
        }
    }

    private func help(for collection: CollectionView) -> String {
        var rights: [String] = []
        if collection.readOnly { rights.append("lecture seule") }
        if collection.hidePasswords { rights.append("mots de passe masqués") }
        return rights.isEmpty ? collection.name : "\(collection.name) : \(rights.joined(separator: ", "))"
    }

    private func row(_ filter: SidebarFilter, _ title: String, _ symbol: String, count: UInt32, tint: Color) -> some View {
        Label {
            HStack {
                Text(title).lineLimit(1)
                Spacer()
                Text("\(count)").monospacedDigit().foregroundStyle(.secondary).font(.callout)
            }
        } icon: {
            Image(systemName: symbol).foregroundStyle(tint)
        }
        .tag(filter)
    }
}

/// « Partager… » : déplace un élément personnel dans les collections d'une
/// organisation. Pour un élément déjà partagé : « Collections… ».
struct SharingView: View {
    @Environment(AppModel.self) private var model
    @Bindable var flow: SharingFlow

    private var organization: OrganizationView? {
        model.organizations.first { $0.id == flow.organizationID }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: "person.2.fill")
                    .font(.system(size: 24))
                    .foregroundStyle(.indigo)
                VStack(alignment: .leading, spacing: 2) {
                    Text(flow.current == nil ? "Partager « \(flow.title) »" : "Collections de « \(flow.title) »")
                        .font(.title3.weight(.semibold))
                    Text(flow.current == nil
                         ? "L'élément quitte votre coffre personnel : il est rechiffré avec la clé de l'organisation, et ses membres le voient selon leurs droits."
                         : "Les membres de chaque collection cochée voient l'élément.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
            }
            .padding(16)
            Divider()

            Form {
                if flow.current == nil {
                    Picker("Organisation", selection: $flow.organizationID) {
                        ForEach(model.writableOrganizations, id: \.id) { org in
                            Text(org.name).tag(org.id)
                        }
                    }
                    .onChange(of: flow.organizationID) { _, _ in
                        let first = organization?.collections.first { !$0.readOnly }
                        flow.collectionIDs = Set(first.map { [$0.id] } ?? [])
                    }
                } else {
                    LabeledContent("Organisation", value: flow.current?.organization ?? "")
                }
                Section("Collections") {
                    ForEach(organization?.collections ?? [], id: \.id) { collection in
                        Toggle(isOn: binding(collection.id)) {
                            HStack {
                                Text(collection.name)
                                if collection.readOnly {
                                    Text("lecture seule").font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }
                        .disabled(collection.readOnly)
                    }
                }
                if let error = flow.error {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack(spacing: 10) {
                if organization?.manageUrl != nil {
                    Button("Gérer dans le coffre web") { model.openWebVault(organizationID: flow.organizationID) }
                        .buttonStyle(.link)
                }
                Spacer()
                if flow.busy { ProgressView().controlSize(.small) }
                Button("Annuler") { model.sharingFlow = nil }
                    .keyboardShortcut(.cancelAction)
                Button(flow.current == nil ? "Partager" : "Enregistrer") {
                    Task { await model.applySharing(flow) }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(flow.collectionIDs.isEmpty || flow.busy)
            }
            .padding(16)
        }
        .frame(width: 480)
        .frame(minHeight: 380)
    }

    private func binding(_ id: String) -> Binding<Bool> {
        Binding(
            get: { flow.collectionIDs.contains(id) },
            set: { on in
                if on { flow.collectionIDs.insert(id) } else { flow.collectionIDs.remove(id) }
            })
    }
}

/// Un champ que l'organisation masque à ce compte : ni affichage ni copie.
struct HiddenFieldRow: View {
    let field: FieldView

    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 4) {
                Text(field.label).font(.caption).foregroundStyle(.secondary)
                HStack(spacing: 6) {
                    MaskedText(count: 8)
                    Text("masqué par l'organisation").font(.caption).foregroundStyle(.tertiary)
                }
            }
            Spacer()
            Image(systemName: "eye.slash").foregroundStyle(.tertiary)
                .help("L'organisation masque ce champ pour votre compte. Le remplissage dans le navigateur reste possible.")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }
}
