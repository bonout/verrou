import SwiftUI

struct ItemDetailView: View {
    @Environment(AppModel.self) private var model
    let detail: ItemDetail

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                stateBanner
                if detail.summary.category == .sshKey, fields.contains(where: { $0.id == "public_key" }) {
                    HStack {
                        Button("Copier la clé publique", systemImage: "doc.on.doc") {
                            model.copyPublicKey(of: detail.summary.id)
                        }
                        .help("Pour ~/.ssh/authorized_keys, GitHub, GitLab…")
                        Spacer()
                    }
                }
                if !detail.urls.isEmpty || !fields.isEmpty {
                    FieldCard {
                        ForEach(Array(fields.enumerated()), id: \.element.id) { index, field in
                            if index > 0 { Divider().padding(.leading, 14) }
                            FieldRow(itemID: detail.summary.id, field: field)
                        }
                    }
                }
                if !detail.urls.isEmpty {
                    SectionTitle("Sites")
                    FieldCard {
                        ForEach(Array(detail.urls.enumerated()), id: \.offset) { index, url in
                            if index > 0 { Divider().padding(.leading, 14) }
                            WebsiteRow(url: url, primary: index == 0)
                        }
                    }
                }
                PasskeysSection(itemID: detail.summary.id, passkeys: model.session.passkeys(id: detail.summary.id))
                if detail.hasNotes {
                    SectionTitle("Notes")
                    FieldCard { NotesRow(itemID: detail.summary.id) }
                }
                if !history.isEmpty {
                    SectionTitle("Anciens mots de passe")
                    FieldCard {
                        ForEach(Array(history.enumerated()), id: \.element.id) { index, field in
                            if index > 0 { Divider().padding(.leading, 14) }
                            FieldRow(itemID: detail.summary.id, field: field)
                        }
                    }
                }
                if !detail.summary.tags.isEmpty {
                    TagsRow(tags: detail.summary.tags)
                }
                metadata
            }
            .padding(.horizontal, 28)
            .padding(.vertical, 24)
            .frame(maxWidth: 720, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 16) {
            ItemIcon(summary: detail.summary, size: 64)
            VStack(alignment: .leading, spacing: 5) {
                Text(detail.summary.title)
                    .font(.system(size: 24, weight: .bold))
                    .textSelection(.enabled)
                HStack(spacing: 8) {
                    Chip(text: detail.summary.category.singular, symbol: detail.summary.category.symbol, tint: detail.summary.category.tint)
                    if let folder = detail.summary.folder {
                        Chip(text: folder, symbol: "folder", tint: .secondary)
                    }
                    if detail.summary.reprompt {
                        Chip(text: "Protégé", symbol: "lock.shield", tint: .orange)
                            .help("Ses secrets demandent une confirmation (Touch ID ou mot de passe principal)")
                    }
                }
            }
            Spacer()
            Button {
                Task { await model.setFavorite(detail.summary.id, !detail.summary.favorite) }
            } label: {
                Image(systemName: detail.summary.favorite ? "star.fill" : "star")
                    .font(.title2)
                    .foregroundStyle(detail.summary.favorite ? Color.yellow : Color.secondary)
            }
            .buttonStyle(.plain)
            .disabled(!model.canEdit || detail.summary.state != .active || model.editorBusy)
            .help(detail.summary.favorite ? "Retirer des favoris" : "Ajouter aux favoris")
        }
        .padding(.bottom, 4)
    }

    /// Champs de l'élément, hors anciens mots de passe (`history-N`).
    private var fields: [FieldView] { detail.fields.filter { !$0.id.hasPrefix("history-") } }
    private var history: [FieldView] { detail.fields.filter { $0.id.hasPrefix("history-") } }

    @ViewBuilder private var stateBanner: some View {
        switch detail.summary.state {
        case .active:
            EmptyView()
        case .archived:
            banner("Archivé : hors de la liste, de la recherche et du remplissage.", symbol: "archivebox",
                   action: "Sortir des archives") { await model.setArchived(detail.summary.id, false) }
        case .trashed:
            banner("À la corbeille : supprimé définitivement par le serveur après 30 jours.", symbol: "trash",
                   action: "Restaurer") { await model.restore(detail.summary.id) }
        }
    }

    private func banner(_ text: String, symbol: String, action: String,
                        perform: @escaping () async -> Void) -> some View {
        HStack(spacing: 10) {
            Image(systemName: symbol).foregroundStyle(.secondary)
            Text(text).font(.callout).foregroundStyle(.secondary)
            Spacer()
            if model.canEdit {
                Button(action) { Task { await perform() } }
                    .disabled(model.editorBusy)
            }
        }
        .padding(12)
        .background(Color.primary.opacity(0.05), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }

    private var metadata: some View {
        let format = Date.FormatStyle(date: .long, time: .shortened).locale(Locale(identifier: "fr_FR"))
        return VStack(alignment: .leading, spacing: 3) {
            Text("Modifié le \(Date(timeIntervalSince1970: TimeInterval(detail.summary.modified)).formatted(format))")
            Text("Créé le \(Date(timeIntervalSince1970: TimeInterval(detail.created)).formatted(format))")
        }
        .font(.caption)
        .foregroundStyle(.tertiary)
        .padding(.top, 6)
    }
}

// MARK: Briques

struct FieldCard<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(spacing: 0) { content }
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: Theme.cornerRadius, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: Theme.cornerRadius, style: .continuous).strokeBorder(.separator.opacity(0.6), lineWidth: 0.5))
            .shadow(color: .black.opacity(0.04), radius: 2, y: 1)
    }
}

struct SectionTitle: View {
    let title: String
    init(_ title: String) { self.title = title }

    var body: some View {
        Text(title.uppercased())
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .tracking(0.6)
            .padding(.leading, 4)
            .padding(.bottom, -10)
    }
}

struct Chip: View {
    let text: String
    let symbol: String
    let tint: Color

    var body: some View {
        Label(text, systemImage: symbol)
            .font(.caption.weight(.medium))
            .foregroundStyle(tint == .secondary ? Color.secondary : tint)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background((tint == .secondary ? Color.secondary : tint).opacity(0.12), in: Capsule())
    }
}

/// Une ligne de champ : un clic copie, le survol montre les actions.
struct FieldRow: View {
    @Environment(AppModel.self) private var model
    let itemID: String
    let field: FieldView
    @State private var hovering = false
    @State private var now = Date()

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            VStack(alignment: .leading, spacing: 4) {
                Text(field.label)
                    .font(.caption)
                    .foregroundStyle(field.fieldType == .password || field.fieldType == .totp ? Theme.accent : Color.secondary)
                value
            }
            Spacer(minLength: 8)
            if field.secret && field.fieldType != .totp {
                IconButton(symbol: model.revealed[field.id] == nil ? "eye" : "eye.slash",
                           help: model.revealed[field.id] == nil ? "Afficher" : "Masquer") {
                    withAnimation(.snappy(duration: 0.18)) { model.toggleReveal(field.id, of: itemID) }
                }
                .opacity(hovering || model.revealed[field.id] != nil ? 1 : 0)
            }
            IconButton(symbol: "doc.on.doc", help: "Copier") {
                model.copyField(field, of: itemID)
            }
            .opacity(hovering ? 1 : 0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .contentShape(Rectangle())
        .background(hovering ? Color.primary.opacity(0.035) : .clear)
        .onHover { hovering = $0 }
        .onTapGesture { model.copyField(field, of: itemID) }
        .accessibilityElement(children: .combine)
        .accessibilityAction(named: "Copier") { model.copyField(field, of: itemID) }
    }

    @ViewBuilder private var value: some View {
        switch field.fieldType {
        case .totp:
            TimelineView(.periodic(from: .now, by: 1)) { context in
                if let code = model.totpCode(of: itemID, at: context.date) {
                    TotpCodeView(code: code)
                } else {
                    // Élément protégé : le code n'apparaît qu'après confirmation.
                    MaskedText(count: 6)
                }
            }
        case .password, .concealed, .pin, .cardNumber:
            if let revealed = model.revealed[field.id] {
                if field.fieldType == .password || field.fieldType == .pin {
                    PasswordText(value: revealed)
                } else {
                    Text(revealed).font(.system(size: 15, design: .monospaced)).textSelection(.enabled)
                }
            } else if field.fieldType == .cardNumber {
                Text("•••• •••• •••• ••••").font(.system(size: 15, design: .monospaced)).foregroundStyle(.secondary)
            } else {
                MaskedText(count: field.fieldType == .pin ? 4 : 12)
            }
        case .address, .multiline:
            Text(field.value ?? "").font(field.fieldType == .multiline ? .system(size: 12, design: .monospaced) : .body)
                .textSelection(.enabled)
                .lineLimit(field.fieldType == .multiline ? 3 : nil)
        case .email, .phone:
            Text(field.value ?? "").foregroundStyle(Theme.accent).textSelection(.enabled)
        default:
            Text(field.value ?? "").textSelection(.enabled)
        }
    }
}

struct IconButton: View {
    let symbol: String
    let help: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(.system(size: 13, weight: .medium))
                .frame(width: 26, height: 24)
                .background(.quaternary.opacity(0.6), in: RoundedRectangle(cornerRadius: 6))
        }
        .buttonStyle(.plain)
        .help(help)
        .accessibilityLabel(help)
    }
}

struct WebsiteRow: View {
    let url: String
    let primary: Bool
    @State private var hovering = false

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(primary ? "Site principal" : "Site").font(.caption).foregroundStyle(.secondary)
                Text(url).foregroundStyle(Theme.accent).lineLimit(1).truncationMode(.middle)
            }
            Spacer()
            if let link = URL(string: url) {
                Button("Ouvrir") { NSWorkspace.shared.open(link) }
                    .controlSize(.small)
                    .opacity(hovering ? 1 : 0.0001)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .contentShape(Rectangle())
        .onHover { hovering = $0 }
    }
}

struct NotesRow: View {
    @Environment(AppModel.self) private var model
    let itemID: String

    var body: some View {
        HStack(alignment: .top) {
            if let notes = model.revealed["notes"] {
                Text(notes).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Contenu masqué").foregroundStyle(.secondary)
                    Text("Cliquez sur l'œil pour afficher la note.").font(.caption).foregroundStyle(.tertiary)
                }
                Spacer()
            }
            IconButton(symbol: model.revealed["notes"] == nil ? "eye" : "eye.slash", help: "Afficher la note") {
                withAnimation(.snappy(duration: 0.18)) { model.toggleReveal("notes", of: itemID) }
            }
        }
        .padding(14)
    }
}

struct TagsRow: View {
    let tags: [String]

    var body: some View {
        HStack(spacing: 6) {
            ForEach(tags, id: \.self) { tag in
                Text("#\(tag)")
                    .font(.caption.weight(.medium))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(.quaternary.opacity(0.7), in: Capsule())
            }
        }
    }
}
