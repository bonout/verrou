import QuickLook
import SwiftUI
import UniformTypeIdentifiers

/// « Pièces jointes » de la fiche d'un élément : ouvrir (Quick Look),
/// enregistrer sous, supprimer ; ajouter par « Ajouter un fichier… » ou en
/// déposant des fichiers sur la fiche.
struct AttachmentsSection: View {
    @Environment(AppModel.self) private var model
    let summary: ItemSummary

    private var store: AttachmentsModel { model.attachments }
    private var entries: [AttachmentEntry] {
        store.itemID == summary.id ? store.entries : []
    }
    private var editable: Bool { model.canEditAttachments(of: summary) }

    var body: some View {
        Group {
            if !entries.isEmpty || store.activity != nil || model.canEdit && summary.state == .active {
                SectionTitle("Pièces jointes")
                FieldCard {
                    ForEach(Array(entries.enumerated()), id: \.element.id) { index, entry in
                        if index > 0 { Divider().padding(.leading, 14) }
                        AttachmentRow(itemID: summary.id, entry: entry, editable: editable)
                    }
                    if let activity = store.activity {
                        if !entries.isEmpty { Divider().padding(.leading, 14) }
                        HStack(spacing: 10) {
                            ProgressView().controlSize(.small)
                            Text(activity).font(.callout).foregroundStyle(.secondary).lineLimit(1)
                            Spacer()
                        }
                        .padding(.horizontal, 14)
                        .padding(.vertical, 10)
                    }
                    if model.canEdit && summary.state == .active {
                        if !entries.isEmpty || store.activity != nil { Divider().padding(.leading, 14) }
                        HStack {
                            Button {
                                model.chooseAttachments(for: summary.id)
                            } label: {
                                Label("Ajouter un fichier…", systemImage: "paperclip")
                            }
                            .buttonStyle(.borderless)
                            .disabled(!editable)
                            Spacer()
                            Text("ou déposez-le ici · 100 Mo au plus")
                                .font(.caption)
                                .foregroundStyle(.tertiary)
                        }
                        .padding(.horizontal, 14)
                        .padding(.vertical, 10)
                    }
                }
            }
        }
    }
}

private struct AttachmentRow: View {
    @Environment(AppModel.self) private var model
    let itemID: String
    let entry: AttachmentEntry
    let editable: Bool
    @State private var hovering = false
    @State private var confirmDelete = false

    var body: some View {
        HStack(spacing: 10) {
            Image(nsImage: NSWorkspace.shared.icon(for: .init(filenameExtension: (entry.fileName as NSString).pathExtension) ?? .data))
                .resizable()
                .frame(width: 28, height: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.readable ? entry.fileName : "Pièce jointe illisible")
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .foregroundStyle(entry.readable ? Color.primary : Color.secondary)
                Text(ByteCountFormatter.string(fromByteCount: Int64(entry.size), countStyle: .file))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            if entry.readable {
                IconButton(symbol: "eye", help: "Ouvrir") { model.openAttachment(entry, of: itemID) }
                    .opacity(hovering ? 1 : 0)
                IconButton(symbol: "square.and.arrow.down", help: "Enregistrer sous…") {
                    model.saveAttachment(entry, of: itemID)
                }
                .opacity(hovering ? 1 : 0)
            }
            if editable {
                IconButton(symbol: "trash", help: "Supprimer") { confirmDelete = true }
                    .opacity(hovering ? 1 : 0)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .contentShape(Rectangle())
        .background(hovering ? Color.primary.opacity(0.035) : .clear)
        .onHover { hovering = $0 }
        .onTapGesture(count: 2) { if entry.readable { model.openAttachment(entry, of: itemID) } }
        .contextMenu {
            if entry.readable {
                Button("Ouvrir") { model.openAttachment(entry, of: itemID) }
                Button("Enregistrer sous…") { model.saveAttachment(entry, of: itemID) }
            }
            if editable {
                Divider()
                Button("Supprimer…", role: .destructive) { confirmDelete = true }
            }
        }
        .confirmationDialog("Supprimer « \(entry.readable ? entry.fileName : "cette pièce jointe") » ?",
                            isPresented: $confirmDelete) {
            Button("Supprimer", role: .destructive) {
                Task { await model.deleteAttachment(entry, of: itemID) }
            }
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("La pièce jointe est supprimée définitivement du serveur, sans passer par la corbeille.")
        }
        .accessibilityElement(children: .combine)
        .accessibilityAction(named: "Ouvrir") { model.openAttachment(entry, of: itemID) }
    }
}

/// Sur la fiche d'un élément : chargement de la liste des pièces jointes,
/// aperçu Quick Look, et dépôt de fichiers (ils deviennent des pièces
/// jointes).
struct AttachmentDropModifier: ViewModifier {
    @Environment(AppModel.self) private var model
    let summary: ItemSummary
    @State private var targeted = false

    func body(content: Content) -> some View {
        content
            .task(id: "\(summary.id)-\(summary.modified)") {
                await model.loadAttachments(of: summary.id)
            }
            .quickLookPreview(Binding(get: { model.attachments.preview },
                                      set: { model.attachments.preview = $0 }))
            .dropDestination(for: URL.self) { urls, _ in
                let files = urls.filter(\.isFileURL)
                guard model.canEditAttachments(of: summary), !files.isEmpty else { return false }
                Task { await model.addAttachments(files, to: summary.id) }
                return true
            } isTargeted: { targeted = $0 && model.canEditAttachments(of: summary) }
            .overlay {
                if targeted {
                    RoundedRectangle(cornerRadius: Theme.cornerRadius, style: .continuous)
                        .strokeBorder(Theme.accent, style: StrokeStyle(lineWidth: 2, dash: [6, 4]))
                        .background(Theme.accent.opacity(0.06), in: RoundedRectangle(cornerRadius: Theme.cornerRadius))
                        .overlay(Label("Déposer pour joindre à l'élément", systemImage: "paperclip")
                            .font(.headline).foregroundStyle(Theme.accent))
                        .padding(8)
                        .allowsHitTesting(false)
                }
            }
    }
}
