import SwiftUI

// MARK: Champs personnalisés (écran de modification)

/// Champs personnalisés d'un élément : ajouter, supprimer, réordonner,
/// renommer. Texte, masqué, case à cocher ; un champ lié s'affiche et se
/// déplace, sans se modifier. Les champs réservés à Verrou n'arrivent jamais
/// ici (le cœur Rust les garde de côté).
struct CustomFieldsSection: View {
    @Binding var fields: [CustomField]
    @State private var shown: Set<Int> = []

    var body: some View {
        Section("Champs personnalisés") {
            ForEach(Array(fields.indices), id: \.self) { index in
                row(index)
            }
            Menu {
                Button("Texte") { add(.text) }
                Button("Masqué") { add(.hidden) }
                Button("Case à cocher") { add(.boolean) }
            } label: {
                Label("Ajouter un champ", systemImage: "plus.circle.fill")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        }
    }

    @ViewBuilder private func row(_ index: Int) -> some View {
        HStack(alignment: .center, spacing: 8) {
            TextField("Nom", text: nameBinding(index), prompt: Text("Nom du champ"))
                .labelsHidden()
                .frame(width: 150)
            value(index)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button {
                move(index, by: -1)
            } label: {
                Image(systemName: "chevron.up")
            }
            .buttonStyle(.borderless)
            .disabled(index == 0)
            .help("Monter")
            Button {
                move(index, by: 1)
            } label: {
                Image(systemName: "chevron.down")
            }
            .buttonStyle(.borderless)
            .disabled(index == fields.count - 1)
            .help("Descendre")
            Button {
                fields.remove(at: index)
                shown.removeAll()
            } label: {
                Image(systemName: "minus.circle.fill").foregroundStyle(.red)
            }
            .buttonStyle(.plain)
            .help("Supprimer ce champ")
        }
    }

    @ViewBuilder private func value(_ index: Int) -> some View {
        switch fields[index].fieldType {
        case .text:
            TextField("Valeur", text: valueBinding(index)).labelsHidden()
        case .hidden:
            HStack(spacing: 6) {
                if shown.contains(index) {
                    TextField("Valeur", text: valueBinding(index))
                        .labelsHidden()
                        .font(.system(.body, design: .monospaced))
                } else {
                    SecureField("Valeur", text: valueBinding(index)).labelsHidden()
                }
                Button {
                    if shown.contains(index) { shown.remove(index) } else { shown.insert(index) }
                } label: {
                    Image(systemName: shown.contains(index) ? "eye.slash" : "eye")
                }
                .buttonStyle(.borderless)
                .help(shown.contains(index) ? "Masquer" : "Afficher")
            }
        case .boolean:
            Toggle("Coché", isOn: Binding(
                get: { fields.indices.contains(index) && fields[index].value == "true" },
                set: { if fields.indices.contains(index) { fields[index].value = $0 ? "true" : "false" } }))
                .labelsHidden()
        case .linked:
            Text("Champ lié (modifiable dans le coffre web)")
                .foregroundStyle(.secondary)
                .help("Il renvoie à un autre champ de l'élément")
        }
    }

    private func add(_ type: CustomFieldType) {
        fields.append(CustomField(name: "", value: type == .boolean ? "false" : nil,
                                  fieldType: type, linkedId: nil))
    }

    private func move(_ index: Int, by offset: Int) {
        let target = index + offset
        guard fields.indices.contains(index), fields.indices.contains(target) else { return }
        fields.swapAt(index, target)
        // Le champ affiché suit sa ligne.
        let wasShown = shown.contains(index), otherShown = shown.contains(target)
        shown.remove(index); shown.remove(target)
        if wasShown { shown.insert(target) }
        if otherShown { shown.insert(index) }
    }

    private func nameBinding(_ index: Int) -> Binding<String> {
        Binding(
            get: { fields.indices.contains(index) ? fields[index].name : "" },
            set: { if fields.indices.contains(index) { fields[index].name = $0 } })
    }

    private func valueBinding(_ index: Int) -> Binding<String> {
        Binding(
            get: { fields.indices.contains(index) ? fields[index].value ?? "" : "" },
            set: { if fields.indices.contains(index) { fields[index].value = $0.isEmpty ? nil : $0 } })
    }
}

// MARK: QR code du Wi-Fi

/// « Afficher le QR code » d'un réseau Wi-Fi : un téléphone le scanne pour
/// rejoindre le réseau. Le mot de passe passe par la même confirmation que
/// les autres secrets (élément protégé) et n'est jamais gardé : seule
/// l'image reste à l'écran, le temps du popover.
struct WifiQRButton: View {
    @Environment(AppModel.self) private var model
    let itemID: String
    let title: String
    @State private var image: NSImage?

    var body: some View {
        Button {
            show()
        } label: {
            Label("Afficher le QR code", systemImage: "qrcode")
        }
        .popover(isPresented: Binding(get: { image != nil }, set: { if !$0 { image = nil } }),
                 arrowEdge: .bottom) {
            if let image {
                VStack(spacing: 12) {
                    Image(nsImage: image)
                        .interpolation(.none)
                        .resizable()
                        .frame(width: 220, height: 220)
                        .padding(10)
                        .background(.white, in: RoundedRectangle(cornerRadius: 8))
                        .accessibilityLabel("QR code du réseau « \(title) »")
                    Text("Scannez avec l'appareil photo pour rejoindre « \(title) ».")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(width: 240)
                }
                .padding(18)
            }
        }
    }

    private func show() {
        if model.awaitsConfirmation(itemID, retry: { show() }) { return }
        guard let payload = try? model.session.wifiQrCode(id: itemID) else {
            model.toast = Toast(message: "QR code impossible", detail: nil, failure: true)
            return
        }
        image = Self.qrImage(payload)
    }

    /// QR code net (sans lissage), correction d'erreur moyenne.
    static func qrImage(_ payload: String) -> NSImage? {
        guard let cgImage = QRCode.cgImage(payload) else { return nil }
        return NSImage(cgImage: cgImage, size: NSSize(width: cgImage.width, height: cgImage.height))
    }
}
