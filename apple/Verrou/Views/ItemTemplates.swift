import SwiftUI

// MARK: Custom fields (edit screen)

/// Custom fields of an item: add, delete, reorder, rename. Text, hidden,
/// checkbox; a linked field is shown and moved, without being edited. The
/// fields reserved for Verrou never arrive here (the Rust core keeps them
/// aside).
struct CustomFieldsSection: View {
    @Binding var fields: [CustomField]
    /// The item's template: its fields' names are shown translated.
    var template: ItemTemplate?
    @State private var shown: Set<Int> = []

    var body: some View {
        Section("Custom fields") {
            ForEach(Array(fields.indices), id: \.self) { index in
                row(index)
            }
            Menu {
                Button("Text") { add(.text) }
                Button("Hidden") { add(.hidden) }
                Button("Checkbox") { add(.boolean) }
            } label: {
                Label("Add a Field", systemImage: "plus.circle.fill")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        }
    }

    @ViewBuilder private func row(_ index: Int) -> some View {
        HStack(alignment: .center, spacing: 8) {
            TextField("Name", text: nameBinding(index), prompt: Text("Field name"))
                .labelsHidden()
                .frame(width: 150)
            value(index)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button {
                move(index, by: -1)
            } label: {
                Image(systemName: "chevron.up")
                    .accessibilityLabel("Move Up")
            }
            .buttonStyle(.borderless)
            .disabled(index == 0)
            .help("Move up")
            Button {
                move(index, by: 1)
            } label: {
                Image(systemName: "chevron.down")
                    .accessibilityLabel("Move Down")
            }
            .buttonStyle(.borderless)
            .disabled(index == fields.count - 1)
            .help("Move down")
            Button {
                fields.remove(at: index)
                shown.removeAll()
            } label: {
                Image(systemName: "minus.circle.fill").foregroundStyle(.red)
                    .accessibilityLabel("Delete this field")
            }
            .buttonStyle(.plain)
            .help("Delete this field")
        }
    }

    @ViewBuilder private func value(_ index: Int) -> some View {
        switch fields[index].fieldType {
        case .text:
            TextField("Value", text: valueBinding(index)).labelsHidden()
        case .hidden:
            HStack(spacing: 8) {
                if shown.contains(index) {
                    TextField("Value", text: valueBinding(index))
                        .labelsHidden()
                        .font(.system(.body, design: .monospaced))
                } else {
                    SecureField("Value", text: valueBinding(index)).labelsHidden()
                }
                Button {
                    if shown.contains(index) { shown.remove(index) } else { shown.insert(index) }
                } label: {
                    Image(systemName: shown.contains(index) ? "eye.slash" : "eye")
                        .accessibilityLabel(shown.contains(index) ? "Hide" : "Show")
                }
                .buttonStyle(.borderless)
                .help(shown.contains(index) ? "Hide" : "Show")
            }
        case .boolean:
            Toggle("Checked", isOn: Binding(
                get: { fields.indices.contains(index) && fields[index].value == "true" },
                set: { if fields.indices.contains(index) { fields[index].value = $0 ? "true" : "false" } }))
                .labelsHidden()
        case .linked:
            Text("Linked field (editable in the web vault)")
                .foregroundStyle(.secondary)
                .help("It refers to another field of the item")
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
        // The shown field follows its row.
        let wasShown = shown.contains(index), otherShown = shown.contains(target)
        shown.remove(index); shown.remove(target)
        if wasShown { shown.insert(target) }
        if otherShown { shown.insert(index) }
    }

    private func nameBinding(_ index: Int) -> Binding<String> {
        Binding(
            get: {
                guard fields.indices.contains(index) else { return "" }
                let name = fields[index].name
                return CoreText.isTemplateField(name, template: template) ? CoreText.localized(name) : name
            },
            set: {
                guard fields.indices.contains(index) else { return }
                // A template field keeps the core's label as long as its translation is not edited.
                let name = fields[index].name
                if CoreText.isTemplateField(name, template: template), $0 == CoreText.localized(name) { return }
                fields[index].name = $0
            })
    }

    private func valueBinding(_ index: Int) -> Binding<String> {
        Binding(
            get: { fields.indices.contains(index) ? fields[index].value ?? "" : "" },
            set: { if fields.indices.contains(index) { fields[index].value = $0.isEmpty ? nil : $0 } })
    }
}

// MARK: Wi-Fi QR code

/// "Show QR Code" of a Wi-Fi network: a phone scans it to join the network.
/// The password goes through the same confirmation as the other secrets
/// (protected item) and is never kept: only the image stays on screen, for
/// the duration of the popover.
struct WifiQRButton: View {
    @Environment(AppModel.self) private var model
    let itemID: String
    let title: String
    @State private var image: NSImage?

    var body: some View {
        Button {
            show()
        } label: {
            Label("Show QR Code", systemImage: "qrcode")
        }
        .popover(isPresented: Binding(get: { image != nil }, set: { if !$0 { image = nil } }),
                 arrowEdge: .bottom) {
            if let image {
                VStack(spacing: 12) {
                    Image(nsImage: image)
                        .interpolation(.none)
                        .resizable()
                        .frame(width: 220, height: 220)
                        .padding(8)
                        .background(.white, in: RoundedRectangle(cornerRadius: 8))
                        .accessibilityLabel("QR code of the “\(title)” network")
                    Text("Scan with the camera to join “\(title)”.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(width: 240)
                }
                .padding(16)
            }
        }
    }

    private func show() {
        if model.awaitsConfirmation(itemID, retry: { show() }) { return }
        guard let payload = try? model.session.wifiQrCode(id: itemID) else {
            model.toast = Toast(message: String(localized: "Couldn't make the QR code"), detail: nil, failure: true)
            return
        }
        image = Self.qrImage(payload)
    }

    /// Sharp QR code (without smoothing), medium error correction.
    static func qrImage(_ payload: String) -> NSImage? {
        guard let cgImage = QRCode.cgImage(payload) else { return nil }
        return NSImage(cgImage: cgImage, size: NSSize(width: cgImage.width, height: cgImage.height))
    }
}
