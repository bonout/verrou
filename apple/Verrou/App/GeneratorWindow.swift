import AppKit
import SwiftUI

@MainActor
final class GeneratorWindow {
    static let identifier = "generator"
    private let model: AppModel
    private var window: NSWindow?

    init(model: AppModel) {
        self.model = model
    }

    func show() {
        guard !AppModel.isReview else { return }
        let window = self.window ?? makeWindow()
        self.window = window
        NSApp.activate()
        window.makeKeyAndOrderFront(nil)
    }

    private func makeWindow() -> NSWindow {
        let controller = NSHostingController(rootView: StandaloneGeneratorView().environment(model))
        controller.sizingOptions = .preferredContentSize
        let window = NSWindow(contentViewController: controller)
        window.styleMask = [.titled, .closable]
        window.title = String(localized: "Generate Password")
        window.isReleasedWhenClosed = false
        window.identifier = NSUserInterfaceItemIdentifier(Self.identifier)
        window.sharingType = .none
        window.center()
        return window
    }
}

private struct StandaloneGeneratorView: View {
    @Environment(AppModel.self) private var model
    @State private var copied: Toast?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            GeneratorView(copy: { value in
                model.copy(value, label: String(localized: "Password"), secret: true)
                copied = Toast(message: String(localized: "Password copied"),
                               detail: Clipboard.clearedLabel)
            }, showsTitle: false)
            if let copied {
                Label {
                    Text(verbatim: copied.spoken)
                } icon: {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.horizontal, 16)
                .padding(.bottom, 12)
                .task(id: copied.id) {
                    copied.announce()
                    try? await Task.sleep(for: .seconds(4))
                    if self.copied?.id == copied.id { self.copied = nil }
                }
            }
        }
    }
}
