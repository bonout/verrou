import AppKit
import Observation
import UniformTypeIdentifiers

/// Import of an export from Apple, 1Password or Proton Pass: file chosen,
/// review, import.
///
/// The file is read by the Rust core, which keeps its secrets until the
/// import (or giving up, or locking); the review only contains titles,
/// usernames and sites.
@MainActor
@Observable
final class ImportFlow: Identifiable {
    enum Stage {
        case reading
        case review(ImportReview)
        case importing(count: Int)
        /// Couldn't read: the format can be chosen by hand.
        case failed(String)
        case done(ImportOutcome)
    }

    /// Where to put the created items.
    enum Placement: Hashable {
        case none
        case folder
        case originalFolders
    }

    let id = UUID()
    let url: URL
    /// `nil`: recognized from the content.
    var format: ImportFormat?
    var stage: Stage = .reading
    /// One choice per review row.
    var choices: [ImportChoice] = []
    var placement: Placement = .folder
    var folderName = ""
    /// Error of the import itself: the review stays displayed.
    var error: String?

    /// Formats offered when detection fails.
    static let formats: [ImportFormat] = [
        .applePasswords, .onePassword1pux, .onePasswordCsv, .protonPassZip, .protonPassCsv,
    ]

    static var contentTypes: [UTType] {
        [.commaSeparatedText, .zip, .json] + [UTType(filenameExtension: "1pux")].compactMap { $0 }
    }

    init(url: URL) {
        self.url = url
    }

    var review: ImportReview? {
        if case .review(let review) = stage { return review }
        return nil
    }

    func loaded(_ review: ImportReview) {
        choices = review.entries.map(\.choice)
        folderName = String(localized: "Import \(review.source)")
        placement = .folder
        error = nil
        stage = .review(review)
    }

    /// Items that will be written (created or completed).
    var writeCount: Int {
        choices.filter { $0 != .skip }.count
    }

    var destination: ImportDestination {
        switch placement {
        case .none: .noFolder
        case .originalFolders: .originalFolders
        case .folder:
            folderName.trimmingCharacters(in: .whitespaces).isEmpty
                ? .noFolder : .folder(name: folderName.trimmingCharacters(in: .whitespaces))
        }
    }
}

extension AppModel {
    // MARK: Import

    /// File → Import…: choice of the file, then review.
    func startImport() {
        guard canEdit else { return }
        showMainWindow()
        let panel = NSOpenPanel()
        panel.title = String(localized: "Import Passwords")
        panel.message = String(localized: "Choose the export from Apple Passwords (CSV), 1Password (1PUX or CSV) or Proton Pass (unencrypted ZIP or CSV).")
        panel.prompt = String(localized: "Choose")
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.allowedContentTypes = ImportFlow.contentTypes
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let flow = ImportFlow(url: url)
        importFlow = flow
        Task { await readImport(flow) }
    }

    /// Reads the file (in the chosen or recognized format) and compares it to the vault.
    func readImport(_ flow: ImportFlow) async {
        flow.stage = .reading
        let scoped = flow.url.startAccessingSecurityScopedResource()
        defer { if scoped { flow.url.stopAccessingSecurityScopedResource() } }
        do {
            let review = try await session.prepareImport(path: flow.url.path, format: flow.format)
            guard importFlow === flow else { return }
            flow.loaded(review)
        } catch {
            flow.stage = .failed(Self.describe(error))
        }
    }

    func commitImport(_ flow: ImportFlow) async {
        guard let review = flow.review, canEdit else { return }
        flow.error = nil
        flow.stage = .importing(count: flow.writeCount)
        do {
            let outcome = try await session.commitImport(choices: flow.choices, destination: flow.destination)
            afterWrite(select: selection)
            flow.stage = .done(outcome)
            let total = outcome.created + outcome.updated
            let count = Int(total)
            toast = Toast(message: count > 1 ? String(localized: "\(count) items imported") : String(localized: "\(count) item imported"),
                          detail: outcome.failures.isEmpty ? String(localized: "Remember to delete the export file")
                                                           : String(localized: "\(outcome.failures.count) not imported"),
                          failure: !outcome.failures.isEmpty)
        } catch {
            flow.error = Self.describe(error)
            flow.stage = .review(review)
        }
    }

    /// Closes the import; the Rust core forgets the file.
    func closeImport() {
        session.cancelImport()
        importFlow = nil
    }
}
