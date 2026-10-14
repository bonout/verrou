import AppKit
import Observation
import UniformTypeIdentifiers

/// Import d'un export d'Apple, de 1Password ou de Proton Pass : fichier
/// choisi, revue, import.
///
/// Le fichier est lu par le cœur Rust, qui en garde les secrets jusqu'à
/// l'import (ou l'abandon, ou le verrouillage) ; la revue ne contient que
/// titres, identifiants et sites.
@MainActor
@Observable
final class ImportFlow: Identifiable {
    enum Stage {
        case reading
        case review(ImportReview)
        case importing(count: Int)
        /// Lecture impossible : on peut choisir le format à la main.
        case failed(String)
        case done(ImportOutcome)
    }

    /// Où ranger les éléments créés.
    enum Placement: Hashable {
        case none
        case folder
        case originalFolders
    }

    let id = UUID()
    let url: URL
    /// `nil` : reconnu d'après le contenu.
    var format: ImportFormat?
    var stage: Stage = .reading
    /// Un choix par ligne de la revue.
    var choices: [ImportChoice] = []
    var placement: Placement = .folder
    var folderName = ""
    /// Erreur de l'import lui-même : la revue reste affichée.
    var error: String?

    /// Formats proposés quand la détection échoue.
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
        folderName = "Import \(review.source)"
        placement = .folder
        error = nil
        stage = .review(review)
    }

    /// Éléments qui seront écrits (créés ou complétés).
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

    /// Fichier → Importer… : choix du fichier, puis revue.
    func startImport() {
        guard canEdit else { return }
        showMainWindow()
        let panel = NSOpenPanel()
        panel.title = "Importer des mots de passe"
        panel.message = "Choisissez l'export des Mots de passe d'Apple (CSV), de 1Password (1PUX ou CSV) ou de Proton Pass (ZIP non chiffré ou CSV)."
        panel.prompt = "Choisir"
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.allowedContentTypes = ImportFlow.contentTypes
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let flow = ImportFlow(url: url)
        importFlow = flow
        Task { await readImport(flow) }
    }

    /// Lit le fichier (au format choisi, ou reconnu) et le compare au coffre.
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
            toast = Toast(message: "\(total) élément\(total > 1 ? "s" : "") importé\(total > 1 ? "s" : "")",
                          detail: outcome.failures.isEmpty ? "Pensez à supprimer le fichier d'export" : "\(outcome.failures.count) non importé(s)",
                          failure: !outcome.failures.isEmpty)
        } catch {
            flow.error = Self.describe(error)
            flow.stage = .review(review)
        }
    }

    /// Ferme l'import ; le cœur Rust oublie le fichier.
    func closeImport() {
        session.cancelImport()
        importFlow = nil
    }
}
