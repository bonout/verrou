import Foundation

/// Fichiers temporaires des pièces jointes déchiffrées (Quick Look,
/// partage). Rien n'est gardé hors ligne : un fichier se télécharge et se
/// déchiffre (dans Rust) à chaque ouverture, puis son fichier temporaire est
/// effacé à la fermeture de l'aperçu, au verrouillage et au lancement suivant.
enum Attachments {
    /// Taille maximale d'un fichier (comme le cœur Rust).
    static let maxSize = 100 * 1024 * 1024

    private static var directory: URL {
        FileManager.default.temporaryDirectory.appending(path: "pieces-jointes", directoryHint: .isDirectory)
    }

    /// Écrit le fichier déchiffré sous son vrai nom (Quick Look s'en sert),
    /// protégé par le chiffrement de l'iPhone tant qu'il est verrouillé.
    static func temporaryFile(named name: String, data: Data) throws -> URL {
        let folder = directory.appending(path: UUID().uuidString, directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        let url = folder.appending(path: safeName(name))
        try data.write(to: url, options: [.atomic, .completeFileProtection])
        return url
    }

    static func discard(_ url: URL) {
        try? FileManager.default.removeItem(at: url.deletingLastPathComponent())
    }

    static func purge() {
        try? FileManager.default.removeItem(at: directory)
    }

    /// Un nom de fichier sans chemin.
    static func safeName(_ name: String) -> String {
        let cleaned = name.replacingOccurrences(of: "/", with: "-").replacingOccurrences(of: ":", with: "-")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.isEmpty || cleaned.hasPrefix(".") ? "fichier\(cleaned)" : cleaned
    }
}
