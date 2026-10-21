import Foundation

/// Temporary files of decrypted attachments (Quick Look, sharing). Nothing
/// is kept offline: a file is downloaded and decrypted (in Rust) on each
/// opening, then its temporary file is erased when the preview closes, on
/// lock and at the next launch.
enum Attachments {
    /// Maximum size of a file (as in the Rust core).
    static let maxSize = 100 * 1024 * 1024

    private static var directory: URL {
        FileManager.default.temporaryDirectory.appending(path: "attachments", directoryHint: .isDirectory)
    }

    /// Writes the decrypted file under its real name (Quick Look uses it),
    /// protected by the iPhone's encryption while it is locked.
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

    /// A file name without a path.
    static func safeName(_ name: String) -> String {
        let cleaned = name.replacingOccurrences(of: "/", with: "-").replacingOccurrences(of: ":", with: "-")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return cleaned.isEmpty || cleaned.hasPrefix(".") ? "file\(cleaned)" : cleaned
    }
}
