import Foundation
import MetricKit
import Observation
import SwiftUI

/// Reports that macOS and iOS hand over about once a day through MetricKit:
/// crashes, hangs, excessive CPU use or disk writes, with their call stacks
/// and versions, never the vault's content. They stay on this device:
/// Verrou never sends them; Settings let the user share them with the
/// developers if something went wrong, or delete them. The 20 most recent
/// are kept.
@MainActor
@Observable
final class Diagnostics: NSObject, MXMetricManagerSubscriber {
    static let shared = Diagnostics()
    private static let kept = 20

    private(set) var reports: [URL] = []
    @ObservationIgnored private let folder: URL
    @ObservationIgnored private var started = false

    private override init() {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        folder = support.appending(path: "Diagnostics", directoryHint: .isDirectory)
        super.init()
        reload()
    }

    /// Subscribes once, at launch, and keeps what the system already has.
    func start() {
        guard !started else { return }
        started = true
        MXMetricManager.shared.add(self)
        save(Self.encoded(MXMetricManager.shared.pastDiagnosticPayloads))
    }

    nonisolated func didReceive(_ payloads: [MXDiagnosticPayload]) {
        let encoded = Self.encoded(payloads)
        Task { @MainActor in self.save(encoded) }
    }

    func deleteAll() {
        for report in reports { try? FileManager.default.removeItem(at: report) }
        reload()
    }

    private nonisolated static func encoded(_ payloads: [MXDiagnosticPayload]) -> [(name: String, data: Data)] {
        payloads.map { payload in
            let stamp = payload.timeStampEnd.formatted(.iso8601).replacingOccurrences(of: ":", with: "-")
            let data = payload.jsonRepresentation()
            // Two payloads of the same day keep their own file.
            let digest = data.reduce(UInt32(5381)) { ($0 &* 33) &+ UInt32($1) }
            return ("verrou-diagnostics-\(stamp)-\(String(digest, radix: 16)).json", data)
        }
    }

    private func save(_ encoded: [(name: String, data: Data)]) {
        guard !encoded.isEmpty else { return }
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        for (name, data) in encoded {
            try? data.write(to: folder.appending(path: name), options: [.atomic, .completeFileProtection])
        }
        reload()
        for old in reports.dropFirst(Self.kept) { try? FileManager.default.removeItem(at: old) }
        reload()
    }

    /// Most recent first.
    private func reload() {
        let files = (try? FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil)) ?? []
        reports = files.filter { $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent > $1.lastPathComponent }
    }
}

/// The reports in Settings: how many, share them, delete them.
struct DiagnosticsSection: View {
    @State private var diagnostics = Diagnostics.shared

    var body: some View {
        Section {
            LabeledContent("Crash and hang reports", value: "\(diagnostics.reports.count)")
            if !diagnostics.reports.isEmpty {
                ShareLink(items: diagnostics.reports) {
                    Label("Share Reports…", systemImage: "square.and.arrow.up")
                }
                Button("Delete Reports", role: .destructive) { diagnostics.deleteAll() }
            }
        } header: {
            Text("Diagnostics")
        } footer: {
            Text("When Verrou crashes or hangs, the system writes a report: its call stacks and versions, nothing from your vault. The reports stay on this device; Verrou never sends them. Share them with the developers if something went wrong.")
        }
    }
}
