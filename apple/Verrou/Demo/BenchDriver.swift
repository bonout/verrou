#if DEBUG || BENCH
import AppKit

/// Mesure de l'interface sur un coffre fictif (`VERROU_BENCH=1`, taille
/// `VERROU_MOCK_SIZE`) : déverrouillage jusqu'à la liste affichée, puis une
/// recherche tapée lettre à lettre. Annonce `BENCH …` puis quitte.
@MainActor
final class BenchDriver {
    /// Lignes de la liste construites par SwiftUI depuis la dernière remise à zéro.
    static var rowsBuilt = 0

    private let model: AppModel

    init(model: AppModel) {
        self.model = model
    }

    func start() {
        Task { await run() }
    }

    private func report(_ line: String) {
        print("BENCH \(line)")
        fflush(stdout)
    }

    /// Temps jusqu'au prochain tour de la boucle principale : SwiftUI a
    /// recalculé et mis en page ce que `change` a invalidé.
    private func timed(_ label: String, _ change: () -> Void) async {
        Self.rowsBuilt = 0
        let start = ContinuousClock.now
        let cpu = clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID)
        change()
        let changed = Perf.ms(since: start)
        await withCheckedContinuation { continuation in
            DispatchQueue.main.async { continuation.resume() }
        }
        let busy = (clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID) - cpu) / 1_000_000
        report("\(label) : \(Perf.ms(since: start)) ms (modèle \(changed) ms, CPU du fil principal \(busy) ms), \(Self.rowsBuilt) lignes construites")
    }

    private func run() async {
        try? await Task.sleep(for: .seconds(1.5))
        // Icônes demandées à un serveur (le Vaultwarden de test s'il est là).
        model.showSiteIcons = true
        let generation = ContinuousClock.now
        model.session.unlockMock(size: model.mockSize, seed: 42)
        report("coffre fictif généré (Rust) : \(Perf.ms(since: generation)) ms")
        model.session.lock()
        await timed("déverrouillage → liste") { model.openVault() }
        await timed("verrouillage") { model.lock() }
        await timed("déverrouillage → liste, deuxième fois") { model.openVault() }
        if ProcessInfo.processInfo.environment["VERROU_BENCH_LOOP"] == "1" {
            // Pour le profileur : la bascule répétée.
            for _ in 0..<15 {
                await timed("verrouillage") { model.lock() }
                try? await Task.sleep(for: .milliseconds(400))
                await timed("déverrouillage → liste") { model.openVault() }
                try? await Task.sleep(for: .milliseconds(400))
            }
        }
        await timed("serveur d'icônes branché") {
            model.siteIcons.server = ProcessInfo.processInfo.environment["VERROU_BENCH_ICONS"]
        }
        try? await Task.sleep(for: .seconds(1))
        report("icônes demandées au serveur : \(model.siteIcons.requestedCount)")
        for (index, _) in "github".enumerated() {
            let prefix = String("github".prefix(index + 1))
            await timed("frappe « \(prefix) »") { model.query = prefix }
        }
        await timed("effacement") { model.query = "" }
        await timed("sélection suivante") { model.moveSelection(by: 1) }
        report("DONE")
        NSApp.terminate(nil)
    }
}
#endif
