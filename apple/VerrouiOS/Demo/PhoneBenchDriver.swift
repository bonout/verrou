#if DEBUG
import SwiftUI

/// Mesures de l'app iPhone sur un coffre fictif (builds Debug,
/// `VERROU_BENCH=1` avec `VERROU_MOCK=1` et `VERROU_MOCK_SIZE`) :
///
/// - lancement à froid jusqu'à l'accueil du coffre ouvert (le coffre fictif
///   est ouvert dès le démarrage, sans attendre de saisie) ;
/// - ouverture de la liste de tous les éléments ;
/// - chaque frappe d'une recherche, jusqu'à l'image suivante ;
/// - déverrouillage : du succès au coffre affiché et utilisable, puis
///   jusqu'au retrait de l'écran verrouillé (fin de l'animation).
///
/// Annonce `BENCH …` sur sa sortie standard (lue par `scripts/ios-bench.sh`),
/// puis `BENCH_DONE`.
@MainActor
final class PhoneBenchDriver {
    /// Lignes d'éléments construites par SwiftUI depuis la dernière remise à zéro.
    static var rowsBuilt = 0
    /// L'accueil du coffre a été affiché.
    static var homeShown = false
    /// La liste filtrée a été affichée.
    static var listShown = false
    /// L'écran verrouillé est dans la hiérarchie des vues.
    static var lockShown = false

    private let model: PhoneModel

    init(model: PhoneModel) {
        self.model = model
    }

    static var enabled: Bool {
        let environment = ProcessInfo.processInfo.environment
        return environment["VERROU_BENCH"] == "1" && environment["VERROU_MOCK"] == "1"
    }

    func start() {
        Task { await run() }
    }

    private func report(_ line: String) {
        print("BENCH \(line)")
        fflush(stdout)
    }

    /// Le prochain tour de la boucle principale : SwiftUI a recalculé, mis en
    /// page et validé l'image de ce que `change` a invalidé.
    private func nextTurn() async {
        await withCheckedContinuation { continuation in
            DispatchQueue.main.async { continuation.resume() }
        }
    }

    private func wait(_ seconds: Double, until condition: () -> Bool) async -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while !condition() {
            if Date() > deadline { return false }
            await nextTurn()
        }
        return true
    }

    /// Durée de `change` jusqu'à l'image suivante, temps CPU du fil principal compris.
    @discardableResult
    private func timed(_ label: String, _ change: () -> Void) async -> Double {
        Self.rowsBuilt = 0
        let start = ContinuousClock.now
        let cpu = clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID)
        change()
        await nextTurn()
        let elapsed = ContinuousClock.now - start
        let ms = Double(elapsed.components.attoseconds) / 1e15 + Double(elapsed.components.seconds) * 1000
        let busy = Double(clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID) - cpu) / 1e6
        report(String(format: "%@ : %.2f ms (CPU %.2f ms), %d lignes construites", label, ms, busy, Self.rowsBuilt))
        return ms
    }

    private func run() async {
        // Lancement à froid : coffre fictif ouvert d'emblée, puis l'accueil.
        model.openMockVault()
        guard await wait(20, until: { Self.homeShown }) else { return report("ÉCHEC accueil jamais affiché") }
        await nextTurn()
        let processCPU = clock_gettime_nsec_np(CLOCK_PROCESS_CPUTIME_ID) / 1_000_000
        report("LAUNCH accueil du coffre ouvert à +\(Perf.msSinceLaunch) ms du lancement, CPU du processus \(processCPU) ms (\(model.summaries.count) éléments)")
        try? await Task.sleep(for: .seconds(1))

        // Liste de tous les éléments.
        Self.listShown = false
        let opening = ContinuousClock.now
        await timed("LIST ouverture de « Tous les éléments »") { model.vaultPath = [.list(.all)] }
        _ = await wait(10, until: { Self.listShown })
        report("LIST affichée en \(Perf.ms(since: opening)) ms")
        try? await Task.sleep(for: .seconds(1))
        model.vaultPath = []
        try? await Task.sleep(for: .seconds(1))

        // Recherche tapée lettre à lettre, puis effacée, trois fois.
        prepareSearch()
        try? await Task.sleep(for: .seconds(1))
        var samples: [Double] = []
        for round in 0..<3 {
            for word in ["github", "camille", "zzq"] {
                var typed = ""
                for letter in word {
                    typed.append(letter)
                    let query = typed
                    let ms = await timed("KEY tour \(round) « \(query) »") { model.searchQuery = query }
                    samples.append(ms)
                    try? await Task.sleep(for: .milliseconds(60))
                }
                while !typed.isEmpty {
                    typed.removeLast()
                    let query = typed
                    let ms = await timed("KEY tour \(round) « \(query) »") { model.searchQuery = query }
                    samples.append(ms)
                    try? await Task.sleep(for: .milliseconds(60))
                }
            }
        }
        let sorted = samples.sorted()
        let median = sorted[sorted.count / 2]
        let p95 = sorted[min(sorted.count - 1, Int(Double(sorted.count) * 0.95))]
        report(String(format: "SEARCH %d frappes : médiane %.2f ms, p95 %.2f ms, max %.2f ms",
                      sorted.count, median, p95, sorted.last ?? 0))
        // Déverrouillage, trois fois : du succès au coffre affiché (les vues du
        // coffre reçoivent les touchers dès cet instant), puis au retrait de
        // l'écran verrouillé.
        model.tab = .vault
        try? await Task.sleep(for: .seconds(1))
        for round in 0..<3 {
            model.lock()
            guard await wait(10, until: { Self.lockShown }) else { return report("ÉCHEC écran verrouillé jamais affiché") }
            try? await Task.sleep(for: .seconds(1))
            Self.homeShown = false
            let start = ContinuousClock.now
            model.openMockVault()
            _ = await wait(10, until: { Self.homeShown })
            await nextTurn()
            let usable = Perf.ms(since: start)
            _ = await wait(10, until: { !Self.lockShown })
            report("UNLOCK tour \(round) : coffre utilisable en \(usable) ms, écran verrouillé retiré en \(Perf.ms(since: start)) ms")
            try? await Task.sleep(for: .seconds(1))
        }
        report("DONE")
        print("BENCH_DONE")
        fflush(stdout)
        // Le script relance l'app à froid pour la mesure suivante.
        exit(0)
    }

    /// Le champ de recherche de tout le coffre à l'écran (onglet Rechercher).
    private func prepareSearch() {
        model.tab = .search
        model.searchPath = []
    }
}
#endif
