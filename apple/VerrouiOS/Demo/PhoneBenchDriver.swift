#if DEBUG
import SwiftUI

/// Measurements of the iPhone app on a demo vault (Debug builds,
/// `VERROU_BENCH=1` with `VERROU_MOCK=1` and `VERROU_MOCK_SIZE`):
///
/// - cold launch until the open vault's home screen (the demo vault is
///   opened at startup, without waiting for input);
/// - opening the list of all items;
/// - each keystroke of a search, until the next frame;
/// - unlock: from the success to the vault shown and usable, then until
///   the lock screen is removed (end of the animation).
///
/// Announces `BENCH …` on its standard output (read by
/// `scripts/ios-bench.sh`), then `BENCH_DONE`.
@MainActor
final class PhoneBenchDriver {
    /// Item rows built by SwiftUI since the last reset.
    static var rowsBuilt = 0
    /// The vault home screen was shown.
    static var homeShown = false
    /// The filtered list was shown.
    static var listShown = false
    /// The lock screen is in the view hierarchy.
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

    /// The next turn of the main run loop: SwiftUI has recomputed, laid out
    /// and committed the frame of what `change` invalidated.
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

    /// Duration of `change` until the next frame, main thread CPU time included.
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
        report(String(format: "%@: %.2f ms (CPU %.2f ms), %d rows built", label, ms, busy, Self.rowsBuilt))
        return ms
    }

    private func run() async {
        // Cold launch: demo vault open right away, then the home screen.
        model.openMockVault()
        guard await wait(20, until: { Self.homeShown }) else { return report("FAILED home screen never shown") }
        await nextTurn()
        let processCPU = clock_gettime_nsec_np(CLOCK_PROCESS_CPUTIME_ID) / 1_000_000
        report("LAUNCH open vault home at +\(Perf.msSinceLaunch) ms from launch, process CPU \(processCPU) ms (\(model.summaries.count) items)")
        try? await Task.sleep(for: .seconds(1))

        // List of all items.
        Self.listShown = false
        let opening = ContinuousClock.now
        await timed("LIST opening “All items”") { model.vaultPath = [.list(.all)] }
        _ = await wait(10, until: { Self.listShown })
        report("LIST shown in \(Perf.ms(since: opening)) ms")
        try? await Task.sleep(for: .seconds(1))
        model.vaultPath = []
        try? await Task.sleep(for: .seconds(1))

        // Search typed letter by letter, then erased, three times.
        prepareSearch()
        try? await Task.sleep(for: .seconds(1))
        var samples: [Double] = []
        for round in 0..<3 {
            for word in ["github", "camille", "zzq"] {
                var typed = ""
                for letter in word {
                    typed.append(letter)
                    let query = typed
                    let ms = await timed("KEY round \(round) “\(query)”") { model.searchQuery = query }
                    samples.append(ms)
                    try? await Task.sleep(for: .milliseconds(60))
                }
                while !typed.isEmpty {
                    typed.removeLast()
                    let query = typed
                    let ms = await timed("KEY round \(round) “\(query)”") { model.searchQuery = query }
                    samples.append(ms)
                    try? await Task.sleep(for: .milliseconds(60))
                }
            }
        }
        let sorted = samples.sorted()
        let median = sorted[sorted.count / 2]
        let p95 = sorted[min(sorted.count - 1, Int(Double(sorted.count) * 0.95))]
        report(String(format: "SEARCH %d keystrokes: median %.2f ms, p95 %.2f ms, max %.2f ms",
                      sorted.count, median, p95, sorted.last ?? 0))
        // Unlock, three times: from the success to the vault shown (the vault's
        // views receive touches from that moment), then to the removal of the
        // lock screen.
        model.tab = .vault
        try? await Task.sleep(for: .seconds(1))
        for round in 0..<3 {
            model.lock()
            guard await wait(10, until: { Self.lockShown }) else { return report("FAILED lock screen never shown") }
            try? await Task.sleep(for: .seconds(1))
            Self.homeShown = false
            let start = ContinuousClock.now
            model.openMockVault()
            _ = await wait(10, until: { Self.homeShown })
            await nextTurn()
            let usable = Perf.ms(since: start)
            _ = await wait(10, until: { !Self.lockShown })
            report("UNLOCK round \(round): vault usable in \(usable) ms, lock screen removed in \(Perf.ms(since: start)) ms")
            try? await Task.sleep(for: .seconds(1))
        }
        report("DONE")
        print("BENCH_DONE")
        fflush(stdout)
        // The script relaunches the app cold for the next measurement.
        exit(0)
    }

    /// The whole vault's search field on screen (Search tab).
    private func prepareSearch() {
        model.tab = .search
        model.searchPath = []
    }
}
#endif
