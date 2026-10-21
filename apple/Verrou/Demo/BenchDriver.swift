#if DEBUG || BENCH
import AppKit

/// Measure of the interface on a mock vault (`VERROU_BENCH=1`, size
/// `VERROU_MOCK_SIZE`): unlock until the list is displayed, then a search
/// typed letter by letter. Announces `BENCH …` then quits.
@MainActor
final class BenchDriver {
    /// List rows built by SwiftUI since the last reset.
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

    /// Time until the next turn of the main run loop: SwiftUI has recomputed
    /// and laid out what `change` invalidated.
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
        report("\(label): \(Perf.ms(since: start)) ms (model \(changed) ms, main thread CPU \(busy) ms), \(Self.rowsBuilt) rows built")
    }

    private func run() async {
        try? await Task.sleep(for: .seconds(1.5))
        // Icons requested from a server (the test Vaultwarden if it's there).
        model.showSiteIcons = true
        let generation = ContinuousClock.now
        model.session.unlockMock(size: model.mockSize, seed: 42, language: .current)
        report("mock vault generated (Rust): \(Perf.ms(since: generation)) ms")
        model.session.lock()
        await timed("unlock → list") { model.openVault() }
        await timed("lock") { model.lock() }
        await timed("unlock → list, second time") { model.openVault() }
        if ProcessInfo.processInfo.environment["VERROU_BENCH_LOOP"] == "1" {
            // For the profiler: the repeated toggle.
            for _ in 0..<15 {
                await timed("lock") { model.lock() }
                try? await Task.sleep(for: .milliseconds(400))
                await timed("unlock → list") { model.openVault() }
                try? await Task.sleep(for: .milliseconds(400))
            }
        }
        await timed("icon server plugged in") {
            model.siteIcons.server = ProcessInfo.processInfo.environment["VERROU_BENCH_ICONS"]
        }
        try? await Task.sleep(for: .seconds(1))
        report("icons requested from the server: \(model.siteIcons.requestedCount)")
        for (index, _) in "github".enumerated() {
            let prefix = String("github".prefix(index + 1))
            await timed("keystroke \"\(prefix)\"") { model.query = prefix }
        }
        await timed("clearing") { model.query = "" }
        await timed("next selection") { model.moveSelection(by: 1) }
        report("DONE")
        NSApp.terminate(nil)
    }
}
#endif
