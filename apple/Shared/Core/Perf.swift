import Foundation
import os

/// Temps des étapes qui se voient : lancement, Touch ID, déverrouillage,
/// affichage, synchronisation. Aucune donnée du coffre, seulement des durées :
///
///     log stream --predicate 'subsystem == "app.verrou.mac" AND category == "perf"'
///     xcrun simctl spawn booted log stream --predicate 'subsystem == "app.verrou.ios" AND category == "perf"'
enum Perf {
    /// Sous-système : l'identifiant de l'app (`app.verrou.mac`, `app.verrou.ios`).
    static let log = Logger(subsystem: Bundle.main.bundleIdentifier ?? "app.verrou", category: "perf")

    /// Millisecondes écoulées depuis `start`.
    static func ms(since start: ContinuousClock.Instant) -> Int {
        let elapsed = ContinuousClock.now - start
        return Int(elapsed.components.seconds * 1000 + elapsed.components.attoseconds / 1_000_000_000_000_000)
    }

    /// Millisecondes écoulées depuis le lancement du processus.
    static var msSinceLaunch: Int {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0 else { return -1 }
        let start = info.kp_proc.p_un.__p_starttime
        let started = Double(start.tv_sec) + Double(start.tv_usec) / 1_000_000
        return Int((Date().timeIntervalSince1970 - started) * 1000)
    }

    /// Mesure `body` et journalise sa durée.
    @MainActor
    static func measure<T>(_ label: String, _ body: () throws -> T) rethrows -> T {
        let start = ContinuousClock.now
        defer { log.notice("\(label, privacy: .public) : \(ms(since: start)) ms") }
        return try body()
    }

    static func measure<T>(_ label: String, _ body: () async throws -> T) async rethrows -> T {
        let start = ContinuousClock.now
        defer { log.notice("\(label, privacy: .public) : \(ms(since: start)) ms") }
        return try await body()
    }
}
