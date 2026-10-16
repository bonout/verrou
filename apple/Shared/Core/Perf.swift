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

    /// Journalise une étape ; dans un build Debug mesuré
    /// (`scripts/ios-bench.sh`), la recopie aussi sur la sortie standard
    /// (`PERF …`), que lit le script.
    static func mark(_ message: String) {
        log.notice("\(message, privacy: .public)")
        #if DEBUG
        if echo {
            print("PERF \(message)")
            fflush(stdout)
        }
        #endif
        #if os(iOS) && !AUTOFILL_EXTENSION
        journal(message)
        #endif
    }

    #if os(iOS) && !AUTOFILL_EXTENSION
    /// Les mêmes étapes, horodatées, dans `Library/Caches/perf.log` (64 Ko au
    /// plus) : lisibles sur un iPhone sans les droits root qu'exige son
    /// journal système, par
    /// `xcrun devicectl device copy from --domain-type appDataContainer
    ///  --domain-identifier app.verrou.ios --source Library/Caches/perf.log`.
    /// Des durées seulement, jamais une donnée du coffre.
    private static let journalQueue = DispatchQueue(label: "verrou.perf.journal", qos: .utility)
    private static let journalURL = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        .appending(path: "perf.log")

    private static func journal(_ message: String) {
        let line = "\(Date().formatted(.iso8601.time(includingFractionalSeconds: true))) [\(getpid())] \(message)\n"
        journalQueue.async {
            guard let data = line.data(using: .utf8) else { return }
            let url = journalURL
            if let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize, size > 64 * 1024 {
                try? FileManager.default.removeItem(at: url)
            }
            if let handle = try? FileHandle(forWritingTo: url) {
                handle.seekToEndOfFile()
                handle.write(data)
                try? handle.close()
            } else {
                try? data.write(to: url)
            }
        }
    }
    #endif

    #if DEBUG
    private static let echo = ProcessInfo.processInfo.environment["VERROU_BENCH"] != nil
        || ProcessInfo.processInfo.environment["VERROU_BENCH_LAUNCH"] != nil
    #endif

    /// Mesure `body` et journalise sa durée.
    @MainActor
    static func measure<T>(_ label: String, _ body: () throws -> T) rethrows -> T {
        let start = ContinuousClock.now
        defer { mark("\(label) : \(ms(since: start)) ms") }
        return try body()
    }

    static func measure<T>(_ label: String, _ body: () async throws -> T) async rethrows -> T {
        let start = ContinuousClock.now
        defer { mark("\(label) : \(ms(since: start)) ms") }
        return try await body()
    }

    // MARK: Déverrouillage

    /// Instant du dernier succès de Face ID / Touch ID (ou du mot de passe),
    /// jusqu'au premier affichage de l'accueil qui suit.
    private static let unlockedAt = OSAllocatedUnfairLock<(at: ContinuousClock.Instant, how: String)?>(initialState: nil)

    /// Face ID (ou Touch ID, le mot de passe) vient de réussir ; `how` le
    /// nomme dans les mesures qui suivent.
    static func unlockSucceeded(_ how: String = Biometrics.name) {
        unlockedAt.withLock { $0 = (ContinuousClock.now, how) }
    }

    /// L'accueil du coffre est à l'écran : le délai depuis le succès, puis
    /// au tour suivant de la boucle principale (l'image est validée, les
    /// touchers sont traités) le délai depuis le lancement.
    @MainActor
    static func homeAppeared() {
        guard let (since, how) = unlockedAt.withLock({ value -> (at: ContinuousClock.Instant, how: String)? in
            defer { value = nil }
            return value
        }) else { return }
        mark("accueil visible à +\(ms(since: since)) ms après \(how)")
        DispatchQueue.main.async {
            mark("accueil interactif à +\(msSinceLaunch) ms du lancement (+\(ms(since: since)) ms après \(how))")
        }
    }
}

/// Plus long blocage du fil principal pendant une période (la première
/// synchronisation après le déverrouillage) : un fil à part poste un bloc
/// vide sur la file principale toutes les 16 ms et mesure son retard.
/// Coût négligeable, et seulement pendant la période observée.
final class MainThreadWatch: @unchecked Sendable {
    private let state = OSAllocatedUnfairLock(initialState: (running: true, worst: 0))

    init() {
        let thread = Thread { [self] in self.run() }
        thread.name = "verrou.perf.main-watch"
        thread.qualityOfService = .userInitiated
        thread.start()
    }

    private func run() {
        let answered = DispatchSemaphore(value: 0)
        while state.withLock({ $0.running }) {
            let posted = ContinuousClock.now
            DispatchQueue.main.async { answered.signal() }
            answered.wait()
            let late = Perf.ms(since: posted)
            state.withLock { $0.worst = max($0.worst, late) }
            Thread.sleep(forTimeInterval: 0.016)
        }
    }

    /// Arrête l'observation ; rend le plus long retard, en millisecondes.
    func stop() -> Int {
        state.withLock {
            $0.running = false
            return $0.worst
        }
    }
}
