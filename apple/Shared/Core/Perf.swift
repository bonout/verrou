import Foundation
import os

/// Timing of the visible steps: launch, Touch ID, unlock, display, sync. No
/// vault data, only durations:
///
///     log stream --predicate 'subsystem == "app.verrou.mac" AND category == "perf"'
///     xcrun simctl spawn booted log stream --predicate 'subsystem == "app.verrou.ios" AND category == "perf"'
enum Perf {
    /// Subsystem: the app's identifier (`app.verrou.mac`, `app.verrou.ios`).
    static let log = Logger(subsystem: Bundle.main.bundleIdentifier ?? "app.verrou", category: "perf")

    /// Milliseconds elapsed since `start`.
    static func ms(since start: ContinuousClock.Instant) -> Int {
        let elapsed = ContinuousClock.now - start
        return Int(elapsed.components.seconds * 1000 + elapsed.components.attoseconds / 1_000_000_000_000_000)
    }

    /// Milliseconds elapsed since the process launched.
    static var msSinceLaunch: Int {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0 else { return -1 }
        let start = info.kp_proc.p_un.__p_starttime
        let started = Double(start.tv_sec) + Double(start.tv_usec) / 1_000_000
        return Int((Date().timeIntervalSince1970 - started) * 1000)
    }

    /// Logs a step; in a measured Debug build (`scripts/ios-bench.sh`), also
    /// copies it to standard output (`PERF …`), which the script reads.
    static func mark(_ message: String) {
        log.notice("\(message, privacy: .public)")
        #if DEBUG
        if echo {
            print("PERF \(message)")
            fflush(stdout)
        }
        #endif
        #if os(iOS)
        journal(message)
        #endif
    }

    #if os(iOS)
    /// The same steps, timestamped, in `Library/Caches/perf.log` (64 KB at
    /// most): readable on an iPhone without the root rights its system log
    /// requires, with
    /// `xcrun devicectl device copy from --domain-type appDataContainer
    ///  --domain-identifier app.verrou.ios --source Library/Caches/perf.log`.
    /// The AutoFill extension writes `perf-autofill.log` in the app group's
    /// `Library/Caches` (`--domain-type appGroupDataContainer
    /// --domain-identifier <group>`). Durations only, never vault data.
    private static let journalQueue = DispatchQueue(label: "verrou.perf.journal", qos: .utility)
    #if AUTOFILL_EXTENSION
    private static let journalURL = (VerrouStorage.groupCachesDirectory()
        ?? FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0])
        .appending(path: "perf-autofill.log")
    #else
    private static let journalURL = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        .appending(path: "perf.log")
    #endif

    private static func journal(_ message: String) {
        let line = "\(Date().formatted(.iso8601.time(includingFractionalSeconds: true))) [\(getpid())] \(message)\n"
        // The extension ends as soon as it answers: written right away.
        #if AUTOFILL_EXTENSION
        let write: (@escaping @Sendable () -> Void) -> Void = { journalQueue.sync(execute: $0) }
        #else
        let write: (@escaping @Sendable () -> Void) -> Void = { journalQueue.async(execute: $0) }
        #endif
        write {
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

    /// Measures `body` and logs its duration.
    @MainActor
    static func measure<T>(_ label: String, _ body: () throws -> T) rethrows -> T {
        let start = ContinuousClock.now
        defer { mark("\(label): \(ms(since: start)) ms") }
        return try body()
    }

    static func measure<T>(_ label: String, isolation: isolated (any Actor)? = #isolation,
                           _ body: () async throws -> T) async rethrows -> T {
        let start = ContinuousClock.now
        defer { mark("\(label): \(ms(since: start)) ms") }
        return try await body()
    }

    // MARK: Unlocking

    /// Moment of the last Face ID / Touch ID (or password) success, until the
    /// first display of the home screen that follows.
    private static let unlockedAt = OSAllocatedUnfairLock<(at: ContinuousClock.Instant, how: String)?>(initialState: nil)

    /// Face ID (or Touch ID, the password) just succeeded; `how` names it in
    /// the measurements that follow.
    static func unlockSucceeded(_ how: String = Biometrics.name) {
        unlockedAt.withLock { $0 = (ContinuousClock.now, how) }
    }

    /// The vault home is on screen: the delay since the success, then on the
    /// next turn of the main run loop (the frame is committed, touches are
    /// handled) the delay since launch.
    @MainActor
    static func homeAppeared() {
        guard let (since, how) = unlockedAt.withLock({ value -> (at: ContinuousClock.Instant, how: String)? in
            defer { value = nil }
            return value
        }) else { return }
        mark("home visible at +\(ms(since: since)) ms after \(how)")
        DispatchQueue.main.async {
            mark("home interactive at +\(msSinceLaunch) ms from launch (+\(ms(since: since)) ms after \(how))")
        }
    }
}

/// Longest main thread stall during a period (the first sync after
/// unlocking): a separate thread posts an empty block on the main queue
/// every 16 ms and measures its delay. Negligible cost, and only during the
/// observed period.
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

    /// Stops observing; returns the longest delay, in milliseconds.
    func stop() -> Int {
        state.withLock {
            $0.running = false
            return $0.worst
        }
    }
}
