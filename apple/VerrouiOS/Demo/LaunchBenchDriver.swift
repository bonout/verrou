#if DEBUG
import Foundation

/// Cold launch with Face ID, against a real Vaultwarden server (Debug
/// builds, `scripts/ios-bench.sh`):
///
/// - `VERROU_BENCH_LAUNCH=setup` (+ `VERROU_BENCH_SERVER`, `_EMAIL`,
///   `_PASSWORD`, `_TOTP`): signs in to the account, turns on Face ID, waits
///   for the sync to finish and quits (`BENCH_SETUP_DONE`);
/// - `VERROU_BENCH_LAUNCH=measure`: touches nothing. The app follows its
///   normal path (lock screen, Face ID requested on its own, which the
///   script accepts), the steps show as `PERF …` lines; the driver waits for
///   the end of the first sync, then quits (`BENCH_DONE`).
@MainActor
final class LaunchBenchDriver {
    enum Phase: String {
        case setup
        case measure
    }

    static var phase: Phase? {
        ProcessInfo.processInfo.environment["VERROU_BENCH_LAUNCH"].flatMap(Phase.init(rawValue:))
    }

    private let model: PhoneModel
    private let phase: Phase

    init(model: PhoneModel, phase: Phase) {
        self.model = model
        self.phase = phase
    }

    func start() {
        Task {
            switch phase {
            case .setup: await setup()
            case .measure: await measure()
            }
            fflush(stdout)
            // `VERROU_BENCH_HOLD=1`: the app stays open (screenshots).
            if ProcessInfo.processInfo.environment["VERROU_BENCH_HOLD"] != "1" { exit(0) }
        }
    }

    private func say(_ line: String) {
        print(line)
        fflush(stdout)
    }

    private func wait(_ seconds: Double, until condition: () -> Bool) async -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while !condition() {
            if Date() > deadline { return false }
            try? await Task.sleep(for: .milliseconds(50))
        }
        return true
    }

    private func setup() async {
        let environment = ProcessInfo.processInfo.environment
        guard let server = environment["VERROU_BENCH_SERVER"], let email = environment["VERROU_BENCH_EMAIL"],
              let password = environment["VERROU_BENCH_PASSWORD"], let secret = environment["VERROU_BENCH_TOTP"]
        else { return say("BENCH_FAIL account variables missing") }
        if !model.needsLogin {
            model.logout()
        }
        model.loginServer = server
        model.loginEmail = email
        await model.signIn(password: password)
        let now = Date().timeIntervalSince1970
        for offset in [0.0, 30.0] where model.lockState != .unlocked {
            await model.answerTwoFactor(.authenticator, token: EndToEndDriver.totp(secret, at: now + offset))
        }
        guard model.lockState == .unlocked else { return say("BENCH_FAIL sign-in: \(model.loginError ?? "?")") }
        guard await wait(20, until: { model.biometricEnrolled }) else { return say("BENCH_FAIL Face ID not turned on") }
        _ = await wait(30) { model.syncsFinished > 0 && model.syncState != .syncing }
        // Home screen screenshots without a favorite: `VERROU_BENCH_NO_FAVORITES=1`.
        if environment["VERROU_BENCH_NO_FAVORITES"] == "1" {
            let favorites = model.summaries.filter(\.favorite).map(\.id)
            if !favorites.isEmpty { await model.performBulk(.favorite(favorite: false), on: favorites) }
        }
        say("BENCH_SETUP_DONE")
    }

    private func measure() async {
        guard await wait(60, until: { model.lockState == .unlocked }) else { return say("BENCH_FAIL never unlocked") }
        guard await wait(90, until: { model.syncsFinished > 0 }) else { return say("BENCH_FAIL sync never finished") }
        try? await Task.sleep(for: .milliseconds(800))
        say("BENCH_DONE")
    }
}
#endif
