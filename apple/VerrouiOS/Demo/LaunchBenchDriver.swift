#if DEBUG
import Foundation

/// Lancement à froid avec Face ID, contre un vrai serveur Vaultwarden
/// (builds Debug, `scripts/ios-bench.sh`) :
///
/// - `VERROU_BENCH_LAUNCH=setup` (+ `VERROU_BENCH_SERVER`, `_EMAIL`,
///   `_PASSWORD`, `_TOTP`) : se connecte au compte, active Face ID, attend la
///   fin de la synchronisation et quitte (`BENCH_SETUP_DONE`) ;
/// - `VERROU_BENCH_LAUNCH=measure` : ne touche à rien. L'app suit son chemin
///   normal (écran verrouillé, Face ID demandé de lui-même, que le script
///   accepte), les étapes s'affichent en lignes `PERF …` ; le pilote attend la
///   fin de la première synchronisation, puis quitte (`BENCH_DONE`).
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
            // `VERROU_BENCH_HOLD=1` : l'app reste ouverte (captures).
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
        else { return say("BENCH_FAIL variables du compte absentes") }
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
        guard model.lockState == .unlocked else { return say("BENCH_FAIL connexion : \(model.loginError ?? "?")") }
        guard await wait(20, until: { model.biometricEnrolled }) else { return say("BENCH_FAIL Face ID non activé") }
        _ = await wait(30) { model.syncsFinished > 0 && model.syncState != .syncing }
        // Captures de l'accueil sans favori : `VERROU_BENCH_NO_FAVORITES=1`.
        if environment["VERROU_BENCH_NO_FAVORITES"] == "1" {
            let favorites = model.summaries.filter(\.favorite).map(\.id)
            if !favorites.isEmpty { await model.performBulk(.favorite(favorite: false), on: favorites) }
        }
        say("BENCH_SETUP_DONE")
    }

    private func measure() async {
        guard await wait(60, until: { model.lockState == .unlocked }) else { return say("BENCH_FAIL jamais déverrouillé") }
        guard await wait(90, until: { model.syncsFinished > 0 }) else { return say("BENCH_FAIL synchro sans fin") }
        try? await Task.sleep(for: .milliseconds(800))
        say("BENCH_DONE")
    }
}
#endif
