import Foundation
import Observation
import Sparkle

/// Updates of the app outside the App Store, by Sparkle: once a day, the
/// appcast of the latest GitHub release (`SUFeedURL`). An update is only
/// installed if its EdDSA signature matches the key in the app
/// (`SUPublicEDKey`) and if it is signed by the same Developer ID. It is
/// installed when the app quits, never by relaunching it on its own: an
/// approval from the iPhone is never cut short.
///
/// Only builds given the public key (scripts/release-macos.sh) have an
/// updater: debug, ad hoc and locally installed builds don't look for updates.
@MainActor
@Observable
final class Updates {
    /// Nil without a public key: no updates for this build.
    @ObservationIgnored private let controller: SPUStandardUpdaterController?
    @ObservationIgnored private var observation: NSKeyValueObservation?
    private(set) var canCheck = false

    init() {
        let key = Bundle.main.object(forInfoDictionaryKey: "SUPublicEDKey") as? String ?? ""
        #if DEBUG
        let enabled = false
        #else
        let enabled = !key.isEmpty
        #endif
        guard enabled else {
            controller = nil
            return
        }
        let controller = SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: nil, userDriverDelegate: nil)
        self.controller = controller
        canCheck = controller.updater.canCheckForUpdates
        observation = controller.updater.observe(\.canCheckForUpdates, options: [.new]) { [weak self] updater, _ in
            let can = updater.canCheckForUpdates
            Task { @MainActor in self?.canCheck = can }
        }
    }

    var isAvailable: Bool { controller != nil }

    /// "Check for Updates…": shows what was found, or that the app is up to date.
    func check() {
        controller?.checkForUpdates(nil)
    }

    var automaticallyChecks: Bool {
        get {
            access(keyPath: \.automaticallyChecks)
            return controller?.updater.automaticallyChecksForUpdates ?? false
        }
        set {
            withMutation(keyPath: \.automaticallyChecks) {
                controller?.updater.automaticallyChecksForUpdates = newValue
            }
        }
    }

    /// Downloaded in the background and installed when the app quits, without
    /// asking.
    var automaticallyInstalls: Bool {
        get {
            access(keyPath: \.automaticallyInstalls)
            return controller?.updater.automaticallyDownloadsUpdates ?? false
        }
        set {
            withMutation(keyPath: \.automaticallyInstalls) {
                controller?.updater.automaticallyDownloadsUpdates = newValue
            }
        }
    }

    var lastCheck: Date? {
        controller?.updater.lastUpdateCheckDate
    }

    static var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
    }
}
