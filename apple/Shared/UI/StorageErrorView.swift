import SwiftUI

/// Shown instead of the sign-in or lock screen when the accounts can't be
/// opened (disk full, protected data not available yet, a registry written
/// by a newer Verrou). Nothing was touched, and nothing is offered that
/// could write somewhere else: only the reason, and Retry when the app can
/// try again (it also does by itself when the app comes back to the front).
struct StorageErrorView: View {
    let message: String
    var retry: (() -> Void)?

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 40))
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            Text("Verrou can't open your accounts")
                .font(.title3.weight(.semibold))
                .multilineTextAlignment(.center)
            Text(message)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
            Text("Your accounts have not been touched.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            if let retry {
                Button("Retry", action: retry)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(24)
        .frame(maxWidth: 420)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .contain)
    }
}

/// An older Verrou left unsent offline changes at the root, next to an
/// account that was kept (a downgrade, then an upgrade): told once.
enum LegacyNotice {
    private static let key = "legacyUnsentChangesNoticeShown"

    /// The toast to show, once per count (`nil` if there is nothing to say
    /// or it was said); showing it is recorded here.
    static func toast(unsent: UInt32, defaults: UserDefaults = .standard) -> Toast? {
        guard unsent > 0, defaults.integer(forKey: key) != Int(unsent) else { return nil }
        defaults.set(Int(unsent), forKey: key)
        let message = unsent == 1
            ? String(localized: "One change from an older Verrou was not sent")
            : String(localized: "\(Int(unsent)) changes from an older Verrou were not sent")
        return Toast(message: message, detail: String(localized: "Open the older version of Verrou to send them."),
                     failure: true, seconds: 10)
    }
}
