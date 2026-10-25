import SwiftUI
import WidgetKit

/// Verrou's widgets (home screen, lock screen, StandBy), the request
/// Live Activity (Dynamic Island) and the Control Center control.
///
/// The extension never opens the vault and doesn't link the Rust core: it
/// reads only the codes the user pinned (`PinnedCodes`, this device's
/// keychain) and opens the app with `verrou://` links. See SECURITY.md,
/// "Widgets, Shortcuts and Live Activity".
@main
struct VerrouWidgetsBundle: WidgetBundle {
    var body: some Widget {
        CodeWidget()
        QuickActionsWidget()
        ApprovalLiveActivity()
        if #available(iOS 18.0, *) {
            SearchControl()
        }
    }
}
