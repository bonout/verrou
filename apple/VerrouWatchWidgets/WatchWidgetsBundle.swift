import SwiftUI
import WidgetKit

/// Verrou's complications for the Apple Watch: a pinned one-time code on the
/// watch face.
///
/// Like the iPhone's widgets, the extension never opens a vault and doesn't
/// link the Rust core: it reads only the codes the user pinned
/// (`PinnedCodes`, the Watch's own keychain, filled by the Watch app from
/// what the iPhone sent). See SECURITY.md, "Pinned one-time codes".
@main
struct WatchWidgetsBundle: WidgetBundle {
    var body: some Widget {
        WatchCodeComplication()
    }
}
