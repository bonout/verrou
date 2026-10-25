import SwiftUI

/// Verrou on the Apple Watch: the one-time codes pinned on the iPhone, and
/// nothing else (see `WatchModel`).
@main
struct VerrouWatchApp: App {
    @State private var model = WatchModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            CodesView(model: model)
                .task { model.activate() }
                .onChange(of: scenePhase) { _, phase in
                    if phase == .active { model.refresh() }
                }
        }
    }
}
