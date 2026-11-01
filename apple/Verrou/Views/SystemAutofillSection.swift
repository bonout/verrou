import SwiftUI

/// Settings: Verrou as the system credential provider (General tab). Only
/// in a build signed by the team, the only one that ships the extension; an
/// ad hoc build just says how to get it.
struct SystemAutofillSection: View {
    @Environment(AppModel.self) private var model
    @State private var enabled: Bool?

    var body: some View {
        if model.mode == .vaultwarden || AppModel.isReview {
            Section {
                if SystemAutofill.isBundled || AppModel.isReview {
                    LabeledContent("Safari and Mac apps") {
                        switch enabled {
                        case true?:
                            Label("Verrou is chosen", systemImage: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                        case false?:
                            Button("Choose Verrou…") { SystemAutofill.openSettings() }
                        case nil:
                            ProgressView().controlSize(.small)
                        }
                    }
                } else {
                    LabeledContent("Safari and Mac apps") {
                        Text("Signed build required").foregroundStyle(.secondary)
                    }
                }
            } header: {
                Text("System passwords and passkeys")
            } footer: {
                Text(footer).foregroundStyle(.secondary)
            }
            .task(id: SystemAutofill.isBundled) {
                // Review (screenshots): the "chosen" state without asking the system.
                enabled = AppModel.isReview ? true : await SystemAutofill.isEnabled()
            }
        }
    }

    private var footer: LocalizedStringKey {
        if SystemAutofill.isBundled || AppModel.isReview {
            return "Choose Verrou in System Settings → General → AutoFill & Passwords: Safari and apps then offer its logins, codes and passkeys."
        }
        return "To offer your passwords and passkeys in Safari and Mac apps, Verrou must be signed by an Apple developer team (macOS requires it of the credential provider and the shared app group): see the guide, “Mac credential provider”."
    }
}
