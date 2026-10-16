import Foundation
import os
import SwiftUI
import UserNotifications

// Notifications locales du partage (jamais un service de notification à
// distance) : invitation acceptée en attente, accès confirmé, membres à
// confirmer, nouveaux éléments partagés, accès d'urgence. Le cœur Rust dit
// ce qui est nouveau (`checkActivity`, une seule fois chaque chose) ; ici,
// on compose le texte et on le poste.
//
// Contenu : un nom d'organisation, une adresse (accès d'urgence), des
// nombres. Jamais un secret, un identifiant de connexion ni un titre
// d'élément.

/// Où mène le toucher d'une notification.
enum ActivityRoute: Equatable {
    /// Les éléments de l'organisation.
    case organization(String)
    /// Les membres de l'organisation (confirmer).
    case members(String)
    /// Le partage : invitations en attente de confirmation.
    case pendingMemberships
    /// L'accès d'urgence.
    case emergency

    init?(userInfo: [AnyHashable: Any]) {
        let organization = userInfo["organization"] as? String
        switch userInfo["route"] as? String {
        case "organization": guard let organization else { return nil }; self = .organization(organization)
        case "members": guard let organization else { return nil }; self = .members(organization)
        case "pending": self = .pendingMemberships
        case "emergency": self = .emergency
        default: return nil
        }
    }

    var userInfo: [String: String] {
        switch self {
        case .organization(let id): ["route": "organization", "organization": id]
        case .members(let id): ["route": "members", "organization": id]
        case .pendingMemberships: ["route": "pending"]
        case .emergency: ["route": "emergency"]
        }
    }
}

extension ActivityNotice {
    private var quoted: String { "« \(organization ?? "l'organisation") »" }

    var title: String {
        switch kind {
        case .membershipPending: "Coffre partagé en attente"
        case .membershipConfirmed: "Coffre partagé ouvert"
        case .membersToConfirm: count > 1 ? "Membres à confirmer" : "Membre à confirmer"
        case .itemsShared: count > 1 ? "Nouveaux éléments partagés" : "Nouvel élément partagé"
        case .emergencyRequested: "Demande d'accès d'urgence"
        case .emergencyApproved: "Accès d'urgence accordé"
        }
    }

    var body: String {
        let person = email ?? "Un proche"
        switch kind {
        case .membershipPending:
            return "Vous avez rejoint \(quoted). Un administrateur doit encore confirmer votre compte : vous serez prévenu."
        case .membershipConfirmed:
            return "Vous avez maintenant accès à \(quoted)."
        case .membersToConfirm:
            return count > 1
                ? "\(count) personnes attendent votre confirmation dans \(quoted)."
                : "Une personne attend votre confirmation dans \(quoted)."
        case .itemsShared:
            return count > 1 ? "\(count) nouveaux éléments dans \(quoted)." : "1 nouvel élément dans \(quoted)."
        case .emergencyRequested:
            return "\(person) demande l'accès à votre coffre. Refusez dans Verrou si vous ne l'attendiez pas."
        case .emergencyApproved:
            return "Le coffre de \(person) vous est ouvert."
        }
    }

    var route: ActivityRoute {
        switch kind {
        case .membershipPending: .pendingMemberships
        case .membershipConfirmed, .itemsShared: organizationId.map { .organization($0) } ?? .pendingMemberships
        case .membersToConfirm: organizationId.map { .members($0) } ?? .pendingMemberships
        case .emergencyRequested, .emergencyApproved: .emergency
        }
    }
}

/// Poste les notifications et ramène leur toucher à l'app.
@MainActor
final class ActivityNotifier: NSObject, UNUserNotificationCenterDelegate {
    static let shared = ActivityNotifier()

    /// Réglage : notifications du partage (activées par défaut).
    static let enabledKey = "activityNotifications"
    static var enabled: Bool {
        UserDefaults.standard.object(forKey: enabledKey) as? Bool ?? true
    }

    /// Revue visuelle, démonstration, parcours de bout en bout : aucune
    /// demande d'autorisation ni notification réelle (le contenu est
    /// seulement journalisé, en Debug).
    var silent = false
    /// Le toucher d'une notification : l'app ouvre l'écran voulu.
    var onOpen: ((ActivityRoute) -> Void)?
    /// Touché avant que l'app ne soit prête (lancement par la notification).
    private var pendingRoute: ActivityRoute?

    #if DEBUG
    /// Ce qui a été posté (crochet de test : le contenu, pas les bannières).
    private(set) var posted: [(key: String, title: String, body: String)] = []
    #endif

    private let log = Logger(subsystem: "app.verrou", category: "notifications")

    /// À appeler au lancement : le toucher d'une notification passe par ici.
    func install() {
        guard !silent else { return }
        UNUserNotificationCenter.current().delegate = self
    }

    /// L'app est prête à ouvrir un écran.
    func setHandler(_ handler: @escaping (ActivityRoute) -> Void) {
        onOpen = handler
        if let route = pendingRoute {
            pendingRoute = nil
            handler(route)
        }
    }

    /// Demande l'autorisation au bon moment (organisations présentes, ou
    /// écran du partage ouvert), jamais au premier lancement. Une seule
    /// fois : le système ne redemande pas une autorisation refusée.
    func requestAuthorizationIfNeeded() async {
        guard !silent, Self.enabled else { return }
        let center = UNUserNotificationCenter.current()
        guard await center.notificationSettings().authorizationStatus == .notDetermined else { return }
        _ = try? await center.requestAuthorization(options: [.alert, .badge])
    }

    /// Poste une notification par nouvelle (même sujet : elle remplace la
    /// précédente).
    func post(_ notices: [ActivityNotice]) {
        guard Self.enabled, !notices.isEmpty else { return }
        for notice in notices {
            let (title, body) = (notice.title, notice.body)
            #if DEBUG
            posted.append((notice.key, title, body))
            print("NOTIFY \(notice.key) | \(title) | \(body)")
            log.debug("notification \(notice.key, privacy: .public) : \(title, privacy: .public) — \(body, privacy: .public)")
            #endif
            guard !silent else { continue }
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            content.threadIdentifier = "verrou.partage"
            content.userInfo = notice.route.userInfo
            let request = UNNotificationRequest(identifier: "verrou.activite.\(notice.key)", content: content, trigger: nil)
            UNUserNotificationCenter.current().add(request) { [log] error in
                if let error { log.error("notification refusée : \(error.localizedDescription, privacy: .public)") }
            }
        }
    }

    /// Pastille de l'icône : ce qui attend une action (membres à confirmer,
    /// adhésions en attente). Zéro l'efface.
    func setBadge(_ count: Int) {
        guard !silent else { return }
        let count = Self.enabled ? count : 0
        Task {
            let center = UNUserNotificationCenter.current()
            let status = await center.notificationSettings().authorizationStatus
            guard status == .authorized || status == .provisional || count == 0 else { return }
            try? await center.setBadgeCount(count)
        }
    }

    /// Réglage coupé : plus rien d'affiché.
    func clearAll() {
        guard !silent else { return }
        let center = UNUserNotificationCenter.current()
        center.removeAllDeliveredNotifications()
        Task { try? await center.setBadgeCount(0) }
    }

    // MARK: UNUserNotificationCenterDelegate

    /// App au premier plan : la bannière s'affiche quand même (sur Mac,
    /// l'app tourne souvent sans fenêtre au premier plan).
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                            willPresent notification: UNNotification) async
        -> UNNotificationPresentationOptions {
        [.banner, .list]
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                            didReceive response: UNNotificationResponse) async {
        guard let route = ActivityRoute(userInfo: response.notification.request.content.userInfo) else { return }
        await MainActor.run {
            if let onOpen { onOpen(route) } else { pendingRoute = route }
        }
    }
}

/// Le réglage, dans les réglages des deux apps.
struct ActivityNotificationsToggle<Label: View>: View {
    @AppStorage(ActivityNotifier.enabledKey) private var enabled = true
    @ViewBuilder var label: Label

    var body: some View {
        Toggle(isOn: $enabled) { label }
            .accessibilityIdentifier("activity-notifications")
            .onChange(of: enabled) { _, on in
                if on {
                    Task { await ActivityNotifier.shared.requestAuthorizationIfNeeded() }
                } else {
                    ActivityNotifier.shared.clearAll()
                }
            }
    }

}

extension ActivityNotificationsToggle where Label == Text {
    init() {
        self.init { Text("Notifications du partage") }
    }
}

enum ActivityNotificationsText {
    /// iPhone : ce que permet la vérification en arrière-plan.
    static let background = "En arrière-plan, quand iOS le permet, Verrou ne regarde que ce que l'app a déjà téléchargé "
        + "si le coffre est verrouillé (ni clé ni réseau) : les nouveautés du serveur arrivent à la prochaine ouverture."

    /// Ce que disent les notifications, et ce qu'elles ne disent jamais.
    static let explanation = "Invitation en attente, accès confirmé, membres à confirmer, nouveaux éléments partagés : "
        + "le nom de l'organisation et des nombres, jamais un mot de passe ni un identifiant. "
        + "Calculées par Verrou sur cet appareil après chaque synchronisation, sans service de notification extérieur."
}
