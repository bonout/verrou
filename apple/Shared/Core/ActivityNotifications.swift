import Foundation
import os
import SwiftUI
import UserNotifications

// Local sharing notifications (never a remote notification service; the
// one exception is the Mac's approval requests on the iPhone, an iCloud
// notification whose text is the app's and says nothing of the request):
// accepted invitation pending, access confirmed, members to confirm, new
// shared items, emergency access. The Rust core says what is new
// (`checkActivity`, each thing only once); here we compose the text and
// post it.
//
// Content: an organization name, an address (emergency access), numbers.
// Never a secret, a login identifier or an item title.

/// Where tapping a notification leads.
enum ActivityRoute: Equatable {
    /// The organization's items.
    case organization(String)
    /// The organization's members (confirm).
    case members(String)
    /// Sharing: invitations awaiting confirmation.
    case pendingMemberships
    /// Emergency access.
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
    private var quoted: String { String(localized: "“\(organization ?? String(localized: "the organization"))”") }

    var title: String {
        switch kind {
        case .membershipPending: String(localized: "Shared vault pending")
        case .membershipConfirmed: String(localized: "Shared vault open")
        case .membersToConfirm: count > 1 ? String(localized: "Members to confirm") : String(localized: "Member to confirm")
        case .itemsShared: count > 1 ? String(localized: "New shared items") : String(localized: "New shared item")
        case .emergencyRequested: String(localized: "Emergency access request")
        case .emergencyApproved: String(localized: "Emergency access granted")
        }
    }

    var body: String {
        let person = email ?? String(localized: "A trusted contact")
        switch kind {
        case .membershipPending:
            return String(localized: "You joined \(quoted). An administrator still has to confirm your account: you will be notified.")
        case .membershipConfirmed:
            return String(localized: "You now have access to \(quoted).")
        case .membersToConfirm:
            return count > 1
                ? String(localized: "\(count) people are waiting for your confirmation in \(quoted).")
                : String(localized: "One person is waiting for your confirmation in \(quoted).")
        case .itemsShared:
            return count > 1 ? String(localized: "\(count) new items in \(quoted).") : String(localized: "1 new item in \(quoted).")
        case .emergencyRequested:
            return String(localized: "\(person) is requesting access to your vault. Deny it in Verrou if you weren't expecting it.")
        case .emergencyApproved:
            return String(localized: "\(person)'s vault is open to you.")
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

/// Posts the notifications and brings their tap back to the app.
@MainActor
final class ActivityNotifier: NSObject, UNUserNotificationCenterDelegate {
    static let shared = ActivityNotifier()

    /// Setting: sharing notifications (on by default).
    static let enabledKey = "activityNotifications"
    static var enabled: Bool {
        UserDefaults.standard.object(forKey: enabledKey) as? Bool ?? true
    }

    /// Visual review, demo, end-to-end run: no authorization request and no
    /// real notification (the content is only logged, in Debug).
    var silent = false
    /// Tapping a notification: the app opens the requested screen.
    var onOpen: ((ActivityRoute) -> Void)?
    /// Tapped before the app is ready (launched by the notification).
    private var pendingRoute: ActivityRoute?
    /// iPhone: a request from the Mac (iCloud notification, `RemoteApprover`).
    private var onApproval: (() -> Void)?
    private var pendingApproval = false

    #if DEBUG
    /// What was posted (test hook: the content, not the banners).
    private(set) var posted: [(key: String, title: String, body: String)] = []
    #endif

    private let log = Logger(subsystem: "app.verrou", category: "notifications")

    /// Call at launch: tapping a notification goes through here.
    func install() {
        guard !silent else { return }
        UNUserNotificationCenter.current().delegate = self
    }

    /// The app is ready to open a screen.
    func setHandler(_ handler: @escaping (ActivityRoute) -> Void) {
        onOpen = handler
        if let route = pendingRoute {
            pendingRoute = nil
            handler(route)
        }
    }

    /// The app is ready to show the Mac's requests.
    func setApprovalHandler(_ handler: @escaping () -> Void) {
        onApproval = handler
        if pendingApproval {
            pendingApproval = false
            handler()
        }
    }

    /// The Mac's requests come from CloudKit (`ck` in the payload); sharing
    /// notifications are local.
    private nonisolated static func isApproval(_ userInfo: [AnyHashable: Any]) -> Bool {
        userInfo["ck"] != nil
    }

    private func approvalArrived() {
        if let onApproval { onApproval() } else { pendingApproval = true }
    }

    /// Asks for authorization at the right moment (organizations present, or
    /// sharing screen open), never on first launch. Only once: the system
    /// does not ask again for a denied authorization.
    func requestAuthorizationIfNeeded() async {
        guard !silent, Self.enabled else { return }
        let center = UNUserNotificationCenter.current()
        guard await center.notificationSettings().authorizationStatus == .notDetermined else { return }
        _ = try? await center.requestAuthorization(options: [.alert, .badge])
    }

    /// Posts one notification per news item (same subject: it replaces the
    /// previous one).
    func post(_ notices: [ActivityNotice]) {
        guard Self.enabled, !notices.isEmpty else { return }
        for notice in notices {
            let (title, body) = (notice.title, notice.body)
            #if DEBUG
            posted.append((notice.key, title, body))
            print("NOTIFY \(notice.key) | \(title) | \(body)")
            log.debug("notification \(notice.key, privacy: .public): \(title, privacy: .public) — \(body, privacy: .public)")
            #endif
            guard !silent else { continue }
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = body
            content.threadIdentifier = "verrou.sharing"
            content.userInfo = notice.route.userInfo
            let request = UNNotificationRequest(identifier: "verrou.activity.\(notice.key)", content: content, trigger: nil)
            UNUserNotificationCenter.current().add(request) { [log] error in
                if let error { log.error("notification refused: \(error.localizedDescription, privacy: .public)") }
            }
        }
    }

    /// Icon badge: what awaits an action (members to confirm, pending
    /// memberships). Zero clears it.
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

    /// Setting turned off: nothing shown any more.
    func clearAll() {
        guard !silent else { return }
        let center = UNUserNotificationCenter.current()
        center.removeAllDeliveredNotifications()
        Task { try? await center.setBadgeCount(0) }
    }

    // MARK: UNUserNotificationCenterDelegate

    /// App in the foreground: the banner shows anyway (on Mac, the app often
    /// runs without a window in the foreground).
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                            willPresent notification: UNNotification) async
        -> UNNotificationPresentationOptions {
        // App in the foreground: the request shows right away, no banner.
        if Self.isApproval(notification.request.content.userInfo) {
            await MainActor.run { approvalArrived() }
            return []
        }
        return [.banner, .list]
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter,
                                            didReceive response: UNNotificationResponse) async {
        let userInfo = response.notification.request.content.userInfo
        if Self.isApproval(userInfo) {
            await MainActor.run { approvalArrived() }
            return
        }
        guard let route = ActivityRoute(userInfo: userInfo) else { return }
        await MainActor.run {
            if let onOpen { onOpen(route) } else { pendingRoute = route }
        }
    }
}

/// The setting, in both apps' settings.
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
        self.init { Text("Sharing notifications") }
    }
}

enum ActivityNotificationsText {
    /// iPhone: what the background check allows.
    static let background = String(localized: "In the background, when iOS allows it, Verrou only looks at what the app has already downloaded if the vault is locked (no key, no network): news from the server arrives the next time you open it.")

    /// What the notifications say, and what they never say.
    static let explanation = String(localized: "Pending invitation, access confirmed, members to confirm, new shared items: the organization name and numbers, never a password or a login. Computed by Verrou on this device after each sync, without an outside notification service.")
}
