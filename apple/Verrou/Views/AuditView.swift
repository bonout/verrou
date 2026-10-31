import SwiftUI

/// Sidebar entry: the audit then occupies the middle column.
struct AuditSidebarButton: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        SidebarPaneButton(title: String(localized: "Security Audit"), symbol: "checkmark.shield", tint: .orange,
                          active: model.showAudit,
                          badge: model.showAudit ? model.audit.map(issues) : nil) {
            model.openAudit()
        }
    }

    private func issues(_ audit: AuditReport) -> Int {
        audit.reused.reduce(0) { $0 + $1.count } + audit.weak.count + audit.insecure.count
            + model.watchtower.issues
    }
}

/// Vault audit: known leaks (on request), reused and weak passwords, HTTP
/// sites. A click shows the item on the right.
struct AuditView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ScrollViewReader { proxy in
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 4) {
                header
                breachSection
                if let audit = model.audit {
                    if !audit.reused.isEmpty {
                        title("Reused passwords", count: audit.reused.reduce(0) { $0 + $1.count },
                              detail: String(localized: "The same password on several sites: a leak at one opens the others."))
                        ForEach(Array(audit.reused.enumerated()), id: \.offset) { _, group in
                            Text("Same password on \(group.count) items")
                                .font(.caption).foregroundStyle(.secondary)
                                .padding(.horizontal, 8).padding(.top, 6)
                            ForEach(group, id: \.id) { row($0, change: true).id("reused-\($0.id)") }
                        }
                    }
                    if !audit.weak.isEmpty {
                        title("Weak passwords", count: audit.weak.count,
                              detail: String(localized: "Too short or too simple to withstand an offline attack."))
                        ForEach(audit.weak, id: \.item.id) { weak in
                            row(weak.item, note: String(localized: "\(Int(weak.bits)) bits"), change: true)
                                .id("weak-\(weak.item.id)")
                        }
                    }
                    if !audit.insecure.isEmpty {
                        title("HTTP sites", count: audit.insecure.count,
                              detail: String(localized: "The password travels there in the clear: Verrou doesn't fill it in Brave."))
                        ForEach(audit.insecure, id: \.id) { row($0, change: true).id("http-\($0.id)") }
                    }
                    if audit.reused.isEmpty && audit.weak.isEmpty && audit.insecure.isEmpty {
                        Label("No reused or weak passwords", systemImage: "checkmark.seal.fill")
                            .foregroundStyle(.green)
                            .padding(8)
                    }
                }
                WatchtowerSections(row: { row($0, note: $1, change: $2) })
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 10)
        }
        .background(Color(nsColor: .controlBackgroundColor))
        .task(id: model.watchtower.focus) {
            // Visual review: a specific section at the top of the pane.
            guard let focus = model.watchtower.focus else { return }
            try? await Task.sleep(for: .milliseconds(100))
            proxy.scrollTo(focus, anchor: .top)
        }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text("Security Audit").font(.title3.weight(.semibold))
                .layoutMark("pane-title")
            if let audit = model.audit {
                Text(summaryLine(audit))
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 8)
        .padding(.bottom, 6)
    }

    private func summaryLine(_ audit: AuditReport) -> String {
        var line = String(localized: "\(Int(audit.checked)) passwords checked, on this Mac")
        if let count = model.watchtower.passkeys?.candidates.count, count > 0 {
            line += " · " + (count > 1 ? String(localized: "\(count) passkeys available")
                                       : String(localized: "\(count) passkey available"))
        }
        return line
    }

    @ViewBuilder private var breachSection: some View {
        if let breaches = model.breaches {
            title("Known leaks", count: breaches.count,
                  detail: breaches.isEmpty
                      ? String(localized: "None of your passwords appears in the recorded leaks.")
                      : String(localized: "These passwords circulate in public leaks: change them first."))
            ForEach(breaches, id: \.item.id) { breach in
                row(breach.item, note: String(localized: "seen \(breach.count.formatted()) times"), change: true)
                    .id("breach-\(breach.item.id)")
            }
        } else {
            VStack(alignment: .leading, spacing: 8) {
                Text("Known leaks").font(.headline)
                Text("Verrou can check your passwords with Have I Been Pwned. Only the first 5 characters of their SHA-1 hash go out: neither the passwords nor their full hash leave this Mac.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Button("Check for Leaks") { Task { await model.checkBreaches() } }
                        .disabled(model.checkingBreaches || model.mode == .demo)
                    if model.checkingBreaches { ProgressView().controlSize(.small) }
                }
                if let error = model.breachError {
                    Text(error).font(.caption).foregroundStyle(.red)
                }
            }
            .padding(10)
            .background(Theme.wash(0.04), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .padding(.bottom, 6)
        }
    }

    private func title(_ text: LocalizedStringKey, count: Int, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(text).font(.headline)
                Text("\(count)").monospacedDigit().foregroundStyle(.secondary)
            }
            Text(detail).font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 8)
        .padding(.top, 14)
        .padding(.bottom, 2)
    }

    /// `change`: the row offers "Change Password" (login with a site).
    private func row(_ summary: ItemSummary, note: String? = nil, change: Bool = false) -> some View {
        let selected = summary.id == model.selection
        return HStack {
            ItemRow(summary: summary, highlights: [], selected: selected)
                .accessibilityElement(children: .combine)
                .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
                .accessibilityAction { model.selection = summary.id }
            if let note {
                Text(note).font(.caption).monospacedDigit()
                    .foregroundStyle(selected ? AnyShapeStyle(Theme.onAccentSecondary(0.85)) : AnyShapeStyle(.secondary))
            }
            if change, summary.canChangePassword {
                ChangePasswordButton(summary: summary, title: "Change", selected: selected)
            }
        }
        .padding(.horizontal, 8)
        .background(selected ? Theme.accent : .clear, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
        .contentShape(Rectangle())
        .onTapGesture { model.selection = summary.id }
        .contextMenu { RowMenu(summary: summary) }
    }
}

/// Audit additions: two-factor authentication available, expired or soon
/// expired cards, old passwords (`Watchtower`).
private struct WatchtowerSections<Row: View>: View {
    @Environment(AppModel.self) private var model
    /// Row of an item: note, and "Change Password" button.
    let row: (ItemSummary, String?, Bool) -> Row

    var body: some View {
        let watchtower = model.watchtower
        twoFactorSection(watchtower)
        passkeySection(watchtower)
        if let report = watchtower.report {
            if !report.cards.isEmpty {
                title("Expired or soon expired cards", count: report.cards.count,
                      detail: String(localized: "Update the date and the security code of the new card, here and with merchants."))
                ForEach(report.cards, id: \.item.id) { card in
                    row(card.item, cardNote(card), false)
                        .id("card-\(card.item.id)")
                }
            }
            if !report.old.isEmpty {
                title("Old passwords", count: report.old.count,
                      detail: String(localized: "Items unchanged for more than 3 years: their password dates back at least that far."))
                ForEach(report.old, id: \.item.id) { old in
                    row(old.item, age(days: old.days), true)
                        .id("old-\(old.item.id)")
                }
            }
        }
    }

    @ViewBuilder private func twoFactorSection(_ watchtower: Watchtower) -> some View {
        if let report = watchtower.twoFactor {
            if !report.missing.isEmpty {
                title("Two-factor authentication available", count: report.missing.count,
                      detail: twoFactorDetail(report))
                ForEach(report.missing, id: \.item.id) { missing in
                    HStack(spacing: 4) {
                        row(missing.item, missing.totp ? nil : methods(missing.methods), false)
                        if let doc = missing.documentation, let url = URL(string: doc) {
                            Link(destination: url) {
                                Image(systemName: "questionmark.circle")
                                    .accessibilityLabel("Help")
                            }
                            .buttonStyle(.borderless)
                            .help("Turn on two-factor authentication on \(missing.site)")
                        }
                    }
                    .id("2fa-\(missing.item.id)")
                }
            }
        } else if watchtower.loadingTwoFactor {
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text("Looking for sites that offer two-factor authentication…")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(.horizontal, 8).padding(.top, 14)
        } else if let error = watchtower.twoFactorError, model.mode == .vaultwarden {
            title("Two-factor authentication available", count: 0,
                  detail: String(localized: "Category skipped: the 2fa.directory list could not be downloaded (\(error))."))
        }
    }

    @ViewBuilder private func passkeySection(_ watchtower: Watchtower) -> some View {
        if let report = watchtower.passkeys {
            if !report.candidates.isEmpty {
                title("Passkey available", count: report.candidates.count, detail: passkeyDetail(report))
                    .id("passkeys")
                ForEach(report.candidates, id: \.item.id) { candidate in
                    HStack(spacing: 4) {
                        row(candidate.item, nil, false)
                        if !candidate.passwordless {
                            Image(systemName: "2.circle")
                                .foregroundStyle(.secondary)
                                .help("Second factor only: the passkey is added to the password")
                                .accessibilityLabel("Second factor only")
                        }
                        if let doc = candidate.documentation, let url = URL(string: doc) {
                            Link(destination: url) {
                                Image(systemName: "questionmark.circle")
                                    .accessibilityLabel("Help")
                            }
                            .buttonStyle(.borderless)
                            .help("Help from \(candidate.domain) on passkeys")
                        }
                        CreatePasskeyButton(candidate: candidate,
                                            mark: candidate.item.id == report.candidates.first?.item.id)
                    }
                    .id("passkey-\(candidate.item.id)")
                }
                Text("Once the passkey is saved, the item leaves this list at the next sync. Keep the password as a backup; if the site allows passwordless login, you can remove it there, then here.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 8).padding(.top, 4)
            }
        } else if watchtower.loadingPasskeys {
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text("Looking for sites that accept passkeys…")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(.horizontal, 8).padding(.top, 14)
        } else if let error = watchtower.passkeysError, model.mode == .vaultwarden {
            title("Passkey available", count: 0,
                  detail: String(localized: "Category skipped: the passkeys.2fa.directory directory could not be downloaded (\(error))."))
        }
    }

    private func passkeyDetail(_ report: PasskeyReport) -> String {
        var text = String(localized: "These sites accept passkeys: nothing to remember, nothing to phish. “Create a Passkey” opens the site's page; the Verrou extension for Brave or Firefox then offers to save it in the item. According to passkeys.2fa.directory")
        if report.stale {
            let date = Date(timeIntervalSince1970: TimeInterval(report.fetchedAt))
            text += " " + String(localized: "(directory of \(date.formatted(date: .abbreviated, time: .omitted)), offline)")
        }
        return text + "."
    }

    private func twoFactorDetail(_ report: TwoFactorReport) -> String {
        var text = String(localized: "These sites offer two-factor authentication, but no one-time code is saved in Verrou. According to 2fa.directory")
        if report.stale {
            let date = Date(timeIntervalSince1970: TimeInterval(report.fetchedAt))
            text += " " + String(localized: "(list of \(date.formatted(date: .abbreviated, time: .omitted)), offline)")
        }
        return text + "."
    }

    private func methods(_ methods: [String]) -> String {
        let names = methods.map { method -> String in
            switch method {
            case "sms": "SMS"
            case "call": String(localized: "call")
            case "email": String(localized: "email")
            case "u2f": String(localized: "security key")
            case "custom-software": String(localized: "app")
            case "custom-hardware": String(localized: "hardware")
            default: method
            }
        }
        return names.joined(separator: ", ")
    }

    private func cardNote(_ card: ExpiringCard) -> String {
        if card.daysLeft < 0 { return String(localized: "expired (\(card.expiry))") }
        if card.daysLeft == 0 { return String(localized: "expires today") }
        let days = Int(card.daysLeft)
        return days > 1 ? String(localized: "expires in \(days) days") : String(localized: "expires in \(days) day")
    }

    private func age(days: Int64) -> String {
        let years = Int(days / 365)
        return years > 1 ? String(localized: "\(years) years") : String(localized: "\(years) year")
    }

    private func title(_ text: LocalizedStringKey, count: Int, detail: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack {
                Text(text).font(.headline)
                Text("\(count)").monospacedDigit().foregroundStyle(.secondary)
            }
            Text(detail).font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 8)
        .padding(.top, 14)
        .padding(.bottom, 2)
    }
}

/// "Create a Passkey": opens the site's page where it is created
/// (`AppModel.createPasskey`). A spinner while looking it up.
struct CreatePasskeyButton: View {
    @Environment(AppModel.self) private var model
    let candidate: PasskeyCandidate
    /// Marker for the visual review (the first button only).
    var mark = false

    var body: some View {
        if mark {
            button.layoutMark("create-passkey")
        } else {
            button
        }
    }

    private var button: some View {
        let busy = model.watchtower.creatingPasskey == candidate.item.id
        return Button {
            Task { await model.createPasskey(for: candidate) }
        } label: {
            HStack(spacing: 4) {
                if busy {
                    ProgressView().controlSize(.mini)
                } else {
                    Image(systemName: "person.badge.key")
                }
                Text("Create a Passkey")
            }
        }
        .disabled(model.watchtower.creatingPasskey != nil || model.lockState != .unlocked)
        .help("Open the page of \(candidate.domain) where a passkey is created")
        .buttonStyle(.borderless)
        .font(.caption.weight(.medium))
        .foregroundStyle(Theme.accent)
    }
}

/// "Change Password": opens the site's page where it is done
/// (`AppModel.changePassword`). A spinner while checking.
struct ChangePasswordButton: View {
    @Environment(AppModel.self) private var model
    let summary: ItemSummary
    var title: LocalizedStringKey = "Change Password"
    /// Selected row (accent background): white text.
    var selected = false
    /// Bordered button (item detail) rather than a discreet link (audit).
    var bordered = false

    var body: some View {
        let busy = model.changingPassword == summary.id
        let button = Button {
            Task { await model.changePassword(of: summary) }
        } label: {
            HStack(spacing: 4) {
                if busy {
                    ProgressView().controlSize(.mini)
                } else {
                    Image(systemName: "arrow.triangle.2.circlepath")
                }
                Text(title)
            }
        }
        .disabled(model.changingPassword != nil || model.lockState != .unlocked)
        .help("Open the change-password page on \(summary.host ?? String(localized: "the website"))")
        .accessibilityLabel("Change Password")
        if bordered {
            button
        } else {
            button
                .buttonStyle(.borderless)
                .font(.caption.weight(.medium))
                .foregroundStyle(selected ? Color.white : Theme.accent)
        }
    }
}
