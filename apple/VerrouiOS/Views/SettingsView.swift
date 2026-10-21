import SwiftUI

/// Settings: account and sync, security (Face ID, auto-lock, clipboard),
/// display, about, sign-out.
struct SettingsTab: View {
    @Environment(PhoneModel.self) private var model
    @State private var confirmLogout = false

    var body: some View {
        @Bindable var model = model
        NavigationStack(path: $model.settingsPath) {
            Form {
                Section {
                    AccountHeader()
                }
                if model.mode == .vaultwarden, let account = model.account {
                    Section {
                        LabeledContent("Email", value: account.email)
                        LabeledContent("Server", value: URL(string: account.server)?.host() ?? account.server)
                        LabeledContent("Synced", value: syncedLabel(account))
                        if let pending = model.pendingLabel {
                            Label(pending, systemImage: "arrow.triangle.2.circlepath")
                                .foregroundStyle(.orange)
                        }
                        Button {
                            Task { await model.syncNow() }
                        } label: {
                            HStack {
                                Text("Sync now")
                                Spacer()
                                if model.syncState == .syncing { ProgressView() }
                            }
                        }
                        .disabled(model.syncState == .syncing)
                        Button {
                            model.sharing.sheet = .fingerprint(nil)
                        } label: {
                            SettingsLabel("Fingerprint phrase", symbol: "person.badge.key.fill", tint: .indigo)
                        }
                        .foregroundStyle(.primary)
                        .accessibilityIdentifier("settings-fingerprint")
                        Button {
                            model.sharing.sheet = .join("")
                        } label: {
                            SettingsLabel("Join an organization", symbol: "envelope.open.fill", tint: .teal)
                        }
                        .foregroundStyle(.primary)
                    } header: {
                        SectionHeader("Account")
                    } footer: {
                        if case .failed(let message) = model.syncState {
                            Text("Last sync failed: \(message)").foregroundStyle(.red)
                        } else if model.syncState == .offline {
                            Text("Server unreachable: the vault shown comes from the cache, changes are waiting for the network.")
                        }
                    }
                }

                Section {
                    Toggle(isOn: $model.biometricsWanted) {
                        SettingsLabel("Unlock with \(Biometrics.name)", symbol: Biometrics.symbolName, tint: .green)
                    }
                    .disabled(!Biometrics.isAvailable || model.mode == .demo)
                    Picker(selection: $model.autoLockSeconds) {
                        Text("Immediately").tag(0)
                        Text("After 1 minute").tag(60)
                        Text("After 5 minutes").tag(300)
                        Text("After 15 minutes").tag(900)
                        Text("After 1 hour").tag(3600)
                        Text("Never").tag(-1)
                    } label: {
                        SettingsLabel("Auto-lock", symbol: "lock.badge.clock", tint: .indigo)
                    }
                    .pickerStyle(.navigationLink)
                    Picker(selection: $model.clipboardSeconds) {
                        Text("After 30 seconds").tag(30)
                        Text("After 90 seconds").tag(90)
                        Text("After 3 minutes").tag(180)
                        Text("After 10 minutes").tag(600)
                    } label: {
                        SettingsLabel("Clear clipboard", symbol: "doc.on.clipboard", tint: .orange)
                    }
                    .pickerStyle(.navigationLink)
                    Button {
                        model.lock()
                    } label: {
                        SettingsLabel("Lock now", symbol: "lock.fill", tint: Theme.accent)
                    }
                } header: {
                    SectionHeader("Security")
                } footer: {
                    Text(securityFooter)
                }

                if model.mode == .vaultwarden {
                    AutoFillSection()
                }

                Section {
                    Toggle(isOn: $model.showSiteIcons) {
                        SettingsLabel("Site icons", symbol: "photo.on.rectangle", tint: .teal)
                    }
                    NavigationLink(value: PhoneModel.SettingsRoute.filling) {
                        SettingsLabel("Vault and filling", symbol: "scope", tint: .purple)
                    }
                    .accessibilityIdentifier("settings-filling")
                } header: {
                    SectionHeader("Display")
                }

                if model.mode == .vaultwarden {
                    Section {
                        ActivityNotificationsToggle {
                            SettingsLabel("Sharing notifications", symbol: "bell.badge.fill", tint: .red)
                        }
                    } header: {
                        SectionHeader("Notifications")
                    } footer: {
                        Text(ActivityNotificationsText.explanation + " " + ActivityNotificationsText.background)
                    }
                }

                Section {
                    Button {
                        model.openAudit()
                    } label: {
                        SettingsLabel("Security audit", symbol: "checkmark.shield.fill", tint: .green)
                    }
                    .accessibilityIdentifier("settings-audit")
                    NavigationLink {
                        AboutView()
                    } label: {
                        SettingsLabel("About and licenses", symbol: "info.circle.fill", tint: .gray)
                    }
                }

                if model.mode == .vaultwarden, model.account != nil {
                    Section {
                        Button("Sign out of this iPhone", role: .destructive) { confirmLogout = true }
                    } footer: {
                        Text("Erases the account, the encrypted cache and \(Biometrics.name) from this iPhone. Your vault stays on the server.")
                    }
                }
            }
            .navigationTitle("Settings")
            .navigationDestination(for: PhoneModel.SettingsRoute.self) { route in
                switch route {
                case .filling: FillingSettingsView()
                }
            }
            .confirmationDialog("Sign out of this iPhone?", isPresented: $confirmLogout, titleVisibility: .visible) {
                Button("Sign out", role: .destructive) { model.logout() }
            } message: {
                if let pending = model.pendingLabel {
                    Text("\(pending): they will be lost.")
                } else {
                    Text("You will need the master password and the second factor to come back.")
                }
            }
        }
    }

    private var securityFooter: String {
        var parts = [
            String(localized: "The delay counts from the moment Verrou goes to the background. Out of the foreground, Verrou's screen is hidden in the app switcher."),
            String(localized: "Copied secrets don't go to your other devices and are cleared by iOS after the delay."),
        ]
        if !Biometrics.isAvailable {
            parts.insert(String(localized: "\(Biometrics.name) is not set up on this iPhone."), at: 0)
        }
        return parts.joined(separator: " ")
    }

    private func syncedLabel(_ account: AccountInfo) -> String {
        guard let synced = account.syncedAt else { return String(localized: "never") }
        let date = Date(timeIntervalSince1970: TimeInterval(synced))
        return date.formatted(.relative(presentation: .named))
    }
}

/// Version, license and third-party components.
struct AboutView: View {
    var body: some View {
        Form {
            Section {
                VStack(spacing: 10) {
                    AppMark(size: 72)
                    Text("Verrou").font(.system(.title2, design: .rounded, weight: .bold))
                    Text("Version \(version)").foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 6)
            }
            .listRowBackground(Color.clear)

            Section("License") {
                Text("Verrou is free software, licensed under GPL-3.0-or-later.")
                Link("Source code", destination: URL(string: "https://github.com/bonout/verrou")!)
            }
            Section("Components") {
                credit("Bitwarden Rust SDK", "GPL-3.0: encryption, decryption and sync of the vault (only the GPL crates of bitwarden/sdk-internal).")
                credit("EFF Long Wordlist", "Electronic Frontier Foundation, CC BY 3.0 US: English passphrases.")
                credit("French diceware list", "Tango for Tails and the Tor project (ulif/diceware), CC0 1.0: French passphrases.")
                credit("UniFFI", "Mozilla, MPL-2.0: binding between the Rust core and Swift.")
            }
            Section {
                Text("“Bitwarden” is a trademark of Bitwarden, Inc. Verrou is neither affiliated with nor endorsed by Bitwarden.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("About")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var version: String {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "\(short) (\(build))"
    }

    private func credit(_ title: LocalizedStringKey, _ detail: LocalizedStringKey) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title)
            Text(detail).font(.caption).foregroundStyle(.secondary)
        }
    }
}

// MARK: Audit

/// Vault audit, computed locally: reused and weak passwords, HTTP sites;
/// known breaches on request (Have I Been Pwned, by k-anonymity: 5
/// characters of each password's SHA-1 hash).
struct AuditView: View {
    @Environment(PhoneModel.self) private var model
    /// The cards have appeared (only once, cascading).
    @State private var appeared = false

    var body: some View {
        ScrollViewReader { proxy in
        List {
            if let audit = model.audit {
                Section {
                    AuditSummary(audit: audit, breaches: model.breaches, passkeys: model.passkeyAudit.count)
                        .staggered(0, shown: appeared)
                    breachesRow
                        .staggered(1, shown: appeared)
                } footer: {
                    Text("Only the first 5 characters of each password's SHA-1 hash leave the iPhone.")
                }
                if let breaches = model.breaches, !breaches.isEmpty {
                    Section {
                        ForEach(breaches, id: \.item.id) { breach in
                            AuditRow(summary: breach.item,
                                     detail: String(localized: "Seen \(breach.count.formatted(.number)) times in breaches"),
                                     tint: .red)
                                .staggered(2, shown: appeared)
                        }
                    } header: {
                        AuditHeader(title: "Compromised", count: breaches.count, tint: .red)
                            .staggered(2, shown: appeared)
                    }
                }
                if !audit.reused.isEmpty {
                    Section {
                        ForEach(Array(audit.reused.enumerated()), id: \.offset) { _, group in
                            ForEach(group, id: \.id) { summary in
                                AuditRow(summary: summary, detail: group.count > 2 ? String(localized: "Same password as \(group.count - 1) others") : String(localized: "Same password as \(group.count - 1) other"),
                                         tint: .orange)
                                    .staggered(3, shown: appeared)
                            }
                        }
                    } header: {
                        AuditHeader(title: "Reused", count: audit.reused.count, tint: .orange,
                                    unit: audit.reused.count > 1 ? String(localized: "groups") : String(localized: "group"))
                            .staggered(3, shown: appeared)
                    }
                }
                if !audit.weak.isEmpty {
                    Section {
                        ForEach(audit.weak, id: \.item.id) { weak in
                            AuditRow(summary: weak.item, detail: String(localized: "\(Int(weak.bits)) bits of estimated entropy"), tint: .orange)
                                .staggered(4, shown: appeared)
                        }
                    } header: {
                        AuditHeader(title: "Weak passwords", count: audit.weak.count, tint: .yellow)
                            .staggered(4, shown: appeared)
                    }
                }
                if !audit.insecure.isEmpty {
                    Section {
                        ForEach(audit.insecure, id: \.id) { summary in
                            AuditRow(summary: summary, detail: String(localized: "The password travels in clear"), tint: .yellow)
                                .staggered(5, shown: appeared)
                        }
                    } header: {
                        AuditHeader(title: "HTTP sites", count: audit.insecure.count, tint: .blue)
                            .staggered(5, shown: appeared)
                    }
                }
                passkeySection
                signalSection
            } else {
                ProgressView()
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Security audit")
        .onChange(of: model.audit != nil, initial: true) { _, ready in
            // First appearance only: the cards, first placed invisible,
            // appear on the next frame.
            guard ready, !appeared else { return }
            DispatchQueue.main.async { appeared = true }
        }
        .onAppear { model.refreshAudit() }
        .refreshable { model.refreshAudit() }
        .onChange(of: model.passkeyAudit.focus) { _, focus in
            // End-to-end run: the section at the top of the screen.
            guard focus else { return }
            withAnimation { proxy.scrollTo("passkeys", anchor: .top) }
        }
        }
    }

    /// "Passkey possible": sites that accept passkeys, according to
    /// passkeys.2fa.directory. Not a problem, an improvement: outside the
    /// score.
    @ViewBuilder private var passkeySection: some View {
        let passkeys = model.passkeyAudit
        if let report = passkeys.report, !report.candidates.isEmpty {
            Section {
                ForEach(report.candidates, id: \.item.id) { candidate in
                    PasskeyCandidateRow(candidate: candidate)
                        .staggered(6, shown: appeared)
                }
            } header: {
                AuditHeader(title: "Passkey possible", count: report.candidates.count, tint: .teal)
                    .staggered(6, shown: appeared)
                    .accessibilityIdentifier("audit-passkeys")
            } footer: {
                Text(passkeyFooter(report))
            }
            .id("passkeys")
        } else if passkeys.loading && passkeys.report == nil {
            Section {
                HStack(spacing: 10) {
                    ProgressView()
                    Text("Looking for sites that accept passkeys…")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
        } else if let error = passkeys.error, model.mode == .vaultwarden {
            Section {
                ErrorLabel(text: String(localized: "Passkey possible: the directory could not be downloaded (\(error))."))
            }
        }
    }

    /// Site signals (iOS 26): the user decides, nothing is deleted
    /// automatically.
    @ViewBuilder private var signalSection: some View {
        let signals = model.passkeyAudit.signals
        if !signals.isEmpty {
            Section {
                ForEach(signals, id: \.self) { finding in
                    AuditRow(summary: finding.item, detail: signalDetail(finding), tint: .indigo)
                }
            } header: {
                AuditHeader(title: "Reported by sites", count: signals.count, tint: .indigo)
            } footer: {
                Text("The keyboard suggestions already take them into account. Verrou deletes nothing: open the item to remove the passkey or the password if you wish.")
            }
        }
    }

    private func signalDetail(_ finding: SignalFinding) -> String {
        switch finding.kind {
        case .passkeyRejected: String(localized: "Passkey unknown to \(finding.site): it can be deleted")
        case .passkeyRenamed: String(localized: "New name at \(finding.site): \(finding.detail ?? "")")
        case .passwordUnused: String(localized: "Password not needed for \(finding.site): passkey in place")
        }
    }

    private func passkeyFooter(_ report: PasskeyReport) -> String {
        var text = String(localized: "These sites accept passkeys: nothing to remember, nothing to phish. “Create” opens the site's page in Safari; choose Verrou to save the passkey. The item leaves the list at the next sync; keep the password as a fallback, or remove it at the site if it allows signing in without a password. According to passkeys.2fa.directory")
        if report.stale {
            let date = Date(timeIntervalSince1970: TimeInterval(report.fetchedAt))
            text += " " + String(localized: "(directory of \(date.formatted(.dateTime.day().month(.wide))), offline)")
        }
        return text + "."
    }

    @ViewBuilder private var breachesRow: some View {
        if model.mode == .vaultwarden {
            Button {
                Task { await model.checkBreaches() }
            } label: {
                HStack {
                    SettingsLabel(model.breaches == nil ? String(localized: "Look for known breaches") : String(localized: "Check again"),
                                  symbol: "exclamationmark.shield.fill", tint: .red)
                    Spacer()
                    if model.checkingBreaches { ProgressView() }
                }
            }
            .disabled(model.checkingBreaches)
            if let error = model.breachError {
                ErrorLabel(text: error)
            } else if model.breaches?.isEmpty == true {
                Label("No password found in known breaches", systemImage: "checkmark.seal")
                    .foregroundStyle(.green)
            }
        }
    }
}

/// Audit summary: colored shield, number of passwords checked and counters
/// per problem (the Mac's duplicate chips).
private struct AuditSummary: View {
    let audit: AuditReport
    let breaches: [BreachedPassword]?
    /// "Passkey possible": an improvement, outside the score.
    var passkeys = 0

    var body: some View {
        let issues = (breaches?.count ?? 0) + audit.reused.count + audit.weak.count + audit.insecure.count
        let tint: Color = (breaches?.isEmpty == false) ? .red : issues > 0 ? .orange : .green
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 14) {
                AuditScoreGauge(score: score, tint: tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text(issues == 0 ? "Nothing to report" : issues > 1 ? "\(issues) points to review" : "\(issues) point to review")
                        .font(.headline)
                    Text("\(audit.checked) passwords checked")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                }
            }
            if issues > 0 || passkeys > 0 {
                FlowLayout(spacing: 6, lineSpacing: 6) {
                    if let count = breaches?.count, count > 0 { CountCapsule(text: String(localized: "\(count) compromised"), tint: .red) }
                    if !audit.reused.isEmpty {
                        CountCapsule(text: audit.reused.count > 1 ? String(localized: "\(audit.reused.count) reused groups") : String(localized: "\(audit.reused.count) reused group"), tint: .orange)
                    }
                    if !audit.weak.isEmpty {
                        CountCapsule(text: audit.weak.count > 1 ? String(localized: "\(audit.weak.count) weak passwords") : String(localized: "\(audit.weak.count) weak password"), tint: .yellow)
                    }
                    if !audit.insecure.isEmpty { CountCapsule(text: String(localized: "\(audit.insecure.count) over HTTP"), tint: .blue) }
                    if passkeys > 0 {
                        CountCapsule(text: passkeys > 1 ? String(localized: "\(passkeys) passkeys possible") : String(localized: "\(passkeys) passkey possible"),
                                     tint: .teal)
                    }
                }
            }
        }
        .padding(.vertical, 6)
        .accessibilityElement(children: .combine)
    }

    /// Share of the passwords checked without any problem, out of 100.
    private var score: Int {
        guard audit.checked > 0 else { return 100 }
        var flagged = Set<String>()
        for group in audit.reused { flagged.formUnion(group.map(\.id)) }
        flagged.formUnion(audit.weak.map(\.item.id))
        flagged.formUnion(audit.insecure.map(\.id))
        flagged.formUnion((breaches ?? []).map(\.item.id))
        let clean = max(0, Int(audit.checked) - flagged.count)
        return Int((Double(clean) / Double(audit.checked) * 100).rounded())
    }
}

/// Audit score: ring gauge that fills on first appearance and follows the
/// changes, the number rolling with it.
private struct AuditScoreGauge: View {
    let score: Int
    let tint: Color
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var shown: Double?

    var body: some View {
        let value = shown ?? 0
        Gauge(value: value, in: 0...100) {
            Text("Security score")
        } currentValueLabel: {
            Text("\(Int(value))")
                .contentTransition(reduceMotion ? .opacity : .numericText(value: value))
        }
        .gaugeStyle(ScoreRingGaugeStyle(tint: tint))
        .frame(width: 56, height: 56)
        .animation(reduceMotion ? .easeOut(duration: 0.2) : .spring(response: 1.0, dampingFraction: 0.86), value: shown)
        .task {
            guard shown == nil else { return }
            shown = 0
            try? await Task.sleep(for: .milliseconds(120))
            shown = Double(score)
        }
        .onChange(of: score) { _, new in shown = Double(new) }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Security score")
        .accessibilityValue("\(score) out of 100")
    }
}

/// Gauge ring: discreet track, tinted arc, number in the center.
private struct ScoreRingGaugeStyle: GaugeStyle {
    let tint: Color

    func makeBody(configuration: Configuration) -> some View {
        ZStack {
            Circle().stroke(tint.opacity(0.18), lineWidth: 6)
            Circle()
                .trim(from: 0, to: configuration.value)
                .stroke(tint.gradient, style: StrokeStyle(lineWidth: 6, lineCap: .round))
                .rotationEffect(.degrees(-90))
            configuration.currentValueLabel
                .font(.system(.headline, design: .rounded, weight: .bold))
                .monospacedDigit()
        }
        .padding(3)
    }
}

/// Header of an audit section: title and number as a label.
private struct AuditHeader: View {
    let title: LocalizedStringKey
    let count: Int
    let tint: Color
    var unit: String?

    var body: some View {
        HStack(spacing: 8) {
            SectionHeader(title)
            Badge(text: unit.map { "\(count) \($0)" } ?? "\(count)", tint: tint)
        }
    }
}

private struct AuditRow: View {
    let summary: ItemSummary
    let detail: String
    let tint: Color

    var body: some View {
        NavigationLink(value: PhoneModel.Route.item(summary.id)) {
            HStack(spacing: 12) {
                ItemIcon(summary: summary, size: 36)
                VStack(alignment: .leading, spacing: 2) {
                    Text(summary.title).lineLimit(1)
                    Text(detail).font(.caption.weight(.medium)).foregroundStyle(tint)
                }
            }
        }
    }
}

/// A login that could move to a passkey: the row leads to the item page,
/// "Create" opens the site's page in Safari.
private struct PasskeyCandidateRow: View {
    @Environment(PhoneModel.self) private var model
    @Environment(\.openURL) private var openURL
    let candidate: PasskeyCandidate

    var body: some View {
        HStack(spacing: 12) {
            HStack(spacing: 12) {
                ItemIcon(summary: candidate.item, size: 36)
                VStack(alignment: .leading, spacing: 2) {
                    Text(candidate.item.title).lineLimit(1)
                    Text(detail).font(.caption.weight(.medium)).foregroundStyle(.teal)
                        .lineLimit(1)
                }
                Spacer(minLength: 0)
            }
            .contentShape(Rectangle())
            .onTapGesture { model.vaultPath.append(.item(candidate.item.id)) }
            .accessibilityElement(children: .combine)
            .accessibilityAddTraits(.isButton)
            if let doc = candidate.documentation, let url = URL(string: doc) {
                Button {
                    openURL(url)
                } label: {
                    Image(systemName: "questionmark.circle")
                        .imageScale(.large)
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Help from \(candidate.domain) on passkeys")
            }
            Button {
                model.createPasskey(for: candidate)
            } label: {
                if model.passkeyAudit.opening == candidate.item.id {
                    ProgressView()
                } else {
                    Label("Create", systemImage: "person.badge.key.fill")
                        .font(.subheadline.weight(.semibold))
                }
            }
            .buttonStyle(.bordered)
            .buttonBorderShape(.capsule)
            .tint(.teal)
            .disabled(model.passkeyAudit.opening != nil)
            .accessibilityLabel("Create a passkey for \(candidate.item.title)")
            .accessibilityIdentifier("create-passkey-\(candidate.item.title)")
        }
    }

    private var detail: String {
        candidate.passwordless ? String(localized: "Passwordless · \(candidate.domain)") : String(localized: "Second factor · \(candidate.domain)")
    }
}

/// Settings header: the logo, the account and the sync state.
private struct AccountHeader: View {
    @Environment(PhoneModel.self) private var model

    var body: some View {
        HStack(spacing: 14) {
            AppMark(size: 56, glow: false)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.headline).lineLimit(1)
                HStack(spacing: 6) {
                    Circle().fill(dot).frame(width: 7, height: 7)
                    Text(detail).font(.subheadline).foregroundStyle(.secondary).lineLimit(1)
                }
            }
        }
        .padding(.vertical, 6)
        .accessibilityElement(children: .combine)
    }

    private var title: String {
        guard model.mode == .vaultwarden, let account = model.account else { return String(localized: "Demo vault") }
        return account.email
    }

    private var detail: String {
        guard model.mode == .vaultwarden, let account = model.account else { return String(localized: "Demonstration data") }
        return URL(string: account.server)?.host() ?? account.server
    }

    private var dot: Color {
        switch model.syncState {
        case .offline: .orange
        case .failed: .red
        default: Theme.online
        }
    }
}

/// A setting's label: symbol on a tinted square, like iOS Settings.
struct SettingsLabel: View {
    let title: Text
    let symbol: String
    let tint: Color

    init(_ title: LocalizedStringKey, symbol: String, tint: Color) {
        self.title = Text(title)
        self.symbol = symbol
        self.tint = tint
    }

    // Disfavored, as in Text: a literal goes to the LocalizedStringKey init.
    @_disfavoredOverload init<S: StringProtocol>(_ title: S, symbol: String, tint: Color) {
        self.title = Text(title)
        self.symbol = symbol
        self.tint = tint
    }

    var body: some View {
        Label {
            title.foregroundStyle(.primary)
        } icon: {
            TintedSymbol(symbol: symbol, tint: tint, size: 28)
        }
    }
}

/// AutoFill: how to choose Verrou in iOS Settings, and where it stands.
private struct AutoFillSection: View {
    @Environment(PhoneModel.self) private var model

    var body: some View {
        Section {
            HStack {
                SettingsLabel("AutoFill", symbol: "key.viewfinder", tint: .blue)
                Spacer()
                switch model.autofillEnabled {
                case .some(true):
                    Text("On").foregroundStyle(.green)
                case .some(false):
                    Text("Off").foregroundStyle(.secondary)
                case .none:
                    ProgressView()
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityIdentifier("autofill-status")
            if model.autofillEnabled != true {
                VStack(alignment: .leading, spacing: 6) {
                    Text("To fill your logins, codes and passkeys in Safari and apps:")
                    Text("1. Open **Settings → General → AutoFill & Passwords**.")
                    Text("2. Turn on **Verrou** in the list of apps.")
                    Text("3. Tap a login field: Verrou offers the site's accounts above the keyboard.")
                }
                .font(.callout)
                .padding(.vertical, 2)
            }
            Button {
                model.openAutofillSettings()
            } label: {
                SettingsLabel(model.autofillEnabled == true ? String(localized: "AutoFill settings") : String(localized: "Open Settings"),
                              symbol: "gear", tint: .gray)
            }
        } header: {
            SectionHeader("AutoFill")
        } footer: {
            Text("The system only receives the sites and user names, for its suggestions. Passwords, codes and passkeys only leave the vault after \(Biometrics.name) or your master password.")
        }
        .task { await model.refreshAutofillStatus() }
    }
}
