import SwiftUI

/// "Members" entry of an organization, under its collections in the
/// "Shared Vaults" sidebar.
struct MembersSidebarRow: View {
    @Environment(AppModel.self) private var model
    let organization: OrganizationView

    private var active: Bool {
        model.pane == .members && model.members.organizationID == organization.id
    }

    /// Members to confirm: the open list, otherwise the last count.
    private var pending: Int {
        active && model.members.loaded ? model.members.pendingConfirmation
                                       : model.organizationAdmin.toConfirm[organization.id] ?? 0
    }

    var body: some View {
        Button {
            model.openMembers(organization.id)
        } label: {
            Label {
                HStack {
                    Text("Members").lineLimit(1)
                    Spacer()
                    if pending > 0 {
                        Text("\(pending)")
                            .monospacedDigit().foregroundStyle(.orange).font(.callout)
                            .help("Members to confirm")
                    }
                }
            } icon: {
                Image(systemName: "person.3").foregroundStyle(.indigo)
            }
            .padding(.vertical, 2)
            .padding(.horizontal, 4)
            .background(active ? Color.primary.opacity(0.08) : .clear,
                        in: RoundedRectangle(cornerRadius: 5, style: .continuous))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.leading, 14)
        .help(organization.canManageMembers
              ? "Invite, confirm and manage the members of \(organization.name)"
              : "Members of \(organization.name)")
    }
}

/// "Members" pane, in the middle column: the members of an organization,
/// grouped by state. The selected member shows on the right.
struct MembersListView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var members = model.members
        let organization = model.membersOrganization
        VStack(spacing: 0) {
            PaneHeader(title: String(localized: "Members · \(organization?.name ?? "")"),
                       caption: organization?.canManageMembers == true
                           ? String(localized: "Invite an address: the person creates their account (Verrou or web vault), accepts, then you confirm them by checking their fingerprint.")
                           : String(localized: "Your role lets you see the members, not manage them."),
                       busy: members.busy, notice: members.notice, error: members.error) {
                if organization?.canManageMembers == true {
                    Button("Invite", systemImage: "plus") { model.inviteMembers() }
                        .buttonStyle(.borderless)
                        .font(.caption)
                        .help("Invite people to \(organization?.name ?? String(localized: "the organization"))")
                }
            }
            Divider()
            List(selection: $members.selection) {
                if members.members.isEmpty {
                    Text(members.loaded ? "No members." : "Loading…")
                        .foregroundStyle(.secondary)
                }
                section("To confirm", .accepted)
                section("Pending invitations", .invited)
                section("Members", .confirmed)
                section("Revoked members", .revoked)
            }
            .listStyle(.inset)
            .contextMenu(forSelectionType: String.self) { ids in
                if let member = ids.first.flatMap({ id in members.members.first { $0.id == id } }),
                   organization?.canManageMembers == true {
                    MemberActionsMenu(member: member)
                }
            }
        }
        .background(Color(nsColor: .controlBackgroundColor))
        .task(id: members.organizationID) { await model.reloadMembers() }
    }

    @ViewBuilder
    private func section(_ title: LocalizedStringKey, _ status: OrganizationMemberStatus) -> some View {
        let rows = model.members.members.filter { $0.status == status }
        if !rows.isEmpty {
            Section(title) {
                ForEach(rows, id: \.id) { member in
                    MemberRow(member: member).tag(member.id)
                }
            }
        }
    }
}

private struct MemberRow: View {
    let member: OrganizationMember

    var body: some View {
        HStack(spacing: 11) {
            Image(systemName: member.role.symbol)
                .accessibilityHidden(true)
                .font(.system(size: 15))
                .foregroundStyle(member.status == .revoked ? Color.secondary : Theme.accent)
                .frame(width: 26)
            VStack(alignment: .leading, spacing: 3) {
                Text(member.displayName).lineLimit(1)
                Text(subtitle).font(.callout).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            if member.status == .accepted {
                Circle().fill(.orange).frame(width: 7, height: 7)
                    .help("To confirm: check their fingerprint")
            }
        }
        .padding(.vertical, 4)
    }

    private var subtitle: String {
        var parts = [member.role.label]
        if member.name != nil { parts.insert(member.email, at: 0) }
        if member.status == .invited, !member.hasAccount { parts.append(String(localized: "no account yet")) }
        return parts.joined(separator: " · ")
    }
}

/// Possible actions on a member depending on their state (context menu).
private struct MemberActionsMenu: View {
    @Environment(AppModel.self) private var model
    let member: OrganizationMember

    var body: some View {
        switch member.status {
        case .accepted:
            Button("Confirm…") { Task { await model.prepareMemberConfirmation(member) } }
        case .invited:
            Button("Resend Invitation") { Task { await model.reinviteMember(member) } }
        case .revoked:
            Button("Restore Access") { Task { await model.restoreMember(member) } }
        case .confirmed:
            EmptyView()
        }
        Button("Edit Role and Collections…") { model.editMember(member) }
        Divider()
        if member.status != .revoked {
            Button("Revoke Access…") { model.members.confirmRevoke = member }
        }
        Button("Remove from Organization…", role: .destructive) { model.members.confirmRemove = member }
    }
}

/// Right column of the "Members" pane: the selected member, their access,
/// and what can be done with them depending on their state.
struct MemberDetailView: View {
    @Environment(AppModel.self) private var model
    let member: OrganizationMember

    private var organization: OrganizationView? { model.membersOrganization }
    private var canManage: Bool { organization?.canManageMembers == true }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                Text(statusText)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if member.status == .invited, canManage {
                    InvitationNextSteps(email: member.email, server: model.account?.server,
                                        hasAccount: member.hasAccount)
                        .padding(14)
                        .background(Theme.accent.opacity(0.07), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                        .layoutMark("invitation-next-steps")
                }
                if canManage {
                    HStack(spacing: 10) {
                        primaryAction
                        Button("Edit…", systemImage: "pencil") { model.editMember(member) }
                        Spacer()
                        if member.status == .revoked {
                            Button("Restore", systemImage: "arrow.uturn.backward") {
                                Task { await model.restoreMember(member) }
                            }
                        } else {
                            Button("Revoke…", systemImage: "hand.raised") { model.members.confirmRevoke = member }
                                .help("Remove their access without deleting them (restorable)")
                        }
                        Button("Remove…", systemImage: "person.badge.minus", role: .destructive) {
                            model.members.confirmRemove = member
                        }
                    }
                    .disabled(model.members.busy)
                }

                SectionTitle(String(localized: "Access"))
                FieldCard {
                    line(String(localized: "Role"), member.role.label)
                    Divider().padding(.leading, 14)
                    if member.accessAll {
                        line(String(localized: "Collections"), String(localized: "All"))
                    } else if member.collections.isEmpty {
                        line(String(localized: "Collections"), String(localized: "None"))
                    } else {
                        ForEach(Array(member.collections.enumerated()), id: \.element.collectionId) { index, access in
                            if index > 0 { Divider().padding(.leading, 14) }
                            line(collectionName(access.collectionId), CollectionPermission(access).label)
                        }
                    }
                }
                Text(member.role.explanation)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                SectionTitle(String(localized: "Account"))
                FieldCard {
                    line(String(localized: "Email"), member.email)
                    Divider().padding(.leading, 14)
                    line(String(localized: "Account on the server"),
                         member.hasAccount ? String(localized: "Created") : String(localized: "Not created yet"))
                    Divider().padding(.leading, 14)
                    line(String(localized: "Two-factor authentication"),
                         member.twoFactorEnabled ? String(localized: "On") : String(localized: "Off"))
                }
            }
            .padding(.horizontal, 28)
            .padding(.vertical, 24)
            .frame(maxWidth: 720, alignment: .leading)
            .frame(maxWidth: .infinity)
        }
    }

    @ViewBuilder
    private var primaryAction: some View {
        switch member.status {
        case .accepted:
            Button("Confirm…") { Task { await model.prepareMemberConfirmation(member) } }
                .buttonStyle(.borderedProminent)
                .help("Check their fingerprint, then entrust them with the organization's key")
        case .invited:
            Button("Resend Invitation") { Task { await model.reinviteMember(member) } }
        case .confirmed, .revoked:
            EmptyView()
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 16) {
            Image(systemName: member.role.symbol)
                .accessibilityHidden(true)
                .font(.system(size: 28))
                .foregroundStyle(Theme.accent)
                .frame(width: 64, height: 64)
                .background(Theme.accent.opacity(0.1), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            VStack(alignment: .leading, spacing: 5) {
                Text(member.displayName)
                    .font(.system(size: 24, weight: .bold))
                    .textSelection(.enabled)
                    .layoutMark("detail-title")
                HStack(spacing: 8) {
                    Chip(text: member.role.label, symbol: member.role.symbol, tint: Theme.accent)
                    Chip(text: member.status.label, symbol: "circle.fill", tint: member.status.tint)
                    if member.twoFactorEnabled {
                        Chip(text: "2FA", symbol: "lock.shield", tint: .secondary)
                            .help("Two-factor authentication on")
                    }
                }
            }
            Spacer()
        }
        .padding(.bottom, 4)
    }

    private var statusText: LocalizedStringKey {
        switch member.status {
        case .invited:
            member.hasAccount
                ? "Invitation sent: waiting for their acceptance."
                : "Invitation sent. The person creates their account with the link received by email (in Verrou: “Create an Account” on the login screen), then accepts it."
        case .accepted:
            "Invitation accepted. Confirm it after comparing their key's fingerprint with the phrase the person reads in their account: the organization's key will be encrypted for them."
        case .confirmed:
            "Member confirmed: they access the collections below."
        case .revoked:
            "Access revoked: they no longer see anything of the organization. Restore gives them back their previous access."
        }
    }

    private func collectionName(_ id: String) -> String {
        organization?.collections.first { $0.id == id }?.name ?? String(localized: "Collection")
    }

    private func line(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label).foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value).textSelection(.enabled)
                .multilineTextAlignment(.trailing)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }
}

/// Sheets and confirmations of the "Members" pane, attached to the main
/// window.
struct MembersPresentations: ViewModifier {
    @Environment(AppModel.self) private var model

    func body(content: Content) -> some View {
        @Bindable var members = model.members
        content
            .sheet(item: $members.draft) { draft in
                MemberEditorView(draft: draft).environment(model)
            }
            .alert("Check the fingerprint of \(members.confirmation?.member.displayName ?? "")",
                   isPresented: Binding(get: { members.confirmation != nil },
                                        set: { if !$0 { members.confirmation = nil } }),
                   presenting: members.confirmation) { confirmation in
                Button("Confirm") { Task { await model.confirmMember(confirmation) } }
                Button("Cancel", role: .cancel) { members.confirmation = nil }
            } message: { confirmation in
                Text("“\(confirmation.fingerprint)”\n\nAsk \(confirmation.member.displayName) for their account's fingerprint phrase (Verrou: Settings → Account; web vault: Settings → My account). Only confirm if it is identical: the organization's key will be encrypted for this person.")
            }
            .confirmationDialog("Revoke the access of \(members.confirmRevoke?.displayName ?? "")?",
                                isPresented: Binding(get: { members.confirmRevoke != nil },
                                                     set: { if !$0 { members.confirmRevoke = nil } }),
                                presenting: members.confirmRevoke) { member in
                Button("Revoke", role: .destructive) { Task { await model.revokeMember(member) } }
            } message: { _ in
                Text("They will no longer see the organization's items. You can restore their access.")
            }
            .confirmationDialog("Remove \(members.confirmRemove?.displayName ?? "") from the organization?",
                                isPresented: Binding(get: { members.confirmRemove != nil },
                                                     set: { if !$0 { members.confirmRemove = nil } }),
                                presenting: members.confirmRemove) { member in
                Button("Remove", role: .destructive) { Task { await model.removeMember(member) } }
            } message: { _ in
                Text("Their account stays on the server; to bring them back, you will need to invite them again.")
            }
    }
}

/// Invitation of new addresses, or edit of a member's role and collections.
struct MemberEditorView: View {
    @Environment(AppModel.self) private var model
    @State private var draft: MemberDraft

    init(draft: MemberDraft) {
        _draft = State(initialValue: draft)
    }

    private var organization: OrganizationView? { model.membersOrganization }

    /// Roles offered: above "user", only by an owner (Vaultwarden's rule).
    private var roles: [OrganizationMemberRole] {
        organization?.isOwner == true ? [.user, .manager, .admin, .owner] : [.user]
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Image(systemName: draft.isNew ? "person.badge.plus" : "person.crop.circle.badge.checkmark")
                    .accessibilityHidden(true)
                    .font(.system(size: 22))
                    .foregroundStyle(.indigo)
                VStack(alignment: .leading, spacing: 2) {
                    Text(draft.isNew ? "Invite to \(organization?.name ?? String(localized: "the organization"))"
                                     : "Access of \(draft.member?.displayName ?? "")")
                        .font(.headline)
                        .layoutMark("sheet-title")
                    Text(draft.isNew ? "The server sends an invitation link to each address."
                                     : "The role and collections replace the previous ones.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(16)
            Divider()
            Form {
                Section {
                    if draft.isNew {
                        TextField("Email addresses", text: $draft.emails,
                                  prompt: Text("lea@example.com, tom@example.com"), axis: .vertical)
                            .lineLimit(1...4)
                    } else {
                        LabeledContent("Email", value: draft.emails)
                    }
                    Picker("Role", selection: $draft.role) {
                        ForEach(roles, id: \.self) { role in
                            Text(role.label).tag(role)
                        }
                    }
                    .disabled(roles.count == 1)
                } footer: {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(draft.role.explanation)
                        if organization?.isOwner != true {
                            Text("Only an owner can give the manager, administrator or owner roles.")
                        }
                    }
                    .font(.caption).foregroundStyle(.secondary)
                }
                Section("Collections") {
                    if draft.seesAll {
                        Text("All collections, with all rights.")
                            .foregroundStyle(.secondary)
                    } else if let collections = organization?.collections, !collections.isEmpty {
                        ForEach(collections, id: \.id) { collection in
                            collectionRow(collection)
                        }
                    } else {
                        Text("No collections in this organization.").foregroundStyle(.secondary)
                    }
                }
                if draft.isNew {
                    Section {
                        Text("Without an account on the server, the person creates it with the link received (in Verrou: “Create an Account” on the login screen, pasting the link). Once the invitation is accepted, you will confirm it by checking their key's fingerprint.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                }
                if let error = model.members.error {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                Spacer()
                if model.members.busy { ProgressView().controlSize(.small) }
                Button("Cancel") { model.members.draft = nil }
                    .keyboardShortcut(.cancelAction)
                Button(draft.isNew ? "Invite" : "Save") { Task { await model.saveMemberDraft(draft) } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!draft.emails.contains("@") || model.members.busy)
                    .layoutMark("sheet-primary")
            }
            .padding(16)
        }
        .frame(width: 520)
        .frame(minHeight: 420, maxHeight: 640)
        .background(Color(nsColor: .windowBackgroundColor))
        .onAppear { model.members.error = nil }
    }

    private func collectionRow(_ collection: CollectionView) -> some View {
        let granted = Binding(
            get: { draft.access[collection.id] != nil },
            set: { draft.access[collection.id] = $0 ? (draft.access[collection.id] ?? .edit) : nil })
        let permission = Binding(
            get: { draft.access[collection.id] ?? .edit },
            set: { draft.access[collection.id] = $0 })
        return HStack {
            Toggle(collection.name, isOn: granted)
                .toggleStyle(.checkbox)
            Spacer()
            Picker("Rights", selection: permission) {
                ForEach(CollectionPermission.allCases) { level in
                    Text(level.label).tag(level)
                }
            }
            .labelsHidden()
            .frame(width: 230)
            .disabled(draft.access[collection.id] == nil)
        }
    }
}

/// Settings → Account: the fingerprint phrase of my public key, to read to
/// the administrator who confirms me in an organization (or to an emergency
/// contact).
struct OwnFingerprintRow: View {
    @Environment(AppModel.self) private var model
    @State private var phrase: String?
    @State private var failed = false

    var body: some View {
        LabeledContent("Fingerprint phrase") {
            if let phrase {
                FingerprintText(phrase: phrase, font: .body.monospaced(), alignment: .trailing)
            } else if model.lockState != .unlocked {
                Text("vault locked").foregroundStyle(.secondary)
            } else if failed {
                Text("unavailable").foregroundStyle(.secondary)
            } else {
                ProgressView().controlSize(.small)
            }
        }
        .help("To compare with the one seen by the person who confirms you (organization or emergency access)")
        .task(id: model.lockState) {
            phrase = nil
            failed = false
            guard model.lockState == .unlocked else { return }
            if model.members.preview {
                phrase = "turban-deftly-anime-chatroom-unselfish"
                return
            }
            do {
                phrase = try await model.session.ownFingerprint()
            } catch {
                failed = true
            }
        }
    }
}
