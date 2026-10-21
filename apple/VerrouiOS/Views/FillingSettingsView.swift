import SwiftUI

/// List opened on unlock, sorting, site match rules (the iPhone's default,
/// folders) and the account's equivalent domains.
struct FillingSettingsView: View {
    @Environment(PhoneModel.self) private var model

    var body: some View {
        @Bindable var model = model
        Form {
            Section {
                Picker("On unlock", selection: $model.defaultFilter) {
                    ForEach(DefaultFilter.allCases) { filter in
                        Text(filter.label).tag(filter)
                    }
                }
                Picker("Sort lists by", selection: $model.sortOrder) {
                    ForEach(ResultOrder.menu, id: \.self) { order in
                        Text(order.label).tag(order)
                    }
                }
            } header: {
                SectionHeader("Vault")
            } footer: {
                Text("Kept on this iPhone. “Last used” follows what you fill, copy or show here: only item IDs and dates, never sent to the server.")
            }

            Section {
                Picker("Default", selection: defaultRule) {
                    ForEach(UriMatchRule.all) { rule in
                        Text(rule.label).tag(rule)
                    }
                }
                .accessibilityIdentifier("default-match")
            } header: {
                SectionHeader("Site matching")
            } footer: {
                Text("For sites without their own rule (chosen when editing a login). \(defaultRule.wrappedValue.explanation)")
            }

            Section {
                ForEach(model.matchSettings?.folderRules ?? [], id: \.folderId) { rule in
                    Picker(selection: folderRule(rule.folderId)) {
                        ForEach(UriMatchRule.all) { option in
                            Text(option.label).tag(option)
                        }
                    } label: {
                        Label(rule.folderName.isEmpty ? String(localized: "Deleted folder") : rule.folderName, systemImage: "folder.fill")
                    }
                    .swipeActions {
                        Button("Remove", systemImage: "minus.circle", role: .destructive) {
                            model.setFolderMatchRule(rule.folderId, nil)
                        }
                    }
                }
                let free = model.folders.filter { folder in
                    !(model.matchSettings?.folderRules.contains { $0.folderId == folder.id } ?? false)
                }
                Menu {
                    ForEach(free, id: \.id) { folder in
                        Button(folder.name) { model.setFolderMatchRule(folder.id, .host) }
                    }
                } label: {
                    Label("Rule for a folder…", systemImage: "plus.circle.fill")
                }
                .disabled(free.isEmpty)
                .accessibilityIdentifier("add-folder-rule")
            } header: {
                SectionHeader("By folder")
            } footer: {
                Text("Bitwarden has no per-folder rule: this one stays on this iPhone and only applies to sites without their own rule (for example “Host” for the Work folder).")
            }

            Section {
                let groups = model.matchSettings?.equivalentDomains ?? []
                if groups.isEmpty {
                    Text(model.mode == .vaultwarden ? "Read at the next sync." : "None in the demo vault.")
                        .foregroundStyle(.secondary)
                } else {
                    DisclosureGroup(groups.count > 1 ? "\(groups.count) domain groups" : "\(groups.count) domain group") {
                        ForEach(Array(groups.enumerated()), id: \.offset) { _, group in
                            Text(group.joined(separator: " · "))
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } header: {
                SectionHeader("Equivalent domains")
            } footer: {
                Text("Settings of your account, read from the server (web vault → Settings → Domains): the “Base domain” rule also offers the login on the domains of the same group.")
            }
        }
        .navigationTitle("Vault and filling")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var defaultRule: Binding<UriMatchRule> {
        Binding(get: { model.matchSettings?.defaultRule ?? .domain },
                set: { model.setDefaultMatchRule($0) })
    }

    private func folderRule(_ folderID: String) -> Binding<UriMatchRule> {
        Binding(get: { model.matchSettings?.folderRules.first { $0.folderId == folderID }?.rule ?? .domain },
                set: { model.setFolderMatchRule(folderID, $0) })
    }
}
