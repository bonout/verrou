import Foundation

/// The Rust core's fixed English labels and messages (field labels, match
/// rules, import reasons, TOTP errors…), translated for display. Each
/// target's catalog holds them under their exact English text; the
/// messages with a parameter are rebuilt here.
enum CoreText {
    /// A fixed label or message from the core, in the user's language
    /// (unchanged when the catalog does not know it).
    static func localized(_ english: String) -> String {
        Bundle.main.localizedString(forKey: english, value: english, table: nil)
    }

    /// A core message (error, import reason): the fixed ones through the
    /// catalog, those with a parameter rebuilt.
    static func message(_ english: String) -> String {
        if let rest = english.after("unreadable file: ") {
            return String(localized: "unreadable file: \(rest)")
        }
        if let rest = english.after("unsupported TOTP parameter: ") {
            return String(localized: "unsupported TOTP parameter: \(rest)")
        }
        if let format = english.between("this file is not a ", " export") {
            return String(localized: "this file is not a \(localized(format)) export")
        }
        if let type = english.between("empty \"", "\" type in the CSV") {
            return String(localized: "empty \"\(type)\" type in the CSV")
        }
        return localized(english)
    }

    /// Why items look like duplicates: "same site (maif.fr), same
    /// username, different password", part by part.
    static func duplicateReason(_ english: String) -> String {
        let whole = localized(english)
        guard whole == english else { return whole }
        return english.components(separatedBy: ", ").map(reasonPart).joined(separator: ", ")
    }

    private static func reasonPart(_ part: String) -> String {
        if let app = part.between("same app (", ")") { return String(localized: "same app (\(app))") }
        if let site = part.between("same site (", ")") { return String(localized: "same site (\(site))") }
        if let domain = part.between("same domain (", ")") { return String(localized: "same domain (\(domain))") }
        if let title = part.between("same title \"", "\"") { return String(localized: "same title \"\(title)\"") }
        if let via = part.between("close to \"", "\"") { return String(localized: "close to \"\(via)\"") }
        if let rest = part.after("title \""), let quote = rest.range(of: "\" ↔ ") {
            let title = String(rest[..<quote.lowerBound]), domain = String(rest[quote.upperBound...])
            return String(localized: "title \"\(title)\" ↔ \(domain)")
        }
        return localized(part)
    }

    /// An item's title: the core names an item without a title "(untitled)".
    static func title(_ title: String) -> String {
        title == "(untitled)" ? localized(title) : title
    }

    /// An organization's name inserted in a sentence: "the organization"
    /// when the invitation did not give it.
    static func organization(_ name: String) -> String {
        name == "the organization" ? localized(name) : name
    }

    // MARK: Fields

    /// Fields the core fills itself (login, card, identity, SSH key): their
    /// label is always the core's.
    private static let builtInFields: Set<String> = [
        "username", "password", "totp", "cardholder", "brand", "number", "expiry", "code",
        "first_name", "middle_name", "last_name", "company", "email", "phone", "address", "ssn",
        "passport", "license", "public_key", "fingerprint", "private_key",
    ]

    /// Labels of the templates' fields (`verrou_core::template`).
    private static let templateFieldLabels: Set<String> = [
        "Version", "License key", "Licensed to", "Email", "Publisher", "Purchase date", "Order number",
        "Network name (SSID)", "Password", "Security", "Bank", "Account holder", "Account type",
        "Account number", "IBAN", "BIC", "PIN", "Number", "Surname", "Given names", "Nationality",
        "Date of birth", "Place of birth", "Sex", "Issue date", "Expiry date", "Issuing authority",
        "Categories", "Country or region", "Hosting provider", "Admin console", "Console username",
        "Console password", "Type", "Port", "Database", "Connection options", "Organization", "Member",
        "Member number", "Member since", "Phone",
    ]

    /// Templates' names, as the core writes them in a subtitle.
    private static let templateNames: Set<String> = [
        "Software License", "Wi-Fi Network", "Bank Account", "Passport", "Driver's License", "ID Card",
        "Server", "Database", "API Key", "Membership or Subscription",
    ]

    /// Is this custom field one of the template's (and not a field the user
    /// named)?
    static func isTemplateField(_ name: String, template: ItemTemplate?) -> Bool {
        template != nil && templateFieldLabels.contains(name)
    }

    /// Label of a field to display: a built-in or template field's label is
    /// translated, a field the user named stays as is.
    static func fieldLabel(id: String, label: String, template: ItemTemplate?) -> String {
        if builtInFields.contains(id) || isTemplateField(label, template: template) { return localized(label) }
        if id.hasPrefix("history-"), let date = label.after("Replaced on ").flatMap(historyDate) {
            return String(localized: "Replaced on \(date.formatted(date: .numeric, time: .shortened))")
        }
        return label
    }

    /// Value of a field to display: a checkbox's "Yes"/"No" and a linked
    /// field's "Linked to the "Username" field" are the core's words.
    static func fieldValue(id: String, value: String) -> String {
        guard id.hasPrefix("custom-") else { return value }
        if value == "Yes" || value == "No" { return localized(value) }
        if let target = value.between("Linked to the \"", "\" field") {
            return String(localized: "Linked to the \"\(localized(target))\" field")
        }
        return value
    }

    /// Subtitle of an item: a template item without a value to show has
    /// the template's name.
    static func subtitle(_ subtitle: String, template: ItemTemplate?) -> String {
        template != nil && templateNames.contains(subtitle) ? localized(subtitle) : subtitle
    }

    /// `2024-05-12 at 14:03` (UTC), as the core writes a password's history.
    private static func historyDate(_ text: String) -> Date? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyy-MM-dd 'at' HH:mm"
        return formatter.date(from: text)
    }
}

extension ItemDetail {
    /// The fields as displayed (and named in "… copied"): the core's labels
    /// and values translated (see `CoreText.fieldLabel`, `fieldValue`).
    var displayFields: [FieldView] {
        fields.map { field in
            var shown = field
            shown.label = CoreText.fieldLabel(id: field.id, label: field.label, template: summary.template)
            shown.value = field.value.map { CoreText.fieldValue(id: field.id, value: $0) }
            return shown
        }
    }
}

extension ItemSummary {
    /// Subtitle to display (see `CoreText.subtitle`).
    var displaySubtitle: String { CoreText.subtitle(subtitle, template: template) }
}

extension ScannedOtp {
    /// Title of a new login: the issuer, otherwise the account, otherwise
    /// "One-time code".
    var displayTitle: String { issuer ?? account ?? CoreText.localized(title) }
}

private extension String {
    /// What follows `prefix`, when the string starts with it.
    func after(_ prefix: String) -> String? {
        hasPrefix(prefix) ? String(dropFirst(prefix.count)) : nil
    }

    /// What lies between `prefix` and `suffix`, when the string is exactly that.
    func between(_ prefix: String, _ suffix: String) -> String? {
        guard hasPrefix(prefix), hasSuffix(suffix), count >= prefix.count + suffix.count else { return nil }
        return String(dropFirst(prefix.count).dropLast(suffix.count))
    }
}
