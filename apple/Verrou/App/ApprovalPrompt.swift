import Foundation

/// The text of an approval, whoever shows it (Touch ID, the master password
/// dialog of a protected item).
enum ApprovalPrompt {
    /// What is asked, then what the asker says about it. `action`: "allow the
    /// terminal to modify “X”". A write names the fields it changes
    /// (`password, url, −Old token`), never their values. The reason is the
    /// asker's own claim, shown after what is asked; an AI agent's request
    /// also says what will run, on lines of its own, with the reason last:
    /// the reason is the agent's claim, the command is what happens.
    static func compose(action: String, changes: String, motive: String, command: String, fields: String) -> String {
        let asked = changes.isEmpty ? action : "\(action): \(changes)"
        guard !command.isEmpty else { return motive.isEmpty ? asked : "\(asked) (\(motive))" }
        var prompt = asked
        prompt += "\n" + String(localized: "Command: \(command)")
        if !fields.isEmpty { prompt += "\n" + String(localized: "Fields: \(fields)") }
        if !motive.isEmpty { prompt += "\n" + String(localized: "The agent says: “\(motive)”") }
        return prompt
    }
}
