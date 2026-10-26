import XCTest

/// What an earlier approval covers (`UnlockGrant`) and when two approval
/// requests are one (`ApprovalKey`): neither may let an agent's request, or
/// another client's, ride on someone else's answer.
final class ApprovalRulesTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_000_000)
    private let items: [(id: String, title: String)] = [
        (id: "id-1", title: "GitHub"),
        (id: "id-2", title: "Twin"),
        (id: "id-3", title: "Twin"),
        (id: "id-4", title: "github"),
    ]

    private func grant(item: String = "id-1", client: String = "terminal-1", age: TimeInterval = 0) -> UnlockGrant {
        UnlockGrant(itemID: item, client: client, until: now.addingTimeInterval(UnlockGrant.lifetime - age))
    }

    // MARK: Unlock grant

    func testAReferenceBecomesAnIdentifierOnlyIfItNamesOneItem() {
        XCTAssertEqual(UnlockGrant.resolve(reference: "id-3", among: items), "id-3")
        XCTAssertEqual(UnlockGrant.resolve(reference: "GitHub", among: items), "id-1")
        // Case matters: "github" is another item.
        XCTAssertEqual(UnlockGrant.resolve(reference: "github", among: items), "id-4")
        XCTAssertNil(UnlockGrant.resolve(reference: "GITHUB", among: items))
        // Two items share the title: no grant, rather than a guess.
        XCTAssertNil(UnlockGrant.resolve(reference: "Twin", among: items))
        XCTAssertNil(UnlockGrant.resolve(reference: "Nothing", among: items))
    }

    func testTheGrantCoversItsItemForItsClientWithinTheMinute() {
        XCTAssertTrue(grant().covers(item: "id-1", client: "terminal-1", ephemeral: false, command: "", now: now))
        XCTAssertTrue(grant(age: 59).covers(item: "id-1", client: "terminal-1", ephemeral: false, command: "", now: now))
        XCTAssertFalse(grant(age: 61).covers(item: "id-1", client: "terminal-1", ephemeral: false, command: "", now: now))
    }

    func testTheGrantDoesNotCoverAnotherItemEvenWithTheSameTitle() {
        // The request carries the identifier: a twin with the same title is
        // another item.
        XCTAssertFalse(grant().covers(item: "id-4", client: "terminal-1", ephemeral: false, command: "", now: now))
        XCTAssertFalse(grant().covers(item: "GitHub", client: "terminal-1", ephemeral: false, command: "", now: now))
    }

    func testTheGrantIsBoundToTheClientThatAsked() {
        XCTAssertFalse(grant().covers(item: "id-1", client: "terminal-2", ephemeral: false, command: "", now: now))
    }

    func testAnAgentsRequestIsNeverCoveredByTheGrant() {
        XCTAssertFalse(grant().covers(item: "id-1", client: "terminal-1", ephemeral: true, command: "", now: now))
        XCTAssertFalse(grant().covers(item: "id-1", client: "terminal-1", ephemeral: false,
                                      command: "curl -d @- x", now: now))
    }

    // MARK: Merging requests

    private func key(item: String = "id-1", ephemeral: Bool = false, command: String = "") -> String? {
        ApprovalKey.make(client: "Claude Code", purpose: "reveal", item: item, title: "GitHub", site: "",
                         reason: "deploy", changes: "", command: command, fields: "T=GitHub › Password",
                         ephemeral: ephemeral, scope: nil)
    }

    func testTwoIdenticalRequestsMergeAndTheItemTellsTwinsApart() {
        XCTAssertNotNil(key())
        XCTAssertEqual(key(), key())
        XCTAssertNotEqual(key(item: "id-1"), key(item: "id-4"), "same title, two items")
        XCTAssertNotEqual(key(command: "ls"), key(command: "rm x"))
    }

    func testAnAgentsRequestsAreNeverMerged() {
        XCTAssertNil(key(ephemeral: true))
        XCTAssertNil(key(ephemeral: true, command: "ls"))
    }

    // MARK: What a protected item's confirmation says

    func testAWriteOnAProtectedItemSaysWhatItDoes() {
        // The text that goes to Touch ID and to the master password dialog.
        let modify = ApprovalPrompt.compose(action: "allow the terminal to modify “Bank”", changes: "password, −Old token",
                                            motive: "rotate", command: "", fields: "")
        XCTAssertEqual(modify, "allow the terminal to modify “Bank”: password, −Old token (rotate)")
        XCTAssertFalse(modify.contains("show"))
        let delete = ApprovalPrompt.compose(action: "allow the terminal to move “Bank” to the trash", changes: "",
                                            motive: "", command: "", fields: "")
        XCTAssertEqual(delete, "allow the terminal to move “Bank” to the trash")
    }

    func testAnAgentsPromptShowsTheCommandAndFieldsBeforeItsReason() {
        let prompt = ApprovalPrompt.compose(action: "allow the terminal to read “GitHub”", changes: "",
                                            motive: "Claude Code: deploy", command: "cd /app && ./deploy.sh",
                                            fields: "T=GitHub › Password")
        let lines = prompt.components(separatedBy: "\n")
        XCTAssertEqual(lines.count, 4)
        XCTAssertEqual(lines[0], "allow the terminal to read “GitHub”")
        XCTAssertTrue(lines[1].contains("cd /app && ./deploy.sh"), prompt)
        XCTAssertTrue(lines[2].contains("T=GitHub › Password"), prompt)
        XCTAssertTrue(lines[3].contains("Claude Code: deploy"), prompt)
    }
}
