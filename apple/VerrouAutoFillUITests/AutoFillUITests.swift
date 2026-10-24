import CryptoKit
import XCTest

/// End-to-end AutoFill, in the simulator's Safari (launched by
/// `scripts/ios-autofill-e2e.sh`, nothing on the Mac's screen):
///
/// 1. the app signs in to the test Vaultwarden and publishes its identities;
/// 2. a login fills from the keyboard suggestion (simulated Face ID,
///    accepted continuously by the script), then the page gets a passkey in
///    the background (conditional creation);
/// 3. a one-time code fills (iOS 18+);
/// 4. a passkey is created on the test page, which verifies the attestation;
/// 5. then used to sign in: the page verifies the ES256 signature.
///
/// The tests run in the order of their names and share the simulator's
/// state. Variables (`TEST_RUNNER_` prefix on the xcodebuild side):
/// `VERROU_AUTOFILL_E2E_*` (see `AutoFillSetupDriver`), `_PAGE` (address of
/// the test page), `_SHOTS` (screenshots folder, on the Mac) and `_PAUSE`
/// (seconds of pause at key steps, for a video one can follow).
@MainActor
final class AutoFillUITests: XCTestCase {
    private let environment = ProcessInfo.processInfo.environment
    private lazy var safari = XCUIApplication(bundleIdentifier: "com.apple.mobilesafari")
    private let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")

    override func setUp() async throws {
        continueAfterFailure = false
    }

    private func value(_ name: String) throws -> String {
        guard let value = environment["VERROU_AUTOFILL_E2E_\(name)"] else {
            throw XCTSkip("VERROU_AUTOFILL_E2E_\(name) not set: run scripts/ios-autofill-e2e.sh")
        }
        return value
    }

    /// Screenshot: taken by the script (`simctl io screenshot`) when it
    /// answers the requests (`_SNAP_DIR`: `req/<name>` then `ack/<name>`),
    /// otherwise by XCUIScreen.
    private func shot(_ name: String) {
        if let exchange = environment["VERROU_AUTOFILL_E2E_SNAP_DIR"] {
            let base = URL(fileURLWithPath: exchange)
            try? FileManager.default.createDirectory(at: base.appending(path: "req"), withIntermediateDirectories: true)
            FileManager.default.createFile(atPath: base.appending(path: "req/\(name)").path, contents: nil)
            let ack = base.appending(path: "ack/\(name)").path
            let deadline = Date().addingTimeInterval(20)
            while !FileManager.default.fileExists(atPath: ack), Date() < deadline { usleep(200_000) }
            return
        }
        guard let dir = environment["VERROU_AUTOFILL_E2E_SHOTS"] else { return }
        let data = XCUIScreen.main.screenshot().pngRepresentation
        try? data.write(to: URL(fileURLWithPath: dir).appending(path: "\(name).png"))
    }

    /// Pause at key steps when the script records a video
    /// (`VERROU_RECORD`); none otherwise.
    private func pause() {
        guard let seconds = environment["VERROU_AUTOFILL_E2E_PAUSE"].flatMap(Double.init), seconds > 0 else { return }
        usleep(UInt32(seconds * 1_000_000))
    }

    /// Timestamped marker in the log, to cut the video.
    private func mark(_ name: String) {
        print("AUTOFILL_E2E_MARK \(name) \(Date().timeIntervalSince1970)")
    }

    /// The accessibility trees, to understand a failure.
    private func dump(_ label: String) {
        print("AUTOFILL_TREE \(label) — Safari:\n\(safari.debugDescription)")
        print("AUTOFILL_TREE \(label) — SpringBoard:\n\(springboard.debugDescription)")
    }

    /// First element found in Safari or SpringBoard (system sheets, the
    /// extension's interface).
    private func find(_ timeout: TimeInterval, _ query: (XCUIApplication) -> XCUIElement) -> XCUIElement? {
        let deadline = Date().addingTimeInterval(timeout)
        repeat {
            for app in [safari, springboard] {
                let element = query(app)
                if element.exists { return element }
            }
            usleep(300_000)
        } while Date() < deadline
        return nil
    }

    private func waitFor(_ timeout: TimeInterval, _ condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() {
            if Date() > deadline { return false }
            usleep(300_000)
        }
        return true
    }

    private func openPage() throws {
        let page = URL(string: try value("PAGE"))!
        let title = safari.webViews.staticTexts["Verrou test bench"]
        // Reloaded at each test (page state reset); a second time if
        // Safari's first launch delayed it.
        for _ in 0..<2 {
            safari.open(page)
            XCTAssertTrue(safari.wait(for: .runningForeground, timeout: 20))
            if title.waitForExistence(timeout: 15) { break }
        }
        XCTAssertTrue(title.exists, "test page")
    }

    /// Taps the field until the keyboard opens (the page may still be
    /// settling).
    private func focus(_ field: XCUIElement) {
        for _ in 0..<4 {
            field.tap()
            if safari.keyboards.firstMatch.waitForExistence(timeout: 3) { return }
        }
    }

    private func pageText(_ prefix: String) -> String? {
        let texts = safari.webViews.staticTexts.allElementsBoundByIndex.map(\.label)
        return texts.first { $0.hasPrefix(prefix) }
    }

    // MARK: 1. The app

    func test1_AppSignsInAndPublishes() throws {
        let ack = URL(fileURLWithPath: try value("ACK"))
        let app = XCUIApplication()
        for key in ["SERVER", "EMAIL", "PASSWORD", "TOTP", "SITE", "ACK"] {
            app.launchEnvironment["VERROU_AUTOFILL_E2E_\(key)"] = try value(key)
        }
        app.launch()
        let ready = waitFor(180) {
            FileManager.default.fileExists(atPath: ack.appending(path: "app-ready").path)
                || FileManager.default.fileExists(atPath: ack.appending(path: "app-failed").path)
        }
        let failure = try? String(contentsOf: ack.appending(path: "app-failed"), encoding: .utf8)
        XCTAssertTrue(ready && failure == nil, "app setup: \(failure ?? "timed out")")
        let status = app.descendants(matching: .any)["autofill-status"]
        if !status.isHittable { app.swipeUp() }
        sleep(1)
        shot("01-app-filling-settings")
        XCTAssertTrue(app.staticTexts["On"].waitForExistence(timeout: 10), "Verrou enabled as provider")
    }

    // MARK: 2. Password

    func test2_PasswordFillsFromTheKeyboardSuggestion() throws {
        try openPage()
        mark("password")
        pause()
        let field = safari.webViews.textFields["Username"]
        XCTAssertTrue(field.waitForExistence(timeout: 10))
        focus(field)
        let suggestion = find(20) { app in
            let fill = app.buttons["FillPasswordButton"]
            if fill.exists { return fill }
            return app.buttons.matching(NSPredicate(format: "label CONTAINS[c] %@", "camille@verrou.test")).firstMatch
        }
        shot("02-keyboard-suggestion")
        guard let suggestion else {
            dump("suggestion")
            return XCTFail("no Verrou suggestion above the keyboard")
        }
        pause()
        suggestion.tap()
        // The system's Face ID then Verrou's (the script accepts them).
        sleep(3)
        shot("03-extension-unlock")
        let filled = waitFor(60) {
            let field = self.safari.webViews.textFields["Username"]
            return field.exists && (field.value as? String) == "camille@verrou.test"
        }
        if !filled { dump("filling") }
        XCTAssertTrue(filled, "login filled")
        shot("04-login-filled")
        pause()
        safari.webViews.buttons["Sign in"].tap()
        XCTAssertTrue(waitFor(10) { self.pageText("user=") != nil })
        pause()
        XCTAssertEqual(pageText("user="), "user=camille@verrou.test pass=Verrou-AutoFill-42")
        // Conditional creation (iOS 18): the page requests a passkey in the
        // background; the extension creates it with the key prepared at fill
        // time, without an interface.
        let upgraded = waitFor(30) { self.pageText("UPGRADE") != nil }
        shot("04b-conditional-passkey")
        print("AUTOFILL_UPGRADE \(pageText("UPGRADE") ?? "no result")")
        XCTAssertTrue(upgraded, "no response to the conditional creation")
        XCTAssertNotNil(pageText("UPGRADE ok"), pageText("UPGRADE_ERROR") ?? "timed out")
    }

    // MARK: 4–5. Passkey

    func test4_PasskeyIsCreatedInVerrou() throws {
        try openPage()
        mark("passkey-create")
        pause()
        safari.webViews.buttons["Create a passkey"].tap()
        // System sheet: choose "Save to Verrou" (Apple Passwords is checked
        // by default), then continue.
        let proceed = find(20) { $0.descendants(matching: .any)["ASAuthorizationControllerContinueButton"] }
        guard let proceed else {
            dump("creation sheet")
            return XCTFail("no passkey creation sheet")
        }
        // The sheet is still rising: wait until it stops moving, otherwise
        // the tap lands next to it and Passwords stays chosen.
        var frame = CGRect.null
        _ = waitFor(5) {
            defer { frame = proceed.frame }
            return proceed.frame == frame
        }
        let verrou = find(5) { app in
            app.buttons.matching(NSPredicate(format: "label CONTAINS[c] %@ AND label CONTAINS[c] %@",
                                             "Save", "Verrou")).firstMatch
        }
        guard let verrou else {
            dump("provider choice")
            return XCTFail("Verrou is not offered to save the passkey")
        }
        for _ in 0..<3 {
            verrou.tap()
            if waitFor(2, { verrou.isSelected }) { break }
        }
        print("AUTOFILL_ROW \(verrou.debugDescription)")
        sleep(1)
        shot("05-passkey-system-sheet")
        pause()
        proceed.tap()
        // The extension: Face ID, then "New login".
        let newLogin = find(60) { $0.buttons["autofill-passkey-new"] }
        shot("06-passkey-extension")
        guard let newLogin else {
            dump("extension, creation")
            return XCTFail("the extension didn't offer to save the passkey")
        }
        pause()
        newLogin.tap()
        let created = waitFor(60) { self.pageText("CREATED ok") != nil || self.pageText("CREATE_ERROR") != nil }
        shot("07-passkey-created")
        pause()
        if !created { dump("creation") }
        XCTAssertNotNil(pageText("CREATED ok"), pageText("CREATE_ERROR") ?? "timed out")
    }

    func test5_PasskeySignsInAndThePageVerifiesIt() throws {
        try openPage()
        mark("passkey-get")
        pause()
        safari.webViews.buttons["Sign in with the passkey"].tap()
        let proceed = find(20) { $0.descendants(matching: .any)["ASAuthorizationControllerContinueButton"] }
        if let proceed {
            // The sheet is still rising: capture it once settled.
            var frame = CGRect.null
            _ = waitFor(5) {
                defer { frame = proceed.frame }
                return proceed.frame == frame
            }
        }
        shot("08-passkey-sign-in-sheet")
        pause()
        if let proceed { proceed.tap() } else { dump("sign-in sheet") }
        let signed = waitFor(60) { self.pageText("SIGNED ok") != nil || self.pageText("GET_ERROR") != nil }
        // The result shows once the sheet has closed.
        _ = waitFor(5) { !self.safari.keyboards.firstMatch.exists && self.find(0) { $0.descendants(matching: .any)["ASAuthorizationControllerContinueButton"] } == nil }
        sleep(1)
        shot("09-passkey-signature-verified")
        pause()
        pause()
        mark("end")
        if !signed { dump("sign-in") }
        let result = pageText("SIGNED ok")
        XCTAssertNotNil(result, pageText("GET_ERROR") ?? "timed out")
        XCTAssertTrue(result?.contains("verified=true") == true && result?.contains("counter=1") == true, result ?? "")
    }

    // MARK: 3. One-time code

    func test3_OneTimeCodeFills() throws {
        guard #available(iOS 18.0, *) else { throw XCTSkip("one-time codes: iOS 18 and later") }
        try openPage()
        mark("otp")
        pause()
        let field = safari.webViews.textFields["Code"]
        XCTAssertTrue(field.waitForExistence(timeout: 10))
        focus(field)
        let suggestion = find(15) { app in
            // Not "Verrou" alone: the status bar's back-to-app button also
            // carries that name.
            // An "Other" element of the QuickType bar, not a button.
            app.descendants(matching: .any)
                .matching(NSPredicate(format: "label CONTAINS[c] %@", "camille@verrou.test")).firstMatch
        }
        shot("10-code-suggestion")
        guard let suggestion else {
            dump("code")
            throw XCTSkip("no one-time code suggestion in this simulator")
        }
        pause()
        suggestion.tap()
        sleep(3)
        shot("10b-code-extension")
        // During the extension's sheet, the page isn't readable.
        let currentCode = { () -> String in
            let field = self.safari.webViews.textFields["Code"]
            return field.exists ? (field.value as? String ?? "") : ""
        }
        let filled = waitFor(60) { currentCode().count == 6 && currentCode().allSatisfy(\.isNumber) }
        shot("11-code-filled")
        pause()
        if !filled { dump("code filled") }
        XCTAssertTrue(filled, "code filled: \(currentCode())")
        let code = currentCode()
        let now = Date().timeIntervalSince1970
        let expected = [-30.0, 0, 30].map { Self.totp("JBSWY3DPEHPK3PXP", at: now + $0) }
        XCTAssertTrue(expected.contains(code), "code \(code) ≠ \(expected)")
    }

    /// TOTP (RFC 6238, SHA-1, 6 digits, 30 s).
    static func totp(_ secret: String, at time: TimeInterval) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var bits = 0, value = 0
        var key = [UInt8]()
        for char in secret.uppercased() where char != "=" {
            guard let index = alphabet.firstIndex(of: char) else { continue }
            value = (value << 5) | index
            bits += 5
            if bits >= 8 {
                key.append(UInt8((value >> (bits - 8)) & 0xFF))
                bits -= 8
            }
        }
        var counter = UInt64(time / 30).bigEndian
        let message = Data(bytes: &counter, count: 8)
        let mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: key)))
        let offset = Int(mac[19] & 0x0F)
        let code = (UInt32(mac[offset] & 0x7F) << 24 | UInt32(mac[offset + 1]) << 16
            | UInt32(mac[offset + 2]) << 8 | UInt32(mac[offset + 3])) % 1_000_000
        return String(format: "%06u", code)
    }
}
