#if DEBUG
import CryptoKit
import SwiftUI
import UIKit

/// End-to-end run of the iPhone app against a test Vaultwarden (Debug
/// builds only), in the simulator: sign-in, TOTP second factor, vault,
/// search, reveal, copy, protected item (simulated Face ID), Wi-Fi QR code,
/// creation and edit, card, bulk actions, offline edit and resync, locking,
/// Face ID, sign-out.
///
/// Launched by `scripts/ios-e2e.sh` with `VERROU_E2E_SERVER`, `_EMAIL`,
/// `_PASSWORD` and `_TOTP` (seed), passed through `SIMCTL_CHILD_*`. It
/// announces on its standard output (read by the script):
///
/// - `E2E_OK <step>` at each check, `E2E_DONE` or `E2E_FAIL <reason>`;
/// - `E2E_SNAP <name>`: the screen is ready, the script takes the screenshot
///   (`xcrun simctl io … screenshot`);
/// - `E2E_FACEID`: a Face ID prompt is waiting, the script presents a
///   recognized face (`notifyutil … pearl.match`);
/// - `E2E_NET off|on`: the script cuts or restores the relay to the server;
/// - `E2E_TEXT <size>`: the script changes the simulator's text size.
@MainActor
final class EndToEndDriver {
    struct Config {
        let server: String
        let email: String
        let password: String
        let totpSecret: String
        /// Second account (invited member), for sharing: address, password,
        /// second factor seed.
        let member: (email: String, password: String, totp: String)?

        init?(_ environment: [String: String]) {
            guard let server = environment["VERROU_E2E_SERVER"], let email = environment["VERROU_E2E_EMAIL"],
                  let password = environment["VERROU_E2E_PASSWORD"], let secret = environment["VERROU_E2E_TOTP"]
            else { return nil }
            self.server = server
            self.email = email
            self.password = password
            totpSecret = secret
            if let memberEmail = environment["VERROU_E2E_MEMBER_EMAIL"],
               let memberPassword = environment["VERROU_E2E_MEMBER_PASSWORD"],
               let memberTotp = environment["VERROU_E2E_MEMBER_TOTP"], !memberEmail.isEmpty {
                member = (memberEmail, memberPassword, memberTotp)
            } else {
                member = nil
            }
        }
    }

    private let model: PhoneModel
    private let config: Config

    init(model: PhoneModel, config: Config) {
        self.model = model
        self.config = config
    }

    func start() {
        Task {
            await run()
            log("E2E_DONE")
        }
    }

    private func log(_ line: String) {
        print(line)
        fflush(stdout)
    }

    private func check(_ condition: Bool, _ step: String) {
        if condition {
            log("E2E_OK \(step)")
        } else {
            log("E2E_FAIL \(step)")
            exit(1)
        }
    }

    private func pause(_ seconds: Double) async {
        try? await Task.sleep(for: .seconds(seconds))
    }

    /// Lets the screen settle, asks for the screenshot and waits for it to be
    /// taken: the script then creates `<VERROU_E2E_ACK>/<name>` (the
    /// simulator's apps see the Mac's disk), otherwise we wait 3 s.
    private func snap(_ name: String) async {
        await pause(1.0)
        log("E2E_SNAP \(name)")
        guard let ack = ProcessInfo.processInfo.environment["VERROU_E2E_ACK"] else {
            await pause(3)
            return
        }
        let marker = URL(fileURLWithPath: ack).appending(path: name)
        _ = await wait(15) { FileManager.default.fileExists(atPath: marker.path) }
    }

    /// Waits for a condition (at most `seconds`).
    private func wait(_ seconds: Double, until condition: () -> Bool) async -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while !condition() {
            if Date() > deadline { return false }
            await pause(0.25)
        }
        return true
    }

    private func id(of title: String) -> String? {
        model.summaries.first { $0.title == title }?.id
    }

    private func run() async {
        await pause(1.5)

        // Sign-in
        check(model.needsLogin, "sign-in screen without an account")
        model.loginServer = config.server
        model.loginEmail = config.email
        await snap("01-sign-in")
        await model.signIn(password: "not the right password")
        check(model.loginError?.localizedCaseInsensitiveContains("incorrect") == true, "wrong password refused")
        await model.signIn(password: config.password)
        check(model.twoFactorOptions == [.authenticator], "second factor requested")
        await snap("02-second-factor")
        await model.answerTwoFactor(.authenticator, token: "000000")
        check(model.loginError != nil && model.lockState != .unlocked, "wrong code refused")
        let now = Date().timeIntervalSince1970
        for offset in [0.0, 30.0] where model.lockState != .unlocked {
            await model.answerTwoFactor(.authenticator, token: Self.totp(config.totpSecret, at: now + offset))
        }
        check(model.lockState == .unlocked, "vault open after the second factor")
        check(model.counts?.all == 9 && model.counts?.trashed == 1,
              "9 items decrypted, 1 in the trash (\(model.counts?.all ?? 0), \(model.counts?.trashed ?? 0))")
        check(model.counts?.folders.map(\.name).sorted() == ["Personnel", "Travail"], "folders decrypted")
        check(model.vault.location.root.path.contains("verrou-e2e-data"), "account in the throwaway folder")
        check(model.biometricEnrolled == Biometrics.isAvailable,
              "Face ID enrolled if available (\(Biometrics.isAvailable ? "yes" : "no"))")
        // The unlock sync first, then one on demand.
        _ = await wait(30) { model.syncState != .syncing }
        await model.syncNow()
        check(model.syncState == .idle, "sync")
        await snap("03-vault")
        if ProcessInfo.processInfo.environment["VERROU_E2E_ONLY"] == "otp" {
            await scanQRCodes()
            return
        }

        // Search (Rust core), without accents or capitals, in the Search tab
        model.tab = .search
        model.searchQuery = "gith"
        check(model.rows(query: "gith", filter: .all).first?.summary.title == "GitHub", "fuzzy search")
        check(model.rows(query: "telecom", filter: .all).isEmpty, "search without results")
        await snap("04-search")
        model.searchQuery = ""
        model.tab = .vault

        // Item page, reveal, copy
        guard let github = id(of: "GitHub") else { return check(false, "GitHub present") }
        model.open(github)
        model.toggleReveal("password", of: github)
        check(model.revealedValue("password", of: github) == "hunter2-hunter2", "password revealed")
        check(model.totpCode(of: github)?.code.count == 6, "one-time code")
        model.copyPassword(of: github)
        check(UIPasteboard.general.string == "hunter2-hunter2", "password copied (local, expiring)")
        await snap("05-login")
        model.vaultPath = []
        await pause(0.8)
        check(model.revealedValue("password", of: github) == nil, "secrets forgotten when leaving the item page")

        // Protected item: Face ID (simulated) or master password
        guard let bank = id(of: "Banque") else { return check(false, "Banque present") }
        model.open(bank)
        await pause(0.8)
        check(model.session.needsConfirmation(id: bank), "protected item: confirmation requested")
        model.toggleReveal("password", of: bank)
        if Biometrics.isAvailable {
            await pause(1.5)
            log("E2E_FACEID")
        } else {
            _ = await wait(5) { model.reprompt != nil }
            await snap("06-master-password")
            await model.answerReprompt(password: config.password)
        }
        check(await wait(15) { model.revealedValue("password", of: bank) != nil },
              "protected item revealed after confirmation")
        await snap("06-protected-item")
        model.vaultPath = []

        // Card, Wi-Fi
        if let visa = id(of: "Visa") {
            model.open(visa)
            await snap("07-card")
            model.vaultPath = []
        }
        guard let wifi = id(of: "Wi-Fi maison") else { return check(false, "Wi-Fi network present") }
        check(model.summary(id: wifi)?.template == .wifi, "Wi-Fi template recognized")
        model.open(wifi)
        await pause(0.6)
        model.showWifiQRCode(of: wifi)
        check(model.qrSheet != nil, "Wi-Fi QR code")
        await snap("08-wifi-qr")
        model.qrSheet = nil
        model.vaultPath = []

        // Creation and edit
        model.newItem(.login)
        let generated = model.editor?.draft.login?.password ?? ""
        check(generated.count == 20, "new login with a generated password")
        if var draft = model.editor?.draft {
            draft.name = "Créé sur iPhone"
            draft.login?.username = "iphone@verrou.test"
            draft.login?.urls = ["https://exemple.fr"]
            model.editor = PhoneModel.Editor(itemID: nil, draft: draft)
            await snap("09-new-login")
            await model.saveEditor(draft)
        }
        // Written locally: the sheet closes right away, sending follows in the background.
        check(model.editor == nil, "sheet closed without waiting for the server")
        guard case .item(let opened)? = model.vaultPath.last, model.summary(id: opened)?.title == "Créé sur iPhone"
        else { return check(false, "item created, item page open") }
        check(await wait(20) { model.pendingChanges == 0 && model.syncState == .idle }, "item sent to the server")
        guard let created = id(of: "Créé sur iPhone") else { return check(false, "item created on the server") }
        check(model.vaultPath.last == .item(created), "the item page follows the server ID")
        await pause(1.2)
        await model.edit(created)
        check(model.editor?.draft.login?.password == generated, "draft prefilled, secrets included")
        if var draft = model.editor?.draft {
            draft.name = "Modifié sur iPhone"
            draft.login?.password = "nouveau-mot-de-passe"
            draft.fields.append(CustomField(name: "PIN", value: "2468", fieldType: .hidden, linkedId: nil))
            model.editor = PhoneModel.Editor(itemID: created, draft: draft)
            await snap("10-edit")
            await model.saveEditor(draft)
        }
        model.toggleReveal("password", of: created)
        check(model.revealedValue("password", of: created) == "nouveau-mot-de-passe"
              && model.summary(id: created)?.title == "Modifié sur iPhone", "edit saved")
        check(model.detail(id: created)?.fields.contains { $0.label == "PIN" } == true, "custom field added")
        model.vaultPath = []
        await pause(1.2)

        // Two-factor authentication QR codes (photo, preview, saving)
        await scanQRCodes()

        // Card created on the iPhone
        model.newItem(.card)
        if var draft = model.editor?.draft {
            draft.name = "Carte du test"
            draft.card?.cardholderName = "CAMILLE MARTIN"
            draft.card?.number = "5555555555554444"
            draft.card?.brand = "Mastercard"
            draft.card?.expMonth = "4"
            draft.card?.expYear = "2030"
            draft.card?.code = "321"
            model.editor = PhoneModel.Editor(itemID: nil, draft: draft)
            await snap("11-new-card")
            await model.saveEditor(draft)
        }
        guard let card = id(of: "Carte du test") else { return check(false, "card created") }
        check(model.summary(id: card)?.category == .card, "created as a card")
        model.toggleReveal("number", of: card)
        check(model.revealedValue("number", of: card)?.filter(\.isNumber) == "5555555555554444", "card number saved")
        model.vaultPath = []
        await pause(1.2)

        // Bulk actions: favorites then archive (server IDs, once the card is
        // sent)
        _ = await wait(20) { model.pendingChanges == 0 && model.syncState == .idle }
        let pair = ["Modifié sur iPhone", "Carte du test"].compactMap { id(of: $0) }
        check(pair.count == 2, "created items found again")
        await model.performBulk(.favorite(favorite: true), on: pair)
        check(pair.allSatisfy { model.summary(id: $0)?.favorite == true },
              "two items added to favorites (\(model.toast?.message ?? "") \(model.toast?.detail ?? ""))")
        model.vaultPath = [.list(.favorites)]
        await snap("12-favorites")
        await pause(1.2)
        await model.performBulk(.archive, on: pair)
        check(pair.allSatisfy { model.summary(id: $0)?.state == .archived }, "two items archived")
        model.vaultPath = []

        // Offline: the change waits, then goes when the network comes back
        log("E2E_NET off")
        await pause(1.5)
        check(await wait(30) {
            if model.syncState != .offline, model.syncState != .syncing { Task { await model.syncNow() } }
            return model.syncState == .offline
        }, "server unreachable: offline")
        await model.setFavorite(github, false)
        check(model.pendingChanges > 0 && model.summary(id: github)?.pendingSync == true,
              "offline change pending (\(model.pendingChanges))")
        model.open(github)
        await snap("13-offline")
        model.vaultPath = []
        log("E2E_NET on")
        await pause(1.5)
        check(await wait(40) {
            if model.syncState != .syncing, model.pendingChanges > 0 { Task { await model.syncNow() } }
            return model.pendingChanges == 0 && model.syncState == .idle
        }, "offline change synced")
        check(model.summary(id: github)?.favorite == false && model.summary(id: github)?.pendingSync == false,
              "server state after sync")

        // Audit, generator, settings
        model.openAudit()
        check((model.audit?.checked ?? 0) >= 4, "vault audit (\(model.audit?.checked ?? 0) passwords)")
        await snap("14-audit")
        // "Passkey possible": passkeys.2fa.directory downloaded whole by the
        // Rust core; Amazon (amazon.fr) is in it.
        check(await wait(30) { model.passkeyAudit.report != nil || model.passkeyAudit.error != nil },
              "passkey directory loaded (\(model.passkeyAudit.error ?? "ok"))")
        let candidates = model.passkeyAudit.report?.candidates ?? []
        check(candidates.contains { $0.item.title == "Amazon" && $0.domain == "amazon.fr" && $0.passwordless },
              "“Passkey possible”: Amazon (\(candidates.map(\.item.title).joined(separator: ", ")))")
        check(!candidates.contains { $0.item.title == "Netflix" }, "“Passkey possible”: Netflix not in the directory")
        model.passkeyAudit.focus = true
        await pause(0.8)
        await snap("14b-audit-passkeys")
        model.passkeyAudit.focus = false
        model.vaultPath = []
        model.tab = .generator
        await snap("15-generator")
        model.tab = .settings
        await snap("16-settings")
        model.tab = .vault

        // Passkeys, sorting, match rules
        await vaultTweaks(github: github)

        // Shared vaults, owner side
        let shared = await sharingAsOwner()

        // Locking, password, Face ID
        // A secret copied right before: locking erases it.
        model.copyPassword(of: github)
        check(UIPasteboard.general.string == "hunter2-hunter2", "secret copied before locking")
        model.lock()
        check(model.lockState == .locked && !model.needsLogin && model.summaries.isEmpty, "locked, vault erased")
        check(UIPasteboard.general.string != "hunter2-hunter2", "clipboard erased on lock")
        await snap("17-locked")
        await model.unlock(masterPassword: "wrong")
        check(model.unlockError == String(localized: "Incorrect master password."), "wrong password on unlock")
        await model.unlock(masterPassword: config.password)
        check(model.lockState == .unlocked && model.counts?.all == 9, "unlock with password")
        if model.biometricEnrolled {
            model.lock()
            let unlocking = Task { await model.unlockWithBiometrics() }
            await pause(1.5)
            log("E2E_FACEID")
            await unlocking.value
            check(model.lockState == .unlocked, "unlock with Face ID (sealed key)")
        }

        // Auto-lock: immediate in the background
        let previous = model.autoLockSeconds
        model.autoLockSeconds = 0
        model.scenePhaseChanged(to: .background)
        check(model.lockState == .locked, "locked when going to the background")
        model.autoLockSeconds = previous

        model.logout()
        check(model.needsLogin && !model.biometricEnrolled && model.account == nil, "sign-out")
        check(!FileManager.default.fileExists(atPath: model.vault.directory.appending(path: "account.json").path),
              "account files erased")
        await snap("18-signed-out")

        // The invited member, then the confirmation, then their permissions
        if let shared, let member = config.member {
            await sharingWithMember(shared, member: member)
        }
    }

    // MARK: QR codes

    /// Seeds of the `scripts/ios-e2e.sh` images (`VERROU_E2E_QR_DIR`).
    static let qrNewSecret = "KRUGKIDROVUWG2ZAMJZG653OEBTG66BA"
    static let qrAmazonSecret = "MFWWC6TPNYQGG33EMUQGC5DUMFRWQZLE"

    /// The "photo or screenshot" path of the "Scan a QR code" sheet: the same
    /// reading as the Photos picker (Vision), on the images the script also
    /// added to the simulator's photo library (`simctl addmedia`). The
    /// simulator has no camera.
    private func scanQRCodes() async {
        guard let dir = ProcessInfo.processInfo.environment["VERROU_E2E_QR_DIR"] else {
            return log("E2E_OK QR codes: no images, step skipped")
        }
        func image(_ name: String) -> Data {
            (try? Data(contentsOf: URL(fileURLWithPath: dir).appending(path: name))) ?? Data()
        }
        func sameCode(_ itemID: String, secret: String) -> Bool {
            let now = Date()
            return model.totpCode(of: itemID, at: now)?.code == Self.totp(secret, at: now.timeIntervalSince1970)
        }
        func appearance(_ mode: String) async {
            log("E2E_APPEARANCE \(mode)")
            await pause(1.5)
        }
        model.vaultPath = []
        model.tab = .vault

        // 1. New login, "Scan a QR code" button
        model.newItem(.login)
        await pause(1.2)
        model.startOTPScan(.editor(isNew: true))
        guard let flow = model.otpScan else { return check(false, "“Scan a QR code” sheet open") }
        check(await wait(5) { flow.camera != .checking }, "camera examined (\(flow.camera))")
        check(flow.camera == .unavailable, "simulator: camera unavailable, photo offered")
        await snap("40-qr-sources")
        await appearance("dark")
        await snap("40b-qr-sources-dark")
        flow.camera = .denied
        await snap("41b-qr-camera-denied-dark")
        await appearance("light")
        await snap("41-qr-camera-denied")
        flow.camera = .unavailable
        await flow.handle(imageData: image("qr-wifi.png"), session: model.session)
        // The core's message, translated by the app in French.
        let notOtp = ["does not contain a one-time code", "pas de code à usage unique"]
        check(flow.result == nil && notOtp.contains { flow.error?.contains($0) == true },
              "Wi-Fi QR code refused (\(flow.error ?? "no error"))")
        await flow.handle(imageData: image("qr-nouveau.png"), session: model.session)
        guard let account = flow.result?.accounts.first else {
            return check(false, "QR code read in the screenshot (\(flow.error ?? "nothing"))")
        }
        check(account.issuer == "Exemple Cloud" && account.account == "camille@exemple.fr",
              "service and account read (\(account.issuer ?? "-") / \(account.account ?? "-"))")
        let t = Date().timeIntervalSince1970
        check((try? totpPreview(value: account.uri, unixTime: UInt64(t)))?.code == Self.totp(Self.qrNewSecret, at: t),
              "first code correct")
        check(account.matches.isEmpty, "no existing login for this service")
        await snap("42-qr-preview")
        await appearance("dark")
        await snap("42b-qr-preview-dark")
        await appearance("light")
        _ = await flow.apply([(account, .form)], model: model)
        check(model.otpScan == nil, "sheet closed")
        check(await wait(3) { model.otpFormFill == nil }, "form filled")
        // No keyboard in the screenshot: the whole form.
        UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil)
        await snap("43-qr-form")
        model.e2eSaveEditor += 1
        check(await wait(10) { model.editor == nil }, "login created with its code")
        guard let created = id(of: "Exemple Cloud") else { return check(false, "“Exemple Cloud” in the vault") }
        check(model.summary(id: created)?.hasTotp == true && sameCode(created, secret: Self.qrNewSecret),
              "the code appears on the item page")
        check(UIPasteboard.general.string?.contains(Self.qrNewSecret) != true, "seed never copied")
        await snap("44-qr-item")
        model.vaultPath = []
        await pause(1.0)

        // 2. The QR code of a service already in the vault, without a code: "Add to Amazon"
        guard let amazon = id(of: "Amazon") else { return check(false, "Amazon present") }
        check(model.summary(id: amazon)?.hasTotp == false, "Amazon without a code")
        model.newItem(.login)
        await pause(1.2)
        model.startOTPScan(.editor(isNew: true))
        guard let matching = model.otpScan else { return check(false, "sheet open (existing login)") }
        await matching.handle(imageData: image("qr-amazon.png"), session: model.session)
        check(matching.result?.accounts.first?.matches.first?.id == amazon, "“Add to Amazon” offered")
        await snap("45-qr-add-to-existing")
        model.otpScan = nil
        await pause(0.8)
        model.editor = nil
        await pause(1.0)

        // 3. Item page without a code: "Add a code (QR)"
        model.open(amazon)
        await pause(1.0)
        model.startOTPScan(.item(id: amazon, title: "Amazon"))
        guard let itemFlow = model.otpScan else { return check(false, "sheet open from the item page") }
        await itemFlow.handle(imageData: image("qr-amazon.png"), session: model.session)
        check(itemFlow.result?.accounts.first?.matches.first?.id == amazon, "Amazon QR code attached to the item page")
        await snap("46-qr-add-to")
        _ = await itemFlow.apply(itemFlow.plan, model: model)
        check(await wait(10) { model.summary(id: amazon)?.hasTotp == true } && sameCode(amazon, secret: Self.qrAmazonSecret),
              "code added to Amazon (\(itemFlow.error ?? "ok"))")
        await snap("47-qr-amazon-item")
        model.vaultPath = []
        await pause(1.0)

        // 4. Google Authenticator export (several accounts), from a new login
        model.newItem(.login)
        await pause(1.2)
        model.startOTPScan(.editor(isNew: true))
        guard let export = model.otpScan else { return check(false, "sheet open for the export") }
        await export.handle(imageData: image("qr-export.png"), session: model.session)
        guard let result = export.result else { return check(false, "export read (\(export.error ?? "nothing"))") }
        check(result.accounts.count == 2 && result.skipped == 1 && result.batchCount == 2,
              "export: 2 TOTP accounts, 1 HOTP set aside, batch 1 of 2")
        await snap("48-qr-export")
        await appearance("dark")
        await snap("48b-qr-export-dark")
        await appearance("light")
        let plan = export.plan.map { ($0.0, OTPScanFlow.Destination.newLogin) }
        _ = await export.apply(plan, model: model)
        check(model.otpScan == nil && model.editor == nil, "accounts imported, creation screen closed")
        guard let rfc = id(of: "RFC 6238"), let team = id(of: "Équipe") else {
            return check(false, "two logins created")
        }
        check(model.totpCode(of: rfc)?.code.count == 8 && model.totpCode(of: team)?.code.count == 6,
              "export codes (8 and 6 digits)")
        model.vaultPath = []
        await pause(1.0)

        // The rest of the run counts the active items: back to the trash.
        for itemID in [created, rfc, team] {
            await model.trash(itemID)
        }
        _ = await wait(20) { model.pendingChanges == 0 && model.syncState == .idle }
    }

    // MARK: Passkeys, sorting, matching

    /// A passkey created as if by AutoFill (on Amazon), the "Passkeys"
    /// filter and the `passkey:` keyword, sorting by creation and by last
    /// use (kept on the iPhone), a per-site rule followed by AutoFill, the
    /// iPhone's rule and a folder's.
    private func vaultTweaks(github: String) async {
        guard let amazon = id(of: "Amazon"), let netflix = id(of: "Netflix") else {
            return check(false, "Amazon and Netflix present")
        }
        let registered = try? await model.session.passkeyRegistration(request: PasskeyCreationRequest(
            rpId: "amazon.fr", userName: "camille@exemple.fr", userHandle: Data((0..<16).map { _ in UInt8.random(in: 0...255) }),
            clientDataHash: Data(repeating: 7, count: 32), userVerified: true, itemId: amazon, excludedCredentials: []))
        check(registered != nil, "passkey created on Amazon")
        model.afterWrite()
        check(model.counts?.passkeys == 1, "1 login with a passkey (\(model.counts?.passkeys ?? 0))")
        check(model.rows(query: "", filter: .passkeys).map(\.summary.title) == ["Amazon"], "“Passkeys” filter")
        check(model.rows(query: "passkey:", filter: .all).map(\.summary.title) == ["Amazon"]
              && model.rows(query: "has:passkey", filter: .all).count == 1
              && model.rows(query: "passkey:amaz", filter: .all).count == 1
              && model.rows(query: "passkey:netflix", filter: .all).isEmpty, "passkey: and has:passkey keywords")
        let summary = model.summary(id: amazon)
        check(summary?.passkeyRpId == "amazon.fr" && summary?.passkeyUserName == "camille@exemple.fr",
              "passkey site and user on the row")
        model.vaultPath = []
        await snap("37-home-passkeys")
        model.vaultPath = [.list(.passkeys)]
        await snap("38-passkeys")

        // Sorting: creation, then last use (copy, secret shown)
        let dates = model.rows(query: "", filter: .all, order: .created).map(\.summary.created)
        check(dates.count == 9 && dates == dates.sorted(by: >), "sort by creation, newest to oldest")
        model.copyUsername(of: amazon)
        await pause(1.2)
        model.copyPassword(of: netflix)
        model.afterWrite()
        model.sortOrder = .lastUsed
        check(DevicePreferences.sort == .lastUsed, "sort kept on the iPhone")
        let used = model.rows(query: "", filter: .all, order: model.sortOrder).map(\.summary.title)
        check(Array(used.prefix(2)) == ["Netflix", "Amazon"], "sort by last use (\(used.prefix(3)))")
        check(model.summary(id: netflix)?.lastUsed != nil, "last use date known")
        model.vaultPath = [.list(.all)]
        await snap("39-sort-last-used")
        model.vaultPath = []
        model.sortOrder = .relevance

        // Per-site rule: host for github.com, never for an old address
        let services = { (host: String) in
            ((try? self.model.session.autofillMatches(services: [host])) ?? []).map(\.title)
        }
        check(services("gist.github.com").contains("GitHub"), "base domain: subdomain offered")
        await model.edit(github)
        if var draft = model.editor?.draft {
            draft.login?.setMatchRule(.host, at: 0)
            draft.login?.appendURL("https://old-github.example")
            let last = (draft.login?.urls.count ?? 1) - 1
            draft.login?.setMatchRule(.never, at: last)
            model.editor = PhoneModel.Editor(itemID: github, draft: draft)
            await snap("40-matching")
            await model.saveEditor(draft)
        }
        check(await wait(20) { model.pendingChanges == 0 && model.syncState == .idle }, "rules sent to the server")
        check(model.detail(id: github)?.urlMatches == [.host, .never], "rules read back (\(model.detail(id: github)?.urlMatches ?? []))")
        check(!services("gist.github.com").contains("GitHub") && services("github.com").contains("GitHub"),
              "AutoFill: “host” rule followed")
        check(!services("old-github.example").contains("GitHub"), "AutoFill: “never” rule followed")
        // The iPhone's rule, then the "Personnel" folder's (Amazon)
        check(services("amazon.fr").contains("Amazon"), "Amazon offered on amazon.fr (domain)")
        model.setDefaultMatchRule(.host)
        check(!services("amazon.fr").contains("Amazon"), "iPhone “host” rule: www.amazon.fr only")
        if let personnel = model.folders.first(where: { $0.name == "Personnel" }) {
            model.setFolderMatchRule(personnel.id, .domain)
            check(services("amazon.fr").contains("Amazon"), "Personnel folder rule: base domain")
            model.tab = .settings
            model.settingsPath = [.filling]
            await snap("41-filling-settings")
            model.settingsPath = []
            model.tab = .vault
            model.setFolderMatchRule(personnel.id, nil)
        } else {
            check(false, "Personnel folder present")
        }
        model.setDefaultMatchRule(.domain)
        check(model.matchSettings?.defaultRule == .domain && model.matchSettings?.folderRules.isEmpty == true,
              "iPhone rules reset to default")
        check((model.matchSettings?.equivalentDomains.count ?? 0) > 10, "account's equivalent domains read")
    }

    /// "Remove from sharing" on the item shared above: confirmation, then a
    /// personal copy (password, PIN field, archive) and the organization's
    /// item deleted.
    private func unshare() async {
        guard let shared = model.summaries.first(where: { $0.title == "Modifié sur iPhone" && $0.sharing != nil }) else {
            return check(false, "shared item to remove from sharing")
        }
        let before = model.counts
        model.vaultPath = [.item(shared.id)]
        await pause(0.8)
        model.requestUnshare([shared.id])
        check(model.unshareRequest?.itemIDs == [shared.id], "removal confirmation requested")
        await snap("22b-remove-from-sharing")
        guard let request = model.unshareRequest else { return }
        await model.performUnshare(request)
        check(model.summary(id: shared.id) == nil, "organization's item deleted (\(model.toast?.message ?? ""))")
        guard let personal = model.summaries.first(where: { $0.title == "Modifié sur iPhone" }) else {
            return check(false, "personal copy present")
        }
        check(personal.sharing == nil && personal.state == shared.state, "personal copy, archived like the original")
        check(model.vaultPath.last == .item(personal.id), "the item page follows the copy")
        model.toggleReveal("password", of: personal.id)
        check(model.revealedValue("password", of: personal.id) == "nouveau-mot-de-passe", "password kept")
        check(model.detail(id: personal.id)?.fields.contains { $0.label == "PIN" } == true, "custom field kept")
        check(model.counts?.all == before?.all && model.counts?.archived == before?.archived, "counts unchanged")
        await snap("22c-removed-from-sharing")
        model.vaultPath = []
    }

    // MARK: Sharing

    struct SharedFixture {
        let organizationID: String
        let communs: String
        let banque: String
        let memberID: String?
    }

    /// Signs in (TOTP second factor included) with this account.
    private func signIn(_ email: String, _ password: String, totp: String, step: String) async {
        model.loginServer = config.server
        model.loginEmail = email
        await model.signIn(password: password)
        let now = Date().timeIntervalSince1970
        for offset in [0.0, 30.0, 60.0] where model.lockState != .unlocked {
            await model.answerTwoFactor(.authenticator, token: Self.totp(totp, at: now + offset))
        }
        check(model.lockState == .unlocked, step)
        _ = await wait(30) { model.syncState != .syncing }
    }

    /// The owner creates the organization and its collections, shares
    /// (several items, then one), changes collections, invites the member;
    /// the last owner cannot leave.
    private func sharingAsOwner() async -> SharedFixture? {
        check(await model.createOrganization(name: "Famille iPhone", collection: "Comptes communs"),
              "organization created on the iPhone (\(model.sharing.error ?? "ok"))")
        guard let org = model.organizations.first(where: { $0.name == "Famille iPhone" }),
              let communs = org.collections.first?.id else {
            check(false, "organization and collection read after creation")
            return nil
        }
        check(org.isOwner && org.canCreateCollections && org.canRename, "owner, with all permissions")
        model.tab = .vault
        model.vaultPath = [.organization(org.id)]
        await snap("19-organization")

        // New collection: the sheet reads the organization's members
        model.openCollectionEditor(org, collection: nil)
        guard case .collection(let opened) = model.sharing.sheet else {
            check(false, "collection editor open")
            return nil
        }
        var draft = await model.session.loadCollectionDraft(opened, organization: org, accountEmail: model.account?.email)
        check(!draft.loading && draft.accessUnavailable == nil && !draft.members.isEmpty,
              "organization members read for the collection (\(draft.accessUnavailable ?? "ok"))")
        draft.name = "Banque iPhone"
        // Reopened with the read draft and the typed name.
        model.sharing.sheet = nil
        await pause(1.5)
        model.sharing.sheet = .collection(draft)
        await snap("20-new-collection")
        model.sharing.sheet = nil
        await pause(0.6)
        check(await model.saveCollection(draft), "collection created (\(model.sharing.error ?? "ok"))")
        guard let banque = model.organization(org.id)?.collections.first(where: { $0.name == "Banque iPhone" })?.id else {
            check(false, "collection name encrypted then read back")
            return nil
        }
        check(model.organization(org.id)?.collections.first { $0.id == banque }?.canManage == true,
              "collection managed by the owner")

        // Bulk share: the two items created above
        let pair = ["Modifié sur iPhone", "Carte du test"].compactMap { id(of: $0) }
        model.vaultPath = [.list(.archived)]
        model.openSharing(items: pair)
        guard let flow = model.sharing.shareFlow, flow.isBulk else {
            check(false, "“Share” sheet for two items")
            return nil
        }
        flow.collectionIDs = [communs]
        await snap("21-share-several")
        check(await model.applySharing(flow), "two items shared (\(flow.error ?? "ok"))")
        check(pair.allSatisfy { model.summary(id: $0)?.sharing?.organizationId == org.id },
              "re-encrypted for the organization (\(model.toast?.message ?? ""))")
        await pause(1.0)

        // A single item, in the bank collection only
        if let netflix = id(of: "Netflix") {
            model.openSharing(netflix)
            if let single = model.sharing.shareFlow {
                single.collectionIDs = [banque]
                check(await model.applySharing(single), "Netflix shared in “Banque iPhone” (\(single.error ?? "ok"))")
            }
        }
        // Change the collections of a shared item
        if let card = id(of: "Carte du test") {
            model.openSharing(card)
            if let collections = model.sharing.shareFlow, collections.current != nil {
                collections.collectionIDs = [communs, banque]
                await snap("22-collections")
                check(await model.applySharing(collections), "card collections changed")
                check(model.summary(id: card)?.sharing?.collectionIds.count == 2, "card in two collections")
            }
        }
        await unshare()
        model.vaultPath = [.organization(org.id)]
        await pause(1.0)

        // Invite the member (without email, the server accepts automatically)
        var memberID: String?
        if let member = config.member {
            model.vaultPath = [.organization(org.id), .members(org.id)]
            await model.loadMembers(org.id)
            let invite = MemberDraft(member: nil, emails: member.email, role: .user,
                                     access: [communs: .edit, banque: .edit])
            model.sharing.sheet = .member(invite, organizationID: org.id)
            await snap("23-invite")
            model.sharing.sheet = nil
            await pause(0.6)
            check(await model.saveMember(invite, in: org.id), "member invited (\(model.sharing.error ?? "ok"))")
            let invited = model.sharing.members[org.id]?.first { $0.email == member.email }
            check(invited?.status == .accepted, "invitation accepted automatically: to confirm")
            memberID = invited?.id
            check(!ActivityNotifier.shared.posted.contains { $0.key.hasPrefix("confirm-") },
                  "no notification for the member just invited")
            // An address without an account: invitation sent, "What's next?".
            let stranger = "nouvelle-\(Int(Date().timeIntervalSince1970))@verrou.test"
            check(await model.saveMember(MemberDraft(member: nil, emails: stranger, role: .user, access: [communs: .view]),
                                         in: org.id),
                  "address without an account invited (\(model.sharing.error ?? "ok"))")
            check(model.sharing.members[org.id]?.first { $0.email == stranger }?.status == .invited,
                  "pending invitation: the person has no account")
            await snap("24-members")
            await model.refreshSharingStatus()
            check(model.sharing.totalToConfirm == 1, "“1 member to confirm”")
            model.vaultPath = []
            await snap("25-members-to-confirm")
            // A collection's editor opened as if by a tap: it reads members
            // and permissions itself (screenshot checked by eye).
            if let banqueView = model.organization(org.id)?.collections.first(where: { $0.id == banque }) {
                model.vaultPath = [.organization(org.id)]
                model.openCollectionEditor(model.organization(org.id) ?? org, collection: banqueView)
                await pause(3)
                await snap("25b-collection-open")
                model.sharing.sheet = nil
                await pause(0.8)
                model.vaultPath = []
            }
        }

        // My fingerprint phrase, the "Join" screen, rename, leave
        model.sharing.sheet = .fingerprint(nil)
        await snap("26-fingerprint")
        // At the largest text sizes: the phrase stays whole.
        log("E2E_TEXT accessibility-extra-extra-extra-large")
        await pause(2)
        await snap("26b-fingerprint-large-text")
        log("E2E_TEXT large")
        await pause(1.5)
        model.sharing.sheet = nil
        await pause(0.6)
        let link = "\(config.server)/#/accept-organization/?email=\(config.email.replacingOccurrences(of: "@", with: "%40"))"
            + "&organizationName=Club%20d%27escalade&organizationId=8e2d4f1a-0000-4000-8000-000000000001"
            + "&organizationUserId=8e2d4f1a-0000-4000-8000-000000000002&token=eyJ0eXAiOiJKV1QifQ.e30.c2ln"
        check((try? model.session.invitationInfo(link: link))?.forThisAccount == true, "invitation link read")
        model.sharing.sheet = .join(link)
        await snap("27-join")
        model.sharing.sheet = nil
        await pause(0.6)
        // Nothing pasted: where to find the email's link.
        model.sharing.sheet = .join("")
        await snap("27b-join-empty")
        model.sharing.sheet = nil
        await pause(0.6)
        check(await model.renameOrganization(org, to: "Famille Martin"), "organization renamed")
        check(model.organization(org.id)?.name == "Famille Martin", "new name read back")
        await model.leaveOrganization(model.organization(org.id) ?? org)
        check(model.organization(org.id) != nil && model.toast?.failure == true, "the last owner doesn't leave")

        // Text Send (Bitwarden Send): created, link copied, listed, deleted
        model.vaultPath = [.sends]
        await model.reloadSends()
        var fields = model.session.newSendFields()
        fields.name = "Code du portail"
        fields.text = "4589B"
        let composer = SendComposer(fields: fields, file: nil)
        model.sharing.sendComposer = composer
        await snap("34-new-send")
        check(await model.createSend(composer), "Send created (\(model.sharing.error ?? "ok"))")
        check(UIPasteboard.general.string?.contains("/#/send/") == true, "Send link copied")
        await snap("35-send-created")
        model.sharing.sendComposer = nil
        await pause(0.8)
        check(model.sharing.sends?.contains { $0.name == "Code du portail" } == true, "Send listed")
        await snap("36-sends")
        if let send = model.sharing.sends?.first(where: { $0.name == "Code du portail" }) {
            await model.deleteSend(send)
            check(model.sharing.sends?.contains { $0.id == send.id } == false, "Send deleted")
        }
        model.vaultPath = []
        return SharedFixture(organizationID: org.id, communs: communs, banque: banque, memberID: memberID)
    }

    /// The member waits for their confirmation, the owner gives it after
    /// comparing the fingerprint, then they read what is shared with them,
    /// with their permissions.
    private func sharingWithMember(_ shared: SharedFixture, member: (email: String, password: String, totp: String)) async {
        await signIn(member.email, member.password, totp: member.totp, step: "member signed in")
        await model.refreshSharingStatus()
        guard let pending = model.sharing.pending.first(where: { $0.organizationId == shared.organizationID }) else {
            return check(false, "invitation awaiting confirmation visible")
        }
        check(model.organization(shared.organizationID) == nil, "no key before the confirmation")
        await snap("28-pending-invitation")
        model.sharing.sheet = .fingerprint(pending)
        await snap("29-member-fingerprint")
        model.sharing.sheet = nil
        let memberFingerprint = (try? await model.session.ownFingerprint()) ?? ""
        await pause(0.6)
        model.logout()

        await signIn(config.email, config.password, totp: config.totpSecret, step: "owner signed in again")
        await model.loadMembers(shared.organizationID)
        guard let accepted = model.sharing.members[shared.organizationID]?.first(where: { $0.email == member.email })
        else { return check(false, "member listed") }
        model.vaultPath = [.organization(shared.organizationID), .members(shared.organizationID)]
        await model.prepareConfirmation(accepted, in: shared.organizationID)
        check(model.sharing.confirmation?.fingerprint == memberFingerprint, "same fingerprint on both sides")
        await snap("30-verify-fingerprint")
        if let confirmation = model.sharing.confirmation {
            await model.confirmMember(confirmation)
        }
        check(model.sharing.members[shared.organizationID]?.first { $0.email == member.email }?.status == .confirmed,
              "member confirmed")
        // "Banque iPhone": read-only, passwords hidden for them
        if let org = model.organization(shared.organizationID),
           let banque = org.collections.first(where: { $0.id == shared.banque }) {
            var draft = await model.session.loadCollectionDraft(
                CollectionDraft(organizationID: org.id, collectionID: banque.id, name: banque.name),
                organization: org, accountEmail: model.account?.email)
            check(draft.accessUnavailable == nil && draft.members.contains { $0.id == accepted.id }
                  && draft.memberAccess[accepted.id] == .edit,
                  "collection access read: the member and their permission (\(draft.accessUnavailable ?? "ok"))")
            do {
                draft.memberAccess[accepted.id] = .viewExceptPasswords
                model.sharing.sheet = nil
                await pause(1.5)
                model.sharing.sheet = .collection(draft)
                await snap("31-collection-access")
                model.sharing.sheet = nil
                await pause(0.6)
                check(await model.saveCollection(draft), "collection permissions saved")
            }
            let access = try? await model.session.collectionAccess(organizationId: org.id, collectionId: banque.id)
            check(access?.members.contains { $0.id == accepted.id && $0.readOnly && $0.hidePasswords } == true,
                  "read-only and passwords hidden read back")
        }
        model.vaultPath = []
        model.logout()

        await signIn(member.email, member.password, totp: member.totp, step: "member signed in again")
        guard let org = model.organization(shared.organizationID) else {
            return check(false, "organization decrypted by the member")
        }
        check(!org.canRename && !org.canCreateCollections && !org.collections.contains(where: \.canManage),
              "member without management permissions")
        guard let netflix = model.summaries.first(where: { $0.title == "Netflix" && $0.sharing != nil }) else {
            return check(false, "shared item readable by the member")
        }
        check(netflix.sharing?.readOnly == true && netflix.sharing?.hidePasswords == true && !model.canModify(netflix),
              "read-only, passwords hidden")
        model.open(netflix.id)
        model.toggleReveal("password", of: netflix.id)
        check(model.revealedValue("password", of: netflix.id) == nil, "password hidden by the organization")
        await snap("32-read-only")
        model.vaultPath = [.organization(org.id)]
        await snap("33-member-organization")
        model.vaultPath = []
        if let card = model.summaries.first(where: { $0.title == "Carte du test" }) {
            check(model.canModify(card), "item of an editable collection: editable")
        }
        await notifications(shared)
        model.logout()
        check(model.needsLogin, "member signed out")
    }

    // MARK: Sharing notifications

    /// The member has the app open; the owner acts from another session (in
    /// this process, throwaway folder): shared item (live channel), access
    /// revoked then given back, then an item that arrived in the cache while
    /// the vault is locked (background task). The notifications are read in
    /// the test hook (`posted`), not on screen.
    private func notifications(_ shared: SharedFixture) async {
        let org = shared.organizationID
        let posted = { (prefix: String) in ActivityNotifier.shared.posted.filter { $0.key == prefix } }
        check(await wait(20) { model.live.connected }, "updates channel open")

        let directory = FileManager.default.temporaryDirectory.appending(path: "verrou-e2e-owner-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: directory) }
        guard let accounts = try? Accounts.open(root: directory.path),
              let ownerTag = try? accounts.primaryTag(),
              let owner = try? accounts.session(tag: ownerTag) else {
            return check(false, "owner's account folder")
        }
        var result = try? await owner.login(server: config.server, email: config.email, password: config.password)
        let now = Date().timeIntervalSince1970
        for offset in [0.0, 30.0, 60.0] {
            guard case .twoFactorRequired = result else { break }
            result = try? await owner.answerTwoFactor(option: .authenticator,
                                                      token: Self.totp(config.totpSecret, at: now + offset))
        }
        guard case .unlocked = result else { return check(false, "owner's second session") }
        _ = try? await owner.sync()
        let draft = { (name: String) in
            ItemDraft(name: name, folderId: nil, favorite: false, notes: nil,
                      login: LoginFields(username: "famille@exemple.fr", password: "secret-partage-direct",
                                         totp: nil, urls: []),
                      fields: [], template: nil)
        }

        // A shared item: live, within a few seconds.
        let before = posted("items-\(org)").count
        check((try? await owner.createSharedItem(draft: draft("Partagé en direct"), organizationId: org,
                                                  collectionIds: [shared.communs])) != nil,
              "item shared by the owner")
        check(await wait(20) { posted("items-\(org)").count > before }, "“new item” notification, live")
        if let notice = posted("items-\(org)").last {
            log("E2E_NOTIFY \(notice.title) | \(notice.body)")
            check(notice.body == String(localized: "1 new item in \(String(localized: "“\("Famille Martin")”"))."), "text: organization and number")
            check(!notice.body.contains("secret") && !notice.body.contains("famille@") && !notice.body.contains("Partagé"),
                  "neither secret, nor login, nor title")
        }
        check(await wait(10) { model.summaries.contains { $0.title == "Partagé en direct" } },
              "item readable without touching anything")

        // Access revoked then given back: "You now have access to …".
        if let memberID = shared.memberID {
            check((try? await owner.revokeOrganizationMember(organizationId: org, memberId: memberID)) != nil,
                  "access revoked")
            await model.syncNow()
            _ = await wait(10) { model.organization(org) == nil }
            await model.refreshSharingStatus()
            check((try? await owner.restoreOrganizationMember(organizationId: org, memberId: memberID)) != nil,
                  "access given back")
            await model.syncNow()
            await model.refreshSharingStatus()
            check(posted("confirmed-\(org)").last?.body == String(localized: "You now have access to \(String(localized: "“\("Famille Martin")”"))."),
                  "“access confirmed” notification")
        }

        // Vault locked: the background task only reads the cache.
        model.live.stop(session: model.session)
        let cached = posted("items-\(org)").count
        _ = try? await owner.createSharedItem(draft: draft("Partagé coffre fermé"), organizationId: org,
                                              collectionIds: [shared.communs])
        // The cache refreshed without a check (as by the extension).
        _ = try? await model.session.sync()
        model.lock()
        await model.backgroundActivityCheck()
        check(model.lockState == .locked, "the background task doesn't unlock")
        check(posted("items-\(org)").count == cached + 1, "notification from the cache, vault locked")
        await model.backgroundActivityCheck()
        check(posted("items-\(org)").count == cached + 1, "no repeat")
        owner.lock()
    }

    /// RFC 6238 (SHA-1, 6 digits, 30 s), to answer the second factor.
    static func totp(_ secret: String, at time: TimeInterval) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var bits = 0, value = 0
        var key = Data()
        for character in secret.uppercased() where character != "=" {
            guard let index = alphabet.firstIndex(of: character) else { continue }
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
#endif
