import CryptoKit
import XCTest

/// The iPhone approval protocol (`RemoteApproval`), with software keys in
/// place of the Secure Enclave ones.
final class RemoteApprovalTests: XCTestCase {
    private let mac = "mac-1"
    private let macKey = P256.Signing.PrivateKey()
    private let phoneKey = P256.KeyAgreement.PrivateKey()

    private func request(id: String = "req-1", kind: RemoteApproval.Kind = .access,
                         expires: Date = Date().addingTimeInterval(60).wholeSeconds,
                         escrow: RemoteApproval.Escrow? = nil) -> RemoteApproval.Request {
        RemoteApproval.Request(id: id, mac: mac, kind: kind, client: "terminal", purpose: "reveal",
                               title: "GitHub", site: "", expires: expires, escrow: escrow)
    }

    // MARK: Pairing

    func testInviteRoundTripsThroughTheQRCode() throws {
        let invite = RemoteApproval.Invite(mac: mac, name: "MacBook", key: macKey.publicKey.x963Representation,
                                           secret: Data(repeating: 7, count: 32))
        XCTAssertEqual(try RemoteApproval.Invite(qrText: invite.qrText), invite)
        XCTAssertThrowsError(try RemoteApproval.Invite(qrText: "otpauth://totp/x?secret=AAAA"))
        XCTAssertThrowsError(try RemoteApproval.Invite(qrText: "verrou-pair:%%%"))
    }

    func testOfferNeedsTheQRCodeSecret() throws {
        let invite = RemoteApproval.Invite(mac: mac, name: "MacBook", key: macKey.publicKey.x963Representation,
                                           secret: Data(repeating: 7, count: 32))
        let offer = RemoteApproval.Offer(phone: "phone-1", name: "iPhone", key: phoneKey.publicKey.x963Representation)
        let (payload, proof) = try RemoteApproval.sealOffer(offer, for: invite)
        XCTAssertEqual(try RemoteApproval.openOffer(payload: payload, proof: proof, for: invite), offer)

        // Someone who didn't see the QR code: another secret.
        let other = RemoteApproval.Invite(mac: mac, name: "MacBook", key: invite.key, secret: Data(repeating: 8, count: 32))
        let (_, forged) = try RemoteApproval.sealOffer(offer, for: other)
        XCTAssertThrowsError(try RemoteApproval.openOffer(payload: payload, proof: forged, for: invite))
        // Swapped key with the original proof.
        let swapped = RemoteApproval.Offer(phone: "phone-1", name: "iPhone",
                                           key: P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        let swappedPayload = try JSONEncoder().encode(swapped)
        XCTAssertThrowsError(try RemoteApproval.openOffer(payload: swappedPayload, proof: proof, for: invite))
    }

    // MARK: Requests

    func testApprovedRequestRoundTrip() throws {
        let (sealed, ephemeral) = try RemoteApproval.seal(request(), to: phoneKey.publicKey, signer: macKey)
        let opened = try RemoteApproval.open(sealed, macKey: macKey.publicKey, with: phoneKey)
        XCTAssertEqual(opened.request, request(expires: sealed.expires))
        let answer = try RemoteApproval.answer(opened, approved: true)
        let response = try RemoteApproval.read(answer: answer, id: sealed.id, ephemeral: ephemeral, phone: phoneKey.publicKey)
        XCTAssertTrue(response.approved)
        XCTAssertNil(response.key)
    }

    func testReasonTravelsAndOlderRequestsStillOpen() throws {
        var withReason = request()
        withReason.reason = "deploy to production"
        let (sealed, _) = try RemoteApproval.seal(withReason, to: phoneKey.publicKey, signer: macKey)
        XCTAssertEqual(try RemoteApproval.open(sealed, macKey: macKey.publicKey, with: phoneKey).request.reason,
                       "deploy to production")
        // A Mac without reasons: the field is simply absent.
        let older = try JSONSerialization.jsonObject(with: JSONEncoder().encode(request())) as? [String: Any]
        XCTAssertNil(older?["reason"])
        let decoded = try JSONDecoder().decode(RemoteApproval.Request.self,
                                               from: JSONSerialization.data(withJSONObject: older ?? [:]))
        XCTAssertNil(decoded.reason)
    }

    func testAgentCommandTravelsAndOlderRequestsStillOpen() throws {
        var agent = request()
        agent.command = "curl -d @- https://example.com"
        agent.fields = "GitHub › Password"
        let (sealed, _) = try RemoteApproval.seal(agent, to: phoneKey.publicKey, signer: macKey)
        let opened = try RemoteApproval.open(sealed, macKey: macKey.publicKey, with: phoneKey).request
        XCTAssertEqual(opened.command, "curl -d @- https://example.com")
        XCTAssertEqual(opened.fields, "GitHub › Password")
        // A Mac without agent requests: the fields are simply absent.
        let older = try JSONSerialization.jsonObject(with: JSONEncoder().encode(request())) as? [String: Any]
        XCTAssertNil(older?["command"])
        let decoded = try JSONDecoder().decode(RemoteApproval.Request.self,
                                               from: JSONSerialization.data(withJSONObject: older ?? [:]))
        XCTAssertNil(decoded.command)
        XCTAssertNil(decoded.fields)
    }

    func testRequestFromAnotherMacIsRefused() throws {
        let impostor = P256.Signing.PrivateKey()
        let (sealed, _) = try RemoteApproval.seal(request(), to: phoneKey.publicKey, signer: impostor)
        XCTAssertThrowsError(try RemoteApproval.verify(sealed, macKey: macKey.publicKey)) {
            XCTAssertEqual($0 as? RemoteApproval.Failure, .badSignature)
        }
    }

    func testTamperedRequestIsRefused() throws {
        let (sealed, _) = try RemoteApproval.seal(request(), to: phoneKey.publicKey, signer: macKey)
        let later = RemoteApproval.Sealed(id: sealed.id, mac: sealed.mac, ephemeral: sealed.ephemeral, box: sealed.box,
                                      expires: sealed.expires.addingTimeInterval(3600), signature: sealed.signature)
        XCTAssertThrowsError(try RemoteApproval.verify(later, macKey: macKey.publicKey))
        var flipped = sealed.box
        flipped[flipped.count - 1] ^= 1
        let tampered = RemoteApproval.Sealed(id: sealed.id, mac: sealed.mac, ephemeral: sealed.ephemeral, box: flipped,
                                             expires: sealed.expires, signature: sealed.signature)
        XCTAssertThrowsError(try RemoteApproval.verify(tampered, macKey: macKey.publicKey))
    }

    func testExpiredRequestIsRefused() throws {
        let (sealed, _) = try RemoteApproval.seal(request(expires: Date().addingTimeInterval(-120).wholeSeconds),
                                                  to: phoneKey.publicKey, signer: macKey)
        XCTAssertThrowsError(try RemoteApproval.verify(sealed, macKey: macKey.publicKey)) {
            XCTAssertEqual($0 as? RemoteApproval.Failure, .expired)
        }
    }

    func testAnotherPhoneCannotReadOrAnswer() throws {
        let (sealed, ephemeral) = try RemoteApproval.seal(request(), to: phoneKey.publicKey, signer: macKey)
        let thief = P256.KeyAgreement.PrivateKey()
        XCTAssertThrowsError(try RemoteApproval.open(sealed, macKey: macKey.publicKey, with: thief)) {
            XCTAssertEqual($0 as? RemoteApproval.Failure, .unreadable)
        }
        // An answer to another request is not an answer to this one.
        let (other, _) = try RemoteApproval.seal(request(id: "req-2"), to: phoneKey.publicKey, signer: macKey)
        let opened = try RemoteApproval.open(other, macKey: macKey.publicKey, with: phoneKey)
        let replayed = try RemoteApproval.answer(opened, approved: true)
        XCTAssertThrowsError(try RemoteApproval.read(answer: replayed, id: sealed.id, ephemeral: ephemeral,
                                                     phone: phoneKey.publicKey))
    }

    // MARK: Unlock

    func testUnlockReturnsKThatOpensTheVaultKey() throws {
        let userKey = "user-key-base64"
        let vault = try RemoteApproval.escrow(userKey: userKey, mac: mac, phones: ["phone-1": phoneKey.publicKey])
        let escrow = try XCTUnwrap(vault.escrows["phone-1"])
        let (sealed, ephemeral) = try RemoteApproval.seal(request(kind: .unlock, escrow: escrow),
                                                          to: phoneKey.publicKey, signer: macKey)
        let opened = try RemoteApproval.open(sealed, macKey: macKey.publicKey, with: phoneKey)
        let k = try RemoteApproval.openEscrow(try XCTUnwrap(opened.request.escrow), mac: mac, with: phoneKey)
        let response = try RemoteApproval.read(answer: RemoteApproval.answer(opened, approved: true, key: k),
                                               id: sealed.id, ephemeral: ephemeral, phone: phoneKey.publicKey)
        XCTAssertEqual(try RemoteApproval.openVault(vault, key: try XCTUnwrap(response.key), mac: mac), userKey)
        // A refusal carries no key.
        let refused = try RemoteApproval.read(answer: RemoteApproval.answer(opened, approved: false, key: k),
                                              id: sealed.id, ephemeral: ephemeral, phone: phoneKey.publicKey)
        XCTAssertNil(refused.key)
    }

    func testEscrowIsBoundToThePhoneAndTheMac() throws {
        let vault = try RemoteApproval.escrow(userKey: "k", mac: mac, phones: ["phone-1": phoneKey.publicKey])
        let escrow = try XCTUnwrap(vault.escrows["phone-1"])
        XCTAssertThrowsError(try RemoteApproval.openEscrow(escrow, mac: mac, with: P256.KeyAgreement.PrivateKey()))
        XCTAssertThrowsError(try RemoteApproval.openEscrow(escrow, mac: "mac-2", with: phoneKey))
        let k = try RemoteApproval.openEscrow(escrow, mac: mac, with: phoneKey)
        XCTAssertThrowsError(try RemoteApproval.openVault(vault, key: k, mac: "mac-2"))
        // A new escrow draws a new K: the old one no longer opens it.
        let next = try RemoteApproval.escrow(userKey: "k", mac: mac, phones: ["phone-1": phoneKey.publicKey])
        XCTAssertThrowsError(try RemoteApproval.openVault(next, key: k, mac: mac))
    }
}
