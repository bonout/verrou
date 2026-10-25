import Foundation
import XCTest

/// Codes computed without the Rust core (widgets, Apple Watch): RFC 6238
/// vectors, and the TOTP field read with the core's rules.
final class PinnedCodesTests: XCTestCase {
    /// RFC 6238, appendix B: the ASCII seeds of each algorithm, 8 digits.
    private func rfc(_ algorithm: PinnedCode.Algorithm) -> PinnedCode {
        let seed: String
        switch algorithm {
        case .sha1: seed = "12345678901234567890"
        case .sha256: seed = "12345678901234567890123456789012"
        case .sha512: seed = "1234567890123456789012345678901234567890123456789012345678901234"
        }
        return PinnedCode(id: "x", title: "x", host: nil, secret: Data(seed.utf8), algorithm: algorithm, digits: 8, period: 30)
    }

    private func code(_ pinned: PinnedCode, _ time: TimeInterval) -> String {
        pinned.code(at: Date(timeIntervalSince1970: time)).value
    }

    func testRFC6238Vectors() {
        let vectors: [(TimeInterval, String, String, String)] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ]
        for (time, sha1, sha256, sha512) in vectors {
            XCTAssertEqual(code(rfc(.sha1), time), sha1, "SHA-1 at \(time)")
            XCTAssertEqual(code(rfc(.sha256), time), sha256, "SHA-256 at \(time)")
            XCTAssertEqual(code(rfc(.sha512), time), sha512, "SHA-512 at \(time)")
        }
    }

    func testWindowFollowsThePeriod() {
        let pinned = PinnedCode(id: "x", title: "x", host: nil, totp: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        let code = pinned?.code(at: Date(timeIntervalSince1970: 89))
        XCTAssertEqual(code?.start, Date(timeIntervalSince1970: 60))
        XCTAssertEqual(code?.end, Date(timeIntervalSince1970: 90))
        XCTAssertEqual(code?.value.count, 6)
        XCTAssertEqual(PinnedCode.Code(value: "123456", start: .now, end: .now).grouped, "123 456")
    }

    func testSeedsAndLinksAsTheCoreReadsThem() throws {
        let bare = try XCTUnwrap(PinnedCode(id: "x", title: "x", host: nil, totp: "gezd gnbv gy3t qojq gezd gnbv gy3t qojq"))
        XCTAssertEqual(bare.secret, Data("12345678901234567890".utf8))
        XCTAssertEqual(bare.algorithm, .sha1)
        XCTAssertEqual(bare.digits, 6)
        XCTAssertEqual(bare.period, 30)
        // The core's own test vector (verrou_core::totp).
        let link = try XCTUnwrap(PinnedCode(
            id: "x", title: "x", host: nil,
            totp: "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=SHA256&digits=8"))
        XCTAssertEqual(code(link, 59), "46119246")
        let custom = try XCTUnwrap(PinnedCode(
            id: "x", title: "x", host: nil, totp: "OTPAUTH://TOTP/Site:me?secret=JBSWY3DPEHPK3PXP&period=60&algorithm=sha512&digits=7"))
        XCTAssertEqual(custom.period, 60)
        XCTAssertEqual(custom.digits, 7)
        XCTAssertEqual(custom.algorithm, .sha512)
    }

    func testCodesTheCoreRefusesAreNotPinnable() {
        for totp in ["", "not base32 !", "otpauth://hotp/x?secret=GEZDGNBV", "otpauth://totp/x?digits=6",
                     "otpauth://totp/x?secret=GEZDGNBV&digits=5", "otpauth://totp/x?secret=GEZDGNBV&period=0",
                     "otpauth://totp/x?secret=GEZDGNBV&algorithm=MD5", "steam://JBSWY3DPEHPK3PXP", "A"] {
            XCTAssertNil(PinnedCode(id: "x", title: "x", host: nil, totp: totp), totp)
        }
    }

    func testTransferContextRoundTrips() throws {
        let codes = [rfc(.sha1), rfc(.sha512), PinnedCode(id: "b", title: "Bank", host: "bank.example", secret: Data([1, 2, 3, 255]),
                                                           algorithm: .sha256, digits: 7, period: 60, revision: 42)]
        let context = try XCTUnwrap(PinnedCodes.transferContext(codes))
        // WatchConnectivity accepts property-list values only.
        XCTAssertTrue(PropertyListSerialization.propertyList(context, isValidFor: .binary))
        XCTAssertEqual(Set(context.keys), ["version", "codes"])
        XCTAssertEqual(PinnedCodes.codes(fromTransferContext: context), codes)
        // A sign-out sends an empty list, not nothing.
        let empty = try XCTUnwrap(PinnedCodes.transferContext([]))
        XCTAssertEqual(PinnedCodes.codes(fromTransferContext: empty), [])
    }

    func testTransferContextRefusesWhatItDoesNotUnderstand() throws {
        let good = try XCTUnwrap(PinnedCodes.transferContext([rfc(.sha1)]))
        var future = good
        future["version"] = PinnedCodes.transferVersion + 1
        XCTAssertNil(PinnedCodes.codes(fromTransferContext: future))
        XCTAssertNil(PinnedCodes.codes(fromTransferContext: [:]))
        XCTAssertNil(PinnedCodes.codes(fromTransferContext: ["version": 1, "codes": "nope"]))
        XCTAssertNil(PinnedCodes.codes(fromTransferContext: ["version": 1, "codes": Data("[{}]".utf8)]))
        // A parameter the computation refuses is never stored.
        let badDigits = PinnedCode(id: "x", title: "x", host: nil, secret: Data([1]), algorithm: .sha1, digits: 3, period: 30)
        let badPeriod = PinnedCode(id: "x", title: "x", host: nil, secret: Data([1]), algorithm: .sha1, digits: 6, period: 0)
        for code in [badDigits, badPeriod] {
            let context = try XCTUnwrap(PinnedCodes.transferContext([code]))
            XCTAssertNil(PinnedCodes.codes(fromTransferContext: context))
        }
    }
}

private extension PinnedCode {
    init?(id: String, title: String, host: String?, totp: String) {
        self.init(id: id, title: title, host: host, revision: 0, totp: totp)
    }
}
