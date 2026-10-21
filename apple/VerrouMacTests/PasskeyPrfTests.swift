import Foundation
import XCTest

/// System PRF inputs: `evalByCredential` takes priority for the chosen
/// passkey, otherwise `eval`, otherwise no PRF.
final class PasskeyPrfTests: XCTestCase {
    private let a = Data([1, 2, 3])
    private let b = Data([4, 5])

    func testPerCredentialInputsWin() {
        let eval = PrfInputs(first: Data("défaut".utf8), second: nil)
        let mine = PrfInputs(first: Data("pour a".utf8), second: Data("second".utf8))
        let request = PasskeyPrfAssertion(eval: eval, perCredential: [a: mine])
        XCTAssertEqual(request.inputs(for: a), mine)
        XCTAssertEqual(request.inputs(for: b), eval)
        XCTAssertFalse(request.isEmpty)
    }

    func testNoInputsForOtherCredentials() {
        let request = PasskeyPrfAssertion(eval: nil, perCredential: [a: PrfInputs(first: a, second: nil)])
        XCTAssertNil(request.inputs(for: b))
        XCTAssertTrue(PasskeyPrfAssertion(eval: nil, perCredential: [:]).isEmpty)
    }
}
