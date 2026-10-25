import XCTest

/// "Continue as…" in the AutoFill list: the login just filled is only
/// offered on the very host it was filled on ("www." aside).
final class RecentFillTests: XCTestCase {
    func testSameHost() {
        XCTAssertTrue(RecentFill.sameSite("example.com", "example.com"))
        XCTAssertTrue(RecentFill.sameSite("www.example.com", "Example.com"))
        XCTAssertTrue(RecentFill.sameSite("accounts.example.com", "ACCOUNTS.example.com"))
    }

    func testNeverAnotherHost() {
        XCTAssertFalse(RecentFill.sameSite("example.com", "example.org"))
        XCTAssertFalse(RecentFill.sameSite("accounts.example.com", "example.com"), "a subdomain may have another owner")
        XCTAssertFalse(RecentFill.sameSite("example.com", "pages.example.com"))
        XCTAssertFalse(RecentFill.sameSite("notexample.com", "example.com"))
        XCTAssertFalse(RecentFill.sameSite("a.co.uk", "b.co.uk"))
        XCTAssertFalse(RecentFill.sameSite("", ""))
    }
}
