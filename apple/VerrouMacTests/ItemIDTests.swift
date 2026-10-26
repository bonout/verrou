import XCTest

/// Item ids as the core emits them (`<tag>:<id>`) and the plain ids that may
/// still be stored on the device from before.
final class ItemIDTests: XCTestCase {
    private let uuid = "0b6e9c1e-4f6e-4a41-9d5b-6f0f4c1a2b3c"

    func testSplitsTheTagOffAnId() {
        XCTAssertEqual(ItemID.split("k3f7qa:\(uuid)").tag, "k3f7qa")
        XCTAssertEqual(ItemID.split("k3f7qa:\(uuid)").id, uuid)
        XCTAssertNil(ItemID.split(uuid).tag)
        XCTAssertEqual(ItemID.split(uuid).id, uuid)
    }

    func testOnlyAnAccountTagCountsAsAPrefix() {
        // Not six characters of a-z2-7: part of the id.
        for id in ["K3F9QA:x", "k3f9q:x", "k3f7qa1:x", "k3f91a:x", ":x", "ssh:key"] {
            XCTAssertNil(ItemID.split(id).tag, id)
            XCTAssertEqual(ItemID.local(id), id)
        }
        XCTAssertEqual(ItemID.local("k3f7qa:a:b"), "a:b")
    }

    func testQualifyingKeepsAnExistingTagAndNeedsOne() {
        XCTAssertEqual(ItemID.qualified(uuid, tag: "k3f7qa"), "k3f7qa:\(uuid)")
        XCTAssertEqual(ItemID.qualified("k3f7qa:\(uuid)", tag: "k3f7qa"), "k3f7qa:\(uuid)")
        XCTAssertEqual(ItemID.qualified("zzzzzz:\(uuid)", tag: "k3f7qa"), "zzzzzz:\(uuid)", "never re-tagged")
        XCTAssertEqual(ItemID.qualified(uuid, tag: nil), uuid, "the demo vault has no tag")
    }

    func testTheSameItemInEitherForm() {
        XCTAssertTrue(ItemID.same("k3f7qa:\(uuid)", uuid))
        XCTAssertTrue(ItemID.same(uuid, "k3f7qa:\(uuid)"))
        XCTAssertTrue(ItemID.same("k3f7qa:\(uuid)", "k3f7qa:\(uuid)"))
        XCTAssertTrue(ItemID.same(uuid, uuid))
        // Another account's id is never the same item, even with the same uuid.
        XCTAssertFalse(ItemID.same("k3f7qa:\(uuid)", "zzzzzz:\(uuid)"))
        XCTAssertFalse(ItemID.same("k3f7qa:\(uuid)", "k3f7qa:other"))
        XCTAssertFalse(ItemID.same(uuid, "other"))
    }
}
