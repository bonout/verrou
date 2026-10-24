import XCTest

/// The sidebar's folder tree, built from the folders' full names.
final class FolderNodeTests: XCTestCase {
    func testNestsFoldersByName() {
        let tree = FolderNode.tree([("Work/Clients/Acme", 2), ("Work", 1), ("Personal", 3), ("Work/Admin", 4)])
        XCTAssertEqual(tree.map(\.path), ["Personal", "Work"])
        XCTAssertNil(tree[0].children, "no subfolder: no disclosure triangle")
        let work = tree[1]
        XCTAssertEqual(work.count, 7, "its own item and its subfolders'")
        XCTAssertEqual(work.children?.map(\.name), ["Admin", "Clients"])
        let clients = work.children?[1]
        XCTAssertEqual(clients?.path, "Work/Clients")
        XCTAssertEqual(clients?.count, 2)
        XCTAssertEqual(clients?.children?.map(\.path), ["Work/Clients/Acme"])
    }

    func testAParentThatOnlyHasSubfoldersStillShows() {
        let tree = FolderNode.tree([("Travel/2026", 5)])
        XCTAssertEqual(tree.map(\.path), ["Travel"])
        XCTAssertEqual(tree[0].count, 5)
        XCTAssertEqual(tree[0].children?.map(\.name), ["2026"])
    }

    func testIgnoresEmptyParts() {
        let tree = FolderNode.tree([("/Work//Clients/", 1)])
        XCTAssertEqual(tree.map(\.path), ["Work"])
        XCTAssertEqual(tree[0].children?.map(\.path), ["Work/Clients"])
    }
}
