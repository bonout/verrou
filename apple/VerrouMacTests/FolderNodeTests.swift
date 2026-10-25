import XCTest

/// The folder tree (Mac sidebar, iPhone folders), built from the folders' full names.
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

    /// The iPhone opens a folder by its path, one level per screen.
    func testFindsAFolderAtAnyDepth() {
        let tree = FolderNode.tree([("Work/Clients/Acme", 2), ("Workshop", 1)])
        XCTAssertEqual(FolderNode.find("Work/Clients/Acme", in: tree)?.count, 2)
        XCTAssertEqual(FolderNode.find("Work", in: tree)?.children?.map(\.name), ["Clients"])
        XCTAssertEqual(FolderNode.find("Workshop", in: tree)?.count, 1, "a prefix of the name isn't a parent")
        XCTAssertNil(FolderNode.find("Work/Admin", in: tree))
    }

    func testNormalizesAFolderName() {
        XCTAssertEqual(FolderNode.path(of: "/Work//Clients/"), "Work/Clients")
        XCTAssertEqual(FolderNode.path(of: "Personal"), "Personal")
    }

    /// A folder created empty is on the server but not in the counts.
    func testAnEmptyFolderShowsWithAZeroCount() {
        let tree = FolderNode.tree(counts: [("Work", 2)], folders: ["Work", "/Ideas/", "Work/Clients"])
        XCTAssertEqual(tree.map(\.path), ["Ideas", "Work"])
        XCTAssertEqual(tree[0].count, 0)
        XCTAssertEqual(tree[1].count, 2)
        XCTAssertEqual(tree[1].children?.map(\.path), ["Work/Clients"])
        XCTAssertEqual(tree[1].children?[0].count, 0)
    }

    /// Renaming or deleting acts on the outermost server folders: the rest follow.
    func testRootsAreTheOutermostFoldersOfABranch() {
        let folders = [(id: "1", name: "Work/Clients"), (id: "2", name: "Work/Clients/Acme"),
                       (id: "3", name: "Workshop"), (id: "4", name: "Work/Admin")]
        XCTAssertEqual(FolderNode.roots(of: "Work", in: folders).map(\.id), ["1", "4"],
                       "Work has no folder of its own; Workshop is not below it")
        XCTAssertEqual(FolderNode.roots(of: "Work/Clients", in: folders).map(\.id), ["1"])
        XCTAssertEqual(FolderNode.roots(of: "Workshop", in: folders).map(\.id), ["3"])
        XCTAssertTrue(FolderNode.roots(of: "Home", in: folders).isEmpty)
    }

    func testMovedFollowsTheRenamedParent() {
        XCTAssertEqual(FolderNode.moved("Work/Clients", from: "Work", to: "Job"), "Job/Clients")
        XCTAssertEqual(FolderNode.moved("Work", from: "Work", to: "Job/Work"), "Job/Work")
        XCTAssertEqual(FolderNode.parent(of: "Work/Clients"), "Work")
        XCTAssertNil(FolderNode.parent(of: "Work"))
    }
}
