import ActivityKit
import AppIntents
import Foundation

/// The Live Activity of a request from the Mac (Dynamic Island, lock
/// screen): which Mac asks, and the time left to answer.
///
/// What is asked (the item, the reason) stays sealed until Face ID in the
/// app, as for the notification: the Mac seals it for this iPhone's Secure
/// Enclave key, usable only after Face ID (SECURITY.md, "Approving from the
/// iPhone"). The Mac's name and the expiry are known before: the name comes
/// from the pairing, the expiry travels in clear with the Mac's signature.
/// Compiled into the app (which starts and ends the activity) and the widget
/// extension (which draws it).
struct ApprovalActivityAttributes: ActivityAttributes {
    struct ContentState: Codable, Hashable {
        enum Stage: String, Codable, Hashable {
            case waiting
            case approved
            case denied
        }

        var stage: Stage
        /// The Mac stops waiting then.
        var expires: Date
    }

    let requestID: String
    /// The Mac's name, given at pairing.
    let macName: String
}

/// "Approve" on the Live Activity: opens Verrou on the request. Face ID
/// then shows what is asked, and the answer is given there, as for the
/// notification: the button never approves by itself.
struct ApproveRequestIntent: LiveActivityIntent {
    static let title: LocalizedStringResource = "Approve"
    static let description = IntentDescription("Opens the request from your Mac in Verrou, to approve it with Face ID.")
    static let openAppWhenRun = true
    static let isDiscoverable = false

    @Parameter(title: "Request")
    var requestID: String

    init() {}

    init(requestID: String) {
        self.requestID = requestID
    }

    @MainActor
    func perform() async throws -> some IntentResult {
        VerrouLinkCenter.open(.approval)
        return .result()
    }
}

/// "Deny" on the Live Activity: opens Verrou on the request too. A refusal
/// is sealed for the Mac like an approval, with the Secure Enclave key that
/// only works after Face ID.
struct DenyRequestIntent: LiveActivityIntent {
    static let title: LocalizedStringResource = "Deny"
    static let description = IntentDescription("Opens the request from your Mac in Verrou, to deny it with Face ID.")
    static let openAppWhenRun = true
    static let isDiscoverable = false

    @Parameter(title: "Request")
    var requestID: String

    init() {}

    init(requestID: String) {
        self.requestID = requestID
    }

    @MainActor
    func perform() async throws -> some IntentResult {
        VerrouLinkCenter.open(.approval)
        return .result()
    }
}
