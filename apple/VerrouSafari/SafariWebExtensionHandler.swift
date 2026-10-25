import Foundation

/// The Safari extension (`extension/safari`) asks nothing of the app: its
/// script submits the sign-in forms that iOS AutoFill fills, in the page.
/// Safari still requires a principal class; it answers empty.
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    func beginRequest(with context: NSExtensionContext) {
        context.completeRequest(returningItems: [], completionHandler: nil)
    }
}
