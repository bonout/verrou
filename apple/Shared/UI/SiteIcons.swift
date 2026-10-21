import Observation
import SwiftUI
#if canImport(AppKit)
import AppKit

/// System image: `NSImage` on the Mac, `UIImage` on the iPhone.
typealias PlatformImage = NSImage

extension Image {
    init(platformImage: PlatformImage) { self.init(nsImage: platformImage) }
}
#else
import UIKit

/// System image: `NSImage` on the Mac, `UIImage` on the iPhone.
typealias PlatformImage = UIImage

extension Image {
    init(platformImage: PlatformImage) { self.init(uiImage: platformImage) }
}
#endif

/// Site icons, served by the account's Vaultwarden (`/icons/<site>/icon.png`).
///
/// Only the site's name goes out, to its own server, which fetches them for
/// us; nothing touches the disk (ephemeral network session, in-memory cache
/// emptied on lock): the list of sites doesn't stay in clear on the
/// device.
@MainActor
@Observable
final class SiteIcons {
    /// A site's icon: observed separately, so that an arrived icon only
    /// redraws the views that show it (not all the rows).
    @MainActor
    @Observable
    final class Entry {
        /// `nil`: download in progress, or no icon (we keep the initial).
        fileprivate(set) var image: PlatformImage?
    }

    /// Requested sites. Not observed: adding one while a view is being
    /// computed invalidates no other view.
    @ObservationIgnored private var entries: [String: Entry] = [:]
    /// The generic image Vaultwarden returns when it finds nothing.
    @ObservationIgnored private var fallback: Task<Data?, Never>?
    @ObservationIgnored private let urlSession: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.httpMaximumConnectionsPerHost = 4
        return URLSession(configuration: configuration)
    }()

    /// Server address; `nil` (demo vault, setting turned off): no icon.
    var server: String? {
        didSet { if oldValue != server { clear() } }
    }

    /// Icons already arrived, per site (measurements, tests).
    var images: [String: PlatformImage] {
        entries.compactMapValues(\.image)
    }

    /// The icon if it's already there; otherwise requests it, and the view will update.
    func image(for host: String) -> PlatformImage? {
        let site = Self.site(of: host)
        if let entry = entries[site] { return entry.image }
        guard let server, !site.isEmpty else { return nil }
        let entry = Entry()
        entries[site] = entry
        Task { await load(site, into: entry, from: server) }
        return entry.image
    }

    /// Sites already requested (measurements).
    var requestedCount: Int { entries.count }

    func clear() {
        // The views showing an icon lose it right away.
        for entry in entries.values { entry.image = nil }
        entries.removeAll()
        fallback?.cancel()
        fallback = nil
    }

    private func load(_ site: String, into entry: Entry, from server: String) async {
        guard let data = await fetch(server: server, site: site),
              data != (await fallbackIcon(server: server)),
              self.server == server else { return }
        // Decoded off the main thread: scrolling only has to display it.
        let image = await Task.detached(priority: .utility) { Self.decoded(data) }.value
        guard let image, self.server == server, entries[site] === entry else { return }
        entry.image = image
    }

    nonisolated private static func decoded(_ data: Data) -> PlatformImage? {
        #if canImport(UIKit)
        guard let image = UIImage(data: data) else { return nil }
        return image.preparingForDisplay() ?? image
        #else
        return NSImage(data: data)
        #endif
    }

    private func fallbackIcon(server: String) async -> Data? {
        if let fallback { return await fallback.value }
        let task = Task { await fetch(server: server, site: "verrou-no-icon.invalid") }
        fallback = task
        return await task.value
    }

    private func fetch(server: String, site: String) async -> Data? {
        guard let url = URL(string: "\(server)/icons/\(site)/icon.png"),
              let (data, response) = try? await urlSession.data(from: url),
              (response as? HTTPURLResponse)?.statusCode == 200 else { return nil }
        return data
    }

    /// The domain name alone: no port, no uppercase.
    static func site(of host: String) -> String {
        let name = host.split(separator: ":").first.map(String.init) ?? host
        return name.lowercased().filter { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" }
    }
}
