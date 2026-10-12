import AppKit
import AVFoundation

/// Capture des fenêtres de Verrou par Verrou lui-même, pour la démonstration.
///
/// L'app dessine ses propres vues dans une image : aucune autorisation
/// « Enregistrement de l'écran » n'est nécessaire, et rien d'autre que ses
/// fenêtres ne peut apparaître dans les captures.
@MainActor
enum WindowSnapshot {
    /// Image de la fenêtre principale, avec les panneaux flottants de l'app
    /// superposés à leur position réelle.
    static func composite(main: NSWindow, overlays: [NSWindow], scale: CGFloat) -> CGImage? {
        let frame = main.frame
        let width = Int(frame.width * scale)
        let height = Int(frame.height * scale)
        guard let context = CGContext(
            data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpace(name: CGColorSpace.sRGB)!,
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return nil }
        context.interpolationQuality = .high
        for window in [main] + overlays where window.isVisible {
            guard let image = render(window) else { continue }
            let rect = CGRect(
                x: (window.frame.minX - frame.minX) * scale,
                y: (window.frame.minY - frame.minY) * scale,
                width: window.frame.width * scale,
                height: window.frame.height * scale)
            context.draw(image, in: rect)
        }
        return context.makeImage()
    }

    static func render(_ window: NSWindow) -> CGImage? {
        // Le cadre de la fenêtre (barre de titre et barre d'outils comprises)
        // est la vue parente de `contentView`.
        guard let view = window.contentView?.superview ?? window.contentView,
              let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return nil }
        view.cacheDisplay(in: view.bounds, to: rep)
        return rep.cgImage
    }

    static func writePNG(_ image: CGImage, to url: URL) throws {
        let rep = NSBitmapImageRep(cgImage: image)
        guard let data = rep.representation(using: .png, properties: [:]) else { return }
        try data.write(to: url)
    }
}

/// Enregistrement vidéo (H.264) de la fenêtre principale, image par image.
@MainActor
final class WindowRecorder {
    private let writer: AVAssetWriter
    private let input: AVAssetWriterInput
    private let adaptor: AVAssetWriterInputPixelBufferAdaptor
    private let main: NSWindow
    private let overlays: () -> [NSWindow]
    private let size: CGSize
    private var timer: Timer?
    private var frame: Int64 = 0
    private let fps: Int32 = 24

    init(url: URL, main: NSWindow, overlays: @escaping () -> [NSWindow]) throws {
        try? FileManager.default.removeItem(at: url)
        self.main = main
        self.overlays = overlays
        size = CGSize(width: main.frame.width, height: main.frame.height)
        writer = try AVAssetWriter(outputURL: url, fileType: .mov)
        input = AVAssetWriterInput(mediaType: .video, outputSettings: [
            AVVideoCodecKey: AVVideoCodecType.h264,
            AVVideoWidthKey: Int(size.width),
            AVVideoHeightKey: Int(size.height),
            AVVideoCompressionPropertiesKey: [AVVideoAverageBitRateKey: 6_000_000],
        ])
        input.expectsMediaDataInRealTime = true
        adaptor = AVAssetWriterInputPixelBufferAdaptor(assetWriterInput: input, sourcePixelBufferAttributes: [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA,
            kCVPixelBufferWidthKey as String: Int(size.width),
            kCVPixelBufferHeightKey as String: Int(size.height),
        ])
        writer.add(input)
    }

    func start() {
        writer.startWriting()
        writer.startSession(atSourceTime: .zero)
        timer = Timer.scheduledTimer(withTimeInterval: 1 / Double(fps), repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.captureFrame() }
        }
    }

    private func captureFrame() {
        guard input.isReadyForMoreMediaData,
              let image = WindowSnapshot.composite(main: main, overlays: overlays(), scale: 1),
              let pool = adaptor.pixelBufferPool else { return }
        var buffer: CVPixelBuffer?
        CVPixelBufferPoolCreatePixelBuffer(nil, pool, &buffer)
        guard let buffer else { return }
        CVPixelBufferLockBaseAddress(buffer, [])
        if let context = CGContext(
            data: CVPixelBufferGetBaseAddress(buffer), width: Int(size.width), height: Int(size.height),
            bitsPerComponent: 8, bytesPerRow: CVPixelBufferGetBytesPerRow(buffer),
            space: CGColorSpace(name: CGColorSpace.sRGB)!,
            bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue | CGBitmapInfo.byteOrder32Little.rawValue) {
            context.setFillColor(NSColor.windowBackgroundColor.cgColor)
            context.fill(CGRect(origin: .zero, size: size))
            context.draw(image, in: CGRect(origin: .zero, size: size))
        }
        CVPixelBufferUnlockBaseAddress(buffer, [])
        adaptor.append(buffer, withPresentationTime: CMTime(value: frame, timescale: fps))
        frame += 1
    }

    func finish() async {
        timer?.invalidate()
        input.markAsFinished()
        await writer.finishWriting()
    }
}
