import AppKit
import AVFoundation
import ScreenCaptureKit
import VideoToolbox

/// Capture des fenêtres de Verrou pour la démonstration, par ScreenCaptureKit.
///
/// Le filtre ne retient que les fenêtres de Verrou : aucune autre app ne peut
/// apparaître dans les captures, même si l'une d'elles recouvre la fenêtre.
/// Demande l'autorisation « Enregistrement de l'écran » pour l'app qui lance
/// Verrou (le terminal, via `scripts/demo-capture.sh`).
///
/// `cacheDisplay(in:to:)` ne convenait pas : il ne sait pas dessiner les
/// matériaux translucides (barre latérale, barre d'outils), rendus en blanc.
enum WindowSnapshot {
    struct Source {
        let filter: SCContentFilter
        /// Rectangle de la fenêtre principale dans l'écran, origine en haut à gauche.
        let rect: CGRect
    }

    /// Toutes les fenêtres de Verrou, y compris celles ouvertes plus tard
    /// (l'accès rapide), cadrées sur la fenêtre principale.
    @MainActor
    static func source(main: NSWindow) async throws -> Source {
        let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: false)
        let pid = ProcessInfo.processInfo.processIdentifier
        guard let app = content.applications.first(where: { $0.processID == pid }) else {
            throw CaptureError.appNotFound
        }
        let screen = main.screen ?? NSScreen.main!
        let displayID = screen.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? CGDirectDisplayID
        guard let display = content.displays.first(where: { $0.displayID == displayID }) ?? content.displays.first else {
            throw CaptureError.displayNotFound
        }
        // Coordonnées AppKit (origine en bas à gauche de l'écran principal)
        // vers celles de l'écran capturé (origine en haut à gauche).
        let primaryHeight = NSScreen.screens.first?.frame.height ?? screen.frame.height
        let frame = main.frame
        let rect = CGRect(
            x: frame.minX - display.frame.minX,
            y: primaryHeight - frame.maxY - display.frame.minY,
            width: frame.width,
            height: frame.height)
        let filter = SCContentFilter(display: display, including: [app], exceptingWindows: [])
        return Source(filter: filter, rect: rect)
    }

    static func configuration(for source: Source, scale: CGFloat) -> SCStreamConfiguration {
        let config = SCStreamConfiguration()
        config.sourceRect = source.rect
        config.width = Int(source.rect.width * scale)
        config.height = Int(source.rect.height * scale)
        config.showsCursor = false
        config.capturesAudio = false
        config.backgroundColor = .clear
        return config
    }

    static func writePNG(_ image: CGImage, to url: URL) throws {
        let rep = NSBitmapImageRep(cgImage: image)
        guard let data = rep.representation(using: .png, properties: [:]) else { return }
        try data.write(to: url)
    }

    enum CaptureError: Error {
        case appNotFound, displayNotFound
    }
}

/// Enregistrement vidéo (H.264) de la fenêtre principale et des panneaux de
/// Verrou qui la recouvrent. Les captures d'écran sont prises dans ce même
/// flux : une seule session ScreenCaptureKit, que les autres apps qui
/// capturent l'écran (visioconférence) ne font pas échouer en cours de route.
final class WindowRecorder: NSObject, SCStreamOutput, SCStreamDelegate, @unchecked Sendable {
    private let writer: AVAssetWriter
    private let input: AVAssetWriterInput
    private var stream: SCStream!
    private let queue = DispatchQueue(label: "app.verrou.demo.recorder")
    private var started = false
    private var latest: CVPixelBuffer?

    @MainActor
    init(url: URL, main: NSWindow) async throws {
        try? FileManager.default.removeItem(at: url)
        let source = try await WindowSnapshot.source(main: main)
        let config = WindowSnapshot.configuration(for: source, scale: 2)
        config.minimumFrameInterval = CMTime(value: 1, timescale: 30)
        config.pixelFormat = kCVPixelFormatType_32BGRA
        config.backgroundColor = NSColor.windowBackgroundColor.cgColor
        writer = try AVAssetWriter(outputURL: url, fileType: .mov)
        input = AVAssetWriterInput(mediaType: .video, outputSettings: [
            AVVideoCodecKey: AVVideoCodecType.h264,
            AVVideoWidthKey: config.width,
            AVVideoHeightKey: config.height,
            AVVideoCompressionPropertiesKey: [AVVideoAverageBitRateKey: 12_000_000],
        ])
        input.expectsMediaDataInRealTime = true
        writer.add(input)
        super.init()
        stream = SCStream(filter: source.filter, configuration: config, delegate: self)
        try stream.addStreamOutput(self, type: .screen, sampleHandlerQueue: queue)
    }

    func start() async throws {
        writer.startWriting()
        try await stream.startCapture()
    }

    func stream(_ stream: SCStream, didOutputSampleBuffer sampleBuffer: CMSampleBuffer, of type: SCStreamOutputType) {
        guard type == .screen, sampleBuffer.isValid, isComplete(sampleBuffer) else { return }
        latest = sampleBuffer.imageBuffer
        if !started {
            writer.startSession(atSourceTime: sampleBuffer.presentationTimeStamp)
            started = true
        }
        if input.isReadyForMoreMediaData {
            input.append(sampleBuffer)
        }
    }

    /// ScreenCaptureKit envoie aussi des images vides quand rien n'a bougé.
    private func isComplete(_ sampleBuffer: CMSampleBuffer) -> Bool {
        guard let attachments = CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, createIfNecessary: false)
                as? [[SCStreamFrameInfo: Any]],
              let raw = attachments.first?[.status] as? Int,
              let status = SCFrameStatus(rawValue: raw) else { return false }
        return status == .complete
    }

    func stream(_ stream: SCStream, didStopWithError error: Error) {
        print("DEMO_LOG flux arrêté : \(error.localizedDescription)")
        fflush(stdout)
    }

    /// Dernière image reçue, en pleine définition.
    func snapshot() -> CGImage? {
        guard let buffer = queue.sync(execute: { latest }) else { return nil }
        var image: CGImage?
        VTCreateCGImageFromCVPixelBuffer(buffer, options: nil, imageOut: &image)
        return image
    }

    func finish() async {
        try? await stream.stopCapture()
        await withCheckedContinuation { (done: CheckedContinuation<Void, Never>) in
            queue.async { [self] in
                input.markAsFinished()
                writer.finishWriting { done.resume() }
            }
        }
    }
}
