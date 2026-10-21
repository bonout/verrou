import AppKit
import AVFoundation
import ScreenCaptureKit
import VideoToolbox

/// Capture of Verrou's windows for the demo, through ScreenCaptureKit.
///
/// The filter only keeps Verrou's windows: no other app can appear in the
/// captures, even if one of them covers the window. Requires the "Screen
/// Recording" permission for the app that launches Verrou (the terminal,
/// through `scripts/demo-capture.sh`).
///
/// `cacheDisplay(in:to:)` didn't work: it can't draw the translucent
/// materials (sidebar, toolbar), rendered in white.
enum WindowSnapshot {
    struct Source {
        let filter: SCContentFilter
        /// Rectangle of the main window in the screen, origin at the top left.
        let rect: CGRect
    }

    /// All of Verrou's windows, including those opened later (quick access),
    /// framed on the main window.
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
        // AppKit coordinates (origin at the bottom left of the main screen) to
        // those of the captured screen (origin at the top left).
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

/// Video recording (H.264) of the main window and of Verrou's panels that
/// cover it. The screenshots are taken from this same stream: a single
/// ScreenCaptureKit session, which other apps capturing the screen (video
/// conferencing) don't make fail along the way.
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

    /// ScreenCaptureKit also sends empty frames when nothing has moved.
    private func isComplete(_ sampleBuffer: CMSampleBuffer) -> Bool {
        guard let attachments = CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, createIfNecessary: false)
                as? [[SCStreamFrameInfo: Any]],
              let raw = attachments.first?[.status] as? Int,
              let status = SCFrameStatus(rawValue: raw) else { return false }
        return status == .complete
    }

    func stream(_ stream: SCStream, didStopWithError error: Error) {
        print("DEMO_LOG stream stopped: \(error.localizedDescription)")
        fflush(stdout)
    }

    /// Last frame received, in full resolution.
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
