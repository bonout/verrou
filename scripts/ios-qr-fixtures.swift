// Images de QR codes pour scripts/ios-e2e.sh : des « captures d'écran »
// de la taille d'un iPhone, où le site montre son QR code de double
// authentification, comme celles que l'on choisit dans Photos.
//
//   swift scripts/ios-qr-fixtures.swift <dossier>
//
// Les graines sont celles qu'attend apple/VerrouiOS/Demo/EndToEndDriver.swift.
import AppKit
import CoreImage
import ImageIO
import UniformTypeIdentifiers

let out = URL(fileURLWithPath: CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ".")
try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)

func qrCode(_ text: String, size: CGFloat) -> CGImage {
    let filter = CIFilter(name: "CIQRCodeGenerator")!
    filter.setValue(Data(text.utf8), forKey: "inputMessage")
    filter.setValue("M", forKey: "inputCorrectionLevel")
    let image = filter.outputImage!
    let scale = (size / image.extent.width).rounded(.down)
    let scaled = image.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
    return CIContext().createCGImage(scaled, from: scaled.extent)!
}

func screenshot(_ name: String, title: String, detail: String, payload: String) throws {
    let (width, height) = (1179, 2556)
    let context = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
                            space: CGColorSpace(name: CGColorSpace.sRGB)!,
                            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    context.setFillColor(CGColor(red: 0.97, green: 0.97, blue: 0.98, alpha: 1))
    context.fill(CGRect(x: 0, y: 0, width: width, height: height))
    context.setFillColor(CGColor(red: 0.16, green: 0.32, blue: 0.75, alpha: 1))
    context.fill(CGRect(x: 0, y: height - 330, width: width, height: 330))
    NSGraphicsContext.current = NSGraphicsContext(cgContext: context, flipped: false)
    let header: [NSAttributedString.Key: Any] = [.font: NSFont.boldSystemFont(ofSize: 64), .foregroundColor: NSColor.white]
    NSAttributedString(string: title, attributes: header).draw(at: CGPoint(x: 80, y: height - 250))
    let body: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: 46), .foregroundColor: NSColor.darkGray]
    NSAttributedString(string: detail, attributes: body)
        .draw(in: CGRect(x: 80, y: height - 640, width: width - 160, height: 240))
    let code = qrCode(payload, size: 760)
    let side = CGFloat(code.width)
    let origin = CGPoint(x: (CGFloat(width) - side) / 2, y: CGFloat(height) / 2 - side / 2 - 120)
    context.setFillColor(.white)
    context.fill(CGRect(origin: origin, size: CGSize(width: side, height: side)).insetBy(dx: -60, dy: -60))
    context.interpolationQuality = .none
    context.draw(code, in: CGRect(origin: origin, size: CGSize(width: side, height: side)))
    NSAttributedString(string: "Impossible de scanner ? Saisissez la clé à la main.", attributes: body)
        .draw(at: CGPoint(x: 80, y: origin.y - 200))
    let file = out.appendingPathComponent(name)
    let destination = CGImageDestinationCreateWithURL(file as CFURL, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(destination, context.makeImage()!, nil)
    guard CGImageDestinationFinalize(destination) else { throw CocoaError(.fileWriteUnknown) }
}

try screenshot("qr-nouveau.png", title: "Exemple Cloud",
               detail: "Activez la double authentification : scannez ce QR code avec votre application.",
               payload: "otpauth://totp/Exemple%20Cloud:camille%40exemple.fr?secret=KRUGKIDROVUWG2ZAMJZG653OEBTG66BA&issuer=Exemple%20Cloud")
try screenshot("qr-amazon.png", title: "Amazon",
               detail: "Connexion en deux étapes : scannez le code avec votre application d'authentification.",
               payload: "otpauth://totp/Amazon:camille%40exemple.fr?secret=MFWWC6TPNYQGG33EMUQGC5DUMFRWQZLE&issuer=Amazon")
// Export de Google Authenticator : deux comptes TOTP et un HOTP, lot 1 sur 2
// (le même que dans crates/verrou-core/src/otp_scan.rs).
try screenshot("qr-export.png", title: "Authenticator",
               detail: "Transférer des comptes : scannez ce QR code (1 sur 2).",
               payload: "otpauth-migration://offline?data=CjcKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEg9yZmNAZXhhbXBsZS5jb20aCFJGQyA2MjM4IAEoAjACCkIKIDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyEg%2FDiXF1aXBlOmNhbWlsbGUaB8OJcXVpcGUgAigBMAIKMAoKSGVsbG8h3q2%2B7xIQaG90cEBleGFtcGxlLmNvbRoIQ29tcHRldXIgASgBMAE4BxABGAIgACjAxAc%3D")
// Un QR code qui n'est pas un code à usage unique.
try screenshot("qr-wifi.png", title: "Wi-Fi invités", detail: "Rejoignez le réseau.",
               payload: "WIFI:S:Invites;T:WPA;P:lilas-annecy;;")
print("images : \(out.path)")
