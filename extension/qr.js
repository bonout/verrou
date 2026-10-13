// Lecture d'un QR code de double authentification (URI `otpauth://totp/…`)
// dans une image, par le lecteur de codes-barres du navigateur.

export const canReadQrCodes = () => "BarcodeDetector" in globalThis;

// L'URI otpauth du premier QR code de double authentification de l'image,
// ou null.
export async function otpauthFrom(blob) {
  const bitmap = await createImageBitmap(blob);
  try {
    const codes = await new BarcodeDetector({ formats: ["qr_code"] }).detect(bitmap);
    return codes.map((code) => code.rawValue).find((value) => /^otpauth:\/\/totp\//i.test(value)) ?? null;
  } finally {
    bitmap.close();
  }
}
