// Reading of a two-factor QR code (URI `otpauth://totp/…`) in an image, by
// the browser's barcode reader.

export const canReadQrCodes = () => "BarcodeDetector" in globalThis;

// The otpauth URI of the image's first two-factor QR code, or null.
export async function otpauthFrom(blob) {
  const bitmap = await createImageBitmap(blob);
  try {
    const codes = await new BarcodeDetector({ formats: ["qr_code"] }).detect(bitmap);
    return codes.map((code) => code.rawValue).find((value) => /^otpauth:\/\/totp\//i.test(value)) ?? null;
  } finally {
    bitmap.close();
  }
}
