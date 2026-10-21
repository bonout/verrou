// Cryptography of the channel with Verrou, in WebCrypto only.
//
// Same primitives and same derivation as crates/verrou-bridge/src/crypto.rs:
// ECDH P-256 → HKDF-SHA256 (salt: public key of the extension then Verrou's,
// info "verrou-bridge v1") → AES-256-GCM key. Associated data:
// "<client>:q" for a request, "<client>:r" for a response.
//
// Works in the extension's service worker as well as in Node (tests).

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const INFO = encoder.encode("verrou-bridge v1");
const CODE_LABEL = encoder.encode("verrou-bridge code");

export function toBase64(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function fromBase64(text) {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(new Uint8Array(part), offset);
    offset += part.byteLength;
  }
  return out;
}

// Pairing key of the extension. The private key is not exportable.
export async function generateKeyPair() {
  return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
}

export async function publicKeyBase64(pair) {
  return toBase64(await crypto.subtle.exportKey("raw", pair.publicKey));
}

// Bytes of the channel key (32), from Verrou's public key.
export async function agree(pair, serverKeyBase64) {
  const serverRaw = fromBase64(serverKeyBase64);
  const serverKey = await crypto.subtle.importKey(
    "raw", serverRaw, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: serverKey }, pair.privateKey, 256);
  const clientRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const hkdf = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: concat(clientRaw, serverRaw), info: INFO }, hkdf, 256);
  return new Uint8Array(bits);
}

// Code shown on both sides during pairing: "482 913".
export async function pairingCode(keyBytes) {
  const digest = new DataView(await crypto.subtle.digest("SHA-256", concat(CODE_LABEL, keyBytes)));
  const n = digest.getUint32(0) % 1_000_000;
  const text = String(n).padStart(6, "0");
  return `${text.slice(0, 3)} ${text.slice(3)}`;
}

// Non-exportable AES-GCM key: once imported, its bytes can no longer be
// read, even by the extension.
export async function importChannelKey(keyBytes) {
  return crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function aad(client, direction) {
  return encoder.encode(`${client}:${direction === "request" ? "q" : "r"}`);
}

export async function seal(key, client, direction, message) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad(client, direction) },
    key, encoder.encode(JSON.stringify(message)));
  return { iv: toBase64(iv), data: toBase64(data) };
}

export async function open(key, client, direction, iv, data) {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(iv), additionalData: aad(client, direction) },
    key, fromBase64(data));
  return JSON.parse(decoder.decode(plain));
}
