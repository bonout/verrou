// Passkeys: conversion between the `navigator.credentials` options and
// Verrou's messages (bytes in base64url), and making of the
// `PublicKeyCredential`s returned to the page.
//
// No state, no network: loaded in the page (MAIN world) right before
// passkey-page.js, which takes it and deletes it from `globalThis`, and in
// the Node tests. Nothing secret goes through here: Verrou only returns the
// public key, the attestation and the signatures.

globalThis.__verrouPasskeyCodec = (() => {
  const MAX_IDS = 64;

  function bytesOf(source) {
    if (source instanceof ArrayBuffer) return new Uint8Array(source);
    if (ArrayBuffer.isView(source)) return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
    throw new TypeError("BufferSource expected");
  }

  function encode(source) {
    let binary = "";
    for (const byte of bytesOf(source)) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  // base64url → ArrayBuffer.
  function decode(text) {
    const base64 = String(text).replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64 + "===".slice((base64.length + 3) % 4));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  const text = (value) => (typeof value === "string" && value ? value : null);
  const ids = (list) => (Array.isArray(list) ? list : [])
    .filter((c) => c?.type === "public-key" && c.id)
    .slice(0, MAX_IDS)
    .map((c) => encode(c.id));

  // `AuthenticationExtensionsPRFValues` inputs (BufferSource) → base64url.
  function prfValues(values) {
    if (!values || values.first === undefined) return null;
    return { first: encode(values.first), second: values.second === undefined ? null : encode(values.second) };
  }

  // `extensions.prf` → PRF request for Verrou (`evalByCredential`: the
  // credential IDs are already in base64url in the options), or null.
  function prfRequest(extensions, withByCredential) {
    const prf = extensions?.prf;
    if (!prf || typeof prf !== "object") return null;
    const byCredential = {};
    if (withByCredential && prf.evalByCredential && typeof prf.evalByCredential === "object") {
      for (const [id, values] of Object.entries(prf.evalByCredential).slice(0, MAX_IDS)) {
        const parsed = prfValues(values);
        if (parsed) byCredential[id] = parsed;
      }
    }
    return { eval: prfValues(prf.eval), eval_by_credential: byCredential };
  }

  // Outputs of Verrou (base64url) → `{ first, second? }` as ArrayBuffer.
  function prfOutputs(results) {
    if (!results?.first) return null;
    const out = { first: decode(results.first) };
    if (results.second) out.second = decode(results.second);
    return out;
  }

  // Extension results returned to the page, and their JSON form.
  function extensionResults(results) {
    const json = structuredClone(results);
    if (json.prf?.results) {
      json.prf.results = Object.fromEntries(Object.entries(json.prf.results).map(([k, v]) => [k, encode(v)]));
    }
    return json;
  }

  // `PublicKeyCredentialCreationOptions` → `passkey_create` request (without
  // the address: the service worker puts the tab's in it).
  function createRequest(publicKey) {
    const { rp = {}, user = {}, authenticatorSelection = {} } = publicKey;
    return {
      rp_id: text(rp.id),
      rp_name: text(rp.name),
      user_id: encode(user.id),
      user_name: text(user.name),
      user_display_name: text(user.displayName),
      challenge: encode(publicKey.challenge),
      algorithms: (Array.isArray(publicKey.pubKeyCredParams) ? publicKey.pubKeyCredParams : [])
        .filter((p) => p?.type === "public-key")
        .map((p) => Number(p.alg)),
      exclude: ids(publicKey.excludeCredentials),
      // "preferred" by default: Verrou asks for Touch ID. PRF requires it.
      uv: authenticatorSelection.userVerification !== "discouraged" || Boolean(publicKey.extensions?.prf),
      attestation: text(publicKey.attestation) ?? "none",
      // `evalByCredential` is refused at creation (WebAuthn §10.1.4).
      prf: prfRequest(publicKey.extensions, false),
    };
  }

  // `PublicKeyCredentialRequestOptions` → `passkey_list` / `passkey_get` request.
  function getRequest(publicKey) {
    return {
      rp_id: text(publicKey.rpId),
      challenge: encode(publicKey.challenge),
      allow: ids(publicKey.allowCredentials),
      uv: publicKey.userVerification !== "discouraged" || Boolean(publicKey.extensions?.prf),
      prf: prfRequest(publicKey.extensions, true),
    };
  }

  // Gives the objects the browser's prototypes (`instanceof`), keeping their
  // own properties.
  function adopt(credential, Response) {
    const Credential = globalThis.PublicKeyCredential;
    if (Response) Object.setPrototypeOf(credential.response, Response.prototype);
    if (Credential) Object.setPrototypeOf(credential, Credential.prototype);
    return credential;
  }

  const copy = (buffer) => buffer.slice(0);

  // Verrou's `registration` reply → credential of `navigator.credentials.create`.
  function registrationCredential(reply, extensions = {}) {
    const clientDataJSON = decode(reply.client_data);
    const attestationObject = decode(reply.attestation_object);
    const authenticatorData = decode(reply.authenticator_data);
    const publicKey = decode(reply.public_key);
    const transports = ["hybrid", "internal"];
    const results = extensions.credProps ? { credProps: { rk: true } } : {};
    if (extensions.prf) {
      const outputs = prfOutputs(reply.prf?.results);
      results.prf = { enabled: Boolean(reply.prf?.enabled), ...(outputs ? { results: outputs } : {}) };
    }
    const response = {
      clientDataJSON,
      attestationObject,
      getTransports: () => [...transports],
      getAuthenticatorData: () => copy(authenticatorData),
      getPublicKey: () => copy(publicKey),
      getPublicKeyAlgorithm: () => reply.algorithm,
    };
    return adopt({
      id: reply.credential,
      rawId: decode(reply.credential),
      type: "public-key",
      authenticatorAttachment: "platform",
      response,
      getClientExtensionResults: () => structuredClone(results),
      toJSON: () => ({
        id: reply.credential,
        rawId: reply.credential,
        type: "public-key",
        authenticatorAttachment: "platform",
        clientExtensionResults: extensionResults(results),
        response: {
          clientDataJSON: reply.client_data,
          attestationObject: reply.attestation_object,
          authenticatorData: reply.authenticator_data,
          transports: [...transports],
          publicKey: reply.public_key,
          publicKeyAlgorithm: reply.algorithm,
        },
      }),
    }, globalThis.AuthenticatorAttestationResponse);
  }

  // Verrou's `assertion` reply → credential of `navigator.credentials.get`.
  function assertionCredential(reply) {
    const outputs = prfOutputs(reply.prf);
    const results = outputs ? { prf: { results: outputs } } : {};
    const response = {
      clientDataJSON: decode(reply.client_data),
      authenticatorData: decode(reply.authenticator_data),
      signature: decode(reply.signature),
      userHandle: reply.user_handle ? decode(reply.user_handle) : null,
    };
    return adopt({
      id: reply.credential,
      rawId: decode(reply.credential),
      type: "public-key",
      authenticatorAttachment: "platform",
      response,
      getClientExtensionResults: () => structuredClone(results),
      toJSON: () => ({
        id: reply.credential,
        rawId: reply.credential,
        type: "public-key",
        authenticatorAttachment: "platform",
        clientExtensionResults: extensionResults(results),
        response: {
          clientDataJSON: reply.client_data,
          authenticatorData: reply.authenticator_data,
          signature: reply.signature,
          userHandle: reply.user_handle ?? null,
        },
      }),
    }, globalThis.AuthenticatorAssertionResponse);
  }

  return { encode, decode, createRequest, getRequest, registrationCredential, assertionCredential };
})();
