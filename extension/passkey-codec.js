// Passkeys : passage entre les options de `navigator.credentials` et les
// messages de Verrou (octets en base64url), et fabrication des
// `PublicKeyCredential` rendus à la page.
//
// Sans état ni réseau : chargé dans la page (monde MAIN) juste avant
// passkey-page.js, qui le récupère et l'efface de `globalThis`, et dans les
// tests Node. Rien de secret ne passe ici : Verrou ne rend que la clé
// publique, l'attestation et les signatures.

globalThis.__verrouPasskeyCodec = (() => {
  const MAX_IDS = 64;

  function bytesOf(source) {
    if (source instanceof ArrayBuffer) return new Uint8Array(source);
    if (ArrayBuffer.isView(source)) return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
    throw new TypeError("BufferSource attendu");
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

  // Entrées `AuthenticationExtensionsPRFValues` (BufferSource) → base64url.
  function prfValues(values) {
    if (!values || values.first === undefined) return null;
    return { first: encode(values.first), second: values.second === undefined ? null : encode(values.second) };
  }

  // `extensions.prf` → requête PRF pour Verrou (`evalByCredential` : les
  // identifiants sont déjà en base64url dans les options), ou null.
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

  // Sorties de Verrou (base64url) → `{ first, second? }` en ArrayBuffer.
  function prfOutputs(results) {
    if (!results?.first) return null;
    const out = { first: decode(results.first) };
    if (results.second) out.second = decode(results.second);
    return out;
  }

  // Résultats d'extension rendus à la page, et leur forme JSON.
  function extensionResults(results) {
    const json = structuredClone(results);
    if (json.prf?.results) {
      json.prf.results = Object.fromEntries(Object.entries(json.prf.results).map(([k, v]) => [k, encode(v)]));
    }
    return json;
  }

  // `PublicKeyCredentialCreationOptions` → requête `passkey_create` (sans
  // l'adresse : le service worker y met celle de l'onglet).
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
      // « preferred » par défaut : Verrou demande Touch ID. La PRF l'exige.
      uv: authenticatorSelection.userVerification !== "discouraged" || Boolean(publicKey.extensions?.prf),
      attestation: text(publicKey.attestation) ?? "none",
      // `evalByCredential` est refusé à la création (WebAuthn §10.1.4).
      prf: prfRequest(publicKey.extensions, false),
    };
  }

  // `PublicKeyCredentialRequestOptions` → requête `passkey_list` / `passkey_get`.
  function getRequest(publicKey) {
    return {
      rp_id: text(publicKey.rpId),
      challenge: encode(publicKey.challenge),
      allow: ids(publicKey.allowCredentials),
      uv: publicKey.userVerification !== "discouraged" || Boolean(publicKey.extensions?.prf),
      prf: prfRequest(publicKey.extensions, true),
    };
  }

  // Donne aux objets les prototypes du navigateur (`instanceof`), en gardant
  // leurs propriétés propres.
  function adopt(credential, Response) {
    const Credential = globalThis.PublicKeyCredential;
    if (Response) Object.setPrototypeOf(credential.response, Response.prototype);
    if (Credential) Object.setPrototypeOf(credential, Credential.prototype);
    return credential;
  }

  const copy = (buffer) => buffer.slice(0);

  // Réponse `registration` de Verrou → credential de `navigator.credentials.create`.
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

  // Réponse `assertion` de Verrou → credential de `navigator.credentials.get`.
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
