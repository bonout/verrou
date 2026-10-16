// Passkeys : demandes de passkeys.js → commandes pour Verrou, et réponses de
// Verrou → réponses pour passkeys.js. Utilisé par le service worker (et par
// les tests, avec le vrai pont).
//
// Les options viennent de la page : Verrou les vérifie (site, longueurs) ;
// ici, seulement leur forme. L'adresse `url` est celle que le navigateur
// attribue à l'onglet, jamais une adresse fournie par la page.

const str = (value, max = 4096) => (typeof value === "string" && value ? value.slice(0, max) : null);
const strings = (list) => (Array.isArray(list) ? list.filter((v) => typeof v === "string").slice(0, 64) : []);

// Entrées de l'extension PRF (base64url), ou null.
function prfValues(values) {
  const first = str(values?.first, 2048);
  return first ? { first, second: str(values?.second, 2048) } : null;
}

// `extensions.prf` de la page (passkey-codec.js), réduit à sa forme.
export function prfRequest(prf) {
  if (!prf || typeof prf !== "object") return null;
  const byCredential = {};
  const entries = prf.eval_by_credential && typeof prf.eval_by_credential === "object"
    ? Object.entries(prf.eval_by_credential).slice(0, 64) : [];
  for (const [id, values] of entries) {
    const parsed = prfValues(values);
    if (parsed && /^[A-Za-z0-9_-]{1,1024}$/.test(id)) byCredential[id] = parsed;
  }
  return { eval: prfValues(prf.eval), eval_by_credential: byCredential };
}

// La commande pour Verrou, ou null pour une demande inconnue.
export function passkeyCommand(message, url) {
  const rp_id = str(message.rp_id, 253);
  switch (message.kind) {
    case "passkeyList":
      return { cmd: "passkey_list", url, rp_id, allow: strings(message.allow) };
    case "passkeyTargets":
      return { cmd: "passkey_targets", url, rp_id, exclude: strings(message.exclude) };
    case "passkeyGet":
      return {
        cmd: "passkey_get", url, rp_id, item: str(message.item), credential: str(message.credential),
        challenge: str(message.challenge), uv: Boolean(message.uv), prf: prfRequest(message.prf),
      };
    case "passkeyCreate":
      return {
        cmd: "passkey_create", url, rp_id, rp_name: str(message.rp_name, 256),
        user_id: str(message.user_id), user_name: str(message.user_name, 256),
        user_display_name: str(message.user_display_name, 256), challenge: str(message.challenge),
        algorithms: Array.isArray(message.algorithms) ? message.algorithms.filter(Number.isInteger).slice(0, 16) : [],
        exclude: strings(message.exclude), uv: Boolean(message.uv), attestation: str(message.attestation, 32),
        item: str(message.item), prf: prfRequest(message.prf),
      };
    default:
      return null;
  }
}

// La réponse déchiffrée de Verrou → ce qu'attend passkeys.js.
export function passkeyResult(reply) {
  const { id, result, ...data } = reply;
  switch (result) {
    case "locked":
      return { state: "locked" };
    case "passkeys":
      return { state: "unlocked", items: data.items ?? [] };
    case "passkey_targets":
      return { state: "unlocked", excluded: Boolean(data.excluded), logins: data.logins ?? [] };
    case "assertion":
    case "registration":
      return { ok: true, credential: data };
    case "confirm":
      return { ok: false, state: "confirm" };
    default:
      return {
        ok: false,
        state: data.reason === "cette passkey est déjà dans Verrou" ? "exists" : (result ?? "denied"),
        reason: data.reason,
      };
  }
}
