// Dans la page (monde MAIN), avant ses propres scripts : les demandes de
// passkey (`navigator.credentials.create` et `.get` avec `publicKey`) passent
// d'abord par Verrou. passkeys.js (le script de contenu) les montre à
// l'utilisateur ; s'il préfère le navigateur, ou si Verrou n'a rien pour ce
// site, l'implémentation d'origine prend le relais avec les mêmes options.
//
// Remplissage automatique (`mediation: "conditional"`) : la demande reste en
// attente chez Verrou, qui propose ses passkeys dans sa pastille en haut de
// la page (content.js) ; sans passkey de Verrou pour ce site, ou sans
// Verrou, elle passe au navigateur, dont le remplissage marche comme avant.
//
// Ce script vit dans le monde de la page : il ne détient rien de secret et
// n'est cru sur rien. Il ne fait que relayer des options que la page aurait
// pu passer elle-même au navigateur ; l'adresse, Verrou la tient du
// navigateur, et rien ne se fait sans un vrai clic dans la fenêtre de Verrou.

(() => {
  const codec = globalThis.__verrouPasskeyCodec;
  delete globalThis.__verrouPasskeyCodec;
  const container = globalThis.navigator?.credentials;
  if (!codec || !container || globalThis.PublicKeyCredential === undefined) return;

  const nativeCreate = container.create.bind(container);
  const nativeGet = container.get.bind(container);
  const origin = location.origin;
  const prefix = `${Math.random().toString(36).slice(2)}:`;
  const pending = new Map();
  let next = 0;

  addEventListener("message", (event) => {
    if (event.source !== window || event.data?.verrouPasskey !== "reply") return;
    const settle = pending.get(event.data.id);
    if (settle) settle(event.data);
  });

  // Demande à passkeys.js (`create`, `get` ou `conditional`) ; la réponse :
  // `credential`, `browser`, `exists` ou `cancelled`.
  function ask(kind, request, signal) {
    return new Promise((resolve, reject) => {
      next += 1;
      const id = `${prefix}${next}`;
      const abort = () => {
        pending.delete(id);
        postMessage({ verrouPasskey: "cancel", id }, origin);
        reject(signal.reason ?? new DOMException("Opération annulée.", "AbortError"));
      };
      if (signal?.aborted) {
        abort();
        return;
      }
      signal?.addEventListener("abort", abort, { once: true });
      pending.set(id, (reply) => {
        pending.delete(id);
        signal?.removeEventListener("abort", abort);
        resolve(reply);
      });
      postMessage({ verrouPasskey: "request", id, kind, request }, origin);
    });
  }

  function outcome(reply, fallback, build) {
    switch (reply.outcome) {
      case "credential":
        return build(reply.credential);
      case "browser":
        return fallback();
      case "exists":
        throw new DOMException("Une passkey de ce compte est déjà enregistrée.", "InvalidStateError");
      default:
        throw new DOMException("L'opération a été annulée ou refusée.", "NotAllowedError");
    }
  }

  async function create(options) {
    const publicKey = options?.publicKey;
    if (!publicKey) return nativeCreate(options);
    let request;
    try {
      request = codec.createRequest(publicKey);
    } catch {
      return nativeCreate(options);
    }
    const reply = await ask("create", request, options.signal);
    return outcome(reply, () => nativeCreate(options),
      (credential) => codec.registrationCredential(credential, {
        credProps: Boolean(publicKey.extensions?.credProps),
        prf: Boolean(publicKey.extensions?.prf),
      }));
  }

  async function get(options) {
    const publicKey = options?.publicKey;
    if (!publicKey) return nativeGet(options);
    let request;
    try {
      request = codec.getRequest(publicKey);
    } catch {
      return nativeGet(options);
    }
    // Remplissage automatique : proposé dans la pastille de Verrou.
    const kind = options.mediation === "conditional" ? "conditional" : "get";
    const reply = await ask(kind, request, options.signal);
    return outcome(reply, () => nativeGet(options), (credential) => codec.assertionCredential(credential));
  }

  for (const [name, method] of [["create", create], ["get", get]]) {
    Object.defineProperty(container, name, {
      value: function (options) { return method(options); },
      writable: true,
      configurable: true,
    });
  }
})();
