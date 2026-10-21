// In the page (MAIN world), before its own scripts: passkey requests
// (`navigator.credentials.create` and `.get` with `publicKey`) go through
// Verrou first. passkeys.js (the content script) shows them to the user; if
// they prefer the browser, or if Verrou has nothing for this site, the
// original implementation takes over with the same options.
//
// Autofill (`mediation: "conditional"`): the request stays pending at
// Verrou, which offers its passkeys in its pill at the top of the page
// (content.js); without a Verrou passkey for this site, or without Verrou,
// it goes to the browser, whose autofill works as before.
//
// This script lives in the page's world: it holds nothing secret and is
// trusted on nothing. It only relays options the page could have passed to
// the browser itself; the address, Verrou gets from the browser, and
// nothing happens without a real click in Verrou's window.

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

  // Asks passkeys.js (`create`, `get` or `conditional`); the answer:
  // `credential`, `browser`, `exists` or `cancelled`.
  function ask(kind, request, signal) {
    return new Promise((resolve, reject) => {
      next += 1;
      const id = `${prefix}${next}`;
      const abort = () => {
        pending.delete(id);
        postMessage({ verrouPasskey: "cancel", id }, origin);
        reject(signal.reason ?? new DOMException("The operation was aborted.", "AbortError"));
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
        throw new DOMException("A passkey for this account is already registered.", "InvalidStateError");
      default:
        throw new DOMException("The operation either timed out or was not allowed.", "NotAllowedError");
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
    // Autofill: offered in Verrou's pill.
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
