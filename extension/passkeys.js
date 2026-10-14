// Passkeys dans la page (cadre principal) : reçoit de passkey-page.js les
// demandes de `navigator.credentials`, propose les passkeys de Verrou pour
// ce site, ou d'en enregistrer une nouvelle, et rend la réponse à la page.
//
// La fenêtre vit dans un shadow DOM fermé et n'obéit qu'aux clics réels
// (`isTrusted`) : la page peut demander, jamais choisir à la place de
// l'utilisateur. Le service worker ajoute l'adresse de l'onglet ; Verrou
// vérifie le site (`rpId`), signe, et garde la clé privée.
//
// Remplissage automatique (`mediation: "conditional"`) : la demande reste en
// attente, et la pastille de content.js (même monde isolé, hors de portée de
// la page) propose d'abord la passkey de Verrou pour ce site, par
// `globalThis.__verrouPasskeyMenu`. Rien pour ce site, ou Verrou absent : la
// demande passe au navigateur.
//
// Quand une demande explicite (create, get) part au navigateur parce que
// Verrou ne peut pas la prendre (injoignable, extension non reliée ou
// périmée, type de clé non géré), un avis discret le dit : jamais de repli
// silencieux.

(() => {
  if (window !== top || globalThis.__verrouPasskeyMenu) return;
  // API d'extension : `browser` (Firefox), sinon `chrome` (Brave). Le test sur
  // `runtime.id` écarte un élément de la page nommé « browser » (voir browser.js).
  const ext = globalThis.browser?.runtime?.id ? globalThis.browser : globalThis.chrome;

  const origin = location.origin;
  const RETRY_MS = 1000;
  const RETRIES = 90;

  // MARK: Messages

  async function send(message) {
    try {
      return await ext.runtime.sendMessage(message);
    } catch {
      // Extension rechargée (mise à jour) : ce script est orphelin, la page
      // doit être rechargée pour retrouver Verrou.
      return { state: ext?.runtime?.id ? "offline" : "outdated" };
    }
  }

  // La demande explicite en cours (une à la fois, comme le navigateur), et la
  // demande de remplissage automatique, qui attend un choix dans la pastille.
  let current = null;
  let conditional = null;
  const listeners = new Set();

  function changed() {
    for (const listener of listeners) {
      try {
        listener();
      } catch {
        // Un abonné en erreur n'empêche pas les autres.
      }
    }
  }

  function answer(request, outcome, credential) {
    if (request.done) return;
    request.done = true;
    if (current === request) current = null;
    if (conditional === request) {
      conditional = null;
      changed();
    }
    postMessage({ verrouPasskey: "reply", id: request.id, outcome, credential }, origin);
  }

  addEventListener("message", (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (data?.verrouPasskey === "request" && typeof data.id === "string"
      && ["create", "get", "conditional"].includes(data.kind) && data.request && typeof data.request === "object") {
      // Une copie à nous : dans Firefox, les objets de la page ne se voient
      // qu'à travers des « Xray » ; la requête (chaînes, nombres, listes) se
      // copie sans perte.
      let copy;
      try {
        copy = JSON.parse(JSON.stringify(data.request));
      } catch {
        return;
      }
      const request = { id: data.id, kind: data.kind, request: copy, done: false };
      // Une nouvelle demande remplace le remplissage automatique en attente,
      // comme dans le navigateur.
      if (conditional) answer(conditional, "cancelled");
      if (data.kind === "conditional") {
        conditional = request;
        prepareConditional(request);
        return;
      }
      if (current) {
        answer(current, "cancelled");
        panel.close();
      }
      current = request;
      (data.kind === "get" ? signIn : register)(current);
    } else if (data?.verrouPasskey === "cancel") {
      // Annulée par la page (AbortSignal) : rien à répondre, la page a déjà
      // rejeté sa promesse.
      for (const request of [current, conditional]) {
        if (request?.id !== data.id) continue;
        request.done = true;
        if (request === current) {
          current = null;
          panel.close();
        } else {
          conditional = null;
          if (panel.owner === request) panel.close();
          changed();
        }
      }
    }
  });

  // MARK: Fenêtre

  const STYLE = `
    :host { all: initial; position: fixed; top: 12px; right: 12px; z-index: 2147483647; }
    .panel {
      width: 340px; padding: 12px 14px;
      font: 13px/1.35 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: #1d1d1f; background: rgba(255,255,255,.98);
      border: 1px solid rgba(0,0,0,.12); border-radius: 10px;
      box-shadow: 0 10px 30px rgba(0,0,0,.18);
    }
    .head { display: flex; gap: 10px; align-items: center; }
    .badge {
      flex: none; width: 26px; height: 26px; border-radius: 7px; display: grid; place-items: center;
      color: #fff; font-weight: 700; background: linear-gradient(135deg, #7b7bf0, #4b4bc4);
    }
    .text { min-width: 0; }
    .title { font-weight: 600; }
    .sub { color: #6e6e73; font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .list { margin-top: 10px; border-radius: 8px; overflow: hidden; border: 1px solid rgba(0,0,0,.08); }
    .row { display: flex; align-items: center; gap: 10px; padding: 7px 10px; cursor: default; }
    .row + .row { border-top: 1px solid rgba(0,0,0,.06); }
    .row:hover { background: rgba(91,91,214,.08); }
    .row.selected { background: #5b5bd6; color: #fff; }
    .row.selected .sub { color: rgba(255,255,255,.8); }
    .row .text { flex: 1; }
    .actions { display: flex; gap: 8px; justify-content: flex-end; flex-wrap: wrap; margin-top: 10px; }
    button {
      font: inherit; border: 0; border-radius: 7px; padding: 6px 11px; cursor: default;
      background: rgba(0,0,0,.06); color: inherit;
    }
    button.primary { background: #5b5bd6; color: #fff; font-weight: 600; }
    button.quiet { background: none; color: #8e8e93; padding: 6px 4px; margin-right: auto; }
    @media (prefers-color-scheme: dark) {
      .panel { color: #f5f5f7; background: rgba(40,40,44,.98); border-color: rgba(255,255,255,.14); }
      .sub { color: #a1a1a6; }
      .list { border-color: rgba(255,255,255,.1); }
      .row + .row { border-color: rgba(255,255,255,.08); }
      button { background: rgba(255,255,255,.1); }
      button.quiet { background: none; color: #a1a1a6; }
    }
  `;

  function div(className, text) {
    const node = document.createElement("div");
    node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  // N'obéit qu'aux vrais clics.
  function onTrustedClick(node, action) {
    node.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (event.isTrusted) action();
    });
    return node;
  }

  function button(label, className, action) {
    const node = document.createElement("button");
    node.className = className;
    node.textContent = label;
    return onTrustedClick(node, action);
  }

  function head(title, subtitle) {
    const box = div("head");
    const text = div("text");
    text.append(div("title", title), div("sub", subtitle));
    box.append(div("badge", "V"), text);
    return box;
  }

  function actions(...buttons) {
    const row = div("actions");
    row.append(...buttons);
    return row;
  }

  const panel = {
    host: null,
    root: null,
    timer: null,
    // La demande dont la fenêtre montre l'avancement (remplissage automatique).
    owner: null,

    show(...nodes) {
      if (!this.host) {
        this.host = document.createElement("verrou-passkey");
        this.root = this.host.attachShadow({ mode: "closed" });
        const style = document.createElement("style");
        style.textContent = STYLE;
        this.root.append(style);
      }
      clearTimeout(this.timer);
      this.root.querySelector(".panel")?.remove();
      const box = div("panel");
      box.setAttribute("role", "dialog");
      box.append(...nodes);
      this.root.append(box);
      if (!this.host.isConnected) document.documentElement.append(this.host);
    },

    close(after = 0) {
      clearTimeout(this.timer);
      this.timer = setTimeout(() => this.host?.remove(), after);
    },
  };

  const siteOf = (request) => request.request.rp_id || location.hostname;

  // Laisser faire le navigateur (ou une clé de sécurité, un téléphone…).
  function toBrowser(request) {
    panel.close();
    answer(request, "browser");
  }

  function cancel(request) {
    panel.close();
    answer(request, "cancelled");
  }

  function failure(request, title, reason) {
    if (request.done) return;
    panel.show(
      head(title, reason || "Verrou ne répond pas"),
      actions(
        button("Fermer", "", () => cancel(request)),
        button("Utiliser le navigateur", "primary", () => toBrowser(request)),
      ),
    );
  }

  // MARK: Avis de repli vers le navigateur

  const NOTICES = {
    offline: ["Verrou n'est pas joignable : la passkey est laissée au navigateur",
      "Ouvrez Verrou, et activez « Brave, Firefox et le terminal » dans ses réglages."],
    unpaired: ["L'extension n'est pas reliée à Verrou : la passkey est laissée au navigateur",
      "Reliez l'extension depuis son icône dans la barre d'outils."],
    outdated: ["Verrou vient d'être mis à jour : la passkey est laissée au navigateur",
      "Rechargez la page pour utiliser les passkeys de Verrou."],
    algorithm: ["Verrou ne gère pas ce type de clé : la passkey est laissée au navigateur",
      "Le site n'accepte pas les clés ES256, les seules que Verrou sait créer."],
  };

  // Avis discret, qui ne bloque rien et s'efface seul.
  function notice(kind, reason) {
    const [title, hint] = NOTICES[kind]
      ?? ["Verrou n'a pas pu prendre la demande : la passkey est laissée au navigateur", reason || "Verrou ne répond pas"];
    panel.owner = null;
    panel.show(head(title, hint), actions(button("OK", "", () => panel.close())));
    panel.close(8000);
  }

  // Repli vers le navigateur parce que Verrou ne peut pas prendre la demande :
  // le dire.
  function fallback(request, state, reason) {
    answer(request, "browser");
    notice(state, reason);
  }

  // Verrou verrouillé : proposer de le déverrouiller, puis reprendre.
  function locked(request, resume) {
    panel.show(
      head("Passkey : Verrou est verrouillé", siteOf(request)),
      actions(
        button("Utiliser le navigateur", "quiet", () => toBrowser(request)),
        button("Annuler", "", () => cancel(request)),
        button("Déverrouiller", "primary", async () => {
          await send({ kind: "unlock" });
          panel.show(head("Déverrouillez Verrou…", "Touch ID ou mot de passe principal"));
          resume(0);
        }),
      ),
    );
  }

  // Réessaie `attempt` tant que Verrou est verrouillé ou attend une
  // confirmation (élément protégé), une minute et demie au plus.
  function retryLater(request, attempt, tries) {
    if (request.done) return;
    if (tries >= RETRIES) {
      failure(request, "Verrou n'a pas répondu à temps", siteOf(request));
      return;
    }
    setTimeout(() => attempt(tries + 1), RETRY_MS);
  }

  // MARK: Se connecter (navigator.credentials.get)

  async function signIn(request, tries = 0) {
    const { rp_id, allow } = request.request;
    const list = await send({ kind: "passkeyList", rp_id, allow });
    if (request.done) return;
    if (list.state === "locked") {
      if (tries === 0) locked(request, (n) => retryLater(request, (t) => signIn(request, t), n));
      else retryLater(request, (t) => signIn(request, t), tries);
      return;
    }
    // Rien dans Verrou pour ce site : le navigateur, sans détour.
    if (list.state === "unlocked" && !list.items?.length) {
      toBrowser(request);
      return;
    }
    // Verrou absent, non relié… : le navigateur, en le disant.
    if (list.state !== "unlocked") {
      fallback(request, list.state, list.reason);
      return;
    }
    const rows = div("list");
    for (const item of list.items) {
      const row = div("row");
      const text = div("text");
      text.append(div("title", item.user_name || item.title), div("sub", item.title));
      row.append(text);
      rows.append(onTrustedClick(row, () => use(request, item)));
    }
    panel.show(
      head("Se connecter avec une passkey de Verrou ?", siteOf(request)),
      rows,
      actions(
        button("Autre appareil ou navigateur", "quiet", () => toBrowser(request)),
        button("Annuler", "", () => cancel(request)),
      ),
    );
  }

  async function use(request, item, tries = 0) {
    if (request.done) return;
    if (tries === 0) {
      panel.owner = request;
      panel.show(head("Connexion…", `${item.user_name || item.title} · ${siteOf(request)}`));
    }
    const { rp_id, challenge, uv } = request.request;
    const reply = await send({ kind: "passkeyGet", rp_id, item: item.item, credential: item.credential, challenge, uv });
    if (request.done) return;
    if (reply.ok) {
      panel.close();
      answer(request, "credential", reply.credential);
    } else if (reply.state === "confirm" || reply.state === "locked") {
      // Élément protégé : Verrou demande la confirmation ; on réessaie.
      if (tries === 0) panel.show(head("Confirmez dans Verrou…", item.title));
      retryLater(request, (t) => use(request, item, t), tries);
    } else {
      failure(request, "Connexion impossible", reply.reason);
    }
  }

  // MARK: Enregistrer (navigator.credentials.create)

  async function register(request, tries = 0) {
    const { rp_id, exclude, algorithms } = request.request;
    // Verrou ne crée que des clés ES256.
    if (algorithms?.length && !algorithms.includes(-7)) {
      fallback(request, "algorithm");
      return;
    }
    const targets = await send({ kind: "passkeyTargets", rp_id, exclude });
    if (request.done) return;
    if (targets.state === "locked") {
      if (tries === 0) locked(request, (n) => retryLater(request, (t) => register(request, t), n));
      else retryLater(request, (t) => register(request, t), tries);
      return;
    }
    if (targets.state !== "unlocked") {
      fallback(request, targets.state, targets.reason);
      return;
    }
    const user = request.request.user_name || request.request.user_display_name || "";
    if (targets.excluded) {
      panel.show(
        head("Cette passkey est déjà dans Verrou", `${user} · ${siteOf(request)}`),
        actions(button("Fermer", "primary", () => {
          panel.close();
          answer(request, "exists");
        })),
      );
      return;
    }
    // Où l'enregistrer : l'identifiant du site au même nom d'utilisateur,
    // sinon un nouvel identifiant.
    const choices = [
      ...targets.logins.map((login) => ({
        item: login.id,
        title: login.title,
        subtitle: [login.username, login.has_passkey ? "remplace sa passkey" : ""].filter(Boolean).join(" · "),
      })),
      { item: null, title: "Nouvel identifiant", subtitle: siteOf(request) },
    ];
    let selected = choices.findIndex((c) => c.item && targets.logins
      .find((l) => l.id === c.item)?.username.toLowerCase() === user.toLowerCase());
    if (selected < 0) selected = choices.length - 1;
    const render = () => {
      const rows = div("list");
      choices.forEach((choice, index) => {
        const row = div(`row${index === selected ? " selected" : ""}`);
        const text = div("text");
        text.append(div("title", choice.title), div("sub", choice.subtitle));
        row.append(text);
        rows.append(onTrustedClick(row, () => {
          selected = index;
          render();
        }));
      });
      panel.show(
        head("Enregistrer une passkey dans Verrou ?", `${user || "sans nom"} · ${siteOf(request)}`),
        rows,
        actions(
          button("Utiliser le navigateur", "quiet", () => toBrowser(request)),
          button("Annuler", "", () => cancel(request)),
          button("Enregistrer", "primary", () => save(request, choices[selected])),
        ),
      );
    };
    render();
  }

  async function save(request, choice) {
    if (request.done) return;
    panel.show(head("Enregistrement…", siteOf(request)));
    const reply = await send({ kind: "passkeyCreate", ...request.request, item: choice.item });
    if (request.done) return;
    if (reply.ok) {
      answer(request, "credential", reply.credential);
      panel.show(head("Passkey enregistrée dans Verrou", choice.item ? choice.title : siteOf(request)));
      panel.close(2500);
    } else if (reply.state === "exists") {
      panel.close();
      answer(request, "exists");
    } else {
      failure(request, "Enregistrement impossible", reply.state === "locked" ? "Verrou est verrouillé" : reply.reason);
    }
  }

  // MARK: Remplissage automatique (mediation: "conditional")

  // Les passkeys de Verrou pour la demande en attente : `ready` (avec
  // `items`), `locked` (Verrou à déverrouiller d'abord) ou `none`. Rien pour
  // ce site, ou Verrou injoignable : la demande passe au navigateur, dont le
  // remplissage reprend la main (sans avis : l'utilisateur n'a rien demandé).
  async function conditionalEntries(request) {
    if (!request || request.done) return { state: "none" };
    const { rp_id, allow } = request.request;
    const list = await send({ kind: "passkeyList", rp_id, allow });
    if (request.done) return { state: "none" };
    if (list.state === "locked") return { state: "locked" };
    if (list.state !== "unlocked" || !list.items?.length) {
      answer(request, "browser");
      return { state: "none" };
    }
    request.items = list.items;
    return { state: "ready", items: list.items };
  }

  async function prepareConditional(request) {
    const entries = await conditionalEntries(request);
    if (entries.state !== "none") changed();
  }

  // Pour la pastille de content.js (même monde isolé : la page n'y a pas accès).
  globalThis.__verrouPasskeyMenu = Object.freeze({
    // Les passkeys à proposer dans la pastille (relues : Verrou a pu être
    // déverrouillé entre-temps).
    entries: () => conditionalEntries(conditional),
    // Choisie dans la pastille, d'un vrai clic ou d'une vraie touche : la même
    // signature qu'une connexion explicite (Touch ID, élément protégé…).
    choose(credential) {
      const request = conditional;
      const item = request?.items?.find((i) => i.credential === credential);
      if (!request || request.done || !item) return false;
      use(request, item);
      return true;
    },
    // Appelé quand la demande en attente arrive, change ou se termine.
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  });
})();
