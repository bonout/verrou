// Passkeys in the page (main frame): receives the `navigator.credentials`
// requests from passkey-page.js, offers Verrou's passkeys for this site, or
// to save a new one, and gives the answer back to the page.
//
// The window lives in a closed shadow DOM and only obeys real clicks
// (`isTrusted`): the page can ask, never choose on behalf of the user. The
// service worker adds the tab's address; Verrou checks the site (`rpId`),
// signs, and keeps the private key.
//
// Autofill (`mediation: "conditional"`): the request stays pending, and the
// pill of content.js (same isolated world, out of reach of the page) first
// offers Verrou's passkey for this site, through
// `globalThis.__verrouPasskeyMenu`. Nothing for this site, or Verrou absent:
// the request goes to the browser.
//
// When an explicit request (create, get) goes to the browser because Verrou
// can't take it (unreachable, extension not linked or outdated, key type
// not supported), a discreet notice says so: never a silent fallback.

(() => {
  if (window !== top || globalThis.__verrouPasskeyMenu) return;
  // Extension API: `browser` (Firefox), otherwise `chrome` (Brave). The test on
  // `runtime.id` rules out a page element named "browser" (see browser.js).
  const ext = globalThis.browser?.runtime?.id ? globalThis.browser : globalThis.chrome;
  // Text of the interface in the browser's language (extension/_locales).
  const t = (name, ...substitutions) => ext.i18n.getMessage(name, substitutions.map(String));

  const origin = location.origin;
  const RETRY_MS = 1000;
  const RETRIES = 90;

  // MARK: Messages

  async function send(message) {
    try {
      return await ext.runtime.sendMessage(message);
    } catch {
      // Extension reloaded (update): this script is orphaned, the page must
      // be reloaded to get Verrou back.
      return { state: ext?.runtime?.id ? "offline" : "outdated" };
    }
  }

  // The explicit request in progress (one at a time, like the browser), and
  // the autofill request, which waits for a choice in the pill.
  let current = null;
  let conditional = null;
  const listeners = new Set();

  function changed() {
    for (const listener of listeners) {
      try {
        listener();
      } catch {
        // A failing subscriber doesn't stop the others.
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
      // Our own copy: in Firefox, the page's objects are only seen through
      // "Xrays"; the request (strings, numbers, lists) copies without loss.
      let copy;
      try {
        copy = JSON.parse(JSON.stringify(data.request));
      } catch {
        return;
      }
      const request = { id: data.id, kind: data.kind, request: copy, done: false };
      // A new request replaces the pending autofill, as in the browser.
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
      // Cancelled by the page (AbortSignal): nothing to answer, the page has
      // already rejected its promise.
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

  // MARK: Window

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

  // Only obeys real clicks.
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
    // The request whose progress the window shows (autofill).
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

  // Let the browser do it (or a security key, a phone…).
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
      head(title, reason || t("verrouNotResponding")),
      actions(
        button(t("close"), "", () => cancel(request)),
        button(t("passkeyUseBrowser"), "primary", () => toBrowser(request)),
      ),
    );
  }

  // MARK: Notice of fallback to the browser

  // Read once, now: once the extension is reloaded ("outdated"), this
  // orphaned script may no longer reach its messages.
  const NOTICES = {
    offline: [t("passkeyOfflineTitle"), t("passkeyOfflineHint", t("settingBridge"))],
    unpaired: [t("passkeyUnpairedTitle"), t("passkeyUnpairedHint")],
    outdated: [t("passkeyOutdatedTitle"), t("passkeyOutdatedHint")],
    algorithm: [t("passkeyAlgorithmTitle"), t("passkeyAlgorithmHint")],
  };
  const OTHER_NOTICE = t("passkeyOtherTitle");
  const NOT_RESPONDING = t("verrouNotResponding");
  const OK = t("ok");

  // Discreet notice, which blocks nothing and goes away by itself.
  function notice(kind, reason) {
    const [title, hint] = NOTICES[kind] ?? [OTHER_NOTICE, reason || NOT_RESPONDING];
    panel.owner = null;
    panel.show(head(title, hint), actions(button(OK, "", () => panel.close())));
    panel.close(8000);
  }

  // Fallback to the browser because Verrou can't take the request: say so.
  function fallback(request, state, reason) {
    answer(request, "browser");
    notice(state, reason);
  }

  // Verrou locked: offer to unlock it, then resume.
  function locked(request, resume) {
    panel.show(
      head(t("passkeyLockedTitle"), siteOf(request)),
      actions(
        button(t("passkeyUseBrowser"), "quiet", () => toBrowser(request)),
        button(t("cancel"), "", () => cancel(request)),
        button(t("unlock"), "primary", async () => {
          await send({ kind: "unlock" });
          panel.show(head(t("unlockWait"), t("unlockHint")));
          resume(0);
        }),
      ),
    );
  }

  // Tries `attempt` again while Verrou is locked or waits for a
  // confirmation (protected item), a minute and a half at most.
  function retryLater(request, attempt, tries) {
    if (request.done) return;
    if (tries >= RETRIES) {
      failure(request, t("passkeyTimedOut"), siteOf(request));
      return;
    }
    setTimeout(() => attempt(tries + 1), RETRY_MS);
  }

  // MARK: Sign in (navigator.credentials.get)

  async function signIn(request, tries = 0) {
    const { rp_id, allow } = request.request;
    const list = await send({ kind: "passkeyList", rp_id, allow });
    if (request.done) return;
    if (list.state === "locked") {
      if (tries === 0) locked(request, (n) => retryLater(request, (t) => signIn(request, t), n));
      else retryLater(request, (t) => signIn(request, t), tries);
      return;
    }
    // Nothing in Verrou for this site: the browser, straight away.
    if (list.state === "unlocked" && !list.items?.length) {
      toBrowser(request);
      return;
    }
    // Verrou absent, not linked…: the browser, saying so.
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
      head(t("passkeySignInTitle"), siteOf(request)),
      rows,
      actions(
        button(t("passkeyOtherDevice"), "quiet", () => toBrowser(request)),
        button(t("cancel"), "", () => cancel(request)),
      ),
    );
  }

  async function use(request, item, tries = 0) {
    if (request.done) return;
    if (tries === 0) {
      panel.owner = request;
      panel.show(head(t("passkeySigningIn"), `${item.user_name || item.title} · ${siteOf(request)}`));
    }
    const { rp_id, challenge, uv, prf } = request.request;
    const reply = await send({ kind: "passkeyGet", rp_id, item: item.item, credential: item.credential, challenge, uv, prf });
    if (request.done) return;
    if (reply.ok) {
      panel.close();
      answer(request, "credential", reply.credential);
    } else if (reply.state === "confirm" || reply.state === "locked") {
      // Protected item: Verrou asks for confirmation; we try again.
      if (tries === 0) panel.show(head(t("confirmInVerrouWait"), item.title));
      retryLater(request, (t) => use(request, item, t), tries);
    } else {
      failure(request, t("passkeySignInFailed"), reply.reason);
    }
  }

  // MARK: Register (navigator.credentials.create)

  async function register(request, tries = 0) {
    const { rp_id, exclude, algorithms } = request.request;
    // Verrou only creates ES256 keys.
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
        head(t("passkeyExists"), `${user} · ${siteOf(request)}`),
        actions(button(t("close"), "primary", () => {
          panel.close();
          answer(request, "exists");
        })),
      );
      return;
    }
    // Where to save it: the site's login with the same username, otherwise
    // a new login.
    const choices = [
      ...targets.logins.map((login) => ({
        item: login.id,
        title: login.title,
        subtitle: [login.username, login.has_passkey ? t("passkeyReplaces") : ""].filter(Boolean).join(" · "),
      })),
      { item: null, title: t("newLogin"), subtitle: siteOf(request) },
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
        head(t("passkeySaveTitle"), `${user || t("passkeyNoName")} · ${siteOf(request)}`),
        rows,
        actions(
          button(t("passkeyUseBrowser"), "quiet", () => toBrowser(request)),
          button(t("cancel"), "", () => cancel(request)),
          button(t("save"), "primary", () => save(request, choices[selected])),
        ),
      );
    };
    render();
  }

  async function save(request, choice) {
    if (request.done) return;
    panel.show(head(t("saving"), siteOf(request)));
    const reply = await send({ kind: "passkeyCreate", ...request.request, item: choice.item });
    if (request.done) return;
    if (reply.ok) {
      answer(request, "credential", reply.credential);
      panel.show(head(t("passkeySaved"), choice.item ? choice.title : siteOf(request)));
      panel.close(2500);
    } else if (reply.state === "exists") {
      panel.close();
      answer(request, "exists");
    } else {
      failure(request, t("saveFailed"), reply.state === "locked" ? t("verrouLocked") : reply.reason);
    }
  }

  // MARK: Autofill (mediation: "conditional")

  // Verrou's passkeys for the pending request: `ready` (with `items`),
  // `locked` (Verrou to unlock first) or `none`. Nothing for this site, or
  // Verrou unreachable: the request goes to the browser, whose autofill
  // takes over (no notice: the user asked for nothing).
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

  // For the pill of content.js (same isolated world: the page has no access to it).
  globalThis.__verrouPasskeyMenu = Object.freeze({
    // The passkeys to offer in the pill (read again: Verrou may have been
    // unlocked in the meantime).
    entries: () => conditionalEntries(conditional),
    // Chosen in the pill, with a real click or a real key: the same
    // signature as an explicit sign-in (Touch ID, protected item…).
    choose(credential) {
      const request = conditional;
      const item = request?.items?.find((i) => i.credential === credential);
      if (!request || request.done || !item) return false;
      use(request, item);
      return true;
    },
    // Called when the pending request arrives, changes or ends.
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  });
})();
