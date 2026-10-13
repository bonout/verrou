// Dans chaque page (et chaque cadre) : repère les champs de connexion et
// propose, sous le champ, les identifiants de Verrou pour ce site.
//
// Le menu vit dans un shadow DOM fermé : la page ne peut ni le lire ni le
// modifier, et seuls les clics réels (`isTrusted`) le déclenchent. Les
// secrets n'arrivent qu'au moment du remplissage, pour l'élément choisi.

(() => {
  if (globalThis.__verrouContent) return;
  globalThis.__verrouContent = true;

  const USERNAME_HINT = /user|login|e-?mail|identifiant|courriel|account|compte|pseudo|nom d.utilisateur/i;
  const OTP_HINT = /otp|totp|2fa|mfa|one.?time|verification|vérification|authenticat|security.?code|code/i;
  const TEXT_TYPES = new Set(["text", "email", "tel", ""]);

  // MARK: Champs

  function visible(input) {
    const box = input.getBoundingClientRect();
    if (box.width < 2 || box.height < 2) return false;
    const style = getComputedStyle(input);
    return style.visibility !== "hidden" && style.display !== "none" && style.opacity !== "0";
  }

  function usable(input) {
    return input instanceof HTMLInputElement && !input.disabled && !input.readOnly && visible(input);
  }

  function scopeOf(input) {
    return input.form ?? input.closest("form") ?? document;
  }

  function inputsOf(scope) {
    return [...scope.querySelectorAll("input")].filter(usable);
  }

  function hintOf(input) {
    return [input.name, input.id, input.placeholder, input.getAttribute("aria-label"),
      input.labels?.[0]?.textContent].filter(Boolean).join(" ");
  }

  const isLoginPassword = (input) =>
    input.type === "password" && !/new-password/i.test(input.autocomplete);

  // « username », « password », « otp » ou null.
  function classify(input) {
    if (!usable(input)) return null;
    const type = (input.getAttribute("type") ?? "text").toLowerCase();
    const autocomplete = (input.autocomplete || "").toLowerCase();
    if (type === "password") return isLoginPassword(input) ? "password" : null;
    if (!TEXT_TYPES.has(type)) return null;
    if (autocomplete.includes("one-time-code")) return "otp";
    if (/\b(username|email)\b/.test(autocomplete) && !autocomplete.includes("new")) return "username";
    const hint = hintOf(input);
    const inputs = inputsOf(scopeOf(input));
    const password = inputs.find(isLoginPassword);
    if (password) {
      // Le champ texte qui précède le mot de passe est l'identifiant.
      const before = inputs.slice(0, inputs.indexOf(password))
        .filter((i) => TEXT_TYPES.has((i.getAttribute("type") ?? "text").toLowerCase()));
      if (before.at(-1) === input || type === "email" || USERNAME_HINT.test(hint)) return "username";
      return null;
    }
    // Connexion en plusieurs étapes : l'identifiant seul sur la page.
    if (type === "email" || USERNAME_HINT.test(hint)) return "username";
    const short = input.maxLength > 0 && input.maxLength <= 8;
    if (OTP_HINT.test(hint) && (short || input.inputMode === "numeric")) return "otp";
    return null;
  }

  let filling = false;

  function setValue(input, value) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    input.focus({ preventScroll: true });
    setter.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // Remplit le formulaire de `anchor` (ou la page) avec `credentials`.
  function apply(credentials, anchor) {
    filling = true;
    try {
      const inputs = inputsOf(anchor ? scopeOf(anchor) : document);
      if (anchor && classify(anchor) === "otp") {
        if (credentials.totp) setValue(anchor, credentials.totp);
        return;
      }
      const username = inputs.find((i) => classify(i) === "username");
      const password = inputs.find(isLoginPassword);
      if (credentials.username && username) setValue(username, credentials.username);
      if (credentials.password && password) setValue(password, credentials.password);
      if (!username && !password) {
        const otp = inputs.find((i) => classify(i) === "otp");
        if (otp && credentials.totp) setValue(otp, credentials.totp);
      }
      (password ?? username)?.focus({ preventScroll: true });
    } finally {
      setTimeout(() => { filling = false; }, 50);
    }
  }

  // MARK: Messages vers le service worker

  async function send(message) {
    try {
      return await chrome.runtime.sendMessage(message);
    } catch {
      return { state: "offline" };
    }
  }

  // MARK: Menu

  const STYLE = `
    :host { all: initial; position: absolute; z-index: 2147483647; }
    .menu {
      font: 13px/1.35 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: #1d1d1f; background: rgba(255,255,255,.98);
      border: 1px solid rgba(0,0,0,.12); border-radius: 10px;
      box-shadow: 0 10px 30px rgba(0,0,0,.18); overflow: hidden; min-width: 260px;
    }
    .row { display: flex; align-items: center; gap: 10px; padding: 8px 10px; cursor: default; }
    .row.selected { background: #5b5bd6; color: #fff; }
    .row.selected .sub { color: rgba(255,255,255,.8); }
    .badge {
      flex: none; width: 26px; height: 26px; border-radius: 7px; display: grid; place-items: center;
      color: #fff; font-weight: 700; background: linear-gradient(135deg, #7b7bf0, #4b4bc4);
    }
    .text { min-width: 0; }
    .title, .sub { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .title { font-weight: 600; }
    .sub { color: #6e6e73; font-size: 12px; }
    .footer { padding: 5px 10px; font-size: 11px; color: #8e8e93; border-top: 1px solid rgba(0,0,0,.08); }
    @media (prefers-color-scheme: dark) {
      .menu { color: #f5f5f7; background: rgba(40,40,44,.98); border-color: rgba(255,255,255,.14); }
      .sub, .footer { color: #a1a1a6; }
      .footer { border-color: rgba(255,255,255,.1); }
    }
  `;

  const menu = {
    host: null,
    root: null,
    anchor: null,
    kind: null,
    rows: [],
    selected: 0,
    poll: null,

    ensure() {
      if (this.host) return;
      this.host = document.createElement("verrou-menu");
      this.root = this.host.attachShadow({ mode: "closed" });
      const style = document.createElement("style");
      style.textContent = STYLE;
      this.root.append(style);
    },

    get open() {
      return Boolean(this.host?.isConnected);
    },

    show(anchor, kind, rows) {
      this.ensure();
      this.anchor = anchor;
      this.kind = kind;
      this.rows = rows;
      this.selected = 0;
      this.render();
      if (!this.host.isConnected) document.documentElement.append(this.host);
      this.place();
    },

    render() {
      this.root.querySelector(".menu")?.remove();
      const box = document.createElement("div");
      box.className = "menu";
      box.setAttribute("role", "listbox");
      this.rows.forEach((row, index) => {
        const line = document.createElement("div");
        line.className = `row${index === this.selected ? " selected" : ""}`;
        line.setAttribute("role", "option");
        const badge = document.createElement("div");
        badge.className = "badge";
        badge.textContent = row.badge;
        const text = document.createElement("div");
        text.className = "text";
        const title = document.createElement("div");
        title.className = "title";
        title.textContent = row.title;
        const sub = document.createElement("div");
        sub.className = "sub";
        sub.textContent = row.subtitle ?? "";
        text.append(title, sub);
        line.append(badge, text);
        // mousedown : garder le curseur dans le champ de la page.
        line.addEventListener("mousedown", (event) => {
          event.preventDefault();
          if (event.isTrusted) this.choose(index);
        });
        line.addEventListener("mousemove", () => {
          if (this.selected !== index) {
            this.selected = index;
            this.render();
          }
        });
        box.append(line);
      });
      const footer = document.createElement("div");
      footer.className = "footer";
      footer.textContent = "Verrou";
      box.append(footer);
      this.root.append(box);
    },

    place() {
      if (!this.open || !this.anchor) return;
      const box = this.anchor.getBoundingClientRect();
      this.host.style.left = `${box.left + scrollX}px`;
      this.host.style.top = `${box.bottom + scrollY + 4}px`;
      this.host.style.width = `${Math.max(box.width, 260)}px`;
    },

    hide() {
      clearInterval(this.poll);
      this.poll = null;
      this.host?.remove();
      this.anchor = null;
    },

    move(offset) {
      if (!this.rows.length) return;
      this.selected = (this.selected + offset + this.rows.length) % this.rows.length;
      this.render();
    },

    async choose(index) {
      const row = this.rows[index];
      const anchor = this.anchor;
      if (!row || !anchor) return;
      if (row.action === "unlock") {
        await send({ kind: "unlock" });
        this.rows = [{ badge: "…", title: "Déverrouillez Verrou", subtitle: "Touch ID ou mot de passe principal" }];
        this.render();
        this.waitForUnlock(anchor, this.kind);
        return;
      }
      const credentials = await send({ kind: "fill", item: row.id });
      this.hide();
      if (credentials?.ok) apply(credentials, anchor);
    },

    // Après « Déverrouiller » : les identifiants apparaissent dès que Verrou est ouvert.
    waitForUnlock(anchor, kind) {
      clearInterval(this.poll);
      let tries = 0;
      this.poll = setInterval(async () => {
        tries += 1;
        if (tries > 90 || this.anchor !== anchor) {
          clearInterval(this.poll);
          return;
        }
        const reply = await send({ kind: "suggest" });
        if (reply.state === "unlocked") {
          clearInterval(this.poll);
          const rows = rowsFor(reply, kind);
          if (rows.length && this.anchor === anchor) this.show(anchor, kind, rows);
          else this.hide();
        }
      }, 1000);
    },
  };

  function rowsFor(reply, kind) {
    if (reply.state === "locked") {
      return [{ action: "unlock", badge: "🔒", title: "Déverrouiller Verrou", subtitle: "pour remplir ce formulaire" }];
    }
    if (reply.state !== "unlocked") return [];
    return reply.items
      .filter((item) => kind !== "otp" || item.has_totp)
      .map((item) => ({
        id: item.id,
        badge: (item.title.trim()[0] ?? "?").toUpperCase(),
        title: kind === "otp" ? `Code de ${item.title}` : item.title,
        subtitle: item.username,
      }));
  }

  async function offer(input) {
    const kind = classify(input);
    if (!kind) return;
    const reply = await send({ kind: "suggest" });
    if (document.activeElement !== input) return;
    // Verrouillé : on ne le signale que sur un vrai formulaire de connexion.
    if (reply.state === "locked" && kind === "otp") return;
    const rows = rowsFor(reply, kind);
    if (rows.length) menu.show(input, kind, rows);
    else menu.hide();
  }

  // MARK: Écouteurs

  document.addEventListener("focusin", (event) => {
    if (filling) return;
    const target = event.composedPath()[0];
    if (target instanceof HTMLInputElement) offer(target);
  }, true);

  document.addEventListener("focusout", (event) => {
    if (event.target === menu.anchor) setTimeout(() => {
      if (document.activeElement !== menu.anchor) menu.hide();
    }, 120);
  }, true);

  document.addEventListener("mousedown", (event) => {
    // Clic sur le champ déjà actif après « Échap » : on rouvre.
    const target = event.composedPath()[0];
    if (event.isTrusted && target instanceof HTMLInputElement && target === document.activeElement
      && !menu.open && !filling) offer(target);
  }, true);

  document.addEventListener("keydown", (event) => {
    if (!menu.open || event.target !== menu.anchor) return;
    const keys = {
      ArrowDown: () => menu.move(1),
      ArrowUp: () => menu.move(-1),
      Enter: () => menu.choose(menu.selected),
      Escape: () => menu.hide(),
    };
    const action = keys[event.key];
    if (!action) return;
    event.preventDefault();
    event.stopPropagation();
    action();
  }, true);

  addEventListener("scroll", () => menu.place(), true);
  addEventListener("resize", () => menu.place());

  // Remplissage demandé depuis la fenêtre de l'extension (cadre principal).
  chrome.runtime.onMessage.addListener((message) => {
    if (message?.kind !== "apply" || window !== top) return;
    const active = document.activeElement;
    apply(message.credentials, active instanceof HTMLInputElement && classify(active) ? active : null);
  });
})();
