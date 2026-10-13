// Dans chaque page (et chaque cadre) : repère les champs de connexion et
// propose, sous le champ, les identifiants de Verrou pour ce site ; sur un
// champ « nouveau mot de passe », un mot de passe fort ; après l'envoi d'un
// formulaire, d'enregistrer l'identifiant dans Verrou.
//
// Le menu et le bandeau vivent dans un shadow DOM fermé : la page ne peut ni
// les lire ni les modifier, et seuls les clics réels (`isTrusted`) les
// déclenchent. Les secrets n'arrivent qu'au moment du remplissage, pour
// l'élément choisi.

(() => {
  if (globalThis.__verrouContent) return;
  globalThis.__verrouContent = true;

  const USERNAME_HINT = /user|login|e-?mail|identifiant|courriel|account|compte|pseudo|nom d.utilisateur/i;
  const OTP_HINT = /otp|totp|2fa|mfa|one.?time|verification|vérification|authenticat|security.?code|code/i;
  const NEW_HINT = /new|nouveau|nouvelle|confirm|repeat|retype|again|verify|vérif|register|sign.?up|inscri|créer|create/i;
  const CURRENT_HINT = /current|old|actuel|ancien|existing/i;
  const SIGNUP_FORM_HINT = /register|sign.?up|inscri|create.?account|créer.?(un|votre).?compte|join/i;
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

  const typeOf = (input) => (input.getAttribute("type") ?? "text").toLowerCase();
  const isText = (input) => TEXT_TYPES.has(typeOf(input));

  function hintOf(input) {
    return [input.name, input.id, input.placeholder, input.getAttribute("aria-label"),
      input.labels?.[0]?.textContent].filter(Boolean).join(" ");
  }

  function formHint(scope) {
    if (scope === document) return "";
    const buttons = [...scope.querySelectorAll("button, input[type=submit]")]
      .map((b) => b.textContent || b.value).join(" ");
    return [scope.id, scope.getAttribute("name"), scope.getAttribute("action"), buttons].filter(Boolean).join(" ");
  }

  // Rôle de chaque champ mot de passe du formulaire : « current » (connexion,
  // ancien mot de passe) ou « new » (inscription, changement, confirmation).
  // `all` : aussi les champs masqués (le formulaire part, la page change).
  function passwordRoles(scope, all = false) {
    const fields = [...scope.querySelectorAll("input")]
      .filter((i) => typeOf(i) === "password" && (all ? !i.disabled : usable(i)));
    const roles = new Map();
    fields.forEach((input, index) => {
      const autocomplete = (input.autocomplete || "").toLowerCase();
      const hint = hintOf(input);
      let role;
      if (autocomplete.includes("new-password")) role = "new";
      else if (autocomplete.includes("current-password")) role = "current";
      else if (CURRENT_HINT.test(hint)) role = "current";
      else if (NEW_HINT.test(hint)) role = "new";
      // Un seul champ : connexion, sauf formulaire d'inscription.
      else if (fields.length === 1) role = SIGNUP_FORM_HINT.test(formHint(scope)) ? "new" : "current";
      // Deux : le mot de passe et sa confirmation. Trois : l'ancien, puis le nouveau deux fois.
      else if (fields.length === 2) role = "new";
      else role = index === 0 ? "current" : "new";
      roles.set(input, role);
    });
    return roles;
  }

  const roleOf = (input) => passwordRoles(scopeOf(input)).get(input) ?? null;

  // MARK: Cartes et adresses

  // Rôle d'un champ de carte ou d'adresse : d'abord `autocomplete`, sinon les
  // indices (nom, libellé…), en français et en anglais.
  const CARD_AUTOCOMPLETE = {
    "cc-name": "cardholder", "cc-number": "number", "cc-exp": "exp",
    "cc-exp-month": "exp_month", "cc-exp-year": "exp_year", "cc-csc": "code",
  };
  const CARD_HINTS = [
    ["exp", /mm\s*\/\s*(yy|aa)/i],
    ["number", /card.?num|cc.?num|num[ée]ro.*carte|carte.*num|cardnumber|n°.?de.?carte/i],
    ["code", /cvc|cvv|csc|cryptogramme|security.?code|code.?de.?s[ée]curit/i],
    ["exp_month", /exp.*(month|\bmm\b|mois)|mois.*exp/i],
    ["exp_year", /exp.*(year|\byy\b|\baa\b|ann[ée]e)|ann[ée]e.*exp/i],
    ["exp", /expir|exp.?date|date.?d.?exp/i],
    ["cardholder", /card.?holder|name.?on.?card|titulaire|nom.*carte|cc.?name/i],
  ];
  const IDENTITY_AUTOCOMPLETE = {
    "given-name": "first_name", "family-name": "last_name", name: "full_name", email: "email",
    tel: "phone", "tel-national": "phone", organization: "company", "street-address": "address1",
    "address-line1": "address1", "address-line2": "address2", "postal-code": "postal_code",
    "address-level2": "city", "address-level1": "state", country: "country", "country-name": "country",
  };
  const IDENTITY_HINTS = [
    ["address2", /address.?(2|line.?2)|compl[ée]ment|appartement|\bapt\b/i],
    ["address1", /address|adresse|street|\brue\b/i],
    ["postal_code", /zip|postal|\bcp\b|postcode/i],
    ["city", /city|ville|town|locality|commune/i],
    ["state", /state|province|r[ée]gion|county/i],
    ["country", /country|pays/i],
    ["first_name", /first.?name|pr[ée]nom|given/i],
    ["last_name", /last.?name|surname|family|nom.?de.?famille/i],
    ["full_name", /full.?name|nom.?complet|^\s*(name|nom)\s*$/i],
    ["company", /company|soci[ée]t[ée]|organi[sz]ation|entreprise/i],
    ["phone", /phone|t[ée]l[ée]phone|mobile|portable/i],
    ["email", /e-?mail|courriel/i],
  ];

  function fieldRole(element, table, hints) {
    const autocomplete = (element.getAttribute("autocomplete") ?? "").toLowerCase().trim().split(/\s+/).pop();
    if (table[autocomplete]) return table[autocomplete];
    const hint = hintOf(element);
    for (const [role, pattern] of hints) if (pattern.test(hint)) return role;
    if (table === IDENTITY_AUTOCOMPLETE && element instanceof HTMLInputElement) {
      if (typeOf(element) === "email") return "email";
      if (typeOf(element) === "tel") return "phone";
    }
    return null;
  }

  // Champs à remplir d'un formulaire : saisies visibles et listes déroulantes.
  function formFields(scope) {
    return [...scope.querySelectorAll("input, select")].filter((element) =>
      !element.disabled && (element instanceof HTMLSelectElement ? visible(element) : usable(element))
      && (element instanceof HTMLSelectElement || !["hidden", "password", "checkbox", "radio", "submit", "button"].includes(typeOf(element))));
  }

  // « card » ou « identity » (avec le rôle du champ), ou null.
  function formKindOf(input) {
    const card = fieldRole(input, CARD_AUTOCOMPLETE, CARD_HINTS);
    if (card) return { kind: "card", role: card };
    const scope = scopeOf(input);
    // Un formulaire de connexion reste un formulaire de connexion.
    if (scope.querySelector("input[type=password]")) return null;
    const role = fieldRole(input, IDENTITY_AUTOCOMPLETE, IDENTITY_HINTS);
    if (!role) return null;
    // Une adresse, pas un simple champ e-mail : trois champs d'identité au moins.
    const count = formFields(scope).filter((f) => fieldRole(f, IDENTITY_AUTOCOMPLETE, IDENTITY_HINTS)).length;
    return count >= 3 ? { kind: "identity", role } : null;
  }

  const MONTHS = ["jan", "f", "mar", "av|apr", "mai|may", "juin|jun", "juil|jul", "ao|aug", "sep", "oct", "nov", "d"];

  // Choisit l'option qui correspond à `value` (mois, année, pays…).
  function selectOption(select, role, value) {
    const wanted = String(value).trim().toLowerCase();
    const options = [...select.options];
    const matches = (option) => {
      const text = option.text.trim().toLowerCase();
      const optionValue = option.value.trim().toLowerCase();
      if (role === "exp_month") {
        const month = Number(wanted);
        return Number(optionValue) === month || Number(text) === month
          || new RegExp(`^(${MONTHS[month - 1]})`).test(text);
      }
      if (role === "exp_year") return optionValue.slice(-2) === wanted.slice(-2) || text.slice(-2) === wanted.slice(-2);
      return optionValue === wanted || text === wanted || (wanted.length > 3 && text.startsWith(wanted));
    };
    const option = options.find(matches);
    if (!option) return;
    select.value = option.value;
    select.dispatchEvent(new Event("input", { bubbles: true }));
    select.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // Remplit le formulaire de `anchor` avec une carte ou une identité.
  function applyForm(data, anchor) {
    withFilling(() => {
      const [table, hints] = data.kind === "card"
        ? [CARD_AUTOCOMPLETE, CARD_HINTS] : [IDENTITY_AUTOCOMPLETE, IDENTITY_HINTS];
      const values = {
        ...data,
        exp: data.exp_month && data.exp_year ? `${data.exp_month}/${data.exp_year.slice(-2)}` : null,
      };
      for (const field of formFields(scopeOf(anchor))) {
        const role = fieldRole(field, table, hints);
        let value = role ? values[role] : null;
        if (!value) continue;
        if (field instanceof HTMLSelectElement) {
          selectOption(field, role, value);
          continue;
        }
        if (role === "exp_year" && field.maxLength === 2) value = value.slice(-2);
        setValue(field, value);
      }
      anchor.focus({ preventScroll: true });
    });
  }
  const isLoginPassword = (input) => typeOf(input) === "password" && roleOf(input) === "current";

  // « username », « password », « new », « otp » ou null.
  function classify(input) {
    if (!usable(input)) return null;
    const type = typeOf(input);
    const autocomplete = (input.autocomplete || "").toLowerCase();
    if (type === "password") return roleOf(input) === "new" ? "new" : "password";
    const form = formKindOf(input);
    if (form) return form.kind;
    if (!isText(input)) return null;
    if (autocomplete.includes("one-time-code")) return "otp";
    if (/\b(username|email)\b/.test(autocomplete) && !autocomplete.includes("new")) return "username";
    const hint = hintOf(input);
    const inputs = inputsOf(scopeOf(input));
    const password = inputs.find((i) => typeOf(i) === "password");
    if (password) {
      // Le champ texte qui précède le mot de passe est l'identifiant.
      const before = inputs.slice(0, inputs.indexOf(password)).filter(isText);
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

  function withFilling(action) {
    filling = true;
    try {
      action();
    } finally {
      setTimeout(() => { filling = false; }, 50);
    }
  }

  // Remplit le formulaire de `anchor` (ou la page) avec `credentials`.
  function apply(credentials, anchor) {
    withFilling(() => {
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
    });
  }

  // Le mot de passe généré dans tous les champs « nouveau » du formulaire
  // (le mot de passe et sa confirmation).
  function applyGenerated(password, anchor) {
    withFilling(() => {
      for (const [input, role] of passwordRoles(scopeOf(anchor))) {
        if (role === "new") setValue(input, password);
      }
      anchor.focus({ preventScroll: true });
    });
  }

  // MARK: Messages vers le service worker

  async function send(message) {
    try {
      return await chrome.runtime.sendMessage(message);
    } catch {
      return { state: "offline" };
    }
  }

  // MARK: Style commun

  const STYLE = `
    :host { all: initial; position: absolute; z-index: 2147483647; }
    .menu, .banner {
      font: 13px/1.35 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: #1d1d1f; background: rgba(255,255,255,.98);
      border: 1px solid rgba(0,0,0,.12); border-radius: 10px;
      box-shadow: 0 10px 30px rgba(0,0,0,.18); overflow: hidden;
    }
    .menu { min-width: 260px; }
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
    .sub.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    .footer { padding: 5px 10px; font-size: 11px; color: #8e8e93; border-top: 1px solid rgba(0,0,0,.08); }
    .banner { width: 340px; padding: 12px 14px; }
    .banner .title { white-space: normal; }
    .head { display: flex; gap: 10px; align-items: center; }
    .actions { display: flex; gap: 8px; justify-content: flex-end; flex-wrap: wrap; margin-top: 10px; }
    button {
      font: inherit; border: 0; border-radius: 7px; padding: 6px 11px; cursor: default;
      background: rgba(0,0,0,.06); color: inherit;
    }
    button.primary { background: #5b5bd6; color: #fff; font-weight: 600; }
    button.quiet { background: none; color: #8e8e93; padding: 6px 4px; margin-right: auto; }
    @media (prefers-color-scheme: dark) {
      .menu, .banner { color: #f5f5f7; background: rgba(40,40,44,.98); border-color: rgba(255,255,255,.14); }
      .sub, .footer { color: #a1a1a6; }
      .footer { border-color: rgba(255,255,255,.1); }
      button { background: rgba(255,255,255,.1); }
      button.quiet { background: none; color: #a1a1a6; }
    }
  `;

  function shadowHost(tag) {
    const host = document.createElement(tag);
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = STYLE;
    root.append(style);
    return { host, root };
  }

  function div(className, text) {
    const node = document.createElement("div");
    node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  // Un bouton qui n'obéit qu'aux vrais clics.
  function trustedButton(label, className, action) {
    const button = document.createElement("button");
    button.className = className;
    button.textContent = label;
    button.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (event.isTrusted) action();
    });
    return button;
  }

  // MARK: Menu sous le champ

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
      ({ host: this.host, root: this.root } = shadowHost("verrou-menu"));
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
      const box = div("menu");
      box.setAttribute("role", "listbox");
      this.rows.forEach((row, index) => {
        const line = div(`row${index === this.selected ? " selected" : ""}`);
        line.setAttribute("role", "option");
        const text = div("text");
        text.append(div("title", row.title), div(`sub${row.mono ? " mono" : ""}`, row.subtitle ?? ""));
        line.append(div("badge", row.badge), text);
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
      box.append(div("footer", "Verrou"));
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
      if (row.form) {
        let reply = await send({ kind: "fillForm", item: row.id });
        if (reply?.state === "confirm") {
          this.rows = [{ badge: "🔐", title: "Confirmez dans Verrou", subtitle: `« ${row.title} » est protégé` }];
          this.render();
          reply = await this.retryUntilConfirmed(row.id, anchor, "fillForm");
        }
        this.hide();
        if (reply?.ok) applyForm(reply.data, anchor);
        return;
      }
      if (row.action === "generate") {
        this.hide();
        applyGenerated(row.password, anchor);
        return;
      }
      if (row.action === "unlock") {
        await send({ kind: "unlock" });
        this.rows = [{ badge: "…", title: "Déverrouillez Verrou", subtitle: "Touch ID ou mot de passe principal" }];
        this.render();
        this.waitForUnlock(anchor, this.kind);
        return;
      }
      let credentials = await send({ kind: "fill", item: row.id });
      if (credentials?.state === "confirm") {
        // Élément protégé : Verrou demande Touch ID (ou le mot de passe
        // principal) ; on réessaie jusqu'à la confirmation.
        this.rows = [{ badge: "🔐", title: "Confirmez dans Verrou", subtitle: `« ${row.title} » est protégé` }];
        this.render();
        credentials = await this.retryUntilConfirmed(row.id, anchor);
      }
      this.hide();
      if (credentials?.ok) apply(credentials, anchor);
    },

    async retryUntilConfirmed(item, anchor, kind = "fill") {
      for (let tries = 0; tries < 60 && this.anchor === anchor; tries += 1) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        const reply = await send({ kind, item });
        if (reply?.state !== "confirm") return reply;
      }
      return null;
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
        const form = kind === "card" || kind === "identity";
        const reply = await send({ kind: form ? "forms" : "suggest" });
        if (reply.state === "unlocked") {
          clearInterval(this.poll);
          if (form) {
            this.hide();
            if (document.activeElement === anchor) offer(anchor);
            return;
          }
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

  function generatorRow() {
    const password = globalThis.verrouGenerator.password();
    return { action: "generate", badge: "✦", title: "Utiliser un mot de passe fort", subtitle: password, mono: true, password };
  }

  async function offer(input) {
    const kind = classify(input);
    if (!kind) return;
    if (kind === "new") {
      // Proposé même coffre verrouillé : rien ne sort de Verrou. Seulement
      // sur un champ vide, pour ne pas écraser ce que l'utilisateur tape.
      if (!input.value) menu.show(input, kind, [generatorRow()]);
      return;
    }
    if (kind === "card" || kind === "identity") {
      const reply = await send({ kind: "forms" });
      if (document.activeElement !== input) return;
      if (reply.state === "locked") {
        menu.show(input, kind, [{ action: "unlock", badge: "🔒", title: "Déverrouiller Verrou",
          subtitle: kind === "card" ? "pour remplir la carte" : "pour remplir l'adresse" }]);
        return;
      }
      const list = (kind === "card" ? reply.cards : reply.identities) ?? [];
      const rows = list.map((item) => ({ form: true, id: item.id, badge: kind === "card" ? "💳" : "👤",
        title: item.title, subtitle: item.subtitle }));
      if (rows.length) menu.show(input, kind, rows);
      else menu.hide();
      return;
    }
    const reply = await send({ kind: "suggest" });
    if (document.activeElement !== input) return;
    // Verrouillé : on ne le signale que sur un vrai formulaire de connexion.
    if (reply.state === "locked" && kind === "otp") return;
    const rows = rowsFor(reply, kind);
    if (rows.length) menu.show(input, kind, rows);
    else menu.hide();
  }

  // MARK: Enregistrement après l'envoi d'un formulaire

  let lastCapture = { key: "", at: 0 };

  // Identifiant et mot de passe du formulaire, au moment où il part.
  function capture(scope) {
    const roles = passwordRoles(scope, true);
    const inputs = [...scope.querySelectorAll("input")].filter((i) => !i.disabled);
    if (!roles.size) {
      // Première étape d'une connexion : l'identifiant seul, gardé pour l'étape suivante.
      const username = inputs.find((i) => classify(i) === "username");
      if (username?.value.trim()) send({ kind: "rememberUsername", username: username.value.trim() });
      return;
    }
    const filled = [...roles].filter(([input]) => input.value);
    const fresh = filled.filter(([, role]) => role === "new").map(([input]) => input.value);
    const current = filled.find(([, role]) => role === "current")?.[0].value ?? null;
    // Confirmation différente du mot de passe : le site va refuser.
    if (new Set(fresh).size > 1) return;
    const password = fresh[0] ?? current;
    if (!password) return;
    const firstPassword = [...roles.keys()][0];
    const texts = inputs.filter(isText);
    const before = texts.filter((i) => i.compareDocumentPosition(firstPassword) & Node.DOCUMENT_POSITION_FOLLOWING);
    const username = (texts.find((i) => classify(i) === "username") ?? before.at(-1))?.value.trim() ?? "";
    const key = `${username}\n${password}`;
    if (key === lastCapture.key && Date.now() - lastCapture.at < 3000) return;
    lastCapture = { key, at: Date.now() };
    send({ kind: "capture", username, password, current: fresh.length ? current : null });
  }

  function captureFrom(target) {
    if (!(target instanceof Element)) return;
    const scope = target.closest("form") ?? document;
    // Formulaire sans <form> : seulement s'il y a un mot de passe sur la page.
    if (scope === document && !document.querySelector("input[type=password]")) return;
    capture(scope);
  }

  document.addEventListener("submit", (event) => captureFrom(event.target), true);

  document.addEventListener("click", (event) => {
    if (!event.isTrusted) return;
    const target = event.composedPath()[0];
    const button = target instanceof Element
      ? target.closest("button, input[type=submit], input[type=button], [role=button]")
      : null;
    if (button) captureFrom(button);
  }, true);

  // MARK: Bandeau « Enregistrer dans Verrou » (cadre principal)

  const banner = {
    host: null,
    root: null,
    timer: null,

    show(...nodes) {
      if (!this.host) {
        ({ host: this.host, root: this.root } = shadowHost("verrou-banner"));
        Object.assign(this.host.style, { position: "fixed", top: "12px", right: "12px" });
      }
      clearTimeout(this.timer);
      this.root.querySelector(".banner")?.remove();
      const box = div("banner");
      box.append(...nodes);
      this.root.append(box);
      if (!this.host.isConnected) document.documentElement.append(this.host);
    },

    hide(after = 0) {
      clearTimeout(this.timer);
      this.timer = setTimeout(() => this.host?.remove(), after);
    },
  };

  function bannerHead(title, subtitle) {
    const head = div("head");
    const text = div("text");
    text.append(div("title", title), div("sub", subtitle));
    head.append(div("badge", "V"), text);
    return head;
  }

  function actions(...buttons) {
    const row = div("actions");
    row.append(...buttons);
    return row;
  }

  function notify(message, detail = "Verrou") {
    banner.show(bannerHead(message, detail));
    banner.hide(2500);
  }

  async function dismiss() {
    await send({ kind: "dismissSave" });
    banner.hide();
  }

  async function showOffer() {
    if (window !== top) return;
    const offer = await send({ kind: "pendingSave" });
    if (!offer?.action) return;
    const who = `${offer.username || "sans identifiant"} · ${offer.site}`;
    if (offer.action === "locked") {
      banner.show(
        bannerHead("Enregistrer dans Verrou ?", who),
        actions(
          trustedButton("Pas maintenant", "", dismiss),
          trustedButton("Déverrouiller", "primary", async () => {
            await send({ kind: "unlock" });
            banner.show(bannerHead("Déverrouillez Verrou…", "Touch ID ou mot de passe principal"));
            waitThenOffer();
          }),
        ),
      );
      return;
    }
    const update = offer.action === "update";
    banner.show(
      bannerHead(update ? `Mettre à jour le mot de passe de « ${offer.title} » ?` : "Enregistrer dans Verrou ?", who),
      actions(
        trustedButton("Jamais pour ce site", "quiet", async () => {
          await send({ kind: "neverSave" });
          banner.hide();
        }),
        trustedButton("Pas maintenant", "", dismiss),
        trustedButton(update ? "Mettre à jour" : "Enregistrer", "primary", async () => {
          banner.show(bannerHead("Enregistrement…", offer.site));
          const result = await send({ kind: "confirmSave" });
          if (result?.ok) notify(update ? "Mot de passe mis à jour" : "Enregistré dans Verrou");
          else notify("Enregistrement impossible", result?.reason ?? "Verrou ne répond pas");
        }),
      ),
    );
  }

  // Après « Déverrouiller » : la vraie proposition dès que Verrou est ouvert.
  function waitThenOffer() {
    let tries = 0;
    const poll = setInterval(async () => {
      tries += 1;
      const offer = await send({ kind: "pendingSave" });
      if (!offer?.action || tries > 90) {
        clearInterval(poll);
        banner.hide();
      } else if (offer.action !== "locked") {
        clearInterval(poll);
        showOffer();
      }
    }, 1000);
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

  document.addEventListener("input", (event) => {
    // On tape soi-même son nouveau mot de passe : le générateur s'efface.
    if (event.isTrusted && menu.open && menu.kind === "new" && event.target === menu.anchor) menu.hide();
  }, true);

  document.addEventListener("mousedown", (event) => {
    // Clic sur le champ déjà actif après « Échap » : on rouvre.
    const target = event.composedPath()[0];
    if (event.isTrusted && target instanceof HTMLInputElement && target === document.activeElement
      && !menu.open && !filling) offer(target);
  }, true);

  document.addEventListener("keydown", (event) => {
    if (menu.open && event.target === menu.anchor) {
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
      return;
    }
    // Envoi au clavier : certains formulaires partent sans « submit ».
    if (event.isTrusted && event.key === "Enter" && event.target instanceof HTMLInputElement) {
      captureFrom(event.target);
    }
  }, true);

  addEventListener("scroll", () => menu.place(), true);
  addEventListener("resize", () => menu.place());

  chrome.runtime.onMessage.addListener((message) => {
    if (window !== top) return;
    // Remplissage demandé depuis la fenêtre de l'extension (cadre principal).
    if (message?.kind === "apply") {
      const active = document.activeElement;
      apply(message.credentials, active instanceof HTMLInputElement && classify(active) ? active : null);
    }
    // Formulaire envoyé sans changer de page (application monopage).
    if (message?.kind === "offerSave") showOffer();
  });

  // Page suivante d'un formulaire envoyé : une proposition attend peut-être.
  showOffer();
})();
