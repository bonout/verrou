// Dans chaque page (et chaque cadre) : repère les formulaires de connexion
// et, quand Verrou a un identifiant (ou une passkey) pour ce site, affiche
// une pastille en haut à gauche de la page, comme 1Password : le site,
// l'identifiant proposé, « Se connecter » et « ✕ ». « Se connecter » remplit
// puis envoie le formulaire quand plus rien n'est à taper (réglage de la
// fenêtre de l'extension, actif par défaut). Sous la pastille,
// l'onglet « Autres identifiants » déroule les autres identifiants du site,
// « Remplir avec un autre identifiant… » et, sur une inscription,
// « Générer un mot de passe ». Sur un champ « nouveau mot de passe », la
// pastille propose un mot de passe fort ; sur un formulaire de paiement ou
// d'adresse, une carte ou une identité. Après l'envoi d'un formulaire, un
// bandeau au même endroit propose d'enregistrer l'identifiant dans Verrou.
//
// Dans le champ actif, seule une petite icône Verrou, au bord droit, ouvre ou
// ferme la pastille : plus de menu accroché sous le champ, qui gênait les
// listes de suggestions des sites.
//
// Quand la page attend une passkey en remplissage automatique (`mediation:
// "conditional"`), la pastille propose d'abord la passkey de Verrou pour ce
// site (passkeys.js, cadre principal).
//
// La pastille, l'icône et le bandeau vivent dans des shadow DOM fermés : la
// page ne peut ni les lire ni les modifier, et seuls les événements réels
// (`isTrusted`) les déclenchent. Les secrets n'arrivent qu'au moment du
// remplissage, pour l'élément choisi.

(() => {
  if (globalThis.__verrouContent) return;
  globalThis.__verrouContent = true;
  // API d'extension : `browser` (Firefox), sinon `chrome` (Brave). Le test sur
  // `runtime.id` écarte un élément de la page nommé « browser » (voir browser.js).
  const ext = globalThis.browser?.runtime?.id ? globalThis.browser : globalThis.chrome;

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

  // Le bouton d'envoi du formulaire : le premier du formulaire, ou, sans
  // <form>, le premier qui suit le dernier champ rempli.
  function submitButtonOf(scope, after) {
    const buttons = [...scope.querySelectorAll("button, input[type=submit]")].filter((button) =>
      !button.disabled && visible(button)
      && (button instanceof HTMLInputElement || (button.getAttribute("type") ?? "submit").toLowerCase() === "submit"));
    if (scope !== document || !after) return buttons[0] ?? null;
    return buttons.find((b) => after.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING) ?? null;
  }

  // MARK: Envoi après le remplissage

  // Réglage « Envoyer le formulaire après le remplissage » de la fenêtre de
  // l'extension, actif par défaut.
  async function autoSubmitEnabled() {
    try {
      const { autoSubmit } = await ext.storage.local.get("autoSubmit");
      return autoSubmit !== false;
    } catch {
      return true;
    }
  }

  // Types de champ qui ne demandent rien à taper.
  const NOT_TYPED = new Set(["checkbox", "radio", "hidden", "submit", "button", "file", "image", "reset", "search"]);

  // Le plus petit élément qui contient tous `nodes`.
  function commonAncestor(nodes) {
    let node = nodes[0];
    while (node && !nodes.every((other) => node.contains(other))) node = node.parentNode;
    return node ?? document.documentElement;
  }

  // Un champ visible, modifiable et vide reste à remplir (code client,
  // chiffres d'un code découpé…) : c'est à l'utilisateur de finir.
  function emptyFieldLeft(area) {
    return [...area.querySelectorAll("input")].some((input) =>
      usable(input) && !NOT_TYPED.has(typeOf(input)) && !input.value);
  }

  const CAPTCHA_SRC = /captcha|recaptcha|hcaptcha|challenges\.cloudflare|turnstile/i;

  // Un captcha visible sur la page. Le badge de reCAPTCHA v3 et les widgets
  // invisibles ne comptent pas : ils ne demandent rien à l'utilisateur.
  function visibleCaptcha() {
    const invisible = (node) => node.closest(".grecaptcha-badge")
      || (node.getAttribute("data-size") ?? "").toLowerCase() === "invisible";
    const frames = [...document.querySelectorAll("iframe")].filter((frame) => {
      const src = frame.getAttribute("src") ?? "";
      return CAPTCHA_SRC.test(src) && !/[?&]size=invisible/i.test(src);
    });
    const widgets = [...document.querySelectorAll(".g-recaptcha, .h-captcha, .cf-turnstile, [data-sitekey]")]
      // Le bouton d'envoi qui porte lui-même le captcha invisible.
      .filter((node) => !(node instanceof HTMLInputElement) && node.tagName !== "BUTTON");
    return [...frames, ...widgets].some((node) => !invisible(node) && visible(node));
  }

  // Le formulaire peut partir : tout ce que Verrou a rempli l'est encore, plus
  // rien à taper autour, pas de captcha.
  function readyToSubmit(scope, filled, button) {
    if (!filled.length || !filled.every(([input, value]) => input.isConnected && input.value === value)) return false;
    const area = scope === document ? commonAncestor([...filled.map(([input]) => input), button].filter(Boolean)) : scope;
    return !emptyFieldLeft(area) && !visibleCaptcha();
  }

  // Envoie comme un clic sur le bouton : `requestSubmit` déclenche la
  // validation et l'événement « submit » que les sites écoutent.
  function submit(scope, button) {
    if (scope !== document && typeof scope.requestSubmit === "function") {
      try {
        if (button && button.form === scope) scope.requestSubmit(button);
        else scope.requestSubmit();
        return;
      } catch {
        // Bouton refusé par le navigateur : le clic, ci-dessous.
      }
    }
    button?.click();
  }

  // Ce que Verrou vient de remplir : envoyé tel quel, le formulaire n'a rien
  // de nouveau à proposer d'enregistrer.
  let lastFill = { username: null, password: null, at: 0 };

  // Remplit le formulaire de `anchor` (ou la page) avec `credentials`, puis
  // place le curseur sur le bouton d'envoi. Avec `autoSubmit` (choix explicite
  // de l'utilisateur : pastille ou fenêtre de l'extension) et le réglage
  // actif, le formulaire part si plus rien n'est à taper.
  function apply(credentials, anchor, { autoSubmit = false } = {}) {
    let scope;
    let button;
    const filled = [];
    const fill = (input, value) => {
      setValue(input, value);
      filled.push([input, input.value]);
    };
    withFilling(() => {
      scope = anchor ? scopeOf(anchor) : document;
      const inputs = inputsOf(scope);
      let last = null;
      if (anchor && classify(anchor) === "otp") {
        if (credentials.totp) fill(anchor, credentials.totp);
        last = anchor;
      } else {
        const username = inputs.find((i) => classify(i) === "username");
        const password = inputs.find(isLoginPassword);
        if (credentials.username && username) fill(username, credentials.username);
        if (credentials.password && password) fill(password, credentials.password);
        last = password ?? username;
        if (!username && !password) {
          const otp = inputs.find((i) => classify(i) === "otp");
          if (otp && credentials.totp) fill(otp, credentials.totp);
          last = otp ?? null;
        }
        // Formulaire sans <form> : celui du champ rempli.
        if (scope === document && last) scope = scopeOf(last);
      }
      lastFill = { username: credentials.username ?? null, password: credentials.password ?? null, at: Date.now() };
      button = submitButtonOf(scope, last);
      (button ?? last)?.focus({ preventScroll: true });
    });
    if (!autoSubmit || !filled.length || (scope === document && !button)) return;
    // Laisser les frameworks traiter la saisie, puis vérifier à nouveau.
    (async () => {
      const enabled = await autoSubmitEnabled();
      await sleep(150);
      if (enabled && readyToSubmit(scope, filled, button)) submit(scope, button);
    })();
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
      return (await ext.runtime.sendMessage(message)) ?? { state: "offline" };
    } catch {
      return { state: "offline" };
    }
  }

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const SITE = location.hostname.replace(/^www\./, "");

  // MARK: Style commun

  // Une capsule sombre, liseré violet, comme celle de 1Password, quel que
  // soit le thème ; l'animation d'arrivée disparaît avec « réduire les
  // animations ».
  const STYLE = `
    :host { all: initial; }
    * { box-sizing: border-box; }
    .stack {
      display: flex; flex-direction: column; align-items: center; gap: 8px;
      margin: 0 auto; max-width: calc(100vw - 32px);
      font: 13px/1.35 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #f4f4f6;
      -webkit-font-smoothing: antialiased;
    }
    /* L'hôte couvre toute la largeur du haut de la page sans capter les
       clics : seuls la pastille et le bandeau en reçoivent. */
    .pill, .banner { pointer-events: auto; }
    .pill { display: flex; flex-direction: column; align-items: center; max-width: 100%; animation: drop .18s ease-out; }
    .shell, .tab, .banner { background: #1b1b20; border: 1.5px solid #6c6cf0; }
    /* La capsule, puis, ouverte, une carte arrondie : en-tête, filet, comptes. */
    .shell {
      display: flex; flex-direction: column; min-width: 360px; max-width: min(480px, calc(100vw - 32px));
      border-radius: 999px; overflow: hidden;
      box-shadow: 0 12px 34px rgba(0,0,0,.38), 0 0 0 4px rgba(108,108,240,.18);
    }
    .shell.open { border-radius: 28px; }
    .capsule { display: flex; align-items: center; gap: 14px; padding: 10px 12px 10px 14px; }
    .icon { flex: none; display: grid; place-items: center; width: 34px; height: 34px; border-radius: 10px;
      background: linear-gradient(135deg, #7474f4, #3b3bbd); }
    .icon svg { width: 20px; height: 20px; display: block; }
    .text { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 1px; }
    .title, .sub { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 280px; }
    .title { font-weight: 600; font-size: 14.5px; }
    .sub { color: #a3a3ad; font-size: 12.5px; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    button { font: inherit; color: inherit; background: none; border: 0; margin: 0; padding: 0; cursor: pointer; }
    button:focus-visible { outline: 2px solid #a5a5ff; outline-offset: 2px; }
    .primary {
      flex: none; max-width: 280px; padding: 9px 18px; border-radius: 999px; font-size: 14px;
      background: #5b5bd6; color: #fff; font-weight: 600;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .primary:hover { background: #6b6be6; }
    .close { flex: none; width: 32px; height: 32px; border-radius: 50%; color: #a3a3ad; font-size: 15px; }
    .close:hover { background: rgba(255,255,255,.1); color: #fff; }
    .tab {
      display: flex; align-items: center; gap: 6px; padding: 5px 16px 7px;
      border-top: 0; border-radius: 0 0 12px 12px; font-size: 12.5px; color: #d4d4da;
    }
    .chev { display: inline-block; transition: transform .15s ease; }
    .tab[aria-expanded="true"] .chev { transform: rotate(180deg); }
    .list {
      max-height: 340px; overflow-y: auto; padding: 8px 10px 12px;
      border-top: 1px solid rgba(255,255,255,.12);
    }
    .row { display: flex; align-items: center; gap: 14px; width: 100%; padding: 10px 10px; border-radius: 14px; text-align: left; }
    .row:hover, .row:focus-visible { background: rgba(108,108,240,.28); outline: none; }
    .badge {
      flex: none; width: 34px; height: 34px; border-radius: 10px; display: grid; place-items: center;
      font-weight: 700; font-size: 13px; color: #2b2b6e; background: #b9b9f6;
    }
    .banner {
      width: 360px; max-width: 100%; padding: 12px 14px; border-radius: 16px;
      box-shadow: 0 10px 30px rgba(0,0,0,.35), 0 0 0 3px rgba(108,108,240,.2); animation: drop .18s ease-out;
    }
    .banner .title { white-space: normal; max-width: none; }
    .head { display: flex; gap: 10px; align-items: center; }
    .actions { display: flex; gap: 8px; justify-content: flex-end; flex-wrap: wrap; margin-top: 10px; }
    .actions button { padding: 6px 12px; border-radius: 999px; background: rgba(255,255,255,.1); }
    .actions button.primary { background: #5b5bd6; }
    .actions button.quiet { background: none; color: #a3a3ad; padding: 6px 4px; margin-right: auto; }
    .field { display: grid; place-items: center; width: 100%; height: 100%; border-radius: 6px; }
    .field .icon { width: 26px; height: 26px; border-radius: 8px; transform: scale(var(--scale, .75)); }
    .field .icon svg { width: 16px; height: 16px; }
    @keyframes drop { from { opacity: 0; transform: translateY(-6px); } }
    @media (prefers-reduced-motion: reduce) {
      .pill, .banner { animation: none; }
      .chev { transition: none; }
    }
    @media (prefers-color-scheme: dark) {
      .shell, .tab, .banner { background: #222228; }
    }
  `;

  // Un hôte de shadow DOM fermé. `pin` le tient en place par des styles en
  // ligne `!important` : une feuille de style de la page ne le déplace ni ne
  // le cache.
  function shadowHost(tag) {
    const host = document.createElement(tag);
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = STYLE;
    root.append(style);
    return { host, root };
  }

  function pin(host, styles) {
    for (const [name, value] of Object.entries(styles)) host.style.setProperty(name, value, "important");
  }

  const HOST_STYLES = {
    display: "block", visibility: "visible", opacity: "1", transform: "none", filter: "none",
    "pointer-events": "auto", margin: "0", padding: "0", "z-index": "2147483647",
  };

  function div(className, text) {
    const node = document.createElement("div");
    node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function span(className, text) {
    const node = document.createElement("span");
    node.className = className;
    node.textContent = text;
    return node;
  }

  // Un bouton qui n'obéit qu'aux vrais clics (souris, ou Entrée et Espace
  // sur le bouton, que le navigateur transforme en clic réel).
  function trustedButton(label, className, action) {
    const button = document.createElement("button");
    button.setAttribute("type", "button");
    button.className = className;
    button.textContent = label;
    button.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (event.isTrusted) action();
    });
    return button;
  }

  // « Maif » → « Ma », comme les pastilles de 1Password.
  function initials(title) {
    const word = (title ?? "").trim().replace(/^[^\p{L}\p{N}]+/u, "");
    if (!word) return "?";
    return word[0].toUpperCase() + (word[1] ?? "").toLowerCase();
  }

  function textBlock(title, subtitle, mono = false) {
    const text = div("text");
    text.append(div("title", title), div(`sub${mono ? " mono" : ""}`, subtitle ?? ""));
    return text;
  }

  // Le cadenas de Verrou : anse, corps et trou de serrure, en SVG (le dessin
  // en CSS se déformait selon la taille).
  function icon() {
    const node = div("icon");
    node.setAttribute("aria-hidden", "true");
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    const shape = (tag, attrs) => {
      const el = document.createElementNS(ns, tag);
      for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
      svg.append(el);
    };
    shape("path", { d: "M7.5 10.5V8a4.5 4.5 0 0 1 9 0v2.5", fill: "none", stroke: "#fff", "stroke-width": "2.2", "stroke-linecap": "round" });
    shape("rect", { x: "4.5", y: "10", width: "15", height: "11", rx: "3", fill: "#fff" });
    shape("circle", { cx: "12", cy: "14.6", r: "1.6", fill: "#4646c8" });
    shape("rect", { x: "11.2", y: "15.2", width: "1.6", height: "3.1", rx: ".8", fill: "#4646c8" });
    node.append(svg);
    return node;
  }

  // MARK: Pastille en haut à gauche (et bandeau d'enregistrement)

  // Un seul hôte, fixé à 16 px du coin haut gauche, au-dessus de la page :
  // la pastille, puis le bandeau d'enregistrement en dessous.
  const ui = {
    host: null,
    root: null,
    stack: null,

    ensure() {
      if (this.host) return;
      ({ host: this.host, root: this.root } = shadowHost("verrou-pill"));
      this.stack = div("stack");
      this.root.append(this.stack);
      // Un clic dans la pastille ne prend pas le focus à la page.
      this.root.addEventListener("mousedown", (event) => event.preventDefault());
      this.root.addEventListener("keydown", (event) => pillKey(event));
    },

    attach() {
      this.ensure();
      // Centrée en haut de la page, comme celle de 1Password : l'hôte prend
      // toute la largeur (sans transformation, que la page ne peut donc pas
      // détourner) et laisse passer les clics hors de la pastille.
      pin(this.host, {
        ...HOST_STYLES, position: "fixed", top: "16px", left: "0", right: "0", bottom: "auto",
        width: "auto", "pointer-events": "none",
      });
      if (!this.host.isConnected) document.documentElement.append(this.host);
    },

    // Plus rien à montrer : l'hôte quitte la page.
    sync() {
      if (this.host && !this.stack.children.length) this.host.remove();
    },
  };

  // Formulaires de connexion déjà proposés, par « étape » (les champs
  // présents : identifiant, mot de passe, code…) : la pastille vient d'elle-
  // même une fois par étape, jamais à chaque focus. Fermée (✕, Échap) : plus
  // rien d'elle-même sur cette page.
  let dismissed = false;
  const queried = new Set();
  let offerSeq = 0;

  const LOGIN_KINDS = new Set(["username", "password", "otp"]);
  const sameGroup = (a, b) => a === b || (LOGIN_KINDS.has(a) && LOGIN_KINDS.has(b));

  const pill = {
    node: null,
    anchor: null,
    kind: null,
    view: null,
    expanded: false,
    busy: false,
    // Change à chaque fermeture : une attente (confirmation, déverrouillage)
    // en cours s'arrête.
    token: 0,

    get open() {
      return Boolean(this.node?.isConnected);
    },

    show(anchor, kind, view, { expanded = false } = {}) {
      this.anchor = anchor;
      this.kind = kind;
      this.view = view;
      this.busy = false;
      this.expanded = expanded;
      this.render();
    },

    // Un état d'attente : plus d'action, la croix seulement.
    wait(title, subtitle) {
      this.busy = true;
      this.view = { title, subtitle, primary: null, others: [] };
      this.expanded = false;
      this.render();
    },

    render() {
      ui.attach();
      const focused = ui.root.activeElement?.getAttribute?.("data-key") ?? null;
      const area = div("pill");
      area.setAttribute("role", "dialog");
      area.setAttribute("aria-label", "Verrou");
      const { view } = this;
      const capsule = div("capsule");
      capsule.append(icon(), textBlock(view.title, view.subtitle, view.mono));
      if (view.primary) {
        const primary = trustedButton(view.primary.label, "primary", view.primary.run);
        primary.setAttribute("data-key", "primary");
        capsule.append(primary);
      }
      const close = trustedButton("✕", "close", () => this.dismiss());
      close.setAttribute("aria-label", "Fermer Verrou sur cette page");
      close.setAttribute("title", "Fermer");
      close.setAttribute("data-key", "close");
      capsule.append(close);
      const shell = div(`shell${this.expanded && view.others?.length ? " open" : ""}`);
      shell.append(capsule);
      area.append(shell);
      if (view.others?.length) {
        const tab = trustedButton(view.tab ?? "Autres identifiants", "tab", () => {
          this.expanded = !this.expanded;
          this.render();
        });
        tab.setAttribute("aria-expanded", String(this.expanded));
        tab.setAttribute("data-key", "tab");
        const chevron = span("chev", "⌄");
        chevron.setAttribute("aria-hidden", "true");
        tab.append(chevron);
        if (this.expanded) {
          const list = div("list");
          list.setAttribute("role", "group");
          list.setAttribute("aria-label", view.tab ?? "Autres identifiants");
          view.others.forEach((row, index) => {
            const line = trustedButton("", "row", row.run);
            line.setAttribute("data-key", `row-${index}`);
            line.setAttribute("aria-label", [row.title, row.subtitle].filter(Boolean).join(", "));
            line.append(div("badge", row.badge), textBlock(row.title, row.subtitle, row.mono));
            list.append(line);
          });
          shell.append(list);
        }
        area.append(tab);
      }
      if (this.node?.isConnected) this.node.replaceWith(area);
      else ui.stack.prepend(area);
      this.node = area;
      // Rendu au clavier : le focus reste sur le même bouton.
      if (focused) this.buttons().find((b) => b.getAttribute("data-key") === focused)?.focus();
    },

    buttons() {
      return this.node ? [...this.node.querySelectorAll("button")] : [];
    },

    hide() {
      this.token += 1;
      this.busy = false;
      this.node?.remove();
      this.node = null;
      this.anchor = null;
      this.view = null;
      ui.sync();
    },

    // ✕ ou Échap : plus rien d'elle-même sur cette page.
    dismiss() {
      const anchor = this.anchor;
      const inside = Boolean(ui.root?.activeElement);
      dismissed = true;
      observer?.disconnect();
      this.hide();
      if (inside && anchor?.isConnected) anchor.focus({ preventScroll: true });
    },
  };

  // Clavier dans la pastille (vraies touches seulement) : Échap la ferme, les
  // flèches passent d'un bouton à l'autre ; Entrée et Espace sont ceux des
  // boutons.
  function pillKey(event) {
    if (!event.isTrusted || !pill.open) return;
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      pill.dismiss();
      return;
    }
    const step = { ArrowDown: 1, ArrowRight: 1, ArrowUp: -1, ArrowLeft: -1 }[event.key];
    if (!step) return;
    const buttons = pill.buttons();
    const index = buttons.indexOf(ui.root.activeElement);
    if (index < 0) return;
    event.preventDefault();
    event.stopPropagation();
    buttons[(index + step + buttons.length) % buttons.length].focus();
  }

  // Le champ à remplir au moment du choix : le champ actif s'il est du même
  // genre, sinon celui de la pastille, sinon celui que la page montre
  // maintenant (application monopage qui a redessiné son formulaire).
  function fillTarget(kind, anchor) {
    const active = document.activeElement;
    if (active instanceof HTMLInputElement && sameGroup(classify(active), kind)) return active;
    if (anchor?.isConnected && usable(anchor)) return anchor;
    return LOGIN_KINDS.has(kind) ? loginFields().anchor : null;
  }

  // Réessaie tant que Verrou attend la confirmation d'un élément protégé
  // (Touch ID ou mot de passe principal), une minute au plus, pastille
  // ouverte.
  async function retryUntilConfirmed(kind, item, token) {
    for (let tries = 0; tries < 60 && pill.token === token; tries += 1) {
      await sleep(1000);
      if (pill.token !== token) break;
      const reply = await send({ kind, item });
      if (reply?.state !== "confirm") return reply;
    }
    return null;
  }

  async function fillLogin(item, kind, anchor) {
    const token = pill.token;
    let credentials = await send({ kind: "fill", item: item.id });
    if (credentials?.state === "confirm") {
      pill.wait("Confirmez dans Verrou", `« ${item.title} » est protégé`);
      credentials = await retryUntilConfirmed("fill", item.id, token);
    }
    if (pill.token !== token) return;
    const target = fillTarget(kind, anchor);
    pill.hide();
    // Choix explicite dans la pastille (vrai clic) : le formulaire peut partir.
    if (credentials?.ok) apply(credentials, target, { autoSubmit: true });
  }

  async function fillCardOrIdentity(item, kind, anchor) {
    const token = pill.token;
    let reply = await send({ kind: "fillForm", item: item.id });
    if (reply?.state === "confirm") {
      pill.wait("Confirmez dans Verrou", `« ${item.title} » est protégé`);
      reply = await retryUntilConfirmed("fillForm", item.id, token);
    }
    if (pill.token !== token) return;
    const target = fillTarget(kind, anchor) ?? anchor;
    pill.hide();
    if (reply?.ok && target) applyForm(reply.data, target);
  }

  // Après « Déverrouiller » : la pastille se remplit dès que Verrou est
  // ouvert (une minute et demie au plus).
  async function unlock(anchor, kind) {
    await send({ kind: "unlock" });
    pill.wait("Déverrouillez Verrou…", "Touch ID ou mot de passe principal");
    const token = pill.token;
    const form = kind === "card" || kind === "identity";
    for (let tries = 0; tries < 90; tries += 1) {
      await sleep(1000);
      if (pill.token !== token) return;
      const reply = await send({ kind: form ? "forms" : "suggest" });
      if (pill.token !== token) return;
      if (reply.state === "locked") continue;
      const view = reply.state === "unlocked" ? await viewFor(anchor, kind, true) : null;
      if (pill.token !== token) return;
      if (view) pill.show(anchor, kind, view, { expanded: !view.primary });
      else pill.hide();
      return;
    }
    if (pill.token === token) pill.hide();
  }

  // MARK: Ce que propose la pastille

  function lockedView(anchor, kind) {
    return {
      title: "Verrou est verrouillé",
      subtitle: SITE,
      primary: { label: "Déverrouiller", run: () => unlock(anchor, kind) },
      others: [],
    };
  }

  // Ouverte à la main (icône du champ) alors que Verrou ne répond pas.
  function unavailableView(state) {
    return state === "unpaired"
      ? { title: "L'extension n'est pas reliée à Verrou", subtitle: "Reliez-la depuis son icône dans la barre d'outils", primary: null, others: [] }
      : { title: "Verrou n'est pas joignable", subtitle: "Ouvrez l'app Verrou", primary: null, others: [] };
  }

  // L'interface de passkeys.js, dans le cadre principal seulement.
  const passkeyMenu = () => (window === top ? globalThis.__verrouPasskeyMenu : undefined);

  // Les passkeys de Verrou que la page attend, pour un champ de connexion.
  async function passkeyEntries(kind) {
    const api = passkeyMenu();
    if (!api || (kind !== "username" && kind !== "password")) return { state: "none" };
    try {
      return await api.entries();
    } catch {
      return { state: "none" };
    }
  }

  // Un champ « nouveau mot de passe » du formulaire de `anchor` (inscription).
  function newPasswordField(anchor) {
    for (const [input, role] of passwordRoles(anchor ? scopeOf(anchor) : document)) {
      if (role === "new") return input;
    }
    return null;
  }

  function generateRow(field) {
    const password = globalThis.verrouGenerator.password();
    return {
      badge: "✦", title: "Générer un mot de passe", subtitle: password, mono: true,
      run: () => {
        pill.hide();
        applyGenerated(password, field);
      },
    };
  }

  // « Remplir avec un autre identifiant… » : la fenêtre de l'extension, où
  // l'on choisit l'identifiant à relier à ce site. La page n'y voit rien.
  function linkRow() {
    return {
      badge: "…", title: "Remplir avec un autre identifiant…", subtitle: "Relier ce site à un identifiant de Verrou",
      run: () => {
        pill.hide();
        send({ kind: "openLinkSite" });
      },
    };
  }

  async function loginView(anchor, kind, manual) {
    const [reply, passkeys] = await Promise.all([send({ kind: "suggest" }), passkeyEntries(kind)]);
    if (reply.state === "locked" || passkeys.state === "locked") {
      // Verrouillé : pas pour un simple code de vérification, sauf à la main.
      return kind === "otp" && !manual ? null : lockedView(anchor, kind);
    }
    if (reply.state !== "unlocked" && passkeys.state !== "ready") return manual ? unavailableView(reply.state) : null;
    // Les passkeys d'abord, comme le navigateur.
    const rows = [
      ...(passkeys.state === "ready" ? passkeys.items : []).map((item) => ({
        badge: "🔑",
        title: `Passkey · ${item.user_name || item.title}`,
        subtitle: item.title,
        username: item.user_name || item.title,
        action: "Se connecter avec une passkey",
        run: () => {
          // La signature et sa fenêtre d'avancement : passkeys.js.
          pill.hide();
          passkeyMenu()?.choose(item.credential);
        },
      })),
      ...(reply.state === "unlocked" ? reply.items : [])
        .filter((item) => kind !== "otp" || item.has_totp)
        .map((item) => ({
          badge: initials(item.title),
          title: kind === "otp" ? `Code de ${item.title}` : item.title,
          subtitle: item.username,
          username: item.username,
          action: kind === "otp" ? "Remplir le code" : "Se connecter",
          run: () => fillLogin(item, kind, anchor),
        })),
    ];
    if (!rows.length && !manual) return null;
    const [top, ...rest] = rows;
    const fresh = newPasswordField(anchor);
    const extras = [
      ...(fresh ? [generateRow(fresh)] : []),
      ...(reply.state === "unlocked" ? [linkRow()] : []),
    ];
    return {
      title: SITE,
      subtitle: top ? top.username || "—" : kind === "otp" ? "Aucun code pour ce site" : "Aucun identifiant pour ce site",
      primary: top ? { label: top.action, run: top.run } : null,
      tab: "Autres identifiants",
      others: [...rest, ...extras],
    };
  }

  async function formView(anchor, kind, manual) {
    const card = kind === "card";
    const reply = await send({ kind: "forms" });
    if (reply.state === "locked") return lockedView(anchor, kind);
    if (reply.state !== "unlocked") return manual ? unavailableView(reply.state) : null;
    const rows = ((card ? reply.cards : reply.identities) ?? []).map((item) => ({
      badge: card ? "💳" : "👤",
      title: item.title,
      subtitle: item.subtitle,
      run: () => fillCardOrIdentity(item, kind, anchor),
    }));
    if (!rows.length && !manual) return null;
    const [top, ...rest] = rows;
    return {
      title: SITE,
      subtitle: top ? top.title : card ? "Aucune carte dans Verrou" : "Aucune adresse dans Verrou",
      primary: top
        ? { label: card ? `Remplir la carte ${top.subtitle}`.trim() : "Remplir l'adresse", run: top.run }
        : null,
      tab: card ? "Autres cartes" : "Autres adresses",
      others: rest,
    };
  }

  function generatorView(anchor) {
    const password = globalThis.verrouGenerator.password();
    return {
      title: SITE,
      subtitle: password,
      mono: true,
      primary: {
        label: "Suggérer un mot de passe fort",
        run: () => {
          pill.hide();
          applyGenerated(password, anchor);
        },
      },
      others: [],
    };
  }

  async function viewFor(anchor, kind, manual) {
    // Proposé même coffre verrouillé : rien ne sort de Verrou.
    if (kind === "new") return generatorView(anchor);
    if (kind === "card" || kind === "identity") return formView(anchor, kind, manual);
    return loginView(anchor, kind, manual);
  }

  // Affiche la pastille pour `anchor`. D'elle-même (`manual` faux) : rien
  // sans identifiant pour ce site, ni après une fermeture. `refresh` : mise à
  // jour de la pastille ouverte, qui s'efface s'il n'y a plus rien.
  async function offer(anchor, kind, { manual = false, refresh = false } = {}) {
    const seq = ++offerSeq;
    const view = await viewFor(anchor, kind, manual);
    if (seq !== offerSeq) return;
    if (!view) {
      if (refresh && pill.open && !pill.busy) pill.hide();
      return;
    }
    if (!manual && (dismissed || pill.busy)) return;
    const keepOpen = refresh && pill.open && pill.expanded;
    pill.show(anchor, kind, view, { expanded: keepOpen || (manual && !view.primary) });
  }

  // MARK: Formulaires de connexion de la page

  // Un identifiant seul (connexion en plusieurs étapes) ne compte que s'il
  // se présente comme tel : pas le champ e-mail d'une lettre d'information.
  function strongUsername(input) {
    const autocomplete = (input.autocomplete || "").toLowerCase();
    return /\b(username|webauthn)\b/.test(autocomplete)
      || /user|login|identifiant|account|compte|pseudo/i.test(`${input.name} ${input.id}`);
  }

  // Le champ de connexion de la page, son genre, et l'étape (les genres de
  // champs présents).
  function loginFields() {
    const found = new Map();
    for (const input of inputsOf(document)) {
      const kind = classify(input);
      if ((LOGIN_KINDS.has(kind) || kind === "new") && !found.has(kind)) found.set(kind, input);
    }
    let anchor = null;
    if (found.has("password")) anchor = found.get("username") ?? found.get("password");
    else if (!found.has("new") && found.has("username") && strongUsername(found.get("username"))) anchor = found.get("username");
    else if (found.has("otp")) anchor = found.get("otp");
    const kinds = [...found.keys()].filter((kind) => LOGIN_KINDS.has(kind)).sort();
    return { anchor, kind: anchor ? classify(anchor) : null, signature: `login:${kinds.join("+")}` };
  }

  // Cherche un formulaire de connexion et, la première fois pour cette
  // étape, propose les identifiants du site.
  function scan() {
    if (dismissed || filling) return;
    const { anchor, kind, signature } = loginFields();
    if (!anchor || queried.has(signature) || pill.busy) return;
    queried.add(signature);
    offer(anchor, kind);
  }

  let scanTimer = null;
  function scheduleScan(delay = 400) {
    clearTimeout(scanTimer);
    scanTimer = setTimeout(scan, delay);
  }

  // Formulaires qui arrivent après le chargement (applications monopages,
  // fenêtres de connexion).
  // Les mouvements de nos propres hôtes ne comptent pas.
  const ours = (node) => node === ui.host || node === badge.host;
  const observer = typeof MutationObserver === "function"
    ? new MutationObserver((records) => {
      const relevant = records.some((r) => !ours(r.target)
        && (r.type !== "childList" || ![...r.addedNodes, ...r.removedNodes].every(ours)));
      if (!relevant) return;
      badge.place();
      scheduleScan();
    })
    : null;

  // La page vient de demander une passkey (ou la demande s'est terminée) :
  // la pastille ouverte se met à jour ; fermée, elle revient proposer la
  // passkey (nouvelle demande de la page), jamais pour un simple mot de passe
  // déjà proposé.
  passkeyMenu()?.subscribe(async () => {
    if (dismissed || filling || pill.busy) return;
    const { anchor, kind, signature } = loginFields();
    if (pill.open && LOGIN_KINDS.has(pill.kind)) {
      offer(pill.anchor?.isConnected ? pill.anchor : anchor ?? pill.anchor, pill.kind, { refresh: true });
      return;
    }
    if (!anchor || (kind !== "username" && kind !== "password")) return;
    if ((await passkeyEntries(kind)).state !== "ready" || pill.open || dismissed) return;
    queried.add(signature);
    offer(anchor, kind);
  });

  // MARK: Icône Verrou dans le champ actif

  const badge = {
    host: null,
    root: null,
    input: null,

    ensure() {
      if (this.host) return;
      ({ host: this.host, root: this.root } = shadowHost("verrou-field"));
      const button = trustedButton("", "field", () => this.toggle());
      button.setAttribute("aria-label", "Verrou : identifiants pour ce site");
      button.setAttribute("title", "Verrou");
      // Hors de l'ordre de tabulation de la page ; un clic garde le focus
      // dans le champ.
      button.setAttribute("tabindex", "-1");
      button.addEventListener("mousedown", (event) => event.preventDefault());
      button.append(icon());
      this.root.append(button);
      this.button = button;
    },

    show(input) {
      this.ensure();
      this.input = input;
      if (!this.place()) return;
      if (!this.host.isConnected) document.documentElement.append(this.host);
    },

    // Au bord droit du champ, centrée verticalement ; trop petit : rien.
    place() {
      if (!this.input) return false;
      if (!this.input.isConnected) {
        this.hide();
        return false;
      }
      const box = this.input.getBoundingClientRect();
      const size = Math.min(22, box.height - 6);
      if (size < 14 || box.width < 80) {
        this.host?.remove();
        return false;
      }
      this.button.style.setProperty("--scale", String(size / 26));
      pin(this.host, {
        ...HOST_STYLES, position: "absolute", width: `${size}px`, height: `${size}px`,
        left: `${box.right + scrollX - size - 6}px`, top: `${box.top + scrollY + (box.height - size) / 2}px`,
        right: "auto", bottom: "auto", "z-index": "2147483646",
      });
      return true;
    },

    hide() {
      this.host?.remove();
      this.input = null;
    },

    // Ouvre la pastille pour ce champ (même après une fermeture), ou la ferme.
    toggle() {
      const input = this.input;
      if (pill.open) {
        pill.hide();
        return;
      }
      const kind = input && classify(input);
      if (kind) offer(input, kind, { manual: true });
    },
  };

  // Les secrets ne vont qu'au cadre dont l'adresse est celle pour laquelle
  // Verrou les a donnés (la page a pu changer entre-temps).
  function forThisPage(message) {
    return typeof message.origin === "string" && message.origin === location.origin;
  }

  // MARK: Enregistrement après l'envoi d'un formulaire

  let lastCapture = { key: "", at: 0 };
  const FILL_MEMORY_MS = 5 * 60_000;

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
    // Identifiant et mot de passe tels que Verrou vient de les remplir (envoi
    // automatique ou Entrée) : rien de nouveau à enregistrer.
    if (!fresh.length && password === lastFill.password && (!username || username === lastFill.username)
      && Date.now() - lastFill.at < FILL_MEMORY_MS) return;
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

  // Au même coin que la pastille, sous elle, dans la même capsule sombre.
  const banner = {
    node: null,
    timer: null,

    show(...nodes) {
      ui.attach();
      clearTimeout(this.timer);
      const box = div("banner");
      box.setAttribute("role", "dialog");
      box.setAttribute("aria-label", "Verrou : enregistrement");
      box.append(...nodes);
      if (this.node?.isConnected) this.node.replaceWith(box);
      else ui.stack.append(box);
      this.node = box;
    },

    hide(after = 0) {
      clearTimeout(this.timer);
      this.timer = setTimeout(() => {
        this.node?.remove();
        this.node = null;
        ui.sync();
      }, after);
    },
  };

  function bannerHead(title, subtitle) {
    const head = div("head");
    head.append(icon(), textBlock(title, subtitle));
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

  async function dismissSave() {
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
          trustedButton("Pas maintenant", "", dismissSave),
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
        trustedButton("Pas maintenant", "", dismissSave),
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

  // Le site gère lui-même une liste de suggestions sous ce champ : la flèche
  // vers le bas reste la sienne.
  function siteListOpen(input) {
    return Boolean(input.getAttribute("list")) || input.getAttribute("aria-expanded") === "true";
  }

  document.addEventListener("focusin", (event) => {
    if (filling) return;
    const target = event.composedPath()[0];
    if (!(target instanceof HTMLInputElement)) return;
    const kind = classify(target);
    if (!kind) {
      badge.hide();
      return;
    }
    badge.show(target);
    if (LOGIN_KINDS.has(kind)) {
      // Formulaire apparu sans mutation visible (style d'un parent…).
      scheduleScan(0);
      return;
    }
    // Mot de passe à créer (champ vide : ne pas écraser ce qu'on tape),
    // carte, adresse : la pastille vient au premier passage dans le champ.
    if (dismissed || (kind === "new" && target.value) || pill.busy) return;
    if (queried.has(kind)) return;
    queried.add(kind);
    offer(target, kind);
  }, true);

  document.addEventListener("focusout", (event) => {
    if (event.target !== badge.input) return;
    setTimeout(() => {
      if (document.activeElement !== badge.input) badge.hide();
    }, 120);
  }, true);

  document.addEventListener("input", (event) => {
    // On tape soi-même son nouveau mot de passe : la suggestion s'efface.
    if (event.isTrusted && pill.open && pill.kind === "new" && !pill.busy && event.target === pill.anchor) pill.hide();
  }, true);

  document.addEventListener("keydown", (event) => {
    // Seulement les vraies touches : la page ne choisit pas à la place de
    // l'utilisateur.
    if (!event.isTrusted) return;
    if (pill.open && event.key === "Escape") {
      // Pas d'arrêt de l'événement : la page ferme aussi ses propres listes.
      pill.dismiss();
      return;
    }
    // Flèche vers le bas dans le champ de la pastille : le clavier passe
    // dans la pastille, sur son action principale.
    if (pill.open && event.key === "ArrowDown" && !event.altKey && !event.metaKey && !event.ctrlKey && !event.shiftKey
      && event.target instanceof HTMLInputElement && event.target === badge.input
      && sameGroup(classify(event.target), pill.kind) && !siteListOpen(event.target)) {
      const first = pill.buttons()[0];
      if (!first) return;
      event.preventDefault();
      event.stopPropagation();
      first.focus();
      return;
    }
    // Envoi au clavier : certains formulaires partent sans « submit ».
    if (event.key === "Enter" && event.target instanceof HTMLInputElement) {
      captureFrom(event.target);
    }
  }, true);

  addEventListener("scroll", () => badge.place(), true);
  addEventListener("resize", () => badge.place());

  ext.runtime.onMessage.addListener((message) => {
    // Remplissage demandé depuis la fenêtre de l'extension : seulement dans
    // le cadre visé, et s'il est toujours à l'adresse remplie.
    if (message?.kind === "apply" && forThisPage(message)) {
      const active = document.activeElement;
      // Choix fait dans la fenêtre de l'extension : le formulaire peut partir.
      apply(message.credentials, active instanceof HTMLInputElement && classify(active) ? active : null,
        { autoSubmit: true });
      pill.hide();
    }
    // Formulaire envoyé sans changer de page (application monopage).
    if (message?.kind === "offerSave" && window === top) showOffer();
  });

  // Page suivante d'un formulaire envoyé : une proposition attend peut-être.
  showOffer();
  // Formulaire de connexion déjà là, ou à venir.
  scan();
  observer?.observe(document.documentElement, {
    childList: true, subtree: true, attributes: true, attributeFilter: ["class", "style", "hidden", "type"],
  });
})();
