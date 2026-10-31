// In every page (and every frame): spots the sign-in forms and, when Verrou
// has a login (or a passkey) for this site, shows a pill at the top left of
// the page, like 1Password: the site, the suggested login, "Sign in" and
// "✕". "Sign in" fills then submits the form when nothing is left to type
// (setting in the extension's popup, on by default). Under the pill, the
// "Other logins" tab unrolls the site's other logins,
// "Fill with another login…" and, on a sign-up,
// "Generate a password". On a "new password" field, the pill suggests a
// strong password; on a payment or address form, a card or an identity.
// After a form is submitted, a banner at the same place offers to save the
// login in Verrou.
//
// In the active field, only a small Verrou icon, at the right edge, opens or
// closes the pill: no more menu hooked under the field, which got in the way
// of the sites' suggestion lists.
//
// When the page waits for a passkey in autofill (`mediation:
// "conditional"`), the pill first offers Verrou's passkey for this site
// (passkeys.js, main frame).
//
// The pill, the icon and the banner live in closed shadow DOMs: the page can
// neither read nor modify them, and only real events (`isTrusted`) trigger
// them. Secrets only arrive at fill time, for the chosen item.

(() => {
  if (globalThis.__verrouContent) return;
  globalThis.__verrouContent = true;
  // Extension API: `browser` (Firefox), otherwise `chrome` (Brave). The test on
  // `runtime.id` rules out a page element named "browser" (see browser.js).
  const ext = globalThis.browser?.runtime?.id ? globalThis.browser : globalThis.chrome;
  // Text of the interface in the browser's language (extension/_locales).
  const t = (name, ...substitutions) => ext.i18n.getMessage(name, substitutions.map(String));

  const USERNAME_HINT = /user|login|e-?mail|identifiant|courriel|account|compte|pseudo|nom d.utilisateur/i;
  const OTP_HINT = /otp|totp|2fa|mfa|one.?time|verification|vérification|authenticat|security.?code|code/i;
  const NEW_HINT = /new|nouveau|nouvelle|confirm|repeat|retype|again|verify|vérif|register|sign.?up|inscri|créer|create/i;
  const CURRENT_HINT = /current|old|actuel|ancien|existing/i;
  const SIGNUP_FORM_HINT = /register|sign.?up|inscri|create.?account|créer.?(un|votre).?compte|join/i;
  const LOGIN_FORM_HINT = /log.?in|sign.?in|se.?connecter|connexion|identifi/i;
  const SIGN_IN_STEP_HINT = /log.?in|sign.?in|connecter|connexion|identifi|\bnext\b|continue|continuer|suivant/i;
  const NEWSLETTER_FORM_HINT = /newsletter|subscribe|abonn/i;
  const EMAIL_HINT = /e-?mail|courriel/i;
  const CONFIRM_HINT = /confirm|repeat|retype|again|verify|vérif|répét/i;
  const TEXT_TYPES = new Set(["text", "email", "tel", ""]);

  // MARK: Fields

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

  // Role of each password field of the form: "current" (sign-in, old
  // password) or "new" (sign-up, change, confirmation).
  // `all`: hidden fields too (the form is leaving, the page changes).
  function passwordRoles(scope, all = false) {
    const fields = [...scope.querySelectorAll("input")]
      .filter((i) => typeOf(i) === "password" && (all ? !i.disabled : usable(i)));
    const roles = new Map();
    fields.forEach((input, index) => {
      const autocomplete = (input.autocomplete || "").toLowerCase();
      const hint = hintOf(input);
      let role;
      // Some sign-in pages mark their only password field "new-password",
      // to keep browsers from filling it: a lone field in a form (or on a
      // page) that says "log in", and nothing about signing up, is the
      // account's current password.
      if (autocomplete.includes("new-password") && fields.length === 1 && signInDespiteNewPassword(scope)) role = "current";
      else if (autocomplete.includes("new-password")) role = "new";
      else if (autocomplete.includes("current-password")) role = "current";
      else if (CURRENT_HINT.test(hint)) role = "current";
      else if (NEW_HINT.test(hint)) role = "new";
      // A single field: sign-in, unless it's a sign-up form.
      else if (fields.length === 1) role = SIGNUP_FORM_HINT.test(formHint(scope)) ? "new" : "current";
      // Two: the password and its confirmation. Three: the old one, then the new one twice.
      else if (fields.length === 2) role = "new";
      else role = index === 0 ? "current" : "new";
      roles.set(input, role);
    });
    return roles;
  }

  function signInDespiteNewPassword(scope) {
    const hint = formHint(scope);
    if (SIGNUP_FORM_HINT.test(hint) || SIGNUP_FORM_HINT.test(location.href)) return false;
    return LOGIN_FORM_HINT.test(hint) || LOGIN_FORM_HINT.test(location.href);
  }

  const roleOf = (input) => passwordRoles(scopeOf(input)).get(input) ?? null;

  // MARK: Cards and addresses

  // Role of a card or address field: `autocomplete` first, otherwise the
  // hints (name, label…), in French and in English.
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

  // Fields to fill in a form: visible inputs and drop-down lists.
  function formFields(scope) {
    return [...scope.querySelectorAll("input, select")].filter((element) =>
      !element.disabled && (element instanceof HTMLSelectElement ? visible(element) : usable(element))
      && (element instanceof HTMLSelectElement || !["hidden", "password", "checkbox", "radio", "submit", "button"].includes(typeOf(element))));
  }

  // "card" or "identity" (with the field's role), or null.
  function formKindOf(input) {
    const card = fieldRole(input, CARD_AUTOCOMPLETE, CARD_HINTS);
    if (card) return { kind: "card", role: card };
    const scope = scopeOf(input);
    // A sign-in form stays a sign-in form.
    if (scope.querySelector("input[type=password]")) return null;
    const role = fieldRole(input, IDENTITY_AUTOCOMPLETE, IDENTITY_HINTS);
    if (!role) return null;
    // An address, not a mere email field: three identity fields at least.
    const count = formFields(scope).filter((f) => fieldRole(f, IDENTITY_AUTOCOMPLETE, IDENTITY_HINTS)).length;
    return count >= 3 ? { kind: "identity", role } : null;
  }

  const MONTHS = ["jan", "f", "mar", "av|apr", "mai|may", "juin|jun", "juil|jul", "ao|aug", "sep", "oct", "nov", "d"];

  // Picks the option matching `value` (month, year, country…).
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

  // Fills the form of `anchor` with a card or an identity.
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

  // "username", "password", "new", "otp" or null.
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
      // The text field before the password is the username.
      const before = inputs.slice(0, inputs.indexOf(password)).filter(isText);
      if (before.at(-1) === input || type === "email" || USERNAME_HINT.test(hint)) return "username";
      return null;
    }
    // Multi-step sign-in: the username alone on the page.
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

  // The form's submit button: the first one of the form, or, without a
  // <form>, the first one after the last filled field.
  function submitButtonOf(scope, after) {
    const buttons = [...scope.querySelectorAll("button, input[type=submit]")].filter((button) =>
      !button.disabled && visible(button)
      && (button instanceof HTMLInputElement || (button.getAttribute("type") ?? "submit").toLowerCase() === "submit"));
    if (scope !== document || !after) return buttons[0] ?? null;
    return buttons.find((b) => after.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING) ?? null;
  }

  // MARK: Submit after filling

  // "Submit the form after filling" setting of the extension's popup, on by
  // default.
  async function autoSubmitEnabled() {
    try {
      const { autoSubmit } = await ext.storage.local.get("autoSubmit");
      return autoSubmit !== false;
    } catch {
      return true;
    }
  }

  // Field types that need nothing typed.
  const NOT_TYPED = new Set(["checkbox", "radio", "hidden", "submit", "button", "file", "image", "reset", "search"]);

  // The smallest element that contains all of `nodes`.
  function commonAncestor(nodes) {
    let node = nodes[0];
    while (node && !nodes.every((other) => node.contains(other))) node = node.parentNode;
    return node ?? document.documentElement;
  }

  // A visible, editable and empty field is left to fill (customer code,
  // digits of a split code…): it's up to the user to finish.
  function emptyFieldLeft(area) {
    return [...area.querySelectorAll("input")].some((input) =>
      usable(input) && !NOT_TYPED.has(typeOf(input)) && !input.value);
  }

  const CAPTCHA_SRC = /captcha|recaptcha|hcaptcha|challenges\.cloudflare|turnstile/i;

  // A visible captcha on the page. The reCAPTCHA v3 badge and the invisible
  // widgets don't count: they ask nothing of the user.
  function visibleCaptcha() {
    const invisible = (node) => node.closest(".grecaptcha-badge")
      || (node.getAttribute("data-size") ?? "").toLowerCase() === "invisible";
    const frames = [...document.querySelectorAll("iframe")].filter((frame) => {
      const src = frame.getAttribute("src") ?? "";
      return CAPTCHA_SRC.test(src) && !/[?&]size=invisible/i.test(src);
    });
    const widgets = [...document.querySelectorAll(".g-recaptcha, .h-captcha, .cf-turnstile, [data-sitekey]")]
      // The submit button that carries the invisible captcha itself.
      .filter((node) => !(node instanceof HTMLInputElement) && node.tagName !== "BUTTON");
    return [...frames, ...widgets].some((node) => !invisible(node) && visible(node));
  }

  // The form can be submitted: everything Verrou filled still is, nothing
  // left to type around, no captcha.
  function readyToSubmit(scope, filled, button) {
    if (!filled.length || !filled.every(([input, value]) => input.isConnected && input.value === value)) return false;
    const area = scope === document ? commonAncestor([...filled.map(([input]) => input), button].filter(Boolean)) : scope;
    return !emptyFieldLeft(area) && !visibleCaptcha();
  }

  // Submits like a click on the button: `requestSubmit` triggers the
  // validation and the "submit" event the sites listen to.
  function submit(scope, button) {
    if (scope !== document && typeof scope.requestSubmit === "function") {
      try {
        if (button && button.form === scope) scope.requestSubmit(button);
        else scope.requestSubmit();
        return;
      } catch {
        // Button refused by the browser: the click, below.
      }
    }
    button?.click();
  }

  // What Verrou just filled: submitted as is, the form has nothing new to
  // offer to save.
  let lastFill = { username: null, password: null, at: 0 };

  // Fills the form of `anchor` (or the page) with `credentials`, then puts
  // the cursor on the submit button. With `autoSubmit` (explicit choice of
  // the user: pill or extension's popup) and the setting on, the form is
  // submitted if nothing is left to type.
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
        // Form without <form>: the one of the filled field.
        if (scope === document && last) scope = scopeOf(last);
      }
      lastFill = { username: credentials.username ?? null, password: credentials.password ?? null, at: Date.now() };
      button = submitButtonOf(scope, last);
      (button ?? last)?.focus({ preventScroll: true });
    });
    if (!autoSubmit || !filled.length || (scope === document && !button)) return;
    // Let the frameworks process the input, then check again.
    (async () => {
      const enabled = await autoSubmitEnabled();
      await sleep(150);
      if (enabled && readyToSubmit(scope, filled, button)) submit(scope, button);
    })();
  }

  function emailField(input) {
    const autocomplete = (input.autocomplete || "").toLowerCase();
    return typeOf(input) === "email" || /\bemail\b/.test(autocomplete) || EMAIL_HINT.test(hintOf(input));
  }

  function signupEmail(input) {
    if (!emailField(input) || CONFIRM_HINT.test(hintOf(input))) return false;
    if (newPasswordField(input)) return true;
    const scope = scopeOf(input);
    return scope !== document && SIGNUP_FORM_HINT.test(formHint(scope))
      || SIGNUP_FORM_HINT.test(`${location.pathname} ${document.title}`);
  }

  let lastAlias = { value: null, at: 0 };

  function applyAlias(address, anchor) {
    withFilling(() => {
      setValue(anchor, address);
      for (const input of inputsOf(scopeOf(anchor))) {
        if (input !== anchor && isText(input) && !input.value && emailField(input) && CONFIRM_HINT.test(hintOf(input))) {
          setValue(input, address);
        }
      }
      anchor.focus({ preventScroll: true });
    });
    lastAlias = { value: address, at: Date.now() };
  }

  function aliasInput(inputs) {
    if (!lastAlias.value || Date.now() - lastAlias.at > FILL_MEMORY_MS) return null;
    return inputs.find((input) => isText(input) && input.value.trim() === lastAlias.value) ?? null;
  }

  // The generated password in all the "new" fields of the form (the
  // password and its confirmation).
  function applyGenerated(password, anchor) {
    withFilling(() => {
      for (const [input, role] of passwordRoles(scopeOf(anchor))) {
        if (role === "new") setValue(input, password);
      }
      anchor.focus({ preventScroll: true });
    });
  }

  // MARK: Messages to the service worker

  async function send(message) {
    try {
      return (await ext.runtime.sendMessage(message)) ?? { state: "offline" };
    } catch {
      return { state: "offline" };
    }
  }

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const SITE = location.hostname.replace(/^www\./, "");
  const ANNOUNCE_DELAY_MS = 150;
  const NOTICE_MS = 6000;
  const FIELD_TARGET_PX = 24;

  // MARK: Shared style

  // A dark capsule with a purple border, like 1Password's, whatever the
  // theme; the entry animation goes away with "reduce motion".
  const STYLE = `
    :host { all: initial; }
    * { box-sizing: border-box; }
    .stack {
      display: flex; flex-direction: column; align-items: center; gap: 8px;
      margin: 0 auto; max-width: calc(100vw - 32px);
      font: .8125em/1.35 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #f4f4f6;
      -webkit-font-smoothing: antialiased;
    }
    /* The host covers the whole width of the top of the page without
       catching clicks: only the pill and the banner receive them. */
    .pill, .banner { pointer-events: auto; }
    .pill { display: flex; flex-direction: column; align-items: center; max-width: 100%; animation: drop .18s ease-out; }
    .shell, .tab, .banner { background: #1b1b20; border: 1.5px solid #6c6cf0; }
    /* The capsule, then, open, a rounded card: header, rule, accounts. */
    .shell {
      display: flex; flex-direction: column; min-width: 27.5em; max-width: min(43em, calc(100vw - 32px));
      border-radius: 999px; overflow: hidden;
      box-shadow: 0 12px 34px rgba(0,0,0,.38), 0 0 0 4px rgba(108,108,240,.18);
    }
    .shell.open { border-radius: 28px; }
    .capsule { display: flex; align-items: center; gap: 14px; padding: 10px 12px 10px 14px; }
    .icon { flex: none; display: grid; place-items: center; width: 34px; height: 34px; border-radius: 10px;
      background: linear-gradient(135deg, #7474f4, #3b3bbd); }
    .icon svg { width: 20px; height: 20px; display: block; }
    .text { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 1px; }
    .title, .sub { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .capsule .title { white-space: normal; overflow: visible; overflow-wrap: anywhere; }
    .title { font-weight: 600; font-size: 1.115em; }
    .sub { color: #a3a3ad; font-size: .962em; }
    button { font: inherit; color: inherit; background: none; border: 0; margin: 0; padding: 0; cursor: pointer; }
    button:focus-visible { outline: 2px solid #a5a5ff; outline-offset: 2px; }
    .primary {
      flex: none; max-width: 20em; padding: 9px 18px; border-radius: 999px; font-size: 1.077em;
      background: #5b5bd6; color: #fff; font-weight: 600;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .primary:hover { background: #6b6be6; }
    .close { flex: none; width: 32px; height: 32px; border-radius: 50%; color: #a3a3ad; font-size: 1.154em; }
    .close:hover { background: rgba(255,255,255,.1); color: #fff; }
    .tab {
      display: flex; align-items: center; gap: 6px; padding: 5px 16px 7px;
      border-top: 0; border-radius: 0 0 12px 12px; font-size: .962em; color: #d4d4da;
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
      font-weight: 700; font-size: 1em; color: #2b2b6e; background: #b9b9f6;
    }
    .banner {
      width: 30.75em; max-width: 100%; padding: 12px 14px; border-radius: 16px;
      box-shadow: 0 10px 30px rgba(0,0,0,.35), 0 0 0 3px rgba(108,108,240,.2); animation: drop .18s ease-out;
    }
    .banner .title { white-space: normal; }
    .head { display: flex; gap: 10px; align-items: center; }
    .actions { display: flex; gap: 8px; justify-content: flex-end; align-items: center; flex-wrap: wrap; margin-top: 10px; }
    .choice { display: flex; gap: 8px; margin-left: auto; }
    .actions button { padding: 6px 12px; border-radius: 999px; background: rgba(255,255,255,.1); white-space: nowrap; }
    .actions button.primary { background: #5b5bd6; }
    .actions button.quiet { background: none; color: #a3a3ad; padding: 6px 4px; margin-right: auto; }
    .field { display: grid; place-items: center; width: 100%; height: 100%; border-radius: 6px; }
    .field .icon { width: 26px; height: 26px; border-radius: 8px; transform: scale(var(--scale, .75)); }
    .field .icon svg { width: 16px; height: 16px; }
    .announce {
      position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; border: 0;
      overflow: hidden; clip-path: inset(50%); white-space: nowrap;
    }
    @keyframes drop { from { opacity: 0; transform: translateY(-6px); } }
    @media (prefers-reduced-motion: reduce) {
      .pill, .banner { animation: none; }
      .chev { transition: none; }
    }
    @media (prefers-color-scheme: dark) {
      .shell, .tab, .banner { background: #222228; }
    }
  `;

  // A closed shadow DOM host. `pin` holds it in place with inline
  // `!important` styles: a style sheet of the page neither moves nor hides
  // it.
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
    "pointer-events": "auto", margin: "0", padding: "0", "z-index": "2147483647", "font-size": "medium",
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

  // Clickjacking: the page can make the pill invisible (opacity, filter,
  // clip or mask on <html>, which the pill, placed under <html>, can't
  // undo), cover it with a decoy, or slide its field under the pointer just
  // before a click. A mouse click only counts on a pill shown for a moment,
  // visible, and in the foreground under the pointer. Chrome and Brave also
  // tell whether anything covers it (IntersectionObserver v2); Firefox
  // doesn't know: Verrou asks for Touch ID for a card anyway.
  const MIN_SHOWN_MS = 300;
  const shownAt = new WeakMap();
  const reallyVisible = new WeakMap();
  let visibilityObserver;

  // Puts the pill (`host`) in the page and notes when.
  function attach(host) {
    if (host.isConnected) return;
    document.documentElement.append(host);
    shownAt.set(host, Date.now());
    if (typeof IntersectionObserver !== "function" || typeof IntersectionObserverEntry !== "function"
      || !("isVisible" in IntersectionObserverEntry.prototype)) return;
    visibilityObserver ??= new IntersectionObserver((entries) => {
      for (const entry of entries) reallyVisible.set(entry.target, entry.isVisible);
    }, { trackVisibility: true, delay: 100 });
    visibilityObserver.observe(host);
  }

  // Computed value of a property, or the default one if the browser doesn't
  // give it.
  function computed(style, name, fallback) {
    const value = style?.[name];
    return value === undefined || value === "" ? fallback : String(value);
  }

  function seenByTheUser(button, event) {
    const host = button.getRootNode()?.host;
    if (!host) return false;
    const page = getComputedStyle(document.documentElement);
    if (computed(page, "opacity", "1") !== "1" || computed(page, "visibility", "visible") !== "visible"
      || computed(page, "filter", "none") !== "none" || computed(page, "clipPath", "none") !== "none"
      || computed(page, "maskImage", computed(page, "webkitMaskImage", "none")) !== "none") return false;
    const own = getComputedStyle(host);
    if (computed(own, "opacity", "1") !== "1" || computed(own, "visibility", "visible") !== "visible") return false;
    if (reallyVisible.get(host) === false) return false;
    // Keyboard (Enter, Space on the button): no pointer, and the page can't
    // type into the pill.
    if (!(event.detail > 0)) return true;
    if (Date.now() - (shownAt.get(host) ?? 0) < MIN_SHOWN_MS) return false;
    return typeof document.elementFromPoint !== "function"
      || document.elementFromPoint(event.clientX, event.clientY) === host;
  }

  // A button that only obeys real clicks (mouse, or Enter and Space on the
  // button, which the browser turns into a real click), on a pill the user
  // sees.
  function trustedButton(label, className, action) {
    const button = document.createElement("button");
    button.setAttribute("type", "button");
    button.className = className;
    button.textContent = label;
    button.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (event.isTrusted && seenByTheUser(button, event)) action();
    });
    return button;
  }

  // "Maif" → "Ma", like 1Password's badges.
  function initials(title) {
    const word = (title ?? "").trim().replace(/^[^\p{L}\p{N}]+/u, "");
    if (!word) return "?";
    return word[0].toUpperCase() + (word[1] ?? "").toLowerCase();
  }

  function textBlock(title, subtitle) {
    const text = div("text");
    text.append(div("title", title), div("sub", subtitle ?? ""));
    return text;
  }

  // Verrou's padlock: shackle, body and keyhole, in SVG (the CSS drawing got
  // distorted depending on the size).
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

  // MARK: Pill at the top left (and save banner)

  // A single host, fixed 16 px from the top left corner, above the page: the
  // pill, then the save banner below.
  const ui = {
    host: null,
    root: null,
    stack: null,
    live: null,
    said: null,
    saying: null,

    ensure() {
      if (this.host) return;
      ({ host: this.host, root: this.root } = shadowHost("verrou-pill"));
      this.stack = div("stack");
      this.live = div("announce");
      this.live.setAttribute("role", "status");
      this.live.setAttribute("aria-live", "polite");
      this.live.setAttribute("aria-atomic", "true");
      this.root.append(this.stack, this.live);
      // A click in the pill doesn't take the focus from the page.
      this.root.addEventListener("mousedown", (event) => event.preventDefault());
      this.root.addEventListener("keydown", (event) => pillKey(event));
    },

    attach() {
      this.ensure();
      // Centered at the top of the page, like 1Password's: the host takes
      // the whole width (without a transform, which the page thus can't
      // hijack) and lets clicks outside the pill through.
      pin(this.host, {
        ...HOST_STYLES, position: "fixed", top: "16px", left: "0", right: "0", bottom: "auto",
        width: "auto", "pointer-events": "none",
      });
      attach(this.host);
    },

    // Nothing left to show: the host leaves the page.
    sync() {
      if (!this.host || this.stack.children.length) return;
      this.host.remove();
      clearTimeout(this.saying);
      this.live.textContent = "";
      this.said = null;
    },

    announce(text) {
      if (text === this.said) return;
      this.said = text;
      clearTimeout(this.saying);
      this.live.textContent = "";
      this.saying = setTimeout(() => { this.live.textContent = text; }, ANNOUNCE_DELAY_MS);
    },
  };

  // Sign-in forms already offered, by "step" (the fields present: username,
  // password, code…): the pill comes by itself once per step, never on each
  // focus. Closed (✕, Escape): nothing more by itself on this page.
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
    // Changes on each close: a wait in progress (confirmation, unlock)
    // stops.
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

    // A waiting state: no more action, only the cross.
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
      capsule.append(icon(), textBlock(view.title, view.subtitle));
      if (view.primary) {
        const primary = trustedButton(view.primary.label, "primary", view.primary.run);
        primary.setAttribute("data-key", "primary");
        capsule.append(primary);
      }
      const close = trustedButton("✕", "close", () => this.dismiss());
      close.setAttribute("aria-label", t("pillClose"));
      close.setAttribute("title", t("close"));
      close.setAttribute("data-key", "close");
      capsule.append(close);
      const shell = div(`shell${this.expanded && view.others?.length ? " open" : ""}`);
      shell.append(capsule);
      area.append(shell);
      if (view.others?.length) {
        const tab = trustedButton(view.tab ?? t("pillOtherLogins"), "tab", () => {
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
          list.setAttribute("aria-label", view.tab ?? t("pillOtherLogins"));
          view.others.forEach((row, index) => {
            const line = trustedButton("", "row", row.run);
            line.setAttribute("data-key", `row-${index}`);
            line.setAttribute("aria-label", [row.title, row.subtitle].filter(Boolean).join(", "));
            line.append(div("badge", row.badge), textBlock(row.title, row.subtitle));
            list.append(line);
          });
          shell.append(list);
        }
        area.append(tab);
      }
      if (this.node?.isConnected) this.node.replaceWith(area);
      else ui.stack.prepend(area);
      this.node = area;
      // Rendered from the keyboard: the focus stays on the same button.
      if (focused) this.buttons().find((b) => b.getAttribute("data-key") === focused)?.focus();
      ui.announce(t("announce", view.title, view.subtitle ?? ""));
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

    // ✕ or Escape: nothing more by itself on this page.
    dismiss() {
      const anchor = this.anchor;
      const inside = Boolean(ui.root?.activeElement);
      dismissed = true;
      observer?.disconnect();
      this.hide();
      if (inside && anchor?.isConnected) anchor.focus({ preventScroll: true });
    },
  };

  // Keyboard in the pill (real keys only): Escape closes it, the arrows move
  // from one button to the next, Tab past either end goes back to the
  // field; Enter and Space are the buttons' own.
  function pillKey(event) {
    if (!event.isTrusted || !pill.open) return;
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      pill.dismiss();
      return;
    }
    if (event.key === "Tab" && !event.altKey && !event.ctrlKey && !event.metaKey) {
      const buttons = pill.buttons();
      const index = buttons.indexOf(ui.root.activeElement);
      const edge = event.shiftKey ? 0 : buttons.length - 1;
      if (index < 0 || index !== edge || !pill.anchor?.isConnected) return;
      event.preventDefault();
      event.stopPropagation();
      pill.anchor.focus({ preventScroll: true });
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

  // The field to fill at the time of the choice: the active field if it is
  // of the same kind, otherwise the pill's, otherwise the one the page shows
  // now (single-page application that redrew its form).
  function fillTarget(kind, anchor) {
    const active = document.activeElement;
    if (active instanceof HTMLInputElement && sameGroup(classify(active), kind)) return active;
    if (anchor?.isConnected && usable(anchor)) return anchor;
    return LOGIN_KINDS.has(kind) ? loginFields().anchor : null;
  }

  // Tries again while Verrou waits for the confirmation of a protected item
  // (Touch ID or master password), one minute at most, with the pill
  // open.
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
      pill.wait(t("confirmInVerrou"), t("pillProtected", item.title));
      credentials = await retryUntilConfirmed("fill", item.id, token);
    }
    if (pill.token !== token) return;
    const target = fillTarget(kind, anchor);
    pill.hide();
    // Explicit choice in the pill (real click): the form can be submitted.
    if (credentials?.ok) apply(credentials, target, { autoSubmit: true });
  }

  async function fillCardOrIdentity(item, kind, anchor) {
    const token = pill.token;
    let reply = await send({ kind: "fillForm", item: item.id });
    if (reply?.state === "confirm") {
      pill.wait(t("confirmInVerrou"), t("pillProtected", item.title));
      reply = await retryUntilConfirmed("fillForm", item.id, token);
    }
    if (pill.token !== token) return;
    const target = fillTarget(kind, anchor) ?? anchor;
    pill.hide();
    if (reply?.ok && target) applyForm(reply.data, target);
  }

  // After "Unlock" or "Open Verrou": the pill fills in as soon as Verrou
  // is open (a minute and a half at most).
  async function unlock(anchor, kind) {
    pill.wait(t("unlockWait"), t("unlockHint"));
    const token = pill.token;
    await send({ kind: "unlock" });
    const form = kind === "card" || kind === "identity";
    for (let tries = 0; tries < 90; tries += 1) {
      await sleep(1000);
      if (pill.token !== token) return;
      const reply = await send({ kind: form ? "forms" : "suggest" });
      if (pill.token !== token) return;
      if (reply.state === "locked" || reply.state === "offline") continue;
      const view = reply.state === "unlocked" ? await viewFor(anchor, kind, true) : null;
      if (pill.token !== token) return;
      if (view) pill.show(anchor, kind, view, { expanded: !view.primary });
      else pill.hide();
      return;
    }
    if (pill.token === token) pill.hide();
  }

  // MARK: What the pill offers

  function lockedView(anchor, kind) {
    return {
      title: SITE,
      subtitle: t("verrouLocked"),
      primary: { label: t("unlock"), run: () => unlock(anchor, kind) },
      others: [],
    };
  }

  // Opened by hand (field icon) while Verrou doesn't respond.
  function unavailableView(state, anchor, kind) {
    if (state === "unpaired") return { title: t("pillUnpairedTitle"), subtitle: t("pillUnpairedHint"), primary: null, others: [] };
    return {
      title: SITE,
      subtitle: t("verrouUnreachable"),
      primary: { label: t("pillOpenVerrou"), run: () => unlock(anchor, kind) },
      others: [],
    };
  }

  // The interface of passkeys.js, in the main frame only.
  const passkeyMenu = () => (window === top ? globalThis.__verrouPasskeyMenu : undefined);

  // Verrou's passkeys the page is waiting for, for a sign-in field.
  async function passkeyEntries(kind) {
    const api = passkeyMenu();
    if (!api || (kind !== "username" && kind !== "password")) return { state: "none" };
    try {
      return await api.entries();
    } catch {
      return { state: "none" };
    }
  }

  // A "new password" field of the form of `anchor` (sign-up).
  function newPasswordField(anchor) {
    for (const [input, role] of passwordRoles(anchor ? scopeOf(anchor) : document)) {
      if (role === "new") return input;
    }
    return null;
  }

  function generateRow(field) {
    const password = globalThis.verrouGenerator.password();
    return {
      badge: "✦", title: t("pillGenerate"), subtitle: t("pillPasswordDescription", password.length),
      run: () => {
        pill.hide();
        applyGenerated(password, field);
      },
    };
  }

  async function aliasFor(anchor, kind) {
    if (kind !== "username" || !anchor || !signupEmail(anchor)) return null;
    const reply = await send({ kind: "alias" });
    if (!reply?.ok || typeof reply.address !== "string") return null;
    return {
      badge: "@", title: t("pillCreateAlias"), subtitle: reply.address, mono: true,
      run: () => {
        pill.hide();
        applyAlias(reply.address, anchor);
      },
    };
  }

  function aliasView(row, others = []) {
    return {
      title: SITE,
      subtitle: row.subtitle,
      mono: true,
      primary: { label: t("pillCreateAlias"), run: row.run },
      others,
    };
  }

  // "Fill with another login…": the extension's popup, where the login to
  // link to this site is chosen. The page sees nothing of it.
  function linkRow() {
    return {
      badge: "…", title: t("otherLogin"), subtitle: t("pillLinkHint"),
      run: () => {
        pill.hide();
        send({ kind: "openLinkSite" });
      },
    };
  }

  async function loginView(anchor, kind, manual, aliasOnly = false) {
    const [reply, passkeys, alias] = await Promise.all([
      send({ kind: "suggest" }), passkeyEntries(kind), aliasFor(anchor, kind),
    ]);
    if (aliasOnly && !alias) return null;
    if (reply.state === "locked" || passkeys.state === "locked") {
      if (alias) {
        const locked = lockedView(anchor, kind);
        return aliasView(alias, [{ badge: "🔒", title: locked.primary.label, subtitle: locked.title, run: locked.primary.run }]);
      }
      // Locked: not for a mere verification code, unless by hand.
      return kind === "otp" && !manual ? null : lockedView(anchor, kind);
    }
    if (reply.state !== "unlocked" && passkeys.state !== "ready") return manual ? unavailableView(reply.state, anchor, kind) : null;
    // Passkeys first, like the browser.
    const rows = [
      ...(passkeys.state === "ready" ? passkeys.items : []).map((item) => ({
        badge: "🔑",
        title: t("pillPasskey", item.user_name || item.title),
        subtitle: item.title,
        username: item.user_name || item.title,
        action: t("pillSignInPasskey"),
        run: () => {
          // The signature and its progress window: passkeys.js.
          pill.hide();
          passkeyMenu()?.choose(item.credential);
        },
      })),
      ...(reply.state === "unlocked" ? reply.items : [])
        .filter((item) => kind !== "otp" || item.has_totp)
        .map((item) => ({
          badge: initials(item.title),
          title: kind === "otp" ? t("pillCodeOf", item.title) : item.title,
          subtitle: item.username,
          username: item.username,
          action: kind === "otp" ? t("pillFillCode") : t("pillSignIn"),
          run: () => fillLogin(item, kind, anchor),
        })),
    ];
    if (!rows.length && !manual && !alias) return null;
    const [top, ...rest] = rows;
    const fresh = newPasswordField(anchor);
    const extras = [
      ...(alias && top ? [alias] : []),
      ...(fresh ? [generateRow(fresh)] : []),
      ...(reply.state === "unlocked" ? [linkRow()] : []),
    ];
    if (!top && alias) return { ...aliasView(alias, extras), tab: t("pillOtherLogins") };
    return {
      title: SITE,
      subtitle: top ? top.username || "—" : kind === "otp" ? t("pillNoCode") : t("pillNoLogin"),
      primary: top ? { label: top.action, run: top.run } : null,
      tab: rest.length ? t("pillOtherLogins") : t("pillMoreOptions"),
      others: [...rest, ...extras],
    };
  }

  async function formView(anchor, kind, manual) {
    const card = kind === "card";
    const reply = await send({ kind: "forms" });
    if (reply.state === "locked") return lockedView(anchor, kind);
    if (reply.state !== "unlocked") return manual ? unavailableView(reply.state, anchor, kind) : null;
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
      subtitle: top ? top.title : card ? t("pillNoCard") : t("pillNoAddress"),
      primary: top
        ? { label: card ? t("pillFillCard", top.subtitle ?? "").trim() : t("pillFillAddress"), run: top.run }
        : null,
      tab: card ? t("pillOtherCards") : t("pillOtherAddresses"),
      others: rest,
    };
  }

  function generatorView(anchor) {
    const password = globalThis.verrouGenerator.password();
    return {
      title: SITE,
      subtitle: t("pillPasswordDescription", password.length),
      primary: {
        label: t("pillSuggestPassword"),
        run: () => {
          pill.hide();
          applyGenerated(password, anchor);
        },
      },
      others: [],
    };
  }

  async function viewFor(anchor, kind, manual, aliasOnly) {
    // Offered even with the vault locked: nothing leaves Verrou.
    if (kind === "new") return generatorView(anchor);
    if (kind === "card" || kind === "identity") return formView(anchor, kind, manual);
    return loginView(anchor, kind, manual, aliasOnly);
  }

  // Shows the pill for `anchor`. By itself (`manual` false): nothing without
  // a login for this site, nor after a close. `refresh`: update of the open
  // pill, which goes away if nothing is left.
  async function offer(anchor, kind, { manual = false, refresh = false, aliasOnly = false } = {}) {
    const seq = ++offerSeq;
    const view = await viewFor(anchor, kind, manual, aliasOnly);
    if (seq !== offerSeq) return;
    if (!view) {
      if (refresh && pill.open && !pill.busy) pill.hide();
      return;
    }
    if (!manual && (dismissed || pill.busy)) return;
    const keepOpen = refresh && pill.open && pill.expanded;
    pill.show(anchor, kind, view, { expanded: keepOpen || (manual && !view.primary) });
  }

  // MARK: Sign-in forms of the page

  // A username alone (multi-step sign-in) only counts if it presents itself
  // as such: not the email field of a newsletter.
  function strongUsername(input) {
    const autocomplete = (input.autocomplete || "").toLowerCase();
    return /\b(username|webauthn)\b/.test(autocomplete)
      || /user|login|identifiant|account|compte|pseudo/i.test(`${input.name} ${input.id}`)
      || signInStep(input);
  }

  // A lone e-mail field on a page or in a form that says "log in" or "next"
  // (EDF, Vercel, Airbnb: the first step of a sign-in), unless its form
  // speaks of a newsletter.
  function signInStep(input) {
    const form = formHint(scopeOf(input));
    if (NEWSLETTER_FORM_HINT.test(form)) return false;
    const buttons = scopeOf(input) === document
      ? [...document.querySelectorAll("button, input[type=submit]")].map((b) => b.textContent || b.value).join(" ")
      : "";
    return SIGN_IN_STEP_HINT.test(`${form} ${buttons} ${document.title} ${location.pathname}`);
  }

  // The page's sign-in field, its kind, and the step (the kinds of fields
  // present).
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

  // Looks for a sign-in form and, the first time for this step, offers the
  // site's logins.
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

  // Forms that arrive after loading (single-page applications, sign-in
  // dialogs).
  // Movements of our own hosts don't count.
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

  // The page just asked for a passkey (or the request ended): the open pill
  // updates; closed, it comes back to offer the passkey (new request of the
  // page), never for a mere password already offered.
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

  // MARK: Verrou icon in the active field

  const badge = {
    host: null,
    root: null,
    input: null,

    ensure() {
      if (this.host) return;
      ({ host: this.host, root: this.root } = shadowHost("verrou-field"));
      const button = trustedButton("", "field", () => this.toggle());
      button.setAttribute("aria-label", t("fieldButton"));
      button.setAttribute("title", t("fieldButton"));
      // Out of the page's tab order; a click keeps the focus in the
      // field.
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
      attach(this.host);
    },

    // At the right edge of the field, vertically centered; too small: nothing.
    place() {
      if (!this.input) return false;
      if (!this.input.isConnected) {
        this.hide();
        return false;
      }
      const box = this.input.getBoundingClientRect();
      const glyph = Math.min(22, box.height - 6);
      if (glyph < 14 || box.width < 80) {
        this.host?.remove();
        return false;
      }
      const size = Math.max(FIELD_TARGET_PX, glyph);
      this.button.style.setProperty("--scale", String(glyph / 26));
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

    // Opens the pill for this field (even after a close), or closes it.
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

  // Secrets only go to the frame whose address is the one Verrou gave them
  // for (the page may have changed in the meantime).
  function forThisPage(message) {
    return typeof message.origin === "string" && message.origin === location.origin;
  }

  // MARK: Saving after a form is submitted

  let lastCapture = { key: "", at: 0 };
  const FILL_MEMORY_MS = 5 * 60_000;

  // Username and password of the form, at the moment it is submitted.
  function capture(scope) {
    const roles = passwordRoles(scope, true);
    const inputs = [...scope.querySelectorAll("input")].filter((i) => !i.disabled);
    if (!roles.size) {
      // First step of a sign-in: the username alone, kept for the next step.
      const username = aliasInput(inputs) ?? inputs.find((i) => classify(i) === "username");
      if (username?.value.trim()) send({ kind: "rememberUsername", username: username.value.trim() });
      return;
    }
    const filled = [...roles].filter(([input]) => input.value);
    const fresh = filled.filter(([, role]) => role === "new").map(([input]) => input.value);
    const current = filled.find(([, role]) => role === "current")?.[0].value ?? null;
    // Confirmation different from the password: the site will refuse.
    if (new Set(fresh).size > 1) return;
    const password = fresh[0] ?? current;
    if (!password) return;
    const firstPassword = [...roles.keys()][0];
    const texts = inputs.filter(isText);
    const before = texts.filter((i) => i.compareDocumentPosition(firstPassword) & Node.DOCUMENT_POSITION_FOLLOWING);
    const username = (aliasInput(texts) ?? texts.find((i) => classify(i) === "username") ?? before.at(-1))?.value.trim() ?? "";
    // Username and password as Verrou just filled them (automatic submit or
    // Enter): nothing new to save.
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
    // Form without <form>: only if there is a password on the page.
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


  // MARK: "Save in Verrou" banner (main frame)

  // In the same corner as the pill, under it, in the same dark capsule.
  const banner = {
    node: null,
    timer: null,

    show({ title, subtitle, closable = false }, ...nodes) {
      ui.attach();
      clearTimeout(this.timer);
      const box = div("banner");
      box.setAttribute("role", "dialog");
      box.setAttribute("aria-label", t("bannerLabel"));
      const head = div("head");
      head.append(icon(), textBlock(title, subtitle));
      if (closable) {
        const close = trustedButton("✕", "close", () => this.hide());
        close.setAttribute("aria-label", t("close"));
        close.setAttribute("title", t("close"));
        head.append(close);
      }
      box.append(head, ...nodes);
      if (this.node?.isConnected) this.node.replaceWith(box);
      else ui.stack.append(box);
      this.node = box;
      ui.announce(t("announce", title, subtitle));
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

  function actions(aside, ...choice) {
    const row = div("actions");
    const group = div("choice");
    group.append(...choice);
    if (aside) row.append(aside);
    row.append(group);
    return row;
  }

  function notify(message, detail = "Verrou") {
    banner.show({ title: message, subtitle: detail, closable: true });
    banner.hide(NOTICE_MS);
  }

  async function dismissSave() {
    await send({ kind: "dismissSave" });
    banner.hide();
  }

  async function showOffer() {
    if (window !== top) return;
    const offer = await send({ kind: "pendingSave" });
    if (!offer?.action) return;
    const who = `${offer.username || t("bannerNoUsername")} · ${offer.site}`;
    if (offer.action === "locked") {
      banner.show(
        { title: t("bannerSaveTitle"), subtitle: who },
        actions(
          null,
          trustedButton(t("bannerNotNow"), "", dismissSave),
          trustedButton(t("unlock"), "primary", async () => {
            await send({ kind: "unlock" });
            banner.show({ title: t("unlockWait"), subtitle: t("unlockHint") });
            waitThenOffer();
          }),
        ),
      );
      return;
    }
    const update = offer.action === "update";
    banner.show(
      { title: update ? t("bannerUpdateTitle", offer.title) : t("bannerSaveTitle"), subtitle: who },
      actions(
        trustedButton(t("bannerNever"), "quiet", async () => {
          await send({ kind: "neverSave" });
          banner.hide();
        }),
        trustedButton(t("bannerNotNow"), "", dismissSave),
        trustedButton(update ? t("bannerUpdate") : t("save"), "primary", async () => {
          banner.show({ title: t("saving"), subtitle: offer.site });
          const result = await send({ kind: "confirmSave" });
          if (result?.ok) notify(update ? t("bannerPasswordUpdated") : t("bannerSaved"));
          else notify(t("saveFailed"), result?.reason ?? t("verrouNotResponding"));
        }),
      ),
    );
  }

  // After "Unlock": the real offer as soon as Verrou is open.
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

  // MARK: Listeners

  // The site handles a suggestion list under this field itself: the down
  // arrow stays its own.
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
      // Form that appeared without a visible mutation (style of a parent…).
      scheduleScan(0);
      if (kind === "username" && !target.value && !dismissed && !pill.busy && !queried.has("alias")
        && signupEmail(target)) {
        queried.add("alias");
        offer(target, kind, { aliasOnly: true });
      }
      return;
    }
    // Password to create (empty field: don't overwrite what is being typed),
    // card, address: the pill comes the first time the field is entered.
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
    // Typing one's own new password: the suggestion goes away.
    if (event.isTrusted && pill.open && pill.kind === "new" && !pill.busy && event.target === pill.anchor) pill.hide();
  }, true);

  document.addEventListener("keydown", (event) => {
    // Real keys only: the page doesn't choose on behalf of the user.
    if (!event.isTrusted) return;
    if (pill.open && event.key === "Escape") {
      // The event isn't stopped: the page closes its own lists too.
      pill.dismiss();
      return;
    }
    // Down arrow in the pill's field: the keyboard moves into the pill, on
    // its main action.
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
    // Keyboard submit: some forms are submitted without "submit".
    if (event.key === "Enter" && event.target instanceof HTMLInputElement) {
      captureFrom(event.target);
    }
  }, true);

  addEventListener("scroll", () => badge.place(), true);
  addEventListener("resize", () => badge.place());

  ext.runtime.onMessage.addListener((message) => {
    // Fill requested from the extension's popup: only in the targeted frame,
    // and if it is still at the filled address.
    if (message?.kind === "apply" && forThisPage(message)) {
      const active = document.activeElement;
      // Choice made in the extension's popup: the form can be submitted.
      apply(message.credentials, active instanceof HTMLInputElement && classify(active) ? active : null,
        { autoSubmit: true });
      pill.hide();
    }
    // Form submitted without changing page (single-page application).
    if (message?.kind === "offerSave" && window === top) showOffer();
  });

  // Next page of a submitted form: an offer may be waiting.
  showOffer();
  // Sign-in form already there, or to come.
  scan();
  observer?.observe(document.documentElement, {
    childList: true, subtree: true, attributes: true, attributeFilter: ["class", "style", "hidden", "type"],
  });
})();
