// Safari on the iPhone (VerrouSafari, the app's Safari extension): when iOS
// AutoFill fills a sign-in form (Verrou's login, picked above the keyboard),
// submits it, as the Mac extension's "Sign in" does. A two-step form
// (username, then password on the next page) goes through both steps.
//
// The fill itself stays the system's: this script never sees the vault and
// asks nothing of Verrou. It only watches for fields filled without a
// keystroke, then applies content.js's rules: a sign-in form only (a
// password filled, or a username alone), nothing left to type, no visible
// captcha, once per form. An address or a card filled by Safari is never
// submitted.

(() => {
  if (globalThis.__verrouAutofillSubmit) return;
  globalThis.__verrouAutofillSubmit = true;

  const USERNAME_HINT = /user|login|e-?mail|identifiant|courriel|account|compte|pseudo|nom d.utilisateur/i;
  // Fields of a payment or address form (`autocomplete` tokens).
  const NOT_SIGN_IN = /cc-|address|postal|country|tel|bday|organization|given-name|family-name|new-password/i;
  const CAPTCHA_SRC = /captcha|recaptcha|hcaptcha|challenges\.cloudflare|turnstile/i;
  // Field types that need nothing typed.
  const NOT_TYPED = new Set(["checkbox", "radio", "hidden", "submit", "button", "file", "image", "reset", "search"]);
  // iOS fills the username, then the password: one decision for both.
  const SETTLE_MS = 300;
  // A form that comes back (wrong password) isn't submitted in a loop.
  const RESUBMIT_MS = 10_000;

  const typeOf = (input) => (input.getAttribute("type") ?? "text").toLowerCase();

  function visible(node) {
    const box = node.getBoundingClientRect();
    if (box.width < 2 || box.height < 2) return false;
    const style = getComputedStyle(node);
    return style.visibility !== "hidden" && style.display !== "none" && style.opacity !== "0";
  }

  function usable(input) {
    return input instanceof HTMLInputElement && !input.disabled && !input.readOnly && visible(input);
  }

  const scopeOf = (input) => input.form ?? input.closest("form") ?? document;
  const inputsOf = (scope) => [...scope.querySelectorAll("input")].filter(usable);

  // MARK: Filled by the system

  let lastKeystroke = 0;
  document.addEventListener("keydown", () => { lastKeystroke = Date.now(); }, true);
  document.addEventListener("beforeinput", (event) => {
    if (event.inputType?.startsWith("insertText") || event.inputType?.startsWith("delete")) lastKeystroke = Date.now();
  }, true);

  // WebKit marks what its AutoFill filled (`:autofill`, formerly
  // `:-webkit-autofill`); without that, a value that arrives without a
  // keystroke, nor a paste.
  function filledBySystem(input, event) {
    for (const selector of [":autofill", ":-webkit-autofill"]) {
      try {
        if (input.matches(selector)) return true;
      } catch {
        // Selector unknown to this engine.
      }
    }
    return !event.inputType?.startsWith("insertFromPaste") && Date.now() - lastKeystroke > 500;
  }

  // MARK: Sign-in form

  function usernameLike(input) {
    if (["email", "text", "tel"].indexOf(typeOf(input)) < 0) return false;
    const autocomplete = input.getAttribute("autocomplete") ?? "";
    if (/username|email/i.test(autocomplete)) return true;
    return USERNAME_HINT.test(`${input.name} ${input.id} ${input.placeholder} ${input.getAttribute("aria-label") ?? ""}`);
  }

  // The form, if it is a sign-in ready to go: its password filled (a single
  // one: two are a sign-up or a change), or a username alone (first step).
  function signInReady(scope) {
    const inputs = inputsOf(scope);
    if (inputs.some((input) => NOT_SIGN_IN.test(input.getAttribute("autocomplete") ?? ""))) return false;
    const passwords = inputs.filter((input) => typeOf(input) === "password");
    if (passwords.length > 1) return false;
    if (passwords.length === 1) return Boolean(passwords[0].value);
    const typed = inputs.filter((input) => !NOT_TYPED.has(typeOf(input)));
    return typed.length === 1 && usernameLike(typed[0]) && Boolean(typed[0].value);
  }

  // The form's submit button: the first one of the form, or, without a
  // <form>, the first one after the filled field.
  function submitButtonOf(scope, after) {
    const buttons = [...scope.querySelectorAll("button, input[type=submit]")].filter((button) =>
      !button.disabled && visible(button)
      && (button instanceof HTMLInputElement || (button.getAttribute("type") ?? "submit").toLowerCase() === "submit"));
    if (scope !== document) return buttons[0] ?? null;
    return buttons.find((b) => after.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING) ?? null;
  }

  function emptyFieldLeft(scope) {
    return inputsOf(scope).some((input) => !NOT_TYPED.has(typeOf(input)) && !input.value);
  }

  // A visible captcha on the page; the reCAPTCHA v3 badge and the invisible
  // widgets ask nothing of the user.
  function visibleCaptcha() {
    const invisible = (node) => node.closest(".grecaptcha-badge")
      || (node.getAttribute("data-size") ?? "").toLowerCase() === "invisible";
    const frames = [...document.querySelectorAll("iframe")].filter((frame) => {
      const src = frame.getAttribute("src") ?? "";
      return CAPTCHA_SRC.test(src) && !/[?&]size=invisible/i.test(src);
    });
    const widgets = [...document.querySelectorAll(".g-recaptcha, .h-captcha, .cf-turnstile, [data-sitekey]")]
      .filter((node) => !(node instanceof HTMLInputElement) && node.tagName !== "BUTTON");
    return [...frames, ...widgets].some((node) => !invisible(node) && visible(node));
  }

  // Like a click on the button: `requestSubmit` triggers the validation and
  // the "submit" event the sites listen to.
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

  // MARK: Decision

  const submittedAt = new WeakMap();
  let pending = null;

  function decide(input) {
    if (!input.isConnected) return;
    const scope = scopeOf(input);
    if (Date.now() - (submittedAt.get(scope) ?? 0) < RESUBMIT_MS) return;
    if (!signInReady(scope) || emptyFieldLeft(scope) || visibleCaptcha()) return;
    const button = submitButtonOf(scope, input);
    if (scope === document && !button) return;
    submittedAt.set(scope, Date.now());
    submit(scope, button);
  }

  function filled(event) {
    const input = event.target;
    if (!event.isTrusted || !usable(input) || !input.value || !filledBySystem(input, event)) return;
    clearTimeout(pending);
    pending = setTimeout(() => decide(input), SETTLE_MS);
  }

  document.addEventListener("input", filled, true);
  document.addEventListener("change", filled, true);
})();
