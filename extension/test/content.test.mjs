// The pill of content.js, without a browser: the script runs in a fake DOM
// (fake-dom.mjs), the service worker and passkeys.js are simulated. We
// check when the pill comes, what it offers, what it fills, and that the
// page can trigger nothing on behalf of the user.
//
//   node --test extension/test/content.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import { eventually, fakeBackground, openPage, sleep, source } from "./page.mjs";

const loginForm = (h) => h("form", { id: "login", action: "/connexion" },
  h("input", { id: "email", type: "email", name: "email", autocomplete: "username" }),
  h("input", { id: "password", type: "password", name: "password", autocomplete: "current-password" }),
  h("button", { id: "submit", type: "submit" }, "Se connecter"));

// MARK: When the pill comes

test("the pill comes once with a login for the site, without a menu under the field", async () => {
  const background = fakeBackground();
  const page = openPage(loginForm, background);
  await eventually(() => page.pillText().includes("Sign in"), "pill");
  const live = page.host("verrou-pill").shadow.querySelector("[role=status]");
  assert.equal(live.getAttribute("aria-live"), "polite");
  await eventually(() => live.textContent === "Verrou: connect.maif.fr, camille@exemple.fr", "announced");
  const text = page.pillText();
  assert.match(text, /connect\.maif\.fr/);
  assert.match(text, /camille@exemple\.fr/);
  assert.match(text, /✕/);
  assert.match(text, /Other logins/);
  assert.equal(background.sent("suggest").length, 1);

  // Fixed at the top left, above everything, safe from the page's styles.
  const host = page.host("verrou-pill");
  assert.equal(host.style.getPropertyValue("position"), "fixed");
  assert.equal(host.style.getPropertyValue("top"), "16px");
  assert.equal(host.style.getPropertyValue("left"), "0");
  assert.equal(host.style.getPropertyValue("right"), "0");
  assert.equal(host.style.getPropertyValue("pointer-events"), "none");
  assert.equal(host.style.getPropertyValue("z-index"), "2147483647");
  assert.equal(host.style.getPropertyPriority("position"), "important");
  assert.equal(host.style.getPropertyValue("font-size"), "medium", "text sized from the browser's default, not the page's");
  assert.equal(host.style.getPropertyPriority("font-size"), "important");
  assert.equal(host.shadowRoot, null, "closed shadow DOM");
  assert.equal(page.pillNode().getAttribute("role"), "dialog");

  // The focus didn't move; in the field, only the Verrou icon.
  assert.equal(page.document.activeElement, page.document.body);
  page.byId("email").focus();
  page.byId("password").focus();
  page.mutate();
  await sleep(500);
  assert.equal(background.sent("suggest").length, 1, "once per page, not on each focus");
  assert.equal(page.host("verrou-menu"), undefined, "no more menu hooked to the field");
  const badge = page.host("verrou-field");
  assert.ok(badge, "icon in the field");
  assert.equal(badge.style.getPropertyValue("position"), "absolute");
  assert.equal(badge.style.getPropertyValue("left"), `${350 - 24 - 6}px`, "at the right edge of the field");
  assert.equal(badge.style.getPropertyValue("width"), "24px", "a 24 px target");
  assert.equal(badge.style.getPropertyValue("height"), "24px");
  const icon = [...badge.shadow.walk()].find((n) => n.tagName === "BUTTON");
  assert.match(icon.getAttribute("aria-label"), /logins for this site.*↓/, "the keyboard shortcut is named");
  assert.equal(icon.getAttribute("title"), icon.getAttribute("aria-label"));
});

test("the pill's text follows the browser's font size: no size in pixels", () => {
  const style = /const STYLE = `([^`]*)`/.exec(source("content.js"))[1];
  assert.match(style, /font: \.8125em/);
  assert.deepEqual(style.match(/font(-size)?:\s*[^;]*\d(\.\d+)?px/g), null);
});

test("no login for this site: nothing by itself; the field icon offers another login", async () => {
  const background = fakeBackground({ items: [] });
  const page = openPage(loginForm, background);
  await eventually(() => background.sent("suggest").length === 1, "search for logins");
  await sleep(50);
  assert.equal(page.host("verrou-pill"), undefined);

  page.byId("email").focus();
  const icon = [...page.host("verrou-field").shadow.walk()].find((n) => n.tagName === "BUTTON");
  // A click simulated by the page on the icon: nothing.
  page.fire(icon, "click", { trusted: false });
  await sleep(50);
  assert.equal(page.host("verrou-pill"), undefined);
  page.fire(icon, "click");
  await eventually(() => page.pillText().includes("Fill with another login"), "list open");
  assert.match(page.pillText(), /No login for this site/);
  assert.match(page.pillText(), /More options/);
  assert.doesNotMatch(page.pillText(), /Other logins/, "no other login to promise");
  page.press("Fill with another login");
  assert.equal(background.sent("openLinkSite").length, 1, "the extension's popup opens on the choice");
  assert.equal(page.pillNode(), null);
  // The icon closes the pill too.
  page.fire(icon, "click");
  await eventually(() => page.pillNode(), "reopened");
  page.fire(icon, "click");
  assert.equal(page.pillNode(), null);
});

test("a lone email field (newsletter) doesn't call Verrou", async () => {
  const background = fakeBackground();
  openPage((h) => h("form", {}, h("input", { id: "news", type: "email", name: "email" }), h("button", {}, "S'abonner")), background);
  await sleep(100);
  assert.equal(background.sent("suggest").length, 0);
});

// MARK: Sign in

const formOf = (page) => page.document.documentElement.querySelector("form");
const buttonById = (page, id) => page.document.documentElement.querySelectorAll("button").find((b) => b.id === id);

test("\"Sign in\" fills the username and the password, then submits the form", async () => {
  const background = fakeBackground();
  const page = openPage(loginForm, background);
  const seen = [];
  page.document.addEventListener("submit", (event) => {
    seen.push([page.byId("email").value, page.byId("password").value, event.submitter]);
  });
  await eventually(() => page.pillText().includes("Sign in"), "pill");
  page.press("Sign in");
  await eventually(() => page.byId("password").value, "fill");
  assert.deepEqual(background.sent("fill").map((m) => m.item), ["camille"]);
  assert.equal(page.byId("email").value, "camille@exemple.fr");
  assert.equal(page.byId("password").value, "mot-de-passe-camille");
  assert.equal(page.pillNode(), null, "the pill goes away");
  const submit = buttonById(page, "submit");
  assert.equal(page.document.activeElement, submit, "the submit button has the focus");
  assert.equal(seen.length, 0, "not right away: the page processes the input first");
  await eventually(() => formOf(page).submissions.length, "form submitted");
  assert.deepEqual(seen, [["camille@exemple.fr", "mot-de-passe-camille", submit]], "submitted once, by its button");
  // Credentials from Verrou, unchanged: nothing to offer to save.
  await sleep(30);
  assert.equal(background.sent("capture").length, 0);
});

test("setting off: filled, the cursor on the submit button, nothing is submitted", async () => {
  const page = openPage(loginForm, fakeBackground(), { settings: { autoSubmit: false } });
  let submitted = false;
  page.document.addEventListener("submit", () => { submitted = true; });
  await eventually(() => page.pillText().includes("Sign in"), "pill");
  page.press("Sign in");
  await eventually(() => page.byId("password").value, "fill");
  await sleep(300);
  assert.equal(page.document.activeElement, buttonById(page, "submit"), "Enter is enough");
  assert.equal(submitted, false);
});

test("one more empty field (\"Code client\"): nothing is submitted", async () => {
  const page = openPage((h) => h("form", { id: "login" },
    h("input", { id: "client", type: "text", name: "client", placeholder: "Code client" }),
    h("input", { id: "email", type: "email", autocomplete: "username" }),
    h("input", { id: "password", type: "password", autocomplete: "current-password" }),
    h("input", { id: "remember", type: "checkbox", name: "remember" }),
    h("button", { id: "submit", type: "submit" }, "Se connecter")), fakeBackground());
  await eventually(() => page.pillText().includes("Sign in"), "pill");
  page.press("Sign in");
  await eventually(() => page.byId("password").value, "fill");
  await sleep(300);
  assert.equal(formOf(page).submissions.length, 0);
  assert.equal(page.document.activeElement, buttonById(page, "submit"));
});

test("visible captcha: nothing is submitted; the invisible reCAPTCHA badge doesn't get in the way", async () => {
  const withCaptcha = (extra) => (h) => [loginForm(h), extra(h)];
  const captchas = [
    (h) => h("iframe", { src: "https://www.google.com/recaptcha/api2/anchor?k=cle&size=normal" }),
    (h) => h("div", { class: "h-captcha", "data-sitekey": "cle" }),
    (h) => h("div", { class: "cf-turnstile" }),
    (h) => h("iframe", { src: "https://challenges.cloudflare.com/cdn-cgi/challenge-platform/turnstile" }),
  ];
  for (const captcha of captchas) {
    const page = openPage(withCaptcha(captcha), fakeBackground());
    await eventually(() => page.pillText().includes("Sign in"), "pill");
    page.press("Sign in");
    await eventually(() => page.byId("password").value, "fill");
    await sleep(250);
    assert.equal(formOf(page).submissions.length, 0, `captcha: ${captcha(page.h).getAttribute("src") ?? captcha(page.h).className}`);
  }

  // reCAPTCHA v3: the badge at the bottom of the page, and a button carrying the invisible widget.
  const page = openPage((h) => [
    h("form", { id: "login" },
      h("input", { id: "email", type: "email", autocomplete: "username" }),
      h("input", { id: "password", type: "password", autocomplete: "current-password" }),
      h("button", { id: "submit", type: "submit", class: "g-recaptcha", "data-sitekey": "cle" }, "Se connecter")),
    h("div", { class: "grecaptcha-badge" },
      h("iframe", { src: "https://www.google.com/recaptcha/api2/anchor?k=cle&size=invisible" })),
    // Hidden: the page doesn't show it.
    h("div", { class: "h-captcha", hidden: true }),
  ], fakeBackground());
  await eventually(() => page.pillText().includes("Sign in"), "pill");
  page.press("Sign in");
  await eventually(() => formOf(page).submissions.length, "submitted despite the badge");
});

test("two-step sign-in: the username step is submitted too", async () => {
  const background = fakeBackground();
  const page = openPage((h) => h("form", { id: "step" },
    h("input", { id: "user", type: "email", name: "username", autocomplete: "username" }),
    h("button", { type: "submit" }, "Suivant")), background);
  await eventually(() => page.pillText().includes("Sign in"), "pill of step 1");
  page.press("Sign in");
  await eventually(() => formOf(page).submissions.length, "step 1 submitted");
  assert.equal(background.sent("fill").length, 1);
  assert.deepEqual(background.sent("rememberUsername").map((m) => m.username), ["camille@exemple.fr"]);
});

test("verification code filled from the pill: submitted", async () => {
  const page = openPage((h) => h("form", {},
    h("input", { id: "otp", autocomplete: "one-time-code", maxLength: 6 }),
    h("button", { type: "submit" }, "Valider")), fakeBackground());
  await eventually(() => page.pillText().includes("Fill the code"), "code offered");
  page.press("Fill the code");
  await eventually(() => formOf(page).submissions.length, "code submitted");
  assert.equal(page.byId("otp").value, "123456");
});

test("without <form>: the click on the button after the fields", async () => {
  const page = openPage((h) => [
    h("div", { id: "header" }, h("input", { id: "search", type: "text", name: "q" })),
    h("div", { id: "box" },
      h("input", { id: "email", type: "email", autocomplete: "username" }),
      h("input", { id: "password", type: "password", autocomplete: "current-password" }),
      h("button", { id: "go" }, "Se connecter")),
  ], fakeBackground());
  let clicks = 0;
  buttonById(page, "go").addEventListener("click", () => { clicks += 1; });
  await eventually(() => page.pillText().includes("Sign in"), "pill");
  page.press("Sign in");
  await eventually(() => clicks, "button clicked");
  await sleep(200);
  assert.equal(clicks, 1);
});

test("credentials changed before submitting: the banner can offer to save", async () => {
  const background = fakeBackground();
  const page = openPage(loginForm, background, { settings: { autoSubmit: false } });
  await eventually(() => page.pillText().includes("Sign in"), "pill");
  page.press("Sign in");
  await eventually(() => page.byId("password").value, "fill");
  page.fire(buttonById(page, "submit"), "click");
  assert.equal(background.sent("capture").length, 0, "unchanged: nothing");
  page.byId("password").value = "nouveau-mot-de-passe";
  formOf(page).requestSubmit();
  assert.deepEqual(background.sent("capture").map((m) => m.password), ["nouveau-mot-de-passe"]);
});

test("two-step sign-in: the pill comes back for the next step", async () => {
  const background = fakeBackground();
  const page = openPage((h) => h("form", { id: "step" },
    h("input", { id: "user", type: "email", name: "username", autocomplete: "username" }),
    h("button", { type: "submit" }, "Suivant")), background);
  await eventually(() => page.pillText().includes("Sign in"), "pill of step 1");
  page.press("Sign in");
  await eventually(() => page.byId("user").value === "camille@exemple.fr", "username filled");
  // The application replaces the step: the password.
  const form = page.document.documentElement.querySelector("form");
  form.textContent = "";
  form.append(page.h("input", { id: "pass", type: "password", autocomplete: "current-password" }), page.h("button", { type: "submit" }, "Se connecter"));
  page.mutate();
  await eventually(() => page.pillText().includes("Sign in"), "pill of step 2");
  page.press("Sign in");
  await eventually(() => page.byId("pass").value === "mot-de-passe-camille", "password filled");
});

test("other logins: the list under the tab, and the choice of another one", async () => {
  const background = fakeBackground();
  const page = openPage(loginForm, background);
  await eventually(() => page.pillText().includes("Other logins"), "tab");
  assert.doesNotMatch(page.pillText(), /dominique/, "list collapsed");
  const tab = page.button("Other logins");
  assert.equal(tab.getAttribute("aria-expanded"), "false");
  page.press("Other logins");
  assert.equal(page.button("Other logins").getAttribute("aria-expanded"), "true");
  const text = page.pillText();
  assert.match(text, /MAIF pro/);
  assert.match(text, /dominique@exemple\.fr/);
  assert.match(text, /Fill with another login…/);
  assert.doesNotMatch(text, /Generate a password/, "not on a mere sign-in");
  page.press("MAIF pro");
  await eventually(() => page.byId("password").value, "fill");
  assert.equal(page.byId("email").value, "dominique@exemple.fr");
  assert.equal(page.byId("password").value, "mot-de-passe-dominique");
});

test("a single login: the tab offers \"More options\", not other logins", async () => {
  const page = openPage(loginForm, fakeBackground({ items: [{ id: "camille", title: "MAIF", username: "camille@exemple.fr", has_totp: false }] }));
  await eventually(() => page.pillText().includes("Sign in"), "pill");
  assert.doesNotMatch(page.pillText(), /Other logins/);
  page.press("More options");
  assert.equal(page.button("More options").getAttribute("aria-expanded"), "true");
  assert.match(page.pillText(), /Fill with another login…/);
});

test("protected item: the pill waits for the confirmation in Verrou", async () => {
  const background = fakeBackground();
  let asks = 0;
  const handle = background.handle;
  background.handle = async (message) => {
    if (message.kind === "fill" && asks++ === 0) {
      background.messages.push(message);
      return { ok: false, state: "confirm" };
    }
    return handle(message);
  };
  const page = openPage(loginForm, background);
  await eventually(() => page.pillText().includes("Sign in"), "pill");
  page.press("Sign in");
  await eventually(() => page.pillText().includes("Confirm in Verrou"), "waiting");
  await eventually(() => page.byId("password").value === "mot-de-passe-camille", "filled after confirmation", 3000);
  assert.equal(page.pillNode(), null);
});

// MARK: Passkeys

function fakePasskeys(entries) {
  const api = {
    entries: async () => api.state,
    state: entries,
    chosen: [],
    listeners: [],
    choose(credential) {
      api.chosen.push(credential);
      return true;
    },
    subscribe(listener) {
      api.listeners.push(listener);
    },
    notify: () => api.listeners.forEach((listener) => listener()),
  };
  return api;
}

test("pending passkey request: Verrou's passkey comes first", async () => {
  const background = fakeBackground();
  const passkeys = fakePasskeys({ state: "ready", items: [{ item: "camille", credential: "cred-1", user_name: "camille", title: "MAIF" }] });
  const page = openPage(loginForm, background, { passkeys });
  await eventually(() => page.pillText().includes("Sign in with a passkey"), "passkey offered");
  assert.match(page.pillText(), /camille/);
  page.press("Other logins");
  assert.match(page.pillText(), /camille@exemple\.fr/, "the passwords stay in the list");
  page.press("Sign in with a passkey");
  assert.deepEqual(passkeys.chosen, ["cred-1"]);
  assert.equal(background.sent("fill").length, 0, "no password leaves");
  assert.equal(page.pillNode(), null);
});

test("the passkey arrives after loading: the pill comes to offer it, then removes it", async () => {
  const background = fakeBackground({ items: [] });
  const passkeys = fakePasskeys({ state: "none" });
  const page = openPage(loginForm, background, { passkeys });
  await eventually(() => background.sent("suggest").length === 1, "search");
  await sleep(30);
  assert.equal(page.pillNode(), null);
  passkeys.state = { state: "ready", items: [{ item: "camille", credential: "cred-2", user_name: "camille", title: "MAIF" }] };
  passkeys.notify();
  await eventually(() => page.pillText().includes("Sign in with a passkey"), "passkey offered");
  // The page cancels its request: the passkey leaves the pill.
  passkeys.state = { state: "none" };
  passkeys.notify();
  await eventually(() => !page.pillText().includes("passkey"), "passkey removed");
});

// MARK: Verrou locked

test("Verrou locked: \"Unlock\", then the logins", async () => {
  const background = fakeBackground({ state: "locked" });
  const page = openPage(loginForm, background);
  await eventually(() => page.pillText().includes("Verrou is locked"), "locked pill");
  assert.equal(page.pillNode().querySelector(".title").textContent, "connect.maif.fr", "the site first, never cut");
  assert.match(page.pillText(), /Unlock/);
  page.press("Unlock");
  await eventually(() => page.pillText().includes("Unlock Verrou"), "waiting for the unlock");
  assert.equal(background.sent("unlock").length, 1);
  background.state = "unlocked";
  await eventually(() => page.pillText().includes("Sign in"), "logins after unlock", 3000);
  assert.match(page.pillText(), /camille@exemple\.fr/);
});

test("Verrou unreachable, pill opened by hand: \"Open Verrou\", then the logins", async () => {
  const background = fakeBackground({ state: "offline" });
  const page = openPage(loginForm, background);
  await eventually(() => background.sent("suggest").length === 1, "search");
  await sleep(30);
  assert.equal(page.pillNode(), null, "nothing by itself");
  page.byId("email").focus();
  page.fire([...page.host("verrou-field").shadow.walk()].find((n) => n.tagName === "BUTTON"), "click");
  await eventually(() => page.pillText().includes("Verrou can't be reached"), "unreachable pill");
  assert.equal(page.pillNode().querySelector(".title").textContent, "connect.maif.fr");
  page.press("Open Verrou", false);
  assert.equal(background.sent("unlock").length, 0, "made-up click: nothing");
  page.press("Open Verrou");
  await eventually(() => page.pillText().includes("Unlock Verrou"), "waiting for Verrou");
  assert.equal(background.sent("unlock").length, 1, "the host brings Verrou forward");
  await sleep(1100);
  assert.ok(page.pillText().includes("Unlock Verrou"), "still offline: still waiting");
  background.state = "unlocked";
  await eventually(() => page.pillText().includes("Sign in"), "logins once Verrou answers", 3000);
});

// MARK: Close

test("✕ closes the pill for the page; Escape too, but not a key from the page", async () => {
  const background = fakeBackground();
  const page = openPage(loginForm, background);
  await eventually(() => page.pillNode(), "pill");
  page.press("✕");
  assert.equal(page.pillNode(), null);
  assert.equal(page.host("verrou-pill"), undefined, "the host leaves the page");
  // New form, new step: nothing more by itself.
  page.document.body.append(page.h("form", {}, page.h("input", { id: "otp", autocomplete: "one-time-code" })));
  page.mutate();
  await sleep(500);
  assert.equal(page.pillNode(), null);

  const other = openPage(loginForm, fakeBackground());
  await eventually(() => other.pillNode(), "pill");
  other.byId("email").focus();
  other.fire(other.byId("email"), "keydown", { trusted: false, key: "Escape" });
  assert.ok(other.pillNode(), "Escape made up by the page: nothing");
  other.fire(other.byId("email"), "keydown", { key: "Escape" });
  assert.equal(other.pillNode(), null);
});

test("keyboard: down arrow in the field, then Escape brings back to the field", async () => {
  const page = openPage(loginForm, fakeBackground());
  await eventually(() => page.pillNode(), "pill");
  const email = page.byId("email");
  email.focus();
  const event = page.fire(email, "keydown", { key: "ArrowDown" });
  assert.equal(event.defaultPrevented, true);
  assert.equal(page.host("verrou-pill").shadow.activeElement, page.button("Sign in"));
  page.fire(page.host("verrou-pill").shadow.activeElement, "keydown", { key: "ArrowRight" });
  assert.equal(page.host("verrou-pill").shadow.activeElement, page.button("✕"));
  page.fire(page.host("verrou-pill").shadow.activeElement, "keydown", { key: "Escape" });
  assert.equal(page.pillNode(), null);
  assert.equal(page.document.activeElement, email);

  const back = openPage(loginForm, fakeBackground());
  await eventually(() => back.pillNode(), "pill");
  const field = back.byId("email");
  field.focus();
  back.fire(field, "keydown", { key: "ArrowDown" });
  const shadow = back.host("verrou-pill").shadow;
  assert.equal(back.fire(shadow.activeElement, "keydown", { key: "Tab" }).defaultPrevented, false, "inside the pill: the browser's Tab");
  back.button("Other logins").focus();
  assert.equal(back.fire(shadow.activeElement, "keydown", { key: "Tab", trusted: false }).defaultPrevented, false, "made-up key: nothing");
  assert.equal(back.fire(shadow.activeElement, "keydown", { key: "Tab" }).defaultPrevented, true, "Tab past the last button");
  assert.equal(back.document.activeElement, field);
  back.fire(field, "keydown", { key: "ArrowDown" });
  assert.equal(back.fire(shadow.activeElement, "keydown", { key: "Tab", shiftKey: true }).defaultPrevented, true, "Shift-Tab before the first");
  assert.equal(back.document.activeElement, field);
  assert.ok(back.pillNode(), "the pill stays");

  // Site's suggestion list open: the arrow stays with the site.
  const site = openPage(loginForm, fakeBackground());
  await eventually(() => site.pillNode(), "pill");
  site.byId("email").setAttribute("aria-expanded", "true");
  site.byId("email").focus();
  assert.equal(site.fire(site.byId("email"), "keydown", { key: "ArrowDown" }).defaultPrevented, false);
});

// MARK: The page doesn't choose

test("clicks made up by the page fill nothing", async () => {
  const background = fakeBackground();
  const page = openPage(loginForm, background);
  await eventually(() => page.pillNode(), "pill");
  page.press("Sign in", false);
  page.button("Sign in").click();
  page.fire(page.host("verrou-pill"), "click", { trusted: false });
  page.press("Other logins", false);
  page.press("✕", false);
  await sleep(300);
  assert.equal(background.sent("fill").length, 0);
  assert.equal(page.byId("password").value, "");
  assert.equal(formOf(page).submissions.length, 0, "nothing is submitted");
  assert.ok(page.pillNode(), "still there, list closed");
  assert.doesNotMatch(page.pillText(), /MAIF pro/);
});

// A real mouse click (`detail`: number of clicks), at point (10, 10).
const mouseClick = (page, label) => page.fire(page.button(label), "click", { detail: 1, clientX: 10, clientY: 10 });

test("pill made invisible by the page (opacity, clip, mask on <html>): a click fills nothing", async () => {
  const background = fakeBackground();
  const page = openPage(loginForm, background);
  await eventually(() => page.pillNode(), "pill");
  await sleep(350);
  const visible = page.context.getComputedStyle;
  for (const hidden of [{ opacity: "0.01" }, { clipPath: "inset(0 0 100% 0)" }, { maskImage: "linear-gradient(transparent, transparent)" }, { filter: "opacity(0)" }]) {
    page.context.getComputedStyle = (node) => (node === page.document.documentElement ? { ...visible(node), ...hidden } : visible(node));
    mouseClick(page, "Sign in");
    await sleep(30);
    assert.equal(background.sent("fill").length, 0, JSON.stringify(hidden));
  }
  page.context.getComputedStyle = visible;
  mouseClick(page, "Sign in");
  await eventually(() => page.byId("password").value, "fill once visible");
});

test("pill covered by the page: a click fills nothing", async () => {
  const background = fakeBackground();
  const page = openPage(loginForm, background);
  await eventually(() => page.pillNode(), "pill");
  await sleep(350);
  const decoy = page.h("div", { id: "leurre" });
  page.document.body.append(decoy);
  page.document.elementFromPoint = () => decoy;
  mouseClick(page, "Sign in");
  await sleep(30);
  assert.equal(background.sent("fill").length, 0, "a decoy is in the foreground");
  page.document.elementFromPoint = () => page.host("verrou-pill");
  mouseClick(page, "Sign in");
  await eventually(() => page.byId("password").value, "fill, the pill in the foreground");
});

test("click as soon as the pill appears: ignored (the page can't slide it under the pointer)", async () => {
  const background = fakeBackground();
  const page = openPage(loginForm, background);
  await eventually(() => page.pillNode(), "pill");
  mouseClick(page, "Sign in");
  await sleep(30);
  assert.equal(background.sent("fill").length, 0, "too soon");
  await sleep(350);
  mouseClick(page, "Sign in");
  await eventually(() => page.byId("password").value, "fill after a moment");
});

test("fill from the extension's popup: only for the filled address", async () => {
  const page = openPage(loginForm, fakeBackground({ items: [] }));
  const credentials = { username: "camille@exemple.fr", password: "secret" };
  page.deliver({ kind: "apply", credentials, origin: "https://piege.example" });
  page.deliver({ kind: "apply", credentials });
  assert.equal(page.byId("password").value, "", "another address, or none: nothing");
  await sleep(300);
  assert.equal(formOf(page).submissions.length, 0, "nothing submitted either");
  page.deliver({ kind: "apply", credentials, origin: "https://connect.maif.fr" });
  assert.equal(page.byId("password").value, "secret");
  await eventually(() => formOf(page).submissions.length === 1, "submitted after the fill");
});

// MARK: Sign-up, cards, codes

test("sign-up: \"Suggest a strong password\" fills the password and its confirmation", async () => {
  const background = fakeBackground({ items: [] });
  const page = openPage((h) => h("form", { id: "signup", action: "/inscription" },
    h("input", { id: "new-email", type: "email", name: "email" }),
    h("input", { id: "new-password", type: "password", name: "password", autocomplete: "new-password" }),
    h("input", { id: "confirm", type: "password", name: "confirm", autocomplete: "new-password" }),
    h("button", { type: "submit" }, "Créer mon compte")), background);
  await sleep(50);
  assert.equal(page.pillNode(), null, "nothing by itself before the field");
  page.byId("new-password").focus();
  await eventually(() => page.pillText().includes("Suggest a strong password"), "suggestion");
  const shown = page.pillText();
  assert.match(shown, /20 characters: letters, digits and symbols/);
  page.press("Suggest a strong password");
  const value = page.byId("new-password").value;
  assert.equal(value.length, 20);
  assert.ok(!shown.includes(value), "the password is never drawn on the page");
  assert.equal(page.byId("confirm").value, value);
  // Once per page.
  page.byId("new-email").focus();
  page.byId("confirm").focus();
  await sleep(50);
  assert.equal(page.pillNode(), null);
});

test("sign-in page whose password field says \"new-password\": filled as a sign-in", async () => {
  // As on collectives.cafannecy.fr: a lone password field marked
  // new-password, in a form with a "Login" button.
  const background = fakeBackground();
  const page = openPage((h) => h("form", { id: "basic_form", action: "" },
    h("input", { id: "login", type: "text", name: "login" }),
    h("input", { id: "password", type: "password", name: "password", autocomplete: "new-password" }),
    h("input", { id: "submit_button", type: "submit", value: "Login" })), background);
  await eventually(() => page.pillText().includes("Sign in"), "pill");
  page.press("Sign in");
  await eventually(() => page.byId("password").value, "fill");
  assert.equal(page.byId("login").value, "camille@exemple.fr");
  assert.equal(page.byId("password").value, "mot-de-passe-camille");
});

test("sign-up page with a lone \"new-password\" field: still a new password", async () => {
  const page = openPage((h) => h("form", { id: "signup" },
    h("input", { id: "email", type: "email", name: "email" }),
    h("input", { id: "password", type: "password", name: "password", autocomplete: "new-password" }),
    h("button", { type: "submit" }, "Créer mon compte")), fakeBackground({ items: [] }));
  page.byId("password").focus();
  await eventually(() => page.pillText().includes("Suggest a strong password"), "suggestion");
});

test("sign-in on a sign-up page: \"Generate a password\" in the list", async () => {
  const page = openPage((h) => h("form", { id: "both" },
    h("input", { id: "email", type: "email", autocomplete: "username" }),
    h("input", { id: "current", type: "password", autocomplete: "current-password" }),
    h("input", { id: "fresh", type: "password", autocomplete: "new-password" }),
    h("button", { type: "submit" }, "Valider")), fakeBackground());
  await eventually(() => page.pillNode(), "pill");
  page.press("Other logins");
  const shown = page.pillText();
  page.press("Generate a password");
  assert.equal(page.byId("fresh").value.length, 20);
  assert.ok(!shown.includes(page.byId("fresh").value), "described, not shown");
  assert.equal(page.byId("current").value, "");
});

const signupForm = (h) => h("form", { id: "signup", action: "/inscription" },
  h("input", { id: "pseudo", type: "text", name: "username" }),
  h("input", { id: "new-email", type: "email", name: "email" }),
  h("input", { id: "confirm-email", type: "email", name: "confirm_email", placeholder: "Confirm your email" }),
  h("input", { id: "new-password", type: "password", name: "password", autocomplete: "new-password" }),
  h("input", { id: "confirm", type: "password", name: "confirm", autocomplete: "new-password" }),
  h("button", { id: "create", type: "submit" }, "Créer mon compte"));

test("sign-up with an alias domain: \"Create email alias\" fills the email, saved as the username", async () => {
  const background = fakeBackground({ items: [], aliasDomain: "alias.example.com" });
  const page = openPage(signupForm, background);
  await sleep(50);
  assert.equal(page.pillNode(), null, "nothing by itself before the field");
  assert.equal(background.sent("alias").length, 0);
  page.byId("new-email").focus();
  await eventually(() => page.pillText().includes("Create email alias"), "alias offered");
  assert.match(page.pillText(), /maif\.a1x1z@alias\.example\.com/);
  page.press("Create email alias");
  assert.equal(page.byId("new-email").value, "maif.a1x1z@alias.example.com");
  assert.equal(page.byId("confirm-email").value, "maif.a1x1z@alias.example.com");
  assert.equal(page.pillNode(), null);

  page.byId("pseudo").value = "camille";
  page.byId("new-password").value = "un-mot-de-passe-solide";
  page.byId("confirm").value = "un-mot-de-passe-solide";
  formOf(page).requestSubmit();
  const [capture] = background.sent("capture");
  assert.equal(capture.username, "maif.a1x1z@alias.example.com");
  assert.equal(capture.password, "un-mot-de-passe-solide");

  page.byId("pseudo").focus();
  page.byId("new-email").focus();
  await sleep(50);
  assert.equal(background.sent("alias").length, 1, "once per page");
});

test("no alias domain: the sign-up email field stays quiet", async () => {
  const background = fakeBackground({ aliasDomain: null });
  const page = openPage(signupForm, background);
  page.byId("new-email").focus();
  await eventually(() => background.sent("alias").length === 1, "alias asked");
  await sleep(50);
  assert.equal(page.pillNode(), null);
  const icon = [...page.host("verrou-field").shadow.walk()].find((n) => n.tagName === "BUTTON");
  page.fire(icon, "click");
  await eventually(() => page.pillNode(), "pill by hand");
  assert.doesNotMatch(page.pillText(), /Create email alias/);
});

test("alias beside the site's logins, and first when Verrou is locked", async () => {
  const background = fakeBackground({ aliasDomain: "alias.example.com" });
  const page = openPage(signupForm, background);
  page.byId("new-email").focus();
  await eventually(() => page.pillText().includes("Sign in"), "logins first");
  page.press("Other logins");
  await eventually(() => page.pillText().includes("Create email alias"), "alias in the list");
  page.press("Create email alias");
  assert.match(page.byId("new-email").value, /@alias\.example\.com$/);

  const locked = fakeBackground({ state: "locked", aliasDomain: "alias.example.com" });
  const other = openPage(signupForm, locked);
  other.byId("new-email").focus();
  await eventually(() => other.pillText().includes("Create email alias"), "alias while locked");
  other.press("Other logins");
  other.press("Unlock");
  assert.equal(locked.sent("unlock").length, 1);
});

test("a sign-in form's email field asks for no alias", async () => {
  const background = fakeBackground({ aliasDomain: "alias.example.com" });
  const page = openPage(loginForm, background);
  await eventually(() => page.pillText().includes("Sign in"), "pill");
  page.byId("email").focus();
  await sleep(50);
  assert.doesNotMatch(page.pillText(), /Create email alias/);
  assert.equal(background.sent("alias").length, 0);
});

test("payment form: \"Fill card Visa •••• 0005\", the other cards under the tab", async () => {
  const background = fakeBackground({
    cards: [{ id: "visa", title: "Carte perso", subtitle: "Visa •••• 0005" }, { id: "amex", title: "Carte pro", subtitle: "Amex •••• 1000" }],
  });
  const page = openPage((h) => h("form", { id: "card" },
    h("input", { id: "cc", name: "cardnumber" }),
    h("input", { id: "name", name: "cc-name", autocomplete: "cc-name" }),
    h("input", { id: "year", name: "exp-year", maxLength: 2 }),
    h("input", { id: "cvc", name: "cvc" }),
    h("button", { type: "submit" }, "Payer")), background, { origin: "https://boutique.exemple.fr" });
  await sleep(50);
  assert.equal(background.sent("forms").length, 0, "nothing before the field");
  page.byId("cc").focus();
  await eventually(() => page.pillText().includes("Fill card Visa •••• 0005"), "card offered");
  page.press("Other cards");
  assert.match(page.pillText(), /Carte pro/);
  page.press("Fill card Visa •••• 0005");
  await eventually(() => page.byId("cc").value, "card filled");
  assert.deepEqual(background.sent("fillForm").map((m) => m.item), ["visa"]);
  assert.deepEqual(["cc", "name", "year", "cvc"].map((id) => page.byId(id).value), ["4000000000000005", "Camille Martin", "29", "321"]);
  await sleep(300);
  assert.equal(formOf(page).submissions.length, 0, "a payment is never submitted by itself");
});

test("verification code: the pill offers the code, not when Verrou is locked", async () => {
  const otpForm = (h) => h("form", {}, h("input", { id: "otp", autocomplete: "one-time-code", maxLength: 6 }), h("button", { type: "submit" }, "Valider"));
  const page = openPage(otpForm, fakeBackground());
  await eventually(() => page.pillText().includes("Fill the code"), "code offered");
  assert.match(page.pillText(), /dominique@exemple\.fr/, "only the logins with a code");
  page.press("Fill the code");
  await eventually(() => page.byId("otp").value === "123456", "code filled");

  const locked = fakeBackground({ state: "locked" });
  const quiet = openPage(otpForm, locked);
  await eventually(() => locked.sent("suggest").length === 1, "search");
  await sleep(30);
  assert.equal(quiet.pillNode(), null);
});

// MARK: Saving

test("the save banner in the same corner as the pill", async () => {
  const background = fakeBackground({ items: [] });
  const handle = background.handle;
  background.handle = async (message) => (message.kind === "pendingSave"
    ? { action: "save", username: "camille@exemple.fr", site: "connect.maif.fr" }
    : handle(message));
  const page = openPage(loginForm, background);
  const banner = () => page.host("verrou-pill")?.shadow?.querySelector(".banner");
  await eventually(banner, "banner");
  assert.match(banner().textContent, /Save in Verrou\?/);
  const choice = page.button("Save").parentNode;
  assert.equal(choice.className, "choice", "\"Not now\" and \"Save\" wrap together");
  assert.equal(page.button("Not now").parentNode, choice);
  assert.notEqual(page.button("Never for this site").parentNode, choice);
  assert.equal(page.host("verrou-pill").style.getPropertyValue("left"), "0");
  page.press("Save", false);
  await sleep(20);
  assert.equal(background.sent("confirmSave").length, 0, "made-up click: nothing");
  page.press("Not now");
  await eventually(() => !banner(), "banner closed");
});

test("the save banner is announced, and \"Saved in Verrou\" stays until read or closed", async () => {
  const background = fakeBackground({ items: [] });
  const handle = background.handle;
  background.handle = async (message) => (message.kind === "pendingSave"
    ? { action: "save", username: "camille@exemple.fr", site: "connect.maif.fr" }
    : handle(message));
  const page = openPage(loginForm, background);
  const banner = () => page.host("verrou-pill")?.shadow?.querySelector(".banner");
  const live = () => page.host("verrou-pill")?.shadow?.querySelector("[role=status]");
  await eventually(banner, "banner");
  await eventually(() => live()?.textContent === "Verrou: Save in Verrou?, camille@exemple.fr · connect.maif.fr", "offer announced");
  await sleep(350);
  page.press("Save");
  await eventually(() => banner()?.textContent.includes("Saved in Verrou"), "saved");
  await eventually(() => live()?.textContent === "Verrou: Saved in Verrou, Verrou", "confirmation announced");
  await sleep(2700);
  assert.match(banner()?.textContent ?? "", /Saved in Verrou/, "still there after 2.5 s");
  page.press("✕");
  await eventually(() => !banner(), "closed by hand");
});

// MARK: Firefox

test("Firefox: the same pill, through the `browser` API", async () => {
  const background = fakeBackground();
  const page = openPage(loginForm, background, { firefox: true });
  await eventually(() => page.pillText().includes("Sign in"), "pill");
  page.press("Sign in");
  await eventually(() => page.byId("password").value === "mot-de-passe-camille", "fill");
});
