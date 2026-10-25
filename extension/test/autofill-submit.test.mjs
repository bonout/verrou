// Safari on the iPhone: autofill-submit.js submits a sign-in form that iOS
// AutoFill just filled, and nothing else.
//
//   node --test extension/test/autofill-submit.test.mjs

import { existsSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";

import { createDom } from "./fake-dom.mjs";
import { root, source, sleep } from "./page.mjs";

// A page with `build(h)`, autofill-submit.js running.
function openPage(build) {
  const dom = createDom({ origin: "https://connect.maif.fr" });
  for (const node of [build(dom.h)].flat()) dom.document.body.append(node);
  dom.run(source("safari/autofill-submit.js"));
  const byId = (id) => [...dom.document.documentElement.walk()].find((n) => n.id === id);
  // iOS AutoFill: the values arrive without a keystroke.
  const autofill = (values) => {
    for (const [id, value] of Object.entries(values)) {
      byId(id).value = value;
      dom.fire(byId(id), "input");
    }
  };
  const submissions = () => dom.document.documentElement.querySelector("form")?.submissions ?? [];
  return { ...dom, byId, autofill, submissions };
}

const loginForm = (h) => h("form", { id: "login" },
  h("input", { id: "email", type: "email", name: "email", autocomplete: "username" }),
  h("input", { id: "password", type: "password", name: "password", autocomplete: "current-password" }),
  h("button", { id: "submit", type: "submit" }, "Se connecter"));

const SETTLED = 400;

test("a sign-in filled by AutoFill is submitted once, by its button", async () => {
  const page = openPage(loginForm);
  page.autofill({ email: "camille@exemple.fr", password: "mot-de-passe-camille" });
  assert.equal(page.submissions().length, 0, "not right away: both fields first");
  await sleep(SETTLED);
  assert.equal(page.submissions().length, 1);
  assert.equal(page.submissions()[0].submitter, page.byId("submit"));
  // The form comes back (wrong password): not submitted again in a loop.
  page.autofill({ password: "mot-de-passe-camille" });
  await sleep(SETTLED);
  assert.equal(page.submissions().length, 1);
});

test("the first step of a two-step sign-in (username alone) is submitted", async () => {
  const page = openPage((h) => h("form", { id: "step" },
    h("input", { id: "email", type: "email", name: "identifier", autocomplete: "username" }),
    h("button", { type: "submit" }, "Continuer")));
  page.autofill({ email: "camille@exemple.fr" });
  await sleep(SETTLED);
  assert.equal(page.submissions().length, 1);
});

test("typed by the user: nothing is submitted", async () => {
  const page = openPage(loginForm);
  for (const [id, value] of [["email", "camille@exemple.fr"], ["password", "mot-de-passe"]]) {
    page.fire(page.byId(id), "keydown");
    page.byId(id).value = value;
    page.fire(page.byId(id), "input", { inputType: "insertText" });
  }
  await sleep(SETTLED);
  assert.equal(page.submissions().length, 0);
});

test("an event made by the page doesn't count", async () => {
  const page = openPage(loginForm);
  page.byId("email").value = "camille@exemple.fr";
  page.byId("password").value = "mot-de-passe";
  page.fire(page.byId("password"), "input", { trusted: false });
  await sleep(SETTLED);
  assert.equal(page.submissions().length, 0);
});

test("a sign-up, an address, a field left to fill or a captcha: never submitted", async () => {
  const forms = {
    "sign-up": (h) => h("form", {},
      h("input", { id: "email", type: "email", autocomplete: "username" }),
      h("input", { id: "password", type: "password", autocomplete: "new-password" }),
      h("input", { id: "confirm", type: "password", autocomplete: "new-password" }),
      h("button", { type: "submit" }, "Créer")),
    address: (h) => h("form", {},
      h("input", { id: "email", type: "email", autocomplete: "email" }),
      h("input", { id: "street", type: "text", autocomplete: "address-line1" }),
      h("button", { type: "submit" }, "Livrer")),
    "field left": (h) => h("form", {},
      h("input", { id: "email", type: "email", autocomplete: "username" }),
      h("input", { id: "password", type: "password" }),
      h("input", { id: "customer", type: "text", name: "customer" }),
      h("button", { type: "submit" }, "Se connecter")),
    captcha: (h) => [loginForm(h), h("div", { class: "g-recaptcha", "data-sitekey": "x" })],
  };
  for (const [name, build] of Object.entries(forms)) {
    const page = openPage(build);
    const values = { email: "camille@exemple.fr" };
    if (page.byId("password")) values.password = "mot-de-passe";
    if (page.byId("confirm")) values.confirm = "mot-de-passe";
    if (page.byId("street")) values.street = "1 rue de la Paix";
    page.autofill(values);
    await sleep(SETTLED);
    assert.equal(page.submissions().length, 0, name);
  }
});

test("a search box filled without typing isn't a sign-in", async () => {
  const page = openPage((h) => h("form", {},
    h("input", { id: "q", type: "text", name: "q" }),
    h("button", { type: "submit" }, "Chercher")));
  page.autofill({ q: "verrou" });
  await sleep(SETTLED);
  assert.equal(page.submissions().length, 0);
});

test("the Safari manifest follows the extension's version and names files that exist", () => {
  const safari = JSON.parse(source("safari/manifest.json"));
  const desktop = JSON.parse(source("manifest.json"));
  assert.equal(safari.version, desktop.version);
  assert.deepEqual(safari.content_scripts.flatMap((script) => script.js), ["autofill-submit.js"]);
  for (const icon of Object.values(safari.icons)) assert.ok(existsSync(`${root}extension/${icon}`), icon);
});
