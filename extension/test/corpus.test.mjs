// Real sign-in pages (corpus/*.json, recorded by scripts/login-corpus.mjs):
// each one rebuilt in the fake DOM, then the extension must fill what its
// "expect" says.
//
//   "login":          username and password on the same page
//   "username-first": a first step with the username only
//   "skipped":        no usable form in a headless browser (bot check, SSO
//                     only…), kept to be recorded again
//
//   node --test extension/test/corpus.test.mjs

import { readFileSync, readdirSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";

import { SECRETS, eventually, fakeBackground, openPage } from "./page.mjs";

const folder = new URL("./corpus/", import.meta.url);
const pages = readdirSync(folder).filter((f) => f.endsWith(".json"))
  .map((f) => JSON.parse(readFileSync(new URL(f, folder), "utf8")));

const ATTRIBUTES = { type: "type", id: "id", name: "name", autocomplete: "autocomplete", placeholder: "placeholder",
  ariaLabel: "aria-label", inputmode: "inputmode", maxlength: "maxlength" };

// The recorded forms, as elements of <body>.
function build(h, page) {
  return page.forms.flatMap((form) => {
    const children = form.inputs.flatMap((field) => {
      const attributes = {};
      for (const [key, attribute] of Object.entries(ATTRIBUTES)) {
        if (field[key] !== undefined) attributes[attribute] = field[key];
      }
      const input = h("input", attributes);
      if (!field.label) return [input];
      return field.id ? [h("label", { for: field.id }, field.label), input] : [h("label", {}, field.label, input)];
    });
    const buttons = form.buttons.map((b) => b.tag === "input"
      ? h("input", { type: b.type ?? "submit", value: b.text })
      : h("button", b.type ? { type: b.type } : {}, b.text));
    if (form.loose) return [...children, ...buttons];
    const attributes = {};
    for (const key of ["id", "name", "action"]) if (form[key]) attributes[key] = form[key];
    return [h("form", attributes, ...children, ...buttons)];
  });
}

// A field by its id or name, or "@n" for the nth input of the page (a field
// with neither).
const field = (page, key) => {
  const inputs = page.document.documentElement.querySelectorAll("input");
  if (key.startsWith("@")) return inputs[Number(key.slice(1))];
  return inputs.find((n) => n.id === key || n.getAttribute("name") === key);
};

for (const recorded of pages) {
  const expect = recorded.expect;
  if (!expect || expect.kind === "skipped") {
    test(`${recorded.name}: ${expect?.reason ?? "no expectation written yet"}`, { skip: true }, () => {});
    continue;
  }
  test(`${recorded.name} (${expect.kind}): ${recorded.url.slice(0, 60)}`, async () => {
    const page = openPage((h) => build(h, recorded), fakeBackground(), { origin: recorded.url, title: recorded.title ?? "" });
    await eventually(() => page.pillText().includes("Sign in"), "the pill offers to sign in");
    page.press("Sign in");
    const username = field(page, expect.username);
    assert.ok(username, `username field "${expect.username}"`);
    await eventually(() => username.value, "username filled");
    assert.equal(username.value, SECRETS.camille.username);
    if (expect.kind === "login") {
      const password = field(page, expect.password);
      assert.ok(password, `password field "${expect.password}"`);
      await eventually(() => password.value, "password filled");
      assert.equal(password.value, SECRETS.camille.password);
    }
    // Nothing else of the page gets a value (a search box, a promo code…).
    const expected = new Set([field(page, expect.username), expect.password && field(page, expect.password)]);
    const others = page.document.documentElement.querySelectorAll("input")
      .filter((n) => n.value && !expected.has(n)
        && !["checkbox", "radio", "submit", "button"].includes((n.getAttribute("type") ?? "").toLowerCase()));
    assert.deepEqual(others.map((n) => n.id || n.getAttribute("name")), [], "no other field filled");
  });
}
