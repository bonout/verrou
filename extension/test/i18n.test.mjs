// The extension's texts (extension/_locales): English and French have the
// same messages and placeholders, and every message the code asks for
// exists.
//
//   node --test extension/test/i18n.test.mjs

import { readFileSync, readdirSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const messages = (locale) => JSON.parse(readFileSync(`${root}_locales/${locale}/messages.json`, "utf8"));
const placeholdersOf = (entry) => [...entry.message.matchAll(/\$([A-Za-z0-9_]+)\$/g)].map((m) => m[1].toLowerCase()).sort();

test("English and French have the same messages and placeholders", () => {
  const en = messages("en");
  const fr = messages("fr");
  assert.deepEqual(Object.keys(fr).sort(), Object.keys(en).sort());
  for (const [name, entry] of Object.entries(en)) {
    assert.match(name, /^[A-Za-z0-9_]+$/);
    assert.deepEqual(placeholdersOf(fr[name]), placeholdersOf(entry), name);
    assert.deepEqual(fr[name].placeholders, entry.placeholders, name);
    for (const key of placeholdersOf(entry)) assert.ok(entry.placeholders?.[key], `${name}: $${key}$ undefined`);
  }
});

test("every message used by the code and the manifest exists", () => {
  const en = messages("en");
  const manifest = JSON.parse(readFileSync(`${root}manifest.json`, "utf8"));
  assert.equal(manifest.default_locale, "en");
  const used = [...JSON.stringify(manifest).matchAll(/__MSG_([A-Za-z0-9_]+)__/g)].map((m) => m[1]);
  for (const file of readdirSync(root).filter((name) => name.endsWith(".js"))) {
    const source = readFileSync(`${root}${file}`, "utf8");
    used.push(...[...source.matchAll(/\bt\("([A-Za-z0-9_]+)"/g)].map((m) => m[1]));
  }
  assert.ok(used.length > 50);
  for (const name of used) assert.ok(en[name], `missing message: ${name}`);
});
