// The extension's texts (extension/_locales): every language has the same
// messages and placeholders as English, and every message the code asks
// for exists.
//
//   node --test extension/test/i18n.test.mjs

import { readFileSync, readdirSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const messages = (locale) => JSON.parse(readFileSync(`${root}_locales/${locale}/messages.json`, "utf8"));
const placeholdersOf = (entry) => [...entry.message.matchAll(/\$([A-Za-z0-9_]+)\$/g)].map((m) => m[1].toLowerCase()).sort();

const locales = readdirSync(`${root}_locales`).filter((name) => name !== "en");

test("every language has English's messages and placeholders", () => {
  const en = messages("en");
  assert.deepEqual(locales.sort(), ["de", "es", "fr", "it"]);
  for (const locale of locales) {
    const translated = messages(locale);
    assert.deepEqual(Object.keys(translated).sort(), Object.keys(en).sort(), locale);
    for (const [name, entry] of Object.entries(en)) {
      assert.match(name, /^[A-Za-z0-9_]+$/);
      assert.ok(translated[name].message.trim(), `${locale}: ${name} empty`);
      assert.deepEqual(placeholdersOf(translated[name]), placeholdersOf(entry), `${locale}: ${name}`);
      assert.deepEqual(translated[name].placeholders, entry.placeholders, `${locale}: ${name}`);
    }
  }
  for (const [name, entry] of Object.entries(en)) {
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
