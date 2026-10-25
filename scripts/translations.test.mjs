// The Apple string catalogs and the extension's _locales: every string is
// translated into every language, and each language really is that language
// (a German catalog filled with Spanish passes every placeholder check).
//
//   node --test scripts/translations.test.mjs

import { readFileSync, readdirSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const LANGUAGES = ["de", "es", "fr", "it"];
const CATALOGS = [
  "apple/Verrou/Localizable.xcstrings",
  "apple/VerrouiOS/Localizable.xcstrings",
  "apple/VerrouAutoFill/Localizable.xcstrings",
  "apple/VerrouAutoFillMac/Localizable.xcstrings",
  "apple/VerrouAutoFill/InfoPlist.xcstrings",
  "apple/VerrouiOS/InfoPlist.xcstrings",
  "apple/VerrouiOS/AppShortcuts.xcstrings",
  "apple/VerrouWidgets/Localizable.xcstrings",
  "apple/VerrouWatch/Localizable.xcstrings",
  "apple/VerrouWatchWidgets/Localizable.xcstrings",
];
// Short words frequent in each language and rare in the others.
const STOPWORDS = {
  de: ["der", "die", "das", "und", "nicht", "ist", "mit", "für", "ein", "eine", "auf", "zu", "den", "wird", "oder"],
  es: ["el", "los", "las", "y", "no", "es", "con", "para", "una", "que", "del", "se", "al", "está", "o"],
  fr: ["le", "les", "et", "ne", "pas", "est", "avec", "pour", "une", "que", "des", "du", "au", "vous", "ou"],
  it: ["il", "gli", "e", "non", "è", "con", "per", "una", "che", "della", "si", "al", "sono", "o", "nel"],
};

/** Per language, the translated texts of every catalog and the extension. */
function texts() {
  const all = Object.fromEntries(LANGUAGES.map((language) => [language, []]));
  for (const catalog of CATALOGS) {
    const { strings } = JSON.parse(readFileSync(`${root}${catalog}`, "utf8"));
    for (const [key, value] of Object.entries(strings)) {
      if (value.shouldTranslate === false || !/[A-Za-z]{2}/.test(key)) continue;
      for (const language of LANGUAGES) {
        // A Siri phrase (AppShortcuts.xcstrings) has a set of values.
        const localization = value.localizations?.[language];
        const texts = localization?.stringSet?.values ?? [localization?.stringUnit?.value];
        for (const text of texts) {
          assert.ok(text?.trim(), `${catalog}: ${JSON.stringify(key)} not translated into ${language}`);
          all[language].push(text);
        }
      }
    }
  }
  for (const language of LANGUAGES) {
    const messages = JSON.parse(readFileSync(`${root}extension/_locales/${language}/messages.json`, "utf8"));
    all[language].push(...Object.values(messages).map((entry) => entry.message));
  }
  return all;
}

const words = (text) => text.toLowerCase().match(/\p{L}+/gu) ?? [];

test("every string is translated, each in its own language", () => {
  const all = texts();
  for (const language of LANGUAGES) {
    const counts = Object.fromEntries(LANGUAGES.map((other) => [other, 0]));
    for (const text of all[language]) {
      for (const word of words(text)) {
        for (const other of LANGUAGES) if (STOPWORDS[other].includes(word)) counts[other] += 1;
      }
    }
    const [first, second] = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    assert.equal(first[0], language, `${language} reads like ${first[0]}: ${JSON.stringify(counts)}`);
    assert.ok(first[1] > 3 * second[1], `${language} is mixed with ${second[0]}: ${JSON.stringify(counts)}`);
  }
});

test("no two languages share their sentences", () => {
  const all = texts();
  for (const [i, a] of LANGUAGES.entries()) {
    for (const b of LANGUAGES.slice(i + 1)) {
      const shared = all[a].filter((text, index) => words(text).length >= 4 && text === all[b][index]);
      assert.ok(shared.length < 10, `${a} and ${b} share ${shared.length} sentences, e.g. ${JSON.stringify(shared.slice(0, 3))}`);
    }
  }
});
