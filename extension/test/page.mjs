// The extension's content script in a fake page (fake-dom.mjs), for the
// tests: the page, the simulated service worker, and waiting helpers.

import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

import { createDom, i18n } from "./fake-dom.mjs";

export const root = fileURLToPath(new URL("../../", import.meta.url));
export const source = (name) => readFileSync(`${root}extension/${name}`, "utf8");
export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function eventually(probe, what, timeout = 3000) {
  const end = Date.now() + timeout;
  for (;;) {
    const value = await probe();
    if (value) return value;
    if (Date.now() > end) throw new Error(`timed out: ${what}`);
    await sleep(10);
  }
}

export const LOGINS = [
  { id: "camille", title: "MAIF", username: "camille@exemple.fr", has_totp: false },
  { id: "dominique", title: "MAIF pro", username: "dominique@exemple.fr", has_totp: true },
];

export const SECRETS = {
  camille: { username: "camille@exemple.fr", password: "mot-de-passe-camille", totp: null },
  dominique: { username: "dominique@exemple.fr", password: "mot-de-passe-dominique", totp: "123456" },
};

// The service worker: `state` changes during the test (locked, then
// open…). `messages` keeps everything the script asked for.
export function fakeBackground({ state = "unlocked", items = LOGINS, cards = [], identities = [], aliasDomain = null } = {}) {
  let aliases = 0;
  const background = {
    state,
    items,
    aliasDomain,
    messages: [],
    async handle(message) {
      background.messages.push(message);
      switch (message.kind) {
        case "suggest":
          return background.state === "unlocked" ? { state: "unlocked", items: background.items } : { state: background.state };
        case "fill":
          return SECRETS[message.item] ? { ok: true, ...SECRETS[message.item] } : { ok: false, state: "error" };
        case "forms":
          return background.state === "unlocked" ? { state: "unlocked", cards, identities } : { state: background.state };
        case "fillForm":
          return { ok: true, data: { kind: "card", cardholder: "Camille Martin", number: "4000000000000005", exp_month: "9", exp_year: "2029", code: "321" } };
        case "pendingSave":
          return {};
        case "alias":
          aliases += 1;
          return background.aliasDomain
            ? { ok: true, address: `maif.a${aliases}x${aliases}z@${background.aliasDomain}` }
            : { ok: false, reason: "no email alias domain is set" };
        default:
          return { ok: true };
      }
    },
    sent: (kind) => background.messages.filter((m) => m.kind === kind),
  };
  return background;
}

// A page, its fields (`build(h)` returns the elements of <body>), the
// generator and content.js. `passkeys`: the pending passkey request
// (interface of passkeys.js). `firefox`: the `browser` API, `chrome` trapped.
// `settings`: the extension's `storage.local` (`autoSubmit` setting…).
export function openPage(build, background, { origin = "https://connect.maif.fr", title = "", passkeys = null, firefox = false, settings = {} } = {}) {
  const dom = createDom({ origin, title });
  const { context, document, h } = dom;
  for (const node of [build(h)].flat()) document.body.append(node);
  const onMessage = [];
  const runtime = {
    id: "extension",
    sendMessage: (message) => background.handle(message),
    onMessage: { addListener: (listener) => onMessage.push(listener) },
  };
  const storage = {
    local: {
      get: async (key) => (Object.hasOwn(settings, key) ? { [key]: settings[key] } : {}),
      set: async (values) => Object.assign(settings, values),
    },
  };
  if (firefox) {
    context.browser = { runtime, storage, i18n };
    context.chrome = { runtime: { id: "extension", sendMessage: () => { throw new Error("chrome.runtime used in Firefox"); } } };
  } else {
    context.chrome = { runtime, storage, i18n };
  }
  if (passkeys) context.__verrouPasskeyMenu = passkeys;
  dom.run(source("generator.js"));
  dom.run(source("content.js"));

  const host = (tag) => document.documentElement.children.find((n) => n.tagName === tag.toUpperCase());
  const pillNode = () => host("verrou-pill")?.shadow?.querySelector(".pill") ?? null;
  const pillText = () => pillNode()?.textContent ?? "";
  const button = (label) => {
    const node = [...(host("verrou-pill")?.shadow?.walk() ?? [])]
      .find((n) => n.tagName === "BUTTON" && n.textContent.includes(label));
    assert.ok(node, `button "${label}" in "${pillText()}"`);
    return node;
  };
  return {
    ...dom,
    host,
    pillNode,
    pillText,
    button,
    // A real click on a button of the pill.
    press: (label, trusted = true) => dom.fire(button(label), "click", { trusted }),
    deliver: (message) => onMessage.forEach((listener) => listener(message)),
    byId: (id) => document.documentElement.querySelectorAll("input").find((n) => n.id === id),
  };
}
