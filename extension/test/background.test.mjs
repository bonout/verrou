// The service worker (background.js), loaded as is with simulated extension
// APIs: the sign-in in several steps. After a step filled with a login, the
// next steps of the same tab and site get that login, each kind of field
// once; another tab, another site, or the ✕ get nothing.
//
//   node --test extension/test/background.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import { i18n } from "./fake-dom.mjs";

const session = new Map();
let onMessage;
globalThis.chrome = {
  runtime: {
    id: "extension",
    getManifest: () => ({ version: "0.0.0" }),
    getURL: (path) => `chrome-extension://extension/${path}`,
    onMessage: { addListener: (listener) => { onMessage = listener; } },
    connectNative: () => { throw new Error("no Verrou in this test"); },
  },
  i18n,
  storage: {
    session: {
      get: async (key) => (session.has(key) ? { [key]: structuredClone(session.get(key)) } : {}),
      set: async (values) => { for (const [key, value] of Object.entries(values)) session.set(key, structuredClone(value)); },
      remove: async (keys) => { for (const key of [keys].flat()) session.delete(key); },
    },
    local: { get: async () => ({}), set: async () => {} },
  },
  alarms: { get: async () => ({}), create: () => {}, onAlarm: { addListener: () => {} } },
  tabs: { onRemoved: { addListener: () => {} }, query: async () => [] },
};
// No disk to read the manifest from: the update check fails quietly.
globalThis.fetch = async () => { throw new Error("offline"); };

await import("../background.js");

const send = (message, { tab = 7, url = "https://connect.maif.fr/login" } = {}) => new Promise((resolve) => {
  onMessage(message, { id: "extension", url, tab: { id: tab }, frameId: 0 }, resolve);
});

const filled = (kinds, extra = {}, sender) => send({
  kind: "signInFilled", item: "camille", title: "MAIF", username: "camille@exemple.fr", totp: false, kinds, ...extra,
}, sender);

test("the password step after the username: the same login, once", async () => {
  session.clear();
  assert.deepEqual(await send({ kind: "signInNext", kinds: ["password"] }), {}, "no sign-in in progress");
  await filled(["username"]);
  const next = await send({ kind: "signInNext", kinds: ["password"] }, { url: "https://connect.maif.fr/password" });
  assert.deepEqual(next, { item: "camille", title: "MAIF", username: "camille@exemple.fr" });
  assert.equal(JSON.stringify([...session.values()]).includes("mot-de-passe"), false, "no secret kept");
  assert.deepEqual(await send({ kind: "signInNext", kinds: ["username"] }), {}, "the username step again: nothing");

  // The password filled, then refused by the site: the step comes back.
  await filled(["password"], { title: undefined, username: undefined });
  assert.deepEqual(await send({ kind: "signInNext", kinds: ["password"] }), {}, "never in a loop");
  const [flow] = session.values();
  assert.deepEqual(flow.done, ["username", "password"]);
  assert.equal(flow.username, "camille@exemple.fr", "kept from the first step");
});

test("the verification code: only for a login that has one", async () => {
  session.clear();
  await filled(["username", "password"]);
  assert.deepEqual(await send({ kind: "signInNext", kinds: ["otp"] }), {});
  await filled(["username", "password"], { totp: true });
  assert.equal((await send({ kind: "signInNext", kinds: ["otp"] })).item, "camille");
});

test("another tab, another site, the ✕ or another login: not the same sign-in", async () => {
  session.clear();
  await filled(["username"]);
  assert.deepEqual(await send({ kind: "signInNext", kinds: ["password"] }, { tab: 8 }), {}, "another tab");
  assert.deepEqual(await send({ kind: "signInNext", kinds: ["password"] }, { url: "https://piege.example/login" }), {},
    "another site in the same tab");
  assert.equal((await send({ kind: "signInNext", kinds: ["password"] }, { url: "https://auth.maif.fr/" })).item, "camille",
    "a subdomain of the same site");

  await filled(["username"], { item: "dominique", username: "dominique@exemple.fr" });
  assert.equal((await send({ kind: "signInNext", kinds: ["password"] })).item, "dominique", "the last login chosen");

  await send({ kind: "signInCancel" });
  assert.deepEqual(await send({ kind: "signInNext", kinds: ["password"] }), {}, "cancelled");
});

test("a step goes stale after three minutes", async () => {
  session.clear();
  await filled(["username"]);
  const [[key, flow]] = session.entries();
  session.set(key, { ...flow, at: Date.now() - 3 * 60_000 - 1 });
  assert.deepEqual(await send({ kind: "signInNext", kinds: ["password"] }), {});
});

test("unknown kinds and a missing item are ignored", async () => {
  session.clear();
  await filled(["new", "card"]);
  await send({ kind: "signInFilled", kinds: ["username"] });
  assert.equal(session.size, 0);
});
