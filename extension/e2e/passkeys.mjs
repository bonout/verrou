// Passkeys in a real Brave, in the background, on a throwaway profile: a
// page calls `navigator.credentials.create` then `.get`; Verrou's window
// opens, a click (real for the page) saves then uses the passkey, and the
// page checks the signature itself with WebCrypto.
//
//   cargo build -p verrou-bridge --example test_server --bin verrou-native-host
//   node extension/e2e/passkeys.mjs
//
// Verrou is replaced by the bridge's test server (fake vault, approvals
// given automatically). The Native Messaging host is declared in the
// throwaway profile only: nothing is written outside it.

import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const root = fileURLToPath(new URL("../../", import.meta.url));
const BRAVE = process.env.BRAVE ?? "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser";
const EXTENSION_ID = "pmdlgnpbjfdnmpeadbecmgfoojmocibg";
const DEVTOOLS_PORT = 9_557;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const step = (text) => console.log(`PASSKEY_OK ${text}`);
const children = [];

async function eventually(probe, what, timeout = 10_000) {
  const end = Date.now() + timeout;
  for (;;) {
    const value = await probe();
    if (value) return value;
    if (Date.now() > end) throw new Error(`timed out: ${what}`);
    await sleep(150);
  }
}

// MARK: Fake Verrou and test page

const server = spawn(`${root}target/debug/examples/test_server`, {
  env: { ...process.env, VERROU_BRIDGE_PORT: "0" },
  stdio: ["ignore", "pipe", "inherit"],
});
children.push(server);
const saved = [];
const port = await new Promise((resolve) => {
  createInterface({ input: server.stdout }).on("line", (line) => {
    if (line.startsWith("PORT ")) resolve(line.slice(5));
    if (line.startsWith("SAVED ")) saved.push(line.slice(6));
  });
});

const page = createServer((request, response) => {
  response.setHeader("content-type", "text/html; charset=utf-8");
  response.end(`<!doctype html><title>Passkeys</title><h1>Passkeys</h1>`);
}).listen(0, "127.0.0.1");
await new Promise((resolve) => page.once("listening", resolve));
const pageUrl = `http://localhost:${page.address().port}/compte`;

// MARK: Brave

const profile = mkdtempSync(join(tmpdir(), "verrou-passkeys-"));
// The user's Native Messaging hosts: `<profile>/NativeMessagingHosts`.
mkdirSync(join(profile, "NativeMessagingHosts"));
writeFileSync(join(profile, "NativeMessagingHosts", "app.verrou.bridge.json"), JSON.stringify({
  name: "app.verrou.bridge",
  description: "Verrou (tests)",
  path: `${root}target/debug/verrou-native-host`,
  type: "stdio",
  allowed_origins: [`chrome-extension://${EXTENSION_ID}/`],
}));
const flags = [
  `--user-data-dir=${profile}`, `--remote-debugging-port=${DEVTOOLS_PORT}`,
  `--load-extension=${root}extension`, `--disable-extensions-except=${root}extension`,
  "--disable-features=DisableLoadExtensionCommandLineSwitch",
  "--no-first-run", "--no-default-browser-check", "--window-size=1000,700", "about:blank",
];
const brave = spawn("/usr/bin/open", [
  "-g", "-n", "-a", BRAVE.replace(/\/Contents\/MacOS\/.*$/, ""),
  "--env", `VERROU_BRIDGE_PORT=${port}`, "--env", "VERROU_BRIDGE_NO_LAUNCH=1",
  "--args", ...flags,
], { stdio: "ignore" });
await new Promise((resolve) => brave.once("exit", resolve));
const endpoint = await eventually(async () => {
  try {
    return (await (await fetch(`http://127.0.0.1:${DEVTOOLS_PORT}/json/version`)).json()).webSocketDebuggerUrl;
  } catch {
    return null;
  }
}, "Brave's DevTools", 20_000);

const socket = new WebSocket(endpoint);
await new Promise((resolve) => socket.addEventListener("open", resolve, { once: true }));
let nextId = 1;
const waiting = new Map();
socket.addEventListener("message", (event) => {
  const message = JSON.parse(event.data);
  const handler = waiting.get(message.id);
  if (handler) {
    waiting.delete(message.id);
    message.error ? handler.reject(new Error(message.error.message)) : handler.resolve(message.result);
  }
});
function cdp(method, params = {}, sessionId) {
  const id = nextId++;
  socket.send(JSON.stringify({ id, method, params, sessionId }));
  return new Promise((resolve, reject) => waiting.set(id, { resolve, reject }));
}

async function openTab(url) {
  const { targetId } = await cdp("Target.createTarget", { url });
  const { sessionId } = await cdp("Target.attachToTarget", { targetId, flatten: true });
  await cdp("Page.enable", {}, sessionId);
  await cdp("Runtime.enable", {}, sessionId);
  return sessionId;
}

async function evaluate(sessionId, expression) {
  const { result, exceptionDetails } = await cdp("Runtime.evaluate",
    { expression, awaitPromise: true, returnByValue: true }, sessionId);
  if (exceptionDetails) throw new Error(exceptionDetails.exception?.description ?? exceptionDetails.text);
  return result.value;
}

// Center of the element of Verrou's window (closed shadow DOM: DevTools goes
// through it, the page doesn't) whose text is `text`.
async function find(sessionId, text) {
  const { root: tree } = await cdp("DOM.getDocument", { depth: -1, pierce: true }, sessionId);
  let found = null;
  const walk = (node, inside) => {
    const here = inside || node.nodeName === "VERROU-PASSKEY";
    if (here && node.nodeType === 1 && ["BUTTON", "DIV"].includes(node.nodeName)
      && node.children?.length === 1 && node.children[0].nodeType === 3 && node.children[0].nodeValue === text) {
      found ??= node.nodeId;
    }
    for (const child of [...(node.children ?? []), ...(node.shadowRoots ?? [])]) walk(child, here);
  };
  walk(tree, false);
  if (!found) return null;
  const { model } = await cdp("DOM.getBoxModel", { nodeId: found }, sessionId);
  const [x1, y1, , , x3, y3] = model.content;
  return [(x1 + x3) / 2, (y1 + y3) / 2];
}

async function click(sessionId, [x, y]) {
  for (const type of ["mousePressed", "mouseReleased"]) {
    await cdp("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: 1 }, sessionId);
  }
}

// A text of the extension in the browser's language, asked of the
// extension's popup (extension/_locales).
let popup;
const message = (name) => evaluate(popup, `chrome.i18n.getMessage(${JSON.stringify(name)})`);

let failed = false;
try {
  await eventually(async () => (await cdp("Target.getTargets")).targetInfos
    .some((t) => t.url.startsWith(`chrome-extension://${EXTENSION_ID}/`)), "extension service worker");
  // Pairing (accepted automatically by the fake Verrou).
  popup = await openTab(`chrome-extension://${EXTENSION_ID}/popup.html`);
  const pair = await eventually(() => message("popupPair"), "extension texts");
  await eventually(() => evaluate(popup, `document.querySelector("button")?.textContent === ${JSON.stringify(pair)}`), "popup");
  await evaluate(popup, `document.querySelector("button").click()`);
  const unlocked = await message("popupUnlocked");
  await eventually(() => evaluate(popup, `document.getElementById("state").textContent === ${JSON.stringify(unlocked)}`),
    "extension linked", 20_000);
  step("extension linked");

  const tab = await openTab(pageUrl);
  await eventually(() => evaluate(tab, `document.readyState === "complete"`), "page loaded");
  await cdp("Page.bringToFront", {}, tab);
  await cdp("DOM.enable", {}, tab);
  assert.equal(await evaluate(tab, `"__verrouPasskeyCodec" in globalThis`), false, "the codec doesn't stay in the page");

  // Creation: the page waits, Verrou's window offers to save.
  await evaluate(tab, `window.created = navigator.credentials.create({ publicKey: {
    rp: { name: "Site local" },
    user: { id: new TextEncoder().encode("id-dominique"), name: "dominique", displayName: "Dominique" },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { residentKey: "required", userVerification: "discouraged" },
    extensions: { credProps: true },
  } }).then((c) => ({ ok: true, c }), (e) => ({ ok: false, error: e.name + ": " + e.message })); true`);
  const saveLabel = await message("save");
  const save = await eventually(() => find(tab, saveLabel), "\"Save a passkey\" window");
  step("save window open");
  // A click simulated by the page saves nothing.
  await evaluate(tab, `document.querySelector("verrou-passkey").dispatchEvent(new MouseEvent("click", { bubbles: true })); true`);
  await sleep(300);
  assert.deepEqual(saved, []);
  await click(tab, save);
  const registration = await evaluate(tab, `window.created.then(async (r) => {
    if (!r.ok) return r;
    const c = r.c;
    window.publicKey = c.response.getPublicKey();
    window.rawId = c.rawId;
    return { ok: true, pkc: c instanceof PublicKeyCredential, att: c.response instanceof AuthenticatorAttestationResponse,
      type: c.type, alg: c.response.getPublicKeyAlgorithm(), rk: c.getClientExtensionResults().credProps?.rk,
      client: JSON.parse(new TextDecoder().decode(c.response.clientDataJSON)), json: c.toJSON().id === c.id };
  })`);
  assert.equal(registration.ok, true, registration.error);
  assert.deepEqual(
    [registration.pkc, registration.att, registration.type, registration.alg, registration.rk, registration.json],
    [true, true, "public-key", -7, true, true]);
  assert.equal(registration.client.type, "webauthn.create");
  assert.equal(registration.client.origin, new URL(pageUrl).origin);
  assert.equal(saved.length, 1);
  step(`passkey created by Verrou and saved (${saved[0]})`);

  // Sign-in: the passkey is offered, a click signs.
  await evaluate(tab, `window.challenge = crypto.getRandomValues(new Uint8Array(32));
    window.used = navigator.credentials.get({ publicKey: { challenge: window.challenge, rpId: "localhost",
      userVerification: "discouraged" } }).then((c) => ({ ok: true, c }), (e) => ({ ok: false, error: e.name + ": " + e.message })); true`);
  const row = await eventually(() => find(tab, "dominique"), "passkey offered");
  step("passkey offered at sign-in");
  await click(tab, row);
  const assertion = await evaluate(tab, `window.used.then(async (r) => {
    if (!r.ok) return r;
    const c = r.c;
    const key = await crypto.subtle.importKey("spki", window.publicKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const data = new Uint8Array(c.response.authenticatorData);
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", c.response.clientDataJSON));
    // DER → r ‖ s
    const der = new Uint8Array(c.response.signature);
    const part = (o) => { let v = der.subarray(o + 2, o + 2 + der[o + 1]); while (v.length > 32) v = v.subarray(1);
      const out = new Uint8Array(32); out.set(v, 32 - v.length); return [out, o + 2 + der[o + 1]]; };
    const [rr, next] = part(2); const [ss] = part(next);
    const raw = new Uint8Array(64); raw.set(rr); raw.set(ss, 32);
    const message = new Uint8Array(data.length + 32); message.set(data); message.set(hash, data.length);
    const client = JSON.parse(new TextDecoder().decode(c.response.clientDataJSON));
    const challenge = btoa(String.fromCharCode(...window.challenge)).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
    return { ok: true, valid: await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, raw, message),
      same: c.id === btoa(String.fromCharCode(...new Uint8Array(window.rawId))).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, ""),
      counter: new DataView(data.buffer).getUint32(33), type: client.type, challenge: client.challenge === challenge,
      user: new TextDecoder().decode(c.response.userHandle) };
  })`);
  assert.equal(assertion.ok, true, assertion.error);
  assert.deepEqual(assertion, { ok: true, valid: true, same: true, counter: 1, type: "webauthn.get", challenge: true, user: "id-dominique" });
  step("signature checked by the page, counter at 1");

  // Cancellation by the page (AbortSignal): the window closes.
  const aborted = await evaluate(tab, `(async () => {
    const controller = new AbortController();
    const pending = navigator.credentials.get({ publicKey: { challenge: new Uint8Array(32), userVerification: "discouraged" },
      signal: controller.signal }).catch((e) => e.name);
    await new Promise((r) => setTimeout(r, 800));
    controller.abort();
    return pending;
  })()`);
  assert.equal(aborted, "AbortError");
  await sleep(200);
  assert.equal(await find(tab, await message("cancel")), null, "window closed");
  step("cancellation by the page");
} catch (error) {
  failed = true;
  console.error(`PASSKEY_FAIL ${error.stack}`);
} finally {
  socket.close();
  page.close();
  for (const child of children) child.kill();
  spawn("/usr/bin/pkill", ["-f", `user-data-dir=${profile}`]);
  await sleep(500);
  rmSync(profile, { recursive: true, force: true });
}
console.log(failed ? "PASSKEY_FAILED" : "PASSKEY_DONE");
process.exit(failed ? 1 : 0);
