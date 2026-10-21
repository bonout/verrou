// An extension that goes unnoticed, in a real Brave, in the background, on a
// throwaway profile:
//
// - autofill: the page waits for a passkey (`mediation: "conditional"`),
//   Verrou's pill at the top of the page offers it first, a real key (down
//   arrow from the field, then Enter) signs, and the page checks the
//   signature;
// - update (SEAMLESS_UPDATE=1, see below): the version of manifest.json
//   changes on disk (as when Verrou.app is replaced), the extension reloads
//   by itself, only once, and stays linked; an extension that is not the one
//   Verrou ships is flagged in its popup.
//
//   cargo build -p verrou-bridge --example test_server --bin verrou-native-host
//   node extension/e2e/seamless.mjs
//
// Opens a Brave window (in the background): run it when that's fine.
//
// The extension is loaded from a temporary copy (its version is changed
// there). Verrou is replaced by the bridge's test server; the Native
// Messaging host is declared in the throwaway profile only.

import { spawn } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const root = fileURLToPath(new URL("../../", import.meta.url));
const BRAVE = process.env.BRAVE ?? "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser";
const EXTENSION_ID = "pmdlgnpbjfdnmpeadbecmgfoojmocibg";
const EXTENSION_URL = `chrome-extension://${EXTENSION_ID}/`;
const DEVTOOLS_PORT = 9_559;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const step = (text) => console.log(`SEAMLESS_OK ${text}`);
const children = [];

async function eventually(probe, what, timeout = 10_000) {
  const end = Date.now() + timeout;
  for (;;) {
    let value = null;
    try {
      value = await probe();
    } catch {
      value = null;
    }
    if (value) return value;
    if (Date.now() > end) throw new Error(`timed out: ${what}`);
    await sleep(150);
  }
}

// MARK: Copied extension, fake Verrou, test page

const scratch = mkdtempSync(join(tmpdir(), "verrou-seamless-"));
const extension = join(scratch, "extension");
cpSync(`${root}extension`, extension, { recursive: true });
const manifestPath = join(extension, "manifest.json");
const setDiskVersion = (version) => {
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  manifest.version = version;
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
};
const initial = JSON.parse(readFileSync(manifestPath, "utf8")).version;
// The manifest.json "of the app bundle", whose version the bridge announces.
const bundled = join(scratch, "bundled-manifest.json");
const setBundledVersion = (version) => writeFileSync(bundled, JSON.stringify({ name: "Verrou", version }));
setBundledVersion(initial);

const server = spawn(`${root}target/debug/examples/test_server`, {
  env: { ...process.env, VERROU_BRIDGE_PORT: "0", VERROU_EXTENSION_MANIFEST: bundled },
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
  response.end(`<!doctype html><title>Connexion</title><h1>Connexion</h1>
    <form id="login" onsubmit="return false">
      <input id="username" type="text" name="username" autocomplete="username webauthn" style="width:240px">
      <input id="password" type="password" name="password" autocomplete="current-password" style="width:240px">
      <button type="submit">Se connecter</button>
    </form>`);
}).listen(0, "127.0.0.1");
await new Promise((resolve) => page.once("listening", resolve));
const pageUrl = `http://localhost:${page.address().port}/connexion`;

// MARK: Brave

const profile = join(scratch, "profile");
mkdirSync(join(profile, "NativeMessagingHosts"), { recursive: true });
writeFileSync(join(profile, "NativeMessagingHosts", "app.verrou.bridge.json"), JSON.stringify({
  name: "app.verrou.bridge",
  description: "Verrou (tests)",
  path: `${root}target/debug/verrou-native-host`,
  type: "stdio",
  allowed_origins: [EXTENSION_URL],
}));
const flags = [
  `--user-data-dir=${profile}`, `--remote-debugging-port=${DEVTOOLS_PORT}`,
  `--load-extension=${extension}`, `--disable-extensions-except=${extension}`,
  "--disable-features=DisableLoadExtensionCommandLineSwitch",
  "--no-first-run", "--no-default-browser-check", "--window-size=1000,700", "about:blank",
];
const brave = spawn("/usr/bin/open", [
  "-g", "-n", "-a", BRAVE.replace(/\/Contents\/MacOS\/.*$/, ""),
  "--env", `VERROU_BRIDGE_PORT=${port}`, "--env", "VERROU_BRIDGE_NO_LAUNCH=1",
  "--args", ...flags,
], { stdio: "ignore" });
await new Promise((resolve) => brave.once("exit", resolve));
const endpoint = await eventually(async () =>
  (await (await fetch(`http://127.0.0.1:${DEVTOOLS_PORT}/json/version`)).json()).webSocketDebuggerUrl,
"Brave's DevTools", 20_000);

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

// The text of Verrou's pill (closed shadow DOM: DevTools goes through it,
// the page doesn't).
async function pillText(sessionId) {
  const { root: tree } = await cdp("DOM.getDocument", { depth: -1, pierce: true }, sessionId);
  const texts = [];
  const walk = (node, inside) => {
    if (node.nodeName === "STYLE") return;
    const here = inside || node.nodeName === "VERROU-PILL";
    if (here && node.nodeType === 3 && node.nodeValue) texts.push(node.nodeValue);
    for (const child of [...(node.children ?? []), ...(node.shadowRoots ?? [])]) walk(child, here);
  };
  walk(tree, false);
  return texts.join(" | ");
}

async function press(sessionId, key) {
  const codes = { Enter: 13, ArrowDown: 40, Escape: 27 };
  for (const type of ["rawKeyDown", "keyUp"]) {
    await cdp("Input.dispatchKeyEvent", {
      type, key, code: key, windowsVirtualKeyCode: codes[key],
      ...(key === "Enter" && type === "rawKeyDown" ? { text: "\r" } : {}),
    }, sessionId);
  }
}

// The extension's service worker (its ID changes on each reload).
async function worker() {
  const { targetInfos } = await cdp("Target.getTargets");
  return targetInfos.find((t) => t.type === "service_worker" && t.url.startsWith(EXTENSION_URL));
}

// Opens the extension's popup in a tab; returns its session.
async function openPopup() {
  const session = await openTab(`${EXTENSION_URL}popup.html`);
  await eventually(() => evaluate(session, `document.getElementById("state")?.textContent !== ""`), "extension popup");
  return session;
}

let failed = false;
try {
  await eventually(worker, "extension service worker");
  const popup = await openPopup();
  // The extension's texts in the browser's language (extension/_locales).
  const T = await evaluate(popup, `Object.fromEntries(${JSON.stringify(
    ["popupPair", "popupUnlocked", "save", "pillSignInPasskey", "popupVersionTitle"])}
    .map((name) => [name, chrome.i18n.getMessage(name)]))`);
  await eventually(() => evaluate(popup, `document.querySelector("button")?.textContent === ${JSON.stringify(T.popupPair)}`), "popup");
  await evaluate(popup, `document.querySelector("button").click()`);
  await eventually(() => evaluate(popup, `document.getElementById("state").textContent === ${JSON.stringify(T.popupUnlocked)}`),
    "extension linked", 20_000);
  assert.equal(await evaluate(popup, `document.querySelector(".warning") === null`), true, "no warning");
  step("extension linked, versions match");

  // MARK: Passkey in the pill

  const tab = await openTab(pageUrl);
  await eventually(() => evaluate(tab, `document.readyState === "complete"`), "page loaded");
  await cdp("Page.bringToFront", {}, tab);
  await cdp("DOM.enable", {}, tab);

  // A passkey to use, created by Verrou ("Save" window).
  await evaluate(tab, `window.created = navigator.credentials.create({ publicKey: {
    rp: { name: "Site local" },
    user: { id: new TextEncoder().encode("id-dominique"), name: "dominique", displayName: "Dominique" },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { residentKey: "required", userVerification: "discouraged" },
  } }).then((c) => { window.publicKey = c.response.getPublicKey(); window.rawId = c.rawId; return true; },
    (e) => e.name + ": " + e.message); true`);
  const save = await eventually(async () => {
    const { root: tree } = await cdp("DOM.getDocument", { depth: -1, pierce: true }, tab);
    let found = null;
    const walk = (node, inside) => {
      const here = inside || node.nodeName === "VERROU-PASSKEY";
      if (here && node.nodeName === "BUTTON" && node.children?.[0]?.nodeValue === T.save) found ??= node.nodeId;
      for (const child of [...(node.children ?? []), ...(node.shadowRoots ?? [])]) walk(child, here);
    };
    walk(tree, false);
    if (!found) return null;
    const { model } = await cdp("DOM.getBoxModel", { nodeId: found }, tab);
    return [(model.content[0] + model.content[4]) / 2, (model.content[1] + model.content[5]) / 2];
  }, "\"Save a passkey\" window");
  for (const type of ["mousePressed", "mouseReleased"]) {
    await cdp("Input.dispatchMouseEvent", { type, x: save[0], y: save[1], button: "left", clickCount: 1 }, tab);
  }
  assert.equal(await evaluate(tab, "window.created"), true);
  assert.equal(saved.length, 1);
  step(`passkey created in Verrou (${saved[0]})`);

  // The page asks for a passkey in autofill, like github.com or google.com:
  // the pill offers it first, without taking the focus.
  await evaluate(tab, `window.challenge = crypto.getRandomValues(new Uint8Array(32));
    window.conditional = navigator.credentials.get({ mediation: "conditional",
      publicKey: { challenge: window.challenge, rpId: "localhost", userVerification: "discouraged" } })
      .then((c) => ({ ok: true, c }), (e) => ({ ok: false, error: e.name + ": " + e.message })); true`);
  const text = await eventually(async () => {
    const value = await pillText(tab);
    return value.includes(T.pillSignInPasskey) ? value : null;
  }, "passkey in the pill");
  assert.match(text, /dominique/);
  assert.equal(await evaluate(tab, `document.activeElement === document.body`), true, "the pill doesn't take the focus");
  step(`pill: ${text}`);
  await evaluate(tab, `document.getElementById("username").focus()`);

  // An Enter key made up by the page chooses nothing.
  await evaluate(tab, `document.getElementById("username").dispatchEvent(new KeyboardEvent("keydown",
    { key: "Enter", bubbles: true, cancelable: true })); true`);
  await sleep(500);
  assert.equal(await evaluate(tab, `Promise.race([window.conditional.then(() => "settled"), new Promise((r) => setTimeout(() => r("pending"), 100))])`),
    "pending", "the page doesn't choose on behalf of the user");

  // Real keys: down arrow (into the pill), Enter on "Sign in with a
  // passkey"; Verrou signs, the page receives the passkey.
  await press(tab, "ArrowDown");
  await press(tab, "Enter");
  const assertion = await evaluate(tab, `window.conditional.then(async (r) => {
    if (!r.ok) return r;
    const c = r.c;
    const key = await crypto.subtle.importKey("spki", window.publicKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const data = new Uint8Array(c.response.authenticatorData);
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", c.response.clientDataJSON));
    const der = new Uint8Array(c.response.signature);
    const part = (o) => { let v = der.subarray(o + 2, o + 2 + der[o + 1]); while (v.length > 32) v = v.subarray(1);
      const out = new Uint8Array(32); out.set(v, 32 - v.length); return [out, o + 2 + der[o + 1]]; };
    const [rr, next] = part(2); const [ss] = part(next);
    const raw = new Uint8Array(64); raw.set(rr); raw.set(ss, 32);
    const message = new Uint8Array(data.length + 32); message.set(data); message.set(hash, data.length);
    const client = JSON.parse(new TextDecoder().decode(c.response.clientDataJSON));
    return { ok: true, pkc: c instanceof PublicKeyCredential,
      valid: await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, raw, message),
      counter: new DataView(data.buffer).getUint32(33), type: client.type,
      user: new TextDecoder().decode(c.response.userHandle) };
  })`);
  assert.deepEqual(assertion, { ok: true, pkc: true, valid: true, counter: 1, type: "webauthn.get", user: "id-dominique" });
  await eventually(async () => !(await pillText(tab)).includes(T.pillSignInPasskey), "pill closed");
  step("passkey chosen in the pill, signature checked by the page");

  // The page gives up its request: the passkey leaves the pill.
  await evaluate(tab, `document.getElementById("password").focus();
    window.controller = new AbortController();
    window.aborted = navigator.credentials.get({ mediation: "conditional", signal: window.controller.signal,
      publicKey: { challenge: new Uint8Array(32), rpId: "localhost" } }).catch((e) => e.name); true`);
  await evaluate(tab, `document.getElementById("username").focus()`);
  await eventually(async () => (await pillText(tab)).includes(T.pillSignInPasskey), "passkey offered again");
  await evaluate(tab, `window.controller.abort()`);
  assert.equal(await evaluate(tab, "window.aborted"), "AbortError");
  await eventually(async () => !(await pillText(tab)).includes(T.pillSignInPasskey), "passkey removed from the pill");
  step("cancellation by the page: passkey removed from the pill");

  // MARK: App update
  //
  // Only with SEAMLESS_UPDATE=1: in Brave, an extension loaded with
  // --load-extension (as here) disappeared after `chrome.runtime.reload()`
  // during the trials, whereas an extension loaded from brave://extensions
  // ("Load unpacked", the real case) reloads from disk. To be checked by hand
  // in that real case.
  if (process.env.SEAMLESS_UPDATE) {
    // Verrou.app replaced: new version on disk and in the bridge.
    const updated = `${initial}.4242`;
    setDiskVersion(updated);
    setBundledVersion(updated);
    // The extension's popup asks Verrou: the extension sees the new version
    // and reloads by itself (its pages close).
    await openTab(`${EXTENSION_URL}popup.html`);
    const reloaded = await eventually(async () => {
      const session = await openTab(`${EXTENSION_URL}popup.html`);
      await sleep(300);
      if (await evaluate(session, "chrome.runtime.getManifest().version") === updated) return session;
      const { targetInfo } = await cdp("Target.getTargetInfo", {}, session);
      await cdp("Target.closeTarget", { targetId: targetInfo.targetId }).catch(() => {});
      return null;
    }, "extension reload", 20_000);
    const attempt = await evaluate(reloaded, `chrome.storage.local.get("reloadAttempt").then((r) => r.reloadAttempt)`);
    assert.deepEqual([attempt.version, attempt.from], [updated, initial]);
    await eventually(() => evaluate(reloaded, `document.getElementById("state").textContent === ${JSON.stringify(T.popupUnlocked)}`),
      "still linked after the reload");
    step(`extension reloaded by itself (${initial} → ${updated}), still linked`);

    // No loop: it stays in place.
    const after = await eventually(worker, "service worker reloaded");
    await sleep(3000);
    assert.equal((await worker())?.targetId, after.targetId, "a single reload");
    step("a single reload");

    // An extension that is not the one Verrou ships (loaded from another
    // folder): the popup flags it. (At most one reload attempt happens
    // first, without effect: the version on disk doesn't change.)
    setBundledVersion(`${initial}.9999`);
    const warning = await eventually(async () => {
      const session = await openPopup();
      return evaluate(session, `document.querySelector(".warning")?.textContent`);
    }, "version warning", 20_000);
    assert.ok(warning.includes(T.popupVersionTitle), warning);
    assert.match(warning, new RegExp(`${updated}.*${initial}\\.9999`));
    step(`popup: "${warning.slice(0, 60)}…"`);
  }
} catch (error) {
  failed = true;
  console.error(`SEAMLESS_FAIL ${error.stack}`);
} finally {
  socket.close();
  page.close();
  for (const child of children) child.kill();
  spawn("/usr/bin/pkill", ["-f", `user-data-dir=${profile}`]);
  await sleep(800);
  rmSync(scratch, { recursive: true, force: true });
}
console.log(failed ? "SEAMLESS_FAILED" : "SEAMLESS_DONE");
process.exit(failed ? 1 : 0);
