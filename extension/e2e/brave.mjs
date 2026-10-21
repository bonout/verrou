// Walk through the extension in a real Brave, in the background, on a
// throwaway profile: pairing from the extension's popup, then filling a
// sign-in form with the keyboard, like a user.
//
//   cargo build -p verrou-bridge --example test_server --bin verrou-native-host
//   node extension/e2e/brave.mjs
//
// Verrou is replaced by the bridge's test server (fake vault, pairing
// accepted automatically): the Native Messaging host, the extension and
// Brave are the real ones.

import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const root = fileURLToPath(new URL("../../", import.meta.url));
const BRAVE = process.env.BRAVE ?? "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser";
const EXTENSION_ID = "pmdlgnpbjfdnmpeadbecmgfoojmocibg";
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const children = [];
const step = (text) => console.log(`BRAVE_OK ${text}`);

async function eventually(probe, what, timeout = 10_000) {
  const end = Date.now() + timeout;
  for (;;) {
    const value = await probe();
    if (value) return value;
    if (Date.now() > end) throw new Error(`timed out: ${what}`);
    await sleep(150);
  }
}

// MARK: Fake Verrou

const server = spawn(`${root}target/debug/examples/test_server`, {
  env: { ...process.env, VERROU_BRIDGE_PORT: "0" },
  stdio: ["ignore", "pipe", "inherit"],
});
children.push(server);
const codes = [];
const saved = [];
const port = await new Promise((resolve) => {
  createInterface({ input: server.stdout }).on("line", (line) => {
    if (line.startsWith("PORT ")) resolve(line.slice(5));
    if (line.startsWith("CODE ")) codes.push(line.slice(5));
    if (line.startsWith("SAVED ")) saved.push(line.slice(6));
  });
});

// MARK: Sign-in page

const page = createServer((request, response) => {
  if (request.url === "/qr.png") {
    response.setHeader("content-type", "image/png");
    response.setHeader("access-control-allow-origin", "*");
    return response.end(readFileSync(`${root}extension/e2e/fixtures/otpauth.png`));
  }
  response.setHeader("content-type", "text/html; charset=utf-8");
  if (request.url.startsWith("/inscription")) {
    return response.end(`<!doctype html><title>Inscription</title>
      <form id="signup" action="/bienvenue" method="post">
        <label>E-mail <input id="new-email" type="email" name="email"></label>
        <label>Mot de passe <input id="new-password" type="password" name="password"></label>
        <label>Confirmation <input id="confirm" type="password" name="confirm"></label>
        <button id="create">Créer mon compte</button>
      </form>`);
  }
  if (request.url.startsWith("/paiement")) {
    return response.end(`<!doctype html><title>Paiement</title>
      <form id="checkout" onsubmit="return false">
        <fieldset><legend>Livraison</legend>
          <label>Prénom <input id="given" autocomplete="given-name"></label>
          <label>Nom <input id="family" autocomplete="family-name"></label>
          <label>Adresse <input id="street" name="adresse"></label>
          <label>Code postal <input id="zip" name="code_postal"></label>
          <label>Ville <input id="city" name="ville"></label>
          <label>Pays <select id="country" name="pays"><option value="">—</option><option value="BE">Belgique</option><option value="FR">France</option></select></label>
        </fieldset>
      </form>
      <form id="card" onsubmit="return false">
        <label>Numéro de carte <input id="cc" name="cardnumber" inputmode="numeric"></label>
        <label>Mois d'expiration <select id="month" name="exp-month">${[..."123456789"].map((m) => `<option value="0${m}">0${m}</option>`).join("")}<option>10</option><option>11</option><option>12</option></select></label>
        <label>Année <input id="year" name="exp-year" maxlength="2"></label>
        <label>Cryptogramme <input id="cvc" name="cvc"></label>
      </form>`);
  }
  if (request.url.startsWith("/bienvenue")) {
    return response.end(`<!doctype html><title>Bienvenue</title><h1>Compte créé</h1>`);
  }
  response.end(`<!doctype html><title>Connexion</title>
    <form id="login" onsubmit="return false">
      <label>E-mail <input id="email" type="email" name="email" autocomplete="username"></label>
      <label>Mot de passe <input id="password" type="password" name="password" autocomplete="current-password"></label>
      <button>Se connecter</button>
    </form>
    <p>Newsletter <input id="newsletter" type="text" name="nom"></p>`);
}).listen(0, "127.0.0.1");
await new Promise((resolve) => page.once("listening", resolve));
const pageUrl = `http://localhost:${page.address().port}/connexion`;
const signupUrl = `http://localhost:${page.address().port}/inscription`;

// MARK: Brave, throwaway profile

const profile = mkdtempSync(join(tmpdir(), "verrou-brave-"));
// Brave looks for Native Messaging hosts in Google Chrome's folder (and in
// its own for the usual profile): we put the test's there, keeping aside
// the one Verrou may have installed.
const hosts = join(homedir(), "Library/Application Support/Google/Chrome/NativeMessagingHosts");
const manifestPath = join(hosts, "app.verrou.bridge.json");
mkdirSync(hosts, { recursive: true });
const previousManifest = existsSync(manifestPath) ? readFileSync(manifestPath) : null;
writeFileSync(manifestPath, JSON.stringify({
  name: "app.verrou.bridge",
  description: "Verrou (tests)",
  path: `${root}target/debug/verrou-native-host`,
  type: "stdio",
  allowed_origins: [`chrome-extension://${EXTENSION_ID}/`],
}));

// A real Brave, on the throwaway profile, in the background (`open -g`: it
// doesn't take the focus). The host inherits the environment: the fake
// Verrou's port, and never opening the real app.
const DEVTOOLS_PORT = 9_555;
const flags = [
  `--user-data-dir=${profile}`, `--remote-debugging-port=${DEVTOOLS_PORT}`,
  `--load-extension=${root}extension`, `--disable-extensions-except=${root}extension`,
  "--disable-features=DisableLoadExtensionCommandLineSwitch",
  "--no-first-run", "--no-default-browser-check", "--window-size=1000,700",
  ...(process.env.BRAVE_LOG ? ["--enable-logging", "--v=1"] : []), "about:blank",
];
const brave = spawn("/usr/bin/open", [
  "-g", "-n", "-a", BRAVE.replace(/\/Contents\/MacOS\/.*$/, ""),
  "--env", `VERROU_BRIDGE_PORT=${port}`, "--env", "VERROU_BRIDGE_NO_LAUNCH=1",
  "--args", ...flags,
], { stdio: "ignore" });
await new Promise((resolve) => brave.once("exit", resolve));
const endpoint = await eventually(async () => {
  try {
    const response = await fetch(`http://127.0.0.1:${DEVTOOLS_PORT}/json/version`);
    return (await response.json()).webSocketDebuggerUrl;
  } catch {
    return null;
  }
}, "Brave's DevTools", 20_000);

// MARK: DevTools

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
  await cdp("DOM.enable", {}, sessionId);
  return sessionId;
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

// The center of the `label` button in the `tag` host (closed shadow DOM).
async function shadowButton(sessionId, tag, label) {
  const { root: tree } = await cdp("DOM.getDocument", { depth: -1, pierce: true }, sessionId);
  let found = null;
  const walk = (node, inside) => {
    const here = inside || node.nodeName === tag;
    if (here && node.nodeName === "BUTTON" && (label === null || node.children?.[0]?.nodeValue === label)) found ??= node.nodeId;
    for (const child of [...(node.children ?? []), ...(node.shadowRoots ?? [])]) walk(child, here);
  };
  walk(tree, false);
  if (!found) return null;
  const { model } = await cdp("DOM.getBoxModel", { nodeId: found }, sessionId);
  return [(model.content[0] + model.content[4]) / 2, (model.content[1] + model.content[5]) / 2];
}

async function evaluate(sessionId, expression) {
  const { result, exceptionDetails } = await cdp("Runtime.evaluate",
    { expression, awaitPromise: true, returnByValue: true }, sessionId);
  if (exceptionDetails) throw new Error(exceptionDetails.text);
  return result.value;
}

// A real click (isTrusted), at the window's coordinates.
async function click(sessionId, x, y) {
  for (const type of ["mousePressed", "mouseReleased"]) {
    await cdp("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: 1 }, sessionId);
  }
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

// A text of the extension in the browser's language, asked of the
// extension's popup (extension/_locales).
const text = (name) => evaluate(popup, `chrome.i18n.getMessage(${JSON.stringify(name)})`);

let failed = false;
let popup;
try {
  // The extension is loaded, with the expected ID.
  await eventually(async () => (await cdp("Target.getTargets")).targetInfos
    .some((t) => t.url.startsWith(`chrome-extension://${EXTENSION_ID}/`)), "extension service worker");
  step("extension loaded");

  // Pairing from the extension's popup.
  popup = await openTab(`chrome-extension://${EXTENSION_ID}/popup.html`);
  const pair = await eventually(() => text("popupPair"), "extension texts");
  await eventually(() => evaluate(popup, `document.querySelector("button")?.textContent === ${JSON.stringify(pair)}`),
    `"${pair}" button`);
  await evaluate(popup, `document.querySelector("button").click()`);
  const shown = await eventually(() => evaluate(popup, `document.querySelector(".code")?.textContent`),
    "pairing code", 15_000);
  assert.ok(codes.includes(shown), `code ${shown} shown by the extension, ${codes} by Verrou`);
  step(`same code on both sides (${shown})`);
  const unlocked = await text("popupUnlocked");
  await eventually(() => evaluate(popup, `document.getElementById("state").textContent === ${JSON.stringify(unlocked)}`),
    "extension linked");
  step("extension linked");

  // Form: the pill comes by itself at the top left; with the keyboard, down
  // arrow from the username, then Enter.
  const tab = await openTab(pageUrl);
  await eventually(() => evaluate(tab, `document.readyState === "complete"`), "page loaded");
  await cdp("Page.bringToFront", {}, tab);
  const signIn = await text("pillSignIn");
  await eventually(async () => (await pillText(tab)).includes(signIn), "Verrou pill");
  const corner = await evaluate(tab, `(() => { const r = document.querySelector("verrou-pill").getBoundingClientRect(); return [r.left, r.top]; })()`);
  assert.deepEqual(corner, [16, 16]);
  step(`pill at the top left: ${await pillText(tab)}`);
  await evaluate(tab, `document.querySelector("verrou-pill").shadowRoot === null`).then((closed) => {
    assert.equal(closed, true, "the pill must be invisible to the page (closed shadow DOM)");
  });
  assert.equal(await evaluate(tab, `document.activeElement === document.body`), true, "the pill doesn't take the focus");
  await evaluate(tab, `document.getElementById("email").focus()`);
  await eventually(() => evaluate(tab, `Boolean(document.querySelector("verrou-field"))`), "icon in the field");
  assert.equal(await evaluate(tab, `Boolean(document.querySelector("verrou-menu"))`), false, "no more menu under the field");
  await press(tab, "ArrowDown");
  await press(tab, "Enter");
  const filled = await eventually(() => evaluate(tab,
    `document.getElementById("password").value && [document.getElementById("email").value, document.getElementById("password").value]`),
  "form filled");
  assert.deepEqual(filled, ["camille@exemple.fr", "mot-de-passe-local"]);
  step("username and password filled with the keyboard");

  // A field unrelated to signing in: no Verrou icon.
  await evaluate(tab, `document.getElementById("newsletter").focus()`);
  await sleep(800);
  assert.equal(await evaluate(tab, `Boolean(document.querySelector("verrou-field"))`), false);
  step("no icon outside the sign-in fields");

  // The field's icon reopens the pill (real click); a click simulated by the
  // page fills nothing.
  await evaluate(tab, `document.getElementById("password").value = ""; document.getElementById("email").value = ""`);
  await evaluate(tab, `document.getElementById("password").focus()`);
  const icon = await eventually(() => shadowButton(tab, "VERROU-FIELD", null), "icon in the field");
  await click(tab, ...icon);
  await eventually(async () => (await pillText(tab)).includes(signIn), "pill reopened");
  await evaluate(tab, `document.querySelector("verrou-pill").dispatchEvent(new MouseEvent("click", { bubbles: true }))`);
  await sleep(600);
  assert.equal(await evaluate(tab, `document.getElementById("password").value`), "");
  step("a click simulated by the page fills nothing");

  // Sign-up: strong password suggested in the field, with the keyboard.
  const signup = await openTab(signupUrl);
  await eventually(() => evaluate(signup, `document.readyState === "complete"`), "sign-up page");
  await cdp("Page.bringToFront", {}, signup);
  await evaluate(signup, `document.getElementById("new-email").value = "dominique@exemple.fr"`);
  await evaluate(signup, `document.getElementById("new-password").focus()`);
  const suggest = await text("pillSuggestPassword");
  await eventually(async () => (await pillText(signup)).includes(suggest), "generator");
  await press(signup, "ArrowDown");
  await press(signup, "Enter");
  const generated = await eventually(() => evaluate(signup,
    `document.getElementById("new-password").value && [document.getElementById("new-password").value, document.getElementById("confirm").value]`),
  "password generated");
  assert.equal(generated[0].length, 20);
  assert.equal(generated[0], generated[1], "the confirmation gets the same password");
  step("strong password generated in the field and its confirmation");

  // Form submission: the next page offers to save.
  const box = await evaluate(signup, `(() => { const r = document.getElementById("create").getBoundingClientRect(); return [r.x + r.width / 2, r.y + r.height / 2]; })()`);
  await click(signup, ...box);
  await eventually(() => evaluate(signup, `location.pathname === "/bienvenue" && document.readyState === "complete"`), "next page");
  const save = await text("save");
  const saveButton = await eventually(() => shadowButton(signup, "VERROU-PILL", save), `"${save}" banner`);
  step("save banner after the form is submitted");
  // A click simulated by the page on the banner saves nothing.
  await evaluate(signup, `document.querySelector("verrou-pill").dispatchEvent(new MouseEvent("click", { bubbles: true }))`);
  await sleep(500);
  assert.deepEqual(saved, []);
  await click(signup, ...saveButton);
  await eventually(() => saved.length > 0, "saved in Verrou");
  step(`login saved in Verrou (${saved[0]})`);

  // Payment: the card, then the address, from the pill.
  const checkout = await openTab(pageUrl.replace("/connexion", "/paiement"));
  await eventually(() => evaluate(checkout, `document.readyState === "complete"`), "payment page");
  await cdp("Page.bringToFront", {}, checkout);
  await evaluate(checkout, `document.getElementById("cc").focus()`);
  const fillCard = (await text("pillFillCard")).trim();
  await eventually(async () => (await pillText(checkout)).includes(fillCard), "cards pill");
  await press(checkout, "ArrowDown");
  await press(checkout, "Enter");
  const card = await eventually(() => evaluate(checkout, `(() => {
    const v = (id) => document.getElementById(id).value;
    return v("cc") && [v("cc"), v("month"), v("year"), v("cvc")];
  })()`), "card filled");
  assert.deepEqual(card, ["4242424242424242", "09", "29", "123"]);
  step("card filled (number, month in a list, 2-digit year, security code)");
  await evaluate(checkout, `document.getElementById("given").focus()`);
  const fillAddress = await text("pillFillAddress");
  await eventually(async () => (await pillText(checkout)).includes(fillAddress), "addresses pill");
  await press(checkout, "ArrowDown");
  await press(checkout, "Enter");
  const address = await eventually(() => evaluate(checkout, `(() => {
    const v = (id) => document.getElementById(id).value;
    return v("given") && [v("given"), v("family"), v("street"), v("zip"), v("city"), v("country")];
  })()`), "address filled");
  assert.deepEqual(address, ["Camille", "Martin", "12 rue des Lilas", "74000", "Annecy", "FR"]);
  step("address filled, country chosen in the list");

  // Two-factor QR code read in the extension's popup.
  const otpauth = await evaluate(popup, `import("./qr.js").then(async (qr) =>
    qr.otpauthFrom(await (await fetch("http://localhost:${page.address().port}/qr.png")).blob()))`);
  assert.equal(otpauth, "otpauth://totp/Local:dominique%40exemple.fr?secret=JBSWY3DPEHPK3PXP&issuer=Local");
  step("two-factor QR code read");
} catch (error) {
  failed = true;
  console.error(`BRAVE_FAIL ${error.message}`);
  if (popup) {
    console.error(`extension popup: ${await evaluate(popup, "document.body.innerText").catch(() => "?")}`);
    console.error(`pairing: ${await evaluate(popup, "chrome.storage.session.get('pairing').then(JSON.stringify)").catch((e) => e.message)}`);
    console.error(`codes seen by Verrou: ${codes.join(", ") || "none"}`);
    console.error(`status: ${await evaluate(popup, "Promise.race([chrome.runtime.sendMessage({ kind: 'status' }).then(JSON.stringify), new Promise((r) => setTimeout(() => r('blocked'), 3000))])").catch((e) => e.message)}`);
  }
} finally {
  socket.close();
  page.close();
  for (const child of children) child.kill();
  spawn("/usr/bin/pkill", ["-f", `user-data-dir=${profile}`]);
  if (previousManifest) writeFileSync(manifestPath, previousManifest);
  else rmSync(manifestPath, { force: true });
  await sleep(300);
  if (process.env.BRAVE_LOG) console.log(`log: ${profile}/chrome_debug.log`);
  else rmSync(profile, { recursive: true, force: true });
}
console.log(failed ? "BRAVE_FAILED" : "BRAVE_DONE");
process.exit(failed ? 1 : 0);
