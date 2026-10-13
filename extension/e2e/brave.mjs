// Parcours de l'extension dans un vrai Brave, en arrière-plan, sur un profil
// jetable : appairage depuis la fenêtre de l'extension, puis
// remplissage d'un formulaire de connexion au clavier, comme un utilisateur.
//
//   cargo build -p verrou-bridge --example test_server --bin verrou-native-host
//   node extension/e2e/brave.mjs
//
// Verrou est remplacé par le serveur de test du pont (faux coffre, appairage
// accepté d'office) : l'hôte Native Messaging, l'extension et Brave sont les
// vrais.

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
    if (Date.now() > end) throw new Error(`délai dépassé : ${what}`);
    await sleep(150);
  }
}

// MARK: Faux Verrou

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

// MARK: Page de connexion

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

// MARK: Brave, profil jetable

const profile = mkdtempSync(join(tmpdir(), "verrou-brave-"));
// Brave cherche les hôtes Native Messaging dans le dossier de Google Chrome
// (et dans le sien pour le profil habituel) : on y pose celui du test, en
// gardant de côté celui que Verrou aurait installé.
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

// Un vrai Brave, sur le profil jetable, en arrière-plan (`open -g` : il ne
// prend pas le focus). L'hôte hérite de l'environnement : le port du faux
// Verrou, et jamais d'ouverture de la vraie app.
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
}, "DevTools de Brave", 20_000);

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
  return sessionId;
}

async function evaluate(sessionId, expression) {
  const { result, exceptionDetails } = await cdp("Runtime.evaluate",
    { expression, awaitPromise: true, returnByValue: true }, sessionId);
  if (exceptionDetails) throw new Error(exceptionDetails.text);
  return result.value;
}

// Un vrai clic (isTrusted), aux coordonnées de la fenêtre.
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

let failed = false;
let popup;
try {
  // L'extension est chargée, avec l'identifiant attendu.
  await eventually(async () => (await cdp("Target.getTargets")).targetInfos
    .some((t) => t.url.startsWith(`chrome-extension://${EXTENSION_ID}/`)), "service worker de l'extension");
  step("extension chargée");

  // Appairage depuis la fenêtre de l'extension.
  popup = await openTab(`chrome-extension://${EXTENSION_ID}/popup.html`);
  await eventually(() => evaluate(popup, `document.querySelector("button")?.textContent === "Relier à Verrou"`),
    "bouton « Relier à Verrou »");
  await evaluate(popup, `document.querySelector("button").click()`);
  const shown = await eventually(() => evaluate(popup, `document.querySelector(".code")?.textContent`),
    "code d'appairage", 15_000);
  assert.ok(codes.includes(shown), `code ${shown} affiché par l'extension, ${codes} par Verrou`);
  step(`même code des deux côtés (${shown})`);
  await eventually(() => evaluate(popup, `document.getElementById("state").textContent === "Déverrouillé"`),
    "extension reliée");
  step("extension reliée");

  // Formulaire : focus sur l'identifiant, menu Verrou, Entrée.
  const tab = await openTab(pageUrl);
  await eventually(() => evaluate(tab, `document.readyState === "complete"`), "page chargée");
  await cdp("Page.bringToFront", {}, tab);
  await evaluate(tab, `document.getElementById("email").focus()`);
  await eventually(() => evaluate(tab, `Boolean(document.querySelector("verrou-menu"))`), "menu Verrou");
  step("menu proposé sous le champ");
  await evaluate(tab, `document.querySelector("verrou-menu").shadowRoot === null`).then((closed) => {
    assert.equal(closed, true, "le menu doit être invisible pour la page (shadow DOM fermé)");
  });
  await press(tab, "Enter");
  const filled = await eventually(() => evaluate(tab,
    `document.getElementById("password").value && [document.getElementById("email").value, document.getElementById("password").value]`),
  "formulaire rempli");
  assert.deepEqual(filled, ["camille@exemple.fr", "mot-de-passe-local"]);
  step("identifiant et mot de passe remplis au clavier");

  // Un champ sans rapport avec la connexion : pas de menu.
  await evaluate(tab, `document.getElementById("newsletter").focus()`);
  await sleep(800);
  assert.equal(await evaluate(tab, `Boolean(document.querySelector("verrou-menu"))`), false);
  step("aucun menu hors des champs de connexion");

  // Un clic simulé par la page ne remplit rien.
  await evaluate(tab, `document.getElementById("password").value = ""; document.getElementById("email").value = ""`);
  await evaluate(tab, `document.getElementById("password").focus()`);
  await eventually(() => evaluate(tab, `Boolean(document.querySelector("verrou-menu"))`), "menu Verrou");
  await evaluate(tab, `document.querySelector("verrou-menu").dispatchEvent(new MouseEvent("mousedown", { bubbles: true }))`);
  await sleep(600);
  assert.equal(await evaluate(tab, `document.getElementById("password").value`), "");
  step("un clic simulé par la page ne remplit rien");

  // Inscription : mot de passe fort proposé dans le champ, au clavier.
  const signup = await openTab(signupUrl);
  await eventually(() => evaluate(signup, `document.readyState === "complete"`), "page d'inscription");
  await cdp("Page.bringToFront", {}, signup);
  await evaluate(signup, `document.getElementById("new-email").value = "dominique@exemple.fr"`);
  await evaluate(signup, `document.getElementById("new-password").focus()`);
  await eventually(() => evaluate(signup, `Boolean(document.querySelector("verrou-menu"))`), "générateur");
  await press(signup, "Enter");
  const generated = await eventually(() => evaluate(signup,
    `document.getElementById("new-password").value && [document.getElementById("new-password").value, document.getElementById("confirm").value]`),
  "mot de passe généré");
  assert.equal(generated[0].length, 20);
  assert.equal(generated[0], generated[1], "la confirmation reçoit le même mot de passe");
  step("mot de passe fort généré dans le champ et sa confirmation");

  // Envoi du formulaire : la page suivante propose d'enregistrer.
  const box = await evaluate(signup, `(() => { const r = document.getElementById("create").getBoundingClientRect(); return [r.x + r.width / 2, r.y + r.height / 2]; })()`);
  await click(signup, ...box);
  await eventually(() => evaluate(signup, `location.pathname === "/bienvenue" && document.readyState === "complete"`), "page suivante");
  const bannerBox = await eventually(() => evaluate(signup,
    `(() => { const b = document.querySelector("verrou-banner"); if (!b) return null; const r = b.getBoundingClientRect(); return r.height > 40 && [r.right, r.bottom]; })()`),
  "bandeau « Enregistrer »");
  step("bandeau d'enregistrement après l'envoi du formulaire");
  // Un clic simulé par la page sur le bandeau n'enregistre rien.
  await evaluate(signup, `document.querySelector("verrou-banner").dispatchEvent(new MouseEvent("click", { bubbles: true }))`);
  await sleep(500);
  assert.deepEqual(saved, []);
  // Le bouton « Enregistrer », en bas à droite du bandeau.
  await click(signup, bannerBox[0] - 50, bannerBox[1] - 26);
  await eventually(() => saved.length > 0, "enregistrement dans Verrou");
  step(`identifiant enregistré dans Verrou (${saved[0]})`);

  // Paiement : la carte, puis l'adresse, depuis le menu sous le champ.
  const checkout = await openTab(pageUrl.replace("/connexion", "/paiement"));
  await eventually(() => evaluate(checkout, `document.readyState === "complete"`), "page de paiement");
  await cdp("Page.bringToFront", {}, checkout);
  await evaluate(checkout, `document.getElementById("cc").focus()`);
  await eventually(() => evaluate(checkout, `Boolean(document.querySelector("verrou-menu"))`), "menu des cartes");
  await press(checkout, "Enter");
  const card = await eventually(() => evaluate(checkout, `(() => {
    const v = (id) => document.getElementById(id).value;
    return v("cc") && [v("cc"), v("month"), v("year"), v("cvc")];
  })()`), "carte remplie");
  assert.deepEqual(card, ["4242424242424242", "09", "29", "123"]);
  step("carte remplie (numéro, mois en liste, année sur 2 chiffres, cryptogramme)");
  await evaluate(checkout, `document.getElementById("given").focus()`);
  await eventually(() => evaluate(checkout, `Boolean(document.querySelector("verrou-menu"))`), "menu des adresses");
  await press(checkout, "Enter");
  const address = await eventually(() => evaluate(checkout, `(() => {
    const v = (id) => document.getElementById(id).value;
    return v("given") && [v("given"), v("family"), v("street"), v("zip"), v("city"), v("country")];
  })()`), "adresse remplie");
  assert.deepEqual(address, ["Camille", "Martin", "12 rue des Lilas", "74000", "Annecy", "FR"]);
  step("adresse remplie, pays choisi dans la liste");

  // QR code de double authentification lu dans la fenêtre de l'extension.
  const otpauth = await evaluate(popup, `import("./qr.js").then(async (qr) =>
    qr.otpauthFrom(await (await fetch("http://localhost:${page.address().port}/qr.png")).blob()))`);
  assert.equal(otpauth, "otpauth://totp/Local:dominique%40exemple.fr?secret=JBSWY3DPEHPK3PXP&issuer=Local");
  step("QR code de double authentification lu");
} catch (error) {
  failed = true;
  console.error(`BRAVE_FAIL ${error.message}`);
  if (popup) {
    console.error(`fenêtre de l'extension : ${await evaluate(popup, "document.body.innerText").catch(() => "?")}`);
    console.error(`appairage : ${await evaluate(popup, "chrome.storage.session.get('pairing').then(JSON.stringify)").catch((e) => e.message)}`);
    console.error(`codes vus par Verrou : ${codes.join(", ") || "aucun"}`);
    console.error(`status : ${await evaluate(popup, "Promise.race([chrome.runtime.sendMessage({ kind: 'status' }).then(JSON.stringify), new Promise((r) => setTimeout(() => r('bloqué'), 3000))])").catch((e) => e.message)}`);
  }
} finally {
  socket.close();
  page.close();
  for (const child of children) child.kill();
  spawn("/usr/bin/pkill", ["-f", `user-data-dir=${profile}`]);
  if (previousManifest) writeFileSync(manifestPath, previousManifest);
  else rmSync(manifestPath, { force: true });
  await sleep(300);
  if (process.env.BRAVE_LOG) console.log(`journal : ${profile}/chrome_debug.log`);
  else rmSync(profile, { recursive: true, force: true });
}
console.log(failed ? "BRAVE_FAILED" : "BRAVE_DONE");
process.exit(failed ? 1 : 0);
