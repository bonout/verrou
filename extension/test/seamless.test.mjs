// Une extension qui se fait oublier : elle se recharge quand Verrou est mis
// à jour (update.js, version annoncée par le vrai pont), propose ses
// passkeys dans le remplissage automatique (`mediation: "conditional"`), et
// dit quand une passkey part au navigateur faute de Verrou.
//
// passkey-page.js (monde de la page) et passkeys.js (monde isolé) tournent
// ici dans deux contextes, reliés par un faux `postMessage` ; le service
// worker est remplacé par passkey-bridge.js et le vrai pont, à travers le
// vrai hôte Native Messaging. Les signatures sont vérifiées avec WebCrypto.
//
//   cargo build -p verrou-bridge --example test_server --bin verrou-native-host
//   node --test extension/test/seamless.test.mjs

import { execFileSync, spawn } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync, appendFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

import { Channel } from "../bridge.js";
import { passkeyCommand, passkeyResult } from "../passkey-bridge.js";
import { createUpdater } from "../update.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const source = (name) => readFileSync(`${root}extension/${name}`, "utf8");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function eventually(probe, what, timeout = 5000) {
  const end = Date.now() + timeout;
  for (;;) {
    const value = await probe();
    if (value) return value;
    if (Date.now() > end) throw new Error(`délai dépassé : ${what}`);
    await sleep(20);
  }
}

// MARK: Faux Verrou (le vrai pont, sur un faux coffre)

const scratch = mkdtempSync(join(tmpdir(), "verrou-seamless-"));
// Le manifest.json « livré avec l'app » : le pont annonce sa version.
const bundledManifest = join(scratch, "manifest.json");
const writeBundled = (version) => writeFileSync(bundledManifest, JSON.stringify({ name: "Verrou", version }));
writeBundled("0.3.0");

const server = spawn(`${root}target/debug/examples/test_server`, {
  env: { ...process.env, VERROU_BRIDGE_PORT: "0", VERROU_EXTENSION_MANIFEST: bundledManifest },
  stdio: ["ignore", "pipe", "inherit"],
});
const lines = createInterface({ input: server.stdout });
let port;

before(async () => {
  for await (const line of lines) {
    if (line.startsWith("PORT ")) {
      port = line.slice(5);
      break;
    }
  }
});

after(() => {
  paired?.disconnect();
  server.kill();
  rmSync(scratch, { recursive: true, force: true });
});

function hostTransport() {
  const host = spawn(`${root}target/debug/verrou-native-host`, {
    env: { ...process.env, VERROU_BRIDGE_PORT: port, VERROU_BRIDGE_NO_LAUNCH: "1" },
    stdio: ["pipe", "pipe", "inherit"],
  });
  let buffer = Buffer.alloc(0);
  let onMessage = () => {};
  let onDisconnect = () => {};
  host.stdout.on("data", (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (buffer.length >= 4 && buffer.length >= 4 + buffer.readUInt32LE(0)) {
      const length = buffer.readUInt32LE(0);
      onMessage(JSON.parse(buffer.subarray(4, 4 + length).toString("utf8")));
      buffer = buffer.subarray(4 + length);
    }
  });
  host.on("exit", () => onDisconnect("hôte arrêté"));
  return {
    post(message) {
      const body = Buffer.from(JSON.stringify(message));
      const length = Buffer.alloc(4);
      length.writeUInt32LE(body.length);
      host.stdin.write(Buffer.concat([length, body]));
    },
    onMessage: (callback) => { onMessage = callback; },
    onDisconnect: (callback) => { onDisconnect = callback; },
    close: () => host.stdin.end(),
  };
}

let paired = null;
async function pairedChannel() {
  if (!paired) {
    const channel = new Channel(hostTransport);
    channel.setClient(await channel.pair("Brave", () => {}));
    paired = channel;
  }
  return paired;
}

// MARK: A. Rechargement après une mise à jour de l'app

function memoryStore() {
  let value;
  return { get: async () => value, set: async (v) => { value = v; }, peek: () => value };
}

test("la version annoncée par Verrou, puis un seul rechargement par version", async () => {
  const channel = await pairedChannel();
  let disk = "0.3.0";
  let reloads = 0;
  let clock = 1_000_000;
  const store = memoryStore();
  const updater = createUpdater({
    running: "0.3.0",
    readDisk: async () => disk,
    reload: () => { reloads += 1; },
    store,
    now: () => clock,
  });
  const status = async () => (await channel.request({ cmd: "status" })).extension_version;

  // Même version partout : rien.
  assert.equal(await status(), "0.3.0");
  assert.equal((await updater.check({ bridgeVersion: await status() })).reloading, false);
  assert.equal(updater.state().mismatch, false);

  // L'app est mise à jour : le disque et Verrou annoncent la nouvelle version.
  writeBundled("0.3.0.4242");
  disk = "0.3.0.4242";
  assert.equal(await status(), "0.3.0.4242");
  assert.equal((await updater.check({ bridgeVersion: await status() })).reloading, true);
  assert.equal(reloads, 1);
  assert.deepEqual(store.peek(), { version: "0.3.0.4242", from: "0.3.0", at: clock });
  assert.equal(updater.state().mismatch, true);

  // Le rechargement n'a rien changé (le même ancien code tourne encore) :
  // pas de deuxième tentative pour cette version, même bien plus tard.
  clock += 3_600_000;
  for (let i = 0; i < 3; i += 1) assert.equal((await updater.check({ bridgeVersion: await status() })).reloading, false);
  assert.equal(reloads, 1);

  // Le service worker redémarre dans la nouvelle version : plus rien à faire.
  const next = createUpdater({ running: "0.3.0.4242", readDisk: async () => disk, reload: () => { reloads += 1; }, store, now: () => clock });
  assert.equal((await next.check({ bridgeVersion: await status() })).reloading, false);
  assert.equal(next.state().mismatch, false);

  // Nouvelle mise à jour, une seconde après la précédente tentative : on attend.
  writeBundled("0.3.0.777");
  disk = "0.3.0.777";
  await store.set({ version: "0.3.0.4242", at: clock - 1000 });
  assert.equal((await next.check()).reloading, false);
  clock += 120_000;
  assert.equal((await next.check()).reloading, true);
  assert.equal(reloads, 2);
});

test("disque illisible : la version de Verrou décide ; chargée d'ailleurs : avertir sans boucler", async () => {
  const store = memoryStore();
  let reloads = 0;
  const unreadable = createUpdater({
    running: "0.3.0", readDisk: async () => { throw new Error("illisible"); }, reload: () => { reloads += 1; }, store,
  });
  assert.equal((await unreadable.check()).reloading, false, "rien d'annoncé : rien à faire");
  assert.equal((await unreadable.check({ bridgeVersion: "0.3.0.9" })).reloading, true);
  assert.equal((await unreadable.check({ bridgeVersion: "0.3.0.9" })).reloading, false);
  assert.equal(reloads, 1);

  // Extension chargée depuis le dépôt : le disque a la même version que ce
  // qui tourne, Verrou en livre une autre. Un seul essai, puis l'avertissement.
  const dev = createUpdater({ running: "0.3.0", readDisk: async () => "0.3.0", reload: () => { reloads += 1; }, store: memoryStore() });
  assert.equal((await dev.check({ bridgeVersion: "0.3.0.9" })).reloading, true);
  for (let i = 0; i < 3; i += 1) assert.equal((await dev.check({ bridgeVersion: "0.3.0.9" })).reloading, false);
  assert.deepEqual(dev.state(), { running: "0.3.0", bundled: "0.3.0.9", mismatch: true });
  assert.equal(reloads, 2);

  // Appairage en cours : plus tard ; stockage en panne : jamais (risque de boucle).
  let busy = true;
  const later = createUpdater({ running: "0.3.0", readDisk: async () => "0.3.1", reload: () => { reloads += 1; }, store: memoryStore(), busy: () => busy });
  assert.equal((await later.check()).deferred, true);
  busy = false;
  assert.equal((await later.check()).reloading, true);
  assert.equal(reloads, 3);
  const broken = createUpdater({
    running: "0.3.0", readDisk: async () => "0.3.1", reload: () => { reloads += 1; },
    store: { get: async () => undefined, set: async () => { throw new Error("plein"); } },
  });
  assert.equal((await broken.check()).reloading, false);
  assert.equal(reloads, 3);
});

test("la version livrée dépend du contenu de l'extension, et reste valable", () => {
  const copy = join(scratch, "extension");
  cpSync(`${root}extension`, copy, { recursive: true });
  const stamp = () => {
    execFileSync(`${root}scripts/stamp-extension.sh`, [copy], { stdio: "ignore" });
    return JSON.parse(readFileSync(join(copy, "manifest.json"), "utf8")).version;
  };
  const committed = JSON.parse(source("manifest.json")).version;
  assert.match(committed, /^\d+\.\d+\.\d+$/, "la version du dépôt reste a.b.c");
  const first = stamp();
  assert.match(first, new RegExp(`^${committed.replaceAll(".", "\\.")}\\.\\d{1,5}$`));
  assert.ok(Number(first.split(".")[3]) <= 65535);
  assert.equal(stamp(), first, "relancer ne change rien");
  // Les tests ne comptent pas ; un fichier livré, si.
  appendFileSync(join(copy, "test", "bridge.test.mjs"), "\n");
  assert.equal(stamp(), first);
  appendFileSync(join(copy, "content.js"), "\n// changement\n");
  const second = stamp();
  assert.notEqual(second, first);
  // Le reste du manifeste est intact.
  const before = JSON.parse(source("manifest.json"));
  const stamped = JSON.parse(readFileSync(join(copy, "manifest.json"), "utf8"));
  assert.deepEqual({ ...stamped, version: before.version }, before);
});

// MARK: Faux navigateur : la page et le script de contenu

// Un DOM minimal, pour la fenêtre de passkeys.js (shadow DOM compris).
class FakeElement {
  constructor(tag, owner) {
    this.tagName = tag.toUpperCase();
    this.owner = owner;
    this.children = [];
    this.parent = null;
    this.className = "";
    this.text = "";
    this.listeners = {};
    this.attributes = {};
    this.style = {};
  }

  set textContent(value) {
    this.text = String(value);
    this.children = [];
  }

  get textContent() {
    return this.text + this.children.map((child) => child.textContent).join("");
  }

  append(...nodes) {
    for (const node of nodes) {
      node.parent?.children.splice(node.parent.children.indexOf(node), 1);
      node.parent = this;
      this.children.push(node);
    }
  }

  remove() {
    if (!this.parent) return;
    this.parent.children.splice(this.parent.children.indexOf(this), 1);
    this.parent = null;
  }

  get isConnected() {
    let node = this;
    while (node.parent) node = node.parent;
    return node === this.owner.documentElement || Boolean(node.host?.isConnected);
  }

  setAttribute(name, value) {
    this.attributes[name] = value;
  }

  addEventListener(type, listener) {
    (this.listeners[type] ??= []).push(listener);
  }

  attachShadow() {
    this.shadow = new FakeElement("#shadow-root", this.owner);
    this.shadow.host = this;
    return this.shadow;
  }

  *walk() {
    yield this;
    for (const child of this.children) yield* child.walk();
    if (this.shadow) yield* this.shadow.walk();
  }

  querySelector(selector) {
    const name = selector.replace(/^\./, "");
    for (const node of this.walk()) if (node !== this && node.className.split(" ").includes(name)) return node;
    return null;
  }
}

function fakeDocument() {
  const document = { createElement: (tag) => new FakeElement(tag, document) };
  document.documentElement = new FakeElement("html", document);
  return document;
}

// Une page à `origin`, avec ses deux mondes. `background(message)` répond
// aux demandes de passkeys.js, comme le service worker. `firefox` : le monde
// isolé a `browser` (promesses) ; `chrome` y est piégé pour prouver qu'il
// ne sert pas.
function openPage(origin, background, { firefox = false } = {}) {
  const url = new URL(origin);
  const listeners = [];
  const contexts = [];
  const document = fakeDocument();
  const native = [];
  const timer = (fn, ms) => {
    const handle = setTimeout(fn, ms);
    handle.unref?.();
    return handle;
  };
  const postMessage = (data) => {
    const copy = structuredClone(data);
    setTimeout(() => {
      for (const [context, listener] of listeners) listener({ source: context.self, data: copy });
    }, 0);
  };
  const makeContext = (extra) => {
    const context = {
      location: { origin: url.origin, hostname: url.hostname, href: url.href },
      postMessage, setTimeout: timer, clearTimeout,
      btoa, atob, structuredClone, ArrayBuffer, Uint8Array, DOMException, Promise, console,
      ...extra,
    };
    context.addEventListener = (type, listener) => {
      if (type === "message") listeners.push([context, listener]);
    };
    context.window = context;
    context.top = context;
    context.globalThis = context;
    vm.createContext(context);
    // Le `window` que voient les scripts : l'objet global du contexte (vm le
    // substitue à `context` vu de l'intérieur).
    context.self = vm.runInContext("globalThis", context);
    contexts.push(context);
    return context;
  };

  // Monde de la page.
  class PublicKeyCredential {}
  const credentials = {
    create: async (options) => { native.push(["create", options]); return "natif"; },
    get: async (options) => { native.push(["get", options]); return "natif"; },
  };
  const page = makeContext({
    navigator: { credentials },
    PublicKeyCredential,
    AuthenticatorAttestationResponse: class {},
    AuthenticatorAssertionResponse: class {},
    AbortController,
  });
  vm.runInContext(source("passkey-codec.js"), page);
  vm.runInContext(source("passkey-page.js"), page);

  // Monde isolé de l'extension.
  const runtime = {
    id: "extension",
    sendMessage: async (message) => background(message, `${url.origin}/connexion`),
  };
  const unused = { id: "extension", sendMessage: async () => { throw new Error("chrome.runtime utilisé dans Firefox"); } };
  const isolated = makeContext(firefox
    ? { browser: { runtime }, chrome: { runtime: unused }, document }
    : { chrome: { runtime }, document });
  vm.runInContext(source("passkeys.js"), isolated);

  const panelText = () => {
    const host = document.documentElement.children.find((n) => n.tagName === "VERROU-PASSKEY");
    return host?.shadow?.querySelector("panel")?.textContent ?? "";
  };
  // Un vrai clic (isTrusted) sur le bouton de la fenêtre dont le texte est `label`.
  const press = (label) => {
    const host = document.documentElement.children.find((n) => n.tagName === "VERROU-PASSKEY");
    const node = [...(host?.shadow?.walk() ?? [])].find((n) => n.tagName === "BUTTON" && n.textContent === label);
    assert.ok(node, `bouton « ${label} »`);
    for (const listener of node.listeners.click ?? []) {
      listener({ isTrusted: true, preventDefault() {}, stopPropagation() {} });
    }
  };

  return {
    credentials: page.navigator.credentials,
    menu: () => isolated.__verrouPasskeyMenu,
    native,
    panelText,
    press,
    runtime,
  };
}

// Le service worker : passkey-bridge.js et un canal vers le vrai pont.
function backgroundFor(channel) {
  return async (message, url) => {
    if (message.kind === "unlock") return { ok: true };
    const command = passkeyCommand(message, url);
    if (!command) return { error: "commande inconnue" };
    try {
      return passkeyResult(await channel.request(command));
    } catch (error) {
      return { state: error.code === "unpaired" || error.code === "unknown_client" ? "unpaired" : "offline" };
    }
  };
}

// Signature ECDSA DER → r ‖ s (64 octets), la forme qu'attend WebCrypto.
function derToRaw(der) {
  const integer = (offset) => {
    const length = der[offset + 1];
    let value = der.subarray(offset + 2, offset + 2 + length);
    while (value.length > 32 && value[0] === 0) value = value.subarray(1);
    const out = new Uint8Array(32);
    out.set(value, 32 - value.length);
    return [out, offset + 2 + length];
  };
  const [r, next] = integer(2);
  const [s] = integer(next);
  return Buffer.concat([r, s]);
}

const b64url = (bytes) => Buffer.from(bytes).toString("base64url");

// MARK: B. Passkeys dans la pastille (remplissage automatique)

test("remplissage automatique : la passkey de Verrou à la pastille, une signature valide", async () => {
  const channel = await pairedChannel();
  const origin = "http://localhost:8000";
  // Une passkey dans l'identifiant du site de test.
  const created = await channel.request({
    cmd: "passkey_create", url: `${origin}/inscription`, rp_id: "localhost", user_id: b64url(Buffer.from("id-camille")),
    user_name: "camille@exemple.fr", challenge: b64url(crypto.getRandomValues(new Uint8Array(32))),
    algorithms: [-7], exclude: [], uv: false, attestation: "none", item: "local",
  });
  assert.equal(created.result, "registration", JSON.stringify(created));

  const page = openPage(origin, backgroundFor(channel));
  const notified = [];
  page.menu().subscribe(() => notified.push(Date.now()));
  assert.deepEqual({ ...(await page.menu().entries()) }, { state: "none" }, "rien en attente");

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  let settled = null;
  const pending = page.credentials.get({ mediation: "conditional", publicKey: { challenge, rpId: "localhost", userVerification: "discouraged" } })
    .then((c) => { settled = { ok: true, c }; }, (e) => { settled = { ok: false, e }; });
  // La demande reste en attente ; la pastille est prévenue, et propose la passkey.
  await eventually(() => notified.length > 0, "pastille prévenue");
  const entries = await page.menu().entries();
  assert.equal(entries.state, "ready");
  assert.deepEqual(entries.items.map((i) => [i.item, i.credential, i.user_name]), [["local", created.credential, "camille@exemple.fr"]]);
  await sleep(100);
  assert.equal(settled, null, "en attente d'un choix");
  assert.deepEqual(page.native, [], "rien pour le navigateur");

  // Une passkey inconnue ne se choisit pas.
  assert.equal(page.menu().choose("inconnue"), false);
  // Choisie dans la pastille : la même signature qu'une connexion explicite.
  assert.equal(page.menu().choose(created.credential), true);
  await pending;
  assert.equal(settled.ok, true, String(settled.e));
  const credential = settled.c;
  assert.equal(credential.id, created.credential);
  const clientData = JSON.parse(Buffer.from(credential.response.clientDataJSON).toString());
  assert.deepEqual(clientData, { type: "webauthn.get", challenge: b64url(challenge), origin, crossOrigin: false });
  const key = await crypto.subtle.importKey("spki", Buffer.from(created.public_key, "base64url"),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", credential.response.clientDataJSON));
  const data = Buffer.concat([Buffer.from(credential.response.authenticatorData), hash]);
  const signature = derToRaw(new Uint8Array(credential.response.signature));
  assert.equal(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, data), true, "signature ES256 valide");
  assert.equal(Buffer.from(credential.response.authenticatorData).readUInt32BE(33), 1, "compteur enregistré");
  assert.equal(Buffer.from(credential.response.userHandle).toString(), "id-camille");
  // Terminé : plus rien à la pastille.
  assert.equal((await page.menu().entries()).state, "none");
  assert.equal(page.menu().choose(created.credential), false);

  // La page annule (AbortSignal) : la promesse est rejetée, la pastille vidée.
  const controller = new AbortController();
  const aborted = page.credentials.get({ mediation: "conditional", signal: controller.signal, publicKey: { challenge, rpId: "localhost" } })
    .then(() => "résolue", (e) => e.name);
  await eventually(async () => (await page.menu().entries()).state === "ready", "passkey proposée");
  const before = notified.length;
  controller.abort();
  assert.equal(await aborted, "AbortError");
  await eventually(() => notified.length > before, "pastille prévenue de l'annulation");
  assert.equal((await page.menu().entries()).state, "none");
  assert.equal(page.menu().choose(created.credential), false);

  // Une demande explicite remplace celle du remplissage automatique.
  const replaced = page.credentials.get({ mediation: "conditional", publicKey: { challenge, rpId: "localhost" } })
    .then(() => "résolue", (e) => e.name);
  await eventually(async () => (await page.menu().entries()).state === "ready", "passkey proposée");
  const modal = page.credentials.get({ publicKey: { challenge, rpId: "localhost", userVerification: "discouraged" } });
  assert.equal(await replaced, "NotAllowedError");
  await eventually(() => page.panelText().includes("Se connecter avec une passkey de Verrou"), "fenêtre de connexion");
  assert.equal((await page.menu().entries()).state, "none");
  page.press("Annuler");
  await assert.rejects(modal, { name: "NotAllowedError" });
  assert.deepEqual(page.native, []);
});

test("Firefox : les mêmes passkeys à la pastille, par l'API `browser`", async () => {
  const channel = await pairedChannel();
  const origin = "http://localhost:8000";
  const created = await channel.request({
    cmd: "passkey_create", url: `${origin}/inscription`, rp_id: "localhost", user_id: b64url(Buffer.from("id-renard")),
    user_name: "renard@exemple.fr", challenge: b64url(crypto.getRandomValues(new Uint8Array(32))),
    algorithms: [-7], exclude: [], uv: false, attestation: "none", item: "local",
  });
  assert.equal(created.result, "registration", JSON.stringify(created));

  const page = openPage(origin, backgroundFor(channel), { firefox: true });
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const pending = page.credentials.get({ mediation: "conditional", publicKey: { challenge, rpId: "localhost", userVerification: "discouraged" } });
  await eventually(async () => (await page.menu().entries()).state === "ready", "passkey proposée");
  const entries = await page.menu().entries();
  assert.ok(entries.items.some((i) => i.credential === created.credential), JSON.stringify(entries));
  assert.equal(page.menu().choose(created.credential), true);
  const credential = await pending;
  assert.equal(credential.id, created.credential);
  const clientData = JSON.parse(Buffer.from(credential.response.clientDataJSON).toString());
  assert.deepEqual(clientData, { type: "webauthn.get", challenge: b64url(challenge), origin, crossOrigin: false });
  assert.deepEqual(page.native, [], "rien pour le navigateur");
});

test("remplissage automatique sans passkey de Verrou, ou sans Verrou : le navigateur", async () => {
  const channel = await pairedChannel();
  // Aucune passkey pour ce site dans Verrou.
  const page = openPage("https://exemple.org", backgroundFor(channel));
  const challenge = new Uint8Array(32);
  const result = await page.credentials.get({ mediation: "conditional", publicKey: { challenge } });
  assert.equal(result, "natif");
  assert.equal(page.native.length, 1);
  assert.equal(page.native[0][1].mediation, "conditional", "le remplissage du navigateur, avec les mêmes options");
  assert.equal(page.panelText(), "", "aucun avis : l'utilisateur n'a rien demandé");

  // Verrou injoignable : de même.
  const offline = openPage("http://localhost:8000", async () => ({ state: "offline" }));
  assert.equal(await offline.credentials.get({ mediation: "conditional", publicKey: { challenge } }), "natif");
  assert.equal(offline.native[0][1].mediation, "conditional");
  assert.equal(offline.panelText(), "");
});

// MARK: C. Pas de repli silencieux

test("une passkey laissée au navigateur faute de Verrou : un avis le dit", async () => {
  const challenge = new Uint8Array(32);
  const creation = (alg = -7) => ({ publicKey: {
    rp: { name: "Site" }, user: { id: new Uint8Array([1]), name: "dominique", displayName: "Dominique" },
    challenge, pubKeyCredParams: [{ type: "public-key", alg }],
  } });
  const cases = [
    ["injoignable", async () => ({ state: "offline" }), "Verrou n'est pas joignable", "Ouvrez Verrou"],
    ["non reliée", backgroundFor(new Channel(hostTransport)), "n'est pas reliée à Verrou", "Reliez l'extension"],
  ];
  for (const [what, background, title, hint] of cases) {
    const page = openPage("http://localhost:8000", background);
    assert.equal(await page.credentials.get({ publicKey: { challenge } }), "natif", what);
    assert.match(page.panelText(), new RegExp(title));
    assert.match(page.panelText(), new RegExp(hint));
    assert.match(page.panelText(), /laissée au navigateur/);
    assert.equal(await page.credentials.create(creation()), "natif", what);
    assert.match(page.panelText(), new RegExp(title));
    // L'avis se ferme d'un clic, sans rien bloquer.
    page.press("OK");
    await sleep(10);
    assert.equal(page.panelText(), "");
  }

  // Extension rechargée (mise à jour) pendant que la page était ouverte.
  const stale = openPage("http://localhost:8000", async () => { throw new Error("Extension context invalidated."); });
  delete stale.runtime.id;
  assert.equal(await stale.credentials.get({ publicKey: { challenge } }), "natif");
  assert.match(stale.panelText(), /vient d'être mis à jour/);
  assert.match(stale.panelText(), /Rechargez la page/);

  // Type de clé que Verrou ne sait pas créer.
  const channel = await pairedChannel();
  const eddsa = openPage("http://localhost:8000", backgroundFor(channel));
  assert.equal(await eddsa.credentials.create(creation(-8)), "natif");
  assert.match(eddsa.panelText(), /Verrou ne gère pas ce type de clé/);
});

test("pas d'avis pour un choix de l'utilisateur, ni quand Verrou n'a rien pour le site", async () => {
  const channel = await pairedChannel();
  const challenge = new Uint8Array(32);
  // Rien pour ce site : le navigateur, sans détour ni avis.
  const empty = openPage("https://exemple.org", backgroundFor(channel));
  assert.equal(await empty.credentials.get({ publicKey: { challenge } }), "natif");
  assert.equal(empty.panelText(), "");

  // « Utiliser le navigateur » : choisi, donc pas d'avis.
  const page = openPage("http://localhost:8000", backgroundFor(channel));
  const created = page.credentials.create({ publicKey: {
    rp: { name: "Site" }, user: { id: new Uint8Array([2]), name: "alex", displayName: "Alex" },
    challenge, pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  } });
  await eventually(() => page.panelText().includes("Enregistrer une passkey dans Verrou"), "fenêtre d'enregistrement");
  page.press("Utiliser le navigateur");
  assert.equal(await created, "natif");
  await sleep(50);
  assert.equal(page.panelText(), "");
});
