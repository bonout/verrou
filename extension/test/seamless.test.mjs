// An extension that goes unnoticed: it reloads when Verrou is updated
// (update.js, version announced by the real bridge), offers its passkeys in
// autofill (`mediation: "conditional"`), and says when a passkey goes to the
// browser for lack of Verrou.
//
// passkey-page.js (page world) and passkeys.js (isolated world) run here in
// two contexts, linked by a fake `postMessage`; the service worker is
// replaced by passkey-bridge.js and the real bridge, through the real Native
// Messaging host. The signatures are checked with WebCrypto.
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
import { i18n } from "./fake-dom.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const source = (name) => readFileSync(`${root}extension/${name}`, "utf8");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function eventually(probe, what, timeout = 5000) {
  const end = Date.now() + timeout;
  for (;;) {
    const value = await probe();
    if (value) return value;
    if (Date.now() > end) throw new Error(`timed out: ${what}`);
    await sleep(20);
  }
}

// MARK: Fake Verrou (the real bridge, on a fake vault)

const scratch = mkdtempSync(join(tmpdir(), "verrou-seamless-"));
// The manifest.json "shipped with the app": the bridge announces its version.
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
  host.on("exit", () => onDisconnect("host stopped"));
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

// MARK: A. Reload after an app update

function memoryStore() {
  let value;
  return { get: async () => value, set: async (v) => { value = v; }, peek: () => value };
}

test("the version announced by Verrou, then a single reload per version", async () => {
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

  // Same version everywhere: nothing.
  assert.equal(await status(), "0.3.0");
  assert.equal((await updater.check({ bridgeVersion: await status() })).reloading, false);
  assert.equal(updater.state().mismatch, false);

  // The app is updated: the disk and Verrou announce the new version.
  writeBundled("0.3.0.4242");
  disk = "0.3.0.4242";
  assert.equal(await status(), "0.3.0.4242");
  assert.equal((await updater.check({ bridgeVersion: await status() })).reloading, true);
  assert.equal(reloads, 1);
  assert.deepEqual(store.peek(), { version: "0.3.0.4242", from: "0.3.0", at: clock });
  assert.equal(updater.state().mismatch, true);

  // The reload changed nothing (the same old code still runs): no second
  // attempt for this version, even much later.
  clock += 3_600_000;
  for (let i = 0; i < 3; i += 1) assert.equal((await updater.check({ bridgeVersion: await status() })).reloading, false);
  assert.equal(reloads, 1);

  // The service worker restarts in the new version: nothing more to do.
  const next = createUpdater({ running: "0.3.0.4242", readDisk: async () => disk, reload: () => { reloads += 1; }, store, now: () => clock });
  assert.equal((await next.check({ bridgeVersion: await status() })).reloading, false);
  assert.equal(next.state().mismatch, false);

  // New update, one second after the previous attempt: we wait.
  writeBundled("0.3.0.777");
  disk = "0.3.0.777";
  await store.set({ version: "0.3.0.4242", at: clock - 1000 });
  assert.equal((await next.check()).reloading, false);
  clock += 120_000;
  assert.equal((await next.check()).reloading, true);
  assert.equal(reloads, 2);
});

test("unreadable disk: Verrou's version decides; loaded from elsewhere: warn without looping", async () => {
  const store = memoryStore();
  let reloads = 0;
  const unreadable = createUpdater({
    running: "0.3.0", readDisk: async () => { throw new Error("unreadable"); }, reload: () => { reloads += 1; }, store,
  });
  assert.equal((await unreadable.check()).reloading, false, "nothing announced: nothing to do");
  assert.equal((await unreadable.check({ bridgeVersion: "0.3.0.9" })).reloading, true);
  assert.equal((await unreadable.check({ bridgeVersion: "0.3.0.9" })).reloading, false);
  assert.equal(reloads, 1);

  // Extension loaded from the repository: the disk has the same version as
  // what runs, Verrou ships another one. A single attempt, then the warning.
  const dev = createUpdater({ running: "0.3.0", readDisk: async () => "0.3.0", reload: () => { reloads += 1; }, store: memoryStore() });
  assert.equal((await dev.check({ bridgeVersion: "0.3.0.9" })).reloading, true);
  for (let i = 0; i < 3; i += 1) assert.equal((await dev.check({ bridgeVersion: "0.3.0.9" })).reloading, false);
  assert.deepEqual(dev.state(), { running: "0.3.0", bundled: "0.3.0.9", mismatch: true });
  assert.equal(reloads, 2);

  // Pairing in progress: later; storage broken: never (risk of a loop).
  let busy = true;
  const later = createUpdater({ running: "0.3.0", readDisk: async () => "0.3.1", reload: () => { reloads += 1; }, store: memoryStore(), busy: () => busy });
  assert.equal((await later.check()).deferred, true);
  busy = false;
  assert.equal((await later.check()).reloading, true);
  assert.equal(reloads, 3);
  const broken = createUpdater({
    running: "0.3.0", readDisk: async () => "0.3.1", reload: () => { reloads += 1; },
    store: { get: async () => undefined, set: async () => { throw new Error("full"); } },
  });
  assert.equal((await broken.check()).reloading, false);
  assert.equal(reloads, 3);
});

test("the shipped version depends on the extension's content, and stays valid", () => {
  const copy = join(scratch, "extension");
  cpSync(`${root}extension`, copy, { recursive: true });
  const stamp = () => {
    execFileSync(`${root}scripts/stamp-extension.sh`, [copy], { stdio: "ignore" });
    return JSON.parse(readFileSync(join(copy, "manifest.json"), "utf8")).version;
  };
  const committed = JSON.parse(source("manifest.json")).version;
  assert.match(committed, /^\d+\.\d+\.\d+$/, "the repository's version stays a.b.c");
  const first = stamp();
  assert.match(first, new RegExp(`^${committed.replaceAll(".", "\\.")}\\.\\d{1,5}$`));
  assert.ok(Number(first.split(".")[3]) <= 65535);
  assert.equal(stamp(), first, "running again changes nothing");
  // Tests don't count; a shipped file does.
  appendFileSync(join(copy, "test", "bridge.test.mjs"), "\n");
  assert.equal(stamp(), first);
  appendFileSync(join(copy, "content.js"), "\n// change\n");
  const second = stamp();
  assert.notEqual(second, first);
  // The rest of the manifest is intact.
  const before = JSON.parse(source("manifest.json"));
  const stamped = JSON.parse(readFileSync(join(copy, "manifest.json"), "utf8"));
  assert.deepEqual({ ...stamped, version: before.version }, before);
});

// MARK: Fake browser: the page and the content script

// A minimal DOM, for the window of passkeys.js (shadow DOM included).
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

// A page at `origin`, with its two worlds. `background(message)` answers the
// requests of passkeys.js, like the service worker. `firefox`: the isolated
// world has `browser` (promises); `chrome` is trapped there to prove it
// isn't used.
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
    // The `window` the scripts see: the context's global object (vm
    // substitutes it for `context` seen from the inside).
    context.self = vm.runInContext("globalThis", context);
    contexts.push(context);
    return context;
  };

  // Page world.
  class PublicKeyCredential {}
  const credentials = {
    create: async (options) => { native.push(["create", options]); return "native"; },
    get: async (options) => { native.push(["get", options]); return "native"; },
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

  // The extension's isolated world.
  const runtime = {
    id: "extension",
    sendMessage: async (message) => background(message, `${url.origin}/connexion`),
  };
  const unused = { id: "extension", sendMessage: async () => { throw new Error("chrome.runtime used in Firefox"); } };
  const isolated = makeContext(firefox
    ? { browser: { runtime, i18n }, chrome: { runtime: unused }, document }
    : { chrome: { runtime, i18n }, document });
  vm.runInContext(source("passkeys.js"), isolated);

  const panelText = () => {
    const host = document.documentElement.children.find((n) => n.tagName === "VERROU-PASSKEY");
    return host?.shadow?.querySelector("panel")?.textContent ?? "";
  };
  // A real click (isTrusted) on the window's button whose text is `label`.
  const press = (label) => {
    const host = document.documentElement.children.find((n) => n.tagName === "VERROU-PASSKEY");
    const node = [...(host?.shadow?.walk() ?? [])].find((n) => n.tagName === "BUTTON" && n.textContent === label);
    assert.ok(node, `button "${label}"`);
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

// The service worker: passkey-bridge.js and a channel to the real bridge.
function backgroundFor(channel) {
  return async (message, url) => {
    if (message.kind === "unlock") return { ok: true };
    const command = passkeyCommand(message, url);
    if (!command) return { error: "unknown command" };
    try {
      return passkeyResult(await channel.request(command));
    } catch (error) {
      return { state: error.code === "unpaired" || error.code === "unknown_client" ? "unpaired" : "offline" };
    }
  };
}

// DER ECDSA signature → r ‖ s (64 bytes), the form WebCrypto expects.
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

// MARK: B. Passkeys in the pill (autofill)

test("autofill: Verrou's passkey in the pill, a valid signature", async () => {
  const channel = await pairedChannel();
  const origin = "http://localhost:8000";
  // A passkey in the test site's login.
  const created = await channel.request({
    cmd: "passkey_create", url: `${origin}/inscription`, rp_id: "localhost", user_id: b64url(Buffer.from("id-camille")),
    user_name: "camille@exemple.fr", challenge: b64url(crypto.getRandomValues(new Uint8Array(32))),
    algorithms: [-7], exclude: [], uv: false, attestation: "none", item: "local",
  });
  assert.equal(created.result, "registration", JSON.stringify(created));

  const page = openPage(origin, backgroundFor(channel));
  const notified = [];
  page.menu().subscribe(() => notified.push(Date.now()));
  assert.deepEqual({ ...(await page.menu().entries()) }, { state: "none" }, "nothing pending");

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  let settled = null;
  const pending = page.credentials.get({ mediation: "conditional", publicKey: { challenge, rpId: "localhost", userVerification: "discouraged" } })
    .then((c) => { settled = { ok: true, c }; }, (e) => { settled = { ok: false, e }; });
  // The request stays pending; the pill is notified, and offers the passkey.
  await eventually(() => notified.length > 0, "pill notified");
  const entries = await page.menu().entries();
  assert.equal(entries.state, "ready");
  assert.deepEqual(entries.items.map((i) => [i.item, i.credential, i.user_name]), [["local", created.credential, "camille@exemple.fr"]]);
  await sleep(100);
  assert.equal(settled, null, "waiting for a choice");
  assert.deepEqual(page.native, [], "nothing for the browser");

  // An unknown passkey can't be chosen.
  assert.equal(page.menu().choose("unknown"), false);
  // Chosen in the pill: the same signature as an explicit sign-in.
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
  assert.equal(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, data), true, "valid ES256 signature");
  assert.equal(Buffer.from(credential.response.authenticatorData).readUInt32BE(33), 1, "counter saved");
  assert.equal(Buffer.from(credential.response.userHandle).toString(), "id-camille");
  // Done: nothing more in the pill.
  assert.equal((await page.menu().entries()).state, "none");
  assert.equal(page.menu().choose(created.credential), false);

  // The page cancels (AbortSignal): the promise is rejected, the pill emptied.
  const controller = new AbortController();
  const aborted = page.credentials.get({ mediation: "conditional", signal: controller.signal, publicKey: { challenge, rpId: "localhost" } })
    .then(() => "resolved", (e) => e.name);
  await eventually(async () => (await page.menu().entries()).state === "ready", "passkey offered");
  const before = notified.length;
  controller.abort();
  assert.equal(await aborted, "AbortError");
  await eventually(() => notified.length > before, "pill notified of the cancellation");
  assert.equal((await page.menu().entries()).state, "none");
  assert.equal(page.menu().choose(created.credential), false);

  // An explicit request replaces the autofill one.
  const replaced = page.credentials.get({ mediation: "conditional", publicKey: { challenge, rpId: "localhost" } })
    .then(() => "resolved", (e) => e.name);
  await eventually(async () => (await page.menu().entries()).state === "ready", "passkey offered");
  const modal = page.credentials.get({ publicKey: { challenge, rpId: "localhost", userVerification: "discouraged" } });
  assert.equal(await replaced, "NotAllowedError");
  await eventually(() => page.panelText().includes("Sign in with a Verrou passkey"), "sign-in window");
  assert.equal((await page.menu().entries()).state, "none");
  page.press("Cancel");
  await assert.rejects(modal, { name: "NotAllowedError" });
  assert.deepEqual(page.native, []);
});

test("Firefox: the same passkeys in the pill, through the `browser` API", async () => {
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
  await eventually(async () => (await page.menu().entries()).state === "ready", "passkey offered");
  const entries = await page.menu().entries();
  assert.ok(entries.items.some((i) => i.credential === created.credential), JSON.stringify(entries));
  assert.equal(page.menu().choose(created.credential), true);
  const credential = await pending;
  assert.equal(credential.id, created.credential);
  const clientData = JSON.parse(Buffer.from(credential.response.clientDataJSON).toString());
  assert.deepEqual(clientData, { type: "webauthn.get", challenge: b64url(challenge), origin, crossOrigin: false });
  assert.deepEqual(page.native, [], "nothing for the browser");
});

test("autofill without a Verrou passkey, or without Verrou: the browser", async () => {
  const channel = await pairedChannel();
  // No passkey for this site in Verrou.
  const page = openPage("https://exemple.org", backgroundFor(channel));
  const challenge = new Uint8Array(32);
  const result = await page.credentials.get({ mediation: "conditional", publicKey: { challenge } });
  assert.equal(result, "native");
  assert.equal(page.native.length, 1);
  assert.equal(page.native[0][1].mediation, "conditional", "the browser's autofill, with the same options");
  assert.equal(page.panelText(), "", "no notice: the user asked for nothing");

  // Verrou unreachable: likewise.
  const offline = openPage("http://localhost:8000", async () => ({ state: "offline" }));
  assert.equal(await offline.credentials.get({ mediation: "conditional", publicKey: { challenge } }), "native");
  assert.equal(offline.native[0][1].mediation, "conditional");
  assert.equal(offline.panelText(), "");
});

// MARK: C. No silent fallback

test("a passkey left to the browser for lack of Verrou: a notice says so", async () => {
  const challenge = new Uint8Array(32);
  const creation = (alg = -7) => ({ publicKey: {
    rp: { name: "Site" }, user: { id: new Uint8Array([1]), name: "dominique", displayName: "Dominique" },
    challenge, pubKeyCredParams: [{ type: "public-key", alg }],
  } });
  const cases = [
    ["unreachable", async () => ({ state: "offline" }), "Verrou can't be reached", "Open Verrou"],
    ["not linked", backgroundFor(new Channel(hostTransport)), "is not linked to Verrou", "Link the extension"],
  ];
  for (const [what, background, title, hint] of cases) {
    const page = openPage("http://localhost:8000", background);
    assert.equal(await page.credentials.get({ publicKey: { challenge } }), "native", what);
    assert.match(page.panelText(), new RegExp(title));
    assert.match(page.panelText(), new RegExp(hint));
    assert.match(page.panelText(), /left to the browser/);
    assert.equal(await page.credentials.create(creation()), "native", what);
    assert.match(page.panelText(), new RegExp(title));
    // The notice closes with a click, without blocking anything.
    page.press("OK");
    await sleep(10);
    assert.equal(page.panelText(), "");
  }

  // Extension reloaded (update) while the page was open.
  const stale = openPage("http://localhost:8000", async () => { throw new Error("Extension context invalidated."); });
  delete stale.runtime.id;
  assert.equal(await stale.credentials.get({ publicKey: { challenge } }), "native");
  assert.match(stale.panelText(), /was just updated/);
  assert.match(stale.panelText(), /Reload the page/);

  // Key type Verrou can't create.
  const channel = await pairedChannel();
  const eddsa = openPage("http://localhost:8000", backgroundFor(channel));
  assert.equal(await eddsa.credentials.create(creation(-8)), "native");
  assert.match(eddsa.panelText(), /Verrou doesn't support this key type/);
});

test("no notice for a choice of the user, nor when Verrou has nothing for the site", async () => {
  const channel = await pairedChannel();
  const challenge = new Uint8Array(32);
  // Nothing for this site: the browser, straight away and without a notice.
  const empty = openPage("https://exemple.org", backgroundFor(channel));
  assert.equal(await empty.credentials.get({ publicKey: { challenge } }), "native");
  assert.equal(empty.panelText(), "");

  // "Use the browser": chosen, so no notice.
  const page = openPage("http://localhost:8000", backgroundFor(channel));
  const created = page.credentials.create({ publicKey: {
    rp: { name: "Site" }, user: { id: new Uint8Array([2]), name: "alex", displayName: "Alex" },
    challenge, pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  } });
  await eventually(() => page.panelText().includes("Save a passkey in Verrou"), "save window");
  page.press("Use the browser");
  assert.equal(await created, "native");
  await sleep(50);
  assert.equal(page.panelText(), "");
});
