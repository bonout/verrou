// The extension's protocol against the real bridge, through the real Native
// Messaging host: same code as in Brave (bridge.js, crypto.js), only the
// transport changes (a process instead of chrome.runtime.connectNative).
//
//   cargo build -p verrou-bridge --example test_server --bin verrou-native-host
//   node --test extension/test/bridge.test.mjs

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import vm from "node:vm";

import { BridgeError, Channel } from "../bridge.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const server = spawn(`${root}target/debug/examples/test_server`, {
  env: { ...process.env, VERROU_BRIDGE_PORT: "0" },
  stdio: ["ignore", "pipe", "inherit"],
});
const lines = createInterface({ input: server.stdout });
const codes = [];
let port;

before(async () => {
  for await (const line of lines) {
    if (line.startsWith("PORT ")) {
      port = line.slice(5);
      break;
    }
  }
  lines.on("line", (line) => line.startsWith("CODE ") && codes.push(line.slice(5)));
});

after(() => server.kill());

// Native Messaging transport over the host: "length (u32 LE) + JSON" frames.
function hostTransport() {
  const host = spawn(`${root}target/debug/verrou-native-host`, {
    env: { ...process.env, VERROU_BRIDGE_PORT: port },
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

test("pairing, suggestions and filling from the extension", async () => {
  const channel = new Channel(hostTransport);
  await assert.rejects(channel.request({ cmd: "status" }), (e) => e.code === "unpaired");

  let shown;
  const client = await channel.pair("Brave", (code) => { shown = code; });
  assert.match(shown, /^\d{3} \d{3}$/);
  // Verrou showed the same code.
  assert.ok(codes.includes(shown), `code ${shown} missing from ${codes}`);
  channel.setClient(client);

  const status = await channel.request({ cmd: "status" });
  assert.equal(status.result, "status");
  assert.equal(status.unlocked, true);

  const suggestions = await channel.request({ cmd: "suggest", url: "https://github.com/login" });
  assert.deepEqual(suggestions.items.map((i) => i.id), ["github"]);

  const fill = await channel.request({ cmd: "fill", url: "https://github.com/login", item: "github" });
  assert.equal(fill.result, "credentials");
  assert.equal(fill.password, "hunter2-hunter2");
  assert.match(fill.totp, /^\d{6}$/);

  const denied = await channel.request({ cmd: "fill", url: "https://evil.example/", item: "github" });
  assert.equal(denied.result, "denied");

  // Site matching rule ("starts with"): the extension sends the page's full
  // address, the bridge decides.
  const sso = await channel.request({ cmd: "suggest", url: "https://banque.exemple.fr/connexion/etape-2" });
  assert.deepEqual(sso.items.map((i) => i.id), ["banque-sso"]);
  const elsewhere = await channel.request({ cmd: "suggest", url: "https://banque.exemple.fr/aide" });
  assert.deepEqual(elsewhere.items, []);
  const refused = await channel.request({ cmd: "fill", url: "https://banque.exemple.fr/aide", item: "banque-sso" });
  assert.equal(refused.result, "denied");

  // After a form is submitted: new account, then saved.
  const page = "http://localhost:8000/inscription";
  const fresh = await channel.request({ cmd: "check", url: page, username: "dominique", password: "Nouveau-42!" });
  assert.equal(fresh.action, "new");
  const saved = await channel.request({ cmd: "save", url: page, username: "dominique", password: "Nouveau-42!" });
  assert.equal(saved.result, "saved");
  const known = await channel.request({ cmd: "check", url: page, username: "dominique", password: "Nouveau-42!" });
  assert.equal(known.action, "known");
  assert.equal(known.item.id, saved.item);

  // Two-factor QR code added to the site's login.
  const totp = await channel.request({ cmd: "set_totp", url: page, item: saved.item,
    totp: "otpauth://totp/Local:dominique?secret=JBSWY3DPEHPK3PXP&issuer=Local" });
  assert.equal(totp.result, "saved");
  const withCode = await channel.request({ cmd: "fill", url: page, item: saved.item });
  assert.match(withCode.totp, /^\d{6}$/);

  // A new connection (the service worker goes back to sleep) keeps the pairing.
  channel.disconnect();
  const again = await channel.request({ cmd: "suggest", url: "http://localhost:8000/connexion" });
  assert.ok(again.items.some((i) => i.id === "local"));
  channel.disconnect();
});

test("a made-up key gets nothing", async () => {
  const channel = new Channel(hostTransport);
  const key = await crypto.subtle.importKey(
    "raw", new Uint8Array(32), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  channel.setClient({ id: "00000000-0000-0000-0000-000000000000", key });
  await assert.rejects(channel.request({ cmd: "status" }),
    (e) => e instanceof BridgeError && e.code === "unknown_client");
  channel.disconnect();
});

test("Verrou unreachable: the extension knows it", async () => {
  // Closed port: the host tries to open the app, gives up, and says so.
  const closed = new Channel(() => {
    const host = spawn(`${root}target/debug/verrou-native-host`, {
      env: { ...process.env, VERROU_BRIDGE_PORT: "1", VERROU_BRIDGE_NO_LAUNCH: "1" },
      stdio: ["pipe", "pipe", "inherit"],
    });
    let onMessage = () => {};
    let onDisconnect = () => {};
    // The host may already have exited when the request is sent: writing
    // fails (EPIPE), as for a browser whose host stopped.
    host.stdin.on("error", () => {});
    host.stdout.on("data", (chunk) => onMessage(JSON.parse(chunk.subarray(4).toString())));
    host.on("exit", () => onDisconnect("host stopped"));
    // The host can stop before our write (closed port): EPIPE expected.
    host.stdin.on("error", () => {});
    return {
      post: (message) => host.stdin.write(JSON.stringify(message)),
      onMessage: (callback) => { onMessage = callback; },
      onDisconnect: (callback) => { onDisconnect = callback; },
    };
  });
  const key = await crypto.subtle.importKey(
    "raw", new Uint8Array(32), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  closed.setClient({ id: "x", key });
  await assert.rejects(closed.request({ cmd: "status" }), (e) => e.code === "offline");
});

test("the extension's ID is the one the app declares to the browser", async () => {
  const manifest = JSON.parse(readFileSync(`${root}extension/manifest.json`, "utf8"));
  const key = Uint8Array.from(atob(manifest.key), (c) => c.charCodeAt(0));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", key));
  const id = [...digest.slice(0, 16)]
    .flatMap((byte) => [byte >> 4, byte & 15])
    .map((nibble) => String.fromCharCode(97 + nibble))
    .join("");
  const swift = readFileSync(`${root}apple/Verrou/App/BrowserBridge.swift`, "utf8");
  assert.ok(swift.includes(`extensionID = "${id}"`), `BrowserBridge.swift must declare ${id}`);
  const e2e = readFileSync(`${root}extension/e2e/brave.mjs`, "utf8");
  assert.ok(e2e.includes(`EXTENSION_ID = "${id}"`));
});

test("the generator follows Verrou's rules", () => {
  const context = { crypto };
  vm.runInNewContext(readFileSync(`${root}extension/generator.js`, "utf8"), context);
  const { password, CLASSES } = context.verrouGenerator;
  const seen = new Set();
  for (let i = 0; i < 200; i += 1) {
    const value = password();
    assert.equal(value.length, 20);
    for (const set of CLASSES) assert.ok([...value].some((c) => set.includes(c)), `${value} without ${set}`);
    assert.doesNotMatch(value, /[lIO01]/);
    seen.add(value);
  }
  assert.equal(seen.size, 200);
});
