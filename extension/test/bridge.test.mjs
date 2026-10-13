// Le protocole de l'extension contre le vrai pont, à travers le vrai hôte
// Native Messaging : même code que dans Brave (bridge.js, crypto.js), seul
// le transport change (un processus au lieu de chrome.runtime.connectNative).
//
//   cargo build -p verrou-bridge --example test_server --bin verrou-native-host
//   node --test extension/test/bridge.test.mjs

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";

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

// Transport Native Messaging sur l'hôte : trames « longueur (u32 LE) + JSON ».
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

test("appairage, suggestions et remplissage depuis l'extension", async () => {
  const channel = new Channel(hostTransport);
  await assert.rejects(channel.request({ cmd: "status" }), (e) => e.code === "unpaired");

  let shown;
  const client = await channel.pair("Brave", (code) => { shown = code; });
  assert.match(shown, /^\d{3} \d{3}$/);
  // Verrou a affiché le même code.
  assert.ok(codes.includes(shown), `code ${shown} absent de ${codes}`);
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

  // Une nouvelle connexion (le service worker se rendort) garde l'appairage.
  channel.disconnect();
  const again = await channel.request({ cmd: "suggest", url: "http://localhost:8000/connexion" });
  assert.deepEqual(again.items.map((i) => i.id), ["local"]);
  channel.disconnect();
});

test("une clé inventée n'obtient rien", async () => {
  const channel = new Channel(hostTransport);
  const key = await crypto.subtle.importKey(
    "raw", new Uint8Array(32), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  channel.setClient({ id: "00000000-0000-0000-0000-000000000000", key });
  await assert.rejects(channel.request({ cmd: "status" }),
    (e) => e instanceof BridgeError && e.code === "unknown_client");
  channel.disconnect();
});

test("Verrou injoignable : l'extension le sait", async () => {
  // Port fermé : l'hôte tente d'ouvrir l'app, abandonne, et le dit.
  const closed = new Channel(() => {
    const host = spawn(`${root}target/debug/verrou-native-host`, {
      env: { ...process.env, VERROU_BRIDGE_PORT: "1", VERROU_BRIDGE_NO_LAUNCH: "1" },
      stdio: ["pipe", "pipe", "inherit"],
    });
    let onMessage = () => {};
    let onDisconnect = () => {};
    host.stdout.on("data", (chunk) => onMessage(JSON.parse(chunk.subarray(4).toString())));
    host.on("exit", () => onDisconnect("hôte arrêté"));
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

test("l'identifiant de l'extension est celui que l'app déclare au navigateur", async () => {
  const manifest = JSON.parse(readFileSync(`${root}extension/manifest.json`, "utf8"));
  const key = Uint8Array.from(atob(manifest.key), (c) => c.charCodeAt(0));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", key));
  const id = [...digest.slice(0, 16)]
    .flatMap((byte) => [byte >> 4, byte & 15])
    .map((nibble) => String.fromCharCode(97 + nibble))
    .join("");
  const swift = readFileSync(`${root}apple/Verrou/App/BrowserBridge.swift`, "utf8");
  assert.ok(swift.includes(`extensionID = "${id}"`), `BrowserBridge.swift doit déclarer ${id}`);
  const e2e = readFileSync(`${root}extension/e2e/brave.mjs`, "utf8");
  assert.ok(e2e.includes(`EXTENSION_ID = "${id}"`));
});
