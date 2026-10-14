// L'extension pour Firefox : produite à partir de extension/ par
// scripts/firefox-extension.sh (même code, autre manifeste), puis
// versionnée avec celle de Brave par scripts/stamp-extension.sh. Sans
// navigateur : on vérifie le manifeste, les fichiers, la concordance des
// identifiants (app, hôte Native Messaging, extension) et le
// rechargement propre à Firefox (update.js).
//
//   node --test extension/test/firefox.test.mjs
//
// VERROU_LINT_FIREFOX=1 lance aussi `web-ext lint` (l'outil de Mozilla, par npx :
// téléchargé au premier passage) sur le dossier produit.

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { after, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

import { createUpdater } from "../update.js";

const root = fileURLToPath(new URL("../../", import.meta.url));
const scratch = mkdtempSync(join(tmpdir(), "verrou-firefox-"));
after(() => rmSync(scratch, { recursive: true, force: true }));

const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const chromeManifest = readJson(`${root}extension/manifest.json`);

function build(source = `${root}extension`, target = join(scratch, "extension-firefox")) {
  execFileSync(`${root}scripts/firefox-extension.sh`, [source, target], { stdio: "ignore" });
  return target;
}

function files(dir) {
  const out = [];
  const walk = (current) => {
    for (const name of readdirSync(current)) {
      const path = join(current, name);
      if (statSync(path).isDirectory()) walk(path);
      else out.push(relative(dir, path));
    }
  };
  walk(dir);
  return out.sort();
}

test("le manifeste de Firefox : page d'arrière-plan, identifiant, accès aux sites", () => {
  const dir = build();
  const manifest = readJson(join(dir, "manifest.json"));

  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.version, chromeManifest.version);
  assert.equal(manifest.name, chromeManifest.name);
  // Propre à Chrome : absent.
  assert.equal(manifest.key, undefined);
  assert.equal(manifest.minimum_chrome_version, undefined);
  // Firefox n'a pas de service worker d'extension : une page d'arrière-plan,
  // le même module.
  assert.deepEqual(manifest.background, { scripts: ["background.js"], type: "module" });

  const gecko = manifest.browser_specific_settings?.gecko;
  assert.equal(gecko?.id, "verrou@verrou.app");
  // `world: "MAIN"` des scripts de contenu (passkeys) : Firefox 128.
  assert.equal(gecko?.strict_min_version, "128.0");
  assert.deepEqual(gecko?.data_collection_permissions, { required: ["none"] });

  for (const permission of ["nativeMessaging", "storage", "activeTab", "alarms"]) {
    assert.ok(manifest.permissions.includes(permission), permission);
  }
  // Chaque site des scripts de contenu est un accès demandable.
  const matches = new Set(manifest.content_scripts.flatMap((script) => script.matches));
  assert.deepEqual(new Set(manifest.host_permissions), matches);
  assert.ok(manifest.host_permissions.includes("https://*/*"));

  // Les scripts de contenu sont ceux de Brave, monde MAIN compris.
  assert.deepEqual(manifest.content_scripts, chromeManifest.content_scripts);
  assert.ok(manifest.content_scripts.some((script) => script.world === "MAIN"
    && script.run_at === "document_start" && script.js.includes("passkey-page.js")));
  assert.deepEqual(manifest.action, chromeManifest.action);
  assert.deepEqual(manifest.icons, chromeManifest.icons);
});

test("même code que pour Brave : fichiers identiques, rien de manquant", () => {
  const dir = build();
  const shipped = files(`${root}extension`).filter((f) => !/^(test|e2e)\//.test(f) && f !== "manifest.json" && !f.endsWith(".DS_Store"));
  const built = files(dir).filter((f) => f !== "manifest.json");
  assert.deepEqual(built, shipped);
  for (const file of built) {
    assert.ok(readFileSync(join(dir, file)).equals(readFileSync(`${root}extension/${file}`)), file);
  }
  // Tout ce que le manifeste cite existe.
  const manifest = readJson(join(dir, "manifest.json"));
  const cited = [
    ...manifest.background.scripts,
    manifest.action.default_popup,
    ...Object.values(manifest.icons),
    ...Object.values(manifest.action.default_icon),
    ...manifest.content_scripts.flatMap((script) => script.js),
  ];
  for (const file of cited) assert.ok(existsSync(join(dir, file)), file);
  // Relancer remplace le dossier : pas de reste d'un ancien passage.
  appendFileSync(join(dir, "reste.txt"), "ancien");
  build();
  assert.ok(!existsSync(join(dir, "reste.txt")));
});

test("Brave et Firefox reçoivent la même version, tirée des deux dossiers", () => {
  const brave = join(scratch, "stamp", "extension");
  execFileSync("mkdir", ["-p", join(scratch, "stamp")]);
  execFileSync("cp", ["-R", `${root}extension`, brave]);
  const firefox = build(brave, `${brave}-firefox`);
  const stamp = () => {
    execFileSync(`${root}scripts/stamp-extension.sh`, [brave, firefox], { stdio: "ignore" });
    const a = readJson(join(brave, "manifest.json")).version;
    const b = readJson(join(firefox, "manifest.json")).version;
    assert.equal(a, b, "une seule version, annoncée par le pont pour les deux");
    return a;
  };
  const first = stamp();
  assert.match(first, /^\d+\.\d+\.\d+\.\d{1,5}$/);
  assert.equal(stamp(), first, "relancer ne change rien");
  // Reproduire Firefox depuis la copie déjà versionnée (compilation
  // incrémentale) ne change rien non plus.
  build(brave, firefox);
  assert.equal(stamp(), first);
  // Un changement propre au dossier de Firefox change la version.
  appendFileSync(join(firefox, "popup.css"), "\n/* changement */\n");
  assert.notEqual(stamp(), first);
});

test("les identifiants de l'extension concordent : app, hôte Native Messaging, manifestes", () => {
  const swift = readFileSync(`${root}apple/Verrou/App/BrowserBridge.swift`, "utf8");
  const rust = readFileSync(`${root}crates/verrou-bridge/src/lib.rs`, "utf8");
  const script = readFileSync(`${root}scripts/firefox-extension.sh`, "utf8");
  const firefoxId = readJson(join(build(), "manifest.json")).browser_specific_settings.gecko.id;
  assert.match(swift, new RegExp(`static let firefoxExtensionID = "${firefoxId}"`));
  assert.match(rust, new RegExp(`FIREFOX_EXTENSION_ID: &str = "${firefoxId}"`));
  assert.match(script, new RegExp(`FIREFOX_ID="${firefoxId}"`));

  // Chrome : identifiant = SHA-256 de la clé publique, 32 premiers chiffres
  // hexadécimaux écrits de « a » à « p ».
  const digest = createHash("sha256").update(Buffer.from(chromeManifest.key, "base64")).digest("hex");
  const chromeId = [...digest.slice(0, 32)].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
  assert.match(swift, new RegExp(`static let extensionID = "${chromeId}"`));
  assert.match(rust, new RegExp(`CHROMIUM_EXTENSION_ID: &str = "${chromeId}"`));

  // Le sandbox de l'app peut écrire la déclaration de Firefox.
  const entitlements = readFileSync(`${root}apple/Verrou/Verrou.entitlements`, "utf8");
  assert.match(entitlements, /Library\/Application Support\/Mozilla\/NativeMessagingHosts\//);
  assert.match(swift, /"allowed_extensions": \[Self\.firefoxExtensionID\]/);
});

test("Firefox : rechargement pour un manifeste changé sur le disque seulement", async () => {
  const memory = () => {
    let value;
    return { get: async () => value, set: async (v) => { value = v; } };
  };
  let reloads = 0;
  // Module signé, ou extension temporaire à jour : Verrou en livre une autre.
  // Pas de rechargement (il ne changerait rien), l'avertissement à la place.
  const installed = createUpdater({
    running: "0.3.0.1", readDisk: async () => "0.3.0.1", reload: () => { reloads += 1; },
    store: memory(), reloadForBundled: false,
  });
  for (let i = 0; i < 3; i += 1) {
    assert.equal((await installed.check({ bridgeVersion: "0.3.0.2" })).reloading, false);
  }
  assert.deepEqual(installed.state(), { running: "0.3.0.1", bundled: "0.3.0.2", mismatch: true });
  assert.equal(reloads, 0);

  // Extension temporaire chargée depuis Verrou.app, mis à jour : le
  // manifeste sur le disque a changé, elle se recharge (une fois).
  const temporary = createUpdater({
    running: "0.3.0.1", readDisk: async () => "0.3.0.2", reload: () => { reloads += 1; },
    store: memory(), reloadForBundled: false,
  });
  assert.equal((await temporary.check({ bridgeVersion: "0.3.0.2" })).reloading, true);
  assert.equal((await temporary.check({ bridgeVersion: "0.3.0.2" })).reloading, false);
  assert.equal(reloads, 1);
});

test("web-ext lint (VERROU_LINT_FIREFOX=1)", { skip: process.env.VERROU_LINT_FIREFOX !== "1" }, () => {
  const dir = build();
  // Sans NODE_TEST_CONTEXT : web-ext (Node lui aussi) se croirait un test.
  // (Le réglage ne s'appelle pas WEB_EXT_… : web-ext en ferait une option.)
  const { NODE_TEST_CONTEXT, ...env } = process.env;
  const output = execFileSync("npx", ["--yes", "web-ext@8", "lint", "--source-dir", dir, "--output", "json"],
    { encoding: "utf8", env, stdio: ["ignore", "pipe", "pipe"] });
  const report = JSON.parse(output.slice(output.indexOf("{")));
  assert.deepEqual(report.errors, [], JSON.stringify(report.errors, null, 2));
  assert.deepEqual(report.warnings, [], JSON.stringify(report.warnings, null, 2));
});
