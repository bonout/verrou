// Service worker de l'extension (page d'arrière-plan dans Firefox) : la
// seule partie qui parle à Verrou.
//
// Les pages (content.js) ne demandent que pour elles-mêmes : l'adresse
// envoyée à Verrou est celle que le navigateur attribue à l'expéditeur
// (`sender.url`), jamais une adresse fournie par la page.

import { Channel } from "./bridge.js";
import { browserName, ext, firefox } from "./browser.js";
import { passkeyCommand, passkeyResult } from "./passkey-bridge.js";
import { ATTEMPT_KEY, createUpdater } from "./update.js";

const HOST = "app.verrou.bridge";
// Le réglage de Verrou qui active le pont (SettingsView.swift).
const SETTING = "Brave, Firefox et le terminal";
const IDLE_MS = 60_000;

// MARK: Appairage enregistré (IndexedDB : la clé AES y reste non exportable)

function database() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("verrou", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("state");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function stored(mode, action) {
  const db = await database();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction("state", mode);
    const request = action(transaction.objectStore("state"));
    transaction.oncomplete = () => resolve(request?.result);
    transaction.onerror = () => reject(transaction.error);
  });
}

const loadClient = () => stored("readonly", (store) => store.get("client"));
const saveClient = (client) => stored("readwrite", (store) => store.put(client, "client"));
const forgetClient = () => stored("readwrite", (store) => store.delete("client"));

// MARK: Canal

function nativeTransport() {
  const port = ext.runtime.connectNative(HOST);
  return {
    post: (message) => port.postMessage(message),
    onMessage: (callback) => port.onMessage.addListener(callback),
    // Firefox donne l'erreur sur le port, Brave dans `runtime.lastError`.
    onDisconnect: (callback) => port.onDisconnect.addListener(
      (closed) => callback(closed?.error?.message ?? ext.runtime.lastError?.message ?? "déconnecté")),
    close: () => port.disconnect(),
  };
}

const channel = new Channel(nativeTransport);
const ready = loadClient()
  .then((client) => client && channel.setClient(client))
  .catch(() => {});

let idle;
function keepAlive() {
  clearTimeout(idle);
  idle = setTimeout(() => {
    if (!channel.pairing) channel.disconnect();
  }, IDLE_MS);
}

async function call(command) {
  await ready;
  keepAlive();
  // Nouvelle connexion à Verrou : l'occasion de comparer les versions.
  const connecting = !channel.transport;
  try {
    const reply = await channel.request(command);
    if (connecting && command.cmd !== "status") checkWithBridge();
    return reply;
  } catch (error) {
    if (error.code === "unknown_client") {
      // Révoqué dans Verrou : il faudra appairer de nouveau.
      channel.setClient(null);
      await forgetClient();
    }
    throw error;
  }
}

function stateOf(error) {
  if (error?.code === "unpaired" || error?.code === "unknown_client") return "unpaired";
  return "offline";
}

async function status() {
  try {
    const reply = await call({ cmd: "status" });
    await updater.check({ bridgeVersion: reply.extension_version ?? null });
    return { state: reply.unlocked ? "unlocked" : "locked", extension: updater.state() };
  } catch (error) {
    return { state: stateOf(error), extension: updater.state() };
  }
}

// MARK: Mise à jour (extension chargée depuis Verrou.app)
//
// Au démarrage, à chaque connexion à Verrou, et toutes les dix minutes : si
// l'extension sur le disque (ou celle que Verrou livre) n'est plus celle qui
// tourne, elle se recharge (voir update.js).

async function diskVersion() {
  const response = await fetch(ext.runtime.getURL("manifest.json"), { cache: "no-store" });
  return (await response.json()).version;
}

// Firefox : une extension temporaire se recharge depuis son dossier, mais un
// module signé (.xpi) ne change pas en se rechargeant. On ne recharge donc
// que si le manifeste sur le disque a changé ; une version différente chez
// Verrou ne donne que l'avertissement de la fenêtre de l'extension.
const updater = createUpdater({
  running: ext.runtime.getManifest().version,
  reloadForBundled: !firefox,
  readDisk: diskVersion,
  reload: () => ext.runtime.reload(),
  store: {
    get: async () => (await ext.storage.local.get(ATTEMPT_KEY))[ATTEMPT_KEY],
    set: (attempt) => ext.storage.local.set({ [ATTEMPT_KEY]: attempt }),
  },
  busy: () => Boolean(channel.pairing),
});

// La version annoncée par Verrou, sans le lancer : seulement s'il est relié.
async function checkWithBridge() {
  if (!channel.client) return updater.check();
  try {
    const reply = await channel.request({ cmd: "status" });
    return updater.check({ bridgeVersion: reply.extension_version ?? null });
  } catch {
    return updater.check();
  }
}

const UPDATE_ALARM = "verrou-update";
// Recréer l'alarme à chaque réveil du service worker la repousserait sans fin.
ext.alarms.get(UPDATE_ALARM)
  .then((alarm) => alarm ?? ext.alarms.create(UPDATE_ALARM, { periodInMinutes: 10 }))
  .catch(() => {});
ext.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== UPDATE_ALARM) return;
  // Connexion déjà ouverte : demander aussi à Verrou ; sinon le disque seul
  // (ouvrir la connexion lancerait l'app).
  (channel.transport ? checkWithBridge() : updater.check()).catch(() => {});
});
updater.check().catch(() => {});

async function suggest(url) {
  try {
    const reply = await call({ cmd: "suggest", url });
    if (reply.result === "locked") return { state: "locked" };
    return { state: "unlocked", items: reply.items ?? [] };
  } catch (error) {
    return { state: stateOf(error) };
  }
}

async function fill(url, item) {
  try {
    const reply = await call({ cmd: "fill", url, item });
    if (reply.result === "credentials") {
      return { ok: true, username: reply.username, password: reply.password, totp: reply.totp };
    }
    // « confirm » : élément protégé, Verrou demande Touch ID ; on réessaie.
    return { ok: false, state: reply.result, reason: reply.reason };
  } catch (error) {
    return { ok: false, state: stateOf(error) };
  }
}

// MARK: Appairage (piloté par la fenêtre de l'extension)

let pairing = { state: "idle" };

function publish(next) {
  pairing = next;
  ext.storage.session.set({ pairing }).catch(() => {});
}

function startPairing() {
  if (["connecting", "waiting"].includes(pairing.state)) return pairing;
  publish({ state: "connecting" });
  channel.pair(browserName, (code) => publish({ state: "waiting", code }))
    .then(async (client) => {
      await saveClient(client);
      channel.setClient(client);
      publish({ state: "paired" });
    })
    .catch((error) => publish({
      state: "failed",
      error: error.code === "refused" ? "Appairage refusé dans Verrou."
        : error.code === "busy" ? "Un appairage est déjà en cours : réessayez dans un instant."
        : `Verrou ne répond pas. Est-il installé, et « ${SETTING} » activé dans ses réglages ? (${error.message})`,
    }));
  return pairing;
}

// MARK: Enregistrement après l'envoi d'un formulaire
//
// Le mot de passe capté attend la réponse de l'utilisateur dans
// `storage.session` (en mémoire, hors de portée des pages), deux
// minutes au plus, pour l'onglet où le formulaire est parti.

const PENDING_MS = 2 * 60_000;
const USERNAME_MS = 5 * 60_000;

const pendingKey = (tabId) => `save:${tabId}`;
const usernameKey = (tabId) => `user:${tabId}`;

async function sessionGet(key) {
  return (await ext.storage.session.get(key))[key];
}

async function neverList() {
  return (await ext.storage.local.get("never")).never ?? [];
}

const siteOf = (url) => {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
};

async function rememberUsername(tabId, username) {
  await ext.storage.session.set({ [usernameKey(tabId)]: { username, at: Date.now() } });
}

async function capture(sender, message) {
  const tabId = sender.tab?.id;
  if (tabId === undefined || !sender.url || !channel.client) return;
  const site = siteOf(sender.url);
  if ((await neverList()).includes(site)) return;
  let username = String(message.username ?? "").slice(0, 512);
  if (!username) {
    // Deuxième étape d'une connexion : l'identifiant de l'étape précédente.
    const remembered = await sessionGet(usernameKey(tabId));
    if (remembered && Date.now() - remembered.at < USERNAME_MS) username = remembered.username;
  }
  const password = String(message.password ?? "");
  const current = message.current ? String(message.current) : null;
  const pending = { url: sender.url, site, username, password, current, at: Date.now() };
  let reply;
  try {
    reply = await call({ cmd: "check", url: sender.url, username, password, current });
  } catch {
    return;
  }
  if (reply.result === "locked") {
    pending.action = "locked";
  } else if (reply.result === "check" && reply.action !== "known") {
    pending.action = reply.action;
    pending.item = reply.item?.id ?? null;
    pending.title = reply.item?.title ?? "";
  } else {
    await ext.storage.session.remove(pendingKey(tabId));
    return;
  }
  await ext.storage.session.set({ [pendingKey(tabId)]: pending });
  // Application monopage : la page reste, on lui dit de proposer. Sinon, la
  // page suivante le demandera elle-même.
  setTimeout(() => ext.tabs.sendMessage(tabId, { kind: "offerSave" }, { frameId: 0 }).catch(() => {}), 600);
}

async function pendingFor(sender) {
  const tabId = sender.tab?.id;
  if (tabId === undefined) return null;
  const pending = await sessionGet(pendingKey(tabId));
  if (!pending || Date.now() - pending.at > PENDING_MS) return null;
  if (pending.action === "locked") {
    // Verrou vient peut-être d'être déverrouillé : la vraie réponse.
    try {
      const reply = await call({ cmd: "check", url: pending.url, username: pending.username,
        password: pending.password, current: pending.current });
      if (reply.result === "check") {
        if (reply.action === "known") {
          await ext.storage.session.remove(pendingKey(tabId));
          return null;
        }
        Object.assign(pending, { action: reply.action, item: reply.item?.id ?? null, title: reply.item?.title ?? "" });
        await ext.storage.session.set({ [pendingKey(tabId)]: pending });
      }
    } catch {
      // Hors ligne : on garde la proposition telle quelle.
    }
  }
  return pending;
}

async function confirmSave(sender) {
  const pending = await pendingFor(sender);
  if (!pending || pending.action === "locked") return { ok: false, reason: "Verrou est verrouillé" };
  try {
    const reply = await call({ cmd: "save", url: pending.url, username: pending.username,
      password: pending.password, item: pending.action === "update" ? pending.item : null });
    if (reply.result !== "saved") {
      return { ok: false, reason: reply.result === "locked" ? "Verrou est verrouillé" : reply.reason };
    }
    await ext.storage.session.remove(pendingKey(sender.tab.id));
    return { ok: true };
  } catch (error) {
    return { ok: false, reason: `Verrou ne répond pas (${error.message})` };
  }
}

async function neverSave(sender) {
  const pending = await pendingFor(sender);
  if (pending?.site) {
    const never = await neverList();
    if (!never.includes(pending.site)) await ext.storage.local.set({ never: [...never, pending.site] });
  }
  await ext.storage.session.remove(pendingKey(sender.tab.id));
}

ext.tabs.onRemoved.addListener((tabId) => {
  ext.storage.session.remove([pendingKey(tabId), usernameKey(tabId)]).catch(() => {});
});

// MARK: Code de vérification (QR code)

async function setTotp(url, totp, item) {
  try {
    const reply = await call({ cmd: "set_totp", url, totp, item: item ?? null });
    if (reply.result === "saved") return { ok: true };
    return { ok: false, reason: reply.result === "locked" ? "Verrou est verrouillé" : reply.reason };
  } catch (error) {
    return { ok: false, reason: `Verrou ne répond pas (${error.message})` };
  }
}

// MARK: Messages

// MARK: Cartes et adresses

async function forms(url) {
  try {
    const reply = await call({ cmd: "forms", url });
    if (reply.result === "locked") return { state: "locked" };
    return { state: "unlocked", cards: reply.cards ?? [], identities: reply.identities ?? [] };
  } catch (error) {
    return { state: stateOf(error) };
  }
}

async function fillForm(url, item) {
  try {
    const reply = await call({ cmd: "fill_form", url, item });
    if (reply.result === "form") {
      const { id, result, ...data } = reply;
      return { ok: true, data };
    }
    return { ok: false, state: reply.result, reason: reply.reason };
  } catch (error) {
    return { ok: false, state: stateOf(error) };
  }
}

// MARK: Passkeys
//
// Demandes de passkeys.js (cadre principal seulement), pour l'adresse de
// l'onglet (voir passkey-bridge.js).

async function passkey(message, sender) {
  if (sender.frameId !== 0 || !sender.url) return { state: "offline" };
  const command = passkeyCommand(message, sender.url);
  if (!command) return { error: "commande inconnue" };
  try {
    return passkeyResult(await call(command));
  } catch (error) {
    return { state: stateOf(error) };
  }
}

// MARK: Relier un site à un identifiant
//
// « Remplir avec un autre identifiant… » de la pastille (content.js) ouvre
// la fenêtre de l'extension sur ce choix, pour le cadre d'où vient la
// demande. Le choix et l'avertissement restent dans la fenêtre : la page ne
// voit ni la recherche ni les identifiants.

const LINK_INTENT = "linkIntent";

async function openLinkSite(sender) {
  const tabId = sender.tab?.id;
  if (tabId === undefined || !sender.url) return { ok: false };
  await ext.storage.session.set({
    [LINK_INTENT]: { tabId, frameId: sender.frameId ?? 0, url: sender.url, at: Date.now() },
  });
  // La fenêtre de l'extension sous son icône (Brave) ; sinon (Firefox
  // l'interdit hors d'un clic sur l'extension elle-même) une petite fenêtre.
  try {
    await ext.action.openPopup();
    return { ok: true };
  } catch {
    // Repli ci-dessous.
  }
  try {
    await ext.windows.create({ url: ext.runtime.getURL("popup.html"), type: "popup", width: 360, height: 560 });
    return { ok: true };
  } catch (error) {
    return { ok: false, reason: error.message };
  }
}

// L'onglet (et le cadre) à relier : celui de la demande de la pastille, sinon
// l'onglet actif.
async function linkTarget(target) {
  if (target && Number.isInteger(target.tabId) && typeof target.url === "string") {
    return { tabId: target.tabId, frameId: Number.isInteger(target.frameId) ? target.frameId : 0, url: target.url };
  }
  const tab = await activeTab();
  return tab?.url ? { tabId: tab.id, frameId: 0, url: tab.url } : null;
}

const originOf = (url) => {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
};

const fromPage = new Set([
  "suggest", "fill", "unlock", "forms", "fillForm", "openLinkSite",
  "capture", "rememberUsername", "pendingSave", "confirmSave", "dismissSave", "neverSave",
  "passkeyList", "passkeyGet", "passkeyTargets", "passkeyCreate",
]);

async function activeTab() {
  const [tab] = await ext.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function handle(message, sender) {
  if (sender.id !== ext.runtime.id) return { error: "expéditeur inconnu" };
  // Une page de l'extension (fenêtre ou onglet) ; un script de page a
  // l'adresse de la page.
  const fromExtensionPage = sender.url?.startsWith(ext.runtime.getURL("")) ?? false;
  if (!fromExtensionPage && !fromPage.has(message.kind)) return { error: "commande refusée" };

  switch (message.kind) {
    // Depuis une page : pour l'adresse de la page (ou du cadre) seulement.
    case "suggest":
      return suggest(sender.url);
    case "fill":
      return fill(sender.url, message.item);
    case "forms":
      return forms(sender.url);
    case "fillForm":
      return fillForm(sender.url, message.item);
    case "unlock":
      await call({ cmd: "unlock" }).catch(() => {});
      return { ok: true };
    case "openLinkSite":
      return openLinkSite(sender);
    case "capture":
      await capture(sender, message);
      return { ok: true };
    case "rememberUsername":
      if (sender.tab?.id !== undefined) await rememberUsername(sender.tab.id, String(message.username).slice(0, 512));
      return { ok: true };
    case "pendingSave": {
      const pending = await pendingFor(sender);
      // Pas de mot de passe vers la page : le bandeau n'en a pas besoin.
      return pending
        ? { action: pending.action, username: pending.username, site: pending.site, title: pending.title ?? "" }
        : {};
    }
    case "confirmSave":
      return confirmSave(sender);
    case "dismissSave":
      if (sender.tab?.id !== undefined) await ext.storage.session.remove(pendingKey(sender.tab.id));
      return { ok: true };
    case "neverSave":
      await neverSave(sender);
      return { ok: true };
    case "passkeyList":
    case "passkeyGet":
    case "passkeyTargets":
    case "passkeyCreate":
      return passkey(message, sender);

    // Depuis la fenêtre de l'extension.
    case "status":
      await ready;
      return channel.client ? status() : { state: "unpaired", extension: updater.state() };
    case "pair":
      return startPairing();
    case "unpair":
      channel.setClient(null);
      await forgetClient();
      publish({ state: "idle" });
      return { ok: true };
    case "suggestTab": {
      const tab = await activeTab();
      return tab?.url ? suggest(tab.url) : { state: "unlocked", items: [] };
    }
    case "fillTab": {
      const tab = await activeTab();
      if (!tab?.url) return { ok: false };
      const credentials = await fill(tab.url, message.item);
      if (!credentials.ok) return credentials;
      await ext.tabs.sendMessage(tab.id, { kind: "apply", credentials, origin: originOf(tab.url) }, { frameId: 0 });
      return { ok: true };
    }
    case "setTotpTab": {
      const tab = await activeTab();
      if (!tab?.url) return { ok: false, reason: "aucun onglet" };
      return setTotp(tab.url, String(message.totp ?? ""), message.item);
    }
    case "captureTab": {
      // Image de l'onglet, pour y lire un QR code (droit « activeTab » :
      // seulement après un clic sur l'icône de l'extension).
      const tab = await activeTab();
      if (!tab) return { ok: false };
      try {
        return { ok: true, image: await ext.tabs.captureVisibleTab(tab.windowId, { format: "png" }) };
      } catch (error) {
        return { ok: false, reason: error.message };
      }
    }
    case "searchLogins": {
      try {
        const reply = await call({ cmd: "search_logins", query: String(message.query ?? "") });
        return reply.result === "suggestions" ? { items: reply.items } : { items: [], state: reply.result };
      } catch (error) {
        return { items: [], state: stateOf(error) };
      }
    }
    case "linkSiteTab": {
      // Choisi dans la fenêtre de l'extension : rattacher le site de l'onglet
      // (ou du cadre de la pastille) à cet identifiant, puis remplir comme
      // d'habitude.
      const target = await linkTarget(message.target);
      if (!target) return { ok: false, reason: "aucun onglet" };
      try {
        const reply = await call({ cmd: "link_site", url: target.url, item: message.item });
        if (reply.result !== "saved") return { ok: false, reason: reply.reason ?? reply.result };
      } catch (error) {
        return { ok: false, reason: error.message };
      }
      const credentials = await fill(target.url, message.item);
      if (credentials.ok) {
        await ext.tabs.sendMessage(target.tabId, { kind: "apply", credentials, origin: originOf(target.url) },
          { frameId: target.frameId }).catch(() => {});
      }
      return { ok: true };
    }
    case "neverList":
      return { sites: await neverList() };
    case "forgetNever":
      await ext.storage.local.set({ never: (await neverList()).filter((s) => s !== message.site) });
      return { ok: true };
    default:
      return { error: "commande inconnue" };
  }
}

ext.runtime.onMessage.addListener((message, sender, respond) => {
  handle(message, sender).then(respond, (error) => respond({ error: String(error?.message ?? error) }));
  return true;
});

