// Service worker de l'extension : la seule partie qui parle à Verrou.
//
// Les pages (content.js) ne demandent que pour elles-mêmes : l'adresse
// envoyée à Verrou est celle que le navigateur attribue à l'expéditeur
// (`sender.url`), jamais une adresse fournie par la page.

import { Channel } from "./bridge.js";

const HOST = "app.verrou.bridge";
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
  const port = chrome.runtime.connectNative(HOST);
  return {
    post: (message) => port.postMessage(message),
    onMessage: (callback) => port.onMessage.addListener(callback),
    onDisconnect: (callback) => port.onDisconnect.addListener(
      () => callback(chrome.runtime.lastError?.message ?? "déconnecté")),
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
  try {
    return await channel.request(command);
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
    return { state: reply.unlocked ? "unlocked" : "locked" };
  } catch (error) {
    return { state: stateOf(error) };
  }
}

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
    return { ok: false, state: reply.result, reason: reply.reason };
  } catch (error) {
    return { ok: false, state: stateOf(error) };
  }
}

// MARK: Appairage (piloté par la fenêtre de l'extension)

let pairing = { state: "idle" };

function publish(next) {
  pairing = next;
  chrome.storage.session.set({ pairing }).catch(() => {});
}

function startPairing() {
  if (["connecting", "waiting"].includes(pairing.state)) return pairing;
  publish({ state: "connecting" });
  channel.pair("Brave", (code) => publish({ state: "waiting", code }))
    .then(async (client) => {
      await saveClient(client);
      channel.setClient(client);
      publish({ state: "paired" });
    })
    .catch((error) => publish({
      state: "failed",
      error: error.code === "refused" ? "Appairage refusé dans Verrou."
        : error.code === "busy" ? "Un appairage est déjà en cours : réessayez dans un instant."
        : `Verrou ne répond pas. Est-il installé, et le remplissage dans Brave activé ? (${error.message})`,
    }));
  return pairing;
}

// MARK: Enregistrement après l'envoi d'un formulaire
//
// Le mot de passe capté attend la réponse de l'utilisateur dans
// `chrome.storage.session` (en mémoire, hors de portée des pages), deux
// minutes au plus, pour l'onglet où le formulaire est parti.

const PENDING_MS = 2 * 60_000;
const USERNAME_MS = 5 * 60_000;

const pendingKey = (tabId) => `save:${tabId}`;
const usernameKey = (tabId) => `user:${tabId}`;

async function sessionGet(key) {
  return (await chrome.storage.session.get(key))[key];
}

async function neverList() {
  return (await chrome.storage.local.get("never")).never ?? [];
}

const siteOf = (url) => {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
};

async function rememberUsername(tabId, username) {
  await chrome.storage.session.set({ [usernameKey(tabId)]: { username, at: Date.now() } });
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
    await chrome.storage.session.remove(pendingKey(tabId));
    return;
  }
  await chrome.storage.session.set({ [pendingKey(tabId)]: pending });
  // Application monopage : la page reste, on lui dit de proposer. Sinon, la
  // page suivante le demandera elle-même.
  setTimeout(() => chrome.tabs.sendMessage(tabId, { kind: "offerSave" }, { frameId: 0 }).catch(() => {}), 600);
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
          await chrome.storage.session.remove(pendingKey(tabId));
          return null;
        }
        Object.assign(pending, { action: reply.action, item: reply.item?.id ?? null, title: reply.item?.title ?? "" });
        await chrome.storage.session.set({ [pendingKey(tabId)]: pending });
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
    await chrome.storage.session.remove(pendingKey(sender.tab.id));
    return { ok: true };
  } catch (error) {
    return { ok: false, reason: `Verrou ne répond pas (${error.message})` };
  }
}

async function neverSave(sender) {
  const pending = await pendingFor(sender);
  if (pending?.site) {
    const never = await neverList();
    if (!never.includes(pending.site)) await chrome.storage.local.set({ never: [...never, pending.site] });
  }
  await chrome.storage.session.remove(pendingKey(sender.tab.id));
}

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove([pendingKey(tabId), usernameKey(tabId)]).catch(() => {});
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

const fromPage = new Set([
  "suggest", "fill", "unlock",
  "capture", "rememberUsername", "pendingSave", "confirmSave", "dismissSave", "neverSave",
]);

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function handle(message, sender) {
  if (sender.id !== chrome.runtime.id) return { error: "expéditeur inconnu" };
  // Une page de l'extension (fenêtre ou onglet) ; un script de page a
  // l'adresse de la page.
  const fromExtensionPage = sender.url?.startsWith(chrome.runtime.getURL("")) ?? false;
  if (!fromExtensionPage && !fromPage.has(message.kind)) return { error: "commande refusée" };

  switch (message.kind) {
    // Depuis une page : pour l'adresse de la page (ou du cadre) seulement.
    case "suggest":
      return suggest(sender.url);
    case "fill":
      return fill(sender.url, message.item);
    case "unlock":
      await call({ cmd: "unlock" }).catch(() => {});
      return { ok: true };
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
      if (sender.tab?.id !== undefined) await chrome.storage.session.remove(pendingKey(sender.tab.id));
      return { ok: true };
    case "neverSave":
      await neverSave(sender);
      return { ok: true };

    // Depuis la fenêtre de l'extension.
    case "status":
      await ready;
      return channel.client ? status() : { state: "unpaired" };
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
      await chrome.tabs.sendMessage(tab.id, { kind: "apply", credentials }, { frameId: 0 });
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
        return { ok: true, image: await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" }) };
      } catch (error) {
        return { ok: false, reason: error.message };
      }
    }
    case "neverList":
      return { sites: await neverList() };
    case "forgetNever":
      await chrome.storage.local.set({ never: (await neverList()).filter((s) => s !== message.site) });
      return { ok: true };
    default:
      return { error: "commande inconnue" };
  }
}

chrome.runtime.onMessage.addListener((message, sender, respond) => {
  handle(message, sender).then(respond, (error) => respond({ error: String(error?.message ?? error) }));
  return true;
});

