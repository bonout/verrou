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

// MARK: Messages

const fromPage = new Set(["suggest", "fill", "unlock"]);

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
    default:
      return { error: "commande inconnue" };
  }
}

chrome.runtime.onMessage.addListener((message, sender, respond) => {
  handle(message, sender).then(respond, (error) => respond({ error: String(error?.message ?? error) }));
  return true;
});

