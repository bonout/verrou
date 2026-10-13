// Protocole de l'extension avec Verrou, indépendant du navigateur : le
// transport (Native Messaging dans Brave, un processus dans les tests) est
// fourni par l'appelant.
//
//   transport = { post(message), onMessage(callback), onDisconnect(callback) }

import * as wire from "./crypto.js";

export class BridgeError extends Error {
  constructor(code, message) {
    super(message ?? code);
    this.code = code;
  }
}

export class Channel {
  // `connect()` ouvre un transport ; il est rouvert à la demande après une
  // déconnexion.
  constructor(connect) {
    this.connect = connect;
    this.transport = null;
    this.queue = [];
    this.pairing = null;
    this.client = null; // { id, key: CryptoKey }
    this.nextId = 1;
  }

  setClient(client) {
    this.client = client;
  }

  ensureTransport() {
    if (this.transport) return this.transport;
    const transport = this.connect();
    transport.onMessage((message) => this.receive(message));
    transport.onDisconnect((reason) => {
      if (this.transport !== transport) return;
      this.transport = null;
      const error = new BridgeError("offline", reason);
      for (const waiter of this.queue.splice(0)) waiter.reject(error);
      this.pairing?.fail(error);
    });
    this.transport = transport;
    return transport;
  }

  disconnect() {
    const transport = this.transport;
    this.transport = null;
    transport?.close?.();
  }

  receive(message) {
    if (message?.type === "error" && message.code === "app_unavailable") {
      const error = new BridgeError("offline", "Verrou n'a pas pu être ouvert");
      for (const waiter of this.queue.splice(0)) waiter.reject(error);
      this.pairing?.fail(error);
      return;
    }
    if (this.pairing && ["pairing", "paired", "refused"].includes(message?.type)) {
      this.pairing.step(message);
      return;
    }
    if (this.pairing && message?.type === "error" && this.queue.length === 0) {
      this.pairing.fail(new BridgeError(message.code));
      return;
    }
    // Verrou répond dans l'ordre des requêtes d'une même connexion.
    const waiter = this.queue.shift();
    if (!waiter) return;
    if (message?.type === "response") {
      wire.open(waiter.key, waiter.client, "response", message.iv, message.data)
        .then((reply) => (reply.id === waiter.id
          ? waiter.resolve(reply)
          : waiter.reject(new BridgeError("bad_response"))))
        .catch(() => waiter.reject(new BridgeError("bad_response")));
    } else {
      waiter.reject(new BridgeError(message?.code ?? "bad_response"));
    }
  }

  // Commande chiffrée ; rend la réponse déchiffrée (`{ id, result, … }`).
  async request(command) {
    if (!this.client) throw new BridgeError("unpaired");
    const { id: client, key } = this.client;
    const id = this.nextId++;
    const sealed = await wire.seal(key, client, "request", { ...command, id, ts: Date.now() });
    const transport = this.ensureTransport();
    return new Promise((resolve, reject) => {
      this.queue.push({ id, client, key, resolve, reject });
      transport.post({ type: "request", client, ...sealed });
    });
  }

  // Appairage. `onCode(code)` reçoit le code à comparer avec celui de
  // Verrou ; la promesse rend le client appairé `{ id, key }`.
  async pair(name, onCode) {
    if (this.pairing) throw new BridgeError("busy");
    const ours = await wire.generateKeyPair();
    const transport = this.ensureTransport();
    try {
      return await new Promise((resolve, reject) => {
        let channel = null;
        // Les étapes s'enchaînent dans l'ordre d'arrivée : « paired » peut
        // arriver pendant le calcul de la clé.
        let chain = Promise.resolve();
        const handle = async (message) => {
            try {
              if (message.type === "pairing") {
                const bytes = await wire.agree(ours, message.key);
                onCode(await wire.pairingCode(bytes));
                channel = { id: message.client, key: await wire.importChannelKey(bytes) };
                bytes.fill(0);
              } else if (message.type === "paired" && channel) {
                resolve(channel);
              } else {
                reject(new BridgeError("refused", "Appairage refusé dans Verrou"));
              }
            } catch (error) {
              reject(error);
            }
        };
        this.pairing = {
          fail: reject,
          step: (message) => { chain = chain.then(() => handle(message)); },
        };
        wire.publicKeyBase64(ours)
          .then((key) => transport.post({ type: "pair", name, key }))
          .catch(reject);
      });
    } finally {
      this.pairing = null;
    }
  }
}
