// Passkeys: the conversion of WebAuthn options to Verrou's messages
// (passkey-codec.js), then creation and sign-in against the real bridge,
// through the real Native Messaging host. The signatures are checked here
// with WebCrypto, as a site would.
//
//   cargo build -p verrou-bridge --example test_server --bin verrou-native-host
//   node --test extension/test/passkeys.test.mjs

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import vm from "node:vm";

import { Channel } from "../bridge.js";

const root = fileURLToPath(new URL("../../", import.meta.url));

function loadCodec(globals = {}) {
  const context = { btoa, atob, structuredClone, ArrayBuffer, Uint8Array, ...globals };
  vm.runInNewContext(readFileSync(`${root}extension/passkey-codec.js`, "utf8"), context);
  return context.__verrouPasskeyCodec;
}

const codec = loadCodec();
const bytes = (buffer) => [...new Uint8Array(buffer)];

// MARK: Codec

test("base64url round trip, without padding", () => {
  for (const length of [0, 1, 2, 3, 16, 31, 32, 33]) {
    const input = Uint8Array.from({ length }, (_, i) => (i * 37 + 250) % 256);
    const encoded = codec.encode(input);
    assert.doesNotMatch(encoded, /[+/=]/);
    assert.deepEqual(bytes(codec.decode(encoded)), [...input]);
  }
  // A partial view of a buffer: only its bytes.
  const view = new Uint8Array([9, 1, 2, 3, 9]).subarray(1, 4);
  assert.equal(codec.encode(view), "AQID");
});

test("the page's options become a request for Verrou", () => {
  const create = codec.createRequest({
    rp: { id: "github.com", name: "GitHub" },
    user: { id: new Uint8Array([1, 2, 3]), name: "camille", displayName: "Camille" },
    challenge: new Uint8Array(32).fill(7).buffer,
    pubKeyCredParams: [{ type: "public-key", alg: -8 }, { type: "public-key", alg: -7 }, { type: "autre", alg: -257 }],
    excludeCredentials: [{ type: "public-key", id: new Uint8Array([4, 5]) }],
    authenticatorSelection: { userVerification: "discouraged" },
    attestation: "direct",
  });
  assert.deepEqual({ ...create, algorithms: [...create.algorithms], exclude: [...create.exclude] }, {
    rp_id: "github.com", rp_name: "GitHub", user_id: "AQID", user_name: "camille",
    user_display_name: "Camille", challenge: codec.encode(new Uint8Array(32).fill(7)),
    algorithms: [-8, -7], exclude: ["BAU"], uv: false, attestation: "direct", prf: null,
  });
  // WebAuthn defaults: rpId absent, "preferred" verification.
  const get = codec.getRequest({ challenge: new Uint8Array(16) });
  assert.equal(get.rp_id, null);
  assert.equal(get.uv, true);
  assert.equal(get.allow.length, 0);
  assert.throws(() => codec.createRequest({ rp: {}, user: { id: "not a buffer" }, challenge: new Uint8Array(16) }));
});

test("PRF extension: inputs in base64url, user verification required", () => {
  const create = codec.createRequest({
    rp: { id: "github.com" }, user: { id: new Uint8Array([1]) }, challenge: new Uint8Array(16),
    authenticatorSelection: { userVerification: "discouraged" },
    extensions: { prf: { eval: { first: new Uint8Array([1, 2, 3]) }, evalByCredential: { AQ: { first: new Uint8Array([9]) } } } },
  });
  assert.equal(create.uv, true);
  // `evalByCredential` makes no sense at creation: ignored.
  assert.deepEqual(JSON.parse(JSON.stringify(create.prf)), { eval: { first: "AQID", second: null }, eval_by_credential: {} });
  const get = codec.getRequest({
    challenge: new Uint8Array(16), userVerification: "discouraged",
    extensions: { prf: { evalByCredential: { "AQ": { first: new Uint8Array([4]), second: new Uint8Array([5]) } } } },
  });
  assert.equal(get.uv, true);
  assert.deepEqual(JSON.parse(JSON.stringify(get.prf)), { eval: null, eval_by_credential: { AQ: { first: "BA", second: "BQ" } } });
  assert.equal(codec.getRequest({ challenge: new Uint8Array(16) }).prf, null);

  // Outputs of Verrou → `getClientExtensionResults().prf` (ArrayBuffer) and JSON.
  const registration = codec.registrationCredential({
    credential: "AQ", client_data: "e30", attestation_object: "oA", authenticator_data: "AA",
    public_key: "AA", algorithm: -7, prf: { enabled: true, results: { first: "AQID" } },
  }, { prf: true });
  const created = registration.getClientExtensionResults().prf;
  assert.equal(created.enabled, true);
  assert.deepEqual(bytes(created.results.first), [1, 2, 3]);
  assert.equal(created.results.second, undefined);
  assert.deepEqual(JSON.parse(JSON.stringify(registration.toJSON().clientExtensionResults)), { prf: { enabled: true, results: { first: "AQID" } } });
  const assertion = codec.assertionCredential({
    credential: "AQ", client_data: "e30", authenticator_data: "AA", signature: "AA", user_handle: null,
    prf: { first: "AQ", second: "Ag" },
  });
  const results = assertion.getClientExtensionResults().prf.results;
  assert.deepEqual([bytes(results.first), bytes(results.second)], [[1], [2]]);
  // A copy on each call: the page doesn't modify the next one.
  new Uint8Array(results.first)[0] = 42;
  assert.deepEqual(bytes(assertion.getClientExtensionResults().prf.results.first), [1]);
  assert.deepEqual(JSON.parse(JSON.stringify(assertion.toJSON().clientExtensionResults)), { prf: { results: { first: "AQ", second: "Ag" } } });
  assert.deepEqual(Object.keys(codec.assertionCredential({ credential: "AQ", client_data: "e30", authenticator_data: "AA", signature: "AA" })
    .getClientExtensionResults()), []);
});

test("Verrou's replies become PublicKeyCredentials", () => {
  // Fake browser prototypes: `instanceof` must work.
  class PublicKeyCredential {}
  class AuthenticatorAttestationResponse {}
  class AuthenticatorAssertionResponse {}
  const browser = loadCodec({ PublicKeyCredential, AuthenticatorAttestationResponse, AuthenticatorAssertionResponse });
  const created = browser.registrationCredential({
    credential: "AAEC", client_data: "e30", authenticator_data: "AQ", attestation_object: "oA",
    public_key: "MA", algorithm: -7,
  }, { credProps: true });
  assert.ok(created instanceof PublicKeyCredential);
  assert.ok(created.response instanceof AuthenticatorAttestationResponse);
  assert.equal(created.id, "AAEC");
  assert.deepEqual(bytes(created.rawId), [0, 1, 2]);
  assert.equal(created.response.getPublicKeyAlgorithm(), -7);
  assert.deepEqual(bytes(created.response.getAuthenticatorData()), [1]);
  assert.deepEqual(created.getClientExtensionResults(), { credProps: { rk: true } });
  assert.deepEqual([...created.toJSON().response.transports], ["hybrid", "internal"]);
  assert.equal(created.toJSON().response.publicKey, "MA");

  const used = browser.assertionCredential({
    credential: "AAEC", client_data: "e30", authenticator_data: "AQ", signature: "Ag", user_handle: null,
  });
  assert.ok(used.response instanceof AuthenticatorAssertionResponse);
  assert.equal(used.response.userHandle, null);
  assert.deepEqual(bytes(used.response.signature), [2]);
  assert.equal(used.toJSON().response.signature, "Ag");
});

// MARK: Against the bridge

const server = spawn(`${root}target/debug/examples/test_server`, {
  env: { ...process.env, VERROU_BRIDGE_PORT: "0" },
  stdio: ["ignore", "pipe", "inherit"],
});
const lines = createInterface({ input: server.stdout });
const events = [];
let port;

before(async () => {
  for await (const line of lines) {
    if (line.startsWith("PORT ")) {
      port = line.slice(5);
      break;
    }
  }
  lines.on("line", (line) => events.push(line));
});

after(() => server.kill());

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

async function verify(publicKey, reply) {
  const key = await crypto.subtle.importKey("spki", codec.decode(publicKey),
    { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const clientData = new Uint8Array(codec.decode(reply.client_data));
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientData));
  const data = Buffer.concat([Buffer.from(codec.decode(reply.authenticator_data)), hash]);
  const signature = derToRaw(new Uint8Array(codec.decode(reply.signature)));
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, data);
}

const counterOf = (reply) => Buffer.from(codec.decode(reply.authenticator_data)).readUInt32BE(33);

test("creation, then sign-ins signed by Verrou", async () => {
  const channel = new Channel(hostTransport);
  channel.setClient(await channel.pair("Brave", () => {}));
  const page = "https://github.com/settings/security";
  const challenge = codec.encode(crypto.getRandomValues(new Uint8Array(32)));

  // Where to save it: the vault's GitHub login, without a passkey.
  const targets = await channel.request({ cmd: "passkey_targets", url: page, rp_id: "github.com", exclude: [] });
  assert.equal(targets.result, "passkey_targets");
  assert.equal(targets.excluded, false);
  assert.deepEqual(targets.logins.map((l) => [l.id, l.has_passkey]), [["github", false]]);

  const created = await channel.request({
    cmd: "passkey_create", url: page, rp_id: "github.com", rp_name: "GitHub",
    user_id: codec.encode(new TextEncoder().encode("id-camille")), user_name: "camille",
    challenge, algorithms: [-7], exclude: [], uv: true, attestation: "none", item: "github",
  });
  assert.equal(created.result, "registration", JSON.stringify(created));
  assert.equal(created.item, "github");
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.ok(events.includes("CONFIRM passkey GitHub"), "user verification asked of Verrou");
  const clientData = JSON.parse(Buffer.from(codec.decode(created.client_data)).toString());
  assert.deepEqual(clientData, { type: "webauthn.create", challenge, origin: "https://github.com", crossOrigin: false });
  // "none" attestation, and nothing of the private key.
  assert.ok(Buffer.from(codec.decode(created.attestation_object)).includes(Buffer.from("none")));
  assert.equal(Object.keys(created).some((k) => /key_value|private/.test(k)), false);

  // Sign-in: the passkey is offered on the site, and only there.
  const list = await channel.request({ cmd: "passkey_list", url: "https://github.com/login", allow: [] });
  assert.deepEqual(list.items.map((p) => [p.item, p.credential, p.user_name]), [["github", created.credential, "camille"]]);
  const elsewhere = await channel.request({ cmd: "passkey_list", url: "https://gitlab.com/login", rp_id: null, allow: [] });
  assert.deepEqual(elsewhere.items, []);
  const foreignRp = await channel.request({ cmd: "passkey_list", url: "https://evil.example/", rp_id: "github.com", allow: [] });
  assert.equal(foreignRp.result, "denied");

  for (const expected of [1, 2]) {
    const used = await channel.request({
      cmd: "passkey_get", url: "https://github.com/login", rp_id: "github.com", item: "github",
      credential: created.credential, challenge, uv: false,
    });
    assert.equal(used.result, "assertion", JSON.stringify(used));
    assert.equal(counterOf(used), expected, "the counter moves forward");
    assert.equal(await verify(created.public_key, used), true, "valid ES256 signature");
    assert.equal(Buffer.from(codec.decode(used.user_handle)).toString(), "id-camille");
    assert.equal(JSON.parse(Buffer.from(codec.decode(used.client_data)).toString()).type, "webauthn.get");
    // The credential returned to the page, from the reply.
    const credential = codec.assertionCredential(used);
    assert.equal(credential.id, created.credential);
  }

  // Another page can't get it to sign.
  const stolen = await channel.request({
    cmd: "passkey_get", url: "https://github.com.evil.example/", rp_id: null, item: "github",
    credential: created.credential, challenge, uv: false,
  });
  assert.equal(stolen.result, "denied");

  // The site excludes it: it is already there.
  const again = await channel.request({ cmd: "passkey_targets", url: page, exclude: [created.credential] });
  assert.equal(again.excluded, true);
  assert.equal(again.logins[0].has_passkey, true);
  const duplicate = await channel.request({
    cmd: "passkey_create", url: page, user_id: "AQID", challenge, exclude: [created.credential],
  });
  assert.equal(duplicate.result, "denied");
  assert.equal(duplicate.reason, "this passkey is already in Verrou");

  // New login, for a site the vault doesn't know.
  const fresh = await channel.request({
    cmd: "passkey_create", url: "http://localhost:8000/inscription", user_id: "AQID",
    user_name: "dominique", challenge, algorithms: [], uv: false,
  });
  assert.equal(fresh.result, "registration", JSON.stringify(fresh));
  assert.match(fresh.item, /^nouveau-/);

  // PRF: outputs at creation, the same at sign-in for the same input,
  // others for another input.
  const salt = (text) => codec.encode(new TextEncoder().encode(text));
  const withPrf = await channel.request({
    cmd: "passkey_create", url: "https://prf.example/inscription", user_id: "Ag", user_name: "prf",
    challenge, algorithms: [-7], uv: true, prf: { eval: { first: salt("sel-1"), second: salt("sel-2") } },
  });
  assert.equal(withPrf.result, "registration", JSON.stringify(withPrf));
  assert.equal(withPrf.prf.enabled, true);
  assert.equal(codec.decode(withPrf.prf.results.first).byteLength, 32);
  assert.notEqual(withPrf.prf.results.first, withPrf.prf.results.second);
  const prfGet = (prf) => channel.request({
    cmd: "passkey_get", url: "https://prf.example/connexion", item: withPrf.item,
    credential: withPrf.credential, challenge, uv: true, prf,
  });
  const same = await prfGet({ eval: { first: salt("sel-1") } });
  assert.equal(same.result, "assertion", JSON.stringify(same));
  assert.equal(same.prf.first, withPrf.prf.results.first, "same input, same output");
  assert.equal(same.prf.second, undefined);
  const byCredential = await prfGet({
    eval: { first: salt("sel-1") }, eval_by_credential: { [withPrf.credential]: { first: salt("sel-3") } },
  });
  assert.notEqual(byCredential.prf.first, withPrf.prf.results.first, "evalByCredential takes precedence");
  const plain = await prfGet(undefined);
  assert.equal(plain.prf, undefined);
  const local = await channel.request({ cmd: "passkey_list", url: "http://localhost:8000/connexion", allow: [fresh.credential] });
  assert.deepEqual(local.items.map((p) => p.item), [fresh.item]);
  channel.disconnect();
});
