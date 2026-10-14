// La pastille de content.js, sans navigateur : le script tourne dans un faux
// DOM (fake-dom.mjs), le service worker et passkeys.js sont simulés. On
// vérifie quand la pastille vient, ce qu'elle propose, ce qu'elle remplit,
// et que la page ne peut rien déclencher à la place de l'utilisateur.
//
//   node --test extension/test/content.test.mjs

import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

import { createDom } from "./fake-dom.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const source = (name) => readFileSync(`${root}extension/${name}`, "utf8");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function eventually(probe, what, timeout = 3000) {
  const end = Date.now() + timeout;
  for (;;) {
    const value = await probe();
    if (value) return value;
    if (Date.now() > end) throw new Error(`délai dépassé : ${what}`);
    await sleep(10);
  }
}

const LOGINS = [
  { id: "camille", title: "MAIF", username: "camille@exemple.fr", has_totp: false },
  { id: "dominique", title: "MAIF pro", username: "dominique@exemple.fr", has_totp: true },
];

const SECRETS = {
  camille: { username: "camille@exemple.fr", password: "mot-de-passe-camille", totp: null },
  dominique: { username: "dominique@exemple.fr", password: "mot-de-passe-dominique", totp: "123456" },
};

// Le service worker : `state` change en cours de test (verrouillé, puis
// ouvert…). `messages` garde tout ce que le script a demandé.
function fakeBackground({ state = "unlocked", items = LOGINS, cards = [], identities = [] } = {}) {
  const background = {
    state,
    items,
    messages: [],
    async handle(message) {
      background.messages.push(message);
      switch (message.kind) {
        case "suggest":
          return background.state === "unlocked" ? { state: "unlocked", items: background.items } : { state: background.state };
        case "fill":
          return SECRETS[message.item] ? { ok: true, ...SECRETS[message.item] } : { ok: false, state: "error" };
        case "forms":
          return background.state === "unlocked" ? { state: "unlocked", cards, identities } : { state: background.state };
        case "fillForm":
          return { ok: true, data: { kind: "card", cardholder: "Camille Martin", number: "4000000000000005", exp_month: "9", exp_year: "2029", code: "321" } };
        case "pendingSave":
          return {};
        default:
          return { ok: true };
      }
    },
    sent: (kind) => background.messages.filter((m) => m.kind === kind),
  };
  return background;
}

// Une page, ses champs (`build(h)` rend les éléments de <body>), le
// générateur et content.js. `passkeys` : la demande de passkey en attente
// (interface de passkeys.js). `firefox` : l'API `browser`, `chrome` piégé.
function openPage(build, background, { origin = "https://connect.maif.fr", passkeys = null, firefox = false } = {}) {
  const dom = createDom({ origin });
  const { context, document, h } = dom;
  for (const node of [build(h)].flat()) document.body.append(node);
  const onMessage = [];
  const runtime = {
    id: "extension",
    sendMessage: (message) => background.handle(message),
    onMessage: { addListener: (listener) => onMessage.push(listener) },
  };
  if (firefox) {
    context.browser = { runtime };
    context.chrome = { runtime: { id: "extension", sendMessage: () => { throw new Error("chrome.runtime utilisé dans Firefox"); } } };
  } else {
    context.chrome = { runtime };
  }
  if (passkeys) context.__verrouPasskeyMenu = passkeys;
  dom.run(source("generator.js"));
  dom.run(source("content.js"));

  const host = (tag) => document.documentElement.children.find((n) => n.tagName === tag.toUpperCase());
  const pillNode = () => host("verrou-pill")?.shadow?.querySelector(".pill") ?? null;
  const pillText = () => pillNode()?.textContent ?? "";
  const button = (label) => {
    const node = [...(host("verrou-pill")?.shadow?.walk() ?? [])]
      .find((n) => n.tagName === "BUTTON" && n.textContent.includes(label));
    assert.ok(node, `bouton « ${label} » dans « ${pillText()} »`);
    return node;
  };
  return {
    ...dom,
    host,
    pillNode,
    pillText,
    button,
    // Un vrai clic sur un bouton de la pastille.
    press: (label, trusted = true) => dom.fire(button(label), "click", { trusted }),
    deliver: (message) => onMessage.forEach((listener) => listener(message)),
    byId: (id) => document.documentElement.querySelectorAll("input").find((n) => n.id === id),
  };
}

const loginForm = (h) => h("form", { id: "login", action: "/connexion" },
  h("input", { id: "email", type: "email", name: "email", autocomplete: "username" }),
  h("input", { id: "password", type: "password", name: "password", autocomplete: "current-password" }),
  h("button", { id: "submit", type: "submit" }, "Se connecter"));

// MARK: Quand la pastille vient

test("la pastille vient une fois avec un identifiant du site, sans menu sous le champ", async () => {
  const background = fakeBackground();
  const page = openPage(loginForm, background);
  await eventually(() => page.pillText().includes("Se connecter"), "pastille");
  const text = page.pillText();
  assert.match(text, /connect\.maif\.fr/);
  assert.match(text, /camille@exemple\.fr/);
  assert.match(text, /✕/);
  assert.match(text, /Autres identifiants/);
  assert.equal(background.sent("suggest").length, 1);

  // Fixée en haut à gauche, au-dessus de tout, à l'abri des styles de la page.
  const host = page.host("verrou-pill");
  assert.equal(host.style.getPropertyValue("position"), "fixed");
  assert.equal(host.style.getPropertyValue("top"), "16px");
  assert.equal(host.style.getPropertyValue("left"), "16px");
  assert.equal(host.style.getPropertyValue("z-index"), "2147483647");
  assert.equal(host.style.getPropertyPriority("position"), "important");
  assert.equal(host.shadowRoot, null, "shadow DOM fermé");
  assert.equal(page.pillNode().getAttribute("role"), "dialog");

  // Le focus n'a pas bougé ; dans le champ, seule l'icône Verrou.
  assert.equal(page.document.activeElement, page.document.body);
  page.byId("email").focus();
  page.byId("password").focus();
  page.mutate();
  await sleep(500);
  assert.equal(background.sent("suggest").length, 1, "une fois par page, pas à chaque focus");
  assert.equal(page.host("verrou-menu"), undefined, "plus de menu accroché au champ");
  const badge = page.host("verrou-field");
  assert.ok(badge, "icône dans le champ");
  assert.equal(badge.style.getPropertyValue("position"), "absolute");
  assert.equal(badge.style.getPropertyValue("left"), `${350 - 22 - 6}px`, "au bord droit du champ");
});

test("aucun identifiant pour ce site : rien d'office ; l'icône du champ propose un autre identifiant", async () => {
  const background = fakeBackground({ items: [] });
  const page = openPage(loginForm, background);
  await eventually(() => background.sent("suggest").length === 1, "recherche des identifiants");
  await sleep(50);
  assert.equal(page.host("verrou-pill"), undefined);

  page.byId("email").focus();
  const icon = [...page.host("verrou-field").shadow.walk()].find((n) => n.tagName === "BUTTON");
  // Un clic simulé par la page sur l'icône : rien.
  page.fire(icon, "click", { trusted: false });
  await sleep(50);
  assert.equal(page.host("verrou-pill"), undefined);
  page.fire(icon, "click");
  await eventually(() => page.pillText().includes("Remplir avec un autre identifiant"), "liste ouverte");
  assert.match(page.pillText(), /Aucun identifiant pour ce site/);
  page.press("Remplir avec un autre identifiant");
  assert.equal(background.sent("openLinkSite").length, 1, "la fenêtre de l'extension s'ouvre sur le choix");
  assert.equal(page.pillNode(), null);
  // L'icône ferme aussi la pastille.
  page.fire(icon, "click");
  await eventually(() => page.pillNode(), "rouverte");
  page.fire(icon, "click");
  assert.equal(page.pillNode(), null);
});

test("un champ e-mail isolé (lettre d'information) n'appelle pas Verrou", async () => {
  const background = fakeBackground();
  openPage((h) => h("form", {}, h("input", { id: "news", type: "email", name: "email" }), h("button", {}, "S'abonner")), background);
  await sleep(100);
  assert.equal(background.sent("suggest").length, 0);
});

// MARK: Se connecter

test("« Se connecter » remplit l'identifiant et le mot de passe, sans envoyer le formulaire", async () => {
  const background = fakeBackground();
  const page = openPage(loginForm, background);
  let submitted = false;
  page.document.addEventListener("submit", () => { submitted = true; });
  await eventually(() => page.pillText().includes("Se connecter"), "pastille");
  page.press("Se connecter");
  await eventually(() => page.byId("password").value, "remplissage");
  assert.deepEqual(background.sent("fill").map((m) => m.item), ["camille"]);
  assert.equal(page.byId("email").value, "camille@exemple.fr");
  assert.equal(page.byId("password").value, "mot-de-passe-camille");
  assert.equal(page.pillNode(), null, "la pastille s'efface");
  const submit = page.document.documentElement.querySelectorAll("button").find((b) => b.id === "submit");
  assert.equal(page.document.activeElement, submit, "le bouton d'envoi a le focus : Entrée suffit");
  assert.equal(submitted, false);
});

test("connexion en deux étapes : la pastille revient pour l'étape suivante", async () => {
  const background = fakeBackground();
  const page = openPage((h) => h("form", { id: "step" },
    h("input", { id: "user", type: "email", name: "username", autocomplete: "username" }),
    h("button", { type: "submit" }, "Suivant")), background);
  await eventually(() => page.pillText().includes("Se connecter"), "pastille de l'étape 1");
  page.press("Se connecter");
  await eventually(() => page.byId("user").value === "camille@exemple.fr", "identifiant rempli");
  // L'application remplace l'étape : le mot de passe.
  const form = page.document.documentElement.querySelector("form");
  form.textContent = "";
  form.append(page.h("input", { id: "pass", type: "password", autocomplete: "current-password" }), page.h("button", { type: "submit" }, "Se connecter"));
  page.mutate();
  await eventually(() => page.pillText().includes("Se connecter"), "pastille de l'étape 2");
  page.press("Se connecter");
  await eventually(() => page.byId("pass").value === "mot-de-passe-camille", "mot de passe rempli");
});

test("autres identifiants : la liste sous l'onglet, et le choix d'un autre", async () => {
  const background = fakeBackground();
  const page = openPage(loginForm, background);
  await eventually(() => page.pillText().includes("Autres identifiants"), "onglet");
  assert.doesNotMatch(page.pillText(), /dominique/, "liste repliée");
  const tab = page.button("Autres identifiants");
  assert.equal(tab.getAttribute("aria-expanded"), "false");
  page.press("Autres identifiants");
  assert.equal(page.button("Autres identifiants").getAttribute("aria-expanded"), "true");
  const text = page.pillText();
  assert.match(text, /MAIF pro/);
  assert.match(text, /dominique@exemple\.fr/);
  assert.match(text, /Remplir avec un autre identifiant…/);
  assert.doesNotMatch(text, /Générer un mot de passe/, "pas sur une simple connexion");
  page.press("MAIF pro");
  await eventually(() => page.byId("password").value, "remplissage");
  assert.equal(page.byId("email").value, "dominique@exemple.fr");
  assert.equal(page.byId("password").value, "mot-de-passe-dominique");
});

test("élément protégé : la pastille attend la confirmation dans Verrou", async () => {
  const background = fakeBackground();
  let asks = 0;
  const handle = background.handle;
  background.handle = async (message) => {
    if (message.kind === "fill" && asks++ === 0) {
      background.messages.push(message);
      return { ok: false, state: "confirm" };
    }
    return handle(message);
  };
  const page = openPage(loginForm, background);
  await eventually(() => page.pillText().includes("Se connecter"), "pastille");
  page.press("Se connecter");
  await eventually(() => page.pillText().includes("Confirmez dans Verrou"), "attente");
  await eventually(() => page.byId("password").value === "mot-de-passe-camille", "rempli après confirmation", 3000);
  assert.equal(page.pillNode(), null);
});

// MARK: Passkeys

function fakePasskeys(entries) {
  const api = {
    entries: async () => api.state,
    state: entries,
    chosen: [],
    listeners: [],
    choose(credential) {
      api.chosen.push(credential);
      return true;
    },
    subscribe(listener) {
      api.listeners.push(listener);
    },
    notify: () => api.listeners.forEach((listener) => listener()),
  };
  return api;
}

test("demande de passkey en attente : la passkey de Verrou passe en premier", async () => {
  const background = fakeBackground();
  const passkeys = fakePasskeys({ state: "ready", items: [{ item: "camille", credential: "cred-1", user_name: "camille", title: "MAIF" }] });
  const page = openPage(loginForm, background, { passkeys });
  await eventually(() => page.pillText().includes("Se connecter avec une passkey"), "passkey proposée");
  assert.match(page.pillText(), /camille/);
  page.press("Autres identifiants");
  assert.match(page.pillText(), /camille@exemple\.fr/, "les mots de passe restent dans la liste");
  page.press("Se connecter avec une passkey");
  assert.deepEqual(passkeys.chosen, ["cred-1"]);
  assert.equal(background.sent("fill").length, 0, "aucun mot de passe ne sort");
  assert.equal(page.pillNode(), null);
});

test("la passkey arrive après le chargement : la pastille vient la proposer, puis la retire", async () => {
  const background = fakeBackground({ items: [] });
  const passkeys = fakePasskeys({ state: "none" });
  const page = openPage(loginForm, background, { passkeys });
  await eventually(() => background.sent("suggest").length === 1, "recherche");
  await sleep(30);
  assert.equal(page.pillNode(), null);
  passkeys.state = { state: "ready", items: [{ item: "camille", credential: "cred-2", user_name: "camille", title: "MAIF" }] };
  passkeys.notify();
  await eventually(() => page.pillText().includes("Se connecter avec une passkey"), "passkey proposée");
  // La page annule sa demande : la passkey quitte la pastille.
  passkeys.state = { state: "none" };
  passkeys.notify();
  await eventually(() => !page.pillText().includes("passkey"), "passkey retirée");
});

// MARK: Verrou verrouillé

test("Verrou verrouillé : « Déverrouiller », puis les identifiants", async () => {
  const background = fakeBackground({ state: "locked" });
  const page = openPage(loginForm, background);
  await eventually(() => page.pillText().includes("Verrou est verrouillé"), "pastille verrouillée");
  assert.match(page.pillText(), /Déverrouiller/);
  page.press("Déverrouiller");
  await eventually(() => page.pillText().includes("Déverrouillez Verrou"), "attente du déverrouillage");
  assert.equal(background.sent("unlock").length, 1);
  background.state = "unlocked";
  await eventually(() => page.pillText().includes("Se connecter"), "identifiants après déverrouillage", 3000);
  assert.match(page.pillText(), /camille@exemple\.fr/);
});

// MARK: Fermer

test("✕ ferme la pastille pour la page ; Échap aussi, mais pas une touche de la page", async () => {
  const background = fakeBackground();
  const page = openPage(loginForm, background);
  await eventually(() => page.pillNode(), "pastille");
  page.press("✕");
  assert.equal(page.pillNode(), null);
  assert.equal(page.host("verrou-pill"), undefined, "l'hôte quitte la page");
  // Nouveau formulaire, nouvelle étape : plus rien d'office.
  page.document.body.append(page.h("form", {}, page.h("input", { id: "otp", autocomplete: "one-time-code" })));
  page.mutate();
  await sleep(500);
  assert.equal(page.pillNode(), null);

  const other = openPage(loginForm, fakeBackground());
  await eventually(() => other.pillNode(), "pastille");
  other.byId("email").focus();
  other.fire(other.byId("email"), "keydown", { trusted: false, key: "Escape" });
  assert.ok(other.pillNode(), "Échap inventé par la page : rien");
  other.fire(other.byId("email"), "keydown", { key: "Escape" });
  assert.equal(other.pillNode(), null);
});

test("clavier : flèche vers le bas dans le champ, puis Échap ramène au champ", async () => {
  const page = openPage(loginForm, fakeBackground());
  await eventually(() => page.pillNode(), "pastille");
  const email = page.byId("email");
  email.focus();
  const event = page.fire(email, "keydown", { key: "ArrowDown" });
  assert.equal(event.defaultPrevented, true);
  assert.equal(page.host("verrou-pill").shadow.activeElement, page.button("Se connecter"));
  page.fire(page.host("verrou-pill").shadow.activeElement, "keydown", { key: "ArrowRight" });
  assert.equal(page.host("verrou-pill").shadow.activeElement, page.button("✕"));
  page.fire(page.host("verrou-pill").shadow.activeElement, "keydown", { key: "Escape" });
  assert.equal(page.pillNode(), null);
  assert.equal(page.document.activeElement, email);

  // Liste de suggestions du site ouverte : la flèche reste au site.
  const site = openPage(loginForm, fakeBackground());
  await eventually(() => site.pillNode(), "pastille");
  site.byId("email").setAttribute("aria-expanded", "true");
  site.byId("email").focus();
  assert.equal(site.fire(site.byId("email"), "keydown", { key: "ArrowDown" }).defaultPrevented, false);
});

// MARK: La page ne choisit pas

test("les clics inventés par la page ne remplissent rien", async () => {
  const background = fakeBackground();
  const page = openPage(loginForm, background);
  await eventually(() => page.pillNode(), "pastille");
  page.press("Se connecter", false);
  page.button("Se connecter").click();
  page.fire(page.host("verrou-pill"), "click", { trusted: false });
  page.press("Autres identifiants", false);
  page.press("✕", false);
  await sleep(50);
  assert.equal(background.sent("fill").length, 0);
  assert.equal(page.byId("password").value, "");
  assert.ok(page.pillNode(), "toujours là, liste fermée");
  assert.doesNotMatch(page.pillText(), /MAIF pro/);
});

test("remplissage depuis la fenêtre de l'extension : seulement pour l'adresse remplie", async () => {
  const page = openPage(loginForm, fakeBackground({ items: [] }));
  const credentials = { username: "camille@exemple.fr", password: "secret" };
  page.deliver({ kind: "apply", credentials, origin: "https://piege.example" });
  page.deliver({ kind: "apply", credentials });
  assert.equal(page.byId("password").value, "", "autre adresse, ou aucune : rien");
  page.deliver({ kind: "apply", credentials, origin: "https://connect.maif.fr" });
  assert.equal(page.byId("password").value, "secret");
});

// MARK: Inscription, cartes, codes

test("inscription : « Suggérer un mot de passe fort » remplit le mot de passe et sa confirmation", async () => {
  const background = fakeBackground({ items: [] });
  const page = openPage((h) => h("form", { id: "signup", action: "/inscription" },
    h("input", { id: "new-email", type: "email", name: "email" }),
    h("input", { id: "new-password", type: "password", name: "password", autocomplete: "new-password" }),
    h("input", { id: "confirm", type: "password", name: "confirm", autocomplete: "new-password" }),
    h("button", { type: "submit" }, "Créer mon compte")), background);
  await sleep(50);
  assert.equal(page.pillNode(), null, "rien d'office avant le champ");
  page.byId("new-password").focus();
  await eventually(() => page.pillText().includes("Suggérer un mot de passe fort"), "suggestion");
  page.press("Suggérer un mot de passe fort");
  const value = page.byId("new-password").value;
  assert.equal(value.length, 20);
  assert.equal(page.byId("confirm").value, value);
  // Une fois par page.
  page.byId("new-email").focus();
  page.byId("confirm").focus();
  await sleep(50);
  assert.equal(page.pillNode(), null);
});

test("connexion sur une page d'inscription : « Générer un mot de passe » dans la liste", async () => {
  const page = openPage((h) => h("form", { id: "both" },
    h("input", { id: "email", type: "email", autocomplete: "username" }),
    h("input", { id: "current", type: "password", autocomplete: "current-password" }),
    h("input", { id: "fresh", type: "password", autocomplete: "new-password" }),
    h("button", { type: "submit" }, "Valider")), fakeBackground());
  await eventually(() => page.pillNode(), "pastille");
  page.press("Autres identifiants");
  page.press("Générer un mot de passe");
  assert.equal(page.byId("fresh").value.length, 20);
  assert.equal(page.byId("current").value, "");
});

test("formulaire de paiement : « Remplir la carte Visa •••• 0005 », les autres cartes sous l'onglet", async () => {
  const background = fakeBackground({
    cards: [{ id: "visa", title: "Carte perso", subtitle: "Visa •••• 0005" }, { id: "amex", title: "Carte pro", subtitle: "Amex •••• 1000" }],
  });
  const page = openPage((h) => h("form", { id: "card" },
    h("input", { id: "cc", name: "cardnumber" }),
    h("input", { id: "name", name: "cc-name", autocomplete: "cc-name" }),
    h("input", { id: "year", name: "exp-year", maxLength: 2 }),
    h("input", { id: "cvc", name: "cvc" })), background, { origin: "https://boutique.exemple.fr" });
  await sleep(50);
  assert.equal(background.sent("forms").length, 0, "rien avant le champ");
  page.byId("cc").focus();
  await eventually(() => page.pillText().includes("Remplir la carte Visa •••• 0005"), "carte proposée");
  page.press("Autres cartes");
  assert.match(page.pillText(), /Carte pro/);
  page.press("Remplir la carte Visa •••• 0005");
  await eventually(() => page.byId("cc").value, "carte remplie");
  assert.deepEqual(background.sent("fillForm").map((m) => m.item), ["visa"]);
  assert.deepEqual(["cc", "name", "year", "cvc"].map((id) => page.byId(id).value), ["4000000000000005", "Camille Martin", "29", "321"]);
});

test("code de vérification : la pastille propose le code, pas quand Verrou est verrouillé", async () => {
  const otpForm = (h) => h("form", {}, h("input", { id: "otp", autocomplete: "one-time-code", maxLength: 6 }), h("button", { type: "submit" }, "Valider"));
  const page = openPage(otpForm, fakeBackground());
  await eventually(() => page.pillText().includes("Remplir le code"), "code proposé");
  assert.match(page.pillText(), /dominique@exemple\.fr/, "seulement les identifiants avec un code");
  page.press("Remplir le code");
  await eventually(() => page.byId("otp").value === "123456", "code rempli");

  const locked = fakeBackground({ state: "locked" });
  const quiet = openPage(otpForm, locked);
  await eventually(() => locked.sent("suggest").length === 1, "recherche");
  await sleep(30);
  assert.equal(quiet.pillNode(), null);
});

// MARK: Enregistrement

test("le bandeau d'enregistrement au même coin que la pastille", async () => {
  const background = fakeBackground({ items: [] });
  const handle = background.handle;
  background.handle = async (message) => (message.kind === "pendingSave"
    ? { action: "save", username: "camille@exemple.fr", site: "connect.maif.fr" }
    : handle(message));
  const page = openPage(loginForm, background);
  const banner = () => page.host("verrou-pill")?.shadow?.querySelector(".banner");
  await eventually(banner, "bandeau");
  assert.match(banner().textContent, /Enregistrer dans Verrou \?/);
  assert.equal(page.host("verrou-pill").style.getPropertyValue("left"), "16px");
  page.press("Enregistrer", false);
  await sleep(20);
  assert.equal(background.sent("confirmSave").length, 0, "clic inventé : rien");
  page.press("Pas maintenant");
  await eventually(() => !banner(), "bandeau fermé");
});

// MARK: Firefox

test("Firefox : la même pastille, par l'API `browser`", async () => {
  const background = fakeBackground();
  const page = openPage(loginForm, background, { firefox: true });
  await eventually(() => page.pillText().includes("Se connecter"), "pastille");
  page.press("Se connecter");
  await eventually(() => page.byId("password").value === "mot-de-passe-camille", "remplissage");
});
