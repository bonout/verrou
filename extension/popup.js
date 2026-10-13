// Fenêtre de l'extension : état de la liaison avec Verrou, appairage,
// identifiants de l'onglet en cours, et ajout d'un code de vérification.

import { canReadQrCodes, otpauthFrom } from "./qr.js";

const main = document.getElementById("main");
const stateLabel = document.getElementById("state");
const send = (message) => chrome.runtime.sendMessage(message);

function element(tag, props = {}, ...children) {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children);
  return node;
}

function show(...nodes) {
  main.replaceChildren(...nodes);
}

function renderPairing(pairing) {
  if (pairing?.state === "waiting") {
    stateLabel.textContent = "Appairage…";
    show(
      element("p", { textContent: "Vérifiez que Verrou affiche le même code, puis acceptez :" }),
      element("div", { className: "code", textContent: pairing.code }),
      element("p", { textContent: "Si les codes diffèrent, refusez dans Verrou." }),
    );
    return true;
  }
  if (pairing?.state === "connecting") {
    stateLabel.textContent = "Connexion…";
    show(element("p", { textContent: "Connexion à Verrou…" }));
    return true;
  }
  return false;
}

async function renderUnpaired(error) {
  stateLabel.textContent = "Non relié";
  const button = element("button", { textContent: "Relier à Verrou" });
  button.addEventListener("click", async () => renderPairing(await send({ kind: "pair" })));
  show(
    element("p", { textContent: "Reliez l'extension à l'app Verrou de ce Mac pour remplir vos identifiants." }),
    ...(error ? [element("p", { className: "error", textContent: error })] : []),
    button,
  );
}

async function renderUnlocked() {
  stateLabel.textContent = "Déverrouillé";
  const reply = await send({ kind: "suggestTab" });
  const items = reply.items ?? [];
  const list = element("ul");
  for (const item of items) {
    const row = element("li", {},
      element("div", { className: "badge", textContent: (item.title.trim()[0] ?? "?").toUpperCase() }),
      element("div", {},
        element("div", { className: "title", textContent: item.title }),
        element("div", { className: "sub", textContent: item.username })));
    row.addEventListener("click", async () => {
      const result = await send({ kind: "fillTab", item: item.id });
      if (result?.ok) window.close();
    });
    list.append(row);
  }
  const scan = element("button", { className: "secondary", textContent: "Ajouter le QR code affiché" });
  scan.addEventListener("click", () => scanQrCode(items));
  const manual = element("button", { className: "link", textContent: "ou saisir la clé à la main" });
  manual.addEventListener("click", () => enterKey(items));
  show(
    items.length ? list : element("p", { textContent: "Aucun identifiant pour ce site." }),
    element("div", { className: "section" },
      element("div", { className: "section-title", textContent: "Double authentification" }),
      element("p", { textContent: "Le site affiche un QR code pour une app d'authentification : Verrou peut le garder et générer les codes." }),
      scan, manual),
    unpairLink(),
  );
}

// MARK: Code de vérification

// L'URI `otpauth://totp/…` du QR code visible dans l'onglet, s'il y en a un.
async function readQrCode() {
  if (!canReadQrCodes()) throw new Error("ce navigateur ne sait pas lire les QR codes : saisissez la clé à la main");
  const capture = await send({ kind: "captureTab" });
  if (!capture?.ok) throw new Error(`capture de l'onglet impossible (${capture?.reason ?? "?"})`);
  return otpauthFrom(await (await fetch(capture.image)).blob());
}

async function scanQrCode(items) {
  stateLabel.textContent = "Lecture…";
  try {
    const uri = await readQrCode();
    if (!uri) {
      return renderTotpError(items, "Aucun QR code de double authentification visible : faites-le apparaître à l'écran, ou saisissez la clé.");
    }
    renderTotpChoice(items, uri);
  } catch (error) {
    renderTotpError(items, error.message);
  }
}

function renderTotpError(items, message) {
  stateLabel.textContent = "Déverrouillé";
  const retry = element("button", { textContent: "Réessayer" });
  retry.addEventListener("click", () => scanQrCode(items));
  const manual = element("button", { className: "link", textContent: "Saisir la clé à la main" });
  manual.addEventListener("click", () => enterKey(items));
  show(element("p", { className: "error", textContent: message }), retry, manual, backLink());
}

function enterKey(items) {
  const input = element("input", { type: "text", placeholder: "JBSW Y3DP EHPK 3PXP…", autocomplete: "off", spellcheck: false });
  const next = element("button", { textContent: "Continuer" });
  const submit = () => {
    const key = input.value.replace(/\s+/g, "");
    if (key) renderTotpChoice(items, key);
  };
  next.addEventListener("click", submit);
  input.addEventListener("keydown", (event) => event.key === "Enter" && submit());
  show(element("p", { textContent: "La clé secrète affichée par le site (« clé de configuration ») :" }), input, next, backLink());
  input.focus();
}

// Description lisible d'une URI otpauth : « Émetteur · compte ».
function describeTotp(value) {
  try {
    const url = new URL(value);
    const label = decodeURIComponent(url.pathname.replace(/^\/+/, ""));
    const issuer = url.searchParams.get("issuer");
    return [issuer, label.split(":").pop()].filter(Boolean).join(" · ") || "Code de vérification";
  } catch {
    return "Clé saisie";
  }
}

function renderTotpChoice(items, totp) {
  stateLabel.textContent = "Déverrouillé";
  const choices = [
    ...items.map((item) => ({ id: item.id, title: item.title, sub: item.has_totp ? `${item.username} · remplace le code actuel` : item.username })),
    { id: null, title: "Nouvel identifiant", sub: "pour ce site" },
  ];
  // Par défaut : un identifiant sans code, sinon le premier.
  let chosen = (items.find((item) => !item.has_totp) ?? items[0])?.id ?? null;
  const list = element("ul", { className: "choices" });
  const draw = () => {
    list.replaceChildren(...choices.map((choice) => {
      const row = element("li", { className: choice.id === chosen ? "chosen" : "" },
        element("div", { className: "radio" }),
        element("div", {},
          element("div", { className: "title", textContent: choice.title }),
          element("div", { className: "sub", textContent: choice.sub })));
      row.addEventListener("click", () => {
        chosen = choice.id;
        draw();
      });
      return row;
    }));
  };
  draw();
  const add = element("button", { textContent: "Ajouter à Verrou" });
  add.addEventListener("click", async () => {
    add.disabled = true;
    const result = await send({ kind: "setTotpTab", totp, item: chosen });
    if (result?.ok) {
      show(element("p", { className: "done", textContent: "Code ajouté. Verrou génère maintenant les codes de ce site : saisissez le code actuel pour terminer l'activation sur le site." }), backLink());
    } else {
      add.disabled = false;
      show(element("p", { className: "error", textContent: `Ajout impossible : ${result?.reason ?? "Verrou ne répond pas"}` }), backLink());
    }
  });
  show(
    element("div", { className: "code-found", textContent: describeTotp(totp) }),
    element("p", { textContent: "Ajouter ce code de vérification à :" }),
    list,
    add,
    backLink(),
  );
}

function backLink() {
  const link = element("button", { className: "link", textContent: "Retour" });
  link.addEventListener("click", scheduleRender);
  return link;
}

function unpairLink() {
  const link = element("button", { className: "link", textContent: "Délier cette extension" });
  link.addEventListener("click", async () => {
    await send({ kind: "unpair" });
    renderUnpaired();
  });
  return link;
}

async function render() {
  const { pairing } = await chrome.storage.session.get("pairing");
  if (renderPairing(pairing)) return;
  const status = await send({ kind: "status" });
  switch (status.state) {
    case "unpaired":
      return renderUnpaired(pairing?.state === "failed" ? pairing.error : null);
    case "offline":
      stateLabel.textContent = "Hors ligne";
      return show(element("p", { textContent: "Verrou ne répond pas. Ouvrez l'app et activez « Remplissage dans Brave » dans ses réglages." }), unpairLink());
    case "locked": {
      stateLabel.textContent = "Verrouillé";
      const button = element("button", { textContent: "Déverrouiller Verrou" });
      button.addEventListener("click", () => send({ kind: "unlock" }));
      return show(element("p", { textContent: "Verrou est verrouillé." }), button);
    }
    default:
      return renderUnlocked();
  }
}

// Un rendu à la fois : les étapes d'appairage arrivent en rafale.
let rendering = Promise.resolve();
function scheduleRender() {
  rendering = rendering.then(render, render);
}

chrome.storage.session.onChanged.addListener((changes) => {
  if (changes.pairing) scheduleRender();
});

scheduleRender();
