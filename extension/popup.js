// Fenêtre de l'extension : état de la liaison avec Verrou, appairage,
// identifiants de l'onglet en cours, et ajout d'un code de vérification.

import { ext, firefox } from "./browser.js";
import { canReadQrCodes, otpauthFrom } from "./qr.js";

const main = document.getElementById("main");
const stateLabel = document.getElementById("state");
const send = (message) => ext.runtime.sendMessage(message);

// Ouverte par « Remplir avec un autre identifiant… » de la pastille dans la
// page (background.js, `openLinkSite`) : l'onglet et le cadre à relier,
// pris une seule fois, s'ils sont tout frais.
const linkIntent = (async () => {
  try {
    const { linkIntent: intent } = await ext.storage.session.get("linkIntent");
    if (!intent) return null;
    await ext.storage.session.remove("linkIntent");
    return Date.now() - intent.at < 60_000 ? intent : null;
  } catch {
    return null;
  }
})();
let linkIntentShown = false;

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
      let result = await send({ kind: "fillTab", item: item.id });
      // Élément protégé : confirmation dans Verrou, puis nouvel essai.
      for (let tries = 0; result?.state === "confirm" && tries < 60; tries += 1) {
        stateLabel.textContent = "Confirmez dans Verrou…";
        await new Promise((resolve) => setTimeout(resolve, 1000));
        result = await send({ kind: "fillTab", item: item.id });
      }
      if (result?.ok) window.close();
      else stateLabel.textContent = "Déverrouillé";
    });
    list.append(row);
  }
  const other = element("button", { className: "link", textContent: "Remplir avec un autre identifiant…" });
  other.addEventListener("click", () => renderOtherLogin());
  const scan = element("button", { className: "secondary", textContent: "Ajouter le QR code affiché" });
  scan.addEventListener("click", () => scanQrCode(items));
  const manual = element("button", { className: "link", textContent: "ou saisir la clé à la main" });
  manual.addEventListener("click", () => enterKey(items));
  show(
    items.length ? list : element("p", { textContent: "Aucun identifiant pour ce site." }),
    other,
    element("div", { className: "section" },
      element("div", { className: "section-title", textContent: "Double authentification" }),
      element("p", { textContent: "Le site affiche un QR code pour une app d'authentification : Verrou peut le garder et générer les codes." }),
      scan, manual),
    unpairLink(),
  );
}

// MARK: Autre identifiant

// Un site que Verrou ne relie à aucun identifiant (nouveau domaine, site de
// connexion unique…) : on en choisit un, Verrou lui ajoute ce site, puis
// remplit comme d'habitude. Le site reste ensuite associé.
// `target` : l'onglet et le cadre de la pastille ; sinon l'onglet actif.
async function renderOtherLogin(target = null) {
  const url = target?.url ?? (await ext.tabs.query({ active: true, currentWindow: true }))[0]?.url;
  let host = "";
  try {
    host = new URL(url ?? "").hostname;
  } catch {
    // Page sans adresse (onglet système) : rien à relier.
  }
  const input = element("input", { type: "text", placeholder: "Rechercher un identifiant", autocomplete: "off", spellcheck: false });
  const results = element("ul");
  const search = async () => {
    const reply = await send({ kind: "searchLogins", query: input.value });
    results.replaceChildren(...(reply.items ?? []).map((item) => {
      const row = element("li", {},
        element("div", { className: "badge", textContent: (item.title.trim()[0] ?? "?").toUpperCase() }),
        element("div", {},
          element("div", { className: "title", textContent: item.title }),
          element("div", { className: "sub", textContent: item.username })));
      row.addEventListener("click", () => confirmLink(item, host, target));
      return row;
    }));
  };
  let debounce;
  input.addEventListener("input", () => {
    clearTimeout(debounce);
    debounce = setTimeout(search, 150);
  });
  show(
    element("p", { textContent: `Choisissez l'identifiant à utiliser sur ${host || "ce site"}.` }),
    input, results, backLink(),
  );
  input.focus();
  search();
}

function confirmLink(item, host, target) {
  const go = element("button", { textContent: "Ajouter et remplir" });
  go.addEventListener("click", async () => {
    go.disabled = true;
    const result = await send({ kind: "linkSiteTab", item: item.id, target });
    if (result?.ok) window.close();
    else show(element("p", { className: "error", textContent: `Impossible : ${result?.reason ?? "Verrou ne répond pas"}` }), backLink());
  });
  show(
    element("p", { textContent: `Ajouter ${host} à « ${item.title} » ? Verrou le proposera ensuite sur ce site. Vérifiez bien l'adresse : un site d'hameçonnage imite souvent celui qu'il vise.` }),
    go, backLink(),
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

// Avertissement en tête de la fenêtre.
function warning(title, text) {
  return element("div", { className: "warning", role: "alert" },
    element("strong", { textContent: title }), element("span", { textContent: text }));
}

// L'extension qui tourne n'est pas celle que livre Verrou : elle s'est
// rechargée sans changer (chargée depuis un autre dossier), ou va le faire.
// Firefox ne la recharge pas pour une version annoncée par Verrou (voir
// update.js) : on dit comment charger la bonne.
function versionWarning(extension) {
  if (!extension?.mismatch) return null;
  const how = firefox
    ? "Dans about:debugging › Ce Firefox, rechargez-la, ou chargez le manifest.json du dossier "
      + "« extension-firefox » de Verrou.app (Réglages de Verrou › Navigateurs et terminal › "
      + "Extension Firefox › Copier le chemin). Module installé (.xpi) : installez celui de la nouvelle version."
    : "Dans brave://extensions, chargez le dossier « extension » de Verrou.app "
      + "(Réglages de Verrou › Navigateurs et terminal › Copier le chemin), ou rechargez-la.";
  return warning("L'extension n'est pas celle de Verrou",
    `Elle est en version ${extension.running}, Verrou livre la ${extension.bundled}. ${how}`);
}

// MARK: Accès aux sites (Firefox)
//
// Firefox laisse l'utilisateur accorder ou retirer l'accès aux sites d'une
// extension Manifest V3 (`host_permissions`) : sans lui, ni pastille dans
// les pages, ni passkeys. Brave l'accorde à l'installation : rien à demander.

function siteOrigins() {
  return ext.runtime.getManifest().host_permissions ?? [];
}

async function missingSiteAccess() {
  if (!firefox) return false;
  const origins = siteOrigins();
  if (!origins.length) return false;
  try {
    return !(await ext.permissions.contains({ origins }));
  } catch {
    return false;
  }
}

function siteAccessRequest() {
  const button = element("button", { textContent: "Autoriser Verrou sur les sites" });
  const note = element("p", { className: "hint" });
  button.addEventListener("click", () => {
    // Appel direct dans le clic : Firefox n'accepte la demande que pendant
    // le geste de l'utilisateur.
    ext.permissions.request({ origins: siteOrigins() })
      .then((granted) => {
        if (granted) {
          note.textContent = "Accès accordé : rechargez les pages déjà ouvertes.";
          scheduleRender();
        } else {
          note.textContent = "Accès refusé : Verrou ne pourra rien remplir.";
        }
      })
      .catch((error) => { note.textContent = `Demande impossible : ${error.message}`; });
  });
  return element("div", { className: "warning", role: "alert" },
    element("strong", { textContent: "Verrou n'a pas accès aux sites" }),
    element("span", { textContent: "Firefox demande votre accord pour que l'extension remplisse vos identifiants et propose vos passkeys sur les pages." }),
    button, note);
}

async function render() {
  const { pairing } = await ext.storage.session.get("pairing");
  if (renderPairing(pairing)) return;
  const status = await send({ kind: "status" });
  const versionNote = versionWarning(status.extension);
  const accessNote = (await missingSiteAccess()) ? siteAccessRequest() : null;
  switch (status.state) {
    case "unpaired":
      await renderUnpaired(pairing?.state === "failed" ? pairing.error : null);
      break;
    case "offline":
      stateLabel.textContent = "Hors ligne";
      show(
        warning("Verrou n'est pas joignable",
          "Ouvrez l'app et activez « Brave, Firefox et le terminal » dans ses réglages. "
          + "D'ici là, ni remplissage ni passkeys : le navigateur reprend la main."),
        unpairLink(),
      );
      break;
    case "locked": {
      stateLabel.textContent = "Verrouillé";
      const button = element("button", { textContent: "Déverrouiller Verrou" });
      button.addEventListener("click", () => send({ kind: "unlock" }));
      show(element("p", { textContent: "Verrou est verrouillé." }), button);
      break;
    }
    default: {
      const intent = await linkIntent;
      if (intent && !linkIntentShown) {
        linkIntentShown = true;
        await renderOtherLogin(intent);
      } else {
        await renderUnlocked();
      }
    }
  }
  if (versionNote) main.prepend(versionNote);
  if (accessNote) main.prepend(accessNote);
}

// Un rendu à la fois : les étapes d'appairage arrivent en rafale.
let rendering = Promise.resolve();
function scheduleRender() {
  rendering = rendering.then(render, render);
}

ext.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && changes.pairing) scheduleRender();
});

scheduleRender();
