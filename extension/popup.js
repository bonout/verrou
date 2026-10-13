// Fenêtre de l'extension : état de la liaison avec Verrou, appairage, et
// identifiants de l'onglet en cours.

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
  show(
    items.length ? list : element("p", { textContent: "Aucun identifiant pour ce site." }),
    unpairLink(),
  );
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
