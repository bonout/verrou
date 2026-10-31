// The extension's popup: state of the link with Verrou, pairing, logins of
// the current tab, and adding a verification code.

import { ext, firefox, t } from "./browser.js";
import { canReadQrCodes, otpauthFrom } from "./qr.js";

const main = document.getElementById("main");
const stateLabel = document.getElementById("state");
const send = (message) => ext.runtime.sendMessage(message);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const STATUS_TIMEOUT_MS = 3000;
document.documentElement.lang = ext.i18n.getUILanguage();

// Opened by "Fill with another login…" in the pill in the page
// (background.js, `openLinkSite`): the tab and frame to link, taken only
// once, if they are fresh.
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

let view = {};
function show(...nodes) {
  view = {};
  main.replaceChildren(...nodes);
}

function row(title, subtitle, lead, action) {
  const button = element("button", { type: "button", className: "row" },
    lead,
    element("div", { className: "text" },
      element("div", { className: "title", textContent: title }),
      element("div", { className: "sub", textContent: subtitle ?? "" })));
  button.addEventListener("click", action);
  return element("li", {}, button);
}

const badge = (title) => element("div", { className: "badge", textContent: (title.trim()[0] ?? "?").toUpperCase() });

function renderConnecting() {
  stateLabel.textContent = t("popupConnecting");
  show(element("p", { textContent: t("popupConnectingToVerrou") }));
}

function renderPairing(pairing) {
  if (pairing?.state === "waiting") {
    stateLabel.textContent = t("popupPairing");
    show(
      element("p", { textContent: t("popupCheckCode") }),
      element("div", { className: "code", textContent: pairing.code }),
      element("p", { textContent: t("popupCodesDiffer") }),
    );
    return true;
  }
  if (pairing?.state === "connecting") {
    renderConnecting();
    return true;
  }
  return false;
}

async function renderUnpaired(error) {
  stateLabel.textContent = t("popupUnpaired");
  const button = element("button", { textContent: t("popupPair") });
  button.addEventListener("click", async () => renderPairing(await send({ kind: "pair" })));
  show(
    element("p", { textContent: t("popupPairIntro") }),
    ...(error ? [element("p", { className: "error", textContent: error })] : []),
    button,
  );
}

async function renderUnlocked() {
  stateLabel.textContent = t("popupUnlocked");
  const reply = await send({ kind: "suggestTab" });
  const items = reply.items ?? [];
  const list = element("ul");
  for (const item of items) {
    list.append(row(item.title, item.username, badge(item.title), async () => {
      let result = await send({ kind: "fillTab", item: item.id });
      // Protected item: confirmation in Verrou, then a new attempt.
      for (let tries = 0; result?.state === "confirm" && tries < 60; tries += 1) {
        stateLabel.textContent = t("confirmInVerrouWait");
        await sleep(1000);
        result = await send({ kind: "fillTab", item: item.id });
      }
      if (result?.ok) window.close();
      else stateLabel.textContent = t("popupUnlocked");
    }));
  }
  const other = element("button", { className: "link", textContent: t("otherLogin") });
  other.addEventListener("click", () => renderOtherLogin());
  const scan = element("button", { className: "secondary", textContent: t("popupScanQr") });
  scan.addEventListener("click", () => scanQrCode(items));
  const manual = element("button", { className: "link", textContent: t("popupEnterKeyLink") });
  manual.addEventListener("click", () => enterKey(items));
  show(
    items.length ? list : element("p", { textContent: t("popupNoLogins") }),
    other,
    element("div", { className: "section" },
      element("div", { className: "section-title", textContent: t("popupTwoFactor") }),
      element("p", { textContent: t("popupTwoFactorIntro") }),
      scan, manual),
    await autoSubmitSetting(),
    unpairLink(),
  );
}

// MARK: Settings

// "Submit the form after filling" (on by default): read by content.js after
// a fill chosen by the user. Never for a card, an address or a generated
// password.
async function autoSubmitSetting() {
  let enabled = true;
  try {
    enabled = (await ext.storage.local.get("autoSubmit")).autoSubmit !== false;
  } catch {
    // Unreadable setting: the default value.
  }
  const box = element("input", { type: "checkbox", id: "auto-submit", checked: enabled });
  box.setAttribute("aria-describedby", "auto-submit-hint");
  box.addEventListener("change", () => {
    ext.storage.local.set({ autoSubmit: box.checked }).catch(() => {});
  });
  return element("div", { className: "section" },
    element("label", { className: "toggle", htmlFor: "auto-submit" }, box,
      element("span", { textContent: t("popupAutoSubmit") })),
    element("p", { className: "sub", id: "auto-submit-hint",
      textContent: t("popupAutoSubmitHint") }));
}

// MARK: Another login

// A site that Verrou links to no login (new domain, single sign-on site…):
// one is chosen, Verrou adds this site to it, then fills as usual. The site
// then stays associated.
// `target`: the tab and frame of the pill; otherwise the active tab.
async function renderOtherLogin(target = null) {
  const url = target?.url ?? (await ext.tabs.query({ active: true, currentWindow: true }))[0]?.url;
  let host = "";
  try {
    host = new URL(url ?? "").hostname;
  } catch {
    // Page without an address (system tab): nothing to link.
  }
  const input = element("input", { type: "text", placeholder: t("popupSearchLogin"), autocomplete: "off", spellcheck: false });
  const results = element("ul");
  const search = async () => {
    const reply = await send({ kind: "searchLogins", query: input.value });
    results.replaceChildren(...(reply.items ?? []).map((item) =>
      row(item.title, item.username, badge(item.title), () => confirmLink(item, host, target))));
  };
  let debounce;
  input.addEventListener("input", () => {
    clearTimeout(debounce);
    debounce = setTimeout(search, 150);
  });
  show(
    element("p", { textContent: t("popupChooseLogin", host || t("popupThisSite")) }),
    input, results, backLink(),
  );
  input.focus();
  search();
}

function confirmLink(item, host, target) {
  const go = element("button", { textContent: t("popupAddAndFill") });
  go.addEventListener("click", async () => {
    go.disabled = true;
    const result = await send({ kind: "linkSiteTab", item: item.id, target });
    if (result?.ok) window.close();
    else show(element("p", { className: "error", textContent: t("popupFailed", result?.reason ?? t("verrouNotResponding")) }), backLink());
  });
  show(
    element("p", { textContent: t("popupConfirmLink", host, item.title) }),
    go, backLink(),
  );
}

// MARK: Verification code

// The `otpauth://totp/…` URI of the QR code visible in the tab, if there is one.
async function readQrCode() {
  if (!canReadQrCodes()) throw new Error(t("popupQrUnsupported"));
  const capture = await send({ kind: "captureTab" });
  if (!capture?.ok) throw new Error(t("popupCaptureFailed", capture?.reason ?? "?"));
  return otpauthFrom(await (await fetch(capture.image)).blob());
}

async function scanQrCode(items) {
  stateLabel.textContent = t("popupReading");
  try {
    const uri = await readQrCode();
    if (!uri) {
      return renderTotpError(items, t("popupNoQr"));
    }
    renderTotpChoice(items, uri);
  } catch (error) {
    renderTotpError(items, error.message);
  }
}

function renderTotpError(items, message) {
  stateLabel.textContent = t("popupUnlocked");
  const retry = element("button", { textContent: t("popupRetry") });
  retry.addEventListener("click", () => scanQrCode(items));
  const manual = element("button", { className: "link", textContent: t("popupEnterKey") });
  manual.addEventListener("click", () => enterKey(items));
  show(element("p", { className: "error", textContent: message }), retry, manual, backLink());
}

function enterKey(items) {
  const input = element("input", { type: "text", placeholder: "JBSW Y3DP EHPK 3PXP…", autocomplete: "off", spellcheck: false });
  const next = element("button", { textContent: t("popupContinue") });
  const submit = () => {
    const key = input.value.replace(/\s+/g, "");
    if (key) renderTotpChoice(items, key);
  };
  next.addEventListener("click", submit);
  input.addEventListener("keydown", (event) => event.key === "Enter" && submit());
  show(element("p", { textContent: t("popupSecretKey") }), input, next, backLink());
  input.focus();
}

// Readable description of an otpauth URI: "Issuer · account".
function describeTotp(value) {
  try {
    const url = new URL(value);
    const label = decodeURIComponent(url.pathname.replace(/^\/+/, ""));
    const issuer = url.searchParams.get("issuer");
    return [issuer, label.split(":").pop()].filter(Boolean).join(" · ") || t("popupVerificationCode");
  } catch {
    return t("popupEnteredKey");
  }
}

function renderTotpChoice(items, totp) {
  stateLabel.textContent = t("popupUnlocked");
  const choices = [
    ...items.map((item) => ({ id: item.id, title: item.title, sub: item.has_totp ? t("popupReplacesCode", item.username) : item.username })),
    { id: null, title: t("newLogin"), sub: t("popupForThisSite") },
  ];
  // By default: a login without a code, otherwise the first one.
  let chosen = (items.find((item) => !item.has_totp) ?? items[0])?.id ?? null;
  const list = element("ul", { className: "choices" });
  const draw = () => {
    list.replaceChildren(...choices.map((choice) => {
      const line = row(choice.title, choice.sub, element("div", { className: "radio" }), () => {
        chosen = choice.id;
        draw();
        list.querySelectorAll("button")[choices.indexOf(choice)]?.focus();
      });
      line.className = choice.id === chosen ? "chosen" : "";
      line.querySelector("button").setAttribute("aria-pressed", String(choice.id === chosen));
      return line;
    }));
  };
  draw();
  const add = element("button", { textContent: t("popupAddToVerrou") });
  add.addEventListener("click", async () => {
    add.disabled = true;
    const result = await send({ kind: "setTotpTab", totp, item: chosen });
    if (result?.ok) {
      show(element("p", { className: "done", textContent: t("popupCodeAdded") }), backLink());
    } else {
      add.disabled = false;
      show(element("p", { className: "error", textContent: t("popupAddFailed", result?.reason ?? t("verrouNotResponding")) }), backLink());
    }
  });
  show(
    element("div", { className: "code-found", textContent: describeTotp(totp) }),
    element("p", { textContent: t("popupAddCodeTo") }),
    list,
    add,
    backLink(),
  );
}

function backLink() {
  const link = element("button", { className: "link", textContent: t("popupBack") });
  link.addEventListener("click", scheduleRender);
  return link;
}

function unpairLink() {
  const link = element("button", { className: "link", textContent: t("popupUnpair") });
  link.addEventListener("click", async () => {
    await send({ kind: "unpair" });
    renderUnpaired();
  });
  return link;
}

// Warning at the top of the popup.
function warning(title, text) {
  return element("div", { className: "warning", role: "alert" },
    element("strong", { textContent: title }), element("span", { textContent: text }));
}

// The running extension is not the one Verrou ships: it reloaded without
// changing (loaded from another folder), or is about to. Firefox doesn't
// reload it for a version announced by Verrou (see update.js): we say how
// to load the right one.
function versionWarning(extension) {
  if (!extension?.mismatch) return null;
  const how = firefox ? t("popupVersionHowFirefox") : t("popupVersionHowBrave");
  return warning(t("popupVersionTitle"), t("popupVersionText", extension.running, extension.bundled, how));
}

// MARK: Site access (Firefox)
//
// Firefox lets the user grant or withdraw a Manifest V3 extension's access
// to sites (`host_permissions`): without it, no pill in the pages, and no
// passkeys. Brave grants it at install time: nothing to ask.

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
  const button = element("button", { textContent: t("popupAllowSites") });
  const note = element("p", { className: "hint" });
  button.addEventListener("click", () => {
    // Direct call in the click: Firefox only accepts the request during the
    // user's gesture.
    ext.permissions.request({ origins: siteOrigins() })
      .then((granted) => {
        if (granted) {
          note.textContent = t("popupAccessGranted");
          scheduleRender();
        } else {
          note.textContent = t("popupAccessDenied");
        }
      })
      .catch((error) => { note.textContent = t("popupRequestFailed", error.message); });
  });
  return element("div", { className: "warning", role: "alert" },
    element("strong", { textContent: t("popupNoSiteAccess") }),
    element("span", { textContent: t("popupSiteAccessText") }),
    button, note);
}

async function render() {
  const { pairing } = await ext.storage.session.get("pairing");
  if (renderPairing(pairing)) return;
  const answer = send({ kind: "status" }).catch(() => ({ state: "offline" }));
  const status = await Promise.race([answer, sleep(STATUS_TIMEOUT_MS)]);
  if (status) return renderStatus(status, pairing);
  await renderStatus({ state: "offline" }, pairing);
  const shown = view;
  answer.then((late) => {
    rendering = rendering.then(() => (view === shown ? renderStatus(late, pairing) : undefined));
  });
}

async function renderStatus(status, pairing) {
  const versionNote = versionWarning(status.extension);
  const accessNote = (await missingSiteAccess()) ? siteAccessRequest() : null;
  switch (status.state) {
    case "unpaired":
      await renderUnpaired(pairing?.state === "failed" ? pairing.error : null);
      break;
    case "offline":
      stateLabel.textContent = t("popupOffline");
      show(
        warning(t("verrouUnreachable"), t("popupOfflineText", t("settingBridge"))),
        unpairLink(),
      );
      break;
    case "locked": {
      stateLabel.textContent = t("popupLocked");
      const button = element("button", { textContent: t("popupUnlockVerrou") });
      button.addEventListener("click", () => send({ kind: "unlock" }));
      show(element("p", { textContent: t("popupVerrouLocked") }), button);
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

// One render at a time: the pairing steps arrive in bursts.
let rendering = Promise.resolve();
function scheduleRender() {
  rendering = rendering.then(render, render);
}

ext.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && changes.pairing) scheduleRender();
});

renderConnecting();
scheduleRender();
