// The browser running the extension: Brave, Chrome, Firefox, Safira and others.
//
// The extension APIs: `browser` when it exists (Firefox, Chromium 148 and
// later; promises everywhere), otherwise `chrome`. The content scripts
// (classic scripts, not modules) make the same choice in their function, the
// same way: `browser` could there be an element of the page
// (`id="browser"`), hence the test on `runtime.id`.
//
// Firefox is recognized by its manifest (`browser_specific_settings.gecko`,
// added by scripts/firefox-extension.sh): no user agent sniffing.

export const ext = globalThis.browser?.runtime?.id ? globalThis.browser : globalThis.chrome;

export const firefox = Boolean(ext.runtime.getManifest().browser_specific_settings?.gecko);

// The name announced to Verrou when pairing, shown in its settings. From
// standard APIs, not the user agent string: the scheme of the extension's own
// pages (Safira, built on WebKit's WKWebExtension, serves them from
// `webkit-extension://`; Safari from `safari-web-extension://`), then
// Chromium's `navigator.userAgentData` brands (and `navigator.brave`, which
// Brave adds).
export function detectBrowser({ firefox = false, url = "", navigator = {} } = {}) {
  if (firefox || url.startsWith("moz-extension:")) return "Firefox";
  if (url.startsWith("webkit-extension:")) return "Safira";
  if (url.startsWith("safari-web-extension:")) return "Safari";
  if (navigator.brave) return "Brave";
  const brands = (navigator.userAgentData?.brands ?? []).map((entry) => entry.brand);
  const named = [
    ["Brave", "Brave"],
    ["Microsoft Edge", "Edge"],
    ["Opera", "Opera"],
    ["Google Chrome", "Chrome"],
  ].find(([brand]) => brands.includes(brand));
  return named ? named[1] : "Chromium";
}

export const browserName = detectBrowser({
  firefox,
  url: ext.runtime.getURL(""),
  navigator: globalThis.navigator,
});

// Text of the interface in the browser's language (extension/_locales).
export const t = (name, ...substitutions) => ext.i18n.getMessage(name, substitutions.map(String));
