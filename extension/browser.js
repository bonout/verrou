// The browser running the extension: Brave (and Chrome) or Firefox.
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

// The name announced to Verrou when pairing, shown in its settings.
export const browserName = firefox ? "Firefox" : "Brave";

// Text of the interface in the browser's language (extension/_locales).
export const t = (name, ...substitutions) => ext.i18n.getMessage(name, substitutions.map(String));
