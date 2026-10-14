// Le navigateur qui fait tourner l'extension : Brave (et Chrome) ou Firefox.
//
// Les API d'extension : `browser` quand il existe (Firefox, Chromium 148 et
// suivants ; promesses partout), sinon `chrome`. Les scripts de contenu
// (classiques, pas des modules) refont ce choix dans leur fonction, sur le
// même modèle : `browser` pourrait y désigner un élément de la page
// (`id="browser"`), d'où le test sur `runtime.id`.
//
// Firefox se reconnaît à son manifeste (`browser_specific_settings.gecko`,
// ajouté par scripts/firefox-extension.sh) : pas de détection par
// l'agent utilisateur.

export const ext = globalThis.browser?.runtime?.id ? globalThis.browser : globalThis.chrome;

export const firefox = Boolean(ext.runtime.getManifest().browser_specific_settings?.gecko);

// Le nom annoncé à Verrou à l'appairage, affiché dans ses réglages.
export const browserName = firefox ? "Firefox" : "Brave";
