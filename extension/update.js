// Mise à jour de l'extension livrée avec Verrou.
//
// L'extension est chargée « non empaquetée » depuis Verrou.app : quand l'app
// est mise à jour, les fichiers changent sur le disque, mais le navigateur garde
// l'ancien code en mémoire jusqu'à ce qu'on la recharge. On compare donc la
// version qui tourne à celle du manifest.json sur le disque, et à celle
// qu'annonce Verrou ; si elles diffèrent,
// `runtime.reload()` relit l'extension depuis le disque.
//
// Firefox : une extension temporaire (about:debugging) se recharge depuis
// son dossier comme dans Brave ; un module signé (.xpi) ne change pas en se
// rechargeant. L'appelant y passe `reloadForBundled: false` : seul un
// changement du manifeste sur le disque recharge, une version différente
// chez Verrou ne fait qu'avertir (`state().mismatch`).
//
// Pas de boucle : une seule tentative par version visée, et au plus une par
// minute, retenues dans `storage.local` (`storage.session` est vidé
// par le rechargement lui-même).
//
// Sans navigateur : les dépendances sont fournies par l'appelant (testé
// dans extension/test/seamless.test.mjs).

export const ATTEMPT_KEY = "reloadAttempt";
export const MIN_INTERVAL_MS = 60_000;

const differs = (a, b) => Boolean(a && b && a !== b);

// running : version qui tourne. readDisk() : version du manifeste sur le
// disque (null si illisible). reload() : recharger. store : { get(), set(v) }
// pour la dernière tentative. busy() : ne pas recharger maintenant
// (appairage en cours…). reloadForBundled : recharger aussi quand seule la
// version annoncée par Verrou diffère (vrai dans Brave).
export function createUpdater({
  running, readDisk, reload, store, busy = () => false, now = Date.now, reloadForBundled = true,
}) {
  let bundled = null;

  async function check({ bridgeVersion } = {}) {
    if (bridgeVersion !== undefined) bundled = bridgeVersion || null;
    let disk = null;
    try {
      disk = (await readDisk()) || null;
    } catch {
      disk = null;
    }
    // Le disque d'abord ; sinon la version de l'app livrée (disque illisible,
    // ou lu depuis un cache). Une extension chargée d'ailleurs se recharge
    // ainsi une fois pour rien, puis la fenêtre de l'extension avertit.
    const target = differs(disk, running) ? disk
      : (reloadForBundled && differs(bundled, running) ? bundled : null);
    if (!target) return { reloading: false, disk, bundled };
    if (busy()) return { reloading: false, deferred: true, target };
    let last = null;
    try {
      last = await store.get();
    } catch {
      last = null;
    }
    if (last?.version === target) return { reloading: false, blocked: "déjà tenté pour cette version", target };
    if (last && now() - last.at < MIN_INTERVAL_MS) return { reloading: false, blocked: "trop tôt", target };
    try {
      await store.set({ version: target, from: running, at: now() });
    } catch {
      // Sans trace de la tentative, pas de rechargement : il pourrait boucler.
      return { reloading: false, blocked: "stockage indisponible", target };
    }
    reload();
    return { reloading: true, target };
  }

  // Pour la fenêtre de l'extension : l'extension et l'app concordent-elles ?
  function state() {
    return { running, bundled, mismatch: differs(bundled, running) };
  }

  return { check, state };
}
