// Update of the extension shipped with Verrou.
//
// The extension is loaded "unpacked" from Verrou.app: when the app is
// updated, the files change on disk, but the browser keeps the old code in
// memory until the extension is reloaded. So we compare the running version
// with the one in manifest.json on disk, and with the one Verrou
// announces; if they differ,
// `runtime.reload()` reads the extension again from disk.
//
// Firefox: a temporary extension (about:debugging) reloads from its folder
// as in Brave; a signed add-on (.xpi) doesn't change when it reloads. The
// caller passes `reloadForBundled: false` there: only a change of the
// manifest on disk reloads, a different version from Verrou only warns
// (`state().mismatch`).
//
// No loop: a single attempt per target version, and at most one per
// minute, kept in `storage.local` (`storage.session` is cleared by the
// reload itself).
//
// No browser: the dependencies are provided by the caller (tested in
// extension/test/seamless.test.mjs).

export const ATTEMPT_KEY = "reloadAttempt";
export const MIN_INTERVAL_MS = 60_000;

const differs = (a, b) => Boolean(a && b && a !== b);

// running: the running version. readDisk(): the version of the manifest on
// disk (null if unreadable). reload(): reload. store: { get(), set(v) } for
// the last attempt. busy(): don't reload now (pairing in progress…).
// reloadForBundled: also reload when only the version announced by Verrou
// differs (true in Brave).
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
    // The disk first; otherwise the version of the shipped app (disk
    // unreadable, or read from a cache). An extension loaded from elsewhere
    // thus reloads once for nothing, then the extension's popup warns.
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
    if (last?.version === target) return { reloading: false, blocked: "already tried for this version", target };
    if (last && now() - last.at < MIN_INTERVAL_MS) return { reloading: false, blocked: "too soon", target };
    try {
      await store.set({ version: target, from: running, at: now() });
    } catch {
      // Without a record of the attempt, no reload: it could loop.
      return { reloading: false, blocked: "storage unavailable", target };
    }
    reload();
    return { reloading: true, target };
  }

  // For the extension's popup: do the extension and the app match?
  function state() {
    return { running, bundled, mismatch: differs(bundled, running) };
  }

  return { check, state };
}
