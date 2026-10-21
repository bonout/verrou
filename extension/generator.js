// The extension's password generator, same rules as Verrou's
// (crates/verrou-core/src/generator.rs): 20 characters, at least one of each
// class, without ambiguous characters (l, I, O, 0, 1).
//
// Classic script (not a module): it is loaded before content.js in the
// pages, and by the tests in an isolated context.

(() => {
  const CLASSES = [
    "abcdefghijkmnopqrstuvwxyz",
    "ABCDEFGHJKLMNPQRSTUVWXYZ",
    "23456789",
    "!@#$%^&*-_=+?",
  ];

  // Uniform integer in [0, n), without bias (draws rejected beyond the last
  // multiple of n).
  function randomBelow(n) {
    const limit = Math.floor(0x1_0000_0000 / n) * n;
    const word = new Uint32Array(1);
    do {
      crypto.getRandomValues(word);
    } while (word[0] >= limit);
    return word[0] % n;
  }

  function password(length = 20) {
    const pool = CLASSES.join("");
    const chars = CLASSES.map((set) => set[randomBelow(set.length)]);
    while (chars.length < length) chars.push(pool[randomBelow(pool.length)]);
    for (let i = chars.length - 1; i > 0; i -= 1) {
      const j = randomBelow(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join("");
  }

  globalThis.verrouGenerator = Object.freeze({ password, CLASSES });
})();
