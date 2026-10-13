// Générateur de mots de passe de l'extension, mêmes règles que celui de
// Verrou (crates/verrou-core/src/generator.rs) : 20 caractères, au moins un
// de chaque classe, sans caractères ambigus (l, I, O, 0, 1).
//
// Script classique (pas un module) : il est chargé avant content.js dans les
// pages, et par les tests dans un contexte isolé.

(() => {
  const CLASSES = [
    "abcdefghijkmnopqrstuvwxyz",
    "ABCDEFGHJKLMNPQRSTUVWXYZ",
    "23456789",
    "!@#$%^&*-_=+?",
  ];

  // Entier uniforme dans [0, n), sans biais (tirages rejetés au-delà du
  // dernier multiple de n).
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
