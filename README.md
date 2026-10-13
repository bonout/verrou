# Verrou

Gestionnaire de mots de passe natif pour un serveur **Vaultwarden** : application
macOS (puis iPadOS et iOS), extension Brave et CLI, autour d'un cœur en Rust.

> **État : première étape.** L'app et la CLI tournent sur un **coffre fictif**.
> La connexion à Vaultwarden (déchiffrement, synchronisation) arrive dans la
> prochaine PR, construite sur le SDK Rust officiel de Bitwarden.

## Ce qui marche aujourd'hui

- **Recherche locale instantanée** : floue, sans accents ni casse, mots exclus
  (`!pro`), filtres (`tag:banque`, `dossier:maison`, `type:carte`). Moins de
  5 ms par frappe sur 10 000 éléments, environ 0,3 ms sur un coffre réel.
  Les secrets ne sont jamais indexés.
- **App macOS** (SwiftUI) : déverrouillage Touch ID, barre latérale (catégories,
  dossiers, étiquettes), liste avec surlignage, fiche détaillée (copie au clic,
  mot de passe coloré, codes TOTP avec compte à rebours, cartes, identités,
  notes, clés SSH), **accès rapide ⌘⇧Espace** depuis n'importe quelle app.
- **Presse-papiers prudent** : les secrets copiés sont marqués « dissimulés » (les
  historiques de presse-papiers les ignorent) et effacés après 90 s.
- **Verrouillage automatique** : 10 min d'inactivité, mise en veille, écran
  verrouillé.
- **CLI `verrou`** : `search`, `get`, `totp`, `generate`, `bench`, sortie `--json`.

## Architecture

```
crates/
  verrou-core   modèle, recherche, correspondance de sites (PSL), TOTP, générateur, coffre fictif
  verrou-ffi    interface UniFFI vers Swift (aucun secret sans demande explicite)
  verrou-cli    binaire `verrou`
apple/
  Verrou/       app macOS SwiftUI (xcodegen : apple/project.yml)
  Shared/       liaison Swift générée (non versionnée)
scripts/
  build-apple.sh     cœur Rust → VerrouFFI.xcframework + liaison Swift
  demo-capture.sh    démonstration scriptée → docs/media/
```

Le principe de la frontière Rust/Swift : Swift reçoit les **résumés** (titre,
identifiant affiché, site) une fois au déverrouillage ; chaque frappe de
recherche ne renvoie que des **positions**. Un mot de passe ne traverse la
frontière que par `reveal`, quand l'utilisateur l'affiche ou le copie.
Verrouiller libère le coffre, et ses secrets (`SecretString`) sont mis à zéro.

## Construire

Prérequis : Rust stable (`rustup`), Xcode 26, `xcodegen` (`brew install xcodegen`).

```sh
cargo test --workspace                     # cœur, liaison, CLI
cargo run -p verrou-cli -- search github   # CLI sur le coffre fictif

scripts/build-apple.sh                     # bibliothèque universelle + liaison Swift
(cd apple && xcodegen generate && open Verrou.xcodeproj)
```

Variables utiles pour l'app : `VERROU_MOCK_SIZE=10000` (gros coffre fictif),
`VERROU_DEMO=1` (démonstration scriptée, utilisée par `scripts/demo-capture.sh`).

## Feuille de route

1. ✅ Cœur, recherche, app macOS et CLI sur coffre fictif
2. Connexion Vaultwarden : SDK Rust Bitwarden, déchiffrement, synchro, cache chiffré hors ligne, clé dans le trousseau protégée par Touch ID
3. Extension Brave : menu dans les champs, formulaires en plusieurs étapes, cartes, adresses, codes
4. iPhone et iPad : Face ID, extension de remplissage automatique du système
5. YubiKey : connexion FIDO2, déverrouillage `hmac-secret`

## Licence

GPL-3.0-or-later. Verrou s'appuiera sur les crates GPL du SDK Bitwarden
(`bitwarden/sdk-internal`), jamais sur le code sous licence commerciale de ce
dépôt (`bitwarden_license/`). « Bitwarden » est une marque de Bitwarden, Inc. ;
Verrou n'est ni affilié ni approuvé.
