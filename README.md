# Verrou

Gestionnaire de mots de passe natif pour un serveur **Vaultwarden** : application
macOS (puis iPadOS et iOS), extension Brave et CLI, autour d'un cœur en Rust.

> **État : première version utilisable.** L'app Mac se connecte à Vaultwarden
> (second facteur compris), déchiffre le coffre avec le SDK Rust officiel de
> Bitwarden, le garde chiffré pour l'utiliser hors ligne, et se déverrouille
> par Touch ID. **Lecture seule** : rien n'est modifié sur le serveur. La CLI
> travaille encore sur le coffre fictif.

## Ce qui marche aujourd'hui

- **Connexion à Vaultwarden** : mot de passe principal (PBKDF2 ou Argon2id),
  second facteur par **clé de sécurité** (YubiKey en FIDO2, directement en
  USB, sans navigateur), code TOTP, YubiKey OTP ou e-mail. Synchronisation à l'ouverture puis toutes les
  5 min (⌘R pour la forcer).
- **Hors ligne** : le coffre reste disponible sans réseau, déchiffré à partir
  du cache (la réponse du serveur, chiffrée).
- **Touch ID** : la clé du coffre est scellée par le Secure Enclave (voir
  [SECURITY.md](SECURITY.md)).
- **Recherche locale instantanée** : floue, sans accents ni casse, mots exclus
  (`!pro`), filtres (`tag:banque`, `dossier:maison`, `type:carte`). Moins de
  5 ms par frappe sur 10 000 éléments, environ 0,3 ms sur un coffre réel.
  Les secrets ne sont jamais indexés.
- **App macOS** (SwiftUI) : barre latérale (catégories,
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
  verrou-core         modèle, recherche, correspondance de sites (PSL), TOTP, générateur, coffre fictif
  verrou-vaultwarden  connexion, second facteur, cache, déchiffrement (SDK Rust de Bitwarden)
  verrou-ffi          interface UniFFI vers Swift (aucun secret sans demande explicite)
  verrou-cli    binaire `verrou`
apple/
  Verrou/       app macOS SwiftUI (xcodegen : apple/project.yml)
  Shared/       liaison Swift générée (non versionnée)
scripts/
  build-apple.sh     cœur Rust → VerrouFFI.xcframework + liaison Swift
  install-macos.sh   build Release, signé localement, copié dans /Applications
  demo-capture.sh    démonstration scriptée → docs/media/
  e2e.sh             parcours de l'app contre un Vaultwarden jetable
```

Le principe de la frontière Rust/Swift : Swift reçoit les **résumés** (titre,
identifiant affiché, site) une fois au déverrouillage ; chaque frappe de
recherche ne renvoie que des **positions**. Un mot de passe ne traverse la
frontière que par `reveal`, quand l'utilisateur l'affiche ou le copie.
Verrouiller libère le coffre, et ses secrets (`SecretString`) sont mis à zéro.

## Installer sur son Mac

```sh
brew install xcodegen
scripts/install-macos.sh
```

L'app est signée localement (« ad hoc ») : aucun compte de développeur Apple
n'est nécessaire, et elle ne tourne que sur le Mac qui l'a construite. Au
premier lancement, indiquer l'adresse du serveur, l'e-mail et le mot de passe
principal, puis le second facteur. Réinstaller garde le compte ; pour
l'oublier : Réglages (⌘,) → *Se déconnecter de ce Mac*.

## Construire

Prérequis : Rust stable (`rustup`), Xcode 26, `xcodegen` (`brew install xcodegen`).

```sh
cargo test --workspace                     # cœur, connexion, liaison, CLI
cargo run -p verrou-cli -- search github   # CLI sur le coffre fictif

# Tests contre un vrai Vaultwarden (jetable) : voir l'en-tête de
# crates/verrou-vaultwarden/tests/server.rs
VERROU_TEST_SERVER=http://localhost:8099 cargo test -p verrou-vaultwarden

scripts/build-apple.sh                     # bibliothèque universelle + liaison Swift
(cd apple && xcodegen generate && open Verrou.xcodeproj)
```

Variables utiles pour l'app : `VERROU_MOCK=1` (coffre fictif au lieu de
Vaultwarden), `VERROU_MOCK_SIZE=10000` (gros coffre fictif), `VERROU_DEMO=1`
(démonstration scriptée, utilisée par `scripts/demo-capture.sh`).

## Feuille de route

1. ✅ Cœur, recherche, app macOS et CLI sur coffre fictif
2. ✅ Connexion Vaultwarden : SDK Rust Bitwarden, second facteur, déchiffrement, synchro, cache chiffré hors ligne, Touch ID par le Secure Enclave
3. Extension Brave : menu dans les champs, formulaires en plusieurs étapes, cartes, adresses, codes
4. iPhone et iPad : Face ID, extension de remplissage automatique du système
5. YubiKey : ✅ connexion FIDO2 en USB ; déverrouillage `hmac-secret`

## Licence

GPL-3.0-or-later. Verrou s'appuie sur les crates GPL du SDK Bitwarden
(`bitwarden/sdk-internal`), jamais sur le code sous licence commerciale de ce
dépôt (`bitwarden_license/`). « Bitwarden » est une marque de Bitwarden, Inc. ;
Verrou n'est ni affilié ni approuvé.
