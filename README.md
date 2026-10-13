# Verrou

Native password manager for a **Vaultwarden** server: a macOS app (iPadOS and
iOS to follow), a Brave extension and a CLI, built around a Rust core.

> **Status: first usable version.** The Mac app signs in to Vaultwarden
> (second factor included), decrypts the vault with Bitwarden's official Rust
> SDK, keeps it encrypted for offline use, unlocks with Touch ID, creates and
> edits logins and notes, and fills Brave forms through its extension. The CLI
> still works on the mock vault.
>
> The app's interface is in French.

## What works today

- **Vaultwarden sign-in**: master password (PBKDF2 or Argon2id), second factor
  with a **security key** (YubiKey over FIDO2, directly over USB, no browser),
  TOTP code, YubiKey OTP or e-mail. Syncs when the vault opens, then every
  5 min (⌘R to force it).
- **Create and edit** (⌘N, ⌘E): logins (with the password generator and its
  strength meter) and secure notes; title, folder, favorite and notes for the
  other types. The rest of an item (custom fields, passkeys, attachments) is
  kept intact, the old password goes to the item's history, and a change made
  elsewhere in the meantime is never overwritten. Trash can be restored from
  the web vault.
- **Brave extension**: under a login field, a menu offers Verrou's logins for
  that site; Enter or a click fills the username and password (or the
  one-time code). Vault locked: the menu offers to unlock it (Touch ID). The
  extension is linked to the app once, by comparing a 6-digit code; the
  channel is then end-to-end encrypted, and it only receives the logins of the
  site in front of it, over HTTPS. On a "new password" field it suggests a
  strong password (and fills the confirmation too); after a form is submitted,
  a banner offers to save the account or update its password. A two-factor QR
  code shown by a site can be added to the login from the extension's popup
  (or its secret key, typed by hand).
- **Offline**: the vault stays available without network, decrypted from the
  cache (the server's response, still encrypted).
- **Touch ID**: the vault key is sealed by the Secure Enclave (see
  [SECURITY.md](SECURITY.md)).
- **Instant local search**: fuzzy, accent- and case-insensitive, excluded
  words (`!pro`), filters (`tag:banque`, `dossier:maison`, `type:carte`).
  Under 5 ms per keystroke on 10,000 items, about 0.3 ms on a real vault.
  Secrets are never indexed.
- **macOS app** (SwiftUI): sidebar (categories, folders, tags), result list
  with highlighting, detail view (click to copy, colored password, TOTP codes
  with countdown, cards, identities, notes, SSH keys), **Quick Access ⌘⇧Space**
  from any app, **site icons** served by the account's own Vaultwarden, a
  **padlock in the menu bar**, and launch at login (Settings).
- **Careful clipboard**: copied secrets are marked "concealed" (clipboard
  history apps skip them) and cleared after 90 s.
- **Auto-lock**: after 10 min of inactivity, on sleep, and when the screen
  locks.
- **`verrou` CLI**: `search`, `get`, `totp`, `generate`, `bench`, `--json`
  output.

## Architecture

```
crates/
  verrou-core         model, search, site matching (PSL), TOTP, generator, mock vault
  verrou-vaultwarden  sign-in, second factor, cache, decryption (Bitwarden Rust SDK)
  verrou-ffi          UniFFI interface to Swift (no secret without an explicit request)
  verrou-bridge       bridge to the extension: pairing, encrypted channel, Native Messaging host
  verrou-cli          `verrou` binary
extension/      Brave extension (Manifest V3), shipped inside the app
apple/
  Verrou/       SwiftUI macOS app (xcodegen: apple/project.yml)
  Shared/       generated Swift bindings (not versioned)
scripts/
  build-apple.sh     Rust core → VerrouFFI.xcframework + Swift bindings
  install-macos.sh   Release build, signed locally, copied to /Applications
  demo-capture.sh    scripted demo → docs/media/
  e2e.sh             app walkthrough against a throwaway Vaultwarden
```

The Rust/Swift boundary works like this: Swift receives item **summaries**
(title, displayed username, site) once at unlock; each search keystroke only
returns **positions**. A password crosses the boundary only through `reveal`,
when the user shows or copies it. Locking frees the vault, and its secrets
(`SecretString`) are zeroed.

## Install on your Mac

```sh
brew install xcodegen
scripts/install-macos.sh
```

The app is signed locally ("ad hoc"): no Apple developer account is needed,
and it only runs on the Mac that built it. On first launch, enter the server
address, e-mail and master password, then the second factor. Reinstalling keeps
the account; to forget it: Settings (⌘,) → *Se déconnecter de ce Mac* (sign
out of this Mac).

## Brave extension

1. In Verrou: Settings (⌘,) → *Remplissage dans Brave* (fill in Brave). Verrou
   registers its Native Messaging host with Brave and copies the extension's
   path.
2. In Brave: `brave://extensions`, *Developer mode*, *Load unpacked*, ⌘⇧G and
   paste the path (the extension ships inside `Verrou.app` and updates with
   the app).
3. Click Verrou's icon in Brave, *Relier à Verrou* (link to Verrou), check that
   Verrou shows the same code, and accept.

```sh
node --test extension/test/bridge.test.mjs   # extension protocol against the real bridge
node extension/e2e/brave.mjs                  # walkthrough in a real Brave (throwaway profile)
```

(Both need `cargo build -p verrou-bridge --example test_server --bin verrou-native-host`.)

## Build

Requirements: stable Rust (`rustup`), Xcode 26, `xcodegen` (`brew install xcodegen`).

```sh
cargo test --workspace                     # core, sign-in, bindings, CLI
cargo run -p verrou-cli -- search github   # CLI on the mock vault

# Tests against a real (throwaway) Vaultwarden: see the header of
# crates/verrou-vaultwarden/tests/server.rs
VERROU_TEST_SERVER=http://localhost:8099 cargo test -p verrou-vaultwarden

scripts/build-apple.sh                     # universal library + Swift bindings
(cd apple && xcodegen generate && open Verrou.xcodeproj)
```

Useful environment variables for the app: `VERROU_MOCK=1` (mock vault instead
of Vaultwarden), `VERROU_MOCK_SIZE=10000` (large mock vault), `VERROU_DEMO=1`
(scripted demo, used by `scripts/demo-capture.sh`), `VERROU_BENCH=1` (UI
benchmark on the mock vault: unlock, typing, clearing; Debug builds, or
Release built with `SWIFT_ACTIVE_COMPILATION_CONDITIONS=BENCH`).

## Performance

- Rust core: `cargo run --release -p verrou-vaultwarden --example profile_unlock -- <server> <e-mail> <password>`
  times each unlock step on a real account (830 items unlock in about 12 ms).
- App: timings of launch, Touch ID, unlock and sync are logged (durations only):
  `log stream --predicate 'subsystem == "app.verrou.mac" AND category == "perf"'`.

## Roadmap

1. ✅ Core, search, macOS app and CLI on a mock vault
2. ✅ Vaultwarden sign-in: Bitwarden Rust SDK, second factor, decryption, sync, encrypted offline cache, Touch ID through the Secure Enclave
3. Brave extension: ✅ in-field menu, multi-step forms, one-time codes, saving and updating accounts, generator, two-factor QR codes; cards, addresses
4. iPhone and iPad: Face ID, system AutoFill extension
5. YubiKey: ✅ FIDO2 sign-in over USB; `hmac-secret` unlock

## License

GPL-3.0-or-later. Verrou builds on the GPL crates of the Bitwarden SDK
(`bitwarden/sdk-internal`), never on the commercially licensed code of that
repository (`bitwarden_license/`). "Bitwarden" is a trademark of Bitwarden,
Inc.; Verrou is neither affiliated with nor endorsed by it.
