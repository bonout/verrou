# Verrou

Native password manager for a **Vaultwarden** server: a macOS app (iPadOS and
iOS to follow), a Brave extension and a CLI, built around a Rust core.

> **Status: first usable version.** The Mac app signs in to Vaultwarden
> (second factor included), decrypts the vault with Bitwarden's official Rust
> SDK, keeps it encrypted for offline use, unlocks with Touch ID or a YubiKey,
> creates and edits logins and notes, fills Brave forms through its extension,
> and serves the `verrou` CLI and an SSH agent from the real vault.
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
- **Import and duplicates** (File → *Importer…*, ⌘⇧I): exports from Apple
  Passwords, 1Password and Proton Pass, compared with the vault before
  anything is written (new, already there, different password), sent in one
  request; Vault → *Nettoyer les doublons…* moves duplicates to the trash.
  See [Import from another password manager](#import-from-another-password-manager).
- **Brave extension**: under a login field, a menu offers Verrou's logins for
  that site; Enter or a click fills the username and password (or the
  one-time code). Vault locked: the menu offers to unlock it (Touch ID). The
  extension is linked to the app once, by comparing a 6-digit code; the
  channel is then end-to-end encrypted, and it only receives the logins of the
  site in front of it, over HTTPS. On a "new password" field it suggests a
  strong password (and fills the confirmation too); after a form is submitted,
  a banner offers to save the account or update its password. A two-factor QR
  code shown by a site can be added to the login from the extension's popup
  (or its secret key, typed by hand). Payment and address forms get a menu
  too: pick a card or an identity and every field is filled, drop-down lists
  included. A site Verrou doesn't know yet can be linked to an existing login
  from the popup (*Remplir avec un autre identifiant…*).
- **Passkeys in Brave**: when a site asks for a passkey, Verrou offers its
  own for that site, or to save a new one in the site's login (or a new
  one); "use the browser" hands over to Brave. Passkeys are stored the
  Bitwarden way (`fido2Credentials`), so they work both ways with the
  official apps and web vault. The private key stays in the Rust core:
  Verrou signs (ES256) and only the public key and signatures reach the
  extension. Touch ID when the site asks for user verification. An item's
  passkeys (site, user, date) show in its details and can be deleted there.
- **Security audit**: reused, weak and plain-HTTP passwords, computed
  locally; known breaches on request through Have I Been Pwned (k-anonymity:
  only 5 characters of each password's SHA-1 leave the Mac). Also: sites that
  offer two-factor authentication while the login has no one-time code
  (from the full [2fa.directory](https://2fa.directory) list, downloaded at
  most weekly and cached, with a link to the site's 2FA help page), cards
  expired or expiring within 60 days, and logins untouched for more than
  3 years. A password created or changed in Verrou (editor, Brave, import) is
  checked against known breaches in the background, with an alert if it
  appears there (Settings → *Sécurité*, on by default).
- **Protected items**: Bitwarden's "master password re-prompt" is enforced in
  the Rust core: secrets (reveal, copy, codes, edit, Brave fill) need Touch ID
  or the master password, valid 5 minutes per item.
- **Tidy up**: favorites (click the star), **archive** items (kept but out of
  the list, search and autofill), trash with **restore**, previous passwords
  visible in each item, configurable auto-lock delay.
- **Offline**: the vault stays available without network, decrypted from the
  cache (the server's response, still encrypted).
- **Touch ID**: the vault key is sealed by the Secure Enclave (see
  [SECURITY.md](SECURITY.md)).
- **YubiKey unlock**: the vault key is sealed by a secret that never leaves
  the key (FIDO2 `hmac-secret`); unlocking takes the key's PIN and a touch.
  Several keys can be enrolled (main and backup) in Settings, each removable
  on its own. A FIDO2 PIN must be set on the key.
- **Instant local search**: fuzzy, accent- and case-insensitive, excluded
  words (`!pro`), filters (`tag:banque`, `dossier:maison`, `type:carte`).
  Under 5 ms per keystroke on 10,000 items, about 0.3 ms on a real vault.
  Secrets are never indexed.
- **macOS app** (SwiftUI): sidebar (categories, folders, tags), result list
  with highlighting, detail view (click to copy, colored password, TOTP codes
  with countdown, cards, identities, notes, SSH keys), **Quick Access ⌘⇧Space**
  from any app, **site icons** served by the account's own Vaultwarden, a
  **padlock in the menu bar**, and launch at login (Settings).
- **Fill in any Mac app** (⌘\, like 1Password's Universal Autofill): the
  shortcut remembers the app in front, opens Quick Access with the logins
  linked to it, and types the username, Tab and the password (Unicode text,
  any keyboard layout). See [Fill in any app](#fill-in-any-app).
- **Careful clipboard**: copied secrets are marked "concealed" (clipboard
  history apps skip them) and cleared after 90 s.
- **Auto-lock**: after 10 min of inactivity by default (1 min to never, in
  Settings), on sleep, and when the screen locks.
- **`verrou` CLI**: `search`, `get`, `totp`, `generate`, `--json` output, on
  the real vault served by the running app (`--mock` for the mock vault and
  `bench`). Secrets ask for Touch ID in the app.
- **SSH agent** (`verrou ssh-agent`): the vault's SSH keys for `ssh` and
  `git`; the app signs, the private key never leaves it.
- **SSH keys and git commit signing**: *Nouvelle clé SSH…* (+ menu, or the
  SSH keys category) generates an Ed25519 (default) or RSA 4096 key, stored
  as a regular Bitwarden SSH key item; *Copier la clé publique* on the item.
  `verrou git-signing` sets git up to sign commits through the agent, and the
  Touch ID prompt says it is a git signature.

## Architecture

```
crates/
  verrou-core         model, search, site matching (PSL), TOTP, generator, mock vault,
                      import parsers (Apple, 1Password, Proton Pass), duplicates, passkeys
                      (WebAuthn creation and ES256 signing)
  verrou-vaultwarden  sign-in, second factor, cache, decryption, writes and bulk import
                      (Bitwarden Rust SDK), YubiKey unlock
  verrou-ffi          UniFFI interface to Swift (no secret without an explicit request)
  verrou-bridge       bridge to the extension and the CLI: pairing, encrypted channel,
                      per-client permissions, SSH signing, Native Messaging host
  verrou-cli          `verrou` binary and its SSH agent
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

## Import from another password manager

Export your passwords from the other app, then in Verrou: File →
*Importer…* (⌘⇧I) or Settings → *Importer*, and choose the file. The format
is recognized from its content (you can pick it by hand if needed).

| From | How to export | File |
|---|---|---|
| Apple Passwords | Passwords app → File → *Export All Passwords…* | `.csv` |
| 1Password | File → *Export* → choose the account → **1PUX** (or CSV) | `.1pux` / `.csv` |
| Proton Pass | Settings → *Export* → **unencrypted** ZIP (or CSV) | `.zip` / `.csv` |

Before anything is written, Verrou shows a review: new items, items already
in the vault (same site, username and password: skipped), items whose
password differs (you choose: keep the existing one, replace it — the old
password goes to the item's history — or import it separately), items that
only add a one-time code, and entries that cannot be imported, with the
reason. Secrets never appear in the review. Created items can go to a folder
(« Import 1Password » by default), to the source app's own folders or vaults,
or to no folder. Everything is sent in one request, followed by one sync.

What is imported: logins (username, password, sites, one-time code, extra
fields), secure notes and credit cards. Other kinds (identities, servers,
Wi-Fi…) become secure notes with their fields in the notes. Not imported:
attachments and passkeys, archived or trashed items, Proton Pass aliases.
1Password tags have no equivalent in Vaultwarden and are dropped.

**Delete the export file afterwards** (and empty the Finder's trash): it
holds all your passwords in plain text. Verrou only reads it when you import
and never copies it.

Vault → *Nettoyer les doublons…* lists the logins that share a site and a
username (`login.example.com` and `example.com` count as one site, but
`cloud.example.com` and `vault.example.com` do not), suggests which one to
keep (the one with a one-time code, then the most recently modified, then
the most complete) and moves the others to the trash in one request,
restorable from the web vault.

## Fill in any app

1. Settings (⌘,) → *Général* → *Remplissage dans les apps*: on by default,
   shortcut ⌘\ (the key left of Return, whatever the layout; ⌥⌘ or ⌃⌘
   variants if another app already uses it).
2. The first time, allow Verrou in System Settings → Privacy & Security →
   **Accessibility** (Quick Access shows a button that opens it).
3. In any app, put the cursor in the username field (or the password field)
   and press ⌘\. Quick Access opens, titled with that app, listing the
   logins linked to it. Enter fills: Verrou closes, the app comes back to the
   front, and the username, Tab and password are typed.
4. No login linked yet: search for it and press **⌘↩** to fill and link it
   to the app (or click *Associer à …* to link without filling). The link is
   stored in the item as a `macapp://<bundle id>` URI (with Bitwarden's
   "never" match rule, so browser extensions ignore it) and syncs with the
   vault.

Options: press Return after the password (off by default), copy the item's
one-time code to the clipboard after filling (on by default). Protected
items ask for Touch ID or the master password first; a locked vault offers
Touch ID in Quick Access. If another app holds Secure Keyboard Entry (e.g.
Terminal's *Secure Keyboard Entry*), Verrou warns and types nothing.

The app is signed ad hoc: macOS may forget the Accessibility permission
after Verrou is rebuilt or reinstalled. If filling stops working, remove
Verrou from the Accessibility list and allow it again.

## Brave extension

1. In Verrou: Settings (⌘,) → *Brave et le terminal* (Brave and the terminal). Verrou
   registers its Native Messaging host with Brave and copies the extension's
   path.
2. In Brave: `brave://extensions`, *Developer mode*, *Load unpacked*, ⌘⇧G and
   paste the path (the extension ships inside `Verrou.app` and updates with
   the app).
3. Click Verrou's icon in Brave, *Relier à Verrou* (link to Verrou), check that
   Verrou shows the same code, and accept.

```sh
node --test extension/test/bridge.test.mjs   # extension protocol against the real bridge
node --test extension/test/passkeys.test.mjs # passkeys: page options, creation and sign-in
node extension/e2e/brave.mjs                  # walkthrough in a real Brave (throwaway profile)
```

(Both need `cargo build -p verrou-bridge --example test_server --bin verrou-native-host`.)

## Command line and SSH agent

The vault is only decrypted inside the app, so the CLI asks the running app
for what it shows, over the same local bridge as the extension (TCP
`127.0.0.1`, end-to-end encrypted channel). If Verrou isn't running, the CLI
opens it in the background; if the vault is locked, Verrou asks for Touch ID
and the CLI waits up to a minute.

```sh
cargo install --path crates/verrou-cli   # installs `verrou`
verrou link        # once: compare the 6-digit code, accept in Verrou
verrou status
verrou search github            # titles, usernames, sites: never secrets
verrou get github --field password | pbcopy
verrou totp github
verrou generate -l 24           # local, no app needed
verrou unlink
```

The link (client id and channel key) is stored in `~/.config/verrou/cli.json`
(mode 600; `VERROU_CLI_CONFIG` overrides it). Settings → *Brave et le terminal*
must be on. Reading a secret (`get --field password`, `--reveal`, `totp`)
asks for Touch ID (or the session password) in Verrou: *autoriser le terminal
à lire « GitHub »*. An approval lasts 5 minutes for that item and that
terminal, and is forgotten when the vault locks.

### SSH agent

```sh
verrou ssh-agent        # foreground; prints: export SSH_AUTH_SOCK=/Users/you/.verrou/agent.sock
```

It listens on `~/.verrou/agent.sock` (`--socket PATH` to change it; directory
700, socket 600) and offers the vault's SSH key items (Ed25519, ECDSA P-256 and
P-384, RSA with `rsa-sha2-256`/`rsa-sha2-512`). Each signature is made **by the
app**, after a Touch ID prompt (*autoriser ssh à utiliser la clé « … »*), cached
5 minutes per key. Only `ssh` and `git` signing requests are served; adding or
removing keys through the agent is refused.

Use it for every host in `~/.ssh/config`:

```
Host *
    IdentityAgent ~/.verrou/agent.sock
```

To start it at login, a LaunchAgent such as
`~/Library/LaunchAgents/app.verrou.ssh-agent.plist` (adjust the path to
`verrou`, then `launchctl load` it):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>app.verrou.ssh-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/you/.cargo/bin/verrou</string>
        <string>ssh-agent</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/tmp/verrou-ssh-agent.log</string>
</dict>
</plist>
```

### New SSH keys

In the app: + → *Nouvelle clé SSH…* (also in the list header of the *Clés
SSH* category). Pick a title, Ed25519 (default) or RSA 4096, and a folder.
The key is generated by the Rust core and saved as a Bitwarden SSH key item
(type 5: OpenSSH private key without passphrase, public key, `SHA256:`
fingerprint), so the official Bitwarden apps see it too. *Copier la clé
publique* (on the item, or in its context menu) copies the `ssh-ed25519 AAAA…`
line for `authorized_keys`, GitHub or GitLab.

### Signing git commits

git signs with SSH keys (`gpg.format=ssh`) by running `ssh-keygen -Y sign -n
git`, which asks the agent named by `SSH_AUTH_SOCK`. With Verrou's agent, the
Touch ID prompt reads *signer un commit git avec la clé « … »* (a separate
approval from `ssh` logins, also cached 5 minutes per key).

```sh
verrou git-signing github                 # prints the git settings, writes nothing
verrou git-signing github --apply         # writes them to the global git config
verrou git-signing github --apply --local # …or to the current repository only
```

The query matches the key's title or fingerprint (optional when the vault has
a single SSH key). The commit e-mail comes from `git config user.email`
(`--email` to override). `--apply` sets `gpg.format=ssh`,
`user.signingkey=key::<public key>`, `commit.gpgsign` and `tag.gpgsign`, and
adds the key to `~/.config/verrou/allowed_signers` (`--allowed-signers PATH`),
which `gpg.ssh.allowedSignersFile` points to so that `git log
--show-signature` and `git verify-commit` can check signatures. Nothing is
written without `--apply`.

`ssh-keygen` ignores `IdentityAgent` from `~/.ssh/config`: `SSH_AUTH_SOCK`
must point to Verrou's agent in the shell that runs git (for example
`export SSH_AUTH_SOCK=~/.verrou/agent.sock` in `~/.zshrc`; for GUI git clients,
`launchctl setenv SSH_AUTH_SOCK "$HOME/.verrou/agent.sock"`).

## Build

Requirements: stable Rust (`rustup`), Xcode 26, `xcodegen` (`brew install xcodegen`).

```sh
cargo test --workspace                     # core, sign-in, bindings, bridge, CLI, SSH agent
cargo run -p verrou-cli -- --mock search github   # CLI on the mock vault

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
3. ✅ Brave extension: in-field menu, multi-step forms, one-time codes, saving and updating accounts, generator, two-factor QR codes, cards, addresses, linking a new site to a login
4. iPhone and iPad: Face ID, system AutoFill extension
5. YubiKey: ✅ FIDO2 sign-in over USB, ✅ `hmac-secret` unlock

## License

GPL-3.0-or-later. Verrou builds on the GPL crates of the Bitwarden SDK
(`bitwarden/sdk-internal`), never on the commercially licensed code of that
repository (`bitwarden_license/`). "Bitwarden" is a trademark of Bitwarden,
Inc.; Verrou is neither affiliated with nor endorsed by it.
