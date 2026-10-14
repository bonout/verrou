# Verrou: the full guide

Everything Verrou does, in detail. For a short tour, see the [README](../README.md).

Native password manager for a **Vaultwarden** server: a macOS app (iPadOS and
iOS to follow), a browser extension for Brave and Firefox, and a CLI, built
around a Rust core.

> **Status: first usable version.** The Mac app signs in to Vaultwarden
> (second factor included), decrypts the vault with Bitwarden's official Rust
> SDK, keeps it encrypted for offline use, unlocks with Touch ID or a YubiKey,
> creates and edits logins and notes, fills Brave and Firefox forms through its extension,
> and serves the `verrou` CLI and an SSH agent from the real vault.
>
> The app's interface is in French.

## What works today

- **Vaultwarden sign-in**: master password (PBKDF2 or Argon2id), second factor
  with a **security key** (YubiKey over FIDO2, directly over USB, no browser),
  TOTP code, YubiKey OTP or e-mail. Syncs when the vault opens, then every
  5 min (⌘R to force it).
- **Create and edit** (⌘N, ⌘E): logins (with the password generator and its
  strength meter, see [Passwords and passphrases](#passwords-and-passphrases)) and secure notes; title, folder, favorite, notes and
  **custom fields** (text, hidden, checkbox: add, remove, rename, reorder;
  linked fields are shown and kept) for every type. The rest of an item
  (passkeys, attachments) is kept intact, the old password goes to the item's
  history, and a change made elsewhere in the meantime is never overwritten.
  Trash can be restored from the web vault.
- **Templates**: *Nouvel élément* also offers software license, Wi-Fi
  network, bank account, passport, driver's license, ID card, server,
  database, API key and membership. Bitwarden has no such types, so each one
  is a secure note (a login for server, database and API key) with
  predefined custom fields, plus a text field `verrou:type` (e.g. `wifi`)
  that lets Verrou recognize it: it syncs, survives the web vault (where it
  shows as an ordinary field), is never shown in Verrou and is kept as is on
  every edit. Templates get their own icon and sidebar category, and
  `type:wifi`, `type:passeport`… in search. A Wi-Fi network shows a **QR
  code** that phones scan to join it.
- **Select several items** like in Finder: ⌘-click adds or removes one,
  ⇧-click selects a range, ⇧↑/⇧↓ extend it, ⌘A selects every result (list
  focused), Escape goes back to one item. The detail column then offers
  archive/unarchive, trash/restore, favorites and *Déplacer vers un
  dossier…* for the whole selection (also in the toolbar and the context
  menu of a selected row). Vaultwarden's bulk routes are used (one request
  per 500 items, one sync at the end; favorites go one by one); read-only
  shared items and items in the trash are skipped and counted, offline the
  changes wait in the outbox like single ones, and trashing more than one
  item asks first.
- **Import and duplicates** (File → *Importer…*, ⌘⇧I): exports from Apple
  Passwords, 1Password and Proton Pass, compared with the vault before
  anything is written (new, already there, different password), sent in one
  request; Vault → *Nettoyer les doublons…* moves duplicates to the trash.
  See [Import from another password manager](#import-from-another-password-manager).
- **Browser extension (Brave, Firefox)**: like 1Password, a dark pill at the
  top left of the page instead of a menu under the field. On a page with a
  login form and a login (or passkey) for that site, it appears once per page
  load: the site, the suggested username, *Se connecter* (sign in) and ✕.
  *Se connecter* fills the username and password (or the one-time code) and,
  like 1Password, submits the form when nothing is left to type: no other
  empty field and no visible captcha (an invisible reCAPTCHA v3 badge does
  not count). A username-only first step is submitted too; the pill comes
  back on the password step and waits for your click again. Cards, addresses
  and generated passwords are never submitted. The popup's *Envoyer le
  formulaire après le remplissage* checkbox (on by default) turns this off:
  the cursor then lands on the submit button and Enter sends it. The *Autres identifiants ⌄* tab under the pill lists the
  site's other logins and passkeys, *Remplir avec un autre identifiant…*
  (link the site to an existing login, in the extension's popup) and, on a
  sign-up form, *Générer un mot de passe*. In the focused field there is only
  a small Verrou icon at the right edge, which opens or closes the pill (even
  when the site has no login in Verrou); ↓ from that field moves the keyboard
  into the pill. ✕ or Escape hides it for the rest of the page. Nothing is
  attached to the field anymore, so the site's own suggestion lists are left
  alone. Vault locked: the pill says *Verrou est verrouillé* with
  *Déverrouiller* (Touch ID). The extension is linked to the app once, by
  comparing a 6-digit code; the channel is then end-to-end encrypted, and it
  only receives the logins of the site in front of it, over HTTPS. On a "new
  password" field the pill suggests a strong password (and fills the
  confirmation too); after a form is submitted, a banner in the same corner
  offers to save the account or update its password. A two-factor QR code
  shown by a site can be added to the login from the extension's popup (or
  its secret key, typed by hand). Payment and address forms get the same pill
  when you enter a field (*Remplir la carte Visa •••• 4242*, other cards in
  the tab): every field is filled, drop-down lists included.
- **Passkeys in Brave and Firefox**: when a site asks for a passkey, Verrou offers its
  own for that site, or to save a new one in the site's login (or a new
  one); "use the browser" hands over to the browser. Sites that offer passkey
  autofill (`mediation: "conditional"`, e.g. a username field with
  `autocomplete="username webauthn"`) get them in the pill, like 1Password:
  the passkey is the top suggestion (*Se connecter avec une passkey*), the
  passwords stay in the tab, and a click (or Enter on the button) signs in. No passkey in Verrou for that site, or Verrou not reachable:
  the browser's own autofill takes over. When Verrou cannot take a passkey request
  (app not running, extension not linked, key type it cannot create), a short
  notice says so instead of silently handing over to the browser. Passkeys are stored the
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
- **Change a password in one click**: *Changer le mot de passe* on the audit
  rows (known breaches, reused, weak, old, plain HTTP), in a login's details
  and in its context menu opens the site's change-password page. A short
  built-in list covers big sites that don't follow the standard (Google,
  GitHub, Amazon, Microsoft, Apple, Facebook, X, LinkedIn, Dropbox); other
  sites are asked, when you click and for that site only, whether they follow
  the W3C [Well-Known URL for Changing Passwords](https://w3c.github.io/webappsec-change-password-url/)
  (`/.well-known/change-password`, on the login's host, then its registrable
  domain; HTTPS only, no cookies, 5 s timeout). If not, Verrou opens the
  site's home page and says so. On the page, the Brave/Firefox extension
  suggests a strong password on the new-password field and offers to update
  the login after you submit; the audit row then disappears (breaches
  included: a changed password leaves the list without a new check).
- **Shared vaults** (Vaultwarden organizations, like 1Password's shared
  vaults): the sidebar lists each organization and its collections with
  their counts; items show where they are shared. Shared items are edited
  in place (re-encrypted with the organization key), created directly in a
  collection, or moved there from the personal vault (*Partager…*, which
  re-encrypts the item and its attachment keys). Read-only collections and
  "hide passwords" are enforced in the Rust core (filling in Brave still
  works, like Bitwarden). Creating collections and organization policies
  stay in the web vault (*Gérer dans le coffre web*).
- **Members** (sidebar → each organization → *Membres*, a pane of the main
  window like Sends): members grouped by status (*À confirmer*, *Invitations
  en attente*, *Membres*, *Révoqués*) with their role, collections, account
  and two-factor status. Owners and admins invite one or more addresses with
  a role (*Utilisateur*; *Gestionnaire*, *Administrateur* and *Propriétaire*
  for owners only, as Vaultwarden requires) and per-collection access (view,
  view without passwords, edit, edit without passwords, manage), resend an
  invitation, change a member's role and collections, revoke and restore
  access, and remove members. Confirming a member who accepted shows the
  5-word fingerprint phrase of their public key, to compare with what they
  read in their account (Verrou: Settings → *Compte*, which shows your own
  phrase; web vault: Settings → My account); the key is fetched again when
  sending and nothing is sent if the phrase changed. A manager with access to
  all collections sees the list read-only. No admin token is used.
- **Create an account** (sign-in screen → *Créer un compte*): for people
  invited to a server with sign-ups closed. Paste the *Rejoindre* link from
  the invitation e-mail (it fills in the server and address), choose a master
  password (12 characters minimum, strength meter, confirmation, optional
  hint) and PBKDF2 (600,000 iterations, the default) or Argon2id. Keys are
  generated by the Bitwarden SDK. On Vaultwarden 1.37.4, registration goes
  through `POST /identity/accounts/register/finish` with the invitation's
  token (`orgInviteToken` + `organizationUserId`); Verrou then signs in and
  accepts the invitation (`POST /api/organizations/{org}/users/{member}/accept`),
  and an admin confirms you. On a server without e-mail, invited addresses
  register without a link (the server hands out a verification token to
  invited addresses and accepts the invitation itself); a `finish-signup`
  verification link is accepted too.
- **Protected items**: Bitwarden's "master password re-prompt" is enforced in
  the Rust core: secrets (reveal, copy, codes, edit, Brave fill) need Touch ID
  or the master password, valid 5 minutes per item.
- **Tidy up**: favorites (click the star), **archive** items (kept but out of
  the list, search and autofill), trash with **restore**, previous passwords
  visible in each item, configurable auto-lock delay.
- **Attachments and documents**: an item's *Pièces jointes* section lists
  its files (Bitwarden format: a key per file, encrypted before upload).
  Open one in Quick Look, save a decrypted copy, delete it (with
  confirmation), or add files with *Ajouter un fichier…* or by dropping them
  on the item; 100 MB per file. File → *Nouveau document…* stores a file as
  a secure note named after it. Attachments are downloaded on demand, never
  cached: opening one needs the network.
- **Offline**: the vault stays available without network, decrypted from the
  cache (the server's response, still encrypted). Edits keep working too:
  creating, editing, favorites, moving to a folder, trash and restore,
  archives, and logins or passkeys saved from Brave are applied right away
  and wait in an encrypted queue in the account folder (they survive locking
  and quitting). Waiting items show *En attente de synchronisation*, the
  sidebar footer counts *N modifications en attente*, and Verrou retries
  every 30 seconds. On reconnection (next sync, ⌘R or the next edit) the
  queue is sent in order before the vault is downloaded; an item created
  offline gets its server id. If an item changed elsewhere in the meantime,
  both versions are kept: yours becomes a copy named *« … (conflit hors
  ligne) »*. Attachments, sharing to a shared vault, Sends, emergency access
  and import need the server and say so. Signing out discards the queue
  (the confirmation says how many changes would be lost).
- **Touch ID**: the vault key is sealed by the Secure Enclave (see
  [SECURITY.md](../SECURITY.md)).
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
- **Emergency access** (sidebar → *Accès d'urgence*, in the main window like
  the audit: the list in the middle column, the selected contact and its
  actions on the right): invite trusted
  contacts (view only or takeover, with a waiting period of 1 to 90 days),
  confirm them after checking their key fingerprint, approve or reject their
  requests, change or remove them. As someone's contact: request access, and
  once granted, open their vault read-only in a separate sheet. Takeover (a
  new master password for the grantor) stays in the web vault. Invitations
  need the contact to have an account on the server; without e-mail
  configured, Vaultwarden accepts them at once.
- **Send** (sidebar → *Envois*, in the main window: the list in the middle
  column, the selected Send on the right): share a text or a file through an
  end-to-end encrypted link (Bitwarden Send), readable by anyone with the
  link, with or without an account. *Nouvel envoi* offers *Texte* or
  *Fichier…*; you can also drop a file onto the Sends list. The file and its
  name are encrypted with the Send's key before upload (100 MB at most, or
  less if the server's Send quota is lower); the recipient downloads it from
  the web vault like any Bitwarden file Send. Deletion date (7 days by
  default, 31 at most), optional expiration, maximum number of accesses,
  password, hidden e-mail address; the list shows the file name and size,
  access counts and dates, and copies the link, edits, deletes or removes the
  password. Editing a file Send changes its options, never its file (like
  Bitwarden). From a login or a note, right-click → *Envoyer de façon
  sécurisée…* prefills a Send with its password (or the note), hidden from the
  recipient and limited to one access, to confirm before creating it; the same
  action on an attachment (*Pièces jointes* section) prefills a file Send with
  it, decrypted and re-encrypted with the Send's key inside the Rust core.
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
  verrou-vaultwarden  sign-in, second factor, cache, decryption, writes (offline queue), bulk import
                      (Bitwarden Rust SDK), YubiKey unlock
  verrou-ffi          UniFFI interface to Swift (no secret without an explicit request)
  verrou-bridge       bridge to the extension and the CLI: pairing, encrypted channel,
                      per-client permissions, SSH signing, Native Messaging host
  verrou-cli          `verrou` binary and its SSH agent
extension/      browser extension (Manifest V3), shipped inside the app; the Firefox
                variant (extension-firefox/) is generated from it at build time
apple/
  Verrou/       SwiftUI macOS app (xcodegen: apple/project.yml)
  Shared/       generated Swift bindings (not versioned)
scripts/
  build-apple.sh     Rust core → VerrouFFI.xcframework + Swift bindings
  install-macos.sh   Release build, signed locally, copied to /Applications
  demo-capture.sh    scripted demo → docs/media/
  e2e.sh             app walkthrough against a throwaway Vaultwarden
  firefox-extension.sh  extension/ → Firefox variant (manifest only differs)
  stamp-extension.sh    content-derived version for the bundled extensions
  sign-firefox.sh       Mozilla-signed (unlisted) or unsigned .xpi, run by hand
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

## Passwords and passphrases

The wand next to a login's password opens the generator. *Mot de passe* gives
a random password (8 to 64 characters, digits and symbols optional);
*Phrase de passe* gives words drawn at random, like 1Password's memorable
passwords or Bitwarden's passphrases: 3 to 20 words (5 by default), French
(default) or English, separated by `-`, a space, `.`, `_`, `,` or a random
digit, optionally capitalized and with a digit added to one word. The meter
shows the passphrase's exact entropy: about 12.9 bits per word, so 5 words
are about 65 bits and 6 words about 78. The last mode and options are
remembered.

```sh
verrou generate --words 5                                  # fixe-pivoine-monceaux-couteau-ponctue
verrou generate --words 6 --lang en --capitalize --number --separator ' '
verrou generate --words 4 --separator digit                # nymphe9ronfler4compatir8hocher
verrou --json generate --words 5                           # {"value": …, "entropy_bits": 64.6}
```

Words come from two lists embedded in Verrou: the French diceware list by
Tango for Tails and the Tor Project (CC0, 7,775 distinct words, no accents)
and EFF's Long Wordlist (CC BY 3.0 US, 7,776 words); see
[`crates/verrou-core/wordlists/NOTICE`](../crates/verrou-core/wordlists/NOTICE).
Each word is drawn uniformly from the system's random generator. The Brave
extension's strong password suggestion stays a random password, since many
sites refuse spaces.

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
fields), secure notes, credit cards and identities (real Bitwarden
identities; fields Bitwarden has no slot for become custom fields). 1Password
software licenses, wireless routers, bank accounts, passports, driver's
licenses, servers, databases, API credentials and memberships, and Proton
Pass Wi-Fi networks, become the matching Verrou templates. Other kinds
become secure notes with their fields in the notes. Files carried by
a 1PUX or Proton Pass ZIP export become attachments (100 MB per file at most;
a 1Password *Document* becomes a secure note with its file); a file missing
from the archive is mentioned in the item's notes. Items with files are
created one by one, after the bulk request. Not imported: passkeys, archived
or trashed items, Proton Pass aliases, and the files of an entry that matches
an item already in the vault.
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

1. In Verrou: Settings (⌘,) → *Brave, Firefox et le terminal* (Brave, Firefox
   and the terminal). Verrou registers its Native Messaging host with Brave
   (and Chrome, and Firefox if installed). *Extension Brave* → *Copier le
   chemin* copies the extension's path.
2. In Brave: `brave://extensions`, *Developer mode*, *Load unpacked*, ⌘⇧G and
   paste the path (the extension ships inside `Verrou.app` and updates with
   the app).
3. Click Verrou's icon in Brave, *Relier à Verrou* (link to Verrou), check that
   Verrou shows the same code, and accept.

No manual reload after an update: each build gives the bundled extension a
version derived from its files (`scripts/stamp-extension.sh`), and the
bridge reports it. The extension compares it with its own (at startup, on
each connection to Verrou and every 10 minutes) and reloads itself from
disk, at most once per version. Tabs opened before the reload need a page
reload to get the new scripts; a passkey request there says so. If the
popup warns that the extension isn't Verrou's, it was loaded from another
folder: load the one inside `Verrou.app` instead.

## Firefox extension

The same extension, for Firefox 128 or later (the passkey script runs in the
page's world, `world: "MAIN"`, which Firefox supports since 128). There is no
fork: at build time `scripts/firefox-extension.sh` copies `extension/` into
`Verrou.app/Contents/Resources/extension-firefox/` and only rewrites the
manifest:

- `background.scripts` (an event page) instead of `background.service_worker`;
- `browser_specific_settings.gecko`: id `verrou@verrou.app` (the id Verrou
  allows in Firefox's Native Messaging manifest), `strict_min_version` 128.0,
  `data_collection_permissions: none` (nothing leaves the Mac);
- `host_permissions` listing the content scripts' sites. Firefox lets you grant
  or withdraw site access for a Manifest V3 extension; without it there is no
  pill and no passkeys. When access is missing, the popup shows
  *Autoriser Verrou sur les sites* (allow Verrou on sites); reload the pages
  that were already open afterwards;
- no `key` or `minimum_chrome_version` (Chrome-only).

The scripts pick `browser` (Firefox) or `chrome` (Brave) themselves
(`extension/browser.js`); the extension announces itself as « Firefox » when
pairing, so Verrou's settings list it as *Firefox*. Both folders get the same
content-derived version.

Native Messaging: Verrou writes
`~/Library/Application Support/Mozilla/NativeMessagingHosts/app.verrou.bridge.json`
with `allowed_extensions: ["verrou@verrou.app"]` (Firefox's equivalent of
`allowed_origins`), when Firefox is installed. The app's sandbox may only write
inside that `NativeMessagingHosts` folder: if
`~/Library/Application Support/Mozilla` does not exist yet, the settings say
so; create it once with
`mkdir -p ~/Library/Application\ Support/Mozilla/NativeMessagingHosts` and
toggle the setting off and on. Firefox launches `verrou-native-host` with the
manifest path and the extension id as arguments (Brave passes the extension's
origin); the host serves only Verrou's extension in either case.

### Installing it in Firefox

Release Firefox only installs extensions signed by Mozilla for good. Three
ways, from quickest to most durable:

1. **Temporary add-on (any Firefox, nothing to sign).** Verrou → Settings →
   *Extension Firefox* → *Copier le chemin* (copies the path of its
   `manifest.json`). In Firefox: `about:debugging` → *This Firefox* → *Load
   Temporary Add-on…*, ⌘⇧G, paste, *Open*. Then click Verrou's icon,
   *Autoriser Verrou sur les sites* if shown, and *Relier à Verrou*.
   Firefox removes temporary add-ons when it quits: load it again after each
   restart. Its storage goes with it, so it has to be linked again too; unlink
   the old *Firefox* entries in Verrou's settings from time to time. While it
   is loaded, it reloads itself when Verrou is updated, like in Brave.
2. **Firefox Developer Edition or Nightly, unsigned .xpi (permanent).** In
   `about:config`, set `xpinstall.signatures.required` to `false` (release
   and beta Firefox ignore it). Build the package with
   `scripts/sign-firefox.sh --unsigned` (→ `target/firefox-xpi/verrou-<version>-unsigned.xpi`)
   and install it from `about:addons` → ⚙ → *Install Add-on From File…*.
3. **Signed by Mozilla, unlisted (permanent, any Firefox).** Self-distribution
   outside the add-on catalogue; needs your Mozilla account and API keys from
   <https://addons.mozilla.org/developers/addon/api/key/>:

   ```sh
   AMO_JWT_ISSUER=user:12345:678 AMO_JWT_SECRET=… scripts/sign-firefox.sh
   ```

   Signing is automatic and takes a few minutes; the signed file lands in
   `target/firefox-xpi/`. Install it from `about:addons` as above. Mozilla
   signs each version once: any change to the extension gives a new version
   (it is the same content-derived version as the one bundled with Verrou).

An installed .xpi (2 and 3) does not change when Verrou is updated, and
reloading it would not help: on Firefox the extension only reloads itself
when its own files changed on disk (temporary add-on). When Verrou ships a
different version, the popup says so; install the new package.

Not available in Firefox: reading a two-factor QR code from the tab (Firefox
has no `BarcodeDetector`); the popup offers to type the secret key instead.

## Tests of the extension

```sh
node --test extension/test/bridge.test.mjs   # extension protocol against the real bridge
node --test extension/test/passkeys.test.mjs # passkeys: page options, creation and sign-in
node --test extension/test/seamless.test.mjs # self-reload, passkey autofill (Brave and Firefox APIs), fallback notices
node --test extension/test/firefox.test.mjs  # Firefox manifest, shared files and version, ids, Firefox reload rule
node --test extension/test/content.test.mjs  # the pill (content.js) in a fake DOM: when it shows, what it fills, trusted events only
VERROU_LINT_FIREFOX=1 node --test extension/test/firefox.test.mjs  # also Mozilla's `web-ext lint` (via npx)
node extension/e2e/brave.mjs                  # walkthrough in a real Brave (throwaway profile)
node extension/e2e/seamless.mjs               # passkey autofill in a real Brave (SEAMLESS_UPDATE=1: self-reload)
```

(They need `cargo build -p verrou-bridge --example test_server --bin verrou-native-host`,
except `content.test.mjs`, which needs nothing but Node.)
There is no automated walkthrough in a real Firefox yet; the steps above are
checked by hand.

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
verrou generate --words 5       # passphrase (see below)
verrou unlink
```

The link (client id and channel key) is stored in `~/.config/verrou/cli.json`
(mode 600; `VERROU_CLI_CONFIG` overrides it). Settings → *Brave, Firefox et le terminal*
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
# crates/verrou-vaultwarden/tests/server.rs (organizations: tests/organizations.rs, offline edits: tests/offline.rs)
VERROU_TEST_SERVER=http://localhost:8099 cargo test -p verrou-vaultwarden
# Members and invited sign-up on a sign-ups-closed server (with or without
# e-mail, through a Mailpit inbox): see the header of tests/members.rs
VERROU_TEST_MEMBERS_SERVER=http://localhost:8119 cargo test -p verrou-vaultwarden --test members

scripts/build-apple.sh                     # universal library + Swift bindings
(cd apple && xcodegen generate && open Verrou.xcodeproj)
```

Useful environment variables for the app: `VERROU_MOCK=1` (mock vault instead
of Vaultwarden), `VERROU_MOCK_SIZE=10000` (large mock vault), `VERROU_DEMO=1`
(scripted demo, used by `scripts/demo-capture.sh`), `VERROU_BENCH=1` (UI
benchmark on the mock vault: unlock, typing, clearing; Debug builds, or
Release built with `SWIFT_ACTIVE_COMPILATION_CONDITIONS=BENCH`).

### Visual review, offscreen

`scripts/review-capture.sh` (Debug build, `VERROU_REVIEW=1`) renders every
screen of the app on the mock vault, in light and dark mode, and writes the
PNGs to `target/review/`: lock screen, sign-in and second factor, vault list
with a login, card, identity, Wi-Fi, SSH key and shared item, account
creation from an invitation link, the audit, Sends, emergency access and
organization members panes (with mock Sends, contacts and members), the
member invitation and edit sheets, the item editor
(with custom fields), the generator, each Settings tab, duplicates, an import
review (from a mock Apple export) and Quick Access. Nothing appears on screen:
the app runs with the `.prohibited` activation policy, never orders a window
in, never activates and never uses ScreenCaptureKit; the windows are drawn by
AppKit (`cacheDisplay`), so it works while you use the Mac, on any Space. It
uses the in-memory mock vault only (no account data is read or written) and a
separate defaults domain that is removed afterwards.

Known rendering limits: AppKit does not draw Liquid Glass and other materials
offscreen. The sidebar gets a flat background with its contents drawn on top,
toolbar buttons show as empty capsules, and the Settings tab bar is blank.

Each screen also goes through the layout audit (`LayoutAudit.swift`), which
prints `REVIEW_OK` or `REVIEW_FAIL <screen>: <problem>`. The script fails if
any screen fails.

### Layout checks

`scripts/e2e.sh` (the end-to-end walkthrough against a throwaway Vaultwarden)
and the review mode run the same layout audit on every screen they visit,
with no screenshots involved:

- split views and top-level SwiftUI hosting views fit the window's content
  view, and the window keeps the size it was given;
- no split view column is empty or squashed;
- key elements are present and fully visible below the toolbar. They are
  marked in the views with `.layoutMark("…")` (`pane-title`, `sidebar-footer`,
  `detail-title`, `search`, `lock-title`, `login-title`, `edit-title`,
  `sheet-title`, `sheet-primary`), which sets the accessibility identifier and,
  in Debug builds, adds an invisible AppKit view that the audit finds in the
  view hierarchy (SwiftUI only builds its accessibility tree for an
  assistive client, so the identifiers alone cannot be found);
- sheets fit their window and are no taller than the window they sit on.

The walkthrough reports `E2E_OK mise en page : <screen>`, or `E2E_FAIL` with
either "fenêtre principale introuvable" / "feuille introuvable" (the window is
missing) or "mise en page cassée" (the layout is broken), and keeps going so
that every broken screen is listed.

## Performance

- Rust core: `cargo run --release -p verrou-vaultwarden --example profile_unlock -- <server> <e-mail> <password>`
  times each unlock step on a real account (830 items unlock in about 12 ms).
- App: timings of launch, Touch ID, unlock and sync are logged (durations only):
  `log stream --predicate 'subsystem == "app.verrou.mac" AND category == "perf"'`.

## Roadmap

1. ✅ Core, search, macOS app and CLI on a mock vault
2. ✅ Vaultwarden sign-in: Bitwarden Rust SDK, second factor, decryption, sync, encrypted offline cache, Touch ID through the Secure Enclave
3. ✅ Browser extension (Brave, Firefox): top-of-page pill, multi-step forms, one-time codes, saving and updating accounts, generator, two-factor QR codes, cards, addresses, linking a new site to a login
4. iPhone and iPad: Face ID, system AutoFill extension
5. YubiKey: ✅ FIDO2 sign-in over USB, ✅ `hmac-secret` unlock

## License

GPL-3.0-or-later. Verrou builds on the GPL crates of the Bitwarden SDK
(`bitwarden/sdk-internal`), never on the commercially licensed code of that
repository (`bitwarden_license/`). "Bitwarden" is a trademark of Bitwarden,
Inc.; Verrou is neither affiliated with nor endorsed by it.
