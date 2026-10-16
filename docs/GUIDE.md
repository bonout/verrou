# Verrou: the full guide

Everything Verrou does, in detail. For a short tour, see the [README](../README.md).

Native password manager for a **Vaultwarden** server: a macOS app, an iPhone
app (in the iOS Simulator for now, see [iPhone](#iphone)), a browser extension for Brave and Firefox, and a CLI, built
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
  strength meter, see [Passwords and passphrases](#passwords-and-passphrases)) and secure notes
  (cards and identities on iPhone); title, folder, favorite, notes and
  **custom fields** (text, hidden, checkbox: add, remove, rename, reorder;
  linked fields are shown and kept) for every type. The rest of an item
  (passkeys, attachments) is kept intact, the old password goes to the item's
  history, and a change made elsewhere in the meantime is never overwritten.
  Trash can be restored from the web vault. Saving never waits for the
  server (see *Local-first writes* below).
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
  menu of a selected row). The change shows at once and goes through the
  outbox like single ones; sending uses Vaultwarden's bulk routes (one
  request per 500 items, one sync at the end; favorites go one by one);
  read-only shared items and items in the trash are skipped and counted, and
  trashing more than one item asks first.
- **Import and duplicates** (File → *Importer…*, ⌘⇧I): exports from Apple
  Passwords, 1Password and Proton Pass, compared with the vault before
  anything is written (new, already there, different password), sent in one
  request; Vault → *Nettoyer les doublons…* groups duplicates by confidence,
  merges them into the item you keep and moves the copies to the trash.
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
  re-encrypts the item and its attachment keys). Several items move at once
  from a multi-selection (*Partager…*, one `PUT /api/ciphers/share` request;
  items already shared, read-only or in the trash are skipped and counted).
  Read-only collections and "hide passwords" are enforced in the Rust core
  (filling in Brave still works, like Bitwarden). Only organization policies
  stay in the web vault (*Gérer dans le coffre web*).
- **Organizations and collections** (sidebar → *Coffres partagés* → **+**,
  or the File menu): *Nouvelle organisation…* creates one you own (keys
  generated by the SDK; the server may restrict this with
  `ORG_CREATION_USERS`), *Rejoindre une organisation…* accepts an invitation
  with an existing account by pasting the e-mail's *Rejoindre* link. Right
  click an organization for *Nouvelle collection…*, *Groupes…* (when the
  server sets `ORG_GROUPS_ENABLED=true`), *Renommer…* (owners) and *Quitter
  l'organisation…*; right click a collection to edit its name and who can
  access it (each member or group: view, view without passwords, edit, edit
  without passwords, manage), or delete it. An organization you joined but
  that hasn't confirmed you yet shows *En attente de confirmation*, with
  your fingerprint phrase one click away; admins see *N membres à confirmer*
  at the top of the section and on each organization's *Membres* row.
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
- **Local-first writes**: creating, editing, favorites, moving to a folder,
  trash and restore, archives, bulk actions, and logins saved from Brave or
  Firefox are encrypted by the SDK, put in an encrypted queue in the account
  folder (the outbox) and applied to the displayed vault at once: the editor
  closes, the list and the toast (*Enregistré*) update without waiting for
  the server (the Rust core takes about 25 ms on a 900-item vault, whatever
  the latency). The
  queue is then sent in the background, in order, followed by a sync; the
  extension gets its answer as soon as the login is queued. Until the server
  confirms, the item shows *En attente de synchronisation*. A new item gets a
  temporary id, replaced by the server's (the selection follows). If the
  server refuses a change (not a network error), it is removed from the
  queue, the displayed vault goes back to the server's version, and a toast
  gives the reason. Syncs never block the window: network and decryption
  run in Rust off the main thread, concurrent requests are merged (one
  running, one queued), and the new list is published in one go without
  touching the selection, the search or an open editor. Passkeys saved from
  the browser and their counters still reach the server before the site gets
  its answer.
- **Offline**: the vault stays available without network, decrypted from the
  cache (the server's response, still encrypted). Edits keep working too:
  they wait in the same queue (they survive locking and quitting). The
  sidebar footer counts *N modifications en attente*, and Verrou retries
  every 30 seconds. On reconnection (next sync or ⌘R) the queue is sent in
  order before the vault is downloaded. If an item changed elsewhere in the
  meantime, both versions are kept: yours becomes a copy named *« … (conflit
  hors ligne) »*. Attachments, sharing to a shared vault, Sends, emergency
  access and import need the server and say so. Signing out discards the
  queue (the confirmation says how many changes would be lost).
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
  VerrouiOS/    SwiftUI iPhone app (xcodegen target VerrouiOS)
  Shared/       code shared by both apps: Core (storage, Face ID / Touch ID sealing,
                VaultAccess, errors), UI (theme, labels, common views), Generated
                (Swift bindings, not versioned)
scripts/
  build-apple.sh     Rust core → VerrouFFI.xcframework (macOS, iPhone, Simulator) + Swift bindings
  install-macos.sh   Release build, signed locally, copied to /Applications
  install-ios.sh     iPhone Release build, signed with your team, installed over USB/Wi-Fi
  testflight-ios.sh  iPhone archive signed for distribution, uploaded to TestFlight (internal testing)
  demo-capture.sh    scripted demo → docs/media/
  e2e.sh             app walkthrough against a throwaway Vaultwarden
  ios-e2e.sh         iPhone walkthrough in a headless Simulator, same server
  firefox-extension.sh  extension/ → Firefox variant (manifest only differs)
  stamp-extension.sh    content-derived version for the bundled extensions
  sign-firefox.sh       Mozilla-signed (unlisted) or unsigned .xpi, run by hand
```

The Rust/Swift boundary works like this: Swift receives item **summaries**
(title, displayed username, site) once at unlock; each search keystroke only
returns **positions**. A password crosses the boundary only through `reveal`,
when the user shows or copies it. Locking frees the vault, and its secrets
(`SecretString`) are zeroed.

## iPhone

The iPhone app lives in `apple/VerrouiOS` (xcodegen target `VerrouiOS`,
bundle id `app.verrou.ios`, iOS 17 or later, iPhone only for now). Its
interface is in French, with the system's look (Liquid Glass on iOS 26).

### What it does

- **Sign in** to Vaultwarden: server, e-mail, master password, then the
  second factor (authenticator code, e-mail code, YubiKey OTP typed in).
  Security keys over NFC are not supported yet: the screen says so and
  offers the other methods. Same Rust sign-in as the Mac.
- **Unlock** with Face ID (or Touch ID) or the master password. Face ID uses
  the same Secure Enclave sealing as Touch ID on the Mac; changing enrolled
  faces sends you back to the master password. The lock screen asks for
  Face ID by itself when the app comes back.
- **Auto-lock** when the app goes to the background, after a delay chosen in
  Settings (immediately, 1 min by default, 5 min, 15 min, 1 h, never). Out
  of the foreground the screen is blurred and covered, so the app switcher
  shows nothing.
- **Vault tab**: a search field that is always visible (instant, fuzzy,
  accent-insensitive search in the Rust core), then all items, favorites,
  one-time codes, item types and templates, folders, shared vaults and
  their collections, tags, the security audit, archives and trash, with
  counts. Pull to refresh syncs. Lists have their own search, a sort order,
  swipe actions (favorite, archive, trash, restore) and a context menu
  (copy username, password, code).
- **Select several items** (*Choisir*): favorite, move to a folder (existing
  or new), archive, trash (with confirmation), restore from the trash or
  unarchive, in one go through Vaultwarden's bulk routes.
- **Item details**: tap a field to copy it, the eye reveals it, one-time
  codes count down. Logins, cards, identities, secure notes, SSH keys (copy
  the public key) and templates; custom fields, websites (copy, open in
  Safari), password history, passkeys (listed, deletable), tags, dates.
  Wi-Fi networks show a QR code. Attachments open in Quick Look, can be
  shared (Files, AirDrop) or deleted, and new ones added from Files.
- **Protected items** (master password re-prompt): Face ID, or the master
  password, valid 5 minutes per item, like on the Mac.
- **Clipboard**: secrets are copied local-only (never to your other devices
  through Universal Clipboard) with an expiry date, so iOS itself clears
  them after 90 s (30 s to 10 min in Settings); locking clears them too if
  they are still Verrou's.
- **Create and edit** logins (generator, strength meter, one-time code seed,
  websites), secure notes, **cards** and **identities** (new in this version,
  also for the Rust core), and every template; custom fields (text, hidden,
  checkbox; rename, reorder, delete), folder, favorite, notes, and the shared
  vault for a new item. Offline, edits wait in the encrypted outbox and are
  sent on the next sync (when the app comes back to the foreground, every
  5 minutes while it is open, every 30 s while changes are waiting, or by
  pulling down).
- **Shared vaults** (home → *Coffres partagés*, **+** to create or join):
  each organization opens a screen with its items, its collections (swipe
  to edit or delete the ones you manage; *Nouvelle collection…*), its
  *Membres* and *Groupes* when your role allows, *Renommer…* (owners) and
  *Quitter l'organisation…*. *Partager…* moves one item (detail menu, swipe
  right in a list) or a multi-selection into an organization, re-encrypted
  with its key; *Collections…* changes where a shared item sits. Members:
  invite (role, rights per collection), resend, change role and
  collections, revoke, restore, remove, and confirm after comparing the
  5-word fingerprint phrase. A collection's editor sets view, view without
  passwords, edit, edit without passwords or manage for each member and
  group. *Rejoindre une organisation* (home **+** or Settings → *Compte*)
  accepts an invitation by pasting its e-mail link; Settings → *Compte* →
  *Phrase d'empreinte* shows your own phrase. Banners at the top of the home
  page show *N membres à confirmer* and invitations waiting for an admin.
  Read-only items can't be edited, hidden passwords can't be shown or
  copied, and management actions only appear where Vaultwarden would allow
  them. Everything here needs the server; offline, it says so.
- **Envois** (home → *Rangement* → *Envois*): Bitwarden Send for a text or a
  file, with a lifetime, an access limit and an optional password; the link
  (which carries the key) is copied with the clipboard rules and can be
  shared.
- **Generator tab**: passwords and passphrases (same settings as the Mac),
  copied with the same clipboard rules.
- **Audit**: reused, weak and plain-HTTP passwords, and known breaches on
  request (Have I Been Pwned, k-anonymity).
- **Settings**: account, last sync, pending changes, sync now; Face ID,
  auto-lock delay, clipboard delay, lock now; site icons; about and
  licenses; sign out of this iPhone (erases the account, cache and Face ID
  sealing; asks first, and says how many offline changes would be lost).

Not on iPhone yet: Send, emergency access, sharing an item into a shared
vault after creation, import, duplicates, the browser extension, the CLI and
SSH agent, YubiKey unlock. System AutoFill is described [below](#autofill-passwords-codes-and-passkeys).

### Install on your iPhone

`scripts/install-ios.sh` builds the iPhone app in Release, signs it with your
own team and installs it on the connected iPhone:

```sh
VERROU_TEAM=<your team ID> scripts/install-ios.sh [device UDID]
```

You need, once:

- a **paid** Apple Developer account signed in to Xcode → Settings →
  Accounts, with the latest license agreement accepted (free accounts don't
  get App Groups or the AutoFill provider entitlement);
- Developer Mode on the iPhone;
- an **App Group** registered on developer.apple.com (Identifiers → App
  Groups), `group.app.verrou.<team ID in lower case>` by default or
  `VERROU_APP_GROUP`, ticked in the App IDs `app.verrou.ios` and
  `app.verrou.ios.autofill`. `xcodebuild -allowProvisioningUpdates` creates
  the App IDs but not the group; an App Group ID is unique across Apple, so
  `group.app.verrou` itself can't be reused. The app reads the group from its
  Info.plist (`VerrouAppGroup`).

Then turn Verrou on in Settings → General → AutoFill & Passwords. A
development profile carries `get-task-allow` (a debugger can attach), and
expires after a year: run the script again.

### TestFlight (internal testing)

`scripts/testflight-ios.sh` archives the iPhone app in Release, signs it for
distribution with your team and uploads it to App Store Connect, marked for
internal testing only:

```sh
ASC_KEY_PATH=~/path/AuthKey_<KEY ID>.p8 ASC_KEY_ID=<KEY ID> ASC_ISSUER_ID=<issuer> \
  VERROU_TEAM=<team ID> scripts/testflight-ios.sh
```

- The app record must exist in App Store Connect (iOS, bundle `app.verrou.ios`).
- The upload needs an App Store Connect API key with the **Admin** role: Xcode's
  cloud-managed distribution certificate refuses App Manager keys, and
  `xcodebuild` can't use the account signed in to Xcode for an upload. Keep the
  `.p8` outside the repository (`chmod 600`).
- The build number is the UTC timestamp (`VERROU_BUILD` overrides it), so
  each upload is higher than the last.
- Both targets ship a privacy manifest (`PrivacyInfo.xcprivacy`): no tracking,
  no collected data, and the required reasons for UserDefaults and file
  timestamps.
- Internal testing only: an external TestFlight or App Store release would
  distribute the GPL Bitwarden SDK under Apple's terms.

### Build and run in the Simulator

Without a developer account, the iPhone app runs in the iOS Simulator,
**signed ad hoc** (`-`, never a developer team; the project sets it for
Simulator builds):

```sh
PLATFORMS=all scripts/build-apple.sh   # macOS + iPhone + Simulator slices
(cd apple && xcodegen generate)
xcodebuild -project apple/Verrou.xcodeproj -scheme VerrouiOS -configuration Debug \
  -destination 'generic/platform=iOS Simulator' ARCHS=arm64 \
  -derivedDataPath target/xcode-ios.noindex build
```

Ad hoc signing matters: the Simulator reads the entitlements embedded in the
binary (`__TEXT,__entitlements` section), so the app group shared with the
AutoFill extension and the credential-provider entitlement work. A
`CODE_SIGNING_ALLOWED=NO` build still runs, but has no entitlements: the app
falls back to its private folder and the extension cannot see the vault.

`scripts/build-apple.sh` takes `PLATFORMS=macos` (default, what
`install-macos.sh` needs), `ios` or `all`; `IOS_TARGETS=""` skips the device
slice and `SIM_TARGETS` adds `x86_64-apple-ios` on an Intel Mac. Build the
Rust core in release (the default) for the iPhone: debug builds of the
Bitwarden SDK's futures overflow the 512 KB stacks of Swift Concurrency
threads during writes.

To try it by hand, boot a Simulator and install the app (the Simulator app
window is optional; `simctl` works headless):

```sh
xcrun simctl boot "iPhone 17 Pro"
xcrun simctl install booted target/xcode-ios.noindex/Build/Products/Debug-iphonesimulator/Verrou.app
SIMCTL_CHILD_VERROU_MOCK=1 xcrun simctl launch booted app.verrou.ios   # mock vault; without it, your server
```

**Face ID in the Simulator**: enroll a face, then answer each prompt with a
matching (or non-matching) face:

```sh
xcrun simctl spawn booted notifyutil -s com.apple.BiometricKit.enrollmentChanged 1
xcrun simctl spawn booted notifyutil -p com.apple.BiometricKit.enrollmentChanged
xcrun simctl spawn booted notifyutil -p com.apple.BiometricKit_Sim.pearl.match     # recognized
xcrun simctl spawn booted notifyutil -p com.apple.BiometricKit_Sim.pearl.nomatch   # not recognized
```

The Simulator's Secure Enclave refuses biometry-protected keys, so Simulator
builds seal the vault key with a software key instead (see
[SECURITY.md](../SECURITY.md#iphone)); device builds always use the Secure
Enclave.

### End-to-end walkthrough

```sh
scripts/ios-e2e.sh          # OUT=… for the screenshots (default target/ios-e2e)
```

It builds everything, starts a throwaway Vaultwarden in Docker
(`verrou-vw-ios`, port 8118) and creates the walkthrough account with
`seed_walkthrough_account` (an ignored tool in
`crates/verrou-vaultwarden/tests/server.rs`), then creates and boots a
dedicated Simulator ("Verrou E2E") **without opening Simulator.app**, sets
it to French, enrolls Face ID and runs the app with its Debug-only driver
(`apple/VerrouiOS/Demo/EndToEndDriver.swift`, environment passed through
`SIMCTL_CHILD_*`). The driver signs in with TOTP, searches, reveals and
copies, opens a protected item with Face ID, shows a Wi-Fi QR code, creates
and edits a login (with a custom field) and a card, acts on two items at
once, edits offline (the script cuts a TCP relay between the app and the
server) and checks the outbox is sent when the relay is back, runs the
audit, locks, unlocks with the master password and with Face ID, checks the
background auto-lock and signs out. The script answers it (screenshots with
`simctl io screenshot`, Face ID matches, network on/off), then deletes the
Simulator and the container. `SKIP_BUILD=1`, `KEEP_SIMULATOR=1` and
`KEEP_SERVER=1` help when iterating; `VERROU_E2E_SERVER` (+ `_EMAIL`,
`_PASSWORD`, `_TOTP`) uses an existing account.

### Where the data lives

`VerrouStorage` (in `apple/Shared/Core`) decides where the account folder
lives: on iPhone, in the `group.app.verrou` app group container, shared with
the AutoFill extension; without the group (a build with no entitlements), in
the app's own Application Support folder, and an account found there is
moved into the group as soon as it exists. On the Mac nothing changes. The
folder is excluded from backups.

`VaultAccess` (same folder) is the UI-free layer used by both the app and
the extension: open the vault from that folder with Face ID or the master
password, list the logins for a site, read a one-time code, sign with a
passkey, lock. All the work stays in the Rust core.

### AutoFill: passwords, codes and passkeys

The `VerrouAutoFill` extension (`apple/VerrouAutoFill`, bundle id
`app.verrou.ios.autofill`, embedded in the app) is an AutoFill credential
provider: it fills logins, one-time codes (iOS 18 and later) and passkeys
(iOS 17 and later) in Safari and in apps.

- **Turn it on** in Settings → General → AutoFill & Passwords → Verrou
  (French: *Réglages → Général → Remplissage automatique et mots de passe*).
  Verrou's own Settings tab has a *Remplissage automatique* section with the
  steps, the current state and a button that opens that page (iOS 18,
  `ASSettingsHelper`).
- **Keyboard suggestions**: after each unlock, sync or edit, the app
  publishes sites (domains), usernames and passkey identifiers to the
  system's credential identity store, never a secret. Tapping a suggestion
  opens Verrou's sheet, which asks for Face ID by itself (or the master
  password), then fills. Signing out clears the store; locking keeps it.
- **List and search**: from the keyboard's passwords button, Verrou shows the
  logins for the site (same site matching as the browser extension), the
  site's passkeys, and a search across the whole vault.
- **Protected items** need one more confirmation (Face ID or the master
  password), as in the app.
- **One-time codes**: logins with a TOTP seed show as code suggestions
  (`autocomplete="one-time-code"` fields); the current code is filled.
- **Passkeys**: when a site creates a passkey, choose *Enregistrer dans
  Verrou* in the system sheet; Verrou saves it in a new login or an existing
  one for the site, in the Bitwarden format (the official apps read it).
  Signing in with it signs in the Rust core (ES256, `authenticatorData` built
  from the `rpId` and the system's `clientDataHash`). Saving a passkey, or its
  new counter, needs the server: offline, Verrou refuses instead of queuing.
- **Writes from the extension**: it opens the shared folder as a *guest*. It
  reads the app's cache and offline queue, writes passkeys and counters
  straight to the server, then saves the refreshed cache; it never sends or
  rewrites the app's queue. File writes are atomic and serialized by a
  `flock` held only for the rename. Details in
  [SECURITY.md](../SECURITY.md#écritures-depuis-lextension).
- **Memory**: the extension peaked at 56 MB in the Simulator end-to-end test
  (iOS allows about 120 MB); the extension logs `AUTOFILL_MEMORY` lines.

**What was verified, and what needs a paid Apple account.** In an ad
hoc-signed Simulator, everything above runs for real and is covered by
`scripts/ios-autofill-e2e.sh`: the app group, the provider being picked by
iOS, the keyboard suggestion and password fill in Safari, a passkey created
in Verrou and then used to sign in (the test page checks the attestation,
the ES256 signature, the counter and the user handle), and one-time code
fill. Not verifiable without a device and a paid developer account: that the
Secure Enclave key sealed by the app opens from the extension on a real
iPhone (if not, the extension falls back to the master password once, then
seals its own key), passkeys for native apps (associated domains need a
team), and anything on a physical device.

### AutoFill end-to-end test

```sh
scripts/ios-autofill-e2e.sh    # OUT=… for the screenshots (default target/ios-autofill-e2e)
```

It builds the app, the extension and an XCUITest bundle
(`apple/VerrouAutoFillUITests`) signed ad hoc, starts its own Vaultwarden
(`verrou-vw-autofill-ios`, port 8122) with the walkthrough account, serves
the test page (`scripts/ios-autofill-page`) on `http://localhost` (WebAuthn
is allowed there without HTTPS), creates and boots a headless Simulator
("Verrou AutoFill E2E"), enrolls Face ID, installs the app and turns Verrou
on as the AutoFill provider with `pluginkit -e use -i app.verrou.ios.autofill`
(what the Settings switch does). The XCUITest then launches the app (a
Debug-only driver, `AutoFillSetupDriver`, signs in and creates the test
login with a TOTP seed), and drives Safari in the Simulator: password fill
from the keyboard suggestion, one-time code fill, passkey creation in
Verrou, passkey sign-in. The script answers every Face ID prompt, reports the
extension's peak memory (failing above 120 MB), then deletes the Simulator,
the page server and the container. `SKIP_BUILD=1`, `KEEP_SIMULATOR=1`,
`KEEP_SERVER=1` and `ONLY=<test name>` help when iterating; `VW_CONTAINER`
and `VW_PORT` pick another container. Nothing appears on the Mac's screen:
screenshots come from `XCUIScreen` inside the Simulator.

`VERROU_RECORD=<file.mp4>` also records the Simulator's screen
(`simctl io recordVideo`, still headless) and pauses `RECORD_PAUSE` seconds
(default 2) at each key step so a viewer can follow. The log prints
`RECORD_START` and `AUTOFILL_E2E_MARK` timestamps to trim it; the result is
in [`docs/media/ios-autofill.mp4`](media/ios-autofill.mp4).

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

### Duplicates

The same account often arrives several times, from Apple, 1Password and
Proton Pass, with different URLs (`connect.maif.fr`, `www.maif.fr/espace-perso`),
titles (« Maif », « maif.fr », « MAIF - Espace sociétaire ») and sometimes no
username or no URL. Vault → *Nettoyer les doublons…* compares, in the Rust core:

- the **sites** of every URL: scheme, port, path and `www.` ignored, login
  prefixes stripped (`accounts.google.com`, `m.facebook.com`,
  `connect.maif.fr` are `google.com`, `facebook.com`, `maif.fr`), and their
  registrable domain; app URIs (`macapp://`, `iosapp://`, `androidapp://`)
  only against each other; passkey sites too;
- the **title**, normalized (accents, case, punctuation, `www`, `.fr`,
  « connexion », « espace client/perso/sociétaire », parentheses) and its
  brand, compared with the first label of a domain (« Maif » ↔ `maif.fr`);
  a title that is a domain (`maif.fr`) counts as a URL;
- the **username** (trimmed, lowercase, `+tag` of an email ignored);
- the **password** and the **one-time code** secret, compared in constant
  time; Swift only gets the verdict.

Groups come in three levels, most certain first, with the reason in plain
words (« même site (maif.fr), même identifiant, même mot de passe »):

| Level | When | Copies |
|---|---|---|
| **Certain** | same site (or title brand ↔ domain), same username, same password | checked for the trash |
| **Probable** | same site and username, another password; or same password, one username missing; or same title and username without URL | suggested, not checked |
| **À vérifier** | same site, different usernames but the same password; title only without usernames; two subdomains of one domain (`cloud.example.com` and `vault.example.com` are usually two services) | never checked |

Different item types never mix (cards compare their number, notes their
title and content), personal and shared items are only compared within the
same vault, and read-only items are left out. An item without a username
only joins a group when a single account on the site matches.

In each group Verrou keeps the item with passkeys or attachments (they do
not move), then a one-time code, then the most recently modified, with a
URL, the most complete, the longest history; *Garder* picks another one.
**Fusionner et mettre les autres à la corbeille** copies into the kept item
the URLs of hosts it lacks, the username and one-time code if missing, the
notes (appended under the source title), the custom fields it does not have
and the other passwords into its password history; the most recently
changed password stays the current one. It is written like an edit
(revision date checked, offline outbox), then the others go to the trash,
restorable from the web vault for 30 days. **Ignorer ce groupe** remembers
the group on this Mac (by a hash of its item ids, so it comes back if it
changes); the footer shows them again. Grouping 10,000 items takes about
40 ms.

The import review uses the same signals but stays conservative: only a
**Certain** match is skipped automatically; a **Probable** one updates the
vault item (new password in, the old one to its history; or it completes
it), and anything weaker is created.

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
# crates/verrou-vaultwarden/tests/server.rs (organizations: tests/organizations.rs, offline edits: tests/offline.rs,
# local-first writes behind a slow link: tests/optimistic.rs)
VERROU_TEST_SERVER=http://localhost:8099 cargo test -p verrou-vaultwarden
# Members and invited sign-up on a sign-ups-closed server (with or without
# e-mail, through a Mailpit inbox): see the header of tests/members.rs
VERROU_TEST_MEMBERS_SERVER=http://localhost:8119 cargo test -p verrou-vaultwarden --test members
# Sharing end to end (owner, member, new invitee; bulk share with an
# attachment, collection rights, groups, leave): see the header of tests/sharing.rs
VERROU_TEST_SERVER=http://localhost:8099 cargo test -p verrou-vaultwarden --test sharing

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
(with custom fields), the generator, each Settings tab, duplicates (mock
groups of every level, then one ignored and another kept item), an import
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
  After a sync, the line *synchronisation appliquée* splits the reload into
  the part read off the main thread and the part on it.
- Writes: `VERROU_TEST_SERVER=… cargo test --release -p verrou-ffi --test latency -- --ignored --nocapture`
  times saving, favoriting and creating on a 900-item vault, from the call to
  the list showing the change, directly and with 300 ms added to every round
  trip.

## Roadmap

1. ✅ Core, search, macOS app and CLI on a mock vault
2. ✅ Vaultwarden sign-in: Bitwarden Rust SDK, second factor, decryption, sync, encrypted offline cache, Touch ID through the Secure Enclave
3. ✅ Browser extension (Brave, Firefox): top-of-page pill, multi-step forms, one-time codes, saving and updating accounts, generator, two-factor QR codes, cards, addresses, linking a new site to a login
4. iPhone: ✅ app in the Simulator (Face ID, vault, editing, offline), ✅ system AutoFill (passwords, one-time codes, passkeys) in the Simulator; a signed build for real iPhones and iPad later
5. YubiKey: ✅ FIDO2 sign-in over USB, ✅ `hmac-secret` unlock

## License

GPL-3.0-or-later. Verrou builds on the GPL crates of the Bitwarden SDK
(`bitwarden/sdk-internal`), never on the commercially licensed code of that
repository (`bitwarden_license/`). "Bitwarden" is a trademark of Bitwarden,
Inc.; Verrou is neither affiliated with nor endorsed by it.
