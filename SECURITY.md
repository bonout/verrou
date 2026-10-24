# Security

Verrou holds passwords: every choice below is deliberate, and any PR that
touches one of these points says so in its description.

## Principles

1. **No home-made cryptography.** Vault encryption comes from the crates of
   Bitwarden's Rust SDK (the code of the official apps, pinned to a
   commit); the remaining primitives, from CryptoKit and the Secure Enclave.
2. **Secrets stay in Rust as long as possible.** `SecretString` is zeroed on
   drop and never shows up in a `Debug`. Swift receives a secret value only
   on explicit request (`reveal`), at the moment it is shown or copied.
   Known limit: a Swift `String` cannot be zeroed; its lifetime is therefore
   kept short (forgotten as soon as another item is selected or the vault
   locks).
3. **Nothing secret is indexed.** Search covers the title, the displayed
   username, the sites, the folder and the tags. A note's subtitle is never
   taken from its content (a test checks this).
4. **Clipboard**: types `org.nspasteboard.ConcealedType` and
   `TransientType`, cleared after 90 s, and only if the content is still
   ours.
5. **Locking**: inactivity (10 min), sleep, screen locked, end of session.
   Locking releases the vault.
6. **Careful writes**: encrypted by the SDK, sent with the known revision
   date (the server refuses to overwrite a newer version), touching only the
   fields the edit screen shows. They go through an encrypted queue, sent in
   the background or when the network comes back (see "Offline changes").
7. **Sandboxed app**, hardened runtime; incoming, only the bridge to the extension and the terminal, on `127.0.0.1`.

## Connecting to Vaultwarden

- **What the SDK does**: derivation of the master password (PBKDF2 or
  Argon2id, depending on the account), decryption of the user key, the
  private key, the organization keys, the folders and the items. Verrou
  only does the HTTP transport and the conversion to its model.
- **What is sent**: the authentication hash derived by the SDK, never the
  password. HTTPS required (HTTP only for `localhost`, the tests).
- **What is on disk** (`account.json`, in the app container, mode 600): the
  user key encrypted by the master key, the encrypted private key, the sync
  response as the server sends it (encrypted), and the refresh token
  **encrypted by Verrou with the user key**: without the master password (or
  Touch ID), the file allows neither reading the vault nor talking to the
  server. A test checks that no secret appears in it in plaintext.
- **Second factor with a security key** (YubiKey over FIDO2): Verrou talks to
  the key **directly over USB** (CTAP2 protocol, through `authenticator-rs`,
  Firefox's library; entitlement `com.apple.security.device.usb`, which
  requires no developer team). Like a browser, it writes `clientDataJSON`
  with the server's origin and the received challenge; the key signs the
  hash of the domain and that of `clientDataJSON` after a touch: the
  signature is only valid for this server, and the server verifies it. No
  PIN (the server asks for `discouraged`); if the key requires one, Verrou
  points to the fallback. An integration test registers a software key on a
  real Vaultwarden and checks that it accepts Verrou's response and refuses
  a tampered signature.
- **Browser fallback**: the page Vaultwarden publishes for the mobile apps
  (`webauthn-mobile-connector.html`), in an ephemeral Safari session
  (`ASWebAuthenticationSession`). "Remember this device" is not used: a
  new sign-in asks for the second factor again.
- **Site icons**: requested from the account's server
  (`/icons/<site>/icon.png`, like the Bitwarden apps), which receives only
  the site name, without authentication. Ephemeral network session and
  in-memory cache, cleared on lock: the list of sites does not stay in
  plaintext on disk. Can be turned off in the settings.
- **Writing**: the item comes from the cache, decrypted by the SDK; Verrou
  applies the changed fields to it, the SDK re-encrypts it (with the item's
  key or its organization's), then `POST`/`PUT /api/ciphers` and a sync. A
  replaced password joins the item's history (5 entries, like Bitwarden).
  Items an account cannot modify (read-only sharing) are refused before
  anything is sent. To edit, Swift receives the item's secrets
  (`edit_draft`): only when the user opens the edit screen (hidden custom
  fields included). Fields reserved for Verrou (`verrou:type`, which names a
  template such as "Wi-Fi network") are never offered to it and go back
  unchanged. The trash is the server's (`PUT /api/ciphers/{id}/delete`),
  restorable.
- **Wi-Fi QR code**: the content (`WIFI:T:WPA;S:…;P:…;;`, password
  included) leaves Rust (`wifi_qr_code`) only when the user asks for the QR
  code, after the confirmation of a protected item; Swift keeps only the
  image, for the time of the popover.
- **Import** (Apple, 1Password, Proton Pass): the export file is **in
  plaintext**, it contains every password. Verrou reads it only on request,
  once, through the macOS open panel (entitlement
  `com.apple.security.files.user-selected.read-write`, which attachments'
  "Save As…" requires; limited to the chosen file); it does not copy it,
  keep it or write anything to it. The files of an archive (1Password,
  Proton Pass) become attachments: read into memory (100 MB per file,
  512 MB per archive), encrypted like an addition, the item created alone
  then its files. The Rust core reads it and compares it with the vault;
  secrets stay in `SecretString`s until the import, the cancellation or the
  lock, and the review shows Swift only titles, usernames and sites, with
  the verdict of the password comparison. Known limit: the CSV and JSON
  readers keep intermediate copies that are not zeroed. Items are encrypted
  by the SDK like a creation, then sent in one request
  (`POST /api/ciphers/import`, like the web vault); folder names go out
  encrypted. A replaced password joins the item's history. Verrou
  recommends deleting the export file after the import (and emptying the
  Finder's trash). Encrypted exports (Proton Pass PGP) are refused: export
  without encryption.
- **Duplicates**: compared in Rust (sites and domains, title and brand,
  username; passwords and TOTP seeds in constant time, grouped during the
  computation by an in-memory hash, never written); Swift receives only the
  groups, their degree (certain, likely, to check), the reason in plain
  words and the "identical password or not" verdict. Merging (`merge.rs`)
  happens in Rust on the decrypted item, through the write path of an edit
  (revision date, offline queue); attachments and passkeys are never moved
  (merge refused). Ignored groups are kept in the app's preferences as a
  truncated SHA-256 hash of the items' identifiers, with no title or site.
  Bulk trash (`PUT /api/ciphers/delete`) is the server's, restorable, and
  nothing is sent if an item is not editable. Protected items ("re-prompt
  for the master password") are compared like the others, at import as
  here: only the verdict comes out, no secret.
- **Bulk actions** (several selected items, `bulk.rs`): same write path as a
  single item. Trash, restore, archives and folders through Vaultwarden's
  bulk routes (`PUT /api/ciphers/delete`, `…/restore`, `…/archive`,
  `…/unarchive`, `…/move`), in batches of 500; a refused batch is retried
  item by item to find which one. Favorites, with no bulk route, go one by
  one like an edit (encrypted by the SDK, known revision date: an item
  changed elsewhere is refused, never overwritten). Read-only items (and
  those in the trash, except to restore) are set aside before anything is
  sent, and counted. Offline, each item joins the queue as a single action.
  Moving several items to the trash asks for confirmation. The selection
  itself contains only identifiers: no secret.
- **Attachments** (Bitwarden format): each file has its own key (64 bytes,
  drawn by the SDK), encrypted by the item's key (or the user's, or the
  organization's); the file name is encrypted like a field; the content is a
  type 2 `EncArrayBuffer` (AES-256-CBC, HMAC-SHA256 checked before any
  decryption). The SDK does all this cryptography; a test reads back a file
  encrypted by Bitwarden, another checks that one tampered byte makes
  everything fail. Upload in two steps (`POST …/attachment/v2`, then the
  encrypted content to the returned address, which must be on the account's
  server; the reservation is deleted if the upload fails), download through
  the signed address the server gives, over HTTPS (HTTP only to
  `localhost`). 100 MB per file.
  **Nothing is kept offline**: the cache contains only the encrypted
  metadata of the sync; a file is downloaded each time it is opened.
  Decrypted in Rust (buffer cleared on drop), it goes to Swift: for Quick
  Look, into a temporary file in the app container (`tmp/pieces-jointes`,
  mode 600), deleted when the preview closes, when another item is
  selected, on lock and on the next launch; "Save As…" writes a
  **plaintext** copy, where the user chooses (entitlement
  `com.apple.security.files.user-selected.read-write`, limited to files
  chosen in the macOS panels or dropped on the window). A protected item
  gives up its files only after confirmation. Limits: the copy passed to
  Swift (`Data`) is not zeroed, and Quick Look may keep its own thumbnail
  in cache.
- **Shared vaults (organizations)**: each organization's key arrives in the
  profile, encrypted with the account's public key (RSA-OAEP); the SDK
  decrypts it with the private key and uses it for collection names and the
  organization's items. It stays in the SDK, never in Swift nor on disk in
  plaintext (the cache keeps the server's encrypted version). Creating in a
  collection (`POST /api/ciphers/create`), sharing a personal item
  (`PUT /api/ciphers/{id}/share`) or changing its collections
  (`PUT /api/ciphers/{id}/collections_v2`): the SDK encrypts with the
  organization's key, the keys of the item and its attachments included
  (the attachments' content is not downloaded again); attachments in an old
  format, without their own key, make the sharing refused. The permissions
  the server announces are enforced before anything is sent: a read-only
  collection is neither modified nor offered as a destination (the server
  checks it anyway); "hide passwords" is enforced in the Rust core:
  password, TOTP seed, hidden fields and old passwords go neither to Swift
  (`reveal`), nor to the terminal, nor into an edit draft; only filling by
  the extension stays allowed, as in the Bitwarden apps. Duplicates only
  compare items of the same vault, and never a read-only item. Members,
  organizations, collections and groups are managed in Verrou (see "Sharing
  with other accounts" and "Organization members"); the organization's
  rules (policies), in the web vault.
- **Offline changes, and writes without waiting** (`outbox.rs`): online as
  offline, a creation, an edit, a favorite, a folder change, the trash, a
  restore, archives (single or bulk) and logins saved from the browser are
  applied to the displayed vault and wait in a queue, `outbox.json`
  (account folder, mode 600); sending follows immediately, in the
  background, and the extension gets its answer as soon as the local write
  is done. Online, a passkey created from the browser and its counter go to
  the server before the answer to the site; attachments, sharing and import
  do not go through the queue. The item is in it **already encrypted by the
  SDK**, exactly as it would have been sent (same key, same known revision
  date); the whole queue is in addition encrypted by the user key (like the
  refresh token). In plaintext in the file: the account identifier and the
  number of pending changes (to warn before a sign-out, vault locked). A
  test checks that no title or secret appears in it. Locking keeps the
  queue; signing out deletes it (the confirmation says how many changes
  would be lost); a queue from another account is ignored and deleted.
  The queue goes out before the vault is read: creations and edits first,
  in order, then trash, archives and folders (in batches). Sending does not
  keep the connection locked during network calls: a write made meanwhile
  goes behind the one being sent (never merged with it) and starts again
  from the revision date the server returns, without overwriting anything
  else. A sign-out during a send stops any write of the queue to disk; a
  lock stops it after the request in progress (the user key stays in memory
  for that request, 30 s at most, as for any request already sent), the
  rest waits for the next unlock. If the item changed (or disappeared) on
  the server in the meantime, the server refuses the edit; Verrou does not
  overwrite it: the local version becomes a copy, "title (offline
  conflict)", in the same place, without its attachments, and the server's
  version comes back. An edit refused for another reason (and whose copy is
  refused too) is removed from the queue, the displayed vault goes back to
  the server's version, and the refusal is reported with its reason: never
  lost silently. Still impossible offline, with a clear message:
  attachments, sharing to an organization (and creation in a collection),
  Sends, emergency access, import. Read-only items stay read-only. Logins
  saved from the browser follow the same path. Known limit: a write whose
  response is lost (cut during the send) may go out again when the network
  comes back; a creation may then be duplicated, an edit becomes a conflict
  copy (nothing is lost).
- **Known limits**: the per-item master password prompt ("reprompt") is not
  enforced.

## Browser extension

```
extension ──Native Messaging──▶ verrou-native-host ──TCP 127.0.0.1──▶ Verrou
```

- **Why TCP**: the macOS sandbox denies the app (signed locally, without a
  developer team) any Unix socket outside its container, for listening as
  for connecting; it allows listening on `127.0.0.1`
  (`com.apple.security.network.server`). This port can be reached by any
  program on the machine: nothing travels over it in plaintext, and nothing
  is served on it without pairing.
- **Pairing**: the extension creates an ECDH P-256 key (WebCrypto, not
  extractable); Verrou answers with an ephemeral key; HKDF-SHA256 derives
  the channel key from them. Both sides show a 6-digit code derived from
  this key: the user accepts it in Verrou if it is identical ("Decline" is
  the default button). One request at a time, at least three seconds
  between two, two minutes to answer.
- **Channel**: AES-256-GCM, random nonce, associated data = client and
  direction of the message; each request carries a timestamp (± 2 min)
  against replay. The Native Messaging host relays encrypted bytes without
  reading them.
- **What the extension gets** (`verrou-bridge/src/access.rs`): the list of
  logins (title, username) that match the page's site, and the secrets of a
  login only if it matches that site — same registrable domain, like
  Bitwarden — and if the page is on HTTPS (HTTP only to `localhost`). The
  address comes from the browser (`sender.url`), never from the page. Vault
  locked: nothing, except the unlock request.
- **If the pairing key is stolen**: it is the extension that asserts the
  page's address. A program that read the key from the browser profile
  (same macOS user) could claim every login for its own site. Verrou makes
  such looting visible: beyond 8 different items delivered to a client in
  10 minutes (logins, identities, passkeys), each further item asks for
  approval in Verrou (Touch ID), kept 5 minutes for that item; a card and a
  site added to a login always ask for it. The extension's identifier is not
  a proof (the manifest's public key sets this identifier for whoever copies
  it): only pairing is.
- **What the extension writes**: after a form is submitted, the username
  and password entered wait for the user's answer for two minutes at most,
  in `chrome.storage.session` (in memory, out of the pages' reach). Nothing
  is written without a real click on the banner. Verrou checks each write
  again: a new item for the page's site, or the new password (or
  verification code) of a login that matches that site, over HTTPS. The old
  password joins the item's history. A malicious page can at worst offer to
  save whatever it wants for its own site, and the user has to accept it.
- **Generator**: in the extension (`generator.js`), same rules as Verrou's,
  unbiased randomness from `crypto.getRandomValues`. It asks nothing of
  Verrou and works with the vault locked.
- **Two-factor QR code**: on a click in the extension's popup, an image of
  the visible tab (permission `activeTab`, valid only after that click) is
  read by Brave's barcode reader, inside the extension; the image is
  neither kept nor sent. Only the `otpauth://` URI goes to Verrou, for the
  chosen login. Firefox has no barcode reader: the key is entered by hand
  there.
- **Cards and identities**: the pill of a payment or address form receives
  only titles and masked subtitles ("Visa •••• 4242"); the fields come out
  only when an item is chosen, to a page on HTTPS, and a protected item
  waits for confirmation in Verrou. Since a card is linked to no site, any
  secure page can offer it: it is the user who chooses to fill it, and
  Verrou asks for Touch ID for each card (approval kept 5 minutes for that
  card).
- **Linking a site to a login**: only from the extension's popup, never
  from a page. The pill's "Fill with another login…" (real click) only opens
  the popup on that choice, for the tab and frame the click came from
  (address given by the browser, `sender.url`); since Firefox does not open
  the extension's popup outside a click on its icon, it is then a small
  extension window. The search there shows only titles and usernames;
  choosing an item adds the frame's origin to it (after a phishing warning,
  then approval in Verrou, Touch ID, which names the site and the item), and
  filling follows the usual same-site rule.
- **Filling requested by the extension's popup**: the credentials go to the
  targeted frame with the origin for which Verrou gave them; `content.js`
  fills only if its frame is still at that origin (the page may have
  changed in the meantime).
- **In the page**: the pill (top left), the Verrou icon of the active field
  and the save banner live in closed shadow DOMs and obey only real events
  (`isTrusted`); the page can neither read nor trigger them (a click it
  sends to the host does not reach the buttons). Their hosts are held in
  place by inline `!important` styles (fixed position, maximum `z-index`,
  opacity): a page style sheet neither hides nor moves them; a page script
  can still remove them or draw an imitation, but an imitation fills
  nothing. The pill does not take focus; it shows only the site, titles and
  usernames.
- **Clickjacking**: the page can make the pill invisible without touching
  its styles (opacity, filter, clip or mask on `<html>`), cover it with a
  decoy, or slide the field under the pointer. A mouse click counts only if
  `<html>` is neither transparent, filtered, clipped nor masked, if the
  pill is the element under the pointer (`elementFromPoint`), and if it has
  been shown for at least 300 ms. Chrome and Brave also report anything
  covering it, even without capturing clicks (`IntersectionObserver` v2,
  `trackVisibility`); Firefox cannot tell, hence Touch ID for cards.
  Secrets arrive only at fill time, for the chosen item. The save banner
  does not receive the password.
- **Submitting after filling**: only for a sign-in (username, password,
  code), after a real click in the pill (`isTrusted`) or a choice in the
  extension's popup; never for a card, an address or a generated password,
  so never for a payment form. The form is submitted (`requestSubmit`, with
  its button) only if the filled values are still there, no other visible
  field is left empty and no captcha is visible; a following step (password
  after the username) waits for a new click. Setting "Submit the form after
  filling" in the extension's popup (`storage.local`, on by default);
  turned off, the cursor goes to the submit button and nothing is sent.
  Credentials submitted as Verrou filled them: no offer to save.
- **When the extension queries Verrou**: when a page loads that shows a
  sign-in form (password field, a username field that presents itself as
  such, or verification code), once per step of the form, to know whether
  to show the pill; before, it was on first entering the field. The request
  carries only the frame's address, given by the browser, and opens Verrou
  in the background if it is not running (like a passkey request). Cards
  and addresses: only on first entering one of their fields.
- **What is on disk**: on Verrou's side, `bridge-clients.json` (app
  container, mode 600) keeps the key of each paired extension; on Brave's
  or Firefox's side,
  the non-extractable AES key in IndexedDB. These keys give only what the
  extension gives. Settings → *Unlink* revokes a client.
- **Declaration to the browser**: `NativeMessagingHosts/app.verrou.bridge.json`
  allows only the identifier of Verrou's extension: `allowed_origins`
  for Brave and Chrome (identifier set by its manifest's key),
  `allowed_extensions` for Firefox (`verrou@verrou.app`, set by
  `browser_specific_settings.gecko.id`); a test checks that app, host and
  manifests agree. The host also refuses to be launched for another
  extension (`unknown_extension`), based on its arguments: the extension's
  origin (Brave), or the manifest path then the identifier (Firefox).
  Sandbox entitlements limited to the `NativeMessagingHosts` folders of
  Brave, Chrome and Firefox (`Mozilla`).
- **Firefox**: the same extension (`scripts/firefox-extension.sh` changes
  only the manifest); Firefox 128 at least, for the passkey script in the
  page's world. Site access (`host_permissions`) is granted or revoked by
  the user; without it, no Verrou script runs in pages, and the extension's
  popup offers to request it. In the isolated world, objects coming from the
  page are seen through "Xrays": `passkeys.js` copies the request (JSON)
  before using it. Unsigned, the extension can only be loaded temporarily
  (about:debugging): Firefox removes it on quit, with its channel key (it
  has to be linked again; unlink the old one in Verrou). Signed by Mozilla
  (`scripts/sign-firefox.sh`, "unlisted" distribution), Mozilla sees its
  code, not the data: nothing leaves the Mac
  (`data_collection_permissions: none`).
- **Extension updates**: the copy shipped in `Verrou.app` receives at build
  time a version derived from the hash of its files
  (`scripts/stamp-extension.sh`). The bridge announces this version (answer
  to `status`, read from the manifest in the app bundle); the extension
  compares it with its own and with that of the manifest on disk, at
  startup, at each connection to Verrou and every ten minutes, and reloads
  (`runtime.reload()`) if they differ: once per version at
  most, once per minute at most (`storage.local`). Firefox reloads only
  for a manifest changed on disk (temporary extension): an installed add-on
  (.xpi) would not change by reloading, the extension's popup only warns.
  It rereads only its own files; an announced version loads nothing other
  than the folder the user already chose.
- **Known limits**: a program that reads the browser profile can extract
  the channel key from it (like cookies); the extension is loaded in
  developer mode (no Chrome Web Store). Tabs opened before a reload keep the
  old, detached script: the page must be reloaded.

## Emergency access

- **Confirming a contact** amounts to entrusting them with the vault key:
  it is encrypted for their public key (RSA-OAEP-SHA1, by the SDK, like the
  web vault) and entrusted to the server, which cannot read it. The public
  key comes from the server (`/api/users/{id}/public-key`): a malicious
  server could put its own there. Verrou therefore first shows the
  fingerprint of this key (the 5-word phrase of the Bitwarden apps), to be
  compared with the one the contact reads in their account; on sending, the
  key is read again and refused if its fingerprint is no longer the one
  that was verified.
- **Opening a grantor's vault** (read-only, access granted): the grantor's
  key, encrypted for me, opens with my private key, in the SDK; their items
  are decrypted in Rust and kept in a separate object. Swift receives only
  their summaries, and the secrets one by one, on request. Closing the
  window or locking Verrou empties this object (secrets zeroed); it also
  empties itself if the connection that opened it goes away.
- **Takeover** (new master password for the grantor): not in Verrou, only
  in the web vault.

## Sharing with other accounts

- **Where organization keys come from**: only from the profile returned by
  the server, where each key is encrypted for the account's public key
  (RSA-OAEP); the SDK decrypts it with the account's private key and keeps
  it in its key store. Swift never sees a key, neither an account's nor an
  organization's: only names, identifiers and permissions.
- **Creating an organization**: the organization key (AES-256-CBC-HMAC)
  and its RSA key pair are drawn in the SDK's key store; the server
  receives the key encrypted for my public key, the organization's private
  key encrypted by the organization key, and the name of the first
  collection encrypted, as with the web vault. Nothing comes out in
  plaintext, and the working keys are cleared at the end of the operation.
  The server may refuse (`ORG_CREATION_USERS`).
- **Sharing one or more items**: each is decrypted then re-encrypted by the
  SDK under the organization key, attachment keys included (their content
  is neither downloaded again nor uploaded again). Bulk sharing sends the
  batch in one request (`PUT /api/ciphers/share`); items already shared,
  read-only or in the trash are set aside before anything is sent,
  protected items ask for confirmation (Touch ID or master password). Once
  shared, an item can be read by everyone who has the organization key and
  access to its collection: sharing is not undone by removing the key (a
  member may have copied it).
- **Collections and groups**: collection names are encrypted by the
  organization key; group names are in plaintext on the server (Bitwarden's
  format), like members' addresses. Permissions (read-only, hidden
  passwords, manage) are checked in Rust before anything is sent, then by
  the server; "hide passwords" is a display restriction enforced by the
  client, as in the Bitwarden apps: the item is encrypted for the member,
  who could read it with another client. For a real secret, do not open the
  collection.
- **Joining an organization**: the pasted invitation link is read in Rust
  (token signed by the server, address, organization) and is never stored;
  the invitation must target the address of the open account. Accepting
  gives no access: until an administrator has confirmed me by comparing my
  fingerprint phrase (shown next to the pending invitation), I do not have
  the organization key. On the administrator's side, a member key is never
  used without this verification (see below).
- **Removing from sharing**: Bitwarden has no reverse path (the server
  refuses to change the organization of an existing item), and its apps
  only offer to clone to "My vault" then delete the original. Verrou does
  the same in one action: the item is decrypted, its attachments are
  downloaded and decrypted in memory, then a copy is encrypted by the SDK
  under the account key with a **new** item key (the organization does not
  know the copy's key; history, passkeys, TOTP seed, fields and match rules
  follow) and the attachments are re-encrypted under new keys and uploaded
  again. Only then is the organization's item permanently deleted; if the
  deletion fails, the copy is removed (no duplicate). One must be able to
  edit and delete the item, and see its passwords: otherwise the copy would
  reveal what the organization hides. A confirmation is asked (and Touch ID
  or the master password for a protected item). What was shared stays
  shared: a member may have copied the item before its removal.
- **Offline**: everything related to sharing requires the server and stops
  with a clear message; nothing goes into the offline changes queue, which
  cannot re-encrypt for an organization (nor, for a removal, upload
  attachments again).
- **iPhone**: same rules, same Rust core. The pasted invitation link goes
  through the system's "Paste" button (no silent clipboard read). No
  universal link to the app: it would need an
  `apple-app-site-association` file on everyone's server and an associated
  domain signed by an Apple team. The link of a Send, which carries its
  key, is copied locally only and expires like other secrets.
- **Logs**: no key, no decrypted item or collection name, no invitation
  token is written to the logs; error messages only quote the title of a
  refused item, on screen.

## Organization members

- **Without an admin token**: Verrou never uses Vaultwarden's admin panel
  (`/admin`, disabled on a careful server). This token gives the whole
  server (accounts, settings, deletion) to whoever holds it; keeping it in
  a desktop app, or entering it at each invitation, would widen the attack
  surface a lot for no gain. Adding someone goes through an organization
  invitation (`INVITATIONS_ALLOWED=true`), with the signed-in account's
  permissions: owners and administrators manage, a manager with access to
  all collections sees the list, the others nothing. Vaultwarden's rules
  (only an owner invites, confirms, removes or promotes a manager, an
  administrator or an owner) are checked in Rust before anything is sent;
  the server checks them anyway. Before each action on a member, their
  state and account are read again from the server: the interface supplies
  only identifiers.
- **Confirming a member** amounts to entrusting them with the organization
  key: it is encrypted for their public key (RSA-OAEP-SHA1, by the SDK, like
  the web vault) and entrusted to the server, which cannot read it. The
  public key comes from the server (`/api/users/{id}/public-key`): a
  malicious server could put its own there and read the whole shared vault.
  Verrou therefore first shows the fingerprint of this key (the 5-word
  phrase of the Bitwarden apps), to be compared out loud with the one the
  member reads in their account (Verrou: Settings → Account; web vault:
  Settings → My account); on sending, the member and their key are read
  again and nothing goes out if the fingerprint is no longer the one that
  was verified. The same phrase, computed from my private key (never from
  the server), is shown in Settings → Account for whoever confirms me.
- **Creating an account** (sign-in screen): the SDK derives the master key
  from the password (PBKDF2-SHA256 with 600,000 iterations, or Argon2id
  3 × 64 MiB × 4, the Bitwarden apps' defaults), draws the user key and the
  RSA key pair; the server receives only the authentication hash and the
  encrypted keys. Password of at least 12 characters, strength shown
  (zxcvbn, through the SDK), confirmation required; the hint, if there is
  one, is stored **in plaintext** on the server (the screen says so, and
  refuses a hint equal to the password). With sign-ups closed, Vaultwarden
  1.37.4 accepts only: the signed token of the invitation link (server with
  email; the address must be the invitation's), or a verification token it
  returns directly only to invited addresses on a server without email. The
  pasted link is read in Rust; its token serves only for sign-up and
  acceptance, and is not kept beyond the session. Known limit: the entered
  password goes through a Swift `String` (as at sign-in).

## Sharing notifications

Verrou notifies of an accepted invitation awaiting confirmation, of a
confirmed access ("You now have access to …"), of members to confirm
(administrators), of new items in an organization and, on Mac, of
emergency access requests and approvals. Setting: "Sharing notifications"
(Mac: Settings → General; iPhone: Settings → Notifications).

- **Local only**: notifications are computed and posted on the device
  (`UserNotifications`, no remote trigger). No push notification service:
  Vaultwarden's relay (`PUSH_ENABLED`) goes through Bitwarden's servers and
  serves only the official apps (Bitwarden's app identifiers and APNs
  certificates); Verrou does not use it and registers no device token.
- **Content**: the organization's name (which the server already sends in
  plaintext in the sync), the other person's address for emergency access,
  and numbers. Never a password, a login username, an item title or a
  collection name (they are encrypted, and the computation does not decrypt
  them). Depending on system settings, this text may show on the lock
  screen.
- **What is computed, and from what** (Rust core, `activity`): the sync
  response already downloaded, without a key (confirmed organizations,
  accepted memberships `organizationsNew`, item identifiers and their
  organization); vault open, the server with the access token (members to
  confirm, emergency access). An invitation not yet accepted exists nowhere
  for the invitee: Vaultwarden 1.37.4 does not put it in its sync and
  returns it through no route; only the email carries it. The invitation
  link is given to no one else ("resend" resends the email): Verrou
  therefore does not offer to copy it.
- **No repetition**: `activity.json`, in the account folder, keeps what has
  already been seen, as identifiers only (organization, item, membership,
  emergency access), never a name. It survives relaunches, is deleted on
  sign-out, and is never written by the AutoFill extension. The first
  observation of an account notifies nothing. An item created in an
  organization from this device is marked seen there immediately; an
  organization one owns is not announced.
- **Authorization**: requested when sharing concerns the account (an
  organization after a sync, or opening the sharing screens), never at
  first launch.

### Live updates (Mac, and iPhone in the foreground)

With the vault open, Verrou opens Vaultwarden's notification channel
(`/notifications/hub`, `SignalR` over `WebSocket`, the web vault's). The
server pushes only the kind of a change (item, organization keys,
settings…) and the device that made it, never content: Verrou syncs again,
then examines what is new. The access token stays in Rust and goes in the
`Authorization` header (not in the address, which a proxy may log); the
server checks it only when the channel opens. TLS through rustls and the
webpki roots, like the other requests. The channel
is closed on lock; if lost, it is reopened with an increasing delay
(2 s to 5 min). Vaultwarden pushes nothing when a member accepts an
invitation nor for emergency access: those arrive with the periodic sync
(5 minutes, 2 without a channel).

### iPhone in the background

iOS sometimes wakes the app (`BGAppRefreshTask`, at the earliest 30 minutes
after going to the background, at a time it chooses, or never). This
wake-up never unlocks the vault and decrypts nothing:

- **lock delay exceeded**: the vault is locked first, the user key leaves
  memory;
- **vault still open** (within the chosen delay): sync and examination as
  in the foreground, with the key already in memory; nothing is kept longer
  than the delay allowed;
- **vault locked**: only the cache already on the device, without a key or
  network. The refresh token is encrypted by the user key: without it, no
  access token, so nothing new from the server. This case sees only what
  arrived in the cache without being examined (sync by the AutoFill
  extension, app interrupted before the examination).

Accepted consequence: with the vault locked, an accepted invitation or a
shared item is notified the next time the vault is opened, not before.
Keeping a refresh token readable without the key (to query the server while
locked) would give anyone who reads the app container access to the account
on the server: refused.

## Sends (Bitwarden Send)

- **Cryptography**: the SDK's (`bitwarden-send`), like the web vault.
  Each Send has its key, 16 random bytes; HKDF-SHA256 (salt
  `bitwarden-send`, info `send`) derives from it the 64-byte key that
  encrypts the name, the notes, the text, the file name and its content.
  The Send's key is kept on the server encrypted by the user key. Tests
  recompute the derivation and the password hash without the SDK.
- **Files**: the content forms a single `EncArrayBuffer` (type 2, IV, MAC,
  ciphertext), encrypted directly by the Send's key, like the Bitwarden
  apps; the server sees neither the name (the uploaded file carries the
  encrypted name) nor the content, only the encrypted size. Upload in two
  steps (`POST /api/sends/file/v2`, then the content to the returned
  address, which must be on the account's server); if the second step
  fails, the Send is deleted. Fallback to the old `POST /api/sends/file`
  for a server without v2. 100 MB at most, checked before any encryption;
  the server's quota (`USER_SEND_LIMIT`) applies as well. A file is read by
  Swift only at creation, then passed to Rust (`Data` copy not zeroed, as
  for attachments). A Send's file never changes: an edit touches only the
  settings. Tests check the round trip with only the link's key and that
  one tampered byte makes everything fail; an integration test downloads the
  file as an anonymous recipient (with and without a password) and compares
  the bytes.
- **Link**: `<server>/#/send/<access>/<key>`. The key follows the `#`: the
  recipient's browser never sends it to the server. The link therefore
  gives the content: Verrou copies it like a secret (concealed clipboard,
  cleared after 90 s) and does not keep it. Swift receives a Send's link and
  text only on request (copy, edit screen); the list carries only its name,
  counters and dates.
- **Password**: never sent; only its hash (PBKDF2-SHA256, 100,000
  iterations, salted by the Send's key), which the server compares. An edit
  without a new password keeps the old one; removing it is a separate
  action (`PUT /api/sends/{id}/remove-password`).
- **From an item** ("Send Securely…"): the field leaves the Rust core only
  after the confirmation of a protected item, and the prefilled Send
  (hidden for the recipient, a single access, 7 days) waits for the user's
  validation.
- **From an attachment** (same action, "Attachments" section): the
  attachment is downloaded, decrypted (attachment key, MAC checked) then
  encrypted again by the Send's key, entirely in Rust: its plaintext content
  does not cross the boundary to Swift, and the memory is cleared on drop. A
  protected item asks for its confirmation to prefill the Send; Rust checks
  it again at creation (refused if it expired in the meantime).
- **Limits**: a Send's text lives in a Swift `String` while the screen is
  open; the content of a file chosen in the Finder goes through a Swift
  `Data` that is not zeroed. Verrou does not download received Sends
  (receiving, in the Rust core, is only used by tests).

## Passkeys in Brave and Firefox

```
page ──postMessage──▶ passkeys.js ──▶ background ──encrypted bridge──▶ Verrou (signs)
```

- **Interception**: `passkey-page.js`, injected into the page (MAIN world)
  before its scripts, routes `navigator.credentials.create` and `.get`
  (with `publicKey`) through Verrou. It holds nothing: it relays options
  the page could give the browser itself, and returns the response.
  Main frame only.
- **Autofill** (`mediation: "conditional"`): the request stays pending in
  `passkeys.js`, and the pill of `content.js` (same isolated world of the
  extension: the page reaches neither) offers first Verrou's passkey for
  this site ("Sign in with a passkey"), the others in its tab. Only a real
  click or a real key press (`isTrusted`) picks them; the signature follows
  the same path as an explicit request (Touch ID if requested, protected
  item, counter). The page aborts (`AbortSignal`) or starts another request:
  the passkey leaves the pill. With no Verrou passkey for this site, or
  Verrou unreachable or not linked, the request goes straight to the
  browser.
- **User's choice**: Verrou's window (closed shadow DOM, real clicks only)
  offers the site's passkeys, or to save one (in a login of the site, or a
  new one). "Use the browser" hands over to the original implementation,
  with the same options; with no passkey for this site, it is the browser
  from the start. When Verrou can't take an explicit request (unreachable,
  extension not linked or reloaded since, unsupported key type), it goes to
  the browser and a discreet notice says so: never a silent fallback.
- **Origin and site**: the address comes from the browser (`sender.url`,
  main frame), never from the page. The Rust core
  (`verrou-core/src/passkey.rs`) derives from it the origin written in
  `clientDataJSON` and checks the `rpId`: the page's host or one of its
  parent domains, never a public suffix (Public Suffix List), never an IP
  address. A passkey only signs for its `rpId`. HTTPS only (HTTP to
  `localhost`), vault unlocked.
- **Private key**: created in Rust (P-256, `OsRng`), kept encrypted in the
  login in Bitwarden's format (`login.fido2Credentials`, PKCS#8 in
  base64url, each field encrypted by the SDK): the Bitwarden apps and the
  web vault read it back, and Verrou uses the ones they created. It crosses
  neither the Swift boundary (the app only sees site, user and date), nor
  the bridge: the extension only receives the public key, the attestation
  and the signatures. ES256 signature (RustCrypto's `p256`) of
  `authenticatorData ‖ SHA-256(clientDataJSON)`.
- **Attestation**: `none`, or self-signed `packed` if the site asks for
  `direct`/`enterprise`; zero AAGUID (Verrou impersonates no model).
  "Backup eligible" and "backed up" flags: the passkey is synced by the
  vault.
- **User verification**: if the site asks for it (`required` or
  `preferred`, the default), Verrou asks for Touch ID (or the session
  password) before signing or creating, and only then sets the UV flag; the
  approval lasts 5 minutes for this extension and this item. Otherwise, the
  click in Verrou's window counts as presence. A protected item ("master
  password re-prompt") waits for its confirmation, as when filling.
- **Counter**: incremented on each signature and saved on the server
  before the response leaves; offline, the passkey doesn't sign. Only
  exception: an item shared read-only, whose counter stays the server's.
- **One passkey per login**, like Bitwarden: saving one in a login that
  already has one replaces it (the window says so). A passkey the site
  excludes (`excludeCredentials`) and that the vault already contains is not
  created again (`InvalidStateError`).
- **PRF extension** (`extensions.prf`): evaluated by Verrou after Touch ID
  (a request with `prf` requires user verification), outputs returned by
  `getClientExtensionResults()`; see "Passkey PRF extension".
- **Known limits**: ES256 keys only (a site that doesn't accept ES256 goes
  through the browser); no other WebAuthn extension (`largeBlob`); no
  passkey in frames; during a Touch ID request, the extension's other
  requests wait.

## Site matching

- **Per-site rule**: Bitwarden's (`match` of each URI: base domain, host,
  starts with, exact, regular expression, never), saved encrypted in the
  item and honored by every fill path (browser extension, ⌘\ and quick
  access on the Mac, iPhone autofill), which all go through the same
  function of the Rust core. An app address (`macapp://`…) never matches a
  page, whatever its rule.
- **Regular expressions**: evaluated by Rust's `regex` engine, in linear
  time and with a bounded size: a booby-trapped expression can't block
  filling. An invalid expression matches nothing.
- **Default rule and per-folder rule**: device settings (`match-rules.json`
  in the account folder, in plaintext: rules and folder identifiers, no
  name or secret), never sent to the server. Bitwarden has no per-folder
  rule; it only applies on this device and only to sites without a rule of
  their own.
- **Equivalent domains**: read from the server (`/api/settings/domains`, in
  plaintext on the server as in Bitwarden), at sign-in and on each sync;
  they only widen the "base domain" rule. A malicious server could declare
  a domain equivalent to another: that is already the case with the
  Bitwarden apps, and filling remains the user's choice.

## Last used (sorting)

- Bitwarden has no "last used" field for an item (only the date of an old
  password and a passkey's counter): Verrou keeps its own record, **on the
  device only**, never sent to the server nor synced between devices.
- It only contains **item identifiers and timestamps** (`usage.json` in the
  account folder, readable by the user only, 5,000 items at most): no
  title, no site, no username, no secret. It is updated when an item is
  filled (extension, ⌘\, iPhone autofill, passkey), copied, or a secret is
  shown. An item's identifier is the server's: someone who reads this file
  and has access to the server can link the two, they then learn when an
  item was used, not what it contains.
- It is erased with the account files on sign-out; the chosen sort and the
  list opened on unlock are app preferences on the device.

## Protected items and audit

- **"Master password re-prompt"** (Bitwarden setting of an item): the Rust
  core refuses its secrets (`reveal`, codes, edit draft, filling in the
  browser) until the user has confirmed, with Touch ID or the master
  password (checked offline against the cache). A confirmation lasts 5
  minutes for this item and is cleared on lock. From the browser, Verrou
  asks for the confirmation and the extension retries: it receives nothing
  before.
- **Audit**: reused passwords, weak ones (estimated entropy under 60
  bits), HTTP sites, computed locally; only summaries leave the Rust core.
- **Known breaches** (on request): Have I Been Pwned's "Pwned Passwords"
  API by k-anonymity. Only the first 5 hexadecimal characters of each
  password's SHA-1 leave, with padding in the responses; the comparison is
  done on the Mac.
- **New passwords** (setting *Check new passwords in known leaks*,
  on by default): after a write made from Verrou (editor, extension,
  import), the Rust core compares the vault before and after, and only the
  logins whose password is new are checked, with the same API and the same
  k-anonymity. Passwords that arrived by sync are not sent. Setting off:
  nothing is sent, the queue (item identifiers, never secrets) is emptied;
  it is also emptied on lock.
- **Two-factor authentication available**: the full list of
  [2fa.directory](https://2fa.directory) (`api.2fa.directory/v3/tfa.json`,
  about 400 KB) is downloaded when the audit opens, at most once a week, and
  kept in the account folder (`2fa-directory.json`); no request depends on
  the vault, the comparison with the logins' sites is done on the Mac.
  Offline, the last copy is used. Only HTTPS help links are offered.
- **Passkey possible**: the full directory of sites that accept passkeys,
  [passkeys.2fa.directory](https://passkeys.2fa.directory)
  (`passkeys-api.2fa.directory/v1/supported.json`, about 75 KB, from the
  same project as 2fa.directory), is downloaded when the audit opens, at
  most once a week, and kept in the account folder
  (`passkeys-directory.json`); no request depends on the vault, the
  comparison with the logins' sites (host, then registrable domain) is done
  on the device. Offline, the last copy is used. Only HTTPS links are
  offered. A login that already has a passkey (its own, or the one of the
  same account stored elsewhere) is not listed. The demo vault uses a
  bundled excerpt, without network.
- **"Create a Passkey"**: like "Change Password", only on click, for this
  item alone. The Rust core reads `/.well-known/passkey-endpoints` (W3C
  "Passkey Endpoints" standard) on the item's host then its registrable
  domain: HTTPS only, no redirect, no cookie or `Referer`, 5 s timeout, body
  limited to 16 KB; only `enroll` or `manage` HTTPS addresses **of the same
  registrable domain** are kept (the file can't send elsewhere). Otherwise a
  page known in advance (Google, GitHub, Microsoft, PayPal), otherwise the
  address given by the directory, otherwise the site's home page. The
  passkey is then created on the site and saved by the extension (Brave,
  Firefox) or the AutoFill extension (iPhone), as usual. Verrou never
  deletes the password.
- **Cards and old passwords**: computed locally (card expiry, items'
  modification date).
- **"Change Password"**: for a handful of big sites (Google, GitHub,
  Amazon, Microsoft, Apple, Facebook, X, LinkedIn, Dropbox), the page is
  known in advance, without a request. For the others, the Rust core checks
  whether the site follows the W3C "A Well-Known URL for Changing
  Passwords" standard: `/.well-known/change-password` must answer "OK"
  (after redirects) and
  `/.well-known/resource-that-should-not-exist-whose-status-code-should-not-be-200`
  must not answer "OK"; on the item's host, then its registrable domain.
  Only on click, for this item alone, never in bulk: the requests only go to
  the site the user is about to open, which therefore learns nothing more.
  HTTPS only (a redirect to HTTP is not followed), no cookie or `Referer`,
  5 s timeout, response bodies not read. Failing that, the site's home page
  opens. No secret is sent: the new password is suggested then saved by the
  extension, as usual.
- **Breaches and changed passwords**: the Rust core keeps in memory the
  SHA-256 hash of the password of each login found in breaches, at the time
  of the check; a password changed since (Verrou, extension, sync) leaves
  the list without a new request. These hashes are never written to disk
  and are cleared on lock.

## Password and passphrase generator

- **Randomness**: the system generator (`OsRng`, that is `getrandom`); a
  deterministic source is only used for demo data and tests.
- **Passwords**: at least one character of each requested class,
  ambiguous characters (`l`, `I`, `O`, `0`, `1`) excluded, from 8 to 128
  characters.
- **Passphrases**: 3 to 20 words (5 by default) drawn from a list bundled
  at compile time, the French list by Tango for Tails and Tor (CC0, 7,775
  distinct words) or the EFF large list (CC BY 3.0 US, 7,776 words), see
  `crates/verrou-core/wordlists/NOTICE`. Each word is drawn uniformly by
  rejection (no modulo bias), a χ² test checks it. Options: separator
  (`-`, space, `.`, `_`, `,` or a random digit), initial capital, a digit
  added to a randomly drawn word.
- **Displayed entropy**: exact for a passphrase, log2(list size) per word,
  plus log2(10) + log2(number of words) for the digit, plus log2(10) per
  digit separator; the capital adds nothing. 5 words give about 64.6 bits,
  6 words 77.5 bits. It assumes the attacker knows the list and the
  settings. The editor's gauge only uses this value while the field holds
  the generated phrase; elsewhere (audit, phrase typed by hand), the
  character-based estimate remains, and overestimates a passphrase.
- **Extension**: the strong password suggestion in pages remains a random
  password (sites often refuse spaces).

## Filling in apps (⌘\)

- **What is typed**: the username, Tab, the password (Return optional, off
  by default), as `CGEvent` keyboard events whose text goes as Unicode
  (`keyboardSetUnicodeString`), with no key code or modifier. The Rust core
  only returns these keystrokes (`autofill_keystrokes`) when the user picks
  a login, and refuses a protected item until it has been confirmed (Touch
  ID or master password); vault locked, it returns nothing.
- **Where**: in the app that was frontmost when the shortcut was pressed,
  remembered by its PID. Verrou brings it back to the front and only types
  after checking that it is; otherwise, nothing is typed. It neither reads
  nor controls other apps' windows (no interface reading through the
  accessibility API): the user places the cursor in the field.
- **Secure input**: if an app other than the target has enabled secure
  input (`IsSecureEventInputEnabled`, owner read from
  `CGSessionCopyCurrentDictionary`), Verrou warns in quick access and types
  nothing. The target app's own (a password field) is normal.
- **Permission**: typing for another app requires "Accessibility" access
  (`AXIsProcessTrustedWithOptions`, `CGRequestPostEventAccess` for a
  sandboxed app). Signed ad hoc, Verrou can lose this permission on each
  rebuild (macOS ties it to the signature): it must then be removed from the
  list and allowed again.
- **Association**: an app is linked to a login by a
  `macapp://<bundle identifier>` address added to its sites, encrypted and
  synced like them, with the "never" match rule so that the Bitwarden
  extensions offer it on no page. The core never treats it as a site (no web
  suggestion, no icon, no duplicate).
- **Known limits**: an app that reads key codes rather than characters
  (games, remote desktops) receives wrong keystrokes; a malicious frontmost
  app receives what is typed into it, as with copy-paste. The one-time code
  is copied (concealed clipboard, cleared after 90 s), not typed.

## Terminal and SSH agent

```
verrou (CLI) ─────────TCP 127.0.0.1──▶ Verrou
ssh ──Unix socket──▶ verrou ssh-agent ──TCP 127.0.0.1──▶ Verrou
```

- **Pairing**: the same as the extension (ECDH P-256, 6-digit code to
  compare, AES-256-GCM channel), with `verrou link`. The client declares
  itself "terminal"; Verrou's approval window says so ("Link the terminal
  (verrou)") and says what it will be able to do. A client saved without a
  kind (before this version) is an extension.
- **Commands per client kind** (`access::allowed`, checked by the bridge
  for each request, with tests): the extension only has its commands
  (suggest, fill, save); the terminal only has its own (search, read an
  item, reveal, code, SSH keys, sign). Neither can borrow the other's.
- **What the terminal gets without asking**: search results and items
  **without any secret** (title, username, sites, folder, tags, value of
  non-hidden fields); hidden fields, notes and TOTP seeds are not included
  (a test checks it). Vault locked: nothing, except the unlock request
  (Touch ID in Verrou).
- **What requires approval**: each secret (hidden field, notes, one-time
  code) and each SSH signature. Verrou asks for Touch ID (or the session
  password, `.deviceOwnerAuthentication`): "allow the terminal to read
  "title"", "allow ssh to use the key "title"". The approval lasts **5
  minutes for this client and this item** only; it is forgotten when the
  vault locks and when the client is revoked. No answer within 90 s:
  refused. A protected item ("master password re-prompt") requires the
  app's confirmation (Touch ID or master password), which the Rust core
  checks before handing over anything.
- **Reason** (`--reason`, `VERROU_REASON`): sent with each request, cleaned
  by the bridge (one line, no control characters, 120 characters at most)
  and shown after what is asked, on the Mac and on the iPhone's approval
  screen, as "reason given": the client declares it, nothing checks it. It
  travels sealed like the rest of the request; the iPhone's notification
  stays without content.
- **`verrou run`**: the values of `verrou://` references are asked with
  the same approval as `get`, then only placed in the environment of the
  command it starts; nothing is printed, the CLI keeps them in zeroed
  buffers until the command ends. The command's output goes through a mask
  that replaces each of these values (3 bytes or more) with `<concealed by
  Verrou>`, holding back only an end of write that could start one.
  Limits: the command itself, and the programs it starts, can do anything
  with the values (write them to a file, send them); the mask doesn't see a
  value it transforms (encoded, split by other characters); `--no-masking`
  turns it off. It is meant to keep secrets out of the terminal and of an
  agent's context, not to confine a program the user doesn't trust.
- **SSH keys**: the private key (OpenSSH, as Vaultwarden keeps it) never
  leaves the app. Verrou signs (RustCrypto's `ssh-key` crate) and only
  returns the signature; the agent only sees the public keys. Keys
  protected by a passphrase are ignored.
- **New SSH keys**: generated in the Rust core (Ed25519, or RSA 4096;
  system generator, `getrandom`), stored as a Bitwarden "SSH key" item
  (OpenSSH private key without passphrase, protected by the vault's
  encryption like the rest). The private key never goes through Swift: the
  app only receives the identifier of the created item.
- **Git signatures**: `ssh-keygen -Y sign` (which git calls with
  `gpg.format=ssh`) has the agent sign an "SSHSIG" blob that carries its
  namespace. When it is `git`, Verrou says so ("sign a git commit with the
  key "title"") and the approval is **separate** from that of `ssh`:
  accepting a connection doesn't allow signing commits for 5 minutes, nor
  the reverse. The signed content stays chosen by the program that asks:
  the approval doesn't show the commit. An SSH authentication can't pass as
  a git signature (it starts with the length of the session identifier,
  never with "SSHSIG"). `verrou git-signing` only writes git's
  configuration with `--apply`, and only puts the public key in it.
- **What is on disk**: `~/.config/verrou/cli.json` (mode 600, folder 700)
  keeps the client's identifier and the channel key. A program that reads it
  can impersonate the terminal: search without secrets, and ask for secrets
  — which the user still has to accept with Touch ID. Settings → *Unlink*,
  or `verrou unlink`, revokes the link.
- **Agent socket**: `~/.verrou/agent.sock`, folder 700, socket 600. As
  with `ssh-agent`, **any program started by the user** can ask it for the
  public keys and for signatures; each signature with a key still goes
  through Touch ID, then the approval lasts 5 minutes for this key (during
  that time, such a program can sign without a new request). The agent can
  neither add, remove nor export a key; other messages receive
  `SSH_AGENT_FAILURE`.
- **Known limits**: approval is given per item, without showing which
  command asks for it; a program running under the user's account can read
  what the CLI displays.

## Approving from the iPhone

Away from the Mac, the terminal's requests (a secret, an SSH or git
signature, the unlock) can be approved with Face ID on the iPhone. Off by
default: nothing happens until an iPhone is paired. Code:
`apple/Shared/Remote/RemoteApproval.swift` (protocol, tested in
`RemoteApprovalTests`), `RemoteCloud.swift` (transport),
`Verrou/App/RemoteApprovals.swift` (Mac), `VerrouiOS/App/RemoteApprover.swift`
(iPhone).

- **Transport**: the private database of the user's iCloud account
  (CloudKit, container `iCloud.app.verrou`, production environment); no
  server of Verrou's. iCloud only ever sees sealed content, the Mac's
  identifier and expiry dates; the notification text is the app's ("Request
  from your Mac") and says nothing of the request. Records are erased once
  answered, withdrawn or expired.
- **Pairing**: Touch ID (or the session password) on the Mac, which then
  shows a QR code: its random identifier, the public key it signs requests
  with (P-256, in the Mac's Secure Enclave, without biometrics) and a
  32-byte one-time secret. The iPhone answers in iCloud with its public key
  — a P-256 key agreement key **in its Secure Enclave, usable only after
  Face ID** (`.biometryCurrentSet`) — authenticated by an HMAC-SHA256 of the
  secret. A key slipped in by someone who didn't see the QR code is
  refused. The Mac keeps the paired iPhones' public keys in
  `remote-approval.json` (account folder); Settings › Security removes them.
- **Request**: for each request and each iPhone, the Mac draws an
  ephemeral key; ECDH with the iPhone's key, HKDF-SHA256 (the request's
  identifier as salt) gives one AES-256-GCM key per direction. The content
  (who asks, what, which item, expiry) is sealed, and the Mac signs the
  whole (ECDSA). The iPhone checks the signature and the expiry before
  showing anything, then Face ID opens the content.
- **Answer**: sealed with the other key of the same exchange, the request's
  identifier as associated data. Only the iPhone's Secure Enclave, after
  Face ID, can write it; it only answers that request (the Mac forgets the
  ephemeral key as soon as it has an answer). A refusal is sealed too.
- **Who answers**: at the Mac (screen unlocked, input in the last minute),
  Touch ID as before, and the iPhone after 15 s without an answer; away
  (screen locked or idle), the iPhone right away. The first answer decides,
  the other request is withdrawn. A protected item approved on the iPhone
  counts as confirmed for 5 minutes, as with Touch ID. Approvals last 5
  minutes per client and item, as before.
- **Unlock**: the Mac never sends the vault key. At each unlock **on the
  Mac** (password, Touch ID, security key), it draws a key K, seals the
  vault key with K (AES-GCM) and K for each iPhone (ECDH with an ephemeral
  key), then forgets K: both boxes stay **in memory only**, for 12 hours.
  When the terminal finds the vault locked while the user is away, the
  request carries K's box: the iPhone opens it after Face ID and returns K
  in its sealed answer. The iPhone never sees the vault key; K is useless
  without the box in the Mac's memory, and is replaced after each use. The
  vault opens for the bridge only (the window stays locked) and locks again
  5 minutes after the last approval from the iPhone. Quitting Verrou,
  restarting the Mac, logging out, removing an iPhone or turning the
  setting off erases the boxes: the password or Touch ID is needed again.
- **Speed**: about 0.8 s from the request to the iPhone's notification,
  2 s for the round trip without the user (measured over 60 requests,
  iPhone locked and unlocked). While a request waits, the Mac fetches the
  answer by its identifier every 250 ms (then every second after 20 s), and
  right away on iCloud's silent notification.
- **Known limits**: the iPhone shows what the Mac says is asked, as Touch
  ID does on the Mac; an attacker with the iCloud account can withhold or
  erase requests (the Mac then refuses after 90 s) but can neither read nor
  answer them. A program able to write the account folder of the Mac's
  sandbox could add an iPhone key, as it could already add a terminal to
  `bridge-clients.json`; macOS protects that container from other apps.
  Needs the signed Mac app (iCloud entitlement): a locally signed build
  hides the setting.

## Touch ID

The user key is sealed by a P-256 key agreement key **created in the
Secure Enclave**, usable only after Touch ID (`.biometryCurrentSet`):
adding or removing a fingerprint makes it unusable, and the password must
be entered again. Sealing (ECDH with an ephemeral key, HKDF-SHA256,
AES-GCM) requires no authentication; opening does. The `touchid.json` file
only contains an encrypted reference to the Secure Enclave key, unusable
on another Mac. No keychain, so no entitlement to request: the app can be
signed locally.

The user key only crosses the Rust/Swift boundary for enrollment
(`user_key`) and unlocking; since a Swift `String` can't be zeroed, it is
kept in no property.

The Bitwarden SDK accepts any well-formed key (the vault then decrypts to
zero items): Verrou checks the returned key by decrypting the refresh
token with it, and refuses it otherwise.

## iPhone

The iPhone app (`apple/VerrouiOS`) reuses the Rust core and the rules
above; what changes:

- **Account folder** (`VerrouStorage`): the container of the
  `group.app.verrou` app group, shared by the AutoFill extension (see
  below). Without this group (unsigned simulator build), the app's private
  folder; an account found there is moved into the group as soon as it
  exists. The folder is excluded from iCloud and Finder backups. Its
  content is the Mac's: cache encrypted by the server, encrypted offline
  queue, `touchid.json`. No security key (`hmac-secret`) on the iPhone: no
  NFC in this version.
- **Face ID**: the same sealing as Touch ID (P-256 key agreement key in the
  Secure Enclave, `.biometryCurrentSet`, ECDH + HKDF-SHA256 + AES-GCM).
  Adding or removing a face requires entering the password again.
  **Simulator only**: its Secure Enclave refuses keys guarded by
  biometrics; a software key, stored in `touchid.json` itself, replaces it,
  and only the LocalAuthentication check (simulated Face ID) guards opening.
  This path is only compiled for the simulator (`targetEnvironment(simulator)`).
- **Protected items**: Face ID, otherwise the master password (checked by
  the Rust core), valid 5 minutes per item, as on the Mac.
- **Clipboard** (`UIPasteboard`): `localOnly` (never sent to other devices
  by Universal Clipboard) and `expirationDate` (iOS itself clears the
  secret after 90 s by default, adjustable from 30 s to 10 min, even if
  Verrou was closed). On lock, Verrou clears it if it still contains what it
  put there (`changeCount` counter, without reading the content).
  Non-secret values (username, site) don't expire.
- **Auto-lock**: when the app goes to the background, after an adjustable
  delay (immediately, 1 min by default, 5 min, 15 min, 1 h, never); the
  system can also terminate the app, which frees the vault. Out of the
  foreground, the screen is blurred and covered: the app switcher's preview
  shows no item.
- **Attachments**: decrypted in Rust, written for the time of the preview
  or the share into a temporary file protected by the iPhone's encryption
  (`completeFileProtection`), erased on close, on lock and at the next
  launch. A file shared to another app leaves Verrou's control, in
  plaintext.
- **Network**: the Rust core talks to the server with its own stack
  (rustls), without going through App Transport Security; HTTPS required as
  on the Mac (HTTP only for `localhost`, the tests). Site icons come from
  the account's server (ephemeral `URLSession`, nothing on disk).
- **Distribution**: no Apple developer account, so no build for a real
  iPhone in this version; the simulator is built signed ad hoc ("-", never
  a developer team). The simulator then reads the entitlements embedded in
  the binary (`__TEXT,__entitlements` section): the `group.app.verrou` app
  group and the AutoFill provider entitlement work there. A
  `CODE_SIGNING_ALLOWED=NO` build has no entitlement: the app falls back to
  its private folder, and the extension doesn't see the vault. The
  `app.verrou.shared` keychain group is not used.

### Scanning a QR code (one-time codes)

In the edit screen ("Scan a QR code") and from the detail of a login
without a code ("Add a code (QR)"), the app reads a site's two-factor QR
code: `otpauth://totp`, Base32 seed, or Google Authenticator export
(`otpauth-migration://`, protobuf, several accounts). Reading and
validating the seed (Base32, algorithm, digits, period) are in the Rust
core (`verrou_core::otp_scan`); HOTP (counter-based) codes are refused,
since Bitwarden only stores TOTP.

- **Camera**: VisionKit (`DataScannerViewController`, QR codes only),
  otherwise AVFoundation (`AVCaptureMetadataOutput`). Both only return the
  QR code's text: no image is saved, neither on disk nor in memory beyond
  the current frame. Permission is only asked on first use, and only if the
  device has a camera; a refusal is explained, with a link to Settings.
- **Photo or screenshot**: `PhotosPicker` runs outside the app; Verrou only
  receives the chosen image, without access to the photo library (no
  permission asked). The image only exists in memory, while Vision
  (`VNDetectBarcodesRequest`) reads the QR code in it, then it is released.
  Verrou doesn't delete it from Photos: the screenshot of the QR code stays
  in the photo library, to be deleted by the user (it contains the seed).
- **Clipboard**: read only when `PasteButton` is tapped (no paste alert,
  nothing is read when the sheet opens; knowing whether it contains text or
  an image doesn't read it).
- **Seed**: the core rewrites it as a canonical `otpauth://totp` link, which
  goes directly into the item's draft and is then encrypted on save like the
  other fields. It is never logged nor copied to the clipboard; the preview
  only shows the service, the account and the current code. The link
  crosses the Rust → Swift boundary (exception documented in `verrou-ffi`,
  like `edit_draft`), for the time of the preview; closing the sheet or
  locking the vault forgets it.
- **Existing login**: a scanned account can join a login without a code
  for the same service (title, or registrable domain of a site); a
  protected item first asks for Face ID or the master password, and a
  read-only item is never offered.

## AutoFill on iPhone

The `VerrouAutoFill` extension (`apple/VerrouAutoFill`, an
AuthenticationServices credential provider) fills logins, one-time codes
(iOS 18) and passkeys in Safari and apps.

- **What the system receives**: the app publishes to the identity store
  (`ASCredentialIdentityStore`), after each unlock, sync or write, the
  domains and usernames of its logins, the same for one-time codes, and for
  passkeys the site (`rpId`), the username, the credential identifier and
  the user's identifier at the site. **Never a password, a TOTP seed or a
  private key.** This data is used for the keyboard suggestions; the system
  keeps it outside the vault, in plaintext for itself. The store is emptied
  on sign-out; locking keeps it (no secret). Protected items are included
  (username only).
- **One request, one unlock**: each request arrives in a fresh process
  where the vault is locked. "Without interaction" requests hand back to the
  system (`userInteractionRequired`); the extension shows up, Face ID starts
  on its own (or the master password), then it answers and closes the vault
  again (the Rust core erases its secrets). A secret only goes out to the
  system, for the chosen item.
- **Protected items** ("master password re-prompt"): one more confirmation
  (Face ID or master password), even right after unlocking, as in the app.
  An organization's "Hide passwords" doesn't prevent filling (as on the
  Mac).
- **Face ID in the extension**: it first opens the app's sealing
  (`touchid.json`, shared folder). In the simulator (software key), this is
  verified end to end. On a device, a Secure Enclave key created by the app
  should open from the extension (the key is bound to the device, not to the
  process), **which could not be verified without a signed device**; if it
  doesn't open, the extension asks for the master password then seals the
  user key with **its own** Secure Enclave key (`touchid-autofill.json`,
  same ECDH + HKDF + AES-GCM scheme, `.biometryCurrentSet`). The app erases
  both sealings (Face ID turned off, sign-out, sign-in again).
- **Passkeys**: the system builds `clientDataJSON` and checks that the page
  or the app is allowed to ask for this `rpId` (page's domain in Safari,
  associated domains for an app); the extension receives the `rpId` and the
  SHA-256 hash of `clientDataJSON`. The Rust core
  (`passkey::register_for_system`, `assert_for_system`) checks the form of
  the `rpId` (domain name or `localhost`, neither IP address nor public
  suffix), requires a 32-byte hash, builds `authenticatorData` (hash of the
  `rpId`, UP flag, UV if Face ID or the password was asked for this request,
  BE/BS, counter) and signs `authenticatorData ‖ clientDataHash` with
  ES256; the private key never crosses the Swift boundary. Attestation
  `none`, zero AAGUID. ES256 only: a site that doesn't accept it is refused
  with a message. Passkeys excluded by the site (`excludedCredentials`,
  iOS 18) are not created again. A creation or a sign-in only succeeds once
  written to the server (passkey, or new counter); offline, the extension
  refuses.

### Conditional passkey creation (iOS 18)

After a password filled by Verrou, Safari can ask in the background for a
passkey for the same account (`mediation: "conditional"`,
`performWithoutUserInteractionIfPossible(passkeyRegistration:)`, declared
with `SupportsConditionalPasskeyRegistration`). This request has no
interface: the vault is closed and Face ID impossible. Chosen approach
(`crates/verrou-ffi/src/conditional.rs`):

- **During filling** (vault open, Face ID or master password passed), if
  the login has no passkey, has a site and a username, the Rust core
  prepares a P-256 key. The ticket (`passkey-upgrade.json`, account folder,
  0600) keeps the public key, the credential identifier, the registrable
  domains and the item's username (like the identity store), and the
  private key **sealed** with the account's local key (`EncString`, the one
  of the offline queue): unreadable with the vault closed.
- **The background request** consumes the ticket (only once, whether it
  succeeds or not) and only succeeds if: the ticket is less than 5 minutes
  old, the `rpId` has the same registrable domain as a site of the item, and
  the requested username is the item's. Attestation `none`, zero AAGUID,
  counter 0, **without the UP or UV flags** (no interface was shown),
  BE/BS. Otherwise silent refusal: the site keeps the password.
- **The passkey waits** in `passkeys-pending.json` (key still sealed) until
  the app's next sync, vault open: the Rust core unseals the key and writes
  the passkey into the login, on the server (a new login if the item has
  disappeared). Until then, sign-in still uses the password. The password
  is never removed.
- **Limits**: if the app is never reopened, the passkey stays at the site
  without being usable by Verrou; a key sealed by another account (sign-out
  in the meantime) is dropped.

### Site signals (iOS 26)

A site can inform the provider through `ASCredentialUpdater` (declared with
`SupportsCredentialUpdate`); the system calls the extension in the
background, without interface, vault closed:
`reportUnknownPublicKeyCredential(forRelyingParty:credentialID:)`,
`reportAllAcceptedPublicKeyCredentials(forRelyingParty:userHandle:acceptedCredentialIDs:)`,
`reportPublicKeyCredentialUpdate(forRelyingParty:userHandle:newName:)` and
`reportUnusedPasswordCredential(forDomain:userName:)`.

- The extension records the signal (`credential-signals.json`, account
  folder, 0600): site, credential and user identifiers, username, **never a
  secret**. Bounded texts, 200 signals at most, forgotten after 180 days or
  as soon as they no longer match the vault.
- The system's suggestions hide, at the next publication, the passkeys the
  site no longer recognizes and the passwords it says are unused, and take
  the new username.
- **Nothing is deleted from the vault** automatically: a signal can come
  from a site's mistake, and the Bitwarden apps share the vault.

### Writes from the extension

The extension and the app share the account folder (app group). Two
processes that would each rewrite the offline changes queue
(`outbox.json`) would lose or duplicate changes: the app keeps it in memory
and rewrites it whole. Chosen approach:

- **The extension opens the folder as a guest** (`Store::guest`,
  `VaultSession::for_autofill`): it reads the app's cache and queue (to also
  fill what was changed offline), but never sends the queue and never writes
  it (writes of `outbox.json` have no effect as a guest, sending is cut off
  at the source).
- **Its writes go directly to the server**, without a queue: created
  passkey (in a new login or an existing one), a passkey's counter. Then it
  syncs again and saves the cache (`account.json`), so that the next request
  starts from the right counter. Without a server, it refuses instead of
  queueing.
- **Atomic and locked file writes**: a temporary file specific to the
  process and to the write, renamed under a `flock` lock on the folder
  (`.verrou.lock`). The lock is only held for the rename, never during
  network: iOS terminates a suspended app that holds a file lock in a shared
  container (`0xdead10cc`). A reader sees the old file or the new one, never
  a mix.
- **Refresh token**: if the server refuses the token in memory (the other
  process received a new one), Verrou reads the one on disk again and
  retries once.
- **Known consequences**: the app only sees a passkey created by the
  extension at its next sync (when it returns to the foreground); if the app
  had an offline change of the **same** login, the extension's write goes
  with it, and the app's upload becomes a "(offline conflict)" copy: nothing
  is lost. If the app rewrites the cache with an older version between two
  requests, it replaces it with the server's at its next sync.
- **After a creation**, the extension updates the identity store itself
  (otherwise the system wouldn't offer the new passkey before the app
  syncs).
- **Memory**: the extension stays far from the limit of about 120 MB (peak
  measured at 56 MB in the simulator, test vault): decryption, search and
  site matching stay in the Rust core.

## AutoFill on Mac

The `VerrouAutoFillMac` extension (`app.verrou.mac.autofill`) is the
system's credential provider on the Mac (System Settings → General →
AutoFill & Passwords): logins, one-time codes and passkeys in Safari and
apps. It reuses the iPhone's model and controller
(`apple/VerrouAutoFill`); everything said above about the identity store,
"one request, one unlock", protected items, passkeys and guest writes
applies here, with Touch ID instead of Face ID.

- **Signing**: macOS kills an ad hoc signed process that carries the
  `com.apple.developer.authentication-services.autofill-credential-provider`
  entitlement (restricted entitlement, authorized by a provisioning
  profile), and only validates an app group for an app signed by the team
  that prefixes it (`<team>.app.verrou`); without validation, macOS 15 asks
  on each access for permission to read "data from other apps". The
  extension is therefore only shipped in a team-signed build
  (`VERROU_MAC_TEAM`); the ad hoc build, the default, removes it from the
  bundle before signing and keeps the vault in the app's container, as
  before.
- **Shared vault**: in a signed build, the account folder is in the app
  group's container (`~/Library/Group Containers/<team>.app.verrou`),
  protected by the sandbox: only the app and its extension, signed by the
  team, access it. Nothing there is in plaintext (cache encrypted by the
  server, queue encrypted with the user key, Touch ID sealing bound to this
  Mac's Secure Enclave).
- **Migration**: on the first launch of a signed build, the app **copies**
  its folder from the app's container to the group (temporary folder, then
  file-by-file check, size and SHA-256, then atomic rename), writes a
  `migration.json` note, and renames the old folder to
  `Verrou-before-group-<date>` without erasing it: the app no longer reads
  it (a stale offline queue wouldn't go out to the server again). A group
  folder that contains something other than an account stops the migration:
  the app then keeps its private folder. Tested on throwaway copies
  (`apple/VerrouMacTests`), never on the real container.
- **Touch ID in the extension**: as on the iPhone, first the app's sealing,
  otherwise the master password then a sealing specific to the extension
  (`touchid-autofill.json`).
- **With the browser extension**: both coexist. In Brave and Firefox,
  `passkey-page.js` takes passkey requests before the browser; the system
  (and therefore `VerrouAutoFillMac`) is only called upon if the user
  chooses "Use the browser" or if Verrou has nothing for this site: never
  two Touch ID requests for the same operation. Safari and apps only have
  the system provider.

## Passkey PRF extension

A site can ask a passkey for a pseudo-random value bound to a salt of its
choice (`extensions.prf`, WebAuthn level 3); it uses it as an encryption
key. Verrou evaluates it in the provider of the iPhone (iOS 18), of the Mac
(macOS 15) and in the browser extension.

- **Computation** (`verrou-core/src/passkey_prf.rs`), like the CTAP2
  `hmac-secret` extension and `passkey-rs` (Bitwarden SDK):
  `salt = SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input)`, then
  `output = HMAC-SHA256(secret, salt)`. The system passes the raw inputs to
  the provider; Verrou hashes them, like Chrome's provider on iPhone.
- **The secret**: Bitwarden's passkey format has no field for an
  `hmac-secret` secret, and the Bitwarden SDK doesn't evaluate the PRF for
  vault passkeys (PM-30510). Verrou doesn't invent a field (the official
  apps would erase it when rewriting the item): it **derives** the secret
  from the private key, `HKDF-SHA256(P-256 scalar, salt
  "verrou.passkey.prf.v1", info = credential identifier)`. The output is
  therefore stable on all devices where Verrou runs, for any passkey in the
  vault (including those created by Bitwarden). Whoever holds the private
  key can recompute it, as with a secret stored alongside. If Bitwarden ever
  adds a field, its outputs will differ from Verrou's: data a site had
  encrypted with Verrou's PRF wouldn't open with the official apps (which
  today have no PRF at all). Test vectors fixed in the code.
- **User verification**: the PRF is only returned after Face ID, Touch ID
  or the master password (in the browser, a request with `prf` requires
  Touch ID); without verification, no output. The outputs are keys: they
  are neither kept nor written, go from Rust to the system (or to the page),
  and the PRF doesn't touch the counter.
- **`evalByCredential`** takes precedence over `eval` for the chosen
  passkey; at creation, Verrou announces support (`enabled`) and already
  gives the outputs if the site provided inputs.

## Security key (YubiKey, `hmac-secret`)

A YubiKey (or any FIDO2 key with the `hmac-secret` extension and a PIN)
can unlock the vault, in addition to Touch ID and the password.

- **Principle**: at enrollment (vault open, Settings), Verrou creates on
  the key a non-resident credential for the identifier `verrou:` — not a
  domain name, like OpenSSH's `ssh:`: no web page can have a browser use
  it. It draws a 32-byte salt; the key returns, after PIN and touch,
  `HMAC-SHA-256` of a secret it never hands over (the salt first goes
  through the transformation of the WebAuthn PRF extension). HKDF-SHA256
  (salt `verrou.security-key.v1`, info = credential identifier) derives
  from it an AES-256-GCM key that seals the user key; associated data:
  version, credential identifier and salt. All of this is done in Rust
  (`unlock_keys.rs`, RustCrypto primitives): the user key doesn't go
  through Swift.
- **What is on disk** (`security-keys.json`, app container, mode 600,
  atomic write), per key: credential identifier, salt, sealed user key
  (random nonce), name and date. Nothing useful without the physical key.
- **PIN required** (user verification `required`): it takes the key
  **and** its PIN; the key locks after 8 wrong PINs. A key without a PIN is
  refused, with the message that says to set one. It is also a constraint
  of `authenticator-rs` 0.5: without user verification, it doesn't
  establish the shared secret and doesn't send the `hmac-secret` extension.
  The PIN crosses the Swift/Rust boundary once, goes to the key encrypted by
  CTAP2's PIN protocol, and is only kept (erased afterwards) for the time of
  an enrollment, to avoid typing it twice. Limit: the library copies it into
  a `String` that is not erased.
- **Several keys** (main and backup): each has its credential, its salt and
  its sealed copy. On unlock, all credentials are offered (PRF
  `evalByCredential`): the plugged-in key only answers for its own, with the
  matching salt. The same credentials can't be enrolled twice (exclusion
  list).
- **With the file but without the key**, an attacker only has encrypted
  data: the secret doesn't leave the key, and 32 random bytes can't be
  guessed. **With the key but without the PIN**, 8 attempts at most before
  locking. **With the key, the PIN and the file**, they open the vault, as
  with the master password: removing the key in Settings (or signing out)
  makes its sealed copy useless.
- **Invalidation**, like Touch ID: signing in again or signing out erases
  `security-keys.json`; an unsealed key that the vault refuses (vault key
  changed) erases all enrolled keys. Removing a key doesn't erase its
  credential on the YubiKey (worthless without the file; a YubiKey doesn't
  list non-resident credentials).

## Distribution

`scripts/install-macos.sh` builds a Release version **signed ad hoc** (no
developer account), sandboxed (outgoing network and USB), hardened
runtime, without `get-task-allow` (no debugger can attach to it); the
script refuses to install a build that would have it.

## Report a problem

Don't open a public issue: report the vulnerability privately via
[Security › Report a vulnerability](https://github.com/bonout/verrou/security/advisories/new).
