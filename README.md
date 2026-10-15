<p align="center">
  <img src="docs/media/icon.png" width="128" height="128" alt="Verrou icon">
</p>

<h1 align="center">Verrou</h1>

<p align="center"><b>Your Vaultwarden vault, native on your Mac.</b></p>

<p align="center">
  A fast macOS password manager for a self-hosted
  <a href="https://github.com/dani-garcia/vaultwarden">Vaultwarden</a> server,
  with a Brave and Firefox extension, a command line and an SSH agent, all built around a
  Rust core and Bitwarden's official crypto.
</p>

<p align="center">
  <a href="#install"><b>Install on your Mac</b></a> ·
  <a href="docs/GUIDE.md">Full guide</a> ·
  <a href="SECURITY.md">Security</a>
</p>

<p align="center">
  <a href="docs/media/demo.mp4">
    <img src="docs/media/demo.gif" width="860" alt="Verrou demo: unlocking, searching the vault, revealing a password and its one-time code, a card, a Wi-Fi network, a shared family vault, the security audit and Quick Access">
  </a>
</p>

Verrou works with the vault you already have on your Vaultwarden server, so
the official Bitwarden apps and web vault keep working next to it. It opens
in a fraction of a second, searches thousands of items as you type, and fills
your logins in Brave, Firefox and any other Mac app. The interface is in French.

## What you can do

- **Unlock** with Touch ID, a YubiKey (FIDO2 PIN and a touch) or your master
  password. It locks itself after inactivity, on sleep and with the screen.
- **Find anything as you type**: fuzzy, accent-insensitive search, under
  5 ms on 10,000 items, with filters like `type:carte` or `dossier:maison`.
- **Quick Access** (⌘⇧Space) from any app: search, then copy a password or a
  one-time code without opening the main window.
- **Fill in any app** (⌘\\): Verrou types the username and password into the
  app in front of you, like 1Password's Universal Autofill.
- **Fill in Brave and Firefox**: logins, one-time codes, cards and addresses,
  from a 1Password-style pill at the top left of the page (*Se connecter*,
  other logins in a tab under it; logins are submitted once filled, unless
  something is left to type or a captcha shows, which can be turned off in
  the popup), with only a small Verrou icon in the field:
  nothing gets in the way of the site's own suggestion lists. It suggests
  strong passwords, offers to save new accounts, and reads two-factor QR codes
  shown on a page (Brave).
- **Passkeys in Brave and Firefox**: create and use passkeys stored in your vault, in the
  Bitwarden format, so they work with the official apps too. Sites with
  passkey autofill get them as the pill's top suggestion, before passwords.
  In Brave, the extension reloads itself when Verrou is updated.
- **Audit your vault**: reused, weak and old passwords, plain-HTTP sites,
  known breaches (Have I Been Pwned), expiring cards, and sites that offer
  two-factor authentication you haven't turned on. *Changer le mot de passe*
  opens the site's change-password page in one click, and the extension then
  suggests a strong password and saves it.
- **Share**: shared vaults with family or a team (Vaultwarden organizations),
  encrypted links that expire for a text or a file (Send), and emergency
  access for trusted contacts.
- **Bring people in**: invite them to a shared vault, choose their role and
  collections, and confirm them after checking their key's fingerprint
  phrase. Invited people create their account from Verrou's sign-in screen,
  even on a server with sign-ups closed, with no admin token.
- **Store more than passwords**: cards, identities, secure notes, SSH keys,
  attachments and documents, Wi-Fi networks (with a QR code to join),
  passports, licenses, bank accounts, servers, API keys, and custom fields on
  any item.
- **Act on many items at once**: select them like in Finder, then archive,
  trash, restore, favorite or move them to a folder in one go.
- **Save without waiting**: edits show at once and are sent to the server
  in the background, so a slow link never holds up the window.
- **Work offline**: edit, create, trash or archive items without network;
  changes are synced, in order, as soon as the server answers.
- **Generate** strong passwords or memorable passphrases (French or English
  words, like `fixe-pivoine-monceaux-couteau-ponctue`), with their real
  strength, in the app and with `verrou generate`.
- **Move in**: import from Apple Passwords, 1Password and Proton Pass, then
  clean up duplicates: the same account under different URLs, titles or
  usernames is found (certain, probable, to check) and merged into one item.
- **Work from the terminal**: `verrou search`, `get` and `totp`, an SSH agent
  that signs with the keys in your vault, and git commit signing. Each secret
  is approved with Touch ID.

## Private

Your vault is decrypted only on your Mac, by Bitwarden's official Rust SDK.
Verrou talks to your own server, with two exceptions:

- **Breach checks** send only the first 5 characters of a password's SHA-1
  hash to Have I Been Pwned. The whole vault is checked when you ask; new
  passwords are checked automatically, which you can turn off in Settings.
- **The audit** downloads the public [2fa.directory](https://2fa.directory)
  list, at most once a week, as a whole file: it never asks about your sites
  one by one.
- **Changer le mot de passe** asks only the site you are about to open
  whether it has a [change-password page](https://w3c.github.io/webappsec-change-password-url/),
  and only when you click.

The browser extension only receives the logins of the site in front of it, over
an end-to-end encrypted channel. Copied secrets are hidden from clipboard
managers and cleared after 90 seconds. Details and known limits are in
[SECURITY.md](SECURITY.md).

## Install

There is no download yet: you build Verrou on your own Mac, signed locally,
with no Apple developer account.

1. Install [Rust](https://rustup.rs), Xcode 26 and xcodegen
   (`brew install xcodegen`).
2. Clone this repository and run `scripts/install-macos.sh`. It builds the
   app and copies it to `/Applications`.
3. Open Verrou and enter your server address, e-mail and master password,
   then your second factor.

Optional:

- **Brave extension**: Settings → *Navigateurs et terminal*, then follow the
  steps shown there ([guide](docs/GUIDE.md#brave-extension)).
- **Firefox extension** (Firefox 128+): same settings, *Extension Firefox*.
  Unsigned, it loads as a temporary add-on (gone when Firefox quits); for a
  permanent install, use Developer Edition/Nightly or have it signed by
  Mozilla ([guide](docs/GUIDE.md#firefox-extension)).
- **Command line and SSH agent**: `cargo install --path crates/verrou-cli`,
  then `verrou link` ([guide](docs/GUIDE.md#command-line-and-ssh-agent)).
- **Fill in any app**: allow Verrou in System Settings → Privacy & Security →
  Accessibility ([guide](docs/GUIDE.md#fill-in-any-app)).

## Using it

| Keys | Action |
| --- | --- |
| ⌘⇧Space | Quick Access, from any app |
| ⌘\\ | Fill the app in front of you |
| ⌘F | Search |
| ↑ ↓ | Move through the results |
| ⌘-click / ⇧-click | Add an item to the selection / select a range |
| ⇧↑ ⇧↓ / ⌘A | Extend the selection / select all results |
| ⇧⌘C | Copy the selected password |
| ⌘N / ⌘E | New item / edit the selected one |
| ⌘R | Sync now |
| ⌃⌘L | Lock |
| ⇧⌘I | Import from another password manager |
| ⌘, | Settings |

## How it works

```
 Verrou.app (SwiftUI)       Brave / Firefox       verrou CLI, SSH agent
        │                          │                        │
        │ UniFFI                   └── encrypted local bridge ┘
        ▼                                       │
 Rust core ◄────────────────────────────────────┘
   search, audit, passkeys, import
   Bitwarden SDK: decryption, sync
        │
        ▼ HTTPS
 your Vaultwarden server
```

The app only receives item summaries (titles, usernames, sites). A password
crosses into Swift only when you reveal or copy it, and locking zeroes the
decrypted vault. The server's encrypted response is cached, so the vault also
opens offline. Every edit goes through an encrypted queue: it is applied to
the displayed vault at once, then sent in the background, or when the
server is back (an item changed elsewhere meanwhile is kept as a copy, never
overwritten).

## Build from source

```sh
cargo test --workspace          # Rust core, bridge, CLI
scripts/build-apple.sh          # Rust library + Swift bindings
(cd apple && xcodegen generate && open Verrou.xcodeproj)
```

Run the app with `VERROU_MOCK=1` to try it on a made-up vault. Tests against a
throwaway Vaultwarden, the end-to-end walkthrough and the demo recording
(`scripts/demo-capture.sh`) are described in the
[full guide](docs/GUIDE.md#build).

## iPhone

The iPhone app (`apple/VerrouiOS`, iOS 17 or later, French interface) shares
the Rust core and a Swift layer with the Mac app: sign in to Vaultwarden
(TOTP or e-mail second factor), unlock with Face ID or the master password,
search as you type, tap to copy (local-only clipboard that iOS clears after
90 s), reveal with the same protected-item rules, one-time codes, cards,
identities, Wi-Fi QR codes, attachments (Quick Look, share), passkeys listed,
create and edit logins, notes, cards, identities and templates, a password
and passphrase generator, swipe actions and multi-select, offline edits, an
audit, auto-lock in the background and a privacy screen in the app switcher.

For now it runs in the Simulator only, unsigned:

```sh
PLATFORMS=all scripts/build-apple.sh     # Rust core for macOS, iPhone and the Simulator
(cd apple && xcodegen generate)
xcodebuild -project apple/Verrou.xcodeproj -scheme VerrouiOS \
  -destination 'generic/platform=iOS Simulator' ARCHS=arm64 CODE_SIGNING_ALLOWED=NO build
scripts/ios-e2e.sh                       # headless walkthrough against a throwaway Vaultwarden
```

Details, limits and the AutoFill plan are in the
[guide](docs/GUIDE.md#iphone).

## FAQ

**Why not just use the Bitwarden app?**
Verrou is a native Mac app that opens instantly, searches as you type and
fills any app, while your data stays in the Bitwarden format on your server.
You can use both side by side.

**Does it work with bitwarden.com?**
It's built and tested against Vaultwarden only.

**Is there an iPhone app?**
Yes, in progress: the iPhone app builds and runs in the iOS Simulator (see
[iPhone](#iphone)). Installing it on a real iPhone, and system-wide AutoFill,
need an Apple developer account, which this project doesn't use yet.

**What if I stop using Verrou?**
Nothing changes: everything lives on your Vaultwarden server in the standard
Bitwarden format, including passkeys, attachments and shared vaults.

**Has it been audited?**
No. The cryptography comes from Bitwarden's SDK; [SECURITY.md](SECURITY.md)
lists what Verrou adds on top and its known limits.

## License

GPL-3.0-or-later. Verrou builds on the GPL crates of the Bitwarden SDK
(`bitwarden/sdk-internal`), never on the commercially licensed code of that
repository (`bitwarden_license/`). "Bitwarden" is a trademark of Bitwarden,
Inc.; Verrou is neither affiliated with nor endorsed by it.

The passphrase generator embeds two word lists: [EFF's Long
Wordlist](https://www.eff.org/dice) by the Electronic Frontier Foundation
(CC BY 3.0 US), and the French diceware list by Tango for Tails and the Tor
Project, from [ulif/diceware](https://github.com/ulif/diceware) (CC0 1.0).
Details and license texts are in
[`crates/verrou-core/wordlists`](crates/verrou-core/wordlists/NOTICE).
