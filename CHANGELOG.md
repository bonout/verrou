# Changelog

What changes for you in each release. The release workflow publishes the
section of the tagged version as the GitHub release notes: write it before
tagging (docs/RELEASING.md).

## Unreleased

**Mac**
- ⌘\ in a terminal (Terminal, iTerm2, Ghostty, Warp, kitty, Alacritty,
  WezTerm, Hyper) types the password alone, as `sudo`, `ssh` and `git`
  prompts expect, instead of the username, Tab and the password.

## 0.5.1

**iPhone**
- The Dynamic Island for requests from the Mac is gone: iOS only allows it
  while Verrou is open, where the approval screen already shows. The
  notification and the approval screen are unchanged.

## 0.5.0

**Mac**
- SSH keys: choose how long a Touch ID covers the terminal. On a key's page,
  *Terminal approval* offers *Every time*, *For 5 minutes* (the default) and
  *Until Verrou locks*, so signing commits or pushing all day asks once.
  Locking Verrou, sleep and the screen lock still end it, and protected
  keys keep asking at least every 5 minutes.

**iPhone**
- Folders nest as on the Mac: the home screen shows the top-level folders,
  and a folder lists its subfolders above its items.
- AutoFill list: right after a login was filled with Face ID, the list
  opened on the same site's next page offers "Continue as…" first, without
  Face ID (90 seconds, never for a protected item).
- Widgets. *One-time code* shows a code with its countdown on the Home
  Screen, the Lock Screen and in StandBy, without opening the vault: turn on
  *Show in widgets and on Apple Watch* on the item's page first. Only the
  codes you pick, never a protected item; on a locked Lock Screen the code
  stays hidden until Face ID recognizes you. *Quick actions* opens Verrou on
  the search, the generator or the QR code scanner.
- Shortcuts and Siri: *Search in Verrou*, *Generate a password with
  Verrou*, *Show the code of…* (pinned codes) and *Copy a password*, which
  opens Verrou, unlocks with Face ID and copies; Shortcuts never receives a
  password from your vault.
- Control Center (iOS 18): a *Search in Verrou* control.
- Apple Watch: pinned codes and complications. The one-time codes you
  pinned show on the wrist with their countdown, and a *One-time code*
  complication puts one on the watch face. Only the pinned codes go to the
  Watch, never the vault; the codes stay hidden when the wrist is down.
- A request from your Mac shows in the Dynamic Island and on the Lock
  Screen with the time left. *Approve* and *Deny* bring you back to it:
  Face ID still shows what is asked before you answer.
- The approval request for an SSH key says when the Mac will not ask again
  until Verrou locks.

**Mac and iPhone**
- Increase Contrast (system accessibility setting) draws stronger borders,
  selection, focus rings and secondary text; nothing changes with it off.

## 0.4.0

**Mac**
- Folders nest the Bitwarden way: `Work/Clients` shows inside `Work`, in a
  tree in the sidebar, and selecting `Work` lists its subfolders' items too.
- Drag items, or a whole selection, onto a folder in the sidebar to move
  them there.
- New *Item* menu: ⌃⌘C copies the username, ⇧⌘C the password, ⌥⌘C the
  one-time code, ⌥⇧⌘C the website.
- Hold ⌥ to show the hidden fields of the item.
- VoiceOver reads the icon-only buttons and the informative icons, and
  skips decorative ones (ACCESSIBILITY.md).
- Locks when the screen saver starts too, along with sleep and the screen
  lock (Settings → Security).

**iPhone**
- Safari signs you in by itself: once AutoFill has filled a login, the
  Verrou Safari extension submits the form, both steps of a two-step form
  included. Never a sign-up, an address or a card, nor a form with a field
  left or a captcha. Turn it on in Settings → Apps → Safari → Extensions.
- After one Face ID in AutoFill, the next fills on any site skip it for
  5 minutes while the iPhone stays unlocked: a tapped suggestion fills at
  once, without a sheet. Locking Verrou ends it; protected items and
  passkeys always ask. Settings → AutoFill turns it off.

**Mac and iPhone**
- AutoFill is quicker: on a two-step sign-in (username, then password on
  the next page) the second step fills at once, without Face ID, for 90
  seconds; never for a protected item. On the Mac, Touch ID shows up as soon
  as the sheet opens.
- In German, Spanish and Italian too, as is the browser extension.
- Settings → Diagnostics: crash and hang reports from the system stay on
  the device, never sent; share them with the developers if something went
  wrong, or delete them.

**Command line**
- `verrou run`: when one secret starts another (`pass` and `password123`)
  and the command wrote the longer one in two parts, the end of it could show
  after the masked start. Found by fuzzing, fixed.

**Browser extension**
- Sign-in pages that mark their password field as a new password (to stop
  browsers from filling it) are recognized as sign-in pages: the password
  is filled too.
- The first step of a sign-in with a lone e-mail field (EDF, Vercel, Airbnb's
  "phone or e-mail") now gets the pill when the page or its button says
  "log in" or "next"; newsletter forms still don't.
- Tested on a corpus of 40 real sign-in pages (extension/test/corpus).

## 0.3.1

**Mac**
- Verrou updates itself. It checks once a day (or with *Check for Updates…*
  in the Verrou menu), downloads in the background and installs when you
  quit. Updates are checked against Verrou's signing key before they are
  opened. Settings → General → Updates turns automatic checks or installs
  off.
- The `verrou` command ships in the app and updates with it: Settings →
  Browsers and Terminal → Command line → *Copy Command*, then paste it in
  Terminal.

This is the last version to install by hand: the next ones arrive on their
own.

## 0.3.0

**Terminal and AI agents**
- `verrou run` hands secrets to a command in its environment, from
  `verrou://Item/field` references (also in an `--env-file`), and masks them
  in its output: they never reach the terminal or an AI agent's context.
- `--reason` (or `VERROU_REASON`) says why a secret is needed; the approval
  shows it, on the Mac and on the iPhone.

**Approving from the iPhone**
- One approval unlocks the Mac's vault and reads the item, instead of two.
- Unlocking from the iPhone keeps working after Verrou restarts on the Mac.
- Fewer Face ID prompts: one per request, even right after an unlock.
- A vault locked during an approval now says "locked" instead of "refused".

**iPhone**
- Shared vaults appear on the home screen as their organizations.
- Archiving an item turns its page to dust.

## 0.2.0

- Approve the terminal's requests from your iPhone when you're away from the
  Mac, and unlock the Mac's vault from it, through your own iCloud account,
  sealed end to end.
- iPhone: Verrou opens `otpauth://` links and appears in *Set Up Codes In*.
- iPhone: *Try the Demo Vault* on the sign-in screen.

## 0.1.1

- iPhone: ready for the App Store, with a privacy policy.
- The demo vault follows the app's language (English or French).

## 0.1.0

- First release: the Mac app, the iPhone app, the browser extension for
  Brave, Chrome and Firefox, and the `verrou` command with its SSH agent.
