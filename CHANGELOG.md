# Changelog

What changes for you in each release. The release workflow publishes the
section of the tagged version as the GitHub release notes: write it before
tagging (docs/RELEASING.md).

## Unreleased

**Mac**
- ⌘\ in a terminal (Terminal, iTerm2, Ghostty, Warp, kitty, Alacritty,
  WezTerm, Hyper) types the password alone, as `sudo`, `ssh` and `git`
  prompts expect, instead of the username, Tab and the password.

**Terminal and AI agents**
- `verrou mcp`: an MCP server for coding agents (Claude Code, Codex, Cursor).
  The agent finds items and gets `verrou://` references, never a value; it
  runs commands with secrets injected and masked in their output
  (`verrou_run`) and generates passwords. Each call is approved in Verrou
  on its own, on the Mac and the iPhone, which show the command line and the
  fields it receives apart from the agent's reason. Approve only commands
  you understand: the mask hides exact values only.
- `verrou hook install claude|cursor|codex`: a guard rail that stops an
  agent from reading `.env` files, private keys and cloud credentials, or
  printing a token, and points it to `verrou_run`. It also refuses
  `verrou read` and `verrou inject` that print a secret instead of writing a
  file, and `verrou run`, in an agent's shell.
- When a `verrou` command looks driven by an agent, its approvals are asked
  one by one (never reusing your own terminal's five minutes) and show the
  command line; a command too long to be shown whole is refused. The
  approval shows control characters instead of spaces, and the iPhone
  "unlock and read" approval no longer covers an agent's request or another
  terminal.
- `verrou env mount`: a `.env` file whose secrets are never written to disk.
  The file is a named pipe (FIFO) that Verrou fills, after your approval, each
  time a program reads it, from a map of `verrou://` references
  (`.env.verrou`, which you can commit). The approval shows which program
  opens the file (found by the pipe it holds), the chain of processes that
  started it, and every variable served. A read never uses or creates the
  five-minute approval of `verrou get` and `verrou run`. **Every read is
  asked, every time, by default.** `--remember-reads` lets a read by one
  program started from a terminal application (Terminal, iTerm2, Ghostty,
  WezTerm, Alacritty, kitty, `sshd`; not a code editor's terminal) with a
  terminal of its own get five minutes for that file, program, terminal and
  login shell; a coding agent among the ancestors (also under Node), several
  readers, or one that cannot be placed is always asked. The approval says
  *no terminal* when none is above the reader. Once the values are written,
  the mount looks again at who has the pipe open: a program that was not shown
  to you ends the mount, loudly. The second name of a replaced pipe sits in a folder closed to everyone until the values are written. Works with Node, Next.js, Vite, python-dotenv and
  godotenv; Bun and Deno skip a file that is not regular (use `verrou run
  --env-file`). `verrou env status` and `unmount` list and stop mounts;
  `--background` keeps one running. A file, a link or a folder is never
  replaced, and a `.env` that git tracks or does not ignore is refused.
- The bridge protocol gains an optional `approval_scope` in requests, added to
  the key of the five-minute approval, and an optional `capabilities` list in
  the status (`approval_scope`): a terminal sends a remembered read only to a
  bridge that says so, and asks every read of an older one; older terminals and
  bridges are otherwise unaffected.
- The agent hook now refuses reading any FIFO and `docker run --env-file` of a
  secret file, resolves relative paths against the event's folder, refuses an
  agent's `verrou env mount` and `unmount`, and lets `.env.verrou`, `verrou
  env status` and `stat` on a FIFO through.
- References to a custom field now work by the field's name as shown in the
  app (`verrou://Stripe/secret%20key`), as the guide always said.

## 0.5.1

**iPhone**
- The Dynamic Island for requests from the Mac is gone: iOS only allows it
  while Verrou is open, where the approval screen already shows. The
  notification and the approval screen are unchanged.

**Terminal**
- `verrou read verrou://<item>/<field>` prints one value, or writes it to a
  file (`-o`, mode 600 by default).
- `verrou inject` fills a template's `{{ verrou://<item>/<field> }}`
  references: a configuration file with its secrets, never typed.
- `verrou item create`, `edit`, `delete`, `archive` and `restore` write
  the vault from the terminal, the 1Password CLI way (`username=…
  'API key[password]=…' --generate-password`). Each write asks for your
  approval in Verrou, on the Mac or the paired iPhone, every time, and the
  approval names the fields it changes (never their values). `--folder`
  files the item, and creates the folder if it is missing.

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
