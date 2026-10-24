# Changelog

What changes for you in each release. The release workflow publishes the
section of the tagged version as the GitHub release notes: write it before
tagging (docs/RELEASING.md).

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
