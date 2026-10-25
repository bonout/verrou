# Privacy policy

Verrou is a client for a Vaultwarden (Bitwarden-compatible) server that you
choose and run, or that someone you trust runs for you. Verrou's developers
operate no server, collect no data and have no access to your vault.

## What Verrou collects

Nothing. Verrou has no account of its own, no analytics, no advertising, no
crash reporting and no tracking. The app's privacy manifests declare no
collected data.

## Where your data goes

- **Your Vaultwarden server**: your vault, encrypted on your device before it
  is sent (Bitwarden's end-to-end encryption), and site names for website
  icons. Your server's operator is responsible for what it stores.
- **Have I Been Pwned** ("Pwned Passwords", api.pwnedpasswords.com): when the
  breach check runs, only the first 5 characters of a password's SHA-1 hash
  are sent (k-anonymity), never the password or the full hash. The new
  password check can be turned off in Settings.
- **Your iCloud account**, only if you pair an iPhone to approve the Mac's
  requests: the requests and answers go through your own iCloud private
  database (CloudKit), sealed end to end between your two devices, then are
  erased; Apple's push notification service tells the iPhone a request is
  waiting, without its content.
- **GitHub**, for the Mac app downloaded from the website: once a day and
  when you choose "Check for Updates…" (automatic checks can be turned off
  in Settings), Verrou downloads
  the description of the latest release and, if it is newer, its disk image.
  GitHub sees your IP address and the version of Verrou and of macOS (in the
  request's User-Agent); nothing else is sent.
- **The site of an item**, only when you tap "Change Password" or "Create a
  Passkey" for it: Verrou asks that site whether it publishes the standard
  addresses for those pages (`/.well-known/change-password`,
  `/.well-known/passkey-endpoints`), without cookies.

## On your device

The vault is stored encrypted on your device; on iPhone it is excluded from
iCloud and computer backups. Face ID and Touch ID are handled by the system: Verrou never
sees your biometric data. The camera is used only to scan a one-time code's
QR code, and no image is saved.

On iPhone, the one-time codes you choose to show in widgets ("Show in
widgets and on Apple Watch" on an item's page) are kept in this iPhone's
keychain, outside the vault, until you turn this off or sign out: their
title, site and seed, never synced and never sent anywhere. If you have an
Apple Watch with Verrou, the iPhone hands the same list to it directly
(Apple's WatchConnectivity, between your paired devices), and the Watch
keeps it in its own keychain: nothing leaves your Apple devices. When you pick a
vault item in a shortcut, the Shortcuts app keeps its title and identifier;
Verrou adds nothing of your vault to Spotlight.

When Verrou crashes or hangs, macOS and iOS hand it a report (MetricKit)
about once a day: call stacks and versions, nothing from your vault. Verrou
keeps the 20 most recent on the device and never sends them; Settings →
Diagnostics show how many there are, let you share them (you choose with
whom) or delete them.

## Contact

Questions: open an issue at https://github.com/bonout/verrou/issues, or
write to contact@bonout.com. Security reports: see [SECURITY.md](SECURITY.md).

The technical details of every connection are in [SECURITY.md](SECURITY.md).
