# Accessibility

What Verrou does for VoiceOver, the keyboard and motion on the Mac and the
iPhone, how it is checked, and what isn't covered yet. Report a problem: an
issue on GitHub or contact@bonout.com.

## VoiceOver (Mac)

- Every control drawn as an icon alone has a spoken label: show and hide,
  copy, delete, move up and down, generate a password, sort, favorites,
  unlock, help links, and the toolbar.
- Icons that carry information say it: an item's one-time code, a Send
  protected by a password or hiding the e-mail, a field hidden by the
  organization, the kind of a Send or of an imported item.
- Decorative icons, next to a text that already says the same thing, are
  hidden from VoiceOver so that it doesn't read symbol names.
- The menu bar icon says whether the vault is locked or unlocked.

## Keyboard (Mac)

The main actions have a keyboard shortcut:

| Shortcut | Action |
|---|---|
| ⌘⇧Space | Quick Access, from any app |
| ⌘\ | Fill the username and password in the app in front |
| ⌘F | Search |
| ↑ ↓ | Move through the results |
| ⌘N, ⌘⇧N | New login, new secure note |
| ⌘E, ⌘S | Edit, save |
| ⌃⌘C | Copy the username |
| ⇧⌘C | Copy the password |
| ⌥⌘C | Copy the one-time code |
| ⌥⇧⌘C | Copy the website |
| ⌥ (hold) | Show the item's hidden fields |
| ⌘A, ⇧↑ ⇧↓ | Select all, extend the selection |
| ⌘R | Sync |
| ⌃⌘L | Lock |
| ⌘, | Settings |

Any of them can be changed in System Settings → Keyboard → Keyboard
Shortcuts → App Shortcuts, with the menu item's name.

## iPhone and AutoFill

- **VoiceOver**: every icon-only control has a spoken label (show and hide,
  copy, generate, open in Safari, lock, sort, new item). A field row and a
  site row are one element: double-tap copies, and the *Copy*, *Show* and
  *Open in Safari* actions are in the actions rotor. Revealed passwords,
  generated values and one-time codes are spelled out character by
  character; a hidden value reads "Hidden value". The generator's length
  slider reads its number of characters.
- **Announcements**: every notification (copied, saved, moved to the trash,
  failures) is spoken when it appears; failures stay 6 seconds, and a
  notification with *Undo* stays 8 seconds. Unlock and sign-in errors are
  spoken too, in the app and in AutoFill.
- **Dynamic Type**: labels, revealed values, masked dots, one-time codes and
  their countdown follow the text size; at the accessibility sizes the item
  page's header stacks and the quick copy bar gives way to the field rows.
- **Touch targets**: the row buttons (show, copy, open in Safari), the
  editor's show, copy and generate buttons, *Use master password* and the
  notification's *Undo* are at least 44 × 44 points.
- **Color**: orange and yellow are never the only carrier of a message nor
  used for small text on a light background; sync state is written, not only
  shown by a dot.
- **No lost work**: *Cancel* and swiping an edit sheet down ask before
  discarding changes; an edit screen closed by auto-lock reopens after the
  unlock.

## Motion

With *Reduce motion* (System Settings → Accessibility → Display), the
password generator's animation and the one-time code's countdown pulse are
replaced by a fade. Other transitions are short.

## Increase Contrast

With *Increase Contrast* (System Settings → Accessibility → Display on the
Mac, Settings → Accessibility → Display & Text Size on the iPhone), the
colors Verrou draws itself become stronger, on the Mac, the iPhone and in
AutoFill: field and card borders, focus rings, hover and selection
backgrounds, the track of the password strength meter, and the secondary
text of a selected row. The accent color is darker, so that white text on
a selected row stays readable in dark mode too. System colors and
materials already adapt by themselves. With the setting off, nothing
changes. The styles are in `apple/Shared/UI/Contrast.swift`.

## How it is checked

- `scripts/review-capture.sh` renders every screen of the Mac app, in light
  and dark mode, and checks each layout (cut or overlapping elements).
- `VerrouMacUITests` runs Apple's accessibility audit
  (`performAccessibilityAudit`: element descriptions, contrast, hit
  regions, clipped text) on the lock screen, the vault, the search and the
  settings, with the demo vault. It opens the app on screen, with the same
  identifier as the installed Verrou: quit Verrou before running it.
  `xcodebuild test -project apple/Verrou.xcodeproj -scheme VerrouMacUITests`.
- `VerrouiOSUITests/AccessibilityAuditUITests` runs the same audit on the
  iPhone, in a simulator set to English, with the demo vault: lock screen,
  home, an item page, the edit screen, the generator and the settings.
  `xcodebuild test -project apple/Verrou.xcodeproj -scheme VerrouiOS
  -destination 'platform=iOS Simulator,name=iPhone 16'
  -only-testing:VerrouiOSUITests/AccessibilityAuditUITests`. CI builds it
  but doesn't run it (no simulator session there).

## Not covered yet

- No formal WCAG conformance review has been done; the audit above is
  Apple's automated one.
- Text sizes follow macOS, which has no system-wide text size for apps.
- On the iPhone, the master password field's arrow button is smaller than
  44 points (shared with AutoFill, `apple/Shared/UI/Glass.swift`); Return
  on the keyboard unlocks too.
- The iPhone lock screen doesn't scroll: at the largest text sizes with the
  keyboard up, check that the field stays visible.
