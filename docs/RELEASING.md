# Releasing Verrou

A `v*` tag runs [.github/workflows/release.yml](../.github/workflows/release.yml):
it builds every artifact, attests where each one was built, and publishes the
GitHub Release with `SHA256SUMS`.

| Artifact | Without signing secrets | With signing secrets |
|---|---|---|
| Mac app | `Verrou-<v>-macos-arm64-adhoc.zip`: ad hoc, no system credential provider | `Verrou-<v>-macos.dmg`: Developer ID, notarized and stapled, with the credential provider |
| iPhone app | skipped | uploaded to TestFlight (internal testing) |
| Firefox extension | `verrou-<v>-unsigned.xpi` (Developer Edition, Nightly) | `verrou-<v>-firefox.xpi`, signed by Mozilla (unlisted) |
| Chromium extension | `verrou-<v>-chromium.zip` | same |
| CLI | `verrou-<v>-<target>.tar.gz` for Linux x86_64, macOS arm64 and x86_64 | same |

Check a downloaded file:

```
gh attestation verify Verrou-0.1.0-macos.dmg -R bonout/verrou
shasum -a 256 -c SHA256SUMS --ignore-missing
```

## Cutting a release

1. In a pull request, set the same version in `Cargo.toml` (`[workspace.package]
   version`) and `apple/project.yml` (`MARKETING_VERSION`). The extension's
   version follows its content (`scripts/stamp-extension.sh`).
2. Merge it, then tag `main` and push the tag:

   ```
   git checkout main && git pull --ff-only
   git tag -a v0.1.0 -m "Verrou 0.1.0"
   git push origin v0.1.0
   ```

3. Approve the `release` environment in the run (Actions tab): the signing jobs
   wait for it.

A release created by hand in GitHub's interface for the tag is fine: the
files are attached to it and its notes are kept.

The first job fails if the tag and the two versions differ. Running the
workflow by hand (Actions › Release › Run workflow) builds everything and
publishes nothing: a dry run.

## Signing secrets

They live in the `release` environment (Settings › Environments › release),
which requires an approval and only accepts `v*` tags, so a pull request never
sees them.

| Secret | What |
|---|---|
| `APPLE_TEAM_ID` | the 10-character Apple team identifier |
| `ASC_KEY_ID`, `ASC_ISSUER_ID`, `ASC_KEY_P8` | an App Store Connect API key with the Admin role (Users and Access › Integrations): notarization, profiles, TestFlight. `ASC_KEY_P8` is the content of the `.p8` file |
| `MAC_DEVELOPER_ID_P12`, `MAC_DEVELOPER_ID_PASSWORD` | the Developer ID Application certificate and its private key, exported from Keychain Access as `.p12`, then `base64 -i cert.p12 \| pbcopy` |
| `MAC_DEVELOPER_ID_PROFILES` | the two Developer ID provisioning profiles for that certificate, named `Verrou Developer ID` (`app.verrou.mac`) and `Verrou AutoFill Developer ID` (`app.verrou.mac.autofill`): `tar -czf - verrou.provisionprofile verrou-autofill.provisionprofile \| base64`. An API key can't create Developer ID profiles: make them on developer.apple.com (Profiles › Developer ID), again when the certificate is renewed |
| `AMO_JWT_ISSUER`, `AMO_JWT_SECRET` | addons.mozilla.org API keys (https://addons.mozilla.org/developers/addon/api/key/) |

Each pair is optional: without the Developer ID certificate the Mac app is
ad hoc (even with the team and API key, which TestFlight uses); without the
AMO keys the Firefox extension is unsigned.

Signed builds show the Apple team's legal name (`codesign -dv`, Gatekeeper,
TestFlight and the App Store).
