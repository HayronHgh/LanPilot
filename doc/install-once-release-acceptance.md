# Install once, update in place: release acceptance

Status: native pairing, persistence, renewal and recovery have source/isolated
workflow evidence. Consumer installation and signed deployed-update acceptance
remain open. A source commit, a staging folder or a passing CTest suite is not an
installed release. Record the exact package hash and execution context for every
installed result. Keep machine-specific paths and identities in private evidence,
not this public document.

## Supported product boundary

| Surface | Supported destination | Persistent state |
|---|---|---|
| Windows entry | one LanPilot desktop shortcut, fixed LocalAppData/Programs/LanPilot/LanPilot.exe | LocalAppData/LanPilot |
| Windows active payload | one integrity-checked runtime selected by the installer journal | connection profile and native CNG keys remain outside the payload |
| Mac application | ~/Applications/LanPilot.app | ~/Library/Application Support/LanPilot and native Keychain |
| Mac login service | the native app's registered service owner | service/configuration receipts survive program replacement |
| Legacy CLI/SSH | explicit compatibility route only | retain while it is still the working/referenced installation |

Device identity, TLS certificates and publisher identity serve different purposes.
The user-facing pairing workflow creates protected device keys and remembers the
connection. It does not require the consumer to provide CA files, certificate
fingerprints, code-signing credentials or private-key exports. Publisher signing
and the embedded release-verification key are maintainer release configuration.
Initial local pairing approval and OS privacy consent remain explicit. Routine
updates must not create another device identity or reset an existing OS grant.
Revoked permissions and changes required by the OS are not silently bypassed.

## Delivery gaps that must be closed

1. **Windows setup installed acceptance.** The desktop package now includes the
   offline `LanPilot-Setup.exe` GUI. It embeds the complete payload and fixed
   inventory/driver, uses the existing atomic install/update transaction, retains
   settings and keys, and runs child processes without consoles. The as-invoker
   manifest does not request elevation. Local package validation is not publisher
   authentication. Fresh-account and signed installed-update acceptance remain
   open; arbitrary bootstrap replacement is not provided as a repair shortcut.
2. **Canonical Mac release artifact.** Stage the native `macos-app` component;
   A home-domain first-install `.pkg` now has isolated build/expansion checks;
   see `macos-native-installer.md`. Its unsigned development output is not an
   activatable signed release and does not prove installed-user acceptance.
   do not present the legacy CLI `desktop` package as the native product. Configure
   the expected Developer ID team and release-verification key, sign and validate
   the exact artifact, and complete the appropriate distribution checks. Empty
   publisher/update policy intentionally prevents production activation/updates.
   Do not substitute a TLS identity or an ad-hoc signer to pass this gate.
3. **Actual installed evidence.** Verify the package, entrypoint and running
   payload before testing. An existing schema-1 connection proves legacy continuity,
   not deployment of native enrollment, new credential renewal or new Viewer code.
4. **Cleanup after replacement proof.** Only retire a legacy path after no active
   shortcut, task, service, runtime receipt, trust-resource reference or rollback
   dependency needs it. A folder named backup or recovered-trust may still be active.
   Never bulk-delete identity folders, reset TCC or recreate keys as cleanup.

## Required installed acceptance matrix

| Requirement | Strong evidence | Current gate |
|---|---|---|
| New Windows user installs once | trusted setup entry creates the canonical roots, one Apps entry and one shortcut without developer tools/admin/hand-entered trust fields | GUI setup implemented; signing and fresh-account installed proof OPEN |
| New Mac user installs once | exact signed canonical app, foreground native pairing, initial OS consent and login service | OPEN: production signing/configuration and human OS acceptance |
| Only IP and local confirmation | both native UIs complete the same signed pairing; saved profile reloads; private keys never leave native stores | source workflow verified; installed proof OPEN |
| Reopen and reconnect | ten normal open/close cycles and actual service restart/expiry, fresh authentication, no stale input, no extra authorization prompt | source/hidden workflow verified; installed proof OPEN |
| Persistence after reboot | same saved endpoint, native private-key references and pairing transcript; login service/Windows entry usable | OPEN |
| Two ordinary version updates | exact signed versions N,N+1,N+2, same publisher, settings/key references preserved and one active program owner | isolated transactions verified; installed proof OPEN |
| Interrupted update | controlled test instance recovers to known prior/new version with no config/key loss, no partial activation | workflow evidence exists; installed proof OPEN |
| Credential/status expiry | trusted same-key renewal and recovered state, including genuinely expired evidence; no validation bypass or new consent | native fixtures verified; installed migration/long-run proof OPEN |
| Input release and shutdown | remote held-state release on focus/disconnect and no Viewer/SSH residue; expected single Mac listener owner remains | workflow evidence exists; installed/manual proof OPEN |
| Retire duplicates | dependency inventory plus successful replacement and rollback checkpoint; no stale launch entry afterward | OPEN until replacement proof |

Use bounded no-input handshake probes before manual desktop acceptance. A TLS-only
probe proves network/native trust, not capture, input, framebuffer quality or a
fresh-account install. Never infer physical scan-out or input-to-photon from a
successful application write/Present receipt.

## Maintainer verification route

1. Build the exact privacy-clean source for Windows and Mac, run the complete
   workflow/security suites and check the diff. Preserve the tested-source hashes.
2. Inspect installed entry/config/runtime receipts separately from source outputs.
   Verify native key availability without exporting keys or logging command lines.
3. Produce the platform's canonical package and verify its publisher and payload.
   Keep the existing installed release intact until its replacement is accepted.
4. Consolidate Mac human setup into one batch: install the verified app, use its
   foreground permission/pairing/login-service interface, then test from Windows.
   Do not scatter Terminal scripts or new authorization shortcuts on the desktop.
5. Execute the matrix on a fresh user context and the existing installation. Record
   PASS/FAIL/NOT RUN with package hash, command/context and observable result.
6. Publish only after all required installed gates pass. Preserve local research
   history separately from the curated public release lineage and its license.
