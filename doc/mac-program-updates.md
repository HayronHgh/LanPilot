# Mac program transaction storage

Status: implemented storage/verification foundation, not an enabled installer or
unattended updater. The installed application and service have not been changed.
Ordinary launch recovers an interrupted program transaction before login
recovery/actions. A local signed-package UI entry is connected to the real
transaction; online acquisition and signed end-to-end acceptance remain required.

## Program and state boundary

The program location is the actual account's `~/Applications/LanPilot.app`.
Its private same-volume `~/Applications/.LanPilot` directory owns the bounded
journal, one candidate slot, one retained previous app and inventory metadata.
Configuration and Keychain identity remain outside these slots. The transaction
does not back up/rewrite a user's settings or export/import keys. It shares the
product operation lease; quiescence also checks the actual runtime lease.

Source apps are copied into the private candidate. A complete, verified candidate
is required before stopping the old owner. Replacing a prior installation uses
descriptor-relative `renameatx_np(RENAME_SWAP)`, followed by both directory syncs.
There is no move-away interval where the ordinary application path disappears,
and no non-atomic fallback on an unsupported filesystem. First install uses
create-new rename. Both slots must belong to the same filesystem.

The durable schema-1 journal has phases `staging`, `prepared`, `activated`,
`committed`, `restoring`, `rolled_back`, `recovery_failed`. It stores hashes,
canonical versions and prior service state, not filesystem authority or commands.
Recovery compares actual slot hashes, including a swap that completed before the
`activated` write. It restores only a recognized prior app. A post-commit cleanup
failure keeps the healthy new app active; subsequent recovery finishes retention.

Only one previous app is retained. Retired files are removed using a hash-bound
inventory and an exact remaining subset, so a crash halfway through cleanup is
resumable. Unknown paths, links or changed retained files are not blindly removed.
For an unverified partial copy, cleanup is limited to the declared candidate's
known paths, types and size bounds; that relaxation never applies to an active or
previous app. The journal cannot label that partial candidate as activated.

## Authenticated input

The production API accepts the existing shared `VerifiedUpdate` type. Its package
artifact is a detached canonical **bundle inventory**, not a ZIP hash. The update
manifest uses platform `macos-app-inventory`, architecture `universal2`, schema1
and the shared ECDSA-P256 signed payload. The manifest's package size/hash bind
the inventory; the inventory binds every permitted file's data and path. It is
revalidated before and after the private copy. No untrusted archive is extracted.
This format must be produced/signed explicitly; relabeling an ordinary ZIP is
invalid. Production must pin the release verification key, never accept a peer's
choice of verifier/key. That application-level key provisioning is not wired yet.

Independently, source/installed bundles must satisfy the compiled expected
Developer ID publisher requirement and fixed product identifier. Versions are
read from the secured Code Signing information dictionary, with the expected
main executable/package type. Candidate version must match the signed manifest;
downgrades and unexpected changed same-version apps are rejected. Repeating the
same already-authenticated inventory/version does not rewrite/restart the app.
Universal2 input also requires nonoverlapping arm64/x86_64 64-bit Mach-O slices;
that layout check is not a signature or runtime execution proof.

Native staging checks system execution policy with fixed `spctl --assess`
arguments, without modifying trust policy or populating its assessment cache.
The source's bounded extended attributes, including quarantine if present, are
preserved. No quarantine stripping, custom trust rule, private assessment API or
replacement signing identity is used. Successful production signing,
notarization and policy acceptance have **not** been demonstrated in this
development environment.

The canonical app contract permits one main executable, the fixed login job,
Info.plist, optional PkgInfo/signature resources and bounded Resources. It rejects
symlinks, hardlinked files, special files, traversal, executable ownership bits,
unsafe write modes/ACLs and obvious private-key resources. Limits: 4,096 entries,
256 MiB per data file, 512 MiB combined data/copied metadata, 4 MiB inventory,
32 xattrs per object and 64 KiB per attribute. It deliberately does not support
arbitrary framework/helper/symlink layouts. A future format change needs a new
reviewed contract rather than weakening validation.

## Release tooling

The developer-facing entry below hashes only its own bundle into an absolute,
create-new output, outside the bundle. This creates **unsigned inventory data**,
not a signed release or install authorization:

```sh
LanPilot.app/Contents/MacOS/LanPilot --write-program-inventory /absolute/new/bundle.inventory
```

It checks physical ancestors as well as strings, to reject case-insensitive
aliases back into the bundle. Repeating an existing output refuses overwrite.
Produce the inventory after signing/stapling the final universal app; then sign
the shared update manifest through the publisher's release process. The ordinary
user must not need these commands, fingerprints or signing keys.

## Evidence and open integration

Windows full build and CTest10/10 pass (31.79 seconds). Mac full build and
CTest11/11 pass (2.55 seconds). The shared workflow covers eight activation failure/crash
boundaries, untrusted input, same-package no-op and health rollback. Native
temporary-directory tests exercise actual first placement, two consecutive
upgrades, atomic directory swaps, rollback after an omitted phase write,
interrupted retention, partial-copy cleanup without stopping the old owner,
disabled service preservation, xattr preservation and synthetic Mach-O bounds.
A synthetic identity marker remains unchanged and all fixture data is removed.
Fixture manifest verification is explicitly reported as `signature_mode=fixture`;
it does not prove production signatures or native service health.

The real bundle inventory export succeeds; existing output and self-bundle
mutation are rejected. Source hashes match the designated mirror and installed
agent/LaunchAgent hashes remain unchanged. A readonly policy assessment of the
development bundle fails, as expected; no successful signed assessment is claimed.

Before enabling this layer:

1. The native **Install signed update** action now verifies selected metadata
   with the compiled release public key, shows the version for confirmation,
   reverifies the same confirmed offer and invokes these storage APIs. A
   successful update preserves settings/identity and asks the user to reopen
   the application. Online release discovery/download and first installation
   still require integration; this is not an automatic-download claim.
2. The production storage APIs now construct real `ProgramServiceHooks` internally.
   They borrow the already-owned lifecycle directory/lease, durably close the
   login startup gate, use the instance-bound graceful stop receipt, then
   restart the new or restored canonical app with a fresh activation nonce.
   The new instance must have a different instance/PID-birth identity and a
   running Code Signing CDHash/secured version matching the installed app.
   Disabled services stay disabled; pending login approval is not silently
   consumed. No public login entry point is called while holding its lock.
   A fixed bounded child probes only the installed app's own readiness command;
   no consent, key export, peer instruction or shell command is accepted.
3. Complete safe agent termination acceptance. The new
   [shutdown primitives and fixture](agent-shutdown.md) cover terminal input
   ownership, SIGTERM/SIGINT and interruptible pipe I/O without OS input.
   The [instance-bound native stop receipt](mac-service-quiescence.md) is now
   implemented with isolated coverage. Startup receipt publication now waits
   for the native TLS listener-ready state, after local capture/identity checks;
   binding failure/cancellation cannot publish it. This is still local startup
   health, not authenticated peer traffic, decoded presentation or scan-out.
   Actual signed handoff and authenticated TLS cancellation still need
   acceptance; PID disappearance is not a release receipt.
4. Exercise actual signed initial install, two updates, interruption and ordinary
   relaunch, logout/login/reboot and original native permission continuity.
   Correct release deployment target/OS compatibility also needs acceptance.
5. Complete first-time paired enrollment/certificate lifecycle and clean-user
   tests; archive legacy deployments only after canonical operational success.

No Developer ID is currently available. Continue independent implementation,
but do not present the fixture green state as a finished install-once product.

## Startup and recovery fences

Normal visible launch performs program recovery before login recovery, including
when connection settings have not been imported yet. Login activation remains
disabled until this succeeds. The service also reads the program journal before
delegation: `activated/committed` permits only the exact target inventory/version;
`restoring/rolled_back` permits only the verified previous inventory/version.
Other unfinished phases cannot open a new runtime. The gate is read-only in the
service and does not acquire the updater's operation lock.

The local receipt is written synchronously on the agent caller after
Network.framework reports the listener ready, not from its callback queue or
the frame/input hot path. A three-second cancellable readiness wait bounds bind
failure. Exact receipt nonce, configuration, kernel process birth, live lease
and actual launchd job are checked together. Signature/path alone cannot accept
an old process from the same publisher as the newly installed generation.

Portable workflow tests cover gate-before-stop ordering, disabled/absent owners,
pending approval, failure at stop/probe/start/receipt, fresh versus stale runtime
evidence and every program-journal startup phase. The native storage fixture
exercises actual journal gate/nonce writes while the operation lease is held.
These fixtures perform no registration, user capture/input or Keychain access.
Positive signed native service activation remains a distinct release gate.

## Signed package entry

An update folder has exactly these named inputs (other siblings grant no authority):

```text
release.toml       shared signed UpdateManifest
bundle.inventory  artifact bound by the manifest's size and SHA-256
LanPilot.app      bundle whose complete inventory/publisher is verified before stop
```

`LANPILOT_RELEASE_PUBLIC_KEY_XY` is a build-time, 64-byte ECDSA-P256 X||Y public
key in lowercase hexadecimal. Its default is empty: developer builds cannot
install updates through this entry. Invalid syntax/zero keys fail configuration.
The key is not read from connection settings, selected packages or peers. This
release authority is separate from TLS identities and Developer ID code signing.
Do not ship the public RFC test vector as a release pin or mint an ad-hoc signer
to bypass the expected publisher. No production release key is configured yet.

Selected manifest and inventory are bounded and copied once into a protected
two-file scratch slot, with a separate verification lease held through apply.
Parsing and signature verification use those copied bytes. The native transaction
still takes the product operation lease itself; verification never recursively
acquires it. Confirmation binds every canonical signed manifest field and its
signature, so changing a package between review and apply cannot silently switch
the user's chosen update. The installed version and bundle are rechecked under
the transaction's own lease before activation.

Scratch state is limited to 64 KiB manifest plus 4 MiB inventory and one slot.
Cancellation/errors clear the owned scratch files. A later attempt may remove
known empty/truncated scratch files left by a crash, while unknown names, links,
hardlinks or unsafe modes refuse cleanup without deleting them. Lifecycle records,
app slots, settings and keys never use that relaxed scratch cleanup. Quit is
deferred while verification/activation is running, allowing the transaction to
finish or leave its existing durable recovery journal.

The isolated native verifier check uses only the public RFC6979 sample vector
with Security.framework, rejects tampered bytes and creates no keys or Keychain
items. The native scratch fixture uses its own temporary root and exercises
overlap, bounds, cleanup, interrupted empty files and link/unknown-file rejection.
It does not authenticate a real production update or prove an installed upgrade.
