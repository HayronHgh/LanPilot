# Canonical Mac application and permission lifecycle

Status: development foundation, not an installed product or release acceptance.
The existing CLI/TLS installation remains unchanged. Do not deploy this bundle
over an authorized agent just to test its UI.

Initial foundation on the designated Mac mirror passed build/CTest5/5, including
actual bundle metadata, hidden fixture-consent/layout checks and the shared
agent entry. Windows build and CTest7/7 pass. All seven transferred source hashes
match; the installed agent's hash remains unchanged. The own-view preview was
visually checked for readable controls, insets and complete text. No native
consent request or user-visible window occurred during these checks.

## One application owns the code

The future canonical application is LanPilot.app, bundle identifier
`com.lanpilot.desktop`, with one `Contents/MacOS/LanPilot` executable. Its normal
entry opens native setup. Explicit `--desktop-agent ...` enters the SAME shared
agent implementation as the compatibility CLI; it does not add a second helper
code identity or change H.264/RECT/TLS/input framing.

The old CLI executable remains buildable through a thin main wrapper. This is
source compatibility, not a second product installation. The app, its settings,
and the eventual login owner must migrate as one reviewed operation.

The setup window initially reads permission status and code-signing metadata.
It does not import trust, capture pixels, touch the clipboard or inject events.
The explicit login action below can reuse a saved Keychain identity and switch
the service owner after its prerequisites pass. Screen Recording is
requested only by its own button. Accessibility is optional, disabled until the
person chooses to prepare keyboard/mouse control, and still does not constitute
a paired session's control grant. System Settings is opened only on a local
button press using its fixed application URL, without shell automation.

The displayed permission belongs to THIS process. A true preflight result is
not a capture receipt, not proof of a service's responsible-process identity,
and not peer authentication. A signed-with-team flag is not notarization or a
release-signature policy verdict. All those states remain separate.

## Build and isolated validation

On Mac, the normal build includes the LanPilotMac bundle target. The following
checks neither show a window nor request native consent:

```sh
./build/desktop-agent/LanPilot.app/Contents/MacOS/LanPilot --check-application
./build/desktop-agent/LanPilot.app/Contents/MacOS/LanPilot --check-layout
./build/desktop-agent/LanPilot.app/Contents/MacOS/LanPilot --desktop-agent
```

The first command reports actual read-only preflight/signing metadata, explicitly
marking capture/identity/peer verification false. Layout tests use a fixture
permission backend: no native request API is called even when simulated buttons
are exercised. They cover initial optional-control denial, explicit opt-in,
one request per simulated grant and no repeated request after grant. The report
separates simulated requests from native requests (always zero in this test).
No GUI login session returns 77, which CTest records as skipped, not passed.

An optional `--render-layout /absolute/new-preview.png` caches ONLY the app's
own view into a bounded PNG, never a desktop or external window capture. It
refuses existing output files and symlink ancestors. That image uses the same
fixture backend and proves UI layout only. It does not prove native consent.

To stage the bundle without installing or signing it:

```sh
cmake --install build --component macos-app --prefix /absolute/new/stage
```

No Developer ID identity is currently available. Linker-generated development
code signatures are not a production identity workaround; do not create a new
self-signed identity, weaken designated requirements or claim update-stable
authorization from a development bundle. The installed agent's existing cdhash,
Keychain authorization and launchd configuration remain frozen during this unit.

## Remaining deployment gates

The [Mac program transaction layer](mac-program-updates.md) now provides bounded
authenticated-inventory staging, same-volume atomic exchange and recovery. It
has no enabled Install/Update UI or production service hooks yet; those are still
required before the staged application can replace the installed product.

### Protected configuration boundary (validated, not activated)

The staged bundle now owns a bounded schema-1 `service.conf` under the actual
account's `~/Library/Application Support/LanPilot` (resolved through the account
database, not an environment override). Program updates do not replace this
directory. The normal window can import the existing connection with one local
button; no fingerprint, certificate filename or private key is typed by the user.
This migration is for an already paired installation, not first-time enrollment.

The importer reads only the fixed legacy TLS LaunchAgent, accepts the known
endpoint/argument layout, and reconstructs a typed configuration. It never
executes its program path or copies arbitrary launchd keys. It preserves the
opaque Keychain reference, peer certificate pin, selected control/visual policy
and explicit clipboard policy. It checks bounded CA/OCSP resources under the
known user-owned identity roots. Existing trust resources remain at their old
locations so the existing renewal owner is not silently disconnected.

Configuration is create-new, private and durable. Reimporting identical metadata
does not rewrite it; conflicting saved metadata is rejected without overwriting.
Descriptor-relative no-follow traversal, owner/mode/ACL checks, single-link files,
size bounds and an exclusive persistent-inode owner lock protect reads/writes.
The reader distinguishes an absent extended ACL from an ACL retrieval error.
An inherited ACL write grant still fails closed. An import cannot change settings
while the configured service owns its runtime lease. Lifecycle operations own
the operation lease separately, so stopping a service cannot deadlock on the
lease held by that service.

`--run-configured-service` builds the existing agent's argument vector from this
validated configuration, with no shell. The lease lasts through the shared agent
entry. A legacy job file OR a loaded legacy job blocks this endpoint; a staged or
unsigned bundle is also refused. The compatibility CLI remains unchanged.
The login lifecycle below now uses this boundary. No service is registered by
importing. Neither the configuration nor a nonempty code team replaces the
compiled publisher policy.

Isolated acceptance on 2026-10-24:

| Check | Result |
| --- | --- |
| Windows full build / CTest | PASS, 8/8 tests, 39.80 seconds |
| Mac full build / CTest | PASS, 7/7 tests, 1.60 seconds |
| Protocol/configuration workflow | Strict field/schema/number/path/policy rejection, preserved argument ordering |
| Native storage workflow | Atomic create-new, identical repeat, conflict preservation, competing owner, symlink/hardlink/mode/ACL rejection; fixture removed |
| Actual legacy metadata (read-only) | `existing_connection=valid`, zero file changes/Keychain access/listeners |
| Staged service guard | Exit 78, no listener; installed signed bundle is required |
| Hidden native view | Bounds PASS, own-view PNG inspected, no visible window/native consent |
| Transfer / installed state | Seven source hashes match; installed executable and LaunchAgent hashes unchanged |

The readonly commands `--check-configuration` and `--check-existing-connection`
print state only, not identity references, fingerprints, paths or input content.
`--check-configuration-store` uses only temporary fixtures, not user metadata.
`--import-legacy-configuration` is an explicit metadata mutation; automated
validation deliberately did not invoke it against the actual account.

The login lifecycle below is connected in source and isolated-tested; actual
signed registration/rollback still needs acceptance. The bundle is staged only.
Do not ask users to toggle the old CLI and the new bundle's native permissions
as if they had the same responsible-process identity. Consolidate the eventual
local install/consent operations into one reviewed checklist.

### Single login owner and recoverable handoff (source implemented)

The app embeds `Contents/Library/LaunchAgents/com.lanpilot.desktop.service.plist`.
It uses a fixed bundle-relative `BundleProgram` and the same app executable's
`--run-configured-service` entry. No account names, fingerprints, Keychain
references or research paths appear in that job. `SMAppService` owns registration;
the new product does not copy another plist into the user's LaunchAgents folder.
The native window has **Enable start at login** and **Open Login Items** actions.

Activation requires an installed bundle at `~/Applications/LanPilot.app`, with
the fixed bundle identifier, a strict Developer ID Application requirement and
the expected publisher team compiled with `LANPILOT_DEVELOPER_TEAM_ID`. The cache
value defaults to empty, which disables activation. An arbitrary nonempty team
or ad-hoc signature is insufficient. Invalid team configuration is rejected at
configure time. This code-identity predicate does not claim notarization or
authenticate a release-update manifest; those release checks remain open.

The durable handoff journal is bounded, private and binds a fresh nonce to the
canonical configuration hash and validated legacy backup hash. It contains no
executable/path authority. The coordinator performs:

1. Validate code, saved policy, local permission status and noninteractive use
   of the existing Keychain identity. Save a private, validated rollback source.
2. Register the new login item in an `authorizing` state that prevents its
   service endpoint from starting. Pending native background approval leaves
   the original owner untouched. Retry occurs only through the local action.
3. Once approved, unregister/quiesce that provisional item, persist `prepared`,
   stop the exact legacy job, verify its prior PID is gone and retire only its
   validated plist. The original executable and protected identity remain.
4. Persist `starting` and register the canonical item. Its runtime lease,
   absence-of-legacy guard, journal gate and configuration hash prevent a second
   owner. Before publishing a receipt, THIS service checks native permissions,
   uses the existing identity noninteractively and captures one bounded startup
   frame. The startup proof keeps pixels only in memory and records no pixels.
5. Accept only a matching nonce/configuration receipt from the live service PID
   that launchd reports and which holds the runtime lease. Persist `active`.
   This proves local capture/key readiness, not TLS peer authentication,
   Windows presentation, clipboard behavior or physical scan-out.

On failure, persist `restoring` FIRST to close the startup gate, then unregister
the new item and prove its process/runtime lease are gone before restoring the
old validated plist and its original loaded/unloaded state. If stopping or
restoration cannot be proved, retain recovery state and never start both owners.
Normal app launch recovers an interrupted transaction only under the installed
publisher gate. Recovery does not require the failed version's capture/Keychain
approval; it can restore the old owner after those checks fail. An already
active item disabled by the user is not automatically re-enabled on app launch.

The local Enable action may ask the native Keychain dialog to authorize the
same saved identity, then retry. It never generates a replacement identity.
Screen Recording/Accessibility still use their separate explicit native buttons.
Work runs off the UI thread. The old/new code identities are not interchangeable
just because their preflight flags happen to be true in an SSH session.

Current evidence:

| Check | Result and scope |
| --- | --- |
| Mac full build / CTest | PASS, 9/9, 1.97 seconds; native SDK adapter compiled |
| Windows full build / CTest | PASS, 9/9, 33.42 seconds; lifecycle coordinator exercised |
| Coordinator workflow | 12 activation failure/crash boundaries plus four rollback boundaries; pending approval, lost grant, repeated activation and failed stop; no dual owner |
| Actual Mac storage/process fixture | Atomic journal replacement and corruption rejection; stale receipt rejected; child holds the real kernel lease, SIGKILL releases it and durable journal remains readable; fixture removed |
| Bundle inspection | Exact fixed job dictionary passes; actual legacy PID parser observes the existing job; zero registration operations |
| Publisher rejection | Invalid CMake publisher value rejected; staged unconfigured bundle returns 78 before any listener |
| Source / installed state | Twelve source hashes match the mirror; installed agent and legacy LaunchAgent hashes unchanged |
| UI | Own-view 760x640 PNG inspected; all controls bounded; simulated consent only, no actual visible window |

**Not run:** native registration, bootout, actual service capture proof, successful
signed handoff, rollback through real launchd, login/reboot or consecutive signed
updates. No Developer ID is available. The test backend and SIGKILL file fixture
do not substitute for those operations. There was no installed service change,
native consent request, Keychain signing, desktop/clipboard access or injected
input during validation. First-time pairing and the program updater remain open.

1. Validate the bundle build, all Mac CTests and the headless view rendering.
   Keep Windows build/CTest and CLI exit behavior unchanged.
2. The bounded configuration and metadata import boundary above is validated.
   Actual account migration and activation remain open. Retain existing Keychain
   keys; do not copy authority private keys or infer a peer from its IP.
3. Connect native two-end pairing/enrollment and service status. Make an actual
   service permission/capture probe authoritative before claiming ready. A
   foreground app grant must not stand in for a background service's evidence.
4. Accept the implemented ServiceManagement handoff against an actual signed
   installed bundle, including native approval, capture receipt, failure rollback
   and logout/login. The source/fixture checks above do not close this gate.
5. Production-sign the fixed bundle and nested code with the intended Developer
   ID identity; verify matching requirements, notarization and real consecutive
   version updates. The user's absence of Developer ID keeps this gate open;
   it does not justify silently granting permissions or bypassing TCC.
6. Verify fresh-account installation, explicit native consent, paired reconnect,
   logout/login, interrupted updates and actual capture/control; THEN archive
   the obsolete CLI deployment and Desktop authorization command. Keep local
   research mirrors separate from installed programs.

Current installed-service evidence: the Windows viewer's six-second view-only
probe had zero present receipts, and the Mac service logged Screen Recording
denied. This staged application does not retroactively fix or pass that gate.

Apple references:
[ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit),
[CGPreflightScreenCaptureAccess](https://developer.apple.com/documentation/coregraphics/cgpreflightscreencaptureaccess()),
[CGRequestScreenCaptureAccess](https://developer.apple.com/documentation/coregraphics/cgrequestscreencaptureaccess()),
[SMAppService](https://developer.apple.com/documentation/servicemanagement/smappservice),
[code identity requirements](https://developer.apple.com/documentation/technotes/tn3127-inside-code-signing-requirements).
