# Personal installers for an existing paired Windows/Mac installation

This edition preserves a working pair before general fresh-machine distribution.
It does not require Apple Developer membership, notarization or a new TLS identity.
The formal native application's publisher gate is unchanged and is not bypassed.
Instead, the Mac package retains the already-installed compatibility service and
its exact authorized executable. This is not a generic first-time pairing package.

## Windows

The offline setup can pin an existing Viewer executable using the maintainer-only
CMake options `LANPILOT_SETUP_EXISTING_VIEWER` and
`LANPILOT_SETUP_EXISTING_VIEWER_SHA256`. A mismatch prevents configuration. The
selected bytes and all installer code remain embedded in the setup executable;
there is no runtime script/program path option. The ordinary build is unchanged.

The personal setup checks the saved connection and CurrentUser identity before
program installation. It does not generate keys, copy profiles into the package,
change endpoint/control policy or replace missing pairing with invented trust.
`--check-existing-pair` performs that preflight without installing or connecting.
The Viewer still validates the peer, exclusive trust roots and revocation evidence.
The existing transactional updater, runtime lease and one-shortcut layout apply.

## Mac

The maintainer-only `build-personal-installer.py` reads the current user's existing
`com.lanpilot.desktop-tls` service and packages only its existing executable at the
same relative location plus the license. It validates the known compatibility
command/policy and ownership. The package contains two SHA-256 bindings to runtime
and service configuration; it copies no plist configuration, certificate files,
private key, endpoint/account settings or input data. The exact original binary
may retain its original build-path strings, so personal artifacts stay private.
The installed machine's actual
profile is retained and must match the binding. Rebuild the personal package if
that profile changes. Do not distribute this pair-specific package as a general
release or upload its private build artifacts with a source publication.

The internal preinstall guard rejects a different executable/configuration,
unsafe/linked paths, root execution and an existing native app owner. A missing
executable can be restored only while the original matching service remains.
The postinstall verifies bytes and uses only that existing service definition.
It bootstraps that owner if absent and calls `kickstart` WITHOUT `-k`; it does not
terminate an active connection, rewrite a launchd definition or grant control to
another peer. Native Keychain/TCC policy and all TLS checks remain in the original
runtime. The package is unsigned: macOS may require local approval for this known
package, and privacy/keychain prompts remain OS decisions. No global Gatekeeper
disable, quarantine removal, root trust modification or ad-hoc re-signing is used.

## User flow

1. Run the Mac personal package for the current user. The existing identity and
   service are retained. No Terminal command or certificate form is required.
2. Close the Windows connection/Viewer, then run the Windows personal setup.
3. Open the existing Windows LanPilot shortcut and connect with its saved profile.

The Mac welcome and completion pages use the same restrained white/navy design
as Windows setup. They are bundled, static HTML with no external resources,
scripts, input fields or machine-specific data. The completion page explains
that the Mac component runs in the background and points directly to Connect on
Windows; it does not require another authorization helper or certificate form.
The retained LaunchAgent starts the same authorized executable after install and
on login. macOS still controls any local privacy/Keychain approval it requires.

The pair is not portable to a clean account/machine without pairing provisioning.
Do not erase the current profiles, revoke keys or remove the old owner first.
The public native installer remains a separate signed-release route.

## Acceptance

Automated tests build/expand private package fixtures, prove exact executable
bytes and absence of profile/key payloads, reject changed runtime/profile and
linked/missing states, and verify that no destructive kickstart is generated.
Windows tests cover missing/unready identity rejection before installation.
Actual saved-identity readiness and two direct TLS handshakes can be checked
without sending application role headers, desktop pixels, input or clipboard.
Those probes do not prove that pixels/rendering or user interaction passed;
the real installed connection remains a final user acceptance test.

## Artifact provenance and acceptance

Keep separate records for the packaging-source commit, installer SHA-256, embedded
Viewer/agent SHA-256 and, on Mac, the service-configuration binding. A personal
package may reuse a stable installed executable. Do not label that executable as
rebuilt from the packaging commit unless source/build provenance independently
proves it. Package version, source revision and runtime identity are different facts.

Before delivery, verify the actual archive inventory and runtime hashes, run the
Windows `--check-package` / `--check-existing-pair` modes and the Mac read-only
preinstall guard, and confirm installed state was not changed. A handshake-only
probe must retain the native peer/trust/revocation checks, send no role-admission
header or application bytes and avoid desktop/input/clipboard access.

Those checks establish package integrity and connection prerequisites, not an
installed session. The owner still verifies installation, Connect, keyboard/mouse
and close/reopen. Keep that result separate from automated tests. Do not remove
the previous working installation or publish a personal artifact as a generic
release while this acceptance is missing.
