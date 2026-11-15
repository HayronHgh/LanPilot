# macOS native first-install package

The consumer entry is one macOS Installer package. Its payload is exclusively
`Applications/LanPilot.app`, installed into the current user's home domain.
The system and arbitrary-volume domains are disabled. Consumers do not run
Terminal, provision TLS certificates, select DER files or execute an authorization
script. macOS Installer owns the installation UI; there is no additional helper
application on the desktop.

This is a **first-install** package. Its internal read-only guard rejects root,
linked/unsafe destinations and an existing canonical LanPilot.app. It does not
overwrite a running application or replace the existing transactional updater.
An installed application continues to use its signed, pinned-key update flow.
There is no postinstall script, service launch, key generation, trust change,
permission request or automatic connection. Existing legacy services and stored
connections are not removed or migrated by package installation.

The current source still needs signed installed first-use acceptance. Native
pairing, privacy permissions and login-service setup belong to the installed app.
A package build does not prove those steps work on a new user account.

## Maintainer build

Use the verified universal2 macOS build with deployment target 13.0:

```sh
cmake --build <build> --target lanpilot-macos-installer
cmake --install <build> --component macos-installer --prefix <stage>
```

This deliberately produces `LanPilot-macOS-UNSIGNED.pkg`, with an explicit
development notice. It is a package-validation artifact, not an activatable
production release. The app's publisher/TCC/Keychain/service gates are unchanged.
Do not disable Gatekeeper or substitute an ad-hoc signer to make it appear ready.
The existing `macos-app` staging component remains available; the old `desktop`
component is CLI compatibility, not the consumer installer.

The maintainer-only Python builder has a separate release mode. It requires an
already signed, Gatekeeper-assessed universal2 app, the expected publisher team,
release-key configuration and an existing Developer ID Installer identity.
It verifies the app publisher and signs the package; it never creates signing
identities or changes trust. Package notarization/stapling and assessment of the
exact final package remain separate release gates. Supplying command-line build
configuration does not attest that a different app was compiled with those values.

## Automated verification

`lanpilot-macos-installer-workflow` builds and expands an isolated native package.
It compares every payload file with the intended app, checks home-only domains,
minimum OS, the fixed component path and absence of postinstall/extra payloads.
It rejects output replacement and a release request without signing inputs.
Read-only layout fixtures cover fresh/existing/linked/writable/regular targets.
No package is installed and no app, listener, input or clipboard is activated.

Actual Installer execution under a fresh user, interruptions, signed updates,
post-install Finder launch, OS permissions and paired streaming are **not** proven
by package expansion. Keep the current working installation until that acceptance.

Apple's [Distribution XML reference](https://developer.apple.com/library/archive/documentation/DeveloperTools/Reference/DistributionDefinitionRef/Chapters/Distribution_XML_Ref.html)
defines the current-user home domain and its authorization behavior. The package
configuration follows that contract; installed-user verification remains required.

## One final human batch

Do not ask the user to repeat development Terminal/Keychain commands. Once the
publisher prerequisites and assessed artifact are ready, consolidate operations:

1. Install the final verified package and open the installed LanPilot app.
2. Complete the app's foreground pairing and native macOS privacy/login approvals.
3. Connect from the Windows installed app and perform manual input/clipboard and
   close/reopen tests.

Developer ID is currently unavailable. That is a known release prerequisite,
not a reason to rebuild TLS keys, weaken publisher checks or request repeated
permission work now. The unsigned validation package must not be represented as
meeting the two-installers-and-connect acceptance goal.
