# LanPilot desktop package

This package is under acceptance testing. A local staging directory is not a
signed production release or proof that a fresh machine can pair.
The source includes dual-confirmed native pairing and credential renewal. These
must not be confused with the capabilities of an older installed package.
See `doc/install-once-release-acceptance.md` in the corresponding source archive
for the remaining delivery gates.

The `desktop` component contains exactly one platform installer, this README and
LICENSE. Runtime scripts are embedded in the Windows installer, not additional
end-user launchers. Maintainer CLI tools are staged only when explicitly selecting
`desktop-compat`. Do not merge these two packages into one download.

## Windows

Double-click **LanPilot-Setup.exe** to install or update for your Windows account.
The offline setup embeds its complete payload, shows progress and a retryable
result, and does not open a console or start a connection automatically. Choose
**Open LanPilot** after success. Close an active connection before updating.
The package version appears in Windows Apps. Settings and device keys are retained.
Local test builds are unsigned; release publisher signing remains required.

In the separate `desktop-compat` bundle only, the maintainer script entry is:

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\bin\Install-DesktopPreview.ps1
~~~

The installer uses the current user's account; it does not request administrator
rights, install a root CA, create device keys or grant remote control.

- Desktop entry: **LanPilot** (one shortcut).
- Programs: LocalAppData\Programs\LanPilot.
- Saved connection: LocalAppData\LanPilot\connections\default.json.
- Settings, public trust metadata, logs and maintenance state:
  LocalAppData\LanPilot.
- Device private keys stay in the native protected store.

Open LanPilot, confirm the saved computer and choose Connect. Keyboard/mouse
control and optional text clipboard synchronization require explicit consent.
Updates preserve the saved visual/control mode, including Exact-only. H.264
remains available; new profiles currently start in H.264. Fit preserves the source aspect ratio and
centers the picture with black bars. Emergency escape: Ctrl+Alt+Shift+F12.

**Fresh-machine acceptance remains open.** The current source connection UI can
start native two-end pairing: open the verified LanPilot app on the Mac, choose
pairing, enter its IP on Windows, compare both sides and approve locally. Device
keys and public trust metadata are then managed internally; consumers should not
enter certificate hashes or DER paths. This requires the canonical signed Mac
application and its native setup. The source workflow passing tests is not proof
that an unsigned staging build or an old installed launcher supports this flow.
Installing the program alone does not establish trust. Never disable certificate,
revocation or peer checks or replace an existing identity to pass a setup error.

SSH is an explicit compatibility option (-Transport ssh during installation).
It requires OpenSSH Client, an existing user key and a verified Mac host key.
Never ship a private key or disable host-key verification.

## Program updates

Close the connection screen and Viewer, then run the installer from a verified
new package. Existing paired identity and settings are retained by default.
An identical package does not rewrite program files.

The fixed LanPilot.exe and bootstrap directory remain in place. Updates swap
only the runtime directory, with a serialized journal and previous-program
backup under persistent maintenance state. If an updater is interrupted, the
next ordinary launch validates and restores the previous runtime before opening
the connection screen. The same fixed entry starts windowless maintenance.

Integrity hashes detect incomplete/corrupt local transactions. They are not a
publisher signature. Automatic download/install, authenticated bootstrap updates
and rollback-retention policy are not implemented; verify the package source.
Do not edit installed program files: startup fails closed on integrity mismatch.

Windows Apps registration uses one LanPilot entry. Uninstall retains pairing
and settings unless configuration removal is explicitly requested. Native
private keys and SSH keys are not silently deleted. Keep a verified installer
available until actual installed-upgrade acceptance is complete.

## Mac native application candidate

The consumer first-install entry is a native macOS `.pkg`, staged separately:

~~~sh
cmake --build <verified-build> --target lanpilot-macos-installer
cmake --install <verified-build> --component desktop --prefix <staging-directory>
~~~

The default output is explicitly **LanPilot-macOS-UNSIGNED.pkg** for validation.
It is not ready for production activation. The package installs only the app in
the current user's Applications folder and rejects existing canonical installs;
it does not start services, change trust or request permissions. Signed updates
remain in the installed app. See `doc/macos-native-installer.md` in the source.

The app bundle itself can be staged separately for publisher verification:

~~~sh
cmake --install <verified-build> --component macos-app --prefix <staging-directory>
~~~

This produces LanPilot.app for release validation. It is not an installation or
authorization command. The supported installed application belongs at
~/Applications/LanPilot.app, with state in ~/Library/Application Support/LanPilot
and private device keys in the native Keychain. Configure and verify the intended
Developer ID publisher and pinned release-verification key before distributing
or activating it. The app's first-use UI owns pairing, permissions and login
service setup; an end user must not provision certificates in Terminal.

The native app's install, update and service workflow still needs fresh-account,
signed consecutive-update and reboot acceptance. Do not replace a working legacy
agent or erase its identities merely because a staged bundle passes unit tests.

## Explicit Mac CLI compatibility package

The `desktop-compat` component on Mac is the legacy CLI compatibility package:

~~~sh
sh ./bin/install-desktop-preview.sh "$PWD/bin/rwn-desktop-agent"
~~~

It installs ~/.local/libexec/remoteworkspacenode/rwn-desktop-agent for the
explicit SSH compatibility route. It does not install/configure the dedicated
TLS service or create a production LanPilot.app.

Enable Remote Login only for the intended Mac account when using SSH. Screen
Recording requires native macOS approval; keyboard/mouse control also requires
Accessibility. Keep the Mac logged into its desktop. No FileVault, lock-screen,
sleep, TCC or Keychain protections are bypassed.

Production Mac packaging with a stable Developer ID signature and notarized
updates is still a release gate. Rebuilding the current ad-hoc agent may require
new OS authorization; the installer cannot promise otherwise.

## Troubleshooting

- No saved pairing: program installation is complete only as a program; first
  pairing/enrollment must be provided before a new user can connect.
- Certificate/revocation failure: inspect local maintenance status; never disable
  validation or replace an existing identity merely to hide the error.
- Black screen: check Mac login state and Screen Recording permission for the
  actual installed execution context.
- View works, input does not: check Control mode and Accessibility consent.
- Interrupted update: open the normal LanPilot shortcut; no repair shortcut is
  required for a valid recoverable runtime transaction.
- Integrity failure: preserve state and use a verified package; arbitrary
  replacement scripts are not a recovery method.

Project: https://github.com/HayronHgh/LanPilot
