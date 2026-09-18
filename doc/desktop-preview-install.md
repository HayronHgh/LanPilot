# LanPilot Desktop Local Installation

LanPilot retains `RemoteWorkspaceNode` installation directories and `rwn-*` binary
names for compatibility with existing SSH commands and macOS permission grants.

Release packaging gates are tracked in [public-releases.md](public-releases.md).
The current source launcher explicitly selects `--encoder low-latency`; use
`Start-DesktopPreview.ps1 -EncoderMode baseline` only for regression comparison.
Install the matching Viewer and launcher together; older installed copies do not
automatically inherit this setting.

The Windows repository remains the source of truth. The Mac receives a built, immutable
desktop-agent executable at a fixed per-user path. Build mirrors and SSH keys are never part of
the installed product.

## Startup model

The RWV2 desktop agent is an SSH stdio program: its stdout is the authenticated binary visual
stream and its stdin is the RWC1 control stream. A detached LaunchAgent cannot own those streams,
so running the agent permanently at login would not make it reachable and can create an empty
restart loop. The supported local-preview model is:

```text
macOS boot -> system Remote Login/sshd ready
Windows shortcut -> authenticated SSH session
SSH session -> fixed installed rwn-desktop-agent
Viewer closes -> session-scoped agent exits
```

Enable **System Settings > General > Sharing > Remote Login** for the authorized account. That
system service starts at boot. Screen Recording and Accessibility remain user-consent grants for
the installed desktop-agent identity; no installer edits the TCC database.

## Mac install

After the Release build, run as the logged-in desktop user, never root:

```sh
./bin/install-desktop-preview.sh \
  /absolute/build/desktop-agent/rwn-desktop-agent
```

The fixed remote executable becomes:

```text
/Users/<user>/.local/libexec/remoteworkspacenode/rwn-desktop-agent
```

The installed path intentionally contains no whitespace or shell metacharacters. The Viewer
passes the absolute agent path as a fail-closed SSH command token rather than invoking a remote
shell parser or relaxing token validation.

## Windows install

The desktop shortcut now opens a connection screen before starting the stream. Enter the Mac
address, account, existing SSH key file and installed agent path, then choose **View only** or
**Control keyboard and mouse** and press **Connect to Mac**. Settings can be remembered locally;
the key itself is never copied. Existing profiles are prefilled.
New profiles default to view-only. Invalid fields remain on the form with an actionable message.

A fresh package can be installed with `Install-DesktopPreview.ps1` without parameters, then
configured through that screen. Provision SSH access, a trusted host key and the Mac agent/TCC
permissions first. The Viewer uses BatchMode, IdentitiesOnly and StrictHostKeyChecking; it cannot
silently accept an unknown/changed host identity or prompt for a password.

The stream window resizes from its four corners while keeping the remote image aspect ratio
(16:9 for the current 1080p Mac). Side edges do not stretch it. Maximize/Snap remain available;
Fit preserves image proportions with letterboxing where necessary. Initial size fits inside the
Windows work area, and idle content is repainted on resize. Interactive escape:
**Ctrl+Alt+Shift+F12** closes the Viewer and releases remote input.

For scripted use, `Start-DesktopPreview.ps1 -ConnectImmediately` bypasses the settings form.
The desktop shortcut uses the form by default and does not show a console window.

From an extracted Windows Release install tree:

```powershell
.\bin\Install-DesktopPreview.ps1 `
  -HostName 'user@mac-host' `
  -SshKey 'C:\absolute\id_ed25519'
```

The installer copies only the Viewer and launcher scripts to
`%LOCALAPPDATA%\Programs\RemoteWorkspaceNode`, writes a local path-only configuration under
`%LOCALAPPDATA%\RemoteWorkspaceNode`, and creates a **Remote Workspace** desktop shortcut. It does
not copy, embed, or modify the SSH key. The safe default remains `h264`; Snapshot and RAW_RECT must
not become installation defaults until their runtime promotion gates pass.
