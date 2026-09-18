# LanPilot

LanPilot lets a Windows computer view and control a Mac desktop over a local network. The current implementation uses C++23 and CMake, ScreenCaptureKit on macOS, and a D3D11 viewer on Windows. Other host/client combinations are not implemented yet.

The Windows viewer keeps the remote image centered and proportional when its window is resized or maximized. Unused space appears as black bars. `Ctrl+F` selects Fit; `Ctrl+1` selects 1:1 pixels when the window is large enough.

## Version lines

| Line | Visual and control transport | Status |
| --- | --- | --- |
| v0.1 | Hardware H.264 over SSH | Historical baseline |
| v0.2 | Exact snapshots and custom rectangle updates over SSH, with H.264 available | Development line |
| v0.3 | Exact updates over separate TLS visual and control sockets; agent access stays on SSH | Current development line |

These lines describe the project's evolution. They are not downloadable release tags. A signed installer, first-time pairing flow, and final two-host acceptance are still in progress. See [release readiness](doc/release-readiness.md).

## Build and verify

Use CMake 3.25 or newer, a C++23 compiler, and the native SDK for the target operating system. Build each platform on its own machine:

```sh
cmake -S . -B build/dev
cmake --build build/dev --config Release
ctest --test-dir build/dev -C Release --output-on-failure
```

The Windows GPU probes also exercise snapshot transactions and resizing without a live Mac connection. These checks do not replace manual validation of display timing, keyboard and mouse input, or operating-system permissions.

## Set up the SSH preview

These instructions cover the v0.1/v0.2 SSH preview, not automatic v0.3 TLS pairing.

On the Mac, enable **Remote Login** for the intended account. From an unpacked Mac package, install the desktop agent:

```sh
sh ./bin/install-desktop-preview.sh "$PWD/bin/rwn-desktop-agent"
```

macOS must grant Screen Recording to show the desktop, and Accessibility to allow keyboard and mouse control. The agent runs after the Mac user signs in; it does not bypass FileVault or the login screen.

On Windows, install OpenSSH Client and authorize your own SSH key on the Mac. Verify the host key when connecting for the first time. From an unpacked Windows package:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\bin\Install-DesktopPreview.ps1
```

Open the **Remote Workspace** desktop shortcut and enter the Mac address, account, SSH key location, and agent path. Choose view-only or explicit keyboard and mouse control. See the [installation guide](doc/desktop-preview-install.md) for details. The SSH key is private and must not be included in a package.

## Architecture

```text
Mac ScreenCaptureKit → VideoToolbox H.264 or exact BGRA updates
                     → visual transport → Windows D3D11 compositor
Windows keyboard/mouse → control transport → Mac native input events
Agent access            → separate SSH channel
```

Exact updates use a persistent framebuffer, ordered generations, and commit acknowledgements. An acknowledgement confirms that the canonical framebuffer was committed; it does not measure when a monitor scanned out the pixels. H.264 remains available for motion and recovery.

## License and contributions

Personal, non-commercial use is free. Commercial use, including company work and freelance services, requires prior written permission from HayronHgh. See [LICENSE](LICENSE). This is source-available software, not an unrestricted open-source license.

See [CONTRIBUTING.md](CONTRIBUTING.md) for build and commit conventions.
