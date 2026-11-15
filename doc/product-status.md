# Product status

Updated 2026-11-15. LanPilot currently targets Windows-to-Mac LAN desktop access.
Other host/client directions are not implemented. This page is the current
documentation route; older dated reports describe their own source and runs.

The product direction is **one remembered desktop connection, with optional SSH
workspace access**. Visual and control TLS sockets are internal parts of the same
desktop session. See the [architecture decision](architecture.md) and
[engineering study guide](engineering-study-guide.zh-TW.md).

The latest architecture is the main development line. The owner reports stable
use on the existing pair; retain its selected Exact-only/interactive settings.
H.264 remains available, and legacy SSH stays an explicit compatibility route.
The previous public source is preserved in
[`legacy/pre-convergence-20261115`](https://github.com/HayronHgh/LanPilot/tree/legacy/pre-convergence-20261115).
Source promotion does not silently redeploy either installed application.

## What is present, and what is not yet accepted

| Area | In the source | Remaining acceptance |
| --- | --- | --- |
| Desktop | H.264, snapshot/RECT state transactions, persistent GPU framebuffer, independent visual/control TLS | Same-candidate two-host regression, mode-selection evidence, soak and physical latency comparison |
| Input | Keyboard/mouse, local cursor, focus/disconnect release; Mac native IME path | Current installed pair's manual click/drag/shortcut/IME matrix |
| Clipboard | Opt-in bidirectional text synchronization | Installed-pair manual validation; image/file clipboard is not provided |
| Windows app | Fixed GUI launcher, offline setup, remembered profile, background maintenance, recoverable updates, bounded reconnect | Current-pair installation/reinstall/update/rollback and close-without-residue acceptance |
| Mac app | Native application/setup, protected configuration, service ownership, shutdown/update recovery, native Installer packaging | Actual canonical service migration, consent and update continuity; no claim that source-only tests prove these |
| Identity | Native keys, explicit pairing protocol/UI, durable recovery, signed status and credential renewal | Full clean-account pairing and long-lived recovery through the actual installed products |
| Distribution | Allowlisted source export; Windows setup and Mac native/personal package builders; both platform CI jobs pass | Matched deliverables and operational acceptance; signed public distribution remains separate |
| Workspace/Agent | Existing independent SSH access; workspace/build/artifact modules | An integrated scoped Agent product; SSH authentication alone does not establish tool authorization |

The [personal installers](personal-installers.md) are for an **existing paired
Windows/Mac installation**. They do not provision a new user's identity, eliminate
native OS permission prompts, or constitute a signed public release. This
personal route does not require buying an Apple membership before testing; it
also does not disable trust, Keychain, TCC or publisher checks in other routes.

## Candidate evidence

The 0.3.0 package source at `c1ce3e1800985d6dd639a1c349b0480ae00a01b6`
passed Windows/MSVC 25/25 and Mac universal2 26/26 tests, plus the platform TLS
checks, in [run 43670546922](https://github.com/HayronHgh/LanPilot/actions/runs/43670546922).
The local Windows GNU Release build also passed 25/25 tests. The clean export
contains 416 selected files with verified SHA-256 correspondence; private-marker,
linked-path and dependency checks passed.

The package workflow builds and stages the real platform installer, checks that
the product bundle contains only installer/README/LICENSE, and verifies that
explicit `desktop-compat` tools remain available. Mac CI built the actual native
`.pkg`; that unsigned package still does not bypass native activation policy.
Missing installer presentation resources and the SSH selected-settings-root
regression were reproduced and repaired in earlier commits. Cover and architecture
artwork were visually checked.

## Existing-pair package preflight

On 2026-11-15, private personal installers were built from the identified packaging
source while preserving the installed stable Viewer/agent bytes. Windows package,
existing-identity and bootstrap/runtime integrity checks passed. The Mac package
was expanded, its two-file payload and exact executable hash verified, and its
actual read-only preinstall guard passed. Five negative package guards passed in
isolated fixtures. No keys or connection profile were bundled.

Two real LAN TLS handshakes passed with the native certificate, peer-pin and
revocation checks. The probe sent no application bytes, admitted no desktop role,
read no desktop payload and sent no input. Installed profiles, agent bytes and
service configuration remained unchanged.

These private artifacts are for the existing pair, not public downloads. The
packaging commit identifies the installer implementation; it does **not** prove
that the frozen installed streaming executables were rebuilt from that commit.
See [artifact provenance](personal-installers.md#artifact-provenance-and-acceptance)
for the required separate records. Actual user installation, control and reopen
acceptance of these delivered artifacts remains pending.

These results belong to the identified source, not every historical release.
Live installed desktop behavior, input, clipboard and soak were **not retested in
this run**. The owner's prior stable-use report is separate from automated CI.
Promoting the latest source to `main` is separate from publishing an accepted
installer release. See [release convergence](release-convergence.md) for the
remaining package gates; do not reuse old screenshot timings as new benchmarks.

## Source and state ownership

Publish only the explicit `packaging/SourceExport.psm1` selection. Build and test
from that export before creating platform packages. The selection includes
runtime installer resources, not just C++ files and CMake inputs. No personal
profiles, private keys, build directories or private Git history are copied.
The generated SHA-256 inventory proves content integrity, not publisher identity.

Installed program files are replaceable; device identities and remembered
settings have different ownership and must survive an update. Remove a legacy
installation only after replacement and rollback have been verified. No cleanup
step may silently reset permissions or delete the user's paired devices.

For installation routes use the [documentation index](README.md); for production
gates use [install-once acceptance](install-once-release-acceptance.md). The
historical [version lines](public-releases.md) describe v0.1/v0.2/v0.3 evolution,
not three currently accepted downloadable installers.
