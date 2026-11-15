# Product status

Updated 2026-11-15. LanPilot currently targets Windows-to-Mac LAN desktop access.
Other host/client directions are not implemented. This page is the current
documentation route; older dated reports describe their own source and runs.

The product direction is **one remembered desktop connection, with optional SSH
workspace access**. Visual and control TLS sockets are internal parts of the same
desktop session. See the [architecture decision](architecture.md) and
[engineering study guide](engineering-study-guide.zh-TW.md).

## What is present, and what is not yet accepted

| Area | In the source | Remaining acceptance |
| --- | --- | --- |
| Desktop | H.264, snapshot/RECT state transactions, persistent GPU framebuffer, independent visual/control TLS | Same-candidate two-host regression, mode-selection evidence, soak and physical latency comparison |
| Input | Keyboard/mouse, local cursor, focus/disconnect release; Mac native IME path | Current installed pair's manual click/drag/shortcut/IME matrix |
| Clipboard | Opt-in bidirectional text synchronization | Installed-pair manual validation; image/file clipboard is not provided |
| Windows app | Fixed GUI launcher, offline setup, remembered profile, background maintenance, recoverable updates, bounded reconnect | Current-pair installation/reinstall/update/rollback and close-without-residue acceptance |
| Mac app | Native application/setup, protected configuration, service ownership, shutdown/update recovery, native Installer packaging | Actual canonical service migration, consent and update continuity; no claim that source-only tests prove these |
| Identity | Native keys, explicit pairing protocol/UI, durable recovery, signed status and credential renewal | Full clean-account pairing and long-lived recovery through the actual installed products |
| Distribution | Allowlisted source export; Windows setup and Mac native/personal package builders | Platform CI, matched deliverables, operational acceptance; signed public distribution remains separate |
| Workspace/Agent | Existing independent SSH access; workspace/build/artifact modules | An integrated scoped Agent product; SSH authentication alone does not establish tool authorization |

The [personal installers](personal-installers.md) are for an **existing paired
Windows/Mac installation**. They do not provision a new user's identity, eliminate
native OS permission prompts, or constitute a signed public release. This
personal route does not require buying an Apple membership before testing; it
also does not disable trust, Keychain, TCC or publisher checks in other routes.

## Candidate evidence

The 2026-11-15 clean export contains 411 source/resource files. Its Windows GNU
Release build completed all 182 build actions; CTest passed 24/24 in 46.61 seconds.
The source-export workflow passed deterministic hashes, known-private-marker
rejection, dependency checks and linked-path rejection. Mac installer presentation
generation was reproduced as failing in the old export and passing with the two
HTML resources included. The architecture SVG was rendered and visually checked.

Those results belong to the exported candidate used for public source convergence,
not every historical release. GitHub CI must validate the actual public commit
on Windows/MSVC and macOS. Native macOS package execution, installed desktop
behavior, input, clipboard and soak were **not tested in this run**. The portable
presentation check is not a substitute for the macOS installer workflow.

The public candidate is a review branch, not a release tag. See
[release convergence](release-convergence.md) for the remaining gates. Do not
reuse historical screenshot timings as current benchmark results.

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
