# Product status

LanPilot is a development project for Windows-to-Mac desktop access on a LAN.
Other host/client directions are not implemented. The supported release target
is one application per computer, one remembered connection and updates which
preserve protected identity and settings. That target has not passed acceptance.

| Area | Implemented | Still required before a production release |
| --- | --- | --- |
| Visual/control | H.264, exact snapshots/rectangles, separate TLS visual/control sockets; SSH agent access | Two-host final regression and documented mode selection |
| Windows product | Fixed native launcher, remembered settings, windowless maintenance and recoverable local program transactions | Authenticated bootstrap/runtime update and clean-user acceptance |
| Mac product | Canonical application, explicit native consent UI, protected configuration, login ownership and shutdown receipts | Developer ID signing/notarization, actual service migration and permission continuity |
| Identity | Protected native keys, native association, write-ahead recovery, signed durable two-end completion and native remembered-configuration handoff | First-run transport/UI, recovery integration and certificate renewal |
| Updates | Shared release verification plus bounded staging/recovery primitives | Pinned production release key, real activation/health/rollback integration |
| Distribution | Source selection excludes local history/builds and writes a hash inventory | Reproducible clean builds and signed, accepted installation packages |

Automating setup does not silently grant macOS Screen Recording or Accessibility.
The foreground application must guide native consent. View-only connections
must not acquire control or clipboard permission implicitly. Existing keys and
settings must survive updates; no developer identity/profile is shipped to users.

Acceptance includes clean Windows/Mac accounts, first pairing, remembered second
launch, restart/login, two consecutive signed upgrades, interrupted-update
recovery, sleep/offline return, device-certificate lifecycle and safe removal of
legacy programs only after the canonical installation works. Unit tests and a
source inventory do not prove those operational requirements.

## Buildable source, not local deployment state

Use a native C++23 compiler and CMake on each platform. Presets use the compiler
from the configured environment; no developer-specific compiler path is required.

The publication helper creates a new source-only directory under project out/.
It excludes Git history, local build/install trees, personal profiles and key
files. Its explicit script/resource catalog must include all CMake test/package
dependencies. It validates content before writing and creates source-manifest.json
last, containing relative paths, byte sizes and SHA-256 hashes. The inventory
provides integrity and reproducibility, **not publisher authentication**.

Research history and machine-specific diagnostics remain local. Development
source is not a signed installer, and the v0.1/v0.2/v0.3 evolution is not proof
that three accepted release packages exist. See [release readiness](release-readiness.md)
and the [public build guide](public-guide.md).
