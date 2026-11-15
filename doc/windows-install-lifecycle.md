# Windows installation ownership and removal

Status: source/isolated-workflow validation plus actual-user read-only preflight.
The currently installed bootstrap has NOT been replaced by this milestone.
Do not confuse a source fix with a deployed bootstrap upgrade.

## One installation owner

Install, update, startup inspection and removal acquire a named Windows mutex
derived from the current user's SID and canonical program-root SHA-256. State
directory selection cannot bypass this owner. The global namespace covers
sessions; process-local ownership additionally rejects same-thread re-entry
instead of accepting the mutex's normal recursive acquisition. This object is
synchronization, not an authentication or publisher-trust boundary.

The existing exclusive maintenance file lock is retained for compatibility and
physical-handle/MSIX-redirection checks. Runtime leases still prevent replacement
or removal while the connection screen/maintenance owns the active payload.
Busy operations fail before touching registration bindings or program files;
no unrelated process is killed and no lock file is deleted to force progress.

All installer configuration, shortcut, Apps registration and maintenance-task
writes run inside the activation callback while installation ownership is held.
An identical package still reconciles bindings without rewriting program bytes.

## Removal transaction

The public uninstaller accepts only the canonical per-user program root. Before
deactivation, it snapshots and validates this installation's shortcut, exact
maintenance-task action and Apps registration under the same owner/lease.
Another installation's similarly named binding is rejected.

The engine validates all resolved source/retirement paths, rejects reparse points
and bounds directory traversal. It records a bounded, strict local removal
journal and atomically retires the program directory beneath product maintenance
state. Only then are the validated OS bindings removed. A synchronous failure
restores programs before invoking the binding-restoration callback. Successful
removal archives the old runtime transaction so a verified reinstall can retain
the paired state without inheriting an invalid active-program journal.

If a remover is terminated before commit, the next verified installer recovers
the program directory and runtime journal before inspecting/updating the payload.
That installer also reconciles bindings; an interrupted uninstaller does not
claim it can recreate arbitrary OS state merely by reading JSON. Local journal
paths are validated data, never commands or permissions to move other folders.

Default removal preserves identity/settings. Explicit configuration removal
closes its state-directory file handles while retaining kernel installation
ownership, then removes only the validated product state root. It never invokes
native certificate/key-store deletion or removes SSH keys. Failure to reclaim
retired programs is reported as cleanup pending rather than claiming reclaimed
storage. Backup-retention policy and interrupted OS-registration acceptance are
still broader release gates.

## Evidence

The workflow regression first reproduced a second updater entering the SAME
program root through another state directory while the first owner was held.
It then passed with installation-scoped ownership. The expanded existing
PowerShell workflow covers:

- Same-thread and cross-process competing operations, including state-file lock
  release while kernel ownership remains held.
- Busy updater/runtime lease rejects removal before deactivation.
- Read-only removal preparation invokes no deletion callbacks.
- Binding-removal failure restores programs, fixture bindings and profile hashes.
- Invalid retirement paths fail closed without moving user directories.
- Default uninstall preserves opaque identity/profile hashes; verified reinstall
  succeeds and startup validates the new runtime.
- Explicit fixture-state removal succeeds without deleting outside the fixture.
- A real fixture remover is killed after retirement; the next verified installer
  restores the known programs and records rollback before comparing the package.

An actual Windows Interactive/Limited one-time task ran only
`Uninstall-DesktopPreview.ps1 -CheckOnly`: preflight passed as a non-administrator,
with the installed Viewer/profile/shortcut hashes unchanged. Its temporary task
was removed after completion. This is not actual-user uninstall acceptance. No
installed keys, trust, input, clipboard, Mac service or permissions were changed.

To inspect the actual product without removing it, from a normal user context:

```powershell
& .\bin\Uninstall-DesktopPreview.ps1 -CheckOnly
```

When launched inside a packaged developer host, physical AppData checks may
reject redirected storage. Never disable the guard or create another config
there to hide the error.

The new module/uninstaller must ship together in a verified package. The fixed
installed bootstrap deliberately retains its original integrity inventory, so
this milestone does NOT silently rewrite that bootstrap. Authenticated bootstrap
upgrades, signed update manifests and clean-account acceptance remain required
before unattended updates are declared complete.

Microsoft documents the namespace/privilege distinction for named kernel
objects: [Kernel object namespaces](https://learn.microsoft.com/windows/win32/termserv/kernel-object-namespaces).
