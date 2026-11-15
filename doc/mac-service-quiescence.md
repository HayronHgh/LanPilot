# Instance-bound Mac service shutdown

The canonical service records its input lifecycle before delegating to the agent.
Verification is connected to NativeLoginBackend::stop_canonical(), under the
already-owned lifecycle lease. This is one part of future program-update hooks;
it does not complete the production updater or prove a signed native handoff.

## Durable ordering

The fixed protected file service.runtime lives beside service.conf. Schema 1
is at most 1,024 bytes and contains:

| Field | Meaning |
| --- | --- |
| instance | Fresh 32-character identifier per service invocation |
| pid / process_start_us | Kernel process identity, including birth time |
| configuration_hash | Exact validated configuration used by this invocation |
| phase | preflight, pending, stopped_none, stopped_released, stop_failed |
| exit_code | Agent return status, independent from input-release success |
| released / remaining | Bounded counts; no key values or input content |

The producer holds runtime.lock throughout:

1. Save preflight before checks that cannot create an input owner.
2. Complete permission, identity and startup-capture checks.
3. Atomically save/fsync pending **before** invoking the agent.
4. Register the input owner before scheduling its worker. That worker closes
   the receiver and reports bounded release attempts.
5. After the agent returns and destroys workers/transports, freeze the audit
   and persist stopped_none, stopped_released or stop_failed.
6. Release runtime.lock on leaving the wrapper.

A frozen unknown audit cannot later become successful through unrelated progress.
Abandoned ownership is failed evidence. Shared audit state survives a caller
exiting early, preventing use-after-free and another invocation while pending.
No filesystem I/O occurs in the signal handler or per-input hot path. The record
contains no filesystem authority, commands, text, pixels or credentials.

The application's --desktop-agent compatibility flag is readiness-only. It
cannot start a second unmanaged application stream. Real application streams use
the configured service wrapper and its lease/record. The separate development
CLI remains available; it is not represented as a managed product service.
If capture/control permission is revoked after preflight, the managed invocation
reports failure without requesting native consent from the background. Only the
foreground setup UI guides that consent. Explicit standalone CLI requests retain
their existing behavior; workflow tests use a fake permission backend only.

Writes validate phase transitions, instance/PID/birth/configuration identity,
canonical integers, overflow, duplicate/unknown fields and bounded counts. The
existing protected-file reader rejects unsafe mode, links, ACL or wrong owner.
A crash after delegation leaves pending; startup cannot overwrite pending/failed
evidence with a fresh instance. A malformed record is not silently reset.

## Consumer proof

The adapter verifies the compiled publisher policy and fixed canonical bundle.
Its signed Info.plist must declare integer LanPilotServiceProtocol=1. For a
running service, Security.framework also checks dynamic code, publisher, secured
protocol declaration and exact installed executable path. A process name alone
does not satisfy this contract. The helper never reacquires owner.lock.

After unregistering the canonical service, all must hold:

- the original kernel process instance has exited;
- the launchd job is absent and runtime.lock is free;
- the final protected record matches the observed instance, PID, birth time and
  configuration, and proves no input was delegated or tracked input was released.

PID reuse neither makes an old receipt current nor waits for an unrelated new
process. Readiness requires an exact, readable kernel birth-time match; inability
to query it is not positive health proof. An absent runtime file is safe only
under the verified mandatory-record contract and when no previous runtime record
was observed: delegation could not have preceded its durable record. Deleting
an observed record, pending/failed evidence, changed identity, a live job or held
lease rejects quiescence. No missing-receipt SIGKILL fallback is added.

Startup readiness also binds instance and birth time. Capture/identity checks
remain local startup checks, not peer authentication, physical scan-out, another
application's consumption of a CGEvent, or an end-to-end remote-session proof.
The shutdown result means backend releases returned and the invocation completed.
It does not observe physical keyboard state. Legacy CLI/services do not gain
this receipt contract; initial migration needs separate session/input cessation
acceptance. No native authorization or trust checks are bypassed.

## Verification boundaries

The portable workflow covers audit lifetime, frozen/unfinished/abandoned owners,
release retries, every phase pair, new-instance transitions, stale identifiers,
PID/birth/configuration mismatch, independent stop fences and missing/crashed
records. The native fixture uses its own directory and child. That child holds
real owner/runtime leases; SIGKILL releases both while pending remains, and
quiescence must still be rejected. It checks kernel birth time, protected record
mode/corruption rejection and fixture cleanup. Signal/pipe tests use a fake input
backend. No real input, capture, clipboard, Keychain or service activation occurs.

Actual SMAppService handoff, positive signed process verification, authenticated
TLS stop/reconnect and the live desktop baseline remain **NOT RUN**. Developer ID
is unavailable. Retain the installed legacy agent/configuration until those gates
pass. Full ProgramServiceHooks restart/rollback, fresh-code health and ordinary
relaunch recovery are now integrated; see [program updates](mac-program-updates.md).
Their positive signed activation/rollback and peer-session acceptance remain unverified.

Measured on 2026-10-25 (isolated development builds, not installed activation):

| Check | Command | Exit / status | Evidence | Result |
| --- | --- | --- | --- | --- |
| Windows full build/tests | cmake --build; ctest | 0 | 11/11, 33.03 s | PASS |
| Mac full build/tests | cmake --build; ctest | 0 | 13/13, 2.70 s | PASS |
| Native storage/process fixture | --check-configuration-store | 0 | step 14, cleaned=1 | PASS |
| Native signal/pipe workflow | lanpilot_agent_shutdown_workflow | 0 | 60 child cases, max 13.7477 ms; 2 MiB byte/hash equality | PASS |
| Signed installed handoff | No activation performed | Not run | Developer ID unavailable; installed hashes unchanged | NOT RUN |
