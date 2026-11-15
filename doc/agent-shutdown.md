# Agent shutdown and input ownership

## Scope

The shutdown primitives are a prerequisite for in-place program replacement.
They do not install a service or make a PID disappearing an input-release proof.
The existing development working tree also wires them into SSH visual/control
I/O and TLS admission/session cancellation. That integration is still separate
from the native updater's production `ProgramServiceHooks` acceptance.

`ProcessShutdown` is scoped to a streaming endpoint, not onboarding, signing or
native consent commands. SIGTERM/SIGINT only store a lock-free flag, preserving
errno. A normal observer thread samples it every 5 ms and requests cancellation.
Only normal threads cancel sockets; only the original input owner releases
tracked keys/buttons. Scoped SIGPIPE handling turns closed SSH output into an
I/O failure. Previous handlers are restored when the endpoint returns.

`InputReceiver::close()` is terminal: it closes the gate before invoking any
release and rejects all later input and epoch changes. This is not a reusable
`RELEASE_ALL_INPUT` epoch. It attempts every tracked release even if one backend
call throws. Successful releases are removed; failures remain for bounded retry.
The stream integration retries once and reports a nonzero result if any remain.
No key codes, text or clipboard content enter the drain diagnostic.

The receipt means backend release calls returned successfully. It does not prove
that another application consumed a CGEvent, that an OS permission stayed valid,
or that a physical input state has been observed. Native service quiescence must
combine a verified, instance-bound drain receipt with process/runtime-lease
cessation. The canonical service now has an [instance-bound receipt and native
stop adapter](mac-service-quiescence.md); full program-update restart/rollback
hooks and positive native acceptance remain unfinished.

## Cancellation and I/O

The project's existing `CancellationToken`/`CancellationSource` API is preserved
and moved from build.hpp to cancellation.hpp. A bounded registration supports
eight callbacks per source. Registration after stop runs once immediately;
destruction synchronizes with an in-progress callback. Reentrant/already-stopped
requests return without waiting on the callback lock. Callbacks must be bounded,
noexcept and must not join a thread which is unregistering on that source.
This avoids requiring the unavailable std::stop_token/std::jthread on the
current Apple library. No experimental standard-library flags are enabled.

The SSH input owner uses readiness polling rather than closing another thread's
descriptor. An idle read, partial header/payload and blocked output can stop
without unrelated future traffic. Ready data is processed immediately; 10 ms is
the idle cancellation polling interval, not an input/video pacing timer. The
visual writer preserves bytes and restores mutable descriptor status flags.
Darwin's internal FWASWRITTEN bit may change simply because data was written;
the test checks public mutable flags and descriptor flags instead of mistaking
this kernel marker for leaked O_NONBLOCK state. See Apple's
[fcntl definitions](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/fcntl.h).

The working-tree TLS integration carries cancellation through idle acceptance,
handshake, second-channel admission, established I/O and session expiry. Native
channel cancellation completes local waiters without depending on a future
Network.framework callback. Session cancellation closes the input acceptance
gate even when a complete old control message is already buffered. Failed
constructor setup does not leave redirected global stream buffers or a joinable
expiry thread. Per-worker cleanup covers exceptions during stream setup/drain.
Positive authenticated TLS cancellation is not yet a measured runtime result.

## Evidence and remaining gates

The workflow uses a fake InputBackend only: no OS input, capture, clipboard,
Keychain access, service registration or installed-process termination.

- Terminal gate, late keys/buttons/pointer/wheel/text and newer input epochs.
- Release failure continues other releases, bounded retry, persistent failure.
- Unregistered/late/bounded callbacks, 100 simultaneous cross-source races,
  callback destruction during cancellation and safe self-unregistration.
- On macOS, 60 actual fixture-child SIGTERM/SIGINT/closed-output/unwind cases:
  idle input, partial input, blocked visual output and a busy mock injection.
- 2 MiB native pipe round trip: byte equality and SHA-256 equality, no added
  diagnostics, and restored mutable/descriptor flags.

On 2026-10-25, the working-tree Windows full build/CTest passed 11/11 (31.60 s)
and Mac full build/CTest passed 12/12 (3.76 s). A separate run of the native
workflow reported 60 child cases, maximum stop-to-exit 13.8113 ms and 2,097,152
matching bytes. Fourteen synchronized source hashes matched the test mirror.
The Windows sandbox initially denied fixture file renames; the same full suite
passed outside that filesystem restriction. No source workaround was added for
the sandbox. Existing Mac SDK deprecation/linker warnings remain unrelated.

These tests do not establish native updater handoff, actual CGEvent release,
authenticated TLS stop/reconnect or an unchanged live 1080p60 baseline. Those
remain acceptance gates before deployment or duplicate-install cleanup. Existing
legacy executables do not acquire this behavior until a verified update.
