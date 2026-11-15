# Remembered TLS connection recovery

Normal Windows TLS viewing now retains the same window across a temporary
transport interruption. Each retry creates a new ViewerState, native TLS sockets,
admission/session identity, decoder, D3D framebuffer, cursor cache, input epoch,
control sequences and clipboard pump. It repeats native credential refresh when
the saved profile requires it; original bootstrap anchors are not overwritten.
The Mac's existing 30-minute session expiry remains unchanged.

## Retry boundaries

Only typed TCP closure, timeout or explicitly classified temporary Winsock network
errors can request a new session. TLS integrity, certificate/pin/revocation,
admission, protocol parsing, framebuffer and rendering errors cannot request
automatic retry. Sibling-worker cancellation is not a new connection failure.
An error observed while old workers drain prevents a pending retry as well.

Retries use 1,2,4,8,8,8-second backoff, at most six attempts in a 60-second
scheduling window. Each native connection attempt retains its own bounded I/O
deadline; that time is additional to a scheduled backoff. A session that remained
authenticated for 30 seconds resets the budget. Rapidly flapping sessions do not.
An exhausted budget preserves the saved pairing and asks the user to retry from
LanPilot after checking the Mac and LAN; it never resets identity or trust.

The original window remains in place, shows a reconnecting title during backoff,
does not reactivate itself on reconnection, and can be closed to cancel backoff.
Credential refresh,native TLS establishment and channel admission run on an owned
worker while the UI continues processing messages. Closing the window cancels that
worker and joins it before retiring the session. Input is disabled before admission,
including sequence allocation. A fully verified result is published only while the
window and initialization are still valid;cancellation destroys late results.

DNS uses the documented asynchronous GetAddrInfoExW completion event and cancellation
handle. The event is drained before its storage is released. Pending TCP connect and
native TCP waits observe cancellation without restarting their original deadlines;
TLS handshake/admission cancellation shuts down both partially established sockets.
The native probe exposed a2second wait when shutdown alone did not wake select on
this Windows host;explicit cancellation observation corrects that behavior.
Windows native key/store operations complete at their atomic boundaries;LanPilot
does not terminate threads or abandon operations. Cancellation does not undo an
already completed protected credential-cache transaction.

API references:[GetAddrInfoExW](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfoexw),
[GetAddrInfoExCancel](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfoexcancel).

## Input and clipboard

Old workers finish and their TLS streams are cancelled before their state is
destroyed. Existing ordered release-on-close and Mac EOF/session teardown remain
responsible for releasing remote held keys/buttons. No previous control messages,
pointer state, framebuffer transaction or clipboard message is carried forward.
Old per-window queued key/mouse events are discarded, and worker restart
notifications carry an instance identifier so an obsolete session cannot restart
a newer one.

After automatic reconnection, interactive viewing is paused until a new left click
inside the viewer explicitly resumes control. That first click and its release
are consumed locally. Keyboard interception is inactive while control is paused
or the connection failed. Text clipboard synchronization is disabled on a new
automatic session; it requires re-enabling from that connection's menu. View-only
connections remain view-only.

## Verification scope

The workflow unit covers retry budgets, stable versus flapping sessions, and
network-error versus access-denial classification. The Windows hidden reconnect
workflow exercises the real Viewer window procedure and backoff wait, old-state
retirement, fresh state, stale restart messages, fatal-error precedence and closing
the window during backoff. It displays no UI and sends no input or network data.

Native TLS establishment and the remembered credential tests remain separate
tests. The hidden workflow does not prove an installed Windows-to-Mac reconnect,
30 minutes of live viewing, remote release under injected physical input, or
fresh-account install/reboot/signed upgrades. Those require the installed
end-to-end acceptance run before release or retirement of the legacy installation.
Trace and bounded --probe-seconds sessions retain single-session semantics so
their create-new trace paths and failure receipts are not silently reused.

The separate hidden startup workflow exercises success and preserved trust errors,
failure during initialization,real native asynchronous numeric-address resolution,
a temporary127.0.0.1 listener/TCP read,closing during that read,and joining before
disposing a deliberately late result. It verifies that pre-authentication input
does not advance sequence counters. It opens no public listener,uses no identity,
shows no UI and injects no input. This is stronger cancellation evidence than a
sleep-only simulation,but it is not an installed Mac TLS-handshake/reboot test.
