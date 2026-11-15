# Native first-use pairing integration

The existing Windows Viewer now owns a foreground `--pair <private-IPv4>`
entry point. The connection form starts it when there is no usable saved
connection, then reloads the canonical profile after successful completion.
There is no additional executable, certificate-entry form or desktop shortcut.
The Mac app offers an explicit **Pair a Windows computer** action and an
automatically selected LAN address. Pairing is not enabled by a hidden test,
app startup, discovery packet or remote request.

## Actual transaction

`EnrollmentChannel` is a bounded public-enrollment socket, deliberately not an
authenticated desktop transport. Port 45444 is separate from the existing TLS
desktop endpoint. The Mac opens a single-connection, private-IPv4 listener only
after the local action, and closes it on accept, timeout or cancellation.
The pairing exchange has a 120-second deadline and 256 KiB per-direction cap.
Individual reads are at most 4 KiB; the public six-object bundle is at most
128 KiB. Invalid framing, EOF, cancellation or excessive input terminates it.

The worker creates native nonexportable keys behind the existing protected
journal lease, exchanges LPP1 identity/proof messages, and schedules native
comparison UI on each main thread. All 256 comparison bits are displayed.
The shared consent model remains pinned while either UI uses it. Enter/Escape
decline; only the explicit local Allow action supplies local consent. Peer
approval must carry a verified signature over the exact transcript. An IP is
an address to contact, never evidence of trust.

Only then does the Mac issue the exact approved client certificate, exchange
the six public certificate/status objects, and run the existing signed LPC1
durable completion protocol. Protected configuration publication occurs only
after both-end completion evidence. The host uses client OCSP, not server
OCSP. Fresh profiles remain view-only/H.264-only with clipboard disabled.
No private key, desktop pixels, input, clipboard or SSH grant crosses this
pairing channel. Program updates retain their existing runtime inventory.

Closing either window cancels the current exchange; the worker independently
checks cancellation. Before durable PREPARED, cleanup rolls back only owned
staging. After PREPARED, the journal and decision evidence remain recoverable;
there is no unilateral deletion or new commit decision on restart. A completed
record can restore its remembered settings without rekeying.

## Interrupted pairing

The native retry now routes an existing LPJ2 record into `recover_enrollment`
instead of issuing new keys. The Mac's **Finish interrupted pairing** action
remains available after local configuration is saved, so a Windows client that
lost the final host receipt can reconnect. This explicit metadata action does
not stop an active service or replace its existing user-edited configuration.
A configured host without a native enrollment record cannot start a new
enrollment through this recovery action.

LPR1 recovery is scoped to the exact saved host round and transcript binding.
Each endpoint sends a 104-byte hello containing its role, that scope and a fresh
32-byte OS-random nonce. Its native key signs a separate recovery domain plus
both complete hellos in host/client order and its role. The peer verifies the
signature using the exact public key from its protected record. An old proof,
changed scope, changed role or unknown header cannot authenticate this retry.
Signatures remain canonical bounded P-256 DER, at most72bytes. No certificate,
new key, new approval or desktop authorization is issued by recovery.

After mutual proof, four bounded receipt-batch rounds replay the saved LPC1
messages and drain already accepted decisions. Each batch has an eight-byte
LPR1 header, one-byte count and two-byte lengths for at most three receipts of
at most207bytes. Receipt order and signatures are validated by the existing
durable coordinator. The total recovery deadline is30seconds. A resumed host
without a saved commit decision can only sign an abort, never create a new
commit using the old consent. A signed abort returns no persistable proof.
Its durable evidence is retained rather than silently deleted.

Explicit retry now retires a signed abort into protected local `aborted/`
history, removes only the old transaction's newly owned keys/certificate, and
releases the active slot. Cleanup is restartable; the exact terminal LPJ2 proof
is durably archived and read back before the active record is removed. A crash
before that point leaves the signed abort active. Committed transactions cannot
be retired by this operation. Native archives enforce owner/ACL, no-follow,
single-link, atomic-create and size checks. At most128 records of at most138240
bytes are retained; exhaustion refuses a new attempt without dropping evidence.

A host retry may cancel an undecided PREPARED record using its existing key,
archive it, and accept a fresh attempt. A client cannot unilaterally cancel a
PREPARED decision. If it arrives late, the host returns a bounded LPA1 negative
proof: eight-byte header,32-byte round,32-byte binding,two-byte receipt length
and the original signed abort (at most207bytes). The client verifies that exact
host signature,scope,parent and irreversible decision against its own protected
record before cleanup. This negative proof intentionally remains replayable
after the old private keys are removed; it cannot authorize a commit or desktop
session. An unrelated/modified abort is rejected. A host with a newer committed
pairing can replay historical cancellation without modifying its current state.

When no committed pairing blocks replacement, both ends continue into a new
LPP1 exchange on the same explicit pairing attempt. It requires fresh nonces,
new comparison information and a new explicit local approval on EACH endpoint.
This handles both a lost abort response and the host-only PREPARED case without
manual settings deletion or reinstall. Existing committed user configuration
is never silently replaced. History alone does not revive prior consent.

Before PREPARED, a valid LPJ1 orphan can be rolled back using its existing
absent-before-create ownership record before a fresh pairing begins. LPJ2 is
never treated as disposable staging. The production native UI calls this same
recovery path; deterministic and runtime probes do not substitute a mock
coordinator.

## Evidence and remaining gates

The isolated setup probe uses native Windows CNG plus a memory certificate
store and a temporary Mac Keychain. Synthetic local approval is confined to
that test executable; there is no production auto-approval flag. The actual
two-host socket exchange has passed through a localhost-only SSH test tunnel,
while retaining the LAN address in the approved transcript and certificates.
Both native stores completed, persisted compatible configuration, recovered
it from the durable journal and removed their owned fixture identities.
This proves application transaction integration, not direct-LAN admission or
human comparison UI acceptance.

Direct-LAN fixture attempts timed out before the Mac accepted the connection.
The Mac application-firewall log recorded the new probe's inbound flow being
enqueued. No firewall/trust setting was changed. The exact native admission
cause and the real installed app's LAN acceptance remain open; a reported TCP
connection or firewall path status is not sufficient proof. The tunnel is a
diagnostic fixture option, not a production transport fallback.

Windows hidden-view workflow checks exercise the real pairing window's bounds,
full comparison text, Enter cancellation and rejection of a later Allow. They
create no worker/socket/key and do not control another application. The Mac
hidden layout similarly never opens pairing or native permission dialogs.

Recovery fixtures use real loopback sockets, protected journal reloads and
native signatures for lost decision, lost client commit, lost host commit and
undecided-host restart. Tampered and previous-connection recovery proofs are
rejected without changing the completed journals. Controlled two-host runtime
probes additionally interrupt the real enrollment socket at named receipt
boundaries, reconnect and check the same native key references and transcript.
These reload coordinators within the isolated test processes; they are not
whole-machine power-loss or cold-login evidence.

Controlled runtime probes cover new dual confirmation after abort,host-only
PREPARED retry,old owned-key removal,and a late historical client arriving after
the new transaction commits. The newer committed journal must remain byte-equal.
These are isolated native fixtures,not manual UI or cold-account evidence.

**Not yet release acceptance:** actual two-person UI
confirmation, direct-LAN installed-app acceptance, automatic leaf-certificate
renewal, new-account installation, reboot and consecutive signed upgrades.
Native CRL/OCSP refresh is connected separately; see
[status renewal and its verification boundaries](native-status-renewal.md).
Existing configured connections and the installed legacy service are preserved.
No Developer ID is currently available; production signing, TCC continuity and
service activation retain their existing gates. No signing substitute or
permission/trust bypass is introduced by this pairing integration.

See [proofs](native-enrollment-pairing.md),
[durable completion](native-enrollment-completion.md), and
[remembered configuration](native-enrollment-configuration.md).
