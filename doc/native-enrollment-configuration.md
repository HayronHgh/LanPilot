# Remembered enrollment configuration handoff

`EnrollmentConfigurationHandoff` connects a verified `PersistablePairing` to
actual protected Windows/Mac files. It borrows the existing native journal
operation lease. It does not create a replacement identity, start a service,
register login behavior, add trust roots or grant remote control/clipboard.
The production first-contact UI/socket path calls this handoff.

The exact current LPJ2 record must match the typed proof, all signed receipts
must validate, both durable commits must be present and the actual local native
identity must still prove possession. A prepared, aborted or unrelated record
cannot create configuration. Current desktop TLS still validates chain, expiry,
hostname, positive revocation and paired identity when connecting.

Windows writes schema2/eleven-field `connections/default.json`, including
`status: native` to require automatic native revocation refresh. The standalone
TLS script's legacy tls-desktop.json default is unchanged. Mac writes the
existing bounded service.conf format. Six public objects live under the owned
`identity/enrolled-v1/<bundle-sha256>/` directory: root/server/client DER, CRL,
server OCSP and client OCSP. The Mac listener's OCSP file is **client-ocsp.der**,
because its native trust check validates the incoming Windows client. The
Windows profile uses the CRL. No path, key selector or filename comes from a
remote message. New configurations default to view-only, h264-only and no
clipboard; existing different settings are never overwritten.

Publication preflights the existing protected profile before resource writes.
Exact existing output is idempotent; different or unsafe existing state fails
closed. Each public object is create-only or byte-equal, privately owned and
bounded. File flush plus atomic no-replace promotion exposes the final profile
only after all public resources are durable. Mac additionally holds runtime.lock
through the operation, without recursively acquiring the already-owned owner.lock;
an active canonical service is not stopped or rewritten beneath a connection.

The complete LPJ2 outcome is retained as the recovery intent and peer evidence.
`recover` reconstructs completion from that protected record, drains only an
already authorized decision if necessary, and repairs missing configuration or
partial staging without reviving consent or rekeying. It never decides commit.
Call recovery during single-owner startup, not concurrently with a live cached
pairing coordinator. A valid existing user-edited profile should be loaded by
the normal reader; recovery must not reset user choices. The
[first-run transport/UI](native-enrollment-setup.md) now calls this handoff.
Interrupted two-end replay and signed-abort retirement are connected to the
native UI retry flow. See [native status renewal](native-status-renewal.md) for
the separate protected CRL/OCSP cache; it never rewrites these initial resources.

Native workflow probes use real protected files and real isolated native
identities. Windows invokes the actual existing PowerShell settings parser in
a bounded hidden child. Mac invokes the actual service configuration parser
with fixed /Users/fixture logical paths while all physical writes remain in its
isolated temporary directory, matching the existing configuration-store fixture
pattern. This is format/native-file evidence, not an actual service startup.
Cases cover idempotency, partial object/staging repair from LPJ2, conflict
preservation, tampered/hard-linked object rejection, no premature profile from
prepared/aborted pairing and Mac runtime lease contention. Tests never access an
installed profile, personal clipboard, desktop or input.
