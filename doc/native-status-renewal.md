# Native paired revocation refresh

Native enrollment keeps its original root, leaf certificates, nonexportable
keys, peer pins, LPJ2 receipts and six public resource files. Revocation data
has a separate protected atomic cache (`revocation.current`). LPS1 renews only
CRL/OCSP evidence. [Authenticated LPS2 credential renewal](native-credential-renewal.md)
extends this boundary for the same permanently paired authority/device keys.

## Product path

New Windows profiles use schema 2 with `status: native`. The normal launcher
adds `--native-status required`; users see no new field. Before creating its
TLS connection, Viewer checks the committed native journal, endpoint, pinned
root/server and actual client key possession. New connections request signed
public status from the saved private IPv4 on port 45444 to discover the server's
selected certificates,then pass authenticated current credentials and CRL in
memory to the existing positive-revocation TLS verifier. Native profile failure never
downgrades to legacy mode. Schema 1 legacy profiles keep their existing path.

The configured Mac service opens this metadata listener only after the existing
publisher, configuration, runtime, capture and identity gates pass. Its normal
UI startup opens no listener. The native issuer refreshes evidence after 12
hours, with at most 23 hours validity bounded by the selected certificates.
The service checks refresh once per minute; TLS callbacks only copy cached
client OCSP bytes under a short mutex. They do not sign, wait for a socket or
write files. Native TLS independently validates that response at actual time.
Background Keychain interaction is disabled; unavailable authority access fails
closed instead of showing an authorization dialog in response to a request.

The listener accepts only LPQ1 status or existing LPR1 authenticated recovery.
It rejects fresh LPP1 pairing and cannot approve consent, mint a replacement
device key, grant input/clipboard/SSH or alter system trust roots. First pairing remains
an explicit foreground operation with local confirmation on both ends.

## Public bootstrap and storage

An expired revocation proof cannot be required to fetch its replacement.
LPQ1 is therefore a bounded public-metadata request, not an authenticated
desktop connection. It carries the saved round, transcript binding and all
three certificate hashes (164 bytes). LPS1 binds those values, issue/expiry
times, payload lengths and CRL/two OCSP hashes to a native authority signature
under a dedicated domain. The unchanged pinned issuer and native positive
revocation policy are both mandatory before accepting evidence. No private
key or certificate-store selector is received over this socket.

The wire cap is 131104 bytes, individual DER cap 65536 bytes, with 4096-byte
reads and a three-second exchange deadline. Native protected files enforce
ownership, ACLs, no symlink/reparse traversal, single links, exclusive owner
lease, bounded staging, flush and atomic replacement. Interrupted empty staging
is recoverable; malformed committed cache is not silently overwritten. Signed
issue times are monotonic; identical replay is idempotent. Rollback, mismatched
round/pins, truncation, signature damage and oversized data fail closed.

An offline refresh may retain only still-native-valid cached evidence. Once
a refreshed cache exists, the initial bundle is never an expiry fallback.
Historical verification is scoped to a native trust object and does not change
the OS clock or a TLS connection. An expired cache is checked for its authority
signature, exact scope and payload hashes only as a monotonic counter, never
as usable connection evidence. Requiring native current-time revocation for
that expired counter would deadlock refresh. Newly issued/accepted or usable
cached evidence always requires positive native validation at operation time.
Windows additionally checks the supplied CRL
signature, issuer, time and certificate status using Crypt32, preventing a
different OS-cached CRL from hiding damage or expiry in these exact bytes.
The normal positive-revocation chain policy remains an additional requirement.
Mac similarly validates the exact issuer-signed, certificate-bound OCSP good
response and its freshness using the existing native signature verifier before
the native Security chain evaluation. The bounded parser accepts only this
issuer's canonical profile, not arbitrary OCSP or delegated responders. Native
cache selection cannot turn stale, damaged, unknown or revoked supplied status
into acceptance. These are additional evidence checks, not a replacement chain
verifier or a custom cryptography implementation.

## Verification boundaries

Both native-key fixtures exercise genuinely expired, correctly signed evidence
at actual system time, followed by refresh with unchanged keys/receipts. Windows
also exercises future verification times, cache hit, offline boundaries, stale
replay, damage, hard links and fragmented/truncated wire data. Mac keeps native
trust policy unchanged instead of manufacturing future-OCSP acceptance when
Security still uses actual-time revocation freshness. An expired-counter
adapter rejects historical native validation to detect the renewal deadlock.
The explicit setup probe's `status-renewal` scenario pairs the two platforms
and exchanges two expired-to-fresh status cycles over actual sockets, reopens
the protected cache and uses the same connection selector as Viewer. Synthetic
consent and seeding an old signed fixture cache are test-only. Neither machine's
clock changes; this is not multiple elapsed days or an installed-app TLS session.

Build/CTest and fixture results belong in the verification report. Production
service activation, direct-LAN installed-app admission, real fresh-account and
reboot testing, leaf rotation, signed in-place upgrade and long uninterrupted
desktop sessions remain separate release gates. No installed identity or
service is replaced by these tests.

Microsoft documents that `CertGetCertificateChain`'s `pTime` does not set CRL
freshness time: [native chain time semantics](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain).
This distinction is covered explicitly rather than treating a future certificate
verification date as proof that revocation evidence was fresh at that date.
