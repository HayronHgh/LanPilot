# Native certificate association and reconciliation

Status: approved public certificates can be associated with existing native
nonexportable keys, reloaded through a new store adapter and reconciled after a
lost add receipt. **The durable two-end enrollment journal, production pairing
wizard/socket and remembered connection activation are not connected yet.**
This is local identity staging, never desktop admission or a native user grant.

## Before any native store mutation

`IdentityStore::associate` consumes an owned copy of six bounded public objects:
root, server leaf, client leaf, CRL and both OCSP responses. Each object is at most
64 KiB, their total is at most 128 KiB and each certificate is at most 8 KiB.
There are no imported private keys, PFX passwords, paths, commands or remote
certificate-store selectors. The existing `ApprovedPairing` must remain valid,
the local reference purpose must match its role, the local key must already
exist with protected policy and its public point must match the approved identity.

The root's full SHA256 must equal the locally compared transcript. Native parsers
extract and match the root/server/client P256 points to all three approved keys.
A narrow bounded DER profile checker requires v3, positive bounded serials,
ECDSA/SHA256, named P256 SPKI, CA/pathlen0 versus non-CA leaves, exact signing/key-
cert/CRL usage, single role-specific EKU, expected server IP SAN and the required
key identifier extensions. Unknown/duplicate extensions, noncanonical lengths,
oversized input and mismatched roles are rejected. This checker is not a custom
cryptographic or X.509 trust engine: both real native TLS chains, current time,
hostname and positive revocation are still mandatory. Windows uses its CRL;
Mac uses the respective explicit OCSP response. Network fetching is disabled and
the root is application-exclusive, never added to system/user trusted roots.
Approval time is rechecked around native operations, including after signing.

## Native identities and recovery lookup

Windows associates a public leaf with the fixed CurrentUser CNG provider/key
reference using `CERT_KEY_PROV_INFO_PROP_ID`. It never overwrites an existing
certificate/provider association. The actual certificate context must acquire
the expected CNG key silently and sign a locally random, domain-separated
challenge; native public verification proves the binding. The 20-byte SHA1 in
the returned metadata is only the existing CurrentUser/My lookup identifier;
full SHA256 and key equality remain the integrity checks. See
[CertSetCertificateContextProperty](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certsetcertificatecontextproperty).
The test adapter uses a memory certificate store; the production default is
CurrentUser/My, opened for creation only after all approval/trust checks.

Mac stores only the public leaf beside the existing private key and builds the
identity with
[SecIdentityCreateWithCertificate](https://developer.apple.com/documentation/security/secidentitycreatewithcertificate(_:_:_:)).
Native validation/signing must use that same stored certificate and private key.
Lookup uses the certificate's native normalized issuer and serial within the
explicit local keychain, then verifies its complete bytes. These are part of
Apple's [certificate primary key](https://developer.apple.com/documentation/security/ksecclasscertificate);
an unattached `SecCertificateCreateWithData` object is not proof that an item is
stored. Duplicate issuer/serial with different bytes fails without replacement.

The isolated Mac runtime exposed that opaque identity references from this
separately-created key/certificate path did not reload. Fresh native enrollment
therefore uses a bounded app-owned `LPI1` descriptor: closed key purpose, 128-bit
local key ID, server IPv4 and a public leaf of at most 3072 bytes (3099 total).
It contains no private key, path or command. The loader verifies the profile,
existing protected key, exact public point and an actually stored certificate
before rebuilding the native identity. The existing desktop loader recognizes
this descriptor; legacy Keychain references retain their original path. No
default keychain/search-list/trust change or silent key replacement is required.

`locate` is read-only reconciliation for a protected write-ahead record. It
derives the current native reference from the exact certificate/key, rather than
generating an identity or guessing that a prior add succeeded. A newly-created
receipt can remove only that exact certificate association, including when its
opaque/native reference was lost before being saved. Changed bytes, fingerprints,
keys or references fail closed. Reused receipts cannot remove anything; roots
and private keys are never deleted by this API. The controller must write its
creation intent and whether an association already existed BEFORE invoking add,
hold the enrollment lease and finish/roll back its journal after interruption.
This unit does not yet provide that durable coordinator or admission commit.

`ready` proves local association/possession only. It is not a peer handshake,
durable pairing, capture, input permission or physical display receipt. A future
connection still uses existing strict mutual TLS and current revocation policy.
No old paired identity is migrated/rekeyed by these APIs.

## Evidence scope

- Structural workflow/security tests distinguish root/server/client profiles,
  EKU, curve, CA flags, SAN, serial and malformed/oversized DER. Their signature
  fixture is explicitly not native crypto evidence.
- The native key probe uses actual protected fixture keys, signed public chains
  and fresh CRL/OCSP. It rejects stale/revoked/wrong-root/wrong-key/wrong-role and
  expired approvals before adding certificates. It verifies both roles, native
  private-key signing, adapter reopen, duplicate reuse, lost-reference lookup,
  certificate-only rollback, no mutation for bad metadata and preservation of
  private keys after certificate removal. Certificate count returns to zero.
- Windows tests use fresh CNG test containers plus a memory certificate store.
  Mac tests use a standalone temporary keychain whose creation search-list side
  effect is immediately restored, and deletion is verified. Actual installed
  identities, personal certificates, system trust, services and permissions are
  unchanged. Native interactive authorization and actual signed app upgrades are
  separate operational gates; no Developer ID or ad-hoc continuity is claimed.

The [protected pending journal](native-enrollment-journal.md) now uses these real
native hooks for local write-ahead staging and safe recovery. The remaining
integration is authenticated durable two-end receipts and atomic remembered
configuration only after both ends are committed. Then connect the first-run
transport/UI and complete reject/reconnect/reboot/renewal/upgrade acceptance.
