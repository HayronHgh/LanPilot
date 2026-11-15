# Native first-enrollment certificate profile

Status: implemented certificate/CSR/CRL/OCSP encoding, native protected-key stores
and native crypto interoperability probes. **Fresh-user pairing is not connected yet.** This
module is a necessary replacement for the engineering-only certificate tool
dependency; it does not authorize enrollment, provision persistent identities,
start a pairing listener or grant desktop control.

The old identity scripts assume an already-created application authority and
OpenSSL/PowerShell engineering tooling. PairingConsent only models confirmation
after a transcript has been authenticated. Neither is a first-contact protocol.
The native formatter supplies signed public objects which a real bootstrap and
native protected-key controller can use without exporting a TLS private key.
Existing installed identities and strict desktop TLS verification are unchanged.

## Bounded profile

- P-256 public points are checked by the OS key adapter. Signatures use native
  ECDSA/SHA-256; this code implements DER formatting, not elliptic-curve math.
- X.509 v3 root has a path-length-zero CA constraint and certificate/CRL signing
  usage. Separate server/client leaves have critical non-CA constraints and
  digital-signature usage with their respective TLS EKU. Server SANs are bounded
  exact DNS/IP names; no wildcards. The profile follows the certificate/CRL
  structures in [RFC5280](https://www.rfc-editor.org/rfc/rfc5280.html).
- PKCS#10 requests prove possession of the subject key through a native
  signature over the request, using the structure from
  [RFC2986](https://www.rfc-editor.org/rfc/rfc2986.html).
- CRLs have monotonic caller-provided numbers, issuer key identity and at most
  256 distinct revoked serials. OCSP uses a SHA-256 CertID, issuer-by-name
  responder, issuer signature and explicit good/revoked/unknown states with a
  bounded validity window, following
  [RFC6960](https://www.rfc-editor.org/rfc/rfc6960.html).
- Serials are nonzero 128-bit values; the controller must generate unique
  serials per issuer. Authorities are limited to 3660 days, leaves to 366 days
  and revocation windows to 24 hours. All times are bounded to 2020–2099 and
  subordinate windows must fit the issuer validity. GeneralizedTime is used
  when required; certificate times before 2050 use UTCTime.
- Eight SAN entries, exact positive serials, bounded DER/signatures and strict
  role/status enums prevent unbounded requests reaching the signer. No caller
  can request arbitrary extension OIDs or a client certificate with CA powers.

`enrollment::Signer` is an OS-key adapter, not an authorization API. The
production controller must bind an approved role/subject key, nonces and
proof of possession to both local and authenticated peer confirmations BEFORE
issuing a certificate. Never call it from a raw remote confirmation boolean.
The controller must persist unique serial/CRL state and native key references;
no persistent controller is wired by this module.

## Native evidence and probe scope

The runtime probe creates only two ephemeral software keys, signs its own
fixture data and exports public objects. It does not claim those ephemeral
keys prove the required nonexportability of future persistent identities.
Windows uses a memory certificate store/exclusive root engine with offline,
strict SSL and chain revocation checks. Mac uses Security.framework with
application-only anchors, positive revocation required and network fetch off.
No user/system trust or personal key store is modified.

Windows accepts the issued server chain with a valid CRL and rejects revoked
and actually expired CRLs. A simulated certificate-verification date alone
cannot make a CRL expire: Windows evaluates CRL freshness against current time,
as documented for
[CertGetCertificateChain](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain).
The test therefore uses an already-expired CRL before supplying any good proof.
Mac accepts current good OCSP and rejects revoked, unknown and stale responses.
An independent OpenSSL decoder verifies the CSR signature; OpenSSL is only a
development check, not a dependency of this native formatting path.

Optional probe modes export public fixture objects into a new physical folder
or validate received public fixtures in memory. They cannot install trust,
persist an identity, create a pairing record, inject input or capture a desktop.
Their success means only that fixture chains/status data validate against their
explicit fixture root, not that a desktop peer is authorized.

## Remaining connection work

1. Connect the native protected-key stores to bounded pending enrollment recovery
   and existing-identity reuse. The storage adapter exists; the production
   controller is not connected yet. No developer authority/key is shipped.
2. Connect the [first-contact proof session](native-enrollment-pairing.md) to
   production onboarding and its transport. Native transcript/possession and
   signed-confirmation verification now exists; the production socket/UI and
   durable completion controller still need integration.
3. Transactional enrollment and remembered desktop configuration, with no
   manually typed fingerprints/certificate paths and no admission before durable
   two-end completion. Keep existing paired desktop paths intact during migration.
4. Certificate, CRL and OCSP renewal/revocation with authenticated public-data
   refresh so stale evidence cannot permanently strand an installed product.
5. Actual first pairing, reject/cancel/timeout/replay, two-end reconnect and
   continuous-use acceptance. The current signed-app/Developer ID limitation
   remains; no substitute signer or trust/permission bypass is introduced.

## Protected native key storage

`KeyStore` only exposes explicit create-new, open-existing and remove-if-public-key-
matches. References have a closed authority/server/client purpose and a nonzero
128-bit local identifier; neither remote strings nor filesystem paths select a
key. The local controller must generate random identifiers, hold its protected
cross-process enrollment lease and maintain a durable pending journal. An absent
key is never automatically replaced. A key reference does not authorize pairing.

Windows stores current-user P-256 signing keys in the Microsoft software KSP.
It sets export policy to zero and signing-only usage before finalization, and
revalidates both properties on reopen. Creation omits overwrite flags, so the
OS refuses an existing container. See
[NCryptCreatePersistedKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
and [CNG storage properties](https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers).
No machine root certificate or personal certificate is installed by the adapter.

Mac generates permanent P-256 private keys with
[`kSecAttrIsExtractable=false`](https://developer.apple.com/documentation/security/ksecattrisextractable)
and verifies their attributes on reopen. Queries are scoped to the locally opened
keychain and a fixed application tag, reject multiple matches and fail instead
of dismissing an authentication request. Removal also matches the native public-
key label after checking the expected public point. The default store is the
user's default keychain; an explicit local keychain supports isolated testing.
No keychain is created/unlocked or system trust changed by the adapter itself.
For the login-keychain implementation, the nonextractable flag must also be set
at the top level, as seen in Apple's
[native implementation](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/SecKey.cpp).
The runtime test found that a private-attributes-only flag left the persisted key
extractable; the adapter now sets both and checks the result after reopening.

The storage probe deliberately creates only fresh random fixture containers on
Windows and a standalone temporary keychain on Mac, then deletes its own items.
Mac restores any search-list change from keychain creation immediately and uses
only an explicit fixture search list afterward. It tests all three roles, reopen,
signature verification, duplicate-create rejection, wrong-key deletion rejection,
actual private-export denial and cleanup. These tests do not enroll an installed
identity or claim TPM/Secure Enclave protection. Software KSP/Keychain policy is
not hardware nonextractability, and code-signing/Keychain authorization continuity
across production upgrades still requires the real publisher identity.
