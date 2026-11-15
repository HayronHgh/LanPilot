# First-contact pairing proof boundary

Status: bounded public exchange, native proof verifier and native consent-model
handoff implemented. The [first-use integration](native-enrollment-setup.md)
now connects the explicit native UI, socket and durable enrollment. Installed
direct-LAN admission and human UI acceptance remain open. An approved proof
alone does not admit a desktop session.

The old `NodePairingService` assumes an already authenticated TLS peer; it cannot
bootstrap a new installation. `PairingConsent` was deliberately UI-only and must
not consume remote confirmation booleans. `enrollment::PairingSession` now verifies
cryptographic possession and confirmation of an exact public transcript before
advancing that model. Its only result authorizes staging enrollment, never
desktop control, SSH, clipboard, persisted pairing or authenticated transport.

## Exchange and local confirmation

Each local controller supplies its OS-owned P-256 key, a fresh 256-bit CSPRNG
nonce, role and a maximum 120-second monotonic window. The host also supplies
its locally prepared authority public key, exact root certificate SHA-256 and
private-LAN desktop IPv4/port. The client cannot propose an authority, endpoint,
filesystem path, executable, command or capability. Roles, keys and nonces cannot
reflect each other. The host authority is distinct from either endpoint key.

1. Both ends send a fixed hello with their public metadata.
2. Each signs a role-specific proof over the complete canonical transcript hash.
   Only after both proofs verify can the local native confirmation model be shown.
3. Both users compare the **full 256-bit binding** using the native interfaces
   and explicitly allow. No shortened six-digit comparison or automatic local
   approval is claimed. No fingerprints, keys or paths need to be typed.
4. A local allow produces a separate role-specific signed approval. A received
   approval is only applied to the consent model after local approval; it can
   never impersonate a native click. The session requires the actual verified
   approval message even if an adapter incorrectly toggles raw model booleans.
5. The one-shot `ApprovedPairing` result contains the exact transcript and expiry.
   It reserves `begin_persistence`; the controller still owns staging, durable
   two-end completion, cancellation/recovery and native certificate association.

Proof and approval labels are separated by role, purpose and version. The
transcript includes both nonces/identities and the host authority/root/endpoint.
This is a custom enrollment message format, **not a TLS handshake implementation**.
Context separation is also used by TLS CertificateVerify; see
[RFC8446 section 4.4.3](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.3).
An ECDSA proof proves possession of the declared key; it does not establish that
the declaration belongs to the intended person. Full local two-end comparison is
required before first trust, and authenticated durable completion is still a
separate product gate. Do not treat this unit as an external protocol audit or
as permission to deploy an unauthenticated desktop transport.

## Bounded framing

All integers are big-endian. Each direction has exactly three ordered messages:

```text
LPP1 | version=1 | kind:u8 | flags=0:u8 | reserved=0:u8
payload_size:u32 | sequence:u32 | payload

hello:    sequence=1, payload=199 bytes
proof:    sequence=2, payload=8..72 byte canonical ECDSA DER signature
approval: sequence=3, payload=8..72 byte canonical ECDSA DER signature
```

The 199-byte hello is role:u8, nonce:32, identity-key-XY:64, host-authority-XY:64,
host-root-SHA256:32, host-IPv4:4 and host-port:u16. The client's host-only fields
must be zero. Public points are validated by the native crypto adapter. DER
integers must be minimal, positive, nonzero and fit 256 bits; native verification
additionally checks the actual ECDSA values. Unknown fields, flags, messages,
sequences, oversized lengths, stale proofs and any verification exception fail
closed. A failed session cannot be reused.

`PairFrameReader` buffers at most one 215-byte frame, handles byte fragmentation
and reports consumption so a caller can process coalesced frames without an
unbounded queue. Partial EOF fails. It supplies only complete public messages to
the session. No input or visual payload type exists here. RWV2 binary stdout and
the existing desktop mutual-TLS/revocation path are unchanged.

## Native implementation and probes

Native verification reuses the existing OS ECDSA/SHA-256 primitive with a strict
pairing DER decoder. Peer keys enter only the pairing verifier; they cannot
replace the independently pinned release-update authority. The native key probe
also signs/verifies a challenge using reopened protected CNG/Keychain fixture
keys. The certificate probe and pairing probe share the same ephemeral native
fixture signer instead of duplicating crypto. No elliptic-curve arithmetic or
production fake verifier was introduced.

- `lanpilot-enrollment-pairing-workflow`: deterministic workflow/security cases,
  including both confirmation orders, native-model handoff, consumed approval,
  malformed/fragmented/coalesced framing, replay, expiry, clock reversal,
  role/reflection, bad signatures, raw-model boolean misuse and canonical DER.
  Its explicitly named workflow fixture is not crypto evidence.
- `lanpilot-native-enrollment-pairing`: real native P-256 proofs and signed
  approvals, both comparison bindings equal, consumed staging results, modified
  message/signature rejection. Three ephemeral software keys, no stores/listener.
- `rwn-enrollment-pairing-probe --emit-public-fixture`: emits bounded public-only
  fixture bytes as hex, never a private key or local identity reference.
  `--verify-public-fixture` reads bounded hex on stdin, independently recomputes
  the hello transcript binding and verifies all four role/purpose-specific native
  signatures. This mode creates no keys and touches no personal stores. It is a
  cross-OS crypto probe, not a live user pairing or desktop capability.

## Next connection milestone

The [native association/reconciliation adapter](native-enrollment-identity.md)
now exists and verifies the approved public bundle against the owned key before
adding a certificate. The production controller must serialize enrollment with the protected owner
lease and journal, prepare/reuse host keys and root, associate received public
certificates with local nonextractable keys, and transactionally store remembered
connection metadata. It must validate that all certificates match the exact
approved keys/root/endpoint and keep all pending material out of desktop admission.
Then exchange authenticated durable receipts, support interrupted/replayed
completion, and only activate the existing strict desktop TLS path after both
ends are known committed. Existing identities must not be silently replaced.
No network listener, installed identity migration, permission request, service
activation, shortened comparison code or automatic user consent is included here.
