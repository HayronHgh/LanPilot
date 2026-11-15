# Durable two-end enrollment completion

This component advances real native enrollment staging to authenticated durable
completion. It is not yet connected to a production pairing socket, first-run
wizard or active connection/service configuration. No desktop listener or OS
permission is enabled by this component. Runtime TLS and positive revocation
checks remain separate and unchanged.

## Commit order

The host owns the decision. The client cannot prepare until it verifies the
host's prepared receipt, so an emitted client prepare always has a recoverable
host-side decision record. Original native consent is consumed into the owner;
it is not reconstituted from a journal or a remote boolean.

1. Host atomically promotes its staged LPJ1 record to LPJ2 containing the signed
   `HOST_PREPARED`. Only after durable save returns can it expose that receipt.
2. Client verifies that receipt against its current approved full transcript and
   exact public bundle, and atomically persists LPJ2 with `CLIENT_PREPARED`.
3. Host persists the verified client prepare. Only the still-running owner with
   the original unexpired typed approval may decide commit. It persists the
   signed `COMMIT_DECISION` before exposing it.
4. Client persists the verified decision, then persists `CLIENT_COMMITTED` before
   exposing its own durable commit. If signing fails, the already accepted
   decision remains; resume drains this pending work without new network input.
5. Host persists verified client commit, then persists `HOST_COMMITTED` before
   exposing its own durable commit. Resume drains the same interruption safely.
6. Client persists the final host receipt. Both sides can now produce the typed
   `PersistablePairing` proof for a later atomic configuration handoff.

The host may have this proof before the final packet reaches the client. That
proves both durable commits, not instantaneous mutual knowledge or simultaneous
UI activation during a partition. The retained exact signed receipts must be
replayed, not regenerated, so signature randomness cannot change dependency
hashes. The client remains in doubt on timeout; it cannot unilaterally roll back.

A resumed host with no durable decision cannot revive the original <=120-second
approval and make a new commit. It can sign an abort instead. A host with a
durable commit decision must finish forward, even after consent expires. The
decision is authorized/signature-created while consent is live; its subsequent
durable flush/delivery does not manufacture new consent.

## Cancel and recovery

Before a commit decision the host can durably sign `ABORT_DECISION`. Only this
authenticated abort allows LPJ2 cleanup. A late client prepare crossing the
abort is harmless: the host retains/replays its existing abort. Existing/shared
objects survive cleanup; newly owned exact objects use the same native safe
rollback code as local staging. Cleanup can resume after interruption, and its
completion marker is persisted. Signed abort evidence remains even after its
newly-owned private keys are removed, so a future recovery transport must be
able to replay this PUBLIC proof without requiring those deleted keys.

LPJ2 is a distinct closed record version. Old LPJ1 `load/save/clear` and
`EnrollmentStager::rollback` reject it before any native deletion. There is no
API to clear a committed or aborted outcome yet: the next configuration/outcome
handoff must durably preserve the relevant peer recovery evidence before
retiring it. This unit does not guess that the other host saw the last packet.

## Wire and storage bounds

Each LPC1 receipt is 143..207 bytes: magic/type, host round ID, approval binding,
exact bundle SHA-256, dependency receipt SHA-256, 2-byte signature length and
canonical ECDSA/SHA-256 DER. Type implies signer role. All fixed signatures also
cover a purpose-specific domain. The host round comes from its durable local
random transaction; full first-contact nonces, keys, root and endpoint binding
prevent cross-session reuse. Public bundles include the exact certificate and
status objects, not imported private keys or local paths.

The bounded incremental reader accepts one receipt at a time, supports partial
and coalesced TCP input, and rejects unknown kinds, oversized signature lengths
and partial EOF. Duplicate accepted messages must be byte-identical. Wrong
role, altered dependency, bad signature, changed bundle, conflicting decision or
unrelated session fails before advancing persistent state.

LPJ2 stores its complete validated LPJ1 staging record, full transcript, host
round and at most six signed receipts under the SAME protected native lease and
atomic file backend. Total storage cap is 138,240 bytes; the LPJ1/public-bundle
caps remain separately unchanged. Revision and exact previous-file comparisons
prevent an owner from overwriting an unexpectedly changed record. All stored
signatures and transcript bindings are verified on resume. Checksums detect
damage; native ownership/ACLs protect local state. No private key is exported.

`PersistablePairing` is deliberately a configuration persistence proof. It is
constructed only when both committed receipts are present and the exact local
native identity still proves possession. The [native configuration handoff](native-enrollment-configuration.md)
now consumes it to publish compatible protected files and repair interrupted
publication. It does not bypass current TLS chain,
hostname/revocation checks, Screen Recording, Accessibility, input or clipboard
consent. Production first-run UI/transport and startup recovery integration
remain the next integration step.

## Verification scope

The existing native key probe exercises six scenarios against actual protected
fixture keys, native signatures/verification, real certificate association and
the protected file journal. Cases cover normal completion, prepared host restart
without consent revival, expired decision denial, client and host signing
interruption after accepting a durable decision/receipt, signed abort with a
crossed late prepare, exact replay, duplicates, stale sessions, changed bundles,
partial/coalesced receipt framing, LPJ1 rollback refusal and shared-key retention.
These are deterministic isolated native workflow/security probes, not production
cross-host pairing acceptance or remote storage attestation. No personal identity,
installed service, desktop, clipboard or input is touched.
