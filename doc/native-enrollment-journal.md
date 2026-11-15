# Native write-ahead enrollment staging

This unit is a local recovery foundation, not completed pairing or a desktop
grant. It connects the approved certificate bundle and protected native key /
identity stores to a private, bounded write-ahead record. It does not start a
listener, activate a connection, import a private key, install a root, or replace
the existing installation. No publisher/TCC continuity is claimed.

## Ownership and ordering

`EnrollmentStager::begin` records a local random transaction ID and each key's
absent/present state **before** a native key can be created. Host staging uses
authority + server references; client staging uses one client reference. Existing
keys must reopen with exactly the saved point; missing saved keys are never
silently replaced. A newly owned key created immediately before interruption
can be reconciled under its already-durable absent-before-create intent.

`associate` requires an unexpired typed `ApprovedPairing`, matching local keys
and the existing canonical certificate contract. It persists the complete public
bundle, approval binding, endpoint and certificate preexistence state before
calling the native association adapter. The adapter still performs native TLS
chain, current-time, hostname and positive revocation validation. A failed
`locate` is not absence: a separate native absence check must succeed before
recording that the certificate did not previously exist.

`recover_staged` resolves the exact stored certificate and protected private key
after a completed add whose result was not saved. This recovers local staging
only; it does not extend expired UI consent or authorize peer admission.

Rollback deletes only exact newly-owned certificate/key objects. Reused/shared
host keys and certificates survive. Ambiguous/mismatched native objects or a
failed absence check leave the journal intact. Native deletion followed by a
crash is idempotently reconciled using strict absence and the original intent.
There is no remote boolean that can mark an object newly owned.

## Storage

One `enrollment.pending` record, a non-authoritative `.enrollment.next`, and a
never-unlinked owner lease use fixed app-owned names. The LPJ1 record is bounded
to 134,144 bytes; each of six public objects is <=64 KiB and their sum <=128 KiB.
Fields are canonical big-endian integers, closed enums and fixed-size identifiers.
SHA-256 detects record damage; it is **not** an authentication tag. OS ownership,
ACLs and exclusive local leases protect the record. No private key, password,
input text, clipboard content or remote filesystem path is stored.

Save requires revision 1 for a new transaction or precisely old+1 for the same
transaction. Corrupt authoritative records are never overwritten as empty state.
An incomplete owned staging file is discarded only under the exclusive lease;
it never becomes pairing truth. Other malformed, linked, oversized or unowned
objects fail closed rather than being repaired by weakening their protection.

Mac uses descriptor-relative no-follow I/O, user ownership, 0700 directory /
0600 files, single-link files, ACL checks, flock, file fsync, atomic rename and
directory fsync. Production shares the product `owner.lock` used by configuration
and program operations. The canonical installer must supply the protected root.

Windows uses protected CurrentUser/SYSTEM DACLs for the enrollment child,
owner/DACL/reparse/link checks, pinned ancestor handles, non-sharing lease
handles, FlushFileBuffers and MoveFileEx(write-through). Production also acquires
the installer's `maintenance/program-update.lock`; future activation must borrow
that lease rather than recursively acquiring it. The private enrollment child
is separate from legacy connection JSON. Explicit fixture factories never point
at installed configuration in tests.

## Verified scope and remaining integration

The native journal probe kills a real child holding the lease, then a new
process resumes the durable record. It also checks exclusion, revision/ID
conflicts, hard links, truncated/corrupt records and incomplete staging. Mac adds
symlink and weak-mode rejection. Native key/identity probes combine this real
protected journal with actual isolated CNG / standalone Keychain operations,
injecting interruption after native key/certificate creation but before receipt
save, then reopening/reconciling and safely rolling back. Injected exceptions
at these exact boundaries are not a power-loss test or a claim that every
intermediate OS API instruction has been interrupted.

The three local phases are `keys`, `association_intent`, `staged`. **Do not add a
PREPARED/COMMIT phase to this rollback-capable coordinator.** The separate
[durable completion](native-enrollment-completion.md) coordinator atomically
hands off to closed LPJ2 records with authenticated receipts/host decisions;
LPJ1 rollback rejects those records. The remaining integration must activate
remembered configuration only from its typed two-end completion proof.
Once a prepared receipt may have escaped, the client is in doubt and cannot
unilaterally delete its identity on timeout. A durable commit decision must roll
forward, including after restart; only authenticated abort permits rollback.
Remembered active connection/service configuration must wait for that protocol.
The existing <=120-second approval cannot simply be serialized as fresh consent
after reboot. This unit intentionally exposes no admission-ready flag.
