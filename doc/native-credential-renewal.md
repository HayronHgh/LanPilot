# Paired credentials that renew without re-enrollment

The durable pairing identifies three fixed P-256 public keys (authority,Mac,
Windows),roles,endpoint and local native key references. Leaf/root certificates
are renewable credentials for those SAME keys. Renewal cannot replace a key,
change endpoint,grant input/clipboard/SSH or revive an expired comparison UI.
The immutable original LPJ2,profile and six initial public resources remain the
bootstrap authority. Legacy schema1 provisioning keeps its existing behavior.

## Authenticated credential snapshots

LPQ1 still requests the exact saved round/transcript/original certificate hashes.
LPS1 remains the three-object revocation-only format. LPS2 carries all six public
objects:root,server,client,CRL,server OCSP,client OCSP. Version2 uses a separate
signature domain. Each object's hash and length,the original160-byte pairing
scope and issue/expiry times are covered by the original native authority key's
signature. Individual DER65536,combined131072 and total wire131104 byte caps
apply before allocation. No path,private key or store selector is accepted.

All three new certificate profiles AND public keys must match the original
pairing. A signature from the authority does not authorize changing the device
keys. Native positive chain/revocation/time/hostname checks remain mandatory.
Changed certificates must advance validity rather than roll back a known
credential. Status issue times are monotonic and identical replay is idempotent.
Unknown versions,other-session scopes,wrong device keys,damage and oversize
messages fail closed. An expired status is only a signed anti-replay counter,
never connection evidence.

The native issuer renews leaves below30days remaining and roots below365days,
with default180day/3650day lifetimes. Root renewal uses the same permanently
pinned authority public key. This is an explicit authenticated same-key
credential transition,not trusting a newly discovered root or disabling native
TLS validation. Application certificates are not added to system root trust.
The host selects the current certificate snapshot. Each endpoint commits its
own native association atomically;TLS mutually proves the unchanged device keys
before granting a session. An offline client may fetch a later snapshot directly.
Initial enrollment supports bounded host-owned shorter lifetime policies for
isolated expiry tests;the normal UI uses the fixed defaults.

## Atomic native association and bounded cleanup

`CredentialInstaller` holds the existing protected product lease and uses
`credential.current` plus `credential.retired`. Both contain bounded existing
LPJ1 local association records;the original LPJ2 is never rewritten. Every key
intent must reference the original EXISTING native key and match its public
point. No new-key/delete-key path is available during renewal. Missing keys
fail;an expired/missing old certificate alone does not require a replacement key.

Before native certificate add,the installer persists the exact target and
whether that certificate already existed. Lost add receipts reconcile by exact
certificate/key lookup. The previous owned certificate is archived durably
before clearing its slot,and retained until the new identity is usable. Crash
recovery covers archive-before-clear,clear-before-add,and add-before-receipt.
The new native reference is returned only after its current record is durable
and real private-key possession succeeds. Retired cleanup removes only exact
newly-owned certificates;private keys and preexisting/shared certificates remain.
An adopted original anchor certificate is retained. At most one current and one
retired/pending renewal record exist per role;new generations do not accumulate
an unbounded certificate history. Unsafe/ambiguous ownership stops cleanup.

The native file implementations preserve owner/ACL checks,no reparse/symlink
traversal,single links,bounded interrupted staging,flush and atomic replacement.
Neither files nor lookup references are derived from a remote filename.

## Real product entry points

For schema2 native profiles,the Windows launcher allows renewal when the old
certificate is expired or absent. This is launcher eligibility only,not TLS
admission. Wrong EKU,CA identities,not-yet-valid present certificates and
public-only present identities remain rejected. Viewer authenticates the
protected original journal/profile and existing key,fetches the current signed
snapshot,installs its native client certificate,and builds native TLS options
with the authenticated current root/server fingerprint/client reference/CRL.
The original remembered profile is not rewritten. A connection always refreshes
selected certificates because the server may have restarted with a new valid
generation;only still-valid cached evidence may be an offline fallback.
Configuration recovery uses a fresh native private-key possession challenge
and the original complete signed pairing when the old certificate is expired
or absent. Saving public bootstrap settings does not require live revocation
evidence or network access. Its descriptor-only proof cannot authorize TLS.
The normal connection must still fetch/verify current credentials and pass
native TLS. Recovery reconstructs the original bootstrap descriptors and public
resources,not fresh peer pins or user choices. Tests combine missing profile,
missing original certificate and expired status;unavailable key proof prevents
publication and leaves the existing data unchanged.

The Mac configured service validates its saved bootstrap anchors,issues or
reopens current credentials,installs its current native server identity and
uses those bytes before binding TLS. This does not change the saved OS grant,
visual/control policy or installed application. Background Keychain prompts are
disabled. Its incarnation keeps server/root/client certificate selection fixed;
ordinary status refresh updates only revocation evidence. Approaching renewal
requests the existing normal cancellation/input-release shutdown,then the native
login service restarts with renewed credentials. This can interrupt a session;
it is not a claim of seamless live TLS credential replacement. Local cursor,
capture/codec/presentation and transport channels are otherwise unchanged.

## Acceptance scope

### Recovering a decided pairing after certificate replacement

The original certificate can be absent after renewal while an old pairing
completion still needs receipt replay. A resumed journal with a verified,
irrevocable signed COMMIT_DECISION may drain its remaining receipts using a fresh
native possession proof for the exact original device key. Complete replay can
produce only a bootstrap configuration descriptor when the original certificate
is unavailable or not ready. Current TLS admission still requires separately
renewed, native-verified credentials.

This fallback is unavailable to a live approval path or a PREPARED-only journal.
It never creates another commit decision, revives consent, replaces a key or
imports a certificate. Missing key proof, wrong identities, invalid receipts and
replayed recovery challenges remain errors. Native fixtures remove both original
certificates and exercise actual socket recovery from COMMIT_DECISION, including
denied key proofs, unchanged decision bytes and fresh-challenge replay rejection.

Native fixtures use actual isolated CNG/memory certificate stores or explicit
temporary Mac Keychains. They cover two certificate generations,root/leaf renewal,
original certificate removal,nonreplacement of keys,wrong-key signed packages,
replay,hard links,archive interruption,and before/after-add recovery. The explicit
two-host `credential-renewal` fixture starts with short-lived host policy,renews
at actual time,exchanges LPS2,reopens native associations and checks matching
current public certificate hashes. Synthetic confirmation is test-only. Neither
system clock changes. These probes alone do not prove installed-app direct LAN,
a renewed installed TLS desktop session or six months of elapsed operation.

Real new-account installation,one-time OS consent,Developer ID signing continuity,
service activation/reboot,signed in-place updates and automatic reconnect after
normal session expiry remain independent release gates. Do not silently remove
these gates or retire the existing installation based on library tests alone.
