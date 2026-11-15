# Release convergence checklist

This is the current work queue, not a completion announcement. The local
research tree and installed personal pair remain separate from the public
candidate. No cleanup may destroy the only working installation.

| Requirement | Current evidence | Next gate |
| --- | --- | --- |
| Simplify architecture | Documented one desktop session / two TLS sockets / optional SSH; existing session admission retained | Audit launcher/profile/service owners and remove only proven redundant paths |
| Clean release source | Allowlisted current source exported, known-private-marker scan and Windows build/24 tests pass; missing installer resources fixed | Public commit CI, current-pair operational regression, obsolete entrypoint removal after replacement proof |
| Visual explanation | Editable SVG architecture illustration, rendered and inspected | Keep diagram synchronized with any runtime changes |
| GitHub and documentation | Candidate on the existing public history; README routes, index and implementation guides | Resolve CI findings, review candidate, then promote main; do not create a release tag before operational acceptance |
| Engineering learning material | Traditional Chinese study guide, source map, Q&A, exercises and measurement template | Reconcile any changed contracts before release |

## Next tasks, in order

1. Validate the exact public candidate with Windows/MSVC and native macOS CI.
   Preserve failing logs; fix the first blocking issue rather than weakening tests.
2. Produce matching personal packages from that identified source, with versions
   and SHA-256. Do not include personal connection profiles, identity references
   or machine-specific service configuration in a public download.
3. On the authorized existing pair, verify install/reinstall, saved connection,
   offline error, rapid reopen, input release, clipboard opt-in and safe close.
   Human OS consent and visual judgments stay with the user.
4. Verify update preservation and rollback. Only then retire redundant installed
   launchers/services. Keeping a tested compatibility path is not a release defect;
   silently exposing multiple competing default launchers is.
5. Promote the reviewed source to main and publish only the artifacts whose
   gates passed. Signed/public first-install acceptance remains distinct from
   unsigned, existing-pair personal acceptance.

## Deliberately unchanged

No codec replacement, QUIC migration, speculative RECT dependency chain,
permission bypass, new SSH keys, default clipboard enablement or destructive
identity cleanup is part of this convergence. The historical H.264 path remains
available. Transport separation alone is not evidence of a latency improvement.

For source, artifact, manual and operational acceptance details, use
[product status](product-status.md) and [install-once gates](install-once-release-acceptance.md).
