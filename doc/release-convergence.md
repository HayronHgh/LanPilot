# Release convergence checklist

This is the current work queue, not a completion announcement. The local
research tree and installed personal pair remain separate from the public
candidate. No cleanup may destroy the only working installation.

The owner selected the stable latest architecture as the main line. Preserve
the installed visual/control choices and the previous public source in
[`legacy/pre-convergence-20261115`](https://github.com/HayronHgh/LanPilot/tree/legacy/pre-convergence-20261115).
Promote source after CI; installer/public-distribution acceptance is a separate
gate, not a reason to downgrade the current architecture.

| Requirement | Current evidence | Next gate |
| --- | --- | --- |
| Simplify architecture | One desktop session / two TLS sockets / optional SSH; unused transport chooser removed; selected settings-root regression fixed | Retire installed legacy service only after replacement and rollback proof |
| Clean release source | Allowlisted export, privacy checks, Windows/MSVC and Mac universal2 CI pass; missing installer resources fixed | Same-source personal packages and installation/update acceptance |
| Visual explanation | Product cover plus editable architecture SVG, rendered and inspected | Keep assets synchronized with actual supported platforms |
| GitHub and documentation | Latest source on existing public history; old main archived; bilingual homepage and implementation guides | Promote tested source to main; installer release tags require their own acceptance |
| Engineering learning material | Traditional Chinese study guide, source map, Q&A, exercises and measurement template | Reconcile any changed contracts before release |

## Next tasks, in order

1. Promote the reviewed latest source after Windows/MSVC and Mac universal2 CI.
   The routing fix passed both jobs in run 43668835646; verify the final documentation
   head as well. Retain English commits and the archived previous public source.
2. Produce matching personal packages from that identified source, with versions
   and SHA-256. Do not include personal connection profiles, identity references
   or machine-specific service configuration in a public download.
3. On the authorized existing pair, verify install/reinstall, saved connection,
   offline error, rapid reopen, input release, clipboard opt-in and safe close.
   Human OS consent and visual judgments stay with the user.
4. Verify update preservation and rollback. Only then retire redundant installed
   launchers/services. Keeping a tested compatibility path is not a release defect;
   silently exposing multiple competing default launchers is.
5. Publish only the installer artifacts whose gates passed. Signed/public
   first-install acceptance remains distinct from unsigned, existing-pair
   personal acceptance. Source on main is not a claim of completed distribution
   acceptance.

## Deliberately unchanged

No codec replacement, QUIC migration, speculative RECT dependency chain,
permission bypass, new SSH keys, default clipboard enablement or destructive
identity cleanup is part of this convergence. The historical H.264 path remains
available. Transport separation alone is not evidence of a latency improvement.

For source, artifact, manual and operational acceptance details, use
[product status](product-status.md) and [install-once gates](install-once-release-acceptance.md).
