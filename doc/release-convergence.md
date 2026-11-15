# Release convergence checklist

Updated 2026-11-15. This is the remaining work queue, not a release announcement. The local
research tree and installed personal pair remain separate from the public
candidate. No cleanup may destroy the only working installation.

The owner selected the stable latest architecture as the main line. Preserve
the installed visual/control choices and the previous public source in
[`legacy/pre-convergence-20261115`](https://github.com/HayronHgh/LanPilot/tree/legacy/pre-convergence-20261115).
The reviewed latest source is already on `main` through PRs
[#1](https://github.com/HayronHgh/LanPilot/pull/1) and
[#2](https://github.com/HayronHgh/LanPilot/pull/2); the personal-package evidence
was added in [#3](https://github.com/HayronHgh/LanPilot/pull/3).
Installer/public-distribution acceptance is a separate gate, not a reason to
downgrade the current architecture.

| Requirement | Current evidence | Next gate |
| --- | --- | --- |
| Simplify architecture | One desktop session / two TLS sockets / optional SSH; unused transport chooser removed; selected settings-root regression fixed | Retire installed legacy service only after replacement and rollback proof |
| Clean release source | 416-file allowlisted export; Windows/MSVC 25/25 and Mac universal2 26/26 CI; product bundle limited to installer/README/LICENSE | Runtime provenance and installation/update acceptance of the candidate to be distributed |
| Visual explanation | Product cover plus editable architecture SVG, rendered and inspected | Keep assets synchronized with actual supported platforms |
| GitHub and documentation | Latest source merged into main; old main archived; English commits, bilingual homepage and implementation guides | Installer release tags require artifact-specific acceptance |
| Engineering learning material | Traditional Chinese study guide, source map, Q&A, exercises and measurement template | Reconcile any changed contracts before release |

## Delivered personal pair versus public source

The package source at `c1ce3e1800985d6dd639a1c349b0480ae00a01b6` passed
[both native CI jobs](https://github.com/HayronHgh/LanPilot/actions/runs/43670546922).
Private existing-pair installers have been delivered. Their archive integrity,
saved-identity prerequisites and two native TLS handshakes passed without
installing, sending input or reading desktop payloads. Actual owner installation
and connection acceptance remains pending.

Those personal packages intentionally retain the installed stable Viewer/agent
bytes. Their original runtime source revisions are not established by the new
packaging commit. Record installer source and runtime provenance separately;
see [personal artifact provenance](personal-installers.md#artifact-provenance-and-acceptance).
Even successful manual acceptance of this pair would not prove that both runtime
binaries were built from the public candidate source.

## Next tasks, in order

1. On the delivered existing-pair installers, verify install/reinstall, saved connection,
   offline error, rapid reopen, input release, clipboard opt-in and safe close.
   Human OS consent and visual judgments stay with the user.
2. Verify update preservation and rollback. Only then retire redundant installed
   launchers/services. Keeping a tested compatibility path is not a release defect;
   silently exposing multiple competing default launchers is.
3. Before public binary distribution, produce both runtime artifacts from one
   identified exported source and record toolchains, versions and SHA-256.
   Verify installation and behavior of those exact artifacts; do not transfer
   the stable personal pair's acceptance to different binaries. Keep personal
   connection profiles, identity references, machine-specific service configuration
   and private build artifacts out of public downloads.
4. Publish only the installer artifacts whose gates passed. Signed/public
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
