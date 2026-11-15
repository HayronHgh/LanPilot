# LanPilot documentation

Start here. Dated engineering reports are historical evidence, not current
release acceptance. The current source, its CI and the identified installation
under test determine whether a feature is ready.

| Need | Read |
| --- | --- |
| What works / what still needs proof | [Product status](product-status.md) |
| Architecture and simplification | [One desktop session, optional SSH](architecture.md) |
| Prepare for a technical review | [Engineering study guide — 繁體中文](engineering-study-guide.zh-TW.md) |
| Test the existing paired computers | [Personal installers](personal-installers.md) |
| Build source and package components | [Public build guide](public-guide.md) |
| Understand legacy SSH installation | [SSH desktop preview](desktop-preview-install.md) |
| Understand the native Mac package | [macOS Installer](macos-native-installer.md) |
| Track the current cleanup | [Release convergence](release-convergence.md) |
| Final operational acceptance | [Install-once gates](install-once-release-acceptance.md) |
| Historical version boundaries | [v0.1 / v0.2 / v0.3](public-releases.md) |

## Focused implementation contracts

- Connection lifetime: [reconnect](session-reconnect.md), [agent shutdown](agent-shutdown.md).
- Platform ownership: [Windows install/update](windows-install-lifecycle.md),
  [Mac lifecycle](mac-application-lifecycle.md), [Mac updates](mac-program-updates.md),
  [Mac service quiescence](mac-service-quiescence.md).
- Pairing: [identity](native-enrollment-identity.md), [consent protocol](native-enrollment-pairing.md),
  [certificates](native-enrollment-certificates.md), [journal](native-enrollment-journal.md),
  [completion](native-enrollment-completion.md), [configuration](native-enrollment-configuration.md),
  [setup and recovery](native-enrollment-setup.md).
- Persistent trust: [status renewal](native-status-renewal.md),
  [credential renewal](native-credential-renewal.md), [TLS setup boundaries](tls-setup-security.md).

These describe implementation contracts. A successful unit test does not mean a
fresh user's installation, macOS consent, real input or physical display timing
has been accepted. Do not ship developer identities or ask users to disable
system security protections to make setup appear successful.
