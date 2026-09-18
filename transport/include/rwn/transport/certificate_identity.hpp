#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>

namespace rwn::transport {

using CertificateSha256 = std::array<std::uint8_t, 32>;

struct AuthenticatedPeerEvidence {
    CertificateSha256 certificate_sha256{};
    bool tls_1_3_negotiated{};
    bool certificate_chain_valid{};
    bool revocation_checked{};
};

void validate_authenticated_peer_evidence(
    const AuthenticatedPeerEvidence& evidence);
[[nodiscard]] std::string certificate_sha256_hex(
    const CertificateSha256& fingerprint);
[[nodiscard]] AuthenticatedPeerEvidence single_allowed_peer_evidence(
    std::span<const CertificateSha256> allowlist);

}  // namespace rwn::transport
