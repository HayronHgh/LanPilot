#include "rwn/transport/certificate_identity.hpp"

#include <algorithm>
#include <iomanip>
#include <ranges>
#include <sstream>
#include <stdexcept>

namespace rwn::transport {
namespace {

[[nodiscard]] bool all_zero(
    const CertificateSha256& fingerprint) noexcept {
    return std::ranges::all_of(
        fingerprint, [](const auto byte) { return byte == 0; });
}

}  // namespace

void validate_authenticated_peer_evidence(
    const AuthenticatedPeerEvidence& evidence) {
    if (all_zero(evidence.certificate_sha256) ||
        !evidence.tls_1_3_negotiated ||
        !evidence.certificate_chain_valid ||
        !evidence.revocation_checked) {
        throw std::invalid_argument(
            "authenticated peer evidence is incomplete");
    }
}

std::string certificate_sha256_hex(
    const CertificateSha256& fingerprint) {
    if (all_zero(fingerprint)) {
        throw std::invalid_argument(
            "certificate SHA-256 fingerprint cannot be zero");
    }
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const auto byte : fingerprint) {
        output << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return output.str();
}

AuthenticatedPeerEvidence single_allowed_peer_evidence(
    const std::span<const CertificateSha256> allowlist) {
    if (allowlist.size() != 1 || all_zero(allowlist.front())) {
        throw std::invalid_argument(
            "v0.1 authenticated listener requires exactly one allowed peer");
    }
    return {
        .certificate_sha256 = allowlist.front(),
        .tls_1_3_negotiated = true,
        .certificate_chain_valid = true,
        .revocation_checked = true,
    };
}

}  // namespace rwn::transport
