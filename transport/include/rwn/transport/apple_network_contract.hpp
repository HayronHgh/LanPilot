#pragma once

#include "rwn/transport/certificate_identity.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace rwn::transport {

struct AppleNetworkIdentityOptions {
    std::vector<std::byte> keychain_persistent_reference;
    std::vector<CertificateSha256> allowed_peer_certificate_sha256;
};

struct AppleNetworkClientOptions {
    AppleNetworkIdentityOptions identity;
    std::chrono::milliseconds connect_timeout{10'000};
    std::chrono::milliseconds stream_read_timeout{30'000};
    std::size_t maximum_pending_streams{64};
    std::size_t maximum_pending_datagrams{256};
    std::size_t maximum_queued_bytes{32U * 1024U * 1024U};
};

struct AppleNetworkServerOptions {
    AppleNetworkIdentityOptions identity;
    std::uint16_t listen_port{};
    std::chrono::milliseconds stream_read_timeout{30'000};
    std::size_t maximum_pending_connections{64};
    std::size_t maximum_pending_streams{64};
    std::size_t maximum_pending_datagrams{256};
    std::size_t maximum_queued_bytes{32U * 1024U * 1024U};
};

[[nodiscard]] CertificateSha256 parse_apple_network_sha256_fingerprint(
    std::string_view value);
[[nodiscard]] bool apple_network_peer_allowed(
    std::span<const CertificateSha256> allowlist,
    const CertificateSha256& fingerprint) noexcept;
void validate_apple_network_client_options(
    const AppleNetworkClientOptions& options);
void validate_apple_network_server_options(
    const AppleNetworkServerOptions& options);

}  // namespace rwn::transport
