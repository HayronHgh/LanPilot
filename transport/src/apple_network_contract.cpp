#include "rwn/transport/apple_network_contract.hpp"

#include <algorithm>
#include <array>
#include <ranges>
#include <stdexcept>

namespace rwn::transport {
namespace {

constexpr std::size_t maximum_persistent_reference_bytes = 4096;
constexpr std::size_t maximum_peer_identities = 64;

[[nodiscard]] std::uint8_t hex_nibble(const char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<std::uint8_t>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<std::uint8_t>(value - 'a' + 10);
    }
    if (value >= 'A' && value <= 'F') {
        return static_cast<std::uint8_t>(value - 'A' + 10);
    }
    throw std::invalid_argument(
        "Apple Network certificate fingerprint must be hexadecimal");
}

[[nodiscard]] bool all_zero(const CertificateSha256& value) noexcept {
    return std::ranges::all_of(
        value, [](const auto item) { return item == 0; });
}

void validate_identity(const AppleNetworkIdentityOptions& identity) {
    if (identity.keychain_persistent_reference.empty() ||
        identity.keychain_persistent_reference.size() >
            maximum_persistent_reference_bytes) {
        throw std::invalid_argument(
            "Apple Network identity requires a bounded Keychain persistent reference");
    }
    if (identity.allowed_peer_certificate_sha256.empty() ||
        identity.allowed_peer_certificate_sha256.size() >
            maximum_peer_identities) {
        throw std::invalid_argument(
            "Apple Network identity requires a bounded peer allowlist");
    }
    for (auto first = identity.allowed_peer_certificate_sha256.begin();
         first != identity.allowed_peer_certificate_sha256.end(); ++first) {
        if (all_zero(*first)) {
            throw std::invalid_argument(
                "Apple Network peer certificate fingerprint cannot be zero");
        }
        if (std::find(
                std::next(first),
                identity.allowed_peer_certificate_sha256.end(), *first) !=
            identity.allowed_peer_certificate_sha256.end()) {
            throw std::invalid_argument(
                "Apple Network peer certificate fingerprints must be unique");
        }
    }
}

void validate_runtime_bounds(
    const std::chrono::milliseconds stream_read_timeout,
    const std::size_t maximum_pending_streams,
    const std::size_t maximum_pending_datagrams,
    const std::size_t maximum_queued_bytes) {
    if (stream_read_timeout < std::chrono::milliseconds{1} ||
        stream_read_timeout > std::chrono::minutes{5}) {
        throw std::invalid_argument(
            "Apple Network stream read timeout is outside the allowed range");
    }
    if (maximum_pending_streams == 0 || maximum_pending_streams > 1024 ||
        maximum_pending_datagrams == 0 ||
        maximum_pending_datagrams > 4096 || maximum_queued_bytes == 0 ||
        maximum_queued_bytes > 256U * 1024U * 1024U) {
        throw std::invalid_argument(
            "Apple Network queue bounds are outside the allowed range");
    }
}

}  // namespace

CertificateSha256 parse_apple_network_sha256_fingerprint(
    const std::string_view value) {
    if (value.size() != CertificateSha256{}.size() * 2) {
        throw std::invalid_argument(
            "Apple Network certificate fingerprint must contain 64 hexadecimal characters");
    }
    CertificateSha256 parsed{};
    for (std::size_t index = 0; index < parsed.size(); ++index) {
        parsed[index] = static_cast<std::uint8_t>(
            (hex_nibble(value[index * 2]) << 4U) |
            hex_nibble(value[index * 2 + 1]));
    }
    if (all_zero(parsed)) {
        throw std::invalid_argument(
            "Apple Network certificate fingerprint cannot be zero");
    }
    return parsed;
}

bool apple_network_peer_allowed(
    const std::span<const CertificateSha256> allowlist,
    const CertificateSha256& fingerprint) noexcept {
    return std::ranges::find(allowlist, fingerprint) != allowlist.end();
}

void validate_apple_network_client_options(
    const AppleNetworkClientOptions& options) {
    validate_identity(options.identity);
    if (options.connect_timeout < std::chrono::milliseconds{1} ||
        options.connect_timeout > std::chrono::minutes{2}) {
        throw std::invalid_argument(
            "Apple Network connect timeout is outside the allowed range");
    }
    validate_runtime_bounds(
        options.stream_read_timeout, options.maximum_pending_streams,
        options.maximum_pending_datagrams, options.maximum_queued_bytes);
}

void validate_apple_network_server_options(
    const AppleNetworkServerOptions& options) {
    validate_identity(options.identity);
    if (options.listen_port == 0 || options.maximum_pending_connections == 0 ||
        options.maximum_pending_connections > 1024) {
        throw std::invalid_argument(
            "Apple Network server listener bounds are invalid");
    }
    validate_runtime_bounds(
        options.stream_read_timeout, options.maximum_pending_streams,
        options.maximum_pending_datagrams, options.maximum_queued_bytes);
}

}  // namespace rwn::transport
