#pragma once

#include "rwn/transport/encrypted_fallback.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace rwn::platform::windows {

struct SchannelFallbackClientOptions {
    std::array<std::uint8_t, 20> client_certificate_sha1{};
    std::vector<std::array<std::uint8_t, 32>>
        allowed_server_certificate_sha256;
    std::wstring certificate_store_name{L"MY"};
    bool certificate_in_machine_store{};
    std::chrono::milliseconds connect_timeout{10'000};
    std::chrono::milliseconds io_timeout{30'000};
    std::size_t maximum_streams{64};
    std::size_t maximum_queued_stream_messages{256};
    std::size_t maximum_queued_stream_bytes{32U * 1024U * 1024U};
};

void validate_schannel_fallback_client_options(
    const SchannelFallbackClientOptions& options);

[[nodiscard]] std::array<std::uint8_t, 20>
parse_schannel_sha1_thumbprint(std::string_view value);
[[nodiscard]] std::array<std::uint8_t, 32>
parse_schannel_sha256_fingerprint(std::string_view value);

class SchannelFallbackClientProvider final
    : public rwn::transport::EncryptedFallbackProvider {
public:
    explicit SchannelFallbackClientProvider(
        SchannelFallbackClientOptions options);
    ~SchannelFallbackClientProvider() override;

    SchannelFallbackClientProvider(
        SchannelFallbackClientProvider&&) noexcept;
    SchannelFallbackClientProvider& operator=(
        SchannelFallbackClientProvider&&) noexcept;
    SchannelFallbackClientProvider(
        const SchannelFallbackClientProvider&) = delete;
    SchannelFallbackClientProvider& operator=(
        const SchannelFallbackClientProvider&) = delete;

    [[nodiscard]] std::unique_ptr<rwn::transport::FallbackReliablePlane>
    connect_tls13(
        const rwn::transport::TransportEndpoint& endpoint,
        const rwn::transport::QuicTransportSettings& settings) override;
    [[nodiscard]] std::unique_ptr<rwn::transport::FallbackDatagramPlane>
    connect_dtls12(
        const rwn::transport::TransportEndpoint& endpoint,
        const rwn::transport::QuicTransportSettings& settings) override;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace rwn::platform::windows
