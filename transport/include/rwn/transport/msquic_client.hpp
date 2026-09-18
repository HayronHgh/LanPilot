#pragma once

#include "rwn/transport/resilient_transport.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string_view>
#include <vector>

namespace rwn::transport {

struct MsQuicRuntimeInfo {
    std::array<std::uint32_t, 4> library_version{};
    std::filesystem::path loaded_library;
};

struct MsQuicClientOptions {
    std::filesystem::path runtime_library;
    std::array<std::uint8_t, 20> client_certificate_sha1{};
    std::vector<CertificateSha256> allowed_server_certificate_sha256;
    std::chrono::milliseconds connect_timeout{10'000};
    std::chrono::milliseconds stream_read_timeout{30'000};
};

[[nodiscard]] std::array<std::uint8_t, 20> parse_sha1_thumbprint(
    std::string_view value);

[[nodiscard]] MsQuicRuntimeInfo probe_msquic_runtime(
    const std::filesystem::path& runtime_library);
void validate_msquic_client_options(const MsQuicClientOptions& options);

class MsQuicClientConnector final : public TransportConnector {
public:
    explicit MsQuicClientConnector(MsQuicClientOptions options);
    ~MsQuicClientConnector() override;

    MsQuicClientConnector(const MsQuicClientConnector&) = delete;
    MsQuicClientConnector& operator=(const MsQuicClientConnector&) = delete;
    MsQuicClientConnector(MsQuicClientConnector&&) noexcept;
    MsQuicClientConnector& operator=(MsQuicClientConnector&&) noexcept;

    [[nodiscard]] std::unique_ptr<Transport> connect(
        TransportMode mode, const TransportEndpoint& endpoint,
        const QuicTransportSettings& settings) override;
    [[nodiscard]] bool migrate(
        Transport& transport, const TransportEndpoint& endpoint) override;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace rwn::transport
