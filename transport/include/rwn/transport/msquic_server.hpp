#pragma once

#include "rwn/transport/certificate_identity.hpp"
#include "rwn/transport/transport.hpp"
#include "rwn/transport/resilient_transport.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace rwn::transport {

struct MsQuicServerOptions {
    std::filesystem::path runtime_library;
    std::array<std::uint8_t, 20> server_certificate_sha1{};
    std::vector<CertificateSha256> allowed_client_certificate_sha256;
    std::uint16_t listen_port{};
    bool certificate_in_machine_store{true};
    std::chrono::milliseconds stream_read_timeout{30'000};
    std::size_t maximum_pending_connections{64};
};

[[nodiscard]] CertificateSha256 parse_sha256_fingerprint(
    std::string_view value);
[[nodiscard]] bool client_certificate_allowed(
    std::span<const CertificateSha256> allowlist,
    const CertificateSha256& fingerprint) noexcept;
void validate_msquic_server_options(const MsQuicServerOptions& options);

class MsQuicServerListener final {
public:
    MsQuicServerListener(
        MsQuicServerOptions options,
        QuicTransportSettings settings = {});
    ~MsQuicServerListener();

    MsQuicServerListener(const MsQuicServerListener&) = delete;
    MsQuicServerListener& operator=(const MsQuicServerListener&) = delete;
    MsQuicServerListener(MsQuicServerListener&&) noexcept;
    MsQuicServerListener& operator=(MsQuicServerListener&&) noexcept;

    [[nodiscard]] AuthenticatedConnection accept(
        std::chrono::milliseconds timeout);
    [[nodiscard]] std::uint16_t listen_port() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace rwn::transport
