#pragma once

#include "rwn/transport/certificate_identity.hpp"
#include <chrono>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace rwn::transport {
inline constexpr std::string_view desktop_tcp_alpn = "lanpilot/tcp/1";
inline constexpr std::size_t tls_channel_write_limit = 64U * 1024U;

// One instance owns ONE TCP socket / TLS context, not a multiplexed stream.
// One reader and one writer may run concurrently. No application message
// boundaries are implied by TLS records; callers must assemble bounded frames.
// cancel() interrupts IO; join callers before destroying the channel.
class TlsByteChannel {
public:
    virtual ~TlsByteChannel() = default;
    [[nodiscard]] virtual const AuthenticatedPeerEvidence& peer() const noexcept = 0;
    virtual void write(std::span<const std::byte> bytes,
                       std::chrono::milliseconds timeout) = 0;
    [[nodiscard]] virtual std::vector<std::byte> read_some(
        std::chrono::milliseconds timeout) = 0;
    virtual void cancel() noexcept = 0;
    // Optional non-consuming wait, only at an application message boundary.
    // Partial encrypted records count as ready and retain their read deadline.
    // EOF/cancel wakes or throws. False means idle, not EOF. One reader only.
    [[nodiscard]] virtual bool wait_readable(std::chrono::milliseconds) {
        throw std::logic_error("TLS channel does not support idle readiness");
    }
};
} // namespace rwn::transport
