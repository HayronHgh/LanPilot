#pragma once

#include "rwn/transport/certificate_identity.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>

namespace rwn::transport {

enum class TcpChannel : std::uint8_t { visual = 1, control = 2 };
using ChannelSessionId = std::array<std::uint8_t, 16>;

// Sent only AFTER a mutually authenticated TLS 1.3 handshake. This header
// identifies a session; it is not a credential and cannot authorize a peer.
struct ChannelHello {
    TcpChannel channel{};
    ChannelSessionId session_id{};
    std::uint64_t generation{};
};
inline constexpr std::size_t channel_hello_bytes = 32;
[[nodiscard]] std::array<std::byte, channel_hello_bytes> encode_channel_hello(
    const ChannelHello& hello);
[[nodiscard]] ChannelHello decode_channel_hello(std::span<const std::byte> bytes);

struct ChannelGrants {
    bool visual{};
    bool control{};
    // RWC1 ACK/recovery is allowed in view-only mode. Input is a separate,
    // locally authorized capability and never implied by socket admission.
    bool desktop_input{};
};

// Server-to-client only, on authenticated control TLS after both role echoes.
// Describes server-local grants; never accepted as authorization by the server.
struct ChannelAdmission {
    ChannelSessionId session_id{};
    std::uint64_t generation{};
    ChannelGrants grants{};
};
inline constexpr std::size_t channel_admission_bytes = 32;
[[nodiscard]] std::array<std::byte, channel_admission_bytes> encode_channel_admission(const ChannelAdmission&);
[[nodiscard]] ChannelAdmission decode_channel_admission(std::span<const std::byte>);
void validate_channel_admission(const ChannelAdmission&, const ChannelHello& issued, bool request_input);

// Owned by the session admission coordinator, not called concurrently.
// Inputs must come from native TLS verification and the local authorization
// service, never from claimed certificate/grant fields in network messages.
class TcpChannelSession {
public:
    using Clock = std::chrono::steady_clock;
    TcpChannelSession(ChannelSessionId id, std::uint64_t generation,
                      CertificateSha256 peer, ChannelGrants grants,
                      Clock::time_point expires_at);
    [[nodiscard]] bool attach(const ChannelHello& hello,
                              const AuthenticatedPeerEvidence& verified_peer,
                              std::uint64_t local_connection_id,
                              Clock::time_point now);
    [[nodiscard]] bool active(TcpChannel channel, std::uint64_t connection_id,
                              Clock::time_point now) const;
    [[nodiscard]] bool input_allowed(std::uint64_t connection_id,
                                     Clock::time_point now) const;
    // Losing either desktop channel invalidates ALL bindings. The runtime
    // must also release pressed input and cancel pending framebuffer state.
    void disconnect(std::uint64_t connection_id);
    void revoke() noexcept;
    [[nodiscard]] bool revoked() const noexcept { return revoked_; }

private:
    ChannelSessionId id_;
    std::uint64_t generation_;
    CertificateSha256 peer_;
    ChannelGrants grants_;
    Clock::time_point expires_at_;
    std::array<std::uint64_t, 2> connections_{};
    bool revoked_{};
};

} // namespace rwn::transport
