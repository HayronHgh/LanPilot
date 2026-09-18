#include "rwn/transport/channel_session.hpp"

#include <algorithm>
#include <stdexcept>

namespace rwn::transport {
namespace {
template<class T> bool nonzero(const T& bytes) {
    return std::any_of(bytes.begin(), bytes.end(), [](auto b) { return b != 0; });
}
std::size_t index(TcpChannel channel) {
    const auto value = static_cast<unsigned>(channel);
    if (value < 1 || value > 2) throw std::invalid_argument("unknown TCP channel");
    return value - 1;
}
void validate(const ChannelHello& hello) {
    static_cast<void>(index(hello.channel));
    if (!nonzero(hello.session_id) || hello.generation == 0)
        throw std::invalid_argument("empty channel session identity");
}
}

std::array<std::byte, channel_hello_bytes> encode_channel_hello(const ChannelHello& hello) {
    validate(hello);
    std::array<std::byte, channel_hello_bytes> out{};
    out[0] = std::byte{'L'}; out[1] = std::byte{'P'};
    out[2] = std::byte{'T'}; out[3] = std::byte{'1'};
    out[4] = std::byte{1}; out[5] = static_cast<std::byte>(hello.channel);
    for (std::size_t i = 0; i < 16; ++i) out[8+i] = std::byte{hello.session_id[i]};
    for (std::size_t i = 0; i < 8; ++i)
        out[24+i] = std::byte{static_cast<std::uint8_t>(hello.generation >> ((7-i)*8))};
    return out;
}
ChannelHello decode_channel_hello(std::span<const std::byte> bytes) {
    if (bytes.size() != channel_hello_bytes || bytes[0] != std::byte{'L'} ||
        bytes[1] != std::byte{'P'} || bytes[2] != std::byte{'T'} ||
        bytes[3] != std::byte{'1'} || bytes[4] != std::byte{1} ||
        bytes[6] != std::byte{} || bytes[7] != std::byte{})
        throw std::invalid_argument("invalid channel hello framing");
    ChannelHello hello;
    hello.channel = static_cast<TcpChannel>(bytes[5]);
    for (std::size_t i = 0; i < 16; ++i)
        hello.session_id[i] = std::to_integer<std::uint8_t>(bytes[8+i]);
    for (std::size_t i = 0; i < 8; ++i)
        hello.generation = (hello.generation << 8) | std::to_integer<std::uint8_t>(bytes[24+i]);
    validate(hello);
    return hello;
}

std::array<std::byte, channel_admission_bytes> encode_channel_admission(const ChannelAdmission& admission) {
    validate({TcpChannel::visual, admission.session_id, admission.generation});
    if (!admission.grants.visual || !admission.grants.control)
        throw std::invalid_argument("desktop admission requires both channels");
    std::array<std::byte, channel_admission_bytes> out{};
    out[0]=std::byte{'L'}; out[1]=std::byte{'P'}; out[2]=std::byte{'A'}; out[3]=std::byte{'1'};
    out[4]=std::byte{1}; out[5]=admission.grants.desktop_input ? std::byte{7} : std::byte{3};
    for (std::size_t i=0;i<16;++i) out[8+i]=std::byte{admission.session_id[i]};
    for (std::size_t i=0;i<8;++i)
        out[24+i]=std::byte{static_cast<std::uint8_t>(admission.generation >> ((7-i)*8))};
    return out;
}
ChannelAdmission decode_channel_admission(std::span<const std::byte> bytes) {
    if (bytes.size()!=channel_admission_bytes || bytes[0]!=std::byte{'L'} || bytes[1]!=std::byte{'P'} ||
        bytes[2]!=std::byte{'A'} || bytes[3]!=std::byte{'1'} || bytes[4]!=std::byte{1} ||
        (bytes[5]!=std::byte{3} && bytes[5]!=std::byte{7}) || bytes[6]!=std::byte{} || bytes[7]!=std::byte{})
        throw std::invalid_argument("invalid desktop admission framing");
    ChannelAdmission result;
    result.grants={true,true,bytes[5]==std::byte{7}};
    for (std::size_t i=0;i<16;++i) result.session_id[i]=std::to_integer<std::uint8_t>(bytes[8+i]);
    for (std::size_t i=0;i<8;++i) result.generation=(result.generation<<8)|std::to_integer<std::uint8_t>(bytes[24+i]);
    validate({TcpChannel::visual,result.session_id,result.generation});
    return result;
}
void validate_channel_admission(const ChannelAdmission& admission, const ChannelHello& issued, bool request_input) {
    static_cast<void>(encode_channel_admission(admission));
    validate(issued);
    if (issued.channel!=TcpChannel::visual || admission.session_id!=issued.session_id ||
        admission.generation!=issued.generation)
        throw std::invalid_argument("desktop admission session mismatch");
    if (request_input && !admission.grants.desktop_input)
        throw std::invalid_argument("Mac grants view-only; interactive control was not authorized");
}

TcpChannelSession::TcpChannelSession(ChannelSessionId id, std::uint64_t generation,
    CertificateSha256 peer, ChannelGrants grants, Clock::time_point expires_at)
    : id_(id), generation_(generation), peer_(peer), grants_(grants), expires_at_(expires_at) {
    validate({TcpChannel::visual, id_, generation_});
    if (!nonzero(peer_)) throw std::invalid_argument("empty authorized peer");
    if (grants_.desktop_input && !grants_.control)
        throw std::invalid_argument("input requires a control channel grant");
}
bool TcpChannelSession::attach(const ChannelHello& hello,
    const AuthenticatedPeerEvidence& verified_peer, std::uint64_t connection_id,
    Clock::time_point now) {
    validate(hello);
    validate_authenticated_peer_evidence(verified_peer);
    const auto slot = index(hello.channel);
    const std::array allowed{grants_.visual, grants_.control};
    if (revoked_ || now >= expires_at_ || hello.session_id != id_ ||
        hello.generation != generation_ || verified_peer.certificate_sha256 != peer_ ||
        !allowed[slot] || connection_id == 0 || connections_[slot] != 0 ||
        std::find(connections_.begin(), connections_.end(), connection_id) != connections_.end())
        return false;
    connections_[slot] = connection_id;
    return true;
}
bool TcpChannelSession::active(TcpChannel channel, std::uint64_t connection_id,
    Clock::time_point now) const {
    return !revoked_ && now < expires_at_ && connection_id != 0 &&
        connections_[index(channel)] == connection_id;
}
void TcpChannelSession::disconnect(std::uint64_t connection_id) {
    if (connection_id == 0) return;
    if (connections_[0] == connection_id || connections_[1] == connection_id) revoke();
}
bool TcpChannelSession::input_allowed(std::uint64_t connection_id, Clock::time_point now) const {
    return grants_.desktop_input && connections_[0] != 0 &&
        active(TcpChannel::control, connection_id, now);
}
void TcpChannelSession::revoke() noexcept {
    revoked_ = true;
    connections_.fill(0);
}
} // namespace rwn::transport
