#include "rwn/transport/encrypted_fallback.hpp"

#include <algorithm>
#include <ranges>
#include <stdexcept>
#include <utility>

namespace rwn::transport {
namespace {

[[nodiscard]] bool all_zero(const auto& value) {
    return std::ranges::all_of(
        value, [](const auto byte) { return byte == 0; });
}

void validate_plane_evidence(
    const EncryptedPlaneEvidence& evidence,
    const EncryptedPlaneProtocol expected) {
    if (evidence.protocol != expected || !evidence.chain_validated ||
        !evidence.revocation_checked ||
        all_zero(evidence.peer_certificate_sha256) ||
        all_zero(evidence.channel_binding)) {
        throw std::invalid_argument(
            "encrypted fallback plane evidence is invalid");
    }
}

void validate_wait(const std::chrono::milliseconds timeout) {
    if (timeout < std::chrono::milliseconds{1} ||
        timeout > std::chrono::minutes{5}) {
        throw std::invalid_argument("fallback receive timeout is invalid");
    }
}

}  // namespace

EncryptedFallbackTransport::EncryptedFallbackTransport(
    std::unique_ptr<FallbackReliablePlane> reliable,
    std::unique_ptr<FallbackDatagramPlane> datagrams,
    const std::size_t maximum_datagram_bytes)
    : reliable_(std::move(reliable)), datagrams_(std::move(datagrams)),
      maximum_datagram_bytes_(maximum_datagram_bytes) {
    if (!reliable_ || !datagrams_ || maximum_datagram_bytes_ < 256 ||
        maximum_datagram_bytes_ > 64U * 1024U) {
        throw std::invalid_argument("encrypted fallback options are invalid");
    }
    const auto& reliable_evidence = reliable_->evidence();
    const auto& datagram_evidence = datagrams_->evidence();
    validate_plane_evidence(
        reliable_evidence, EncryptedPlaneProtocol::tls13);
    validate_plane_evidence(
        datagram_evidence, EncryptedPlaneProtocol::dtls12);
    if (reliable_evidence.peer_certificate_sha256 !=
            datagram_evidence.peer_certificate_sha256 ||
        reliable_evidence.channel_binding !=
            datagram_evidence.channel_binding) {
        throw std::invalid_argument(
            "fallback TLS and DTLS planes are not peer bound");
    }
}

std::unique_ptr<ReliableStream> EncryptedFallbackTransport::open_stream(
    const StreamPurpose purpose) {
    auto result = reliable_->open_stream(purpose);
    if (!result) throw std::runtime_error("fallback returned a null stream");
    return result;
}

AcceptedStream EncryptedFallbackTransport::accept_stream(
    const std::chrono::milliseconds timeout) {
    validate_wait(timeout);
    auto result = reliable_->accept_stream(timeout);
    if (!result.stream) {
        throw std::runtime_error("fallback accepted a null stream");
    }
    return result;
}

void EncryptedFallbackTransport::send_datagram(
    const DatagramChannel channel,
    const std::span<const std::byte> data) {
    if (data.empty() || data.size() > maximum_datagram_bytes_) {
        throw std::length_error("fallback datagram is outside bounds");
    }
    datagrams_->send_datagram(channel, data);
}

ReceivedDatagram EncryptedFallbackTransport::receive_datagram(
    const std::chrono::milliseconds timeout) {
    validate_wait(timeout);
    auto result = datagrams_->receive_datagram(timeout);
    if (result.payload.empty() ||
        result.payload.size() > maximum_datagram_bytes_ ||
        static_cast<std::uint8_t>(result.channel) >
            static_cast<std::uint8_t>(DatagramChannel::pointer)) {
        throw std::runtime_error(
            "fallback received an invalid datagram");
    }
    return result;
}

std::unique_ptr<Transport> EncryptedFallbackConnector::connect(
    const TransportMode mode, const TransportEndpoint& endpoint,
    const QuicTransportSettings& settings) {
    if (mode != TransportMode::tls_tcp_udp_fallback ||
        !settings.enable_fallback || !settings.require_tls13) {
        throw std::invalid_argument(
            "encrypted fallback connector mode is invalid");
    }
    validate_transport_endpoint(endpoint);
    validate_quic_transport_settings(settings);
    auto reliable = provider_.connect_tls13(endpoint, settings);
    auto datagrams = provider_.connect_dtls12(endpoint, settings);
    return std::make_unique<EncryptedFallbackTransport>(
        std::move(reliable), std::move(datagrams),
        settings.maximum_datagram_bytes);
}

bool EncryptedFallbackConnector::migrate(
    Transport&, const TransportEndpoint&) {
    return false;
}

std::unique_ptr<Transport> RoutedTransportConnector::connect(
    const TransportMode mode, const TransportEndpoint& endpoint,
    const QuicTransportSettings& settings) {
    return mode == TransportMode::quic
        ? primary_.connect(mode, endpoint, settings)
        : fallback_.connect(mode, endpoint, settings);
}

bool RoutedTransportConnector::migrate(
    Transport& transport, const TransportEndpoint& endpoint) {
    if (dynamic_cast<EncryptedFallbackTransport*>(&transport) != nullptr) {
        return fallback_.migrate(transport, endpoint);
    }
    return primary_.migrate(transport, endpoint);
}

}  // namespace rwn::transport
