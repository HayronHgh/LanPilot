#pragma once

#include "rwn/transport/resilient_transport.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace rwn::transport {

enum class EncryptedPlaneProtocol : std::uint8_t { tls13, dtls12 };

struct EncryptedPlaneEvidence {
    EncryptedPlaneProtocol protocol{EncryptedPlaneProtocol::tls13};
    std::array<std::uint8_t, 32> peer_certificate_sha256{};
    std::array<std::uint8_t, 32> channel_binding{};
    bool chain_validated{};
    bool revocation_checked{};
};

class FallbackReliablePlane {
public:
    virtual ~FallbackReliablePlane() = default;
    [[nodiscard]] virtual const EncryptedPlaneEvidence& evidence() const = 0;
    [[nodiscard]] virtual std::unique_ptr<ReliableStream> open_stream(
        StreamPurpose purpose) = 0;
    [[nodiscard]] virtual AcceptedStream accept_stream(
        std::chrono::milliseconds timeout) = 0;
};

class FallbackDatagramPlane {
public:
    virtual ~FallbackDatagramPlane() = default;
    [[nodiscard]] virtual const EncryptedPlaneEvidence& evidence() const = 0;
    virtual void send_datagram(
        DatagramChannel channel, std::span<const std::byte> data) = 0;
    [[nodiscard]] virtual ReceivedDatagram receive_datagram(
        std::chrono::milliseconds timeout) = 0;
};

class EncryptedFallbackProvider {
public:
    virtual ~EncryptedFallbackProvider() = default;
    [[nodiscard]] virtual std::unique_ptr<FallbackReliablePlane>
    connect_tls13(
        const TransportEndpoint& endpoint,
        const QuicTransportSettings& settings) = 0;
    [[nodiscard]] virtual std::unique_ptr<FallbackDatagramPlane>
    connect_dtls12(
        const TransportEndpoint& endpoint,
        const QuicTransportSettings& settings) = 0;
};

class EncryptedFallbackTransport final : public DuplexTransport {
public:
    EncryptedFallbackTransport(
        std::unique_ptr<FallbackReliablePlane> reliable,
        std::unique_ptr<FallbackDatagramPlane> datagrams,
        std::size_t maximum_datagram_bytes);

    [[nodiscard]] std::unique_ptr<ReliableStream> open_stream(
        StreamPurpose purpose) override;
    [[nodiscard]] AcceptedStream accept_stream(
        std::chrono::milliseconds timeout) override;
    void send_datagram(
        DatagramChannel channel,
        std::span<const std::byte> data) override;
    [[nodiscard]] ReceivedDatagram receive_datagram(
        std::chrono::milliseconds timeout) override;

private:
    std::unique_ptr<FallbackReliablePlane> reliable_;
    std::unique_ptr<FallbackDatagramPlane> datagrams_;
    std::size_t maximum_datagram_bytes_{};
};

class EncryptedFallbackConnector final : public TransportConnector {
public:
    explicit EncryptedFallbackConnector(EncryptedFallbackProvider& provider)
        : provider_(provider) {}

    [[nodiscard]] std::unique_ptr<Transport> connect(
        TransportMode mode, const TransportEndpoint& endpoint,
        const QuicTransportSettings& settings) override;
    [[nodiscard]] bool migrate(
        Transport& transport, const TransportEndpoint& endpoint) override;

private:
    EncryptedFallbackProvider& provider_;
};

class RoutedTransportConnector final : public TransportConnector {
public:
    RoutedTransportConnector(
        TransportConnector& primary, TransportConnector& fallback)
        : primary_(primary), fallback_(fallback) {}

    [[nodiscard]] std::unique_ptr<Transport> connect(
        TransportMode mode, const TransportEndpoint& endpoint,
        const QuicTransportSettings& settings) override;
    [[nodiscard]] bool migrate(
        Transport& transport, const TransportEndpoint& endpoint) override;

private:
    TransportConnector& primary_;
    TransportConnector& fallback_;
};

}  // namespace rwn::transport
