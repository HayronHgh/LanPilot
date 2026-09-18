#pragma once

#include "rwn/transport/transport.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace rwn::transport {

enum class TransportMode { quic, tls_tcp_udp_fallback };
enum class NetworkPath { lan, wifi, vpn, unknown };
enum class ConnectionState {
    disconnected,
    connecting,
    ready,
    migrating,
    closed,
};

[[nodiscard]] std::string_view to_string(TransportMode mode);
[[nodiscard]] std::string_view to_string(NetworkPath path);
[[nodiscard]] std::string_view to_string(ConnectionState state);

struct TransportEndpoint {
    std::string host;
    std::uint16_t port{};
    NetworkPath path{NetworkPath::unknown};
};

struct QuicTransportSettings {
    std::string alpn{"rwn/1"};
    bool require_tls13{true};
    bool enable_datagrams{true};
    bool enable_connection_migration{true};
    bool enable_fallback{true};
    std::size_t maximum_datagram_bytes{1400};
    std::chrono::seconds idle_timeout{30};
    std::chrono::seconds keep_alive{5};
    std::size_t primary_failures_before_fallback{2};
};

void validate_transport_endpoint(const TransportEndpoint& endpoint);
void validate_quic_transport_settings(const QuicTransportSettings& settings);

[[nodiscard]] QuicTransportSettings load_transport_settings(
    const std::filesystem::path& path);

enum class VideoFeature {
    h264,
    hevc,
    av1,
    resolution_4k,
    fps_120,
    hdr,
    multi_monitor,
    adaptive_bitrate,
};

struct FeatureOffer {
    std::uint16_t minimum_protocol_version{1};
    std::uint16_t maximum_protocol_version{1};
    std::set<VideoFeature> video_features{VideoFeature::h264};
    std::uint32_t maximum_width{1920};
    std::uint32_t maximum_height{1080};
    std::uint16_t maximum_frames_per_second{60};
    bool datagrams{true};
};

struct NegotiatedFeatures {
    std::uint16_t protocol_version{};
    std::set<VideoFeature> video_features;
    std::uint32_t maximum_width{};
    std::uint32_t maximum_height{};
    std::uint16_t maximum_frames_per_second{};
    bool datagrams{};
};

[[nodiscard]] NegotiatedFeatures negotiate_features(
    const FeatureOffer& local, const FeatureOffer& remote);

struct RecoveryCursor {
    std::string session_id;
    std::string workspace_id;
    std::uint64_t workspace_revision{};
    std::vector<std::string> active_build_ids;
    std::uint64_t audit_sequence{};
};

struct TransportTelemetry {
    std::uint64_t primary_connection_attempts{};
    std::uint64_t primary_connection_failures{};
    std::uint64_t fallback_connections{};
    std::uint64_t migration_attempts{};
    std::uint64_t migration_failures{};
    std::uint64_t reconnects{};
    std::uint64_t streams_opened{};
    std::uint64_t streams_accepted{};
    std::uint64_t datagrams_sent{};
    std::uint64_t datagram_bytes_sent{};
    std::uint64_t datagrams_received{};
    std::uint64_t datagram_bytes_received{};
};

struct TransportEvent {
    std::chrono::steady_clock::time_point occurred_at{};
    ConnectionState state{ConnectionState::disconnected};
    std::optional<TransportMode> mode;
    NetworkPath path{NetworkPath::unknown};
    std::string reason_code;
};

class TransportConnector {
public:
    virtual ~TransportConnector() = default;
    [[nodiscard]] virtual std::unique_ptr<Transport> connect(
        TransportMode mode, const TransportEndpoint& endpoint,
        const QuicTransportSettings& settings) = 0;
    [[nodiscard]] virtual bool migrate(
        Transport& transport, const TransportEndpoint& endpoint) = 0;
};

class ResilientTransport final : public DuplexTransport {
public:
    ResilientTransport(
        TransportConnector& connector, TransportEndpoint endpoint,
        QuicTransportSettings settings = {});

    void connect(std::chrono::steady_clock::time_point now);
    void network_changed(
        TransportEndpoint endpoint,
        std::chrono::steady_clock::time_point now);
    void reconnect(std::chrono::steady_clock::time_point now);
    void close(std::chrono::steady_clock::time_point now);
    void set_recovery_cursor(RecoveryCursor cursor);

    [[nodiscard]] std::unique_ptr<ReliableStream> open_stream(
        StreamPurpose purpose) override;
    [[nodiscard]] AcceptedStream accept_stream(
        std::chrono::milliseconds timeout) override;
    void send_datagram(
        DatagramChannel channel,
        std::span<const std::byte> data) override;
    [[nodiscard]] ReceivedDatagram receive_datagram(
        std::chrono::milliseconds timeout) override;

    [[nodiscard]] ConnectionState state() const noexcept { return state_; }
    [[nodiscard]] std::optional<TransportMode> mode() const noexcept {
        return mode_;
    }
    [[nodiscard]] const RecoveryCursor& recovery_cursor() const noexcept {
        return recovery_;
    }
    [[nodiscard]] const TransportTelemetry& telemetry() const noexcept {
        return telemetry_;
    }
    [[nodiscard]] const std::vector<TransportEvent>& events() const noexcept {
        return events_;
    }

private:
    void validate_event_time(std::chrono::steady_clock::time_point now);
    void append_event(
        std::chrono::steady_clock::time_point now,
        std::string reason_code);
    [[nodiscard]] bool try_connect(
        TransportMode mode, std::chrono::steady_clock::time_point now);
    void require_ready() const;

    TransportConnector& connector_;
    TransportEndpoint endpoint_;
    QuicTransportSettings settings_;
    std::unique_ptr<Transport> active_;
    ConnectionState state_{ConnectionState::disconnected};
    std::optional<TransportMode> mode_;
    RecoveryCursor recovery_;
    TransportTelemetry telemetry_;
    std::vector<TransportEvent> events_;
    std::optional<std::chrono::steady_clock::time_point> last_event_at_;
    std::size_t consecutive_primary_failures_{};
};

}  // namespace rwn::transport
