#include "rwn/transport/resilient_transport.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <limits>
#include <ranges>
#include <stdexcept>
#include <string>
#include <utility>

namespace rwn::transport {
namespace {

bool valid_identifier(const std::string_view value) {
    return !value.empty() && value.size() <= 64 &&
           std::ranges::all_of(value, [](const unsigned char character) {
               return std::isalnum(character) != 0 || character == '-' ||
                      character == '_' || character == '.';
           });
}

void validate_endpoint_fields(const TransportEndpoint& endpoint) {
    if (endpoint.host.empty() || endpoint.host.size() > 255 ||
        endpoint.port == 0 ||
        !std::ranges::all_of(endpoint.host, [](const unsigned char character) {
            return std::isalnum(character) != 0 || character == '-' ||
                   character == '.' || character == ':';
        })) {
        throw std::invalid_argument("transport endpoint is invalid");
    }
}

void validate_settings_fields(const QuicTransportSettings& settings) {
    if (!settings.require_tls13 || settings.alpn.empty() ||
        settings.alpn.size() > 32 ||
        !std::ranges::all_of(settings.alpn, [](const unsigned char character) {
            return std::isalnum(character) != 0 || character == '-' ||
                   character == '.' || character == '/';
        }) ||
        settings.maximum_datagram_bytes < 1200 ||
        settings.maximum_datagram_bytes > 65507 ||
        settings.idle_timeout < std::chrono::seconds{5} ||
        settings.idle_timeout > std::chrono::minutes{5} ||
        settings.keep_alive < std::chrono::seconds{1} ||
        settings.keep_alive * 2 > settings.idle_timeout ||
        settings.primary_failures_before_fallback == 0 ||
        settings.primary_failures_before_fallback > 10) {
        throw std::invalid_argument("QUIC transport settings are invalid");
    }
}

void validate_offer(const FeatureOffer& offer) {
    if (offer.minimum_protocol_version == 0 ||
        offer.maximum_protocol_version < offer.minimum_protocol_version ||
        offer.maximum_protocol_version > 1024 ||
        offer.maximum_width == 0 || offer.maximum_width > 16384 ||
        offer.maximum_height == 0 || offer.maximum_height > 16384 ||
        offer.maximum_frames_per_second == 0 ||
        offer.maximum_frames_per_second > 240 ||
        offer.video_features.size() > 8) {
        throw std::invalid_argument("transport feature offer is invalid");
    }
}

void validate_recovery(const RecoveryCursor& cursor) {
    if (!valid_identifier(cursor.session_id) ||
        !valid_identifier(cursor.workspace_id) ||
        cursor.workspace_revision == 0 ||
        cursor.active_build_ids.size() > 32 ||
        !std::ranges::all_of(cursor.active_build_ids, [](const auto& id) {
            return valid_identifier(id);
        }) ||
        std::set<std::string>(cursor.active_build_ids.begin(),
                              cursor.active_build_ids.end()).size() !=
            cursor.active_build_ids.size()) {
        throw std::invalid_argument("transport recovery cursor is invalid");
    }
}

std::string_view trim(const std::string_view value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1U);
}

std::string quoted(const std::string_view value) {
    const auto clean = trim(value);
    if (clean.size() < 2 || clean.front() != '"' || clean.back() != '"' ||
        clean.substr(1, clean.size() - 2U).find_first_of("\\\"\r\n") !=
            std::string_view::npos) {
        throw std::invalid_argument("transport string setting is invalid");
    }
    return std::string(clean.substr(1, clean.size() - 2U));
}

bool boolean(const std::string_view value) {
    const auto clean = trim(value);
    if (clean == "true") return true;
    if (clean == "false") return false;
    throw std::invalid_argument("transport boolean setting is invalid");
}

std::size_t unsigned_value(const std::string_view value) {
    const auto clean = trim(value);
    std::size_t result{};
    const auto parsed = std::from_chars(
        clean.data(), clean.data() + clean.size(), result);
    if (clean.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != clean.data() + clean.size()) {
        throw std::invalid_argument("transport integer setting is invalid");
    }
    return result;
}

std::chrono::seconds seconds_value(const std::string_view value) {
    const auto parsed = unsigned_value(value);
    using Rep = std::chrono::seconds::rep;
    if (parsed > static_cast<std::size_t>(
                     std::numeric_limits<Rep>::max())) {
        throw std::length_error("transport duration setting exceeds limit");
    }
    return std::chrono::seconds{static_cast<Rep>(parsed)};
}

}  // namespace

void validate_transport_endpoint(const TransportEndpoint& endpoint) {
    validate_endpoint_fields(endpoint);
}

void validate_quic_transport_settings(const QuicTransportSettings& settings) {
    validate_settings_fields(settings);
}

QuicTransportSettings load_transport_settings(
    const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("transport settings file could not be opened");
    }
    QuicTransportSettings settings;
    std::set<std::string, std::less<>> seen;
    std::string line;
    std::size_t line_number{};
    while (std::getline(input, line)) {
        ++line_number;
        auto clean = trim(line);
        if (clean.empty() || clean.front() == '#') continue;
        const auto equals = clean.find('=');
        if (equals == std::string_view::npos ||
            clean.find('=', equals + 1U) != std::string_view::npos) {
            throw std::invalid_argument(
                "transport settings line is invalid: " +
                std::to_string(line_number));
        }
        const auto key_view = trim(clean.substr(0, equals));
        const auto value = trim(clean.substr(equals + 1U));
        const std::string key(key_view);
        if (key.empty() || !seen.insert(key).second) {
            throw std::invalid_argument(
                "duplicate or empty transport setting");
        }
        if (key == "alpn") {
            settings.alpn = quoted(value);
        } else if (key == "require_tls13") {
            settings.require_tls13 = boolean(value);
        } else if (key == "enable_datagrams") {
            settings.enable_datagrams = boolean(value);
        } else if (key == "enable_connection_migration") {
            settings.enable_connection_migration = boolean(value);
        } else if (key == "enable_fallback") {
            settings.enable_fallback = boolean(value);
        } else if (key == "maximum_datagram_bytes") {
            settings.maximum_datagram_bytes = unsigned_value(value);
        } else if (key == "idle_timeout_seconds") {
            settings.idle_timeout = seconds_value(value);
        } else if (key == "keep_alive_seconds") {
            settings.keep_alive = seconds_value(value);
        } else if (key == "primary_failures_before_fallback") {
            settings.primary_failures_before_fallback =
                unsigned_value(value);
        } else {
            throw std::invalid_argument("unknown transport setting");
        }
    }
    if (input.bad()) {
        throw std::runtime_error("transport settings file read failed");
    }
    constexpr std::size_t required_settings = 9;
    if (seen.size() != required_settings) {
        throw std::invalid_argument("transport settings are incomplete");
    }
    validate_quic_transport_settings(settings);
    return settings;
}

std::string_view to_string(const TransportMode mode) {
    switch (mode) {
        case TransportMode::quic: return "quic";
        case TransportMode::tls_tcp_udp_fallback: return "tls_tcp_udp_fallback";
    }
    return "unknown";
}

std::string_view to_string(const NetworkPath path) {
    switch (path) {
        case NetworkPath::lan: return "lan";
        case NetworkPath::wifi: return "wifi";
        case NetworkPath::vpn: return "vpn";
        case NetworkPath::unknown: return "unknown";
    }
    return "unknown";
}

std::string_view to_string(const ConnectionState state) {
    switch (state) {
        case ConnectionState::disconnected: return "disconnected";
        case ConnectionState::connecting: return "connecting";
        case ConnectionState::ready: return "ready";
        case ConnectionState::migrating: return "migrating";
        case ConnectionState::closed: return "closed";
    }
    return "unknown";
}

NegotiatedFeatures negotiate_features(
    const FeatureOffer& local, const FeatureOffer& remote) {
    validate_offer(local);
    validate_offer(remote);
    const auto minimum = std::max(
        local.minimum_protocol_version, remote.minimum_protocol_version);
    const auto maximum = std::min(
        local.maximum_protocol_version, remote.maximum_protocol_version);
    if (minimum > maximum) {
        throw std::logic_error("transport protocol versions do not overlap");
    }
    NegotiatedFeatures result{
        .protocol_version = maximum,
        .video_features = {},
        .maximum_width = std::min(local.maximum_width, remote.maximum_width),
        .maximum_height = std::min(local.maximum_height, remote.maximum_height),
        .maximum_frames_per_second = std::min(
            local.maximum_frames_per_second,
            remote.maximum_frames_per_second),
        .datagrams = local.datagrams && remote.datagrams,
    };
    std::ranges::set_intersection(
        local.video_features, remote.video_features,
        std::inserter(result.video_features, result.video_features.end()));
    if (!result.video_features.contains(VideoFeature::h264)) {
        throw std::logic_error("baseline H.264 feature is not shared");
    }
    if (!result.video_features.contains(VideoFeature::resolution_4k)) {
        result.maximum_width = std::min<std::uint32_t>(result.maximum_width, 1920);
        result.maximum_height = std::min<std::uint32_t>(result.maximum_height, 1080);
    }
    if (!result.video_features.contains(VideoFeature::fps_120)) {
        result.maximum_frames_per_second =
            std::min<std::uint16_t>(result.maximum_frames_per_second, 60);
    }
    return result;
}

ResilientTransport::ResilientTransport(
    TransportConnector& connector, TransportEndpoint endpoint,
    QuicTransportSettings settings)
    : connector_(connector), endpoint_(std::move(endpoint)),
      settings_(std::move(settings)) {
    validate_transport_endpoint(endpoint_);
    validate_quic_transport_settings(settings_);
}

void ResilientTransport::validate_event_time(
    const std::chrono::steady_clock::time_point now) {
    if (now == std::chrono::steady_clock::time_point{} ||
        (last_event_at_ && now < *last_event_at_)) {
        throw std::invalid_argument("transport event time is not monotonic");
    }
    last_event_at_ = now;
}

void ResilientTransport::append_event(
    const std::chrono::steady_clock::time_point now,
    std::string reason_code) {
    if (!valid_identifier(reason_code)) {
        throw std::invalid_argument("transport reason code is invalid");
    }
    events_.push_back({
        .occurred_at = now,
        .state = state_,
        .mode = mode_,
        .path = endpoint_.path,
        .reason_code = std::move(reason_code),
    });
}

bool ResilientTransport::try_connect(
    const TransportMode mode,
    const std::chrono::steady_clock::time_point now) {
    if (mode == TransportMode::quic) {
        ++telemetry_.primary_connection_attempts;
    }
    try {
        auto connection = connector_.connect(mode, endpoint_, settings_);
        if (!connection) throw std::runtime_error("null transport connection");
        active_ = std::move(connection);
        mode_ = mode;
        state_ = ConnectionState::ready;
        if (mode == TransportMode::quic) {
            consecutive_primary_failures_ = 0;
            append_event(now, "primary_connected");
        } else {
            ++telemetry_.fallback_connections;
            append_event(now, "fallback_connected");
        }
        return true;
    } catch (const std::exception&) {
        active_.reset();
        mode_.reset();
        state_ = ConnectionState::disconnected;
        if (mode == TransportMode::quic) {
            ++telemetry_.primary_connection_failures;
            ++consecutive_primary_failures_;
            append_event(now, "primary_failed");
        } else {
            append_event(now, "fallback_failed");
        }
        return false;
    }
}

void ResilientTransport::connect(
    const std::chrono::steady_clock::time_point now) {
    validate_event_time(now);
    if (state_ == ConnectionState::closed) {
        throw std::logic_error("closed transport cannot reconnect");
    }
    if (state_ == ConnectionState::ready) return;
    state_ = ConnectionState::connecting;
    append_event(now, "connect_started");
    if (try_connect(TransportMode::quic, now)) return;
    if (settings_.enable_fallback &&
        consecutive_primary_failures_ >=
            settings_.primary_failures_before_fallback &&
        try_connect(TransportMode::tls_tcp_udp_fallback, now)) {
        return;
    }
    throw std::runtime_error("transport connection failed");
}

void ResilientTransport::network_changed(
    TransportEndpoint endpoint,
    const std::chrono::steady_clock::time_point now) {
    validate_transport_endpoint(endpoint);
    validate_event_time(now);
    require_ready();
    endpoint_ = std::move(endpoint);
    if (mode_ == TransportMode::quic &&
        settings_.enable_connection_migration) {
        state_ = ConnectionState::migrating;
        ++telemetry_.migration_attempts;
        append_event(now, "migration_started");
        try {
            if (connector_.migrate(*active_, endpoint_)) {
                state_ = ConnectionState::ready;
                append_event(now, "migration_succeeded");
                return;
            }
        } catch (const std::exception&) {
        }
        ++telemetry_.migration_failures;
        append_event(now, "migration_failed");
    }
    active_.reset();
    mode_.reset();
    state_ = ConnectionState::disconnected;
    ++telemetry_.reconnects;
    connect(now);
}

void ResilientTransport::reconnect(
    const std::chrono::steady_clock::time_point now) {
    validate_event_time(now);
    if (state_ == ConnectionState::closed) {
        throw std::logic_error("closed transport cannot reconnect");
    }
    active_.reset();
    mode_.reset();
    state_ = ConnectionState::disconnected;
    ++telemetry_.reconnects;
    append_event(now, "reconnect_started");
    connect(now);
}

void ResilientTransport::close(
    const std::chrono::steady_clock::time_point now) {
    validate_event_time(now);
    active_.reset();
    mode_.reset();
    state_ = ConnectionState::closed;
    append_event(now, "closed");
}

void ResilientTransport::set_recovery_cursor(RecoveryCursor cursor) {
    validate_recovery(cursor);
    recovery_ = std::move(cursor);
}

void ResilientTransport::require_ready() const {
    if (state_ != ConnectionState::ready || active_ == nullptr || !mode_) {
        throw std::logic_error("transport is not ready");
    }
}

std::unique_ptr<ReliableStream> ResilientTransport::open_stream(
    const StreamPurpose purpose) {
    require_ready();
    auto stream = active_->open_stream(purpose);
    if (!stream) throw std::runtime_error("transport returned a null stream");
    ++telemetry_.streams_opened;
    return stream;
}

AcceptedStream ResilientTransport::accept_stream(
    const std::chrono::milliseconds timeout) {
    require_ready();
    if (timeout < std::chrono::milliseconds{1} ||
        timeout > std::chrono::minutes{5}) {
        throw std::invalid_argument("transport accept timeout is invalid");
    }
    auto* duplex = dynamic_cast<DuplexTransport*>(active_.get());
    if (duplex == nullptr) {
        throw std::runtime_error(
            "active transport cannot receive peer streams");
    }
    auto accepted = duplex->accept_stream(timeout);
    if (!accepted.stream) {
        throw std::runtime_error("transport accepted a null stream");
    }
    ++telemetry_.streams_accepted;
    return accepted;
}

void ResilientTransport::send_datagram(
    const DatagramChannel channel,
    const std::span<const std::byte> data) {
    require_ready();
    if (!settings_.enable_datagrams || data.empty() ||
        data.size() > settings_.maximum_datagram_bytes) {
        throw std::length_error("transport datagram is outside bounds");
    }
    active_->send_datagram(channel, data);
    ++telemetry_.datagrams_sent;
    telemetry_.datagram_bytes_sent += data.size();
}

ReceivedDatagram ResilientTransport::receive_datagram(
    const std::chrono::milliseconds timeout) {
    require_ready();
    if (!settings_.enable_datagrams ||
        timeout < std::chrono::milliseconds{1} ||
        timeout > std::chrono::minutes{5}) {
        throw std::invalid_argument(
            "transport receive timeout or datagram setting is invalid");
    }
    auto* duplex = dynamic_cast<DuplexTransport*>(active_.get());
    if (duplex == nullptr) {
        throw std::runtime_error(
            "active transport cannot receive datagrams");
    }
    auto datagram = duplex->receive_datagram(timeout);
    if (datagram.payload.empty() ||
        datagram.payload.size() > settings_.maximum_datagram_bytes) {
        throw std::length_error("received transport datagram is outside bounds");
    }
    ++telemetry_.datagrams_received;
    telemetry_.datagram_bytes_received += datagram.payload.size();
    return datagram;
}

}  // namespace rwn::transport
