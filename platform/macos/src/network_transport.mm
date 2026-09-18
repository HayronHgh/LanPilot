#include "rwn/platform/macos/network_transport.hpp"

#include "rwn/core/content_hash.hpp"

#import <Foundation/Foundation.h>
#import <Network/Network.h>
#import <Security/Security.h>

#include <algorithm>
#include <array>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <limits>
#include <mutex>
#include <ranges>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace rwn::platform::macos {
namespace {

using namespace rwn::transport;

constexpr std::size_t maximum_stream_message_bytes = 16U * 1024U * 1024U;
constexpr std::array<std::byte, 4> stream_magic{
    std::byte{'R'}, std::byte{'W'}, std::byte{'N'}, std::byte{1}};

template <typename Value>
class CfOwner {
public:
    explicit CfOwner(Value value = nullptr) : value_(value) {}
    ~CfOwner() {
        if (value_ != nullptr) CFRelease(value_);
    }
    CfOwner(const CfOwner&) = delete;
    CfOwner& operator=(const CfOwner&) = delete;
    [[nodiscard]] Value get() const noexcept { return value_; }

private:
    Value value_{};
};

[[nodiscard]] std::string network_error_text(nw_error_t error) {
    if (error == nullptr) return "unknown Network.framework error";
    return "Network.framework error " +
        std::to_string(nw_error_get_error_code(error));
}

[[nodiscard]] std::vector<std::byte> copy_dispatch_data(
    dispatch_data_t content) {
    if (content == nullptr) return {};
    const void* mapped{};
    std::size_t size{};
    const auto contiguous = dispatch_data_create_map(content, &mapped, &size);
    if (contiguous == nullptr || (size != 0 && mapped == nullptr)) {
        throw std::runtime_error("Network.framework returned invalid content");
    }
    std::vector<std::byte> result(size);
    if (size != 0) std::memcpy(result.data(), mapped, size);
    return result;
}

[[nodiscard]] dispatch_data_t make_dispatch_data(
    const std::span<const std::byte> bytes) {
    if (bytes.empty()) return dispatch_data_empty;
    auto* copy = std::malloc(bytes.size());
    if (copy == nullptr) throw std::bad_alloc();
    std::memcpy(copy, bytes.data(), bytes.size());
    return dispatch_data_create(
        copy, bytes.size(), dispatch_get_global_queue(QOS_CLASS_UTILITY, 0),
        DISPATCH_DATA_DESTRUCTOR_FREE);
}

[[nodiscard]] SecIdentityRef load_identity(
    const std::span<const std::byte> persistent_reference) {
    const CfOwner<CFDataRef> reference(CFDataCreate(
        kCFAllocatorDefault,
        reinterpret_cast<const UInt8*>(persistent_reference.data()),
        static_cast<CFIndex>(persistent_reference.size())));
    if (reference.get() == nullptr) {
        throw std::runtime_error("Keychain persistent reference allocation failed");
    }
    const void* keys[]{kSecClass, kSecValuePersistentRef, kSecReturnRef,
                       kSecMatchLimit};
    const void* values[]{kSecClassIdentity, reference.get(), kCFBooleanTrue,
                         kSecMatchLimitOne};
    const CfOwner<CFDictionaryRef> query(CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 4,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks));
    if (query.get() == nullptr) {
        throw std::runtime_error("Keychain identity query allocation failed");
    }
    CFTypeRef result{};
    const auto status = SecItemCopyMatching(query.get(), &result);
    if (status != errSecSuccess || result == nullptr ||
        CFGetTypeID(result) != SecIdentityGetTypeID()) {
        if (result != nullptr) CFRelease(result);
        throw std::runtime_error(
            "explicit Keychain identity was not found; OSStatus=" +
            std::to_string(status));
    }
    return reinterpret_cast<SecIdentityRef>(const_cast<void*>(result));
}

[[nodiscard]] CertificateSha256 leaf_fingerprint(SecTrustRef trust) {
    const auto certificate = SecTrustGetCertificateAtIndex(trust, 0);
    if (certificate == nullptr) return {};
    const CfOwner<CFDataRef> data(SecCertificateCopyData(certificate));
    if (data.get() == nullptr) return {};
    const auto size = static_cast<std::size_t>(CFDataGetLength(data.get()));
    const auto* bytes = reinterpret_cast<const std::byte*>(
        CFDataGetBytePtr(data.get()));
    if (size == 0 || bytes == nullptr) return {};
    const auto digest = rwn::core::sha256(std::span{bytes, size});
    CertificateSha256 result{};
    std::ranges::transform(digest, result.begin(), [](const std::byte value) {
        return std::to_integer<std::uint8_t>(value);
    });
    return result;
}

[[nodiscard]] bool verify_peer(
    sec_trust_t sec_trust, const bool peer_is_server,
    const std::string& hostname,
    const std::vector<CertificateSha256>& allowlist) {
    const CfOwner<SecTrustRef> trust(sec_trust_copy_ref(sec_trust));
    if (trust.get() == nullptr) return false;

    const CfOwner<CFStringRef> host(peer_is_server ? CFStringCreateWithCString(
        kCFAllocatorDefault, hostname.c_str(), kCFStringEncodingUTF8) : nullptr);
    if (peer_is_server && host.get() == nullptr) return false;
    const CfOwner<SecPolicyRef> tls_policy(SecPolicyCreateSSL(
        peer_is_server, peer_is_server ? host.get() : nullptr));
    const CfOwner<SecPolicyRef> revocation_policy(SecPolicyCreateRevocation(
        kSecRevocationUseAnyAvailableMethod));
    if (tls_policy.get() == nullptr || revocation_policy.get() == nullptr) {
        return false;
    }
    const void* policy_values[]{tls_policy.get(), revocation_policy.get()};
    const CfOwner<CFArrayRef> policies(CFArrayCreate(
        kCFAllocatorDefault, policy_values, 2,
        &kCFTypeArrayCallBacks));
    if (policies.get() == nullptr ||
        SecTrustSetPolicies(trust.get(), policies.get()) != errSecSuccess ||
        SecTrustSetNetworkFetchAllowed(trust.get(), true) != errSecSuccess) {
        return false;
    }
    CFErrorRef error{};
    const auto trusted = SecTrustEvaluateWithError(trust.get(), &error);
    const CfOwner<CFErrorRef> owned_error(error);
    if (!trusted) return false;
    const auto fingerprint = leaf_fingerprint(trust.get());
    return apple_network_peer_allowed(allowlist, fingerprint);
}

[[nodiscard]] nw_parameters_t make_quic_parameters(
    const AppleNetworkIdentityOptions& identity,
    const QuicTransportSettings& settings, const bool server,
    const std::string& hostname, dispatch_queue_t verify_queue) {
    const CfOwner<SecIdentityRef> local_identity(
        load_identity(identity.keychain_persistent_reference));
    const auto sec_identity = sec_identity_create(local_identity.get());
    if (sec_identity == nullptr) {
        throw std::runtime_error("Network.framework identity creation failed");
    }
    const auto alpn = settings.alpn;
    const auto allowlist = identity.allowed_peer_certificate_sha256;
    auto parameters = nw_parameters_create_quic(^(nw_protocol_options_t quic) {
        nw_quic_add_tls_application_protocol(quic, alpn.c_str());
        nw_quic_set_idle_timeout(
            quic, static_cast<std::uint32_t>(settings.idle_timeout.count() * 1000));
        if (settings.enable_datagrams) {
            nw_quic_set_max_datagram_frame_size(
                quic, static_cast<std::uint16_t>(
                    settings.maximum_datagram_bytes + 1));
        }
        const auto security = nw_quic_copy_sec_protocol_options(quic);
        sec_protocol_options_set_local_identity(security, sec_identity);
        sec_protocol_options_set_peer_authentication_required(security, true);
        sec_protocol_options_set_min_tls_protocol_version(
            security, tls_protocol_version_TLSv13);
        sec_protocol_options_set_verify_block(
            security,
            ^(sec_protocol_metadata_t, sec_trust_t trust,
              sec_protocol_verify_complete_t complete) {
                complete(verify_peer(
                    trust, !server, hostname, allowlist));
            },
            verify_queue);
    });
    if (parameters == nullptr) {
        throw std::runtime_error("QUIC parameter creation failed");
    }
    return parameters;
}

struct StreamSignal {
    std::mutex mutex;
    std::condition_variable condition;
    bool complete{};
    bool end_of_stream{};
    std::string error;
    std::vector<std::byte> content;
};

class NetworkReliableStream final : public ReliableStream {
public:
    NetworkReliableStream(
        nw_connection_t connection,
        const std::chrono::milliseconds timeout,
        const std::size_t maximum_queued_bytes)
        : connection_(connection), timeout_(timeout),
          maximum_queued_bytes_(maximum_queued_bytes) {}

    ~NetworkReliableStream() override {
        if (connection_ != nullptr) nw_connection_cancel(connection_);
    }

    void write(const std::span<const std::byte> data) override {
        if (data.empty() || data.size() > maximum_stream_message_bytes ||
            data.size() > maximum_queued_bytes_) {
            throw std::invalid_argument("QUIC stream message size is invalid");
        }
        std::vector<std::byte> framed(4 + data.size());
        const auto length = static_cast<std::uint32_t>(data.size());
        framed[0] = static_cast<std::byte>((length >> 24U) & 0xffU);
        framed[1] = static_cast<std::byte>((length >> 16U) & 0xffU);
        framed[2] = static_cast<std::byte>((length >> 8U) & 0xffU);
        framed[3] = static_cast<std::byte>(length & 0xffU);
        std::ranges::copy(data, framed.begin() + 4);
        const auto content = make_dispatch_data(framed);
        const auto signal = std::make_shared<StreamSignal>();
        nw_connection_send(
            connection_, content, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
            ^(nw_error_t error) {
                std::lock_guard lock(signal->mutex);
                if (error != nullptr) signal->error = network_error_text(error);
                signal->complete = true;
                signal->condition.notify_all();
            });
        wait(*signal, "QUIC stream write timed out");
    }

    [[nodiscard]] std::vector<std::byte> read() override {
        const auto header = receive_exact(4);
        const auto size =
            (std::to_integer<std::uint32_t>(header[0]) << 24U) |
            (std::to_integer<std::uint32_t>(header[1]) << 16U) |
            (std::to_integer<std::uint32_t>(header[2]) << 8U) |
            std::to_integer<std::uint32_t>(header[3]);
        if (size == 0 || size > maximum_stream_message_bytes ||
            size > maximum_queued_bytes_) {
            throw std::runtime_error("peer QUIC stream message size is invalid");
        }
        return receive_exact(size);
    }

private:
    void wait(StreamSignal& signal, const char* timeout_message) const {
        std::unique_lock lock(signal.mutex);
        if (!signal.condition.wait_for(
                lock, timeout_, [&] { return signal.complete; })) {
            nw_connection_cancel(connection_);
            throw std::runtime_error(timeout_message);
        }
        if (!signal.error.empty()) throw std::runtime_error(signal.error);
    }

    [[nodiscard]] std::vector<std::byte> receive_exact(
        const std::size_t required) {
        std::vector<std::byte> result;
        result.reserve(required);
        while (result.size() < required) {
            const auto remaining = required - result.size();
            const auto signal = std::make_shared<StreamSignal>();
            nw_connection_receive(
                connection_, 1, static_cast<std::uint32_t>(remaining),
                ^(dispatch_data_t content, nw_content_context_t, bool complete,
                  nw_error_t error) {
                    std::lock_guard lock(signal->mutex);
                    if (error != nullptr) {
                        signal->error = network_error_text(error);
                    } else {
                        try {
                            signal->content = copy_dispatch_data(content);
                        } catch (const std::exception& exception) {
                            signal->error = exception.what();
                        }
                        signal->end_of_stream = complete;
                    }
                    signal->complete = true;
                    signal->condition.notify_all();
                });
            wait(*signal, "QUIC stream read timed out");
            if (signal->content.empty()) {
                throw std::runtime_error("QUIC stream closed before message completed");
            }
            result.insert(
                result.end(), signal->content.begin(), signal->content.end());
            if (signal->end_of_stream && result.size() < required) {
                throw std::runtime_error("QUIC stream ended inside a message");
            }
        }
        return result;
    }

    nw_connection_t connection_{};
    std::chrono::milliseconds timeout_{};
    std::size_t maximum_queued_bytes_{};
};

struct GroupSignal {
    std::mutex mutex;
    std::condition_variable condition;
    bool ready{};
    bool closed{};
    std::string error;
    std::deque<AcceptedStream> streams;
    std::deque<ReceivedDatagram> datagrams;
    std::size_t queued_bytes{};
};

struct GroupHandlers {
    std::shared_ptr<GroupSignal> signal;
    dispatch_queue_t io_queue{};
    std::chrono::milliseconds stream_timeout{};
    std::size_t maximum_pending_streams{};
    std::size_t maximum_pending_datagrams{};
    std::size_t maximum_queued_bytes{};
    std::size_t maximum_datagram_bytes{};
};

class NetworkFrameworkTransport final : public DuplexTransport {
public:
    NetworkFrameworkTransport(
        nw_connection_group_t group, TransportEndpoint endpoint,
        QuicTransportSettings settings,
        const std::chrono::milliseconds stream_timeout,
        const std::size_t maximum_pending_streams,
        const std::size_t maximum_pending_datagrams,
        const std::size_t maximum_queued_bytes,
        const std::chrono::milliseconds ready_timeout,
        const bool start_group)
        : group_(group), endpoint_(std::move(endpoint)),
          settings_(std::move(settings)), stream_timeout_(stream_timeout),
          maximum_pending_streams_(maximum_pending_streams),
          maximum_pending_datagrams_(maximum_pending_datagrams),
          maximum_queued_bytes_(maximum_queued_bytes),
          queue_(dispatch_queue_create(
              "com.remoteworkspacenode.transport.quic", DISPATCH_QUEUE_SERIAL)),
          io_queue_(dispatch_queue_create(
              "com.remoteworkspacenode.transport.quic.stream", DISPATCH_QUEUE_CONCURRENT)),
          signal_(std::make_shared<GroupSignal>()) {
        if (group_ == nullptr || queue_ == nullptr || io_queue_ == nullptr) {
            throw std::runtime_error("Network.framework group allocation failed");
        }
        install_handlers();
        if (start_group) nw_connection_group_start(group_);
        std::unique_lock lock(signal_->mutex);
        if (!signal_->condition.wait_for(
                lock, ready_timeout,
                [&] { return signal_->ready || signal_->closed; })) {
            nw_connection_group_cancel(group_);
            throw std::runtime_error("Network.framework QUIC handshake timed out");
        }
        if (!signal_->ready) {
            throw std::runtime_error(signal_->error.empty()
                ? "Network.framework QUIC handshake failed"
                : signal_->error);
        }
    }

    ~NetworkFrameworkTransport() override {
        if (group_ != nullptr) nw_connection_group_cancel(group_);
    }

    [[nodiscard]] std::unique_ptr<ReliableStream> open_stream(
        const StreamPurpose purpose) override {
        require_ready();
        const auto stream_options = nw_quic_create_options();
        nw_quic_set_stream_is_unidirectional(stream_options, false);
        const auto connection = nw_connection_group_extract_connection(
            group_, nullptr, stream_options);
        if (connection == nullptr) {
            throw std::runtime_error("failed to open a QUIC stream");
        }
        nw_connection_set_queue(connection, io_queue_);
        const std::array header{
            stream_magic[0], stream_magic[1], stream_magic[2], stream_magic[3],
            static_cast<std::byte>(purpose), std::byte{}, std::byte{},
            std::byte{}};
        const auto content = make_dispatch_data(header);
        const auto sent = std::make_shared<StreamSignal>();
        nw_connection_send(
            connection, content, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
            ^(nw_error_t error) {
                std::lock_guard lock(sent->mutex);
                if (error != nullptr) sent->error = network_error_text(error);
                sent->complete = true;
                sent->condition.notify_all();
            });
        {
            std::unique_lock lock(sent->mutex);
            if (!sent->condition.wait_for(
                    lock, stream_timeout_, [&] { return sent->complete; })) {
                nw_connection_cancel(connection);
                throw std::runtime_error("QUIC stream purpose write timed out");
            }
            if (!sent->error.empty()) throw std::runtime_error(sent->error);
        }
        return std::make_unique<NetworkReliableStream>(
            connection, stream_timeout_, maximum_queued_bytes_);
    }

    [[nodiscard]] AcceptedStream accept_stream(
        const std::chrono::milliseconds timeout) override {
        if (timeout <= std::chrono::milliseconds::zero()) {
            throw std::invalid_argument("QUIC stream accept timeout must be positive");
        }
        std::unique_lock lock(signal_->mutex);
        if (!signal_->condition.wait_for(lock, timeout, [&] {
                return !signal_->streams.empty() || signal_->closed;
            })) {
            throw std::runtime_error("QUIC stream accept timed out");
        }
        if (signal_->streams.empty()) {
            throw std::runtime_error("QUIC connection is closed");
        }
        auto accepted = std::move(signal_->streams.front());
        signal_->streams.pop_front();
        return accepted;
    }

    void send_datagram(
        const DatagramChannel channel,
        const std::span<const std::byte> data) override {
        require_ready();
        if (!settings_.enable_datagrams || data.empty() ||
            data.size() > settings_.maximum_datagram_bytes) {
            throw std::invalid_argument("QUIC datagram is invalid");
        }
        std::vector<std::byte> framed(1 + data.size());
        framed.front() = static_cast<std::byte>(channel);
        std::ranges::copy(data, framed.begin() + 1);
        const auto content = make_dispatch_data(framed);
        const auto sent = std::make_shared<StreamSignal>();
        nw_connection_group_send_message(
            group_, content, nullptr, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT,
            ^(nw_error_t error) {
                std::lock_guard lock(sent->mutex);
                if (error != nullptr) sent->error = network_error_text(error);
                sent->complete = true;
                sent->condition.notify_all();
            });
        std::unique_lock lock(sent->mutex);
        if (!sent->condition.wait_for(
                lock, stream_timeout_, [&] { return sent->complete; })) {
            throw std::runtime_error("QUIC datagram send timed out");
        }
        if (!sent->error.empty()) throw std::runtime_error(sent->error);
    }

    [[nodiscard]] ReceivedDatagram receive_datagram(
        const std::chrono::milliseconds timeout) override {
        if (timeout <= std::chrono::milliseconds::zero()) {
            throw std::invalid_argument("QUIC datagram receive timeout must be positive");
        }
        std::unique_lock lock(signal_->mutex);
        if (!signal_->condition.wait_for(lock, timeout, [&] {
                return !signal_->datagrams.empty() || signal_->closed;
            })) {
            throw std::runtime_error("QUIC datagram receive timed out");
        }
        if (signal_->datagrams.empty()) {
            throw std::runtime_error("QUIC connection is closed");
        }
        auto datagram = std::move(signal_->datagrams.front());
        signal_->queued_bytes -= datagram.payload.size();
        signal_->datagrams.pop_front();
        return datagram;
    }

    [[nodiscard]] bool path_changed(const TransportEndpoint& endpoint) {
        validate_transport_endpoint(endpoint);
        if (!settings_.enable_connection_migration ||
            endpoint.host != endpoint_.host || endpoint.port != endpoint_.port) {
            return false;
        }
        endpoint_ = endpoint;
        return true;
    }

private:
    void require_ready() const {
        std::lock_guard lock(signal_->mutex);
        if (!signal_->ready || signal_->closed) {
            throw std::logic_error("Network.framework QUIC connection is not ready");
        }
    }

    void install_handlers() {
        const auto handlers = std::make_shared<GroupHandlers>(GroupHandlers{
            .signal = signal_,
            .io_queue = io_queue_,
            .stream_timeout = stream_timeout_,
            .maximum_pending_streams = maximum_pending_streams_,
            .maximum_pending_datagrams = maximum_pending_datagrams_,
            .maximum_queued_bytes = maximum_queued_bytes_,
            .maximum_datagram_bytes = settings_.maximum_datagram_bytes,
        });
        nw_connection_group_set_queue(group_, queue_);
        nw_connection_group_set_state_changed_handler(
            group_, ^(nw_connection_group_state_t state, nw_error_t error) {
                std::lock_guard lock(handlers->signal->mutex);
                if (state == nw_connection_group_state_ready) {
                    handlers->signal->ready = true;
                }
                if (state == nw_connection_group_state_failed ||
                    state == nw_connection_group_state_cancelled) {
                    handlers->signal->closed = true;
                    if (error != nullptr) {
                        handlers->signal->error = network_error_text(error);
                    }
                }
                handlers->signal->condition.notify_all();
            });
        nw_connection_group_set_receive_handler(
            group_, static_cast<std::uint32_t>(
                handlers->maximum_datagram_bytes + 1),
            true, ^(dispatch_data_t content, nw_content_context_t, bool) {
                try {
                    auto bytes = copy_dispatch_data(content);
                    if (bytes.size() < 2 ||
                        bytes.size() > handlers->maximum_datagram_bytes + 1) {
                        return;
                    }
                    const auto raw_channel =
                        std::to_integer<std::uint8_t>(bytes.front());
                    if (raw_channel > static_cast<std::uint8_t>(DatagramChannel::pointer)) {
                        return;
                    }
                    ReceivedDatagram datagram{
                        .channel = static_cast<DatagramChannel>(raw_channel),
                        .payload = std::vector<std::byte>(
                            bytes.begin() + 1, bytes.end()),
                    };
                    std::lock_guard lock(handlers->signal->mutex);
                    if (handlers->signal->datagrams.size() >=
                            handlers->maximum_pending_datagrams ||
                        handlers->signal->queued_bytes + datagram.payload.size() >
                            handlers->maximum_queued_bytes) return;
                    handlers->signal->queued_bytes += datagram.payload.size();
                    handlers->signal->datagrams.push_back(std::move(datagram));
                    handlers->signal->condition.notify_all();
                } catch (...) {
                    std::lock_guard lock(handlers->signal->mutex);
                    handlers->signal->closed = true;
                    handlers->signal->error = "invalid QUIC datagram content";
                    handlers->signal->condition.notify_all();
                }
            });
        nw_connection_group_set_new_connection_handler(
            group_, ^(nw_connection_t connection) {
                nw_connection_set_queue(connection, handlers->io_queue);
                nw_connection_receive(
                    connection, 8, 8,
                    ^(dispatch_data_t content, nw_content_context_t, bool,
                      nw_error_t error) {
                        try {
                            auto header = copy_dispatch_data(content);
                            std::lock_guard lock(handlers->signal->mutex);
                            if (error != nullptr || header.size() != 8 ||
                                !std::ranges::equal(
                                    stream_magic,
                                    std::span<const std::byte>(header).first(4)) ||
                                header[5] != std::byte{} ||
                                header[6] != std::byte{} ||
                                header[7] != std::byte{}) {
                                nw_connection_cancel(connection);
                                return;
                            }
                            const auto raw =
                                std::to_integer<std::uint8_t>(header[4]);
                            if (raw > static_cast<std::uint8_t>(StreamPurpose::build) ||
                                handlers->signal->streams.size() >=
                                    handlers->maximum_pending_streams) {
                                nw_connection_cancel(connection);
                                return;
                            }
                            handlers->signal->streams.push_back({
                                .purpose = static_cast<StreamPurpose>(raw),
                                .stream = std::make_unique<NetworkReliableStream>(
                                    connection, handlers->stream_timeout,
                                    handlers->maximum_queued_bytes),
                            });
                            handlers->signal->condition.notify_all();
                        } catch (...) {
                            nw_connection_cancel(connection);
                        }
                    });
            });
    }

    nw_connection_group_t group_{};
    TransportEndpoint endpoint_;
    QuicTransportSettings settings_;
    std::chrono::milliseconds stream_timeout_{};
    std::size_t maximum_pending_streams_{};
    std::size_t maximum_pending_datagrams_{};
    std::size_t maximum_queued_bytes_{};
    dispatch_queue_t queue_{};
    dispatch_queue_t io_queue_{};
    std::shared_ptr<GroupSignal> signal_;
};

[[nodiscard]] nw_connection_group_t make_client_group(
    const AppleNetworkClientOptions& options,
    const TransportEndpoint& endpoint,
    const QuicTransportSettings& settings,
    dispatch_queue_t verify_queue) {
    const auto port = std::to_string(endpoint.port);
    const auto remote = nw_endpoint_create_host(
        endpoint.host.c_str(), port.c_str());
    if (remote == nullptr) throw std::runtime_error("QUIC endpoint creation failed");
    const auto descriptor = nw_group_descriptor_create_multiplex(remote);
    if (descriptor == nullptr) {
        throw std::runtime_error("QUIC multiplex descriptor creation failed");
    }
    const auto parameters = make_quic_parameters(
        options.identity, settings, false, endpoint.host, verify_queue);
    const auto group = nw_connection_group_create(descriptor, parameters);
    if (group == nullptr) throw std::runtime_error("QUIC group creation failed");
    return group;
}

}  // namespace

class NetworkFrameworkClientConnector::Impl {
public:
    explicit Impl(AppleNetworkClientOptions options)
        : options_(std::move(options)),
          verify_queue_(dispatch_queue_create(
              "com.remoteworkspacenode.transport.quic.verify",
              DISPATCH_QUEUE_SERIAL)) {
        validate_apple_network_client_options(options_);
        if (verify_queue_ == nullptr) {
            throw std::runtime_error("QUIC verification queue creation failed");
        }
    }

    [[nodiscard]] std::unique_ptr<Transport> connect(
        const TransportMode mode, const TransportEndpoint& endpoint,
        const QuicTransportSettings& settings) {
        if (mode != TransportMode::quic) {
            throw std::invalid_argument(
                "Network.framework QUIC connector cannot create fallback transports");
        }
        validate_transport_endpoint(endpoint);
        validate_quic_transport_settings(settings);
        const auto group = make_client_group(
            options_, endpoint, settings, verify_queue_);
        return std::make_unique<NetworkFrameworkTransport>(
            group, endpoint, settings, options_.stream_read_timeout,
            options_.maximum_pending_streams,
            options_.maximum_pending_datagrams,
            options_.maximum_queued_bytes, options_.connect_timeout, true);
    }

    [[nodiscard]] bool migrate(
        Transport& transport, const TransportEndpoint& endpoint) {
        auto* native = dynamic_cast<NetworkFrameworkTransport*>(&transport);
        return native != nullptr && native->path_changed(endpoint);
    }

private:
    AppleNetworkClientOptions options_;
    dispatch_queue_t verify_queue_{};
};

NetworkFrameworkClientConnector::NetworkFrameworkClientConnector(
    AppleNetworkClientOptions options)
    : impl_(std::make_unique<Impl>(std::move(options))) {}
NetworkFrameworkClientConnector::~NetworkFrameworkClientConnector() = default;
NetworkFrameworkClientConnector::NetworkFrameworkClientConnector(
    NetworkFrameworkClientConnector&&) noexcept = default;
NetworkFrameworkClientConnector& NetworkFrameworkClientConnector::operator=(
    NetworkFrameworkClientConnector&&) noexcept = default;

std::unique_ptr<Transport> NetworkFrameworkClientConnector::connect(
    const TransportMode mode, const TransportEndpoint& endpoint,
    const QuicTransportSettings& settings) {
    if (!impl_) throw std::logic_error("Network.framework connector was moved");
    return impl_->connect(mode, endpoint, settings);
}

bool NetworkFrameworkClientConnector::migrate(
    Transport& transport, const TransportEndpoint& endpoint) {
    return impl_ != nullptr && impl_->migrate(transport, endpoint);
}

struct ListenerSignal {
    std::mutex mutex;
    std::condition_variable condition;
    std::deque<nw_connection_group_t> pending;
    std::size_t maximum_pending_connections{};
    bool closed{};
    std::string error;
};

class NetworkFrameworkServerListener::Impl {
public:
    Impl(AppleNetworkServerOptions options, QuicTransportSettings settings)
        : options_(std::move(options)), settings_(std::move(settings)),
          queue_(dispatch_queue_create(
              "com.remoteworkspacenode.transport.quic.listener",
              DISPATCH_QUEUE_SERIAL)),
          verify_queue_(dispatch_queue_create(
              "com.remoteworkspacenode.transport.quic.listener.verify",
              DISPATCH_QUEUE_SERIAL)),
          signal_(std::make_shared<ListenerSignal>()) {
        validate_apple_network_server_options(options_);
        validate_quic_transport_settings(settings_);
        if (queue_ == nullptr || verify_queue_ == nullptr) {
            throw std::runtime_error("QUIC listener queue creation failed");
        }
        signal_->maximum_pending_connections =
            options_.maximum_pending_connections;
        const auto parameters = make_quic_parameters(
            options_.identity, settings_, true, {}, verify_queue_);
        const auto port = std::to_string(options_.listen_port);
        listener_ = nw_listener_create_with_port(port.c_str(), parameters);
        if (listener_ == nullptr) {
            throw std::runtime_error("QUIC listener creation failed");
        }
        nw_listener_set_new_connection_limit(
            listener_, static_cast<std::uint32_t>(
                options_.maximum_pending_connections));
        nw_listener_set_queue(listener_, queue_);
        const auto signal = signal_;
        nw_listener_set_state_changed_handler(
            listener_, ^(nw_listener_state_t state, nw_error_t error) {
                std::lock_guard lock(signal->mutex);
                if (state == nw_listener_state_failed ||
                    state == nw_listener_state_cancelled) {
                    signal->closed = true;
                    if (error != nullptr) {
                        signal->error = network_error_text(error);
                    }
                }
                signal->condition.notify_all();
            });
        nw_listener_set_new_connection_group_handler(
            listener_, ^(nw_connection_group_t group) {
                std::lock_guard lock(signal->mutex);
                if (signal->pending.size() >=
                    signal->maximum_pending_connections) {
                    nw_connection_group_cancel(group);
                    return;
                }
                signal->pending.push_back(group);
                signal->condition.notify_all();
            });
        nw_listener_start(listener_);
    }

    ~Impl() {
        if (listener_ != nullptr) nw_listener_cancel(listener_);
    }

    [[nodiscard]] AuthenticatedConnection accept(
        const std::chrono::milliseconds timeout) {
        if (timeout <= std::chrono::milliseconds::zero() ||
            timeout > std::chrono::minutes{5}) {
            throw std::invalid_argument("QUIC listener accept timeout is invalid");
        }
        nw_connection_group_t group{};
        {
            std::unique_lock lock(signal_->mutex);
            if (!signal_->condition.wait_for(lock, timeout, [&] {
                    return !signal_->pending.empty() || signal_->closed;
                })) {
                throw std::runtime_error("QUIC listener accept timed out");
            }
            if (signal_->pending.empty()) {
                throw std::runtime_error(signal_->error.empty()
                    ? "QUIC listener is closed" : signal_->error);
            }
            group = signal_->pending.front();
            signal_->pending.pop_front();
        }
        const auto peer = single_allowed_peer_evidence(
            options_.identity.allowed_peer_certificate_sha256);
        auto transport = std::make_unique<NetworkFrameworkTransport>(
            group, TransportEndpoint{.host = "authenticated-peer",
                                     .port = options_.listen_port},
            settings_, options_.stream_read_timeout,
            options_.maximum_pending_streams,
            options_.maximum_pending_datagrams,
            options_.maximum_queued_bytes, timeout, true);
        return {
            .transport = std::move(transport),
            .peer = peer,
        };
    }

    [[nodiscard]] std::uint16_t listen_port() const noexcept {
        return listener_ == nullptr ? 0 : nw_listener_get_port(listener_);
    }

private:
    AppleNetworkServerOptions options_;
    QuicTransportSettings settings_;
    dispatch_queue_t queue_{};
    dispatch_queue_t verify_queue_{};
    nw_listener_t listener_{};
    std::shared_ptr<ListenerSignal> signal_;
};

NetworkFrameworkServerListener::NetworkFrameworkServerListener(
    AppleNetworkServerOptions options, QuicTransportSettings settings)
    : impl_(std::make_unique<Impl>(std::move(options), std::move(settings))) {}
NetworkFrameworkServerListener::~NetworkFrameworkServerListener() = default;
NetworkFrameworkServerListener::NetworkFrameworkServerListener(
    NetworkFrameworkServerListener&&) noexcept = default;
NetworkFrameworkServerListener& NetworkFrameworkServerListener::operator=(
    NetworkFrameworkServerListener&&) noexcept = default;

rwn::transport::AuthenticatedConnection NetworkFrameworkServerListener::accept(
    const std::chrono::milliseconds timeout) {
    if (!impl_) throw std::logic_error("Network.framework listener was moved");
    return impl_->accept(timeout);
}

std::uint16_t NetworkFrameworkServerListener::listen_port() const noexcept {
    return impl_ == nullptr ? 0 : impl_->listen_port();
}

}  // namespace rwn::platform::macos
