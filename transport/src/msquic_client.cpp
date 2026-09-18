#include "rwn/transport/msquic_client.hpp"
#include "rwn/transport/msquic_server.hpp"

#ifndef _WIN32
#error "The MsQuic Schannel provider is Windows-only"
#endif

#include <msquic.h>
#include <windows.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <limits>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace rwn::transport {
namespace {

constexpr std::size_t maximum_stream_message_bytes = 16U * 1024U * 1024U;
constexpr std::size_t maximum_incoming_streams = 64U;
constexpr std::size_t maximum_queued_stream_messages = 256U;
constexpr std::size_t maximum_queued_stream_bytes = 32U * 1024U * 1024U;
constexpr std::size_t maximum_queued_datagrams = 256U;
constexpr std::size_t maximum_queued_datagram_bytes = 4U * 1024U * 1024U;
constexpr std::array<std::uint8_t, 4> stream_magic{'R', 'W', 'N', 1};

[[nodiscard]] MsQuicClientOptions validate_client_options(
    MsQuicClientOptions options) {
    const auto zero_fingerprint = [](const CertificateSha256& value) {
        return std::ranges::all_of(
            value, [](const auto byte) { return byte == 0; });
    };
    if (options.connect_timeout < std::chrono::milliseconds{100} ||
        options.connect_timeout > std::chrono::minutes{2} ||
        options.stream_read_timeout < std::chrono::milliseconds{100} ||
        options.stream_read_timeout >
            std::chrono::hours{24} + std::chrono::minutes{2} ||
        options.allowed_server_certificate_sha256.empty() ||
        options.allowed_server_certificate_sha256.size() > 256 ||
        std::ranges::all_of(
            options.client_certificate_sha1,
            [](const auto byte) { return byte == 0; })) {
        throw std::invalid_argument("MsQuic client options are invalid");
    }
    for (std::size_t index = 0;
         index < options.allowed_server_certificate_sha256.size(); ++index) {
        if (zero_fingerprint(
                options.allowed_server_certificate_sha256[index]) ||
            std::ranges::find(
                options.allowed_server_certificate_sha256.begin(),
                options.allowed_server_certificate_sha256.begin() +
                    static_cast<std::ptrdiff_t>(index),
                options.allowed_server_certificate_sha256[index]) !=
                options.allowed_server_certificate_sha256.begin() +
                    static_cast<std::ptrdiff_t>(index)) {
            throw std::invalid_argument(
                "MsQuic server certificate fingerprints must be nonzero and unique");
        }
    }
    return options;
}

[[nodiscard]] MsQuicServerOptions validated_server_options(
    MsQuicServerOptions options) {
    const auto all_zero = [](const auto& value) {
        return std::ranges::all_of(
            value, [](const auto byte) { return byte == 0; });
    };
    if (!options.runtime_library.is_absolute() ||
        options.runtime_library.filename() != L"msquic.dll" ||
        options.listen_port == 0 ||
        options.stream_read_timeout < std::chrono::milliseconds{100} ||
        options.stream_read_timeout > std::chrono::minutes{5} ||
        options.maximum_pending_connections == 0 ||
        options.maximum_pending_connections > 256 ||
        all_zero(options.server_certificate_sha1) ||
        options.allowed_client_certificate_sha256.empty() ||
        options.allowed_client_certificate_sha256.size() > 256) {
        throw std::invalid_argument("MsQuic server options are invalid");
    }
    for (std::size_t index = 0;
         index < options.allowed_client_certificate_sha256.size(); ++index) {
        if (all_zero(options.allowed_client_certificate_sha256[index])) {
            throw std::invalid_argument(
                "MsQuic client certificate fingerprint cannot be zero");
        }
        if (std::ranges::find(
                options.allowed_client_certificate_sha256.begin(),
                options.allowed_client_certificate_sha256.begin() +
                    static_cast<std::ptrdiff_t>(index),
                options.allowed_client_certificate_sha256[index]) !=
            options.allowed_client_certificate_sha256.begin() +
                static_cast<std::ptrdiff_t>(index)) {
            throw std::invalid_argument(
                "MsQuic client certificate fingerprints must be unique");
        }
    }
    return options;
}

[[nodiscard]] std::string windows_error(const char* operation) {
    return std::string(operation) + " failed with Windows error " +
           std::to_string(GetLastError());
}

[[nodiscard]] std::filesystem::path validate_runtime_path(
    const std::filesystem::path& path) {
    if (!path.is_absolute() || path.filename() != L"msquic.dll") {
        throw std::invalid_argument(
            "MsQuic runtime must be an absolute path ending in msquic.dll");
    }
    std::error_code error;
    const auto canonical = std::filesystem::weakly_canonical(path, error);
    if (error || !std::filesystem::is_regular_file(canonical, error) || error) {
        throw std::invalid_argument("MsQuic runtime is not a regular file");
    }
    return canonical;
}

[[nodiscard]] std::uint8_t hex_nibble(const char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<std::uint8_t>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<std::uint8_t>(value - 'a' + 10);
    }
    if (value >= 'A' && value <= 'F') {
        return static_cast<std::uint8_t>(value - 'A' + 10);
    }
    throw std::invalid_argument("certificate thumbprint is not hexadecimal");
}

void require_success(const QUIC_STATUS status, const char* operation) {
    if (QUIC_FAILED(status)) {
        throw std::runtime_error(
            std::string(operation) + " failed with QUIC status " +
            std::to_string(static_cast<std::int32_t>(status)));
    }
}

template <typename Function>
[[nodiscard]] Function resolve_function(
    const HMODULE module, const char* symbol_name) {
    const auto symbol = GetProcAddress(module, symbol_name);
    if (symbol == nullptr) throw std::runtime_error(windows_error("GetProcAddress"));
    static_assert(sizeof(Function) == sizeof(symbol));
    Function function{};
    std::memcpy(&function, &symbol, sizeof(function));
    return function;
}

class MsQuicRuntime final {
public:
    explicit MsQuicRuntime(const std::filesystem::path& library_path)
        : path_(validate_runtime_path(library_path)) {
        module_ = LoadLibraryExW(
            path_.c_str(), nullptr,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (module_ == nullptr) throw std::runtime_error(windows_error("LoadLibraryExW"));
        try {
            open_ = resolve_function<MsQuicOpenVersionFn>(
                module_, "MsQuicOpenVersion");
            close_ = resolve_function<MsQuicCloseFn>(module_, "MsQuicClose");
            const void* table{};
            require_success(
                open_(QUIC_API_VERSION_2, &table), "MsQuicOpenVersion");
            api_ = static_cast<const QUIC_API_TABLE*>(table);
            if (api_ == nullptr) {
                throw std::runtime_error("MsQuic returned a null API table");
            }

            const QUIC_REGISTRATION_CONFIG registration_config{
                "RemoteWorkspaceNode", QUIC_EXECUTION_PROFILE_LOW_LATENCY};
            require_success(
                api_->RegistrationOpen(&registration_config, &registration_),
                "RegistrationOpen");
        } catch (...) {
            cleanup();
            throw;
        }
    }

    ~MsQuicRuntime() { cleanup(); }

    void cleanup() noexcept {
        if (registration_ != nullptr && api_ != nullptr) {
            api_->RegistrationClose(registration_);
            registration_ = nullptr;
        }
        if (api_ != nullptr && close_ != nullptr) {
            close_(api_);
            api_ = nullptr;
        }
        if (module_ != nullptr) {
            FreeLibrary(module_);
            module_ = nullptr;
        }
    }

    MsQuicRuntime(const MsQuicRuntime&) = delete;
    MsQuicRuntime& operator=(const MsQuicRuntime&) = delete;

    [[nodiscard]] const QUIC_API_TABLE& api() const { return *api_; }
    [[nodiscard]] HQUIC registration() const { return registration_; }
    [[nodiscard]] const std::filesystem::path& path() const { return path_; }

    [[nodiscard]] MsQuicRuntimeInfo info() const {
        MsQuicRuntimeInfo result{.loaded_library = path_};
        std::uint32_t bytes = static_cast<std::uint32_t>(
            result.library_version.size() * sizeof(std::uint32_t));
        require_success(
            api_->GetParam(nullptr, QUIC_PARAM_GLOBAL_LIBRARY_VERSION, &bytes,
                           result.library_version.data()),
            "GetParam(QUIC_PARAM_GLOBAL_LIBRARY_VERSION)");
        if (bytes != result.library_version.size() * sizeof(std::uint32_t)) {
            throw std::runtime_error("MsQuic returned an invalid version length");
        }
        return result;
    }

private:
    std::filesystem::path path_;
    HMODULE module_{};
    MsQuicOpenVersionFn open_{};
    MsQuicCloseFn close_{};
    const QUIC_API_TABLE* api_{};
    HQUIC registration_{};
};

struct SendContext {
    explicit SendContext(std::vector<std::uint8_t> value)
        : bytes(std::move(value)), buffer{
              static_cast<std::uint32_t>(bytes.size()), bytes.data()} {}

    std::vector<std::uint8_t> bytes;
    QUIC_BUFFER buffer;
};

class MsQuicReliableStream final : public ReliableStream {
public:
    MsQuicReliableStream(
        std::shared_ptr<MsQuicRuntime> runtime, HQUIC connection,
        const StreamPurpose purpose,
        const std::chrono::milliseconds read_timeout)
        : runtime_(std::move(runtime)), read_timeout_(read_timeout) {
        require_success(
            runtime_->api().StreamOpen(
                connection, QUIC_STREAM_OPEN_FLAG_NONE, stream_callback, this,
                &stream_),
            "StreamOpen");
        try {
            require_success(
                runtime_->api().StreamStart(
                    stream_, QUIC_STREAM_START_FLAG_IMMEDIATE),
                "StreamStart");
            send_raw({
                stream_magic[0], stream_magic[1], stream_magic[2], stream_magic[3],
                static_cast<std::uint8_t>(purpose), 0, 0, 0});
        } catch (...) {
            runtime_->api().StreamClose(stream_);
            stream_ = nullptr;
            throw;
        }
    }

    MsQuicReliableStream(
        std::shared_ptr<MsQuicRuntime> runtime, const HQUIC accepted_stream,
        const std::chrono::milliseconds read_timeout)
        : runtime_(std::move(runtime)), stream_(accepted_stream),
          read_timeout_(read_timeout), incoming_(true) {
        if (stream_ == nullptr) {
            throw std::invalid_argument("accepted QUIC stream is null");
        }
        QUIC_STREAM_CALLBACK_HANDLER handler = stream_callback;
        void* callback{};
        static_assert(sizeof(callback) == sizeof(handler));
        std::memcpy(&callback, &handler, sizeof(callback));
        runtime_->api().SetCallbackHandler(stream_, callback, this);
    }

    ~MsQuicReliableStream() override {
        if (stream_ != nullptr) {
            runtime_->api().StreamShutdown(
                stream_, static_cast<QUIC_STREAM_SHUTDOWN_FLAGS>(
                             QUIC_STREAM_SHUTDOWN_FLAG_ABORT |
                             QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE),
                0);
            runtime_->api().StreamClose(stream_);
        }
    }

    void write(const std::span<const std::byte> data) override {
        if (data.empty() || data.size() > maximum_stream_message_bytes) {
            throw std::length_error("QUIC stream message is outside bounds");
        }
        const auto length = static_cast<std::uint32_t>(data.size());
        std::vector<std::uint8_t> framed(4U + data.size());
        framed[0] = static_cast<std::uint8_t>((length >> 24U) & 0xffU);
        framed[1] = static_cast<std::uint8_t>((length >> 16U) & 0xffU);
        framed[2] = static_cast<std::uint8_t>((length >> 8U) & 0xffU);
        framed[3] = static_cast<std::uint8_t>(length & 0xffU);
        std::memcpy(framed.data() + 4U, data.data(), data.size());
        send_raw(std::move(framed));
    }

    [[nodiscard]] std::vector<std::byte> read() override {
        std::unique_lock lock(mutex_);
        if (!condition_.wait_for(lock, read_timeout_, [this] {
                return !messages_.empty() || closed_ || !error_.empty();
            })) {
            throw std::runtime_error("QUIC stream read timed out");
        }
        if (!error_.empty()) throw std::runtime_error(error_);
        if (messages_.empty()) throw std::runtime_error("QUIC stream closed");
        auto message = std::move(messages_.front());
        queued_message_bytes_ -= message.size();
        messages_.pop_front();
        return message;
    }

    [[nodiscard]] StreamPurpose wait_for_purpose(
        const std::chrono::milliseconds timeout) {
        std::unique_lock lock(mutex_);
        if (!incoming_) {
            throw std::logic_error("outgoing QUIC stream has no peer purpose");
        }
        if (!condition_.wait_for(lock, timeout, [this] {
                return purpose_.has_value() || closed_ || !error_.empty();
            })) {
            throw std::runtime_error("QUIC stream purpose timed out");
        }
        if (!error_.empty()) throw std::runtime_error(error_);
        if (!purpose_) throw std::runtime_error("QUIC stream closed before header");
        return *purpose_;
    }

private:
    static QUIC_STATUS QUIC_API stream_callback(
        HQUIC, void* context, QUIC_STREAM_EVENT* event) {
        auto& self = *static_cast<MsQuicReliableStream*>(context);
        if (event == nullptr) return QUIC_STATUS_INVALID_PARAMETER;
        switch (event->Type) {
            case QUIC_STREAM_EVENT_RECEIVE:
                self.receive(*event);
                break;
            case QUIC_STREAM_EVENT_SEND_COMPLETE:
                delete static_cast<SendContext*>(
                    event->SEND_COMPLETE.ClientContext);
                break;
            case QUIC_STREAM_EVENT_START_COMPLETE:
                if (QUIC_FAILED(event->START_COMPLETE.Status)) {
                    self.fail("QUIC stream start failed");
                }
                break;
            case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
                self.fail("QUIC stream was aborted by peer");
                break;
            case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
                std::scoped_lock lock(self.mutex_);
                self.closed_ = true;
                self.condition_.notify_all();
                break;
            }
            default:
                break;
        }
        return QUIC_STATUS_SUCCESS;
    }

    void receive(const QUIC_STREAM_EVENT& event) {
        std::scoped_lock lock(mutex_);
        if (closed_ || !error_.empty()) return;
        for (std::uint32_t index = 0; index < event.RECEIVE.BufferCount; ++index) {
            const auto& buffer = event.RECEIVE.Buffers[index];
            const auto receive_limit = maximum_stream_message_bytes + 4U +
                (incoming_ && !purpose_ ? 8U : 0U);
            if (buffer.Length > receive_limit ||
                receive_bytes_.size() > receive_limit - buffer.Length) {
                error_ = "QUIC stream receive buffer exceeded limit";
                condition_.notify_all();
                return;
            }
            receive_bytes_.insert(
                receive_bytes_.end(), buffer.Buffer,
                buffer.Buffer + buffer.Length);
        }
        if (incoming_ && !purpose_) {
            if (receive_bytes_.size() < 8U) return;
            if (!std::ranges::equal(
                    stream_magic,
                    std::span<const std::uint8_t>(receive_bytes_).first(4)) ||
                receive_bytes_[4] >
                    static_cast<std::uint8_t>(StreamPurpose::build) ||
                receive_bytes_[5] != 0 || receive_bytes_[6] != 0 ||
                receive_bytes_[7] != 0) {
                error_ = "QUIC peer stream header is invalid";
                condition_.notify_all();
                return;
            }
            purpose_ = static_cast<StreamPurpose>(receive_bytes_[4]);
            receive_bytes_.erase(
                receive_bytes_.begin(), receive_bytes_.begin() + 8);
            condition_.notify_all();
        }
        while (receive_bytes_.size() >= 4U) {
            const auto length =
                (static_cast<std::uint32_t>(receive_bytes_[0]) << 24U) |
                (static_cast<std::uint32_t>(receive_bytes_[1]) << 16U) |
                (static_cast<std::uint32_t>(receive_bytes_[2]) << 8U) |
                static_cast<std::uint32_t>(receive_bytes_[3]);
            if (length == 0 || length > maximum_stream_message_bytes) {
                error_ = "QUIC stream frame length is invalid";
                condition_.notify_all();
                return;
            }
            if (receive_bytes_.size() < 4U + length) break;
            if (messages_.size() >= maximum_queued_stream_messages ||
                length > maximum_queued_stream_bytes - queued_message_bytes_) {
                error_ = "QUIC stream message queue exceeded limit";
                condition_.notify_all();
                return;
            }
            std::vector<std::byte> message(length);
            std::memcpy(message.data(), receive_bytes_.data() + 4U, length);
            messages_.push_back(std::move(message));
            queued_message_bytes_ += length;
            receive_bytes_.erase(
                receive_bytes_.begin(), receive_bytes_.begin() + 4U + length);
        }
        condition_.notify_all();
    }

    void fail(std::string message) {
        std::scoped_lock lock(mutex_);
        error_ = std::move(message);
        condition_.notify_all();
    }

    void send_raw(std::vector<std::uint8_t> bytes) {
        if (bytes.size() > std::numeric_limits<std::uint32_t>::max()) {
            throw std::length_error("QUIC stream send exceeds API limit");
        }
        auto context = std::make_unique<SendContext>(std::move(bytes));
        const auto status = runtime_->api().StreamSend(
            stream_, &context->buffer, 1, QUIC_SEND_FLAG_NONE, context.get());
        require_success(status, "StreamSend");
        static_cast<void>(context.release());
    }

    std::shared_ptr<MsQuicRuntime> runtime_;
    HQUIC stream_{};
    std::chrono::milliseconds read_timeout_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::vector<std::uint8_t> receive_bytes_;
    std::deque<std::vector<std::byte>> messages_;
    std::size_t queued_message_bytes_{};
    std::string error_;
    std::optional<StreamPurpose> purpose_;
    bool incoming_{};
    bool closed_{};
};

class MsQuicTransport final : public DuplexTransport {
public:
    MsQuicTransport(
        std::shared_ptr<MsQuicRuntime> runtime, MsQuicClientOptions options,
        TransportEndpoint endpoint, const QuicTransportSettings& settings)
        : runtime_(std::move(runtime)), endpoint_(std::move(endpoint)),
          connect_timeout_(options.connect_timeout),
          stream_read_timeout_(options.stream_read_timeout),
          allowed_server_certificates_(
              std::move(options.allowed_server_certificate_sha256)) {
        validate_transport_endpoint(endpoint_);
        validate_quic_transport_settings(settings);
        if (settings.alpn.size() > std::numeric_limits<std::uint32_t>::max()) {
            throw std::length_error("MsQuic ALPN exceeds API limit");
        }
        alpn_.assign(settings.alpn.begin(), settings.alpn.end());
        maximum_datagram_bytes_ = settings.maximum_datagram_bytes;
        QUIC_BUFFER alpn_buffer{
            static_cast<std::uint32_t>(alpn_.size()), alpn_.data()};
        QUIC_SETTINGS native{};
        native.IdleTimeoutMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                settings.idle_timeout).count());
        native.IsSet.IdleTimeoutMs = TRUE;
        native.KeepAliveIntervalMs = static_cast<std::uint32_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                settings.keep_alive).count());
        native.IsSet.KeepAliveIntervalMs = TRUE;
        native.MigrationEnabled = settings.enable_connection_migration ? TRUE : FALSE;
        native.IsSet.MigrationEnabled = TRUE;
        native.DatagramReceiveEnabled = settings.enable_datagrams ? TRUE : FALSE;
        native.IsSet.DatagramReceiveEnabled = TRUE;
        native.PeerBidiStreamCount = 64;
        native.IsSet.PeerBidiStreamCount = TRUE;

        require_success(
            runtime_->api().ConfigurationOpen(
                runtime_->registration(), &alpn_buffer, 1, &native,
                sizeof(native), nullptr, &configuration_),
            "ConfigurationOpen");
        try {
            QUIC_CERTIFICATE_HASH certificate{};
            std::ranges::copy(
                options.client_certificate_sha1, certificate.ShaHash);
            QUIC_CREDENTIAL_CONFIG credentials{};
            credentials.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
            credentials.CertificateHash = &certificate;
            credentials.Flags = static_cast<QUIC_CREDENTIAL_FLAGS>(
                QUIC_CREDENTIAL_FLAG_CLIENT |
                QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED |
                QUIC_CREDENTIAL_FLAG_USE_SUPPLIED_CREDENTIALS |
                QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT);
            require_success(
                runtime_->api().ConfigurationLoadCredential(
                    configuration_, &credentials),
                "ConfigurationLoadCredential");
            require_success(
                runtime_->api().ConnectionOpen(
                    runtime_->registration(), connection_callback, this,
                    &connection_),
                "ConnectionOpen");
            require_success(
                runtime_->api().ConnectionStart(
                    connection_, configuration_, QUIC_ADDRESS_FAMILY_UNSPEC,
                    endpoint_.host.c_str(), endpoint_.port),
                "ConnectionStart");
            wait_for_connection();
        } catch (...) {
            close_handles();
            throw;
        }
    }

    MsQuicTransport(
        std::shared_ptr<MsQuicRuntime> runtime, const HQUIC connection,
        const std::chrono::milliseconds stream_read_timeout,
        const std::size_t maximum_datagram_bytes,
        std::vector<CertificateSha256> allowed_client_certificates,
        std::function<void()> state_changed)
        : runtime_(std::move(runtime)), connection_(connection),
          stream_read_timeout_(stream_read_timeout),
          maximum_datagram_bytes_(maximum_datagram_bytes),
          allowed_client_certificates_(
              std::move(allowed_client_certificates)),
          state_changed_(std::move(state_changed)), server_side_(true) {
        if (connection_ == nullptr ||
            allowed_client_certificates_.empty()) {
            throw std::invalid_argument(
                "accepted MsQuic connection options are invalid");
        }
        QUIC_CONNECTION_CALLBACK_HANDLER handler = connection_callback;
        void* callback{};
        static_assert(sizeof(callback) == sizeof(handler));
        std::memcpy(&callback, &handler, sizeof(callback));
        runtime_->api().SetCallbackHandler(connection_, callback, this);
    }

    ~MsQuicTransport() override { close_handles(); }

    void start_server(const HQUIC configuration) {
        if (!server_side_ || configuration == nullptr) {
            throw std::invalid_argument(
                "MsQuic server configuration is invalid");
        }
        require_success(
            runtime_->api().ConnectionSetConfiguration(
                connection_, configuration),
            "ConnectionSetConfiguration");
    }

    [[nodiscard]] bool server_ready() const {
        std::scoped_lock lock(mutex_);
        return server_side_ && connected_ && peer_certificate_allowed_ &&
               !closed_;
    }

    [[nodiscard]] bool server_terminal() const {
        std::scoped_lock lock(mutex_);
        return server_side_ && (closed_ || QUIC_FAILED(failure_status_));
    }

    void abandon_server_connection() noexcept {
        if (server_side_) connection_ = nullptr;
    }

    [[nodiscard]] std::int32_t server_failure_status() const {
        std::scoped_lock lock(mutex_);
        return static_cast<std::int32_t>(failure_status_);
    }

    [[nodiscard]] std::string server_failure_reason() const {
        std::scoped_lock lock(mutex_);
        return std::string(server_failure_reason_);
    }

    [[nodiscard]] AuthenticatedPeerEvidence server_peer_evidence() const {
        std::scoped_lock lock(mutex_);
        const auto evidence = AuthenticatedPeerEvidence{
            .certificate_sha256 = peer_certificate_sha256_,
            .tls_1_3_negotiated = connected_,
            .certificate_chain_valid =
                server_deferred_error_flags_ == 0 &&
                !QUIC_FAILED(failure_status_),
            .revocation_checked =
                server_deferred_error_flags_ == 0 &&
                !QUIC_FAILED(failure_status_),
        };
        validate_authenticated_peer_evidence(evidence);
        return evidence;
    }

    [[nodiscard]] std::uint32_t server_deferred_error_flags() const {
        std::scoped_lock lock(mutex_);
        return server_deferred_error_flags_;
    }

    [[nodiscard]] std::unique_ptr<ReliableStream> open_stream(
        const StreamPurpose purpose) override {
        require_connected();
        return std::make_unique<MsQuicReliableStream>(
            runtime_, connection_, purpose, stream_read_timeout_);
    }

    [[nodiscard]] AcceptedStream accept_stream(
        const std::chrono::milliseconds timeout) override {
        require_connected();
        if (timeout < std::chrono::milliseconds{1} ||
            timeout > std::chrono::minutes{5}) {
            throw std::invalid_argument("QUIC peer stream timeout is invalid");
        }
        std::unique_ptr<MsQuicReliableStream> stream;
        {
            std::unique_lock lock(mutex_);
            if (!condition_.wait_for(lock, timeout, [this] {
                    return !incoming_streams_.empty() || closed_ ||
                           !receive_error_.empty();
                })) {
                throw std::runtime_error("QUIC peer stream accept timed out");
            }
            if (!receive_error_.empty()) {
                throw std::runtime_error(receive_error_);
            }
            if (incoming_streams_.empty()) {
                throw std::runtime_error("QUIC connection closed before stream");
            }
            stream = std::move(incoming_streams_.front());
            incoming_streams_.pop_front();
        }
        const auto purpose = stream->wait_for_purpose(timeout);
        return {.purpose = purpose, .stream = std::move(stream)};
    }

    void send_datagram(
        const DatagramChannel channel,
        const std::span<const std::byte> data) override {
        require_connected();
        std::uint16_t peer_limit{};
        {
            std::scoped_lock lock(mutex_);
            if (!datagram_enabled_) {
                throw std::runtime_error("peer did not negotiate QUIC datagrams");
            }
            peer_limit = maximum_datagram_length_;
        }
        if (data.empty() || data.size() + 1U > peer_limit) {
            throw std::length_error("QUIC datagram exceeds peer limit");
        }
        std::vector<std::uint8_t> framed(1U + data.size());
        framed[0] = static_cast<std::uint8_t>(channel);
        std::memcpy(framed.data() + 1U, data.data(), data.size());
        auto context = std::make_unique<SendContext>(std::move(framed));
        const auto status = runtime_->api().DatagramSend(
            connection_, &context->buffer, 1, QUIC_SEND_FLAG_NONE,
            context.get());
        require_success(status, "DatagramSend");
        static_cast<void>(context.release());
    }

    [[nodiscard]] ReceivedDatagram receive_datagram(
        const std::chrono::milliseconds timeout) override {
        require_connected();
        if (timeout < std::chrono::milliseconds{1} ||
            timeout > std::chrono::minutes{5}) {
            throw std::invalid_argument("QUIC datagram timeout is invalid");
        }
        std::unique_lock lock(mutex_);
        if (!condition_.wait_for(lock, timeout, [this] {
                return !incoming_datagrams_.empty() || closed_ ||
                       !receive_error_.empty();
            })) {
            throw std::runtime_error("QUIC datagram receive timed out");
        }
        if (!receive_error_.empty()) {
            throw std::runtime_error(receive_error_);
        }
        if (incoming_datagrams_.empty()) {
            throw std::runtime_error("QUIC connection closed before datagram");
        }
        auto result = std::move(incoming_datagrams_.front());
        queued_datagram_bytes_ -= result.payload.size();
        incoming_datagrams_.pop_front();
        return result;
    }

    [[nodiscard]] bool confirm_migration(const TransportEndpoint& endpoint) {
        if (endpoint.host != endpoint_.host || endpoint.port != endpoint_.port) {
            return false;
        }
        std::scoped_lock lock(mutex_);
        if (!connected_ || local_address_generation_ == consumed_generation_) {
            return false;
        }
        consumed_generation_ = local_address_generation_;
        endpoint_ = endpoint;
        return true;
    }

private:
    static QUIC_STATUS QUIC_API connection_callback(
        HQUIC, void* context, QUIC_CONNECTION_EVENT* event) {
        auto& self = *static_cast<MsQuicTransport*>(context);
        if (event == nullptr) return QUIC_STATUS_INVALID_PARAMETER;
        QUIC_STATUS result = QUIC_STATUS_SUCCESS;
        switch (event->Type) {
            case QUIC_CONNECTION_EVENT_CONNECTED: {
                std::scoped_lock lock(self.mutex_);
                if (!self.peer_certificate_allowed_) {
                    self.connected_ = false;
                    self.failure_status_ = QUIC_STATUS_BAD_CERTIFICATE;
                    if (self.server_failure_reason_.empty()) {
                        self.server_failure_reason_ =
                            "peer_certificate_not_observed";
                    }
                    result = QUIC_STATUS_BAD_CERTIFICATE;
                    break;
                }
                self.connected_ = true;
                self.failure_status_ = QUIC_STATUS_SUCCESS;
                self.consumed_generation_ = self.local_address_generation_;
                break;
            }
            case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT: {
                std::scoped_lock lock(self.mutex_);
                self.connected_ = false;
                self.failure_status_ =
                    event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status;
                if (self.server_side_ &&
                    self.server_failure_reason_.empty()) {
                    self.server_failure_reason_ = "transport";
                }
                break;
            }
            case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER: {
                std::scoped_lock lock(self.mutex_);
                self.connected_ = false;
                self.failure_status_ = QUIC_STATUS_ABORTED;
                if (self.server_side_ &&
                    self.server_failure_reason_.empty()) {
                    self.server_failure_reason_ = "peer_shutdown";
                }
                break;
            }
            case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE: {
                std::scoped_lock lock(self.mutex_);
                self.connected_ = false;
                self.closed_ = true;
                break;
            }
            case QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED: {
                std::scoped_lock lock(self.mutex_);
                ++self.local_address_generation_;
                break;
            }
            case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED: {
                std::scoped_lock lock(self.mutex_);
                self.datagram_enabled_ =
                    event->DATAGRAM_STATE_CHANGED.SendEnabled != FALSE;
                self.maximum_datagram_length_ =
                    event->DATAGRAM_STATE_CHANGED.MaxSendLength;
                break;
            }
            case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED:
                if (QUIC_DATAGRAM_SEND_STATE_IS_FINAL(
                        event->DATAGRAM_SEND_STATE_CHANGED.State)) {
                    delete static_cast<SendContext*>(
                        event->DATAGRAM_SEND_STATE_CHANGED.ClientContext);
                    event->DATAGRAM_SEND_STATE_CHANGED.ClientContext = nullptr;
                }
                break;
            case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
                self.peer_stream_started(
                    event->PEER_STREAM_STARTED.Stream,
                    event->PEER_STREAM_STARTED.Flags);
                break;
            case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
                self.datagram_received(event->DATAGRAM_RECEIVED.Buffer);
                break;
            case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
                result = self.peer_certificate_received(
                    event->PEER_CERTIFICATE_RECEIVED.Certificate,
                    event->PEER_CERTIFICATE_RECEIVED.DeferredErrorFlags,
                    event->PEER_CERTIFICATE_RECEIVED.DeferredStatus);
                break;
            default:
                break;
        }
        self.condition_.notify_all();
        self.notify_state_changed();
        return result;
    }

    [[nodiscard]] QUIC_STATUS peer_certificate_received(
        QUIC_CERTIFICATE* certificate,
        const std::uint32_t deferred_error_flags,
        const QUIC_STATUS deferred_status) noexcept {
        const auto invalid_deferred_validation = server_side_ &&
            (deferred_error_flags != 0 || QUIC_FAILED(deferred_status));
        if (certificate == nullptr || invalid_deferred_validation) {
            std::scoped_lock lock(mutex_);
            failure_status_ = invalid_deferred_validation &&
                    QUIC_FAILED(deferred_status)
                ? deferred_status
                : QUIC_STATUS_BAD_CERTIFICATE;
            server_deferred_error_flags_ = server_side_
                ? deferred_error_flags
                : 0;
            server_failure_reason_ = certificate == nullptr
                ? "peer_certificate_missing"
                : "peer_certificate_chain";
            return QUIC_STATUS_BAD_CERTIFICATE;
        }
        CertificateSha256 fingerprint{};
        DWORD fingerprint_bytes = static_cast<DWORD>(fingerprint.size());
        const auto* context = static_cast<PCCERT_CONTEXT>(certificate);
        if (CertGetCertificateContextProperty(
                context, CERT_SHA256_HASH_PROP_ID, fingerprint.data(),
                &fingerprint_bytes) == FALSE ||
            fingerprint_bytes != fingerprint.size()) {
            std::scoped_lock lock(mutex_);
            failure_status_ = QUIC_STATUS_BAD_CERTIFICATE;
            server_failure_reason_ = "peer_certificate_hash";
            return QUIC_STATUS_BAD_CERTIFICATE;
        }
        const auto& allowlist = server_side_
            ? allowed_client_certificates_
            : allowed_server_certificates_;
        const auto allowed = client_certificate_allowed(allowlist, fingerprint);
        {
            std::scoped_lock lock(mutex_);
            peer_certificate_allowed_ = allowed;
            if (allowed) peer_certificate_sha256_ = fingerprint;
            if (!allowed) {
                failure_status_ = QUIC_STATUS_BAD_CERTIFICATE;
                server_failure_reason_ = "peer_certificate_unpaired";
            }
        }
        return allowed ? QUIC_STATUS_SUCCESS : QUIC_STATUS_BAD_CERTIFICATE;
    }

    void notify_state_changed() noexcept {
        if (!state_changed_) return;
        try {
            state_changed_();
        } catch (...) {
        }
    }

    void wait_for_connection() {
        std::unique_lock lock(mutex_);
        if (!condition_.wait_for(lock, connect_timeout_, [this] {
                return connected_ || closed_ ||
                       QUIC_FAILED(failure_status_);
            })) {
            throw std::runtime_error("MsQuic connection timed out");
        }
        if (!connected_) {
            throw std::runtime_error(
                "MsQuic handshake failed with QUIC status " +
                std::to_string(static_cast<std::int32_t>(failure_status_)));
        }
    }

    void peer_stream_started(
        const HQUIC stream, const QUIC_STREAM_OPEN_FLAGS flags) noexcept {
        try {
            std::scoped_lock lock(mutex_);
            if (closed_ ||
                (flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL) != 0 ||
                incoming_streams_.size() >= maximum_incoming_streams) {
                runtime_->api().StreamShutdown(
                    stream,
                    static_cast<QUIC_STREAM_SHUTDOWN_FLAGS>(
                        QUIC_STREAM_SHUTDOWN_FLAG_ABORT |
                        QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE),
                    1);
                runtime_->api().StreamClose(stream);
                if (!closed_) {
                    receive_error_ =
                        (flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL) != 0
                            ? "QUIC unidirectional peer stream is unsupported"
                            : "QUIC peer stream queue overflow";
                }
                return;
            }
            incoming_streams_.push_back(
                std::make_unique<MsQuicReliableStream>(
                    runtime_, stream, stream_read_timeout_));
        } catch (...) {
            runtime_->api().StreamShutdown(
                stream,
                static_cast<QUIC_STREAM_SHUTDOWN_FLAGS>(
                    QUIC_STREAM_SHUTDOWN_FLAG_ABORT |
                    QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE),
                1);
            runtime_->api().StreamClose(stream);
            std::scoped_lock lock(mutex_);
            receive_error_ = "QUIC peer stream could not be accepted";
        }
    }

    void datagram_received(const QUIC_BUFFER* buffer) noexcept {
        try {
            std::scoped_lock lock(mutex_);
            if (closed_) return;
            if (buffer == nullptr || buffer->Buffer == nullptr ||
                buffer->Length < 2U ||
                buffer->Length > maximum_datagram_bytes_ + 1U ||
                buffer->Buffer[0] >
                    static_cast<std::uint8_t>(DatagramChannel::pointer)) {
                receive_error_ = "QUIC datagram frame is invalid";
                return;
            }
            const auto payload_size =
                static_cast<std::size_t>(buffer->Length - 1U);
            if (incoming_datagrams_.size() >= maximum_queued_datagrams ||
                payload_size > maximum_queued_datagram_bytes -
                                   queued_datagram_bytes_) {
                receive_error_ = "QUIC datagram receive queue overflow";
                return;
            }
            ReceivedDatagram datagram{
                .channel = static_cast<DatagramChannel>(buffer->Buffer[0]),
                .payload = std::vector<std::byte>(payload_size),
            };
            std::memcpy(
                datagram.payload.data(), buffer->Buffer + 1U, payload_size);
            queued_datagram_bytes_ += payload_size;
            incoming_datagrams_.push_back(std::move(datagram));
        } catch (...) {
            std::scoped_lock lock(mutex_);
            receive_error_ = "QUIC datagram receive allocation failed";
        }
    }

    void require_connected() const {
        std::scoped_lock lock(mutex_);
        if (!connected_ || closed_) {
            throw std::logic_error("MsQuic connection is not ready");
        }
    }

    void close_handles() {
        {
            std::scoped_lock lock(mutex_);
            incoming_streams_.clear();
            incoming_datagrams_.clear();
            queued_datagram_bytes_ = 0;
        }
        if (connection_ != nullptr) {
            runtime_->api().ConnectionShutdown(
                connection_, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
            runtime_->api().ConnectionClose(connection_);
            connection_ = nullptr;
        }
        if (configuration_ != nullptr) {
            runtime_->api().ConfigurationClose(configuration_);
            configuration_ = nullptr;
        }
    }

    std::shared_ptr<MsQuicRuntime> runtime_;
    TransportEndpoint endpoint_;
    std::vector<std::uint8_t> alpn_;
    HQUIC configuration_{};
    HQUIC connection_{};
    std::chrono::milliseconds connect_timeout_{10'000};
    std::chrono::milliseconds stream_read_timeout_{30'000};
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::deque<std::unique_ptr<MsQuicReliableStream>> incoming_streams_;
    std::deque<ReceivedDatagram> incoming_datagrams_;
    std::size_t queued_datagram_bytes_{};
    std::string receive_error_;
    QUIC_STATUS failure_status_{QUIC_STATUS_PENDING};
    std::uint64_t local_address_generation_{};
    std::uint64_t consumed_generation_{};
    std::uint16_t maximum_datagram_length_{};
    std::size_t maximum_datagram_bytes_{};
    std::vector<CertificateSha256> allowed_client_certificates_;
    std::vector<CertificateSha256> allowed_server_certificates_;
    CertificateSha256 peer_certificate_sha256_{};
    std::function<void()> state_changed_;
    std::string_view server_failure_reason_;
    std::uint32_t server_deferred_error_flags_{};
    bool connected_{};
    bool closed_{};
    bool datagram_enabled_{};
    bool server_side_{};
    bool peer_certificate_allowed_{};
};

}  // namespace

std::array<std::uint8_t, 20> parse_sha1_thumbprint(
    const std::string_view value) {
    if (value.size() != 40U) {
        throw std::invalid_argument(
            "certificate SHA-1 thumbprint must contain 40 hexadecimal digits");
    }
    std::array<std::uint8_t, 20> result{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = static_cast<std::uint8_t>(
            (hex_nibble(value[index * 2U]) << 4U) |
            hex_nibble(value[index * 2U + 1U]));
    }
    if (std::ranges::all_of(result, [](const auto byte) { return byte == 0; })) {
        throw std::invalid_argument("certificate thumbprint cannot be all zero");
    }
    return result;
}

CertificateSha256 parse_sha256_fingerprint(const std::string_view value) {
    if (value.size() != 64U) {
        throw std::invalid_argument(
            "certificate SHA-256 fingerprint must contain 64 hexadecimal digits");
    }
    CertificateSha256 result{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = static_cast<std::uint8_t>(
            (hex_nibble(value[index * 2U]) << 4U) |
            hex_nibble(value[index * 2U + 1U]));
    }
    if (std::ranges::all_of(
            result, [](const auto byte) { return byte == 0; })) {
        throw std::invalid_argument(
            "certificate SHA-256 fingerprint cannot be all zero");
    }
    return result;
}

bool client_certificate_allowed(
    const std::span<const CertificateSha256> allowlist,
    const CertificateSha256& fingerprint) noexcept {
    if (allowlist.empty() ||
        std::ranges::all_of(
            fingerprint, [](const auto byte) { return byte == 0; })) {
        return false;
    }
    return std::ranges::find(allowlist, fingerprint) != allowlist.end();
}

void validate_msquic_server_options(const MsQuicServerOptions& options) {
    static_cast<void>(validated_server_options(options));
}

MsQuicRuntimeInfo probe_msquic_runtime(
    const std::filesystem::path& runtime_library) {
    return MsQuicRuntime(runtime_library).info();
}

void validate_msquic_client_options(const MsQuicClientOptions& options) {
    static_cast<void>(validate_client_options(options));
}

class MsQuicClientConnector::Impl {
public:
    explicit Impl(MsQuicClientOptions options)
        : options_(validate_client_options(std::move(options))),
          runtime_(std::make_shared<MsQuicRuntime>(options_.runtime_library)) {
        options_.runtime_library = runtime_->path();
    }

    [[nodiscard]] std::unique_ptr<Transport> connect(
        const TransportMode mode, const TransportEndpoint& endpoint,
        const QuicTransportSettings& settings) {
        if (mode != TransportMode::quic) {
            throw std::invalid_argument(
                "MsQuic connector cannot create fallback transports");
        }
        return std::make_unique<MsQuicTransport>(
            runtime_, options_, endpoint, settings);
    }

    [[nodiscard]] bool migrate(
        Transport& transport, const TransportEndpoint& endpoint) {
        auto* native = dynamic_cast<MsQuicTransport*>(&transport);
        return native != nullptr && native->confirm_migration(endpoint);
    }

private:
    MsQuicClientOptions options_;
    std::shared_ptr<MsQuicRuntime> runtime_;
};

MsQuicClientConnector::MsQuicClientConnector(MsQuicClientOptions options)
    : impl_(std::make_unique<Impl>(std::move(options))) {}

MsQuicClientConnector::~MsQuicClientConnector() = default;
MsQuicClientConnector::MsQuicClientConnector(MsQuicClientConnector&&) noexcept = default;
MsQuicClientConnector& MsQuicClientConnector::operator=(
    MsQuicClientConnector&&) noexcept = default;

std::unique_ptr<Transport> MsQuicClientConnector::connect(
    const TransportMode mode, const TransportEndpoint& endpoint,
    const QuicTransportSettings& settings) {
    return impl_->connect(mode, endpoint, settings);
}

bool MsQuicClientConnector::migrate(
    Transport& transport, const TransportEndpoint& endpoint) {
    return impl_->migrate(transport, endpoint);
}

namespace {

struct MsQuicListenerSignal {
    std::mutex mutex;
    std::condition_variable condition;
    bool closed{};
};

}  // namespace

class MsQuicServerListener::Impl {
public:
    Impl(MsQuicServerOptions options, QuicTransportSettings settings)
        : options_(validated_server_options(std::move(options))),
          settings_(std::move(settings)),
          runtime_(std::make_shared<MsQuicRuntime>(
              options_.runtime_library)),
          signal_(std::make_shared<MsQuicListenerSignal>()) {
        validate_quic_transport_settings(settings_);
        options_.runtime_library = runtime_->path();
        pending_.reserve(options_.maximum_pending_connections);
        alpn_.assign(settings_.alpn.begin(), settings_.alpn.end());
        QUIC_BUFFER alpn_buffer{
            static_cast<std::uint32_t>(alpn_.size()), alpn_.data()};
        QUIC_SETTINGS native{};
        native.IdleTimeoutMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                settings_.idle_timeout).count());
        native.IsSet.IdleTimeoutMs = TRUE;
        native.KeepAliveIntervalMs = static_cast<std::uint32_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                settings_.keep_alive).count());
        native.IsSet.KeepAliveIntervalMs = TRUE;
        native.MigrationEnabled =
            settings_.enable_connection_migration ? TRUE : FALSE;
        native.IsSet.MigrationEnabled = TRUE;
        native.DatagramReceiveEnabled =
            settings_.enable_datagrams ? TRUE : FALSE;
        native.IsSet.DatagramReceiveEnabled = TRUE;
        native.PeerBidiStreamCount = 64;
        native.IsSet.PeerBidiStreamCount = TRUE;

        try {
            require_success(
                runtime_->api().ConfigurationOpen(
                    runtime_->registration(), &alpn_buffer, 1, &native,
                    sizeof(native), nullptr, &configuration_),
                "ConfigurationOpen(server)");
            QUIC_CERTIFICATE_HASH_STORE certificate{};
            certificate.Flags = options_.certificate_in_machine_store
                ? QUIC_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE
                : QUIC_CERTIFICATE_HASH_STORE_FLAG_NONE;
            std::ranges::copy(
                options_.server_certificate_sha1, certificate.ShaHash);
            constexpr std::array<char, 3> personal_store{'M', 'Y', '\0'};
            std::ranges::copy(personal_store, certificate.StoreName);
            QUIC_CREDENTIAL_CONFIG credentials{};
            credentials.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE;
            credentials.CertificateHashStore = &certificate;
            credentials.Flags = static_cast<QUIC_CREDENTIAL_FLAGS>(
                QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION |
                QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED |
                QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION |
                QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT);
            require_success(
                runtime_->api().ConfigurationLoadCredential(
                    configuration_, &credentials),
                "ConfigurationLoadCredential(server)");
            require_success(
                runtime_->api().ListenerOpen(
                    runtime_->registration(), listener_callback, this,
                    &listener_),
                "ListenerOpen");
            QUIC_ADDR address{};
            QuicAddrSetFamily(&address, QUIC_ADDRESS_FAMILY_UNSPEC);
            QuicAddrSetPort(&address, options_.listen_port);
            require_success(
                runtime_->api().ListenerStart(
                    listener_, &alpn_buffer, 1, &address),
                "ListenerStart");
        } catch (...) {
            cleanup();
            throw;
        }
    }

    ~Impl() { cleanup(); }

    [[nodiscard]] AuthenticatedConnection accept(
        const std::chrono::milliseconds timeout) {
        if (timeout < std::chrono::milliseconds{1} ||
            timeout > std::chrono::minutes{5}) {
            throw std::invalid_argument(
                "MsQuic server accept timeout is invalid");
        }
        std::unique_lock lock(signal_->mutex);
        const auto ready = [this] {
            return signal_->closed || std::ranges::any_of(
                pending_, [](const auto& connection) {
                    return connection->server_ready() ||
                           connection->server_terminal();
                });
        };
        if (!signal_->condition.wait_for(lock, timeout, ready)) {
            throw std::runtime_error("MsQuic server accept timed out");
        }
        if (signal_->closed) {
            throw std::runtime_error("MsQuic server listener is closed");
        }
        const auto found = std::ranges::find_if(
            pending_, [](const auto& connection) {
                return connection->server_ready();
            });
        if (found == pending_.end()) {
            const auto failed = std::ranges::find_if(
                pending_, [](const auto& connection) {
                    return connection->server_terminal();
                });
            if (failed != pending_.end()) {
                throw std::runtime_error(
                    "MsQuic server handshake failed with QUIC status " +
                    std::to_string((*failed)->server_failure_status()) +
                    " reason " + (*failed)->server_failure_reason() +
                    " flags " + std::to_string(
                        (*failed)->server_deferred_error_flags()));
            }
            throw std::runtime_error(
                "MsQuic server has no authenticated connection");
        }
        auto result = std::move(*found);
        pending_.erase(found);
        const auto peer = result->server_peer_evidence();
        return {
            .transport = std::move(result),
            .peer = peer,
        };
    }

    [[nodiscard]] std::uint16_t listen_port() const noexcept {
        return options_.listen_port;
    }

private:
    static QUIC_STATUS QUIC_API listener_callback(
        HQUIC, void* context, QUIC_LISTENER_EVENT* event) {
        if (context == nullptr || event == nullptr) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        auto& self = *static_cast<Impl*>(context);
        switch (event->Type) {
            case QUIC_LISTENER_EVENT_NEW_CONNECTION:
                return self.new_connection(
                    event->NEW_CONNECTION.Connection,
                    event->NEW_CONNECTION.Info);
            case QUIC_LISTENER_EVENT_STOP_COMPLETE:
                self.signal_->condition.notify_all();
                break;
            default:
                break;
        }
        return QUIC_STATUS_SUCCESS;
    }

    [[nodiscard]] QUIC_STATUS new_connection(
        const HQUIC connection,
        const QUIC_NEW_CONNECTION_INFO* info) noexcept {
        try {
            if (connection == nullptr || info == nullptr ||
                info->NegotiatedAlpn == nullptr ||
                info->NegotiatedAlpnLength != alpn_.size() ||
                !std::ranges::equal(
                    std::span<const std::uint8_t>(
                        info->NegotiatedAlpn,
                        info->NegotiatedAlpnLength),
                    alpn_)) {
                return QUIC_STATUS_CONNECTION_REFUSED;
            }
            const auto weak_signal =
                std::weak_ptr<MsQuicListenerSignal>(signal_);
            MsQuicTransport* accepted_pointer{};
            {
                std::scoped_lock lock(signal_->mutex);
                if (signal_->closed ||
                    pending_.size() >=
                        options_.maximum_pending_connections) {
                    return QUIC_STATUS_CONNECTION_REFUSED;
                }
                auto accepted = std::make_unique<MsQuicTransport>(
                    runtime_, connection, options_.stream_read_timeout,
                    settings_.maximum_datagram_bytes,
                    options_.allowed_client_certificate_sha256,
                    [weak_signal] {
                        if (const auto signal = weak_signal.lock()) {
                            signal->condition.notify_all();
                        }
                    });
                accepted_pointer = accepted.get();
                pending_.push_back(std::move(accepted));
            }
            try {
                accepted_pointer->start_server(configuration_);
            } catch (...) {
                accepted_pointer->abandon_server_connection();
                std::scoped_lock lock(signal_->mutex);
                const auto found = std::ranges::find_if(
                    pending_, [accepted_pointer](const auto& candidate) {
                        return candidate.get() == accepted_pointer;
                    });
                if (found != pending_.end()) pending_.erase(found);
                return QUIC_STATUS_CONNECTION_REFUSED;
            }
            return QUIC_STATUS_SUCCESS;
        } catch (...) {
            return QUIC_STATUS_CONNECTION_REFUSED;
        }
    }

    void cleanup() noexcept {
        if (listener_ != nullptr && runtime_) {
            runtime_->api().ListenerStop(listener_);
            runtime_->api().ListenerClose(listener_);
            listener_ = nullptr;
        }
        std::vector<std::unique_ptr<MsQuicTransport>> connections;
        if (signal_) {
            {
                std::scoped_lock lock(signal_->mutex);
                signal_->closed = true;
                connections = std::move(pending_);
            }
            signal_->condition.notify_all();
        }
        connections.clear();
        if (configuration_ != nullptr && runtime_) {
            runtime_->api().ConfigurationClose(configuration_);
            configuration_ = nullptr;
        }
    }

    MsQuicServerOptions options_;
    QuicTransportSettings settings_;
    std::shared_ptr<MsQuicRuntime> runtime_;
    std::shared_ptr<MsQuicListenerSignal> signal_;
    std::vector<std::uint8_t> alpn_;
    std::vector<std::unique_ptr<MsQuicTransport>> pending_;
    HQUIC configuration_{};
    HQUIC listener_{};
};

MsQuicServerListener::MsQuicServerListener(
    MsQuicServerOptions options, QuicTransportSettings settings)
    : impl_(std::make_unique<Impl>(
          std::move(options), std::move(settings))) {}

MsQuicServerListener::~MsQuicServerListener() = default;
MsQuicServerListener::MsQuicServerListener(
    MsQuicServerListener&&) noexcept = default;
MsQuicServerListener& MsQuicServerListener::operator=(
    MsQuicServerListener&&) noexcept = default;

AuthenticatedConnection MsQuicServerListener::accept(
    const std::chrono::milliseconds timeout) {
    if (!impl_) throw std::logic_error("MsQuic server listener was moved");
    return impl_->accept(timeout);
}

std::uint16_t MsQuicServerListener::listen_port() const noexcept {
    return impl_ ? impl_->listen_port() : 0;
}

}  // namespace rwn::transport
