#include "rwn/platform/windows/schannel_transport.hpp"

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#ifndef SCHANNEL_USE_BLACKLISTS
#define SCHANNEL_USE_BLACKLISTS
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <winternl.h>
#include <security.h>
#include <schannel.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace rwn::platform::windows {
namespace {

using rwn::transport::AcceptedStream;
using rwn::transport::DatagramChannel;
using rwn::transport::EncryptedPlaneEvidence;
using rwn::transport::EncryptedPlaneProtocol;
using rwn::transport::FallbackDatagramPlane;
using rwn::transport::FallbackReliablePlane;
using rwn::transport::QuicTransportSettings;
using rwn::transport::ReceivedDatagram;
using rwn::transport::ReliableStream;
using rwn::transport::StreamPurpose;
using rwn::transport::TransportEndpoint;

constexpr std::size_t maximum_stream_message_bytes = 16U * 1024U * 1024U;
constexpr std::size_t maximum_handshake_bytes = 1024U * 1024U;
constexpr std::size_t maximum_handshake_legs = 32U;
constexpr std::size_t dtls_protocol_overhead_budget = 100U;
constexpr std::size_t frame_header_bytes = 14U;
constexpr std::array<std::uint8_t, 4> frame_magic{'R', 'W', 'F', 1};
constexpr std::array<std::uint8_t, 5> binding_magic{'R', 'W', 'N', 'B', 1};
constexpr std::string_view exporter_label =
    "EXPORTER-RemoteWorkspaceNode-Fallback-v1";
constexpr std::array<std::uint8_t, 15> exporter_context{
    'r', 'w', 'n', '-', 'f', 'a', 'l', 'l', 'b', 'a', 'c', 'k', '-', 'v', '1'};

[[nodiscard]] bool all_zero(const auto& value) {
    return std::ranges::all_of(
        value, [](const auto byte) { return byte == 0; });
}

[[nodiscard]] bool valid_channel(const DatagramChannel channel) {
    return static_cast<std::uint8_t>(channel) <=
           static_cast<std::uint8_t>(DatagramChannel::pointer);
}

[[nodiscard]] bool valid_purpose(const StreamPurpose purpose) {
    return static_cast<std::uint8_t>(purpose) <=
           static_cast<std::uint8_t>(StreamPurpose::build);
}

[[noreturn]] void fail_status(
    const std::string_view operation, const SECURITY_STATUS status) {
    throw std::runtime_error(
        std::string(operation) + " failed; status=" +
        std::to_string(static_cast<std::int32_t>(status)));
}

[[noreturn]] void fail_winsock(const std::string_view operation) {
    throw std::runtime_error(
        std::string(operation) + " failed; wsa=" +
        std::to_string(WSAGetLastError()));
}

[[nodiscard]] std::wstring utf8_to_wide(const std::string_view value) {
    if (value.empty() ||
        value.size() > static_cast<std::size_t>(
                           std::numeric_limits<int>::max())) {
        throw std::invalid_argument("Schannel target name is invalid");
    }
    const auto needed = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0);
    if (needed <= 0) {
        throw std::invalid_argument("Schannel target name is not UTF-8");
    }
    std::wstring result(static_cast<std::size_t>(needed), L'\0');
    if (MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
            static_cast<int>(value.size()), result.data(), needed) != needed) {
        throw std::runtime_error("Schannel target name conversion failed");
    }
    return result;
}

class WinsockRuntime {
public:
    WinsockRuntime() {
        WSADATA data{};
        const auto status = WSAStartup(MAKEWORD(2, 2), &data);
        if (status != 0 || LOBYTE(data.wVersion) != 2 ||
            HIBYTE(data.wVersion) != 2) {
            if (status == 0) WSACleanup();
            throw std::runtime_error(
                "Winsock 2.2 initialization failed; status=" +
                std::to_string(status));
        }
    }
    ~WinsockRuntime() { WSACleanup(); }
    WinsockRuntime(const WinsockRuntime&) = delete;
    WinsockRuntime& operator=(const WinsockRuntime&) = delete;
};

void require_winsock() {
    static const WinsockRuntime runtime;
    static_cast<void>(runtime);
}

class SocketHandle {
public:
    SocketHandle() = default;
    explicit SocketHandle(const SOCKET value) : value_(value) {}
    ~SocketHandle() { reset(); }
    SocketHandle(SocketHandle&& other) noexcept
        : value_(std::exchange(other.value_, INVALID_SOCKET)) {}
    SocketHandle& operator=(SocketHandle&& other) noexcept {
        if (this != &other) {
            reset();
            value_ = std::exchange(other.value_, INVALID_SOCKET);
        }
        return *this;
    }
    SocketHandle(const SocketHandle&) = delete;
    SocketHandle& operator=(const SocketHandle&) = delete;

    [[nodiscard]] SOCKET get() const noexcept { return value_; }

private:
    void reset() noexcept {
        if (value_ != INVALID_SOCKET) closesocket(value_);
        value_ = INVALID_SOCKET;
    }
    SOCKET value_{INVALID_SOCKET};
};

class StoreHandle {
public:
    ~StoreHandle() {
        if (value_ != nullptr) CertCloseStore(value_, 0);
    }
    HCERTSTORE value_{};
};

class CertificateHandle {
public:
    ~CertificateHandle() {
        if (value_ != nullptr) CertFreeCertificateContext(value_);
    }
    PCCERT_CONTEXT value_{};
};

class CredentialHandle {
public:
    CredentialHandle() { SecInvalidateHandle(&value_); }
    ~CredentialHandle() {
        if (active_) FreeCredentialsHandle(&value_);
    }
    CredHandle* output() noexcept { return &value_; }
    CredHandle* get() noexcept { return &value_; }
    void activate() noexcept { active_ = true; }

private:
    CredHandle value_{};
    bool active_{};
};

class ContextHandle {
public:
    ContextHandle() { SecInvalidateHandle(&value_); }
    ~ContextHandle() {
        if (active_) DeleteSecurityContext(&value_);
    }
    CtxtHandle* output() noexcept { return &value_; }
    CtxtHandle* get() noexcept { return &value_; }
    [[nodiscard]] bool active() const noexcept { return active_; }
    void activate() noexcept { active_ = true; }

private:
    CtxtHandle value_{};
    bool active_{};
};

[[nodiscard]] std::chrono::steady_clock::time_point deadline_after(
    const std::chrono::milliseconds timeout) {
    if (timeout < std::chrono::milliseconds{1} ||
        timeout > std::chrono::minutes{5}) {
        throw std::invalid_argument("Schannel I/O timeout is invalid");
    }
    return std::chrono::steady_clock::now() + timeout;
}

void wait_socket(
    const SOCKET socket_value, const bool write,
    const std::chrono::steady_clock::time_point deadline) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) throw std::runtime_error("Schannel socket timed out");
    const auto remaining = std::chrono::duration_cast<std::chrono::microseconds>(
        deadline - now);
    timeval timeout{
        .tv_sec = static_cast<long>(remaining.count() / 1'000'000),
        .tv_usec = static_cast<long>(remaining.count() % 1'000'000),
    };
    fd_set selected;
    FD_ZERO(&selected);
    FD_SET(socket_value, &selected);
    const auto status = select(
        0, write ? nullptr : &selected, write ? &selected : nullptr,
        nullptr, &timeout);
    if (status == 0) throw std::runtime_error("Schannel socket timed out");
    if (status == SOCKET_ERROR) fail_winsock("Schannel socket wait");
}

void send_all(
    const SOCKET socket_value, const std::span<const std::uint8_t> data,
    const std::chrono::steady_clock::time_point deadline) {
    std::size_t sent{};
    while (sent < data.size()) {
        wait_socket(socket_value, true, deadline);
        const auto amount = send(
            socket_value,
            reinterpret_cast<const char*>(data.data() + sent),
            static_cast<int>(std::min<std::size_t>(
                data.size() - sent,
                static_cast<std::size_t>(std::numeric_limits<int>::max()))),
            0);
        if (amount == SOCKET_ERROR) fail_winsock("Schannel TCP send");
        if (amount == 0) throw std::runtime_error("Schannel TCP send closed");
        sent += static_cast<std::size_t>(amount);
    }
}

[[nodiscard]] std::vector<std::uint8_t> receive_tcp(
    const SOCKET socket_value,
    const std::chrono::steady_clock::time_point deadline) {
    wait_socket(socket_value, false, deadline);
    std::array<std::uint8_t, 64U * 1024U> buffer{};
    const auto amount = recv(
        socket_value, reinterpret_cast<char*>(buffer.data()),
        static_cast<int>(buffer.size()), 0);
    if (amount == SOCKET_ERROR) fail_winsock("Schannel TCP receive");
    if (amount == 0) throw std::runtime_error("Schannel TCP peer closed");
    return {buffer.begin(), buffer.begin() + amount};
}

void send_udp(
    const SOCKET socket_value, const std::span<const std::uint8_t> data,
    const std::chrono::steady_clock::time_point deadline) {
    if (data.empty() ||
        data.size() > static_cast<std::size_t>(
                          std::numeric_limits<int>::max())) {
        throw std::length_error("Schannel UDP packet is outside bounds");
    }
    wait_socket(socket_value, true, deadline);
    const auto amount = send(
        socket_value, reinterpret_cast<const char*>(data.data()),
        static_cast<int>(data.size()), 0);
    if (amount == SOCKET_ERROR) fail_winsock("Schannel UDP send");
    if (static_cast<std::size_t>(amount) != data.size()) {
        throw std::runtime_error("Schannel UDP send was partial");
    }
}

[[nodiscard]] std::vector<std::uint8_t> receive_udp(
    const SOCKET socket_value,
    const std::chrono::steady_clock::time_point deadline) {
    wait_socket(socket_value, false, deadline);
    std::vector<std::uint8_t> buffer(65'535);
    const auto amount = recv(
        socket_value, reinterpret_cast<char*>(buffer.data()),
        static_cast<int>(buffer.size()), 0);
    if (amount == SOCKET_ERROR) fail_winsock("Schannel UDP receive");
    if (amount == 0) throw std::runtime_error("Schannel UDP peer closed");
    buffer.resize(static_cast<std::size_t>(amount));
    return buffer;
}

[[nodiscard]] SocketHandle connect_socket(
    const TransportEndpoint& endpoint, const int socket_type,
    const int protocol, const std::chrono::milliseconds timeout) {
    require_winsock();
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socket_type;
    hints.ai_protocol = protocol;
    addrinfo* addresses{};
    const auto service = std::to_string(endpoint.port);
    const auto resolve_status = getaddrinfo(
        endpoint.host.c_str(), service.c_str(), &hints, &addresses);
    if (resolve_status != 0 || addresses == nullptr) {
        throw std::runtime_error(
            "Schannel endpoint resolution failed; status=" +
            std::to_string(resolve_status));
    }
    const auto free_addresses = std::unique_ptr<addrinfo, decltype(&freeaddrinfo)>(
        addresses, &freeaddrinfo);
    static_cast<void>(free_addresses);
    const auto deadline = deadline_after(timeout);
    int last_error{};
    for (auto* address = addresses; address != nullptr;
         address = address->ai_next) {
        SocketHandle candidate(socket(
            address->ai_family, address->ai_socktype,
            address->ai_protocol));
        if (candidate.get() == INVALID_SOCKET) {
            last_error = WSAGetLastError();
            continue;
        }
        u_long nonblocking = 1;
        if (ioctlsocket(candidate.get(), FIONBIO, &nonblocking) != 0) {
            last_error = WSAGetLastError();
            continue;
        }
        auto status = connect(
            candidate.get(), address->ai_addr,
            static_cast<int>(address->ai_addrlen));
        if (status == SOCKET_ERROR) {
            last_error = WSAGetLastError();
            if (last_error != WSAEWOULDBLOCK &&
                last_error != WSAEINPROGRESS) {
                continue;
            }
            try {
                wait_socket(candidate.get(), true, deadline);
            } catch (...) {
                continue;
            }
            int socket_error{};
            int length = sizeof(socket_error);
            if (getsockopt(
                    candidate.get(), SOL_SOCKET, SO_ERROR,
                    reinterpret_cast<char*>(&socket_error), &length) != 0 ||
                socket_error != 0) {
                last_error = socket_error != 0
                    ? socket_error : WSAGetLastError();
                continue;
            }
        }
        nonblocking = 0;
        if (ioctlsocket(candidate.get(), FIONBIO, &nonblocking) != 0) {
            last_error = WSAGetLastError();
            continue;
        }
        return candidate;
    }
    throw std::runtime_error(
        "Schannel endpoint connect failed; wsa=" +
        std::to_string(last_error));
}

[[nodiscard]] std::uint8_t hex_nibble(const char character) {
    if (character >= '0' && character <= '9') {
        return static_cast<std::uint8_t>(character - '0');
    }
    if (character >= 'a' && character <= 'f') {
        return static_cast<std::uint8_t>(character - 'a' + 10);
    }
    if (character >= 'A' && character <= 'F') {
        return static_cast<std::uint8_t>(character - 'A' + 10);
    }
    throw std::invalid_argument("certificate fingerprint is not hexadecimal");
}

template <std::size_t Size>
[[nodiscard]] std::array<std::uint8_t, Size> parse_hex(
    const std::string_view value) {
    if (value.size() != Size * 2U) {
        throw std::invalid_argument("certificate fingerprint length is invalid");
    }
    std::array<std::uint8_t, Size> result{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = static_cast<std::uint8_t>(
            (hex_nibble(value[index * 2U]) << 4U) |
            hex_nibble(value[index * 2U + 1U]));
    }
    if (all_zero(result)) {
        throw std::invalid_argument("certificate fingerprint is zero");
    }
    return result;
}

[[nodiscard]] std::array<std::uint8_t, 32> certificate_sha256(
    const PCCERT_CONTEXT certificate) {
    std::array<std::uint8_t, 32> result{};
    DWORD length = static_cast<DWORD>(result.size());
    if (!CryptHashCertificate2(
            BCRYPT_SHA256_ALGORITHM, 0, nullptr,
            certificate->pbCertEncoded, certificate->cbCertEncoded,
            result.data(), &length) || length != result.size()) {
        throw std::runtime_error("certificate SHA-256 failed");
    }
    return result;
}

[[nodiscard]] std::array<std::uint8_t, 20> certificate_sha1(
    const PCCERT_CONTEXT certificate) {
    std::array<std::uint8_t, 20> result{};
    DWORD length = static_cast<DWORD>(result.size());
    if (!CertGetCertificateContextProperty(
            certificate, CERT_SHA1_HASH_PROP_ID,
            result.data(), &length) || length != result.size()) {
        throw std::runtime_error("certificate SHA-1 property failed");
    }
    return result;
}

[[nodiscard]] std::vector<std::uint8_t> make_alpn(
    const std::string_view alpn) {
    if (alpn.empty() || alpn.size() > 255U) {
        throw std::invalid_argument("Schannel ALPN is invalid");
    }
    constexpr auto protocols_offset =
        offsetof(SEC_APPLICATION_PROTOCOLS, ProtocolLists);
    constexpr auto protocol_offset =
        offsetof(SEC_APPLICATION_PROTOCOL_LIST, ProtocolList);
    const auto list_bytes = protocol_offset + 1U + alpn.size();
    std::vector<std::uint8_t> result(protocols_offset + list_bytes);
    auto* protocols = reinterpret_cast<SEC_APPLICATION_PROTOCOLS*>(
        result.data());
    protocols->ProtocolListsSize = static_cast<unsigned long>(list_bytes);
    auto& list = protocols->ProtocolLists[0];
    list.ProtoNegoExt = SecApplicationProtocolNegotiationExt_ALPN;
    list.ProtocolListSize = static_cast<unsigned short>(1U + alpn.size());
    list.ProtocolList[0] = static_cast<unsigned char>(alpn.size());
    std::memcpy(list.ProtocolList + 1U, alpn.data(), alpn.size());
    return result;
}

class NativeClientChannel {
public:
    NativeClientChannel(
        const SchannelFallbackClientOptions& options,
        const TransportEndpoint& endpoint,
        const QuicTransportSettings& settings,
        const bool datagram)
        : options_(options), endpoint_(endpoint), settings_(settings),
          datagram_(datagram), target_name_(utf8_to_wide(endpoint.host)) {
        open_certificate();
        acquire_credentials();
        socket_ = connect_socket(
            endpoint_, datagram_ ? SOCK_DGRAM : SOCK_STREAM,
            datagram_ ? IPPROTO_UDP : IPPROTO_TCP,
            options_.connect_timeout);
        handshake();
        validate_context();
        query_sizes();
    }

    [[nodiscard]] const EncryptedPlaneEvidence& evidence() const noexcept {
        return evidence_;
    }

    [[nodiscard]] std::array<std::uint8_t, 32> export_binding() {
        if (datagram_) {
            throw std::logic_error("DTLS context cannot define TLS binding");
        }
        auto label = std::string(exporter_label);
        SecPkgContext_KeyingMaterialInfo information{
            .cbLabel = static_cast<WORD>(label.size()),
            .pszLabel = label.data(),
            .cbContextValue = static_cast<WORD>(exporter_context.size()),
            .pbContextValue = const_cast<PBYTE>(exporter_context.data()),
            .cbKeyingMaterial = 32,
        };
        const auto set_status = SetContextAttributesW(
            context_.get(), SECPKG_ATTR_KEYING_MATERIAL_INFO,
            &information, sizeof(information));
        if (set_status != SEC_E_OK) {
            fail_status("Schannel exporter configuration", set_status);
        }
        SecPkgContext_KeyingMaterial material{};
        const auto query_status = QueryContextAttributesW(
            context_.get(), SECPKG_ATTR_KEYING_MATERIAL, &material);
        if (query_status != SEC_E_OK) {
            fail_status("Schannel exporter query", query_status);
        }
        const auto release = std::unique_ptr<void, decltype(&FreeContextBuffer)>(
            material.pbKeyingMaterial, &FreeContextBuffer);
        static_cast<void>(release);
        if (material.cbKeyingMaterial != 32 ||
            material.pbKeyingMaterial == nullptr) {
            throw std::runtime_error("Schannel exporter length is invalid");
        }
        std::array<std::uint8_t, 32> result{};
        std::memcpy(
            result.data(), material.pbKeyingMaterial, result.size());
        if (all_zero(result)) {
            throw std::runtime_error("Schannel exporter is zero");
        }
        return result;
    }

    void set_binding(const std::array<std::uint8_t, 32>& binding) {
        if (all_zero(binding)) {
            throw std::invalid_argument("Schannel binding is zero");
        }
        evidence_.channel_binding = binding;
    }

    void send_plain(
        const std::span<const std::uint8_t> plaintext,
        const std::chrono::milliseconds timeout) {
        if (plaintext.empty() ||
            plaintext.size() > sizes_.cbMaximumMessage) {
            throw std::length_error(
                "Schannel plaintext is outside negotiated bounds");
        }
        std::vector<std::uint8_t> storage(
            static_cast<std::size_t>(sizes_.cbHeader) + plaintext.size() +
            sizes_.cbTrailer);
        SecBuffer buffers[4]{
            {sizes_.cbHeader, SECBUFFER_STREAM_HEADER, storage.data()},
            {static_cast<unsigned long>(plaintext.size()), SECBUFFER_DATA,
             storage.data() + sizes_.cbHeader},
            {sizes_.cbTrailer, SECBUFFER_STREAM_TRAILER,
             storage.data() + sizes_.cbHeader + plaintext.size()},
            {0, SECBUFFER_EMPTY, nullptr},
        };
        std::memcpy(buffers[1].pvBuffer, plaintext.data(), plaintext.size());
        SecBufferDesc descriptor{
            SECBUFFER_VERSION, static_cast<unsigned long>(std::size(buffers)),
            buffers};
        const auto status = EncryptMessage(
            context_.get(), 0, &descriptor, 0);
        if (status != SEC_E_OK) fail_status("Schannel encrypt", status);
        std::vector<std::uint8_t> encrypted;
        encrypted.reserve(storage.size());
        for (const auto& buffer : buffers) {
            if (buffer.cbBuffer == 0 || buffer.pvBuffer == nullptr) continue;
            const auto* begin = static_cast<const std::uint8_t*>(
                buffer.pvBuffer);
            encrypted.insert(
                encrypted.end(), begin, begin + buffer.cbBuffer);
        }
        const auto deadline = deadline_after(timeout);
        if (datagram_) {
            send_udp(socket_.get(), encrypted, deadline);
        } else {
            send_all(socket_.get(), encrypted, deadline);
        }
    }

    [[nodiscard]] std::vector<std::uint8_t> receive_plain(
        const std::chrono::milliseconds timeout) {
        const auto deadline = deadline_after(timeout);
        if (datagram_) {
            auto packet = receive_udp(socket_.get(), deadline);
            return decrypt_packet(packet, false);
        }
        while (true) {
            if (encrypted_pending_.empty()) {
                encrypted_pending_ = receive_tcp(socket_.get(), deadline);
            }
            auto result = decrypt_packet(encrypted_pending_, true);
            if (!result.empty()) return result;
            const auto more = receive_tcp(socket_.get(), deadline);
            if (encrypted_pending_.size() + more.size() >
                maximum_stream_message_bytes + 256U * 1024U) {
                throw std::length_error(
                    "Schannel encrypted receive buffer exceeded bounds");
            }
            encrypted_pending_.insert(
                encrypted_pending_.end(), more.begin(), more.end());
        }
    }

    [[nodiscard]] std::size_t maximum_plaintext() const noexcept {
        return sizes_.cbMaximumMessage;
    }

private:
    void open_certificate() {
        if (options_.certificate_store_name != L"MY") {
            throw std::invalid_argument(
                "Schannel certificate store must be MY");
        }
        const auto location = options_.certificate_in_machine_store
            ? CERT_SYSTEM_STORE_LOCAL_MACHINE
            : CERT_SYSTEM_STORE_CURRENT_USER;
        store_.value_ = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W, 0, 0,
            location | CERT_STORE_READONLY_FLAG,
            options_.certificate_store_name.c_str());
        if (store_.value_ == nullptr) {
            throw std::runtime_error(
                "Schannel certificate store open failed; win32=" +
                std::to_string(GetLastError()));
        }
        CRYPT_HASH_BLOB hash{
            static_cast<DWORD>(options_.client_certificate_sha1.size()),
            const_cast<BYTE*>(options_.client_certificate_sha1.data())};
        certificate_.value_ = CertFindCertificateInStore(
            store_.value_, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0, CERT_FIND_SHA1_HASH, &hash, nullptr);
        if (certificate_.value_ == nullptr) {
            throw std::runtime_error(
                "Schannel client certificate was not found; win32=" +
                std::to_string(GetLastError()));
        }
    }

    void acquire_credentials() {
        TLS_PARAMETERS parameters{};
        const DWORD protocol = datagram_
            ? SP_PROT_DTLS1_2_CLIENT : SP_PROT_TLS1_3_CLIENT;
        parameters.grbitDisabledProtocols = SP_PROT_X_CLIENTS & ~protocol;
        auto* certificate = certificate_.value_;
        SCH_CREDENTIALS credentials{};
        credentials.dwVersion = SCH_CREDENTIALS_VERSION;
        credentials.cCreds = 1;
        credentials.paCred = &certificate;
        credentials.dwFlags =
            SCH_CRED_AUTO_CRED_VALIDATION |
            SCH_CRED_NO_DEFAULT_CREDS |
            SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
            SCH_USE_STRONG_CRYPTO;
        if (datagram_) credentials.dwFlags |= SCH_USE_DTLS_ONLY;
        credentials.cTlsParameters = 1;
        credentials.pTlsParameters = &parameters;
        TimeStamp expiry{};
        const auto status = AcquireCredentialsHandleW(
            nullptr, const_cast<wchar_t*>(SCHANNEL_NAME_W),
            SECPKG_CRED_OUTBOUND, nullptr, &credentials,
            nullptr, nullptr, credential_.output(), &expiry);
        if (status != SEC_E_OK) {
            fail_status("Schannel credential acquisition", status);
        }
        credential_.activate();
    }

    void handshake() {
        auto alpn = make_alpn(settings_.alpn);
        SecBuffer first_input{
            static_cast<unsigned long>(alpn.size()),
            SECBUFFER_APPLICATION_PROTOCOLS, alpn.data()};
        SecBufferDesc first_descriptor{
            SECBUFFER_VERSION, 1, &first_input};
        std::vector<std::uint8_t> incoming;
        bool first = true;
        const ULONG required =
            ISC_REQ_SEQUENCE_DETECT |
            ISC_REQ_REPLAY_DETECT |
            ISC_REQ_CONFIDENTIALITY |
            ISC_REQ_INTEGRITY |
            ISC_REQ_MUTUAL_AUTH |
            ISC_REQ_EXTENDED_ERROR |
            ISC_REQ_ALLOCATE_MEMORY |
            ISC_REQ_USE_SUPPLIED_CREDS |
            (datagram_ ? ISC_REQ_DATAGRAM : ISC_REQ_STREAM);
        const auto deadline = deadline_after(options_.connect_timeout);
        for (std::size_t leg = 0; leg < maximum_handshake_legs; ++leg) {
            SecBuffer input_buffers[2]{};
            SecBufferDesc input_descriptor{};
            SecBufferDesc* input{};
            if (first) {
                input = &first_descriptor;
            } else {
                input_buffers[0] = {
                    static_cast<unsigned long>(incoming.size()),
                    SECBUFFER_TOKEN, incoming.data()};
                input_buffers[1] = {0, SECBUFFER_EMPTY, nullptr};
                input_descriptor = {
                    SECBUFFER_VERSION,
                    static_cast<unsigned long>(std::size(input_buffers)),
                    input_buffers};
                input = &input_descriptor;
            }
            SecBuffer output_buffer{0, SECBUFFER_TOKEN, nullptr};
            SecBufferDesc output_descriptor{
                SECBUFFER_VERSION, 1, &output_buffer};
            ULONG attributes{};
            TimeStamp expiry{};
            auto status = InitializeSecurityContextW(
                credential_.get(),
                context_.active() ? context_.get() : nullptr,
                target_name_.data(), required, 0, SECURITY_NETWORK_DREP,
                input, 0, context_.output(), &output_descriptor,
                &attributes, &expiry);
            if (!context_.active() && SecIsValidHandle(context_.get())) {
                context_.activate();
            }
            configure_dtls_mtu();
            const auto release_output =
                std::unique_ptr<void, decltype(&FreeContextBuffer)>(
                    output_buffer.pvBuffer, &FreeContextBuffer);
            static_cast<void>(release_output);
            if (status == SEC_I_COMPLETE_NEEDED ||
                status == SEC_I_COMPLETE_AND_CONTINUE) {
                const auto complete_status = CompleteAuthToken(
                    context_.get(), &output_descriptor);
                if (complete_status != SEC_E_OK) {
                    fail_status("Schannel complete auth token", complete_status);
                }
            }
            if (output_buffer.cbBuffer != 0 &&
                output_buffer.pvBuffer != nullptr) {
                const auto token = std::span<const std::uint8_t>(
                    static_cast<const std::uint8_t*>(
                        output_buffer.pvBuffer),
                    output_buffer.cbBuffer);
                if (datagram_) {
                    send_udp(socket_.get(), token, deadline);
                } else {
                    send_all(socket_.get(), token, deadline);
                }
            }
            if (status == SEC_E_OK || status == SEC_I_COMPLETE_NEEDED) {
                returned_attributes_ = attributes;
                preserve_handshake_extra(incoming, input_buffers, first);
                return;
            }
            if (status == SEC_E_INCOMPLETE_MESSAGE && !datagram_) {
                const auto more = receive_tcp(socket_.get(), deadline);
                if (incoming.size() + more.size() > maximum_handshake_bytes) {
                    throw std::length_error(
                        "Schannel handshake exceeded bounds");
                }
                incoming.insert(incoming.end(), more.begin(), more.end());
                first = false;
                continue;
            }
            if (status != SEC_I_CONTINUE_NEEDED &&
                status != SEC_I_COMPLETE_AND_CONTINUE) {
                fail_status("Schannel handshake", status);
            }
            preserve_handshake_extra(incoming, input_buffers, first);
            first = false;
            if (datagram_) {
                incoming = receive_udp(socket_.get(), deadline);
            } else if (incoming.empty()) {
                incoming = receive_tcp(socket_.get(), deadline);
            }
            if (incoming.size() > maximum_handshake_bytes) {
                throw std::length_error("Schannel handshake exceeded bounds");
            }
        }
        throw std::runtime_error("Schannel handshake leg limit exceeded");
    }

    void preserve_handshake_extra(
        const std::vector<std::uint8_t>& incoming,
        const SecBuffer (&buffers)[2], const bool first) {
        if (first || datagram_) {
            encrypted_pending_.clear();
            return;
        }
        std::size_t extra{};
        for (const auto& buffer : buffers) {
            if (buffer.BufferType == SECBUFFER_EXTRA) {
                extra = buffer.cbBuffer;
            }
        }
        if (extra > incoming.size()) {
            throw std::runtime_error(
                "Schannel handshake extra bytes are invalid");
        }
        encrypted_pending_.assign(
            incoming.end() - static_cast<std::ptrdiff_t>(extra),
            incoming.end());
    }

    void configure_dtls_mtu() {
        if (!datagram_ || dtls_mtu_configured_ || !context_.active()) return;
        constexpr auto maximum_mtu =
            static_cast<std::size_t>(std::numeric_limits<unsigned short>::max());
        const auto requested = std::min(
            maximum_mtu,
            settings_.maximum_datagram_bytes + 1U +
                dtls_protocol_overhead_budget);
        SEC_DTLS_MTU mtu{
            .PathMTU = static_cast<unsigned short>(requested),
        };
        const auto status = SetContextAttributesW(
            context_.get(), SECPKG_ATTR_DTLS_MTU, &mtu, sizeof(mtu));
        if (status != SEC_E_OK) {
            fail_status("Schannel DTLS MTU configuration", status);
        }
        dtls_mtu_configured_ = true;
        requested_dtls_mtu_ = mtu.PathMTU;
    }

    void validate_context() {
        const ULONG required =
            ISC_RET_CONFIDENTIALITY |
            ISC_RET_INTEGRITY |
            ISC_RET_MUTUAL_AUTH |
            (datagram_ ? ISC_RET_DATAGRAM : ISC_RET_STREAM);
        if ((returned_attributes_ & required) != required) {
            throw std::runtime_error(
                "Schannel context is missing required attributes");
        }
        SecPkgContext_ConnectionInfo connection{};
        auto status = QueryContextAttributesW(
            context_.get(), SECPKG_ATTR_CONNECTION_INFO, &connection);
        if (status != SEC_E_OK) {
            fail_status("Schannel connection info", status);
        }
        const DWORD expected_protocol = datagram_
            ? SP_PROT_DTLS1_2_CLIENT : SP_PROT_TLS1_3_CLIENT;
        if (connection.dwProtocol != expected_protocol ||
            connection.dwCipherStrength < 128) {
            throw std::runtime_error(
                "Schannel negotiated protocol or cipher is invalid");
        }
        SecPkgContext_ApplicationProtocol application{};
        status = QueryContextAttributesW(
            context_.get(), SECPKG_ATTR_APPLICATION_PROTOCOL, &application);
        if (status != SEC_E_OK) {
            fail_status("Schannel ALPN query", status);
        }
        if (application.ProtoNegoStatus !=
                SecApplicationProtocolNegotiationStatus_Success ||
            application.ProtoNegoExt !=
                SecApplicationProtocolNegotiationExt_ALPN ||
            application.ProtocolIdSize != settings_.alpn.size() ||
            !std::equal(
                settings_.alpn.begin(), settings_.alpn.end(),
                application.ProtocolId)) {
            throw std::runtime_error("Schannel ALPN mismatch");
        }
        if (datagram_) {
            SEC_DTLS_MTU mtu{};
            status = QueryContextAttributesW(
                context_.get(), SECPKG_ATTR_DTLS_MTU, &mtu);
            if (status != SEC_E_OK) {
                fail_status("Schannel DTLS MTU query", status);
            }
            if (!dtls_mtu_configured_ || mtu.PathMTU < requested_dtls_mtu_) {
                throw std::runtime_error(
                    "Schannel DTLS MTU is below the configured bound");
            }
        }

        PCCERT_CONTEXT local{};
        status = QueryContextAttributesW(
            context_.get(), SECPKG_ATTR_LOCAL_CERT_CONTEXT, &local);
        if (status != SEC_E_OK || local == nullptr) {
            if (local != nullptr) CertFreeCertificateContext(local);
            fail_status("Schannel local certificate query", status);
        }
        const CertificateHandle local_guard{local};
        if (certificate_sha1(local) != options_.client_certificate_sha1) {
            throw std::runtime_error(
                "Schannel substituted the client certificate");
        }

        PCCERT_CONTEXT remote{};
        status = QueryContextAttributesW(
            context_.get(), SECPKG_ATTR_REMOTE_CERT_CONTEXT, &remote);
        if (status != SEC_E_OK || remote == nullptr) {
            if (remote != nullptr) CertFreeCertificateContext(remote);
            fail_status("Schannel remote certificate query", status);
        }
        const CertificateHandle remote_guard{remote};
        const auto fingerprint = certificate_sha256(remote);
        if (std::ranges::find(
                options_.allowed_server_certificate_sha256,
                fingerprint) ==
            options_.allowed_server_certificate_sha256.end()) {
            throw std::runtime_error(
                "Schannel server certificate is not paired");
        }
        validate_chain(remote);
        evidence_ = {
            .protocol = datagram_
                ? EncryptedPlaneProtocol::dtls12
                : EncryptedPlaneProtocol::tls13,
            .peer_certificate_sha256 = fingerprint,
            .channel_binding = {},
            .chain_validated = true,
            .revocation_checked = true,
        };
    }

    void validate_chain(const PCCERT_CONTEXT remote) {
        CERT_CHAIN_PARA chain_parameters{};
        chain_parameters.cbSize = sizeof(chain_parameters);
        PCCERT_CHAIN_CONTEXT chain{};
        if (!CertGetCertificateChain(
                nullptr, remote, nullptr, remote->hCertStore,
                &chain_parameters,
                CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
                nullptr, &chain) || chain == nullptr) {
            throw std::runtime_error(
                "Schannel certificate chain failed; win32=" +
                std::to_string(GetLastError()));
        }
        const auto release_chain =
            std::unique_ptr<const CERT_CHAIN_CONTEXT,
                            decltype(&CertFreeCertificateChain)>(
                chain, &CertFreeCertificateChain);
        static_cast<void>(release_chain);
        SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl{};
        ssl.cbSize = sizeof(ssl);
        ssl.dwAuthType = AUTHTYPE_SERVER;
        ssl.pwszServerName = target_name_.data();
        CERT_CHAIN_POLICY_PARA policy{};
        policy.cbSize = sizeof(policy);
        policy.pvExtraPolicyPara = &ssl;
        CERT_CHAIN_POLICY_STATUS policy_status{};
        policy_status.cbSize = sizeof(policy_status);
        if (!CertVerifyCertificateChainPolicy(
                CERT_CHAIN_POLICY_SSL, chain, &policy, &policy_status) ||
            policy_status.dwError != 0) {
            throw std::runtime_error(
                "Schannel certificate policy failed; status=" +
                std::to_string(policy_status.dwError));
        }
    }

    void query_sizes() {
        const auto status = QueryContextAttributesW(
            context_.get(), SECPKG_ATTR_STREAM_SIZES, &sizes_);
        if (status != SEC_E_OK) {
            fail_status("Schannel message sizes", status);
        }
        if (sizes_.cbMaximumMessage == 0 ||
            sizes_.cbMaximumMessage > 64U * 1024U * 1024U ||
            sizes_.cbHeader > 64U * 1024U ||
            sizes_.cbTrailer > 64U * 1024U) {
            throw std::runtime_error("Schannel message sizes are invalid");
        }
    }

    [[nodiscard]] std::vector<std::uint8_t> decrypt_packet(
        std::vector<std::uint8_t>& encrypted, const bool stream) {
        if (encrypted.empty()) return {};
        SecBuffer buffers[4]{
            {static_cast<unsigned long>(encrypted.size()), SECBUFFER_DATA,
             encrypted.data()},
            {0, SECBUFFER_EMPTY, nullptr},
            {0, SECBUFFER_EMPTY, nullptr},
            {0, SECBUFFER_EMPTY, nullptr},
        };
        SecBufferDesc descriptor{
            SECBUFFER_VERSION, static_cast<unsigned long>(std::size(buffers)),
            buffers};
        const auto status = DecryptMessage(
            context_.get(), &descriptor, 0, nullptr);
        if (status == SEC_E_INCOMPLETE_MESSAGE && stream) return {};
        if (status == SEC_I_CONTEXT_EXPIRED) {
            throw std::runtime_error("Schannel peer closed securely");
        }
        if (status == SEC_I_RENEGOTIATE) {
            throw std::runtime_error("Schannel renegotiation is not allowed");
        }
        if (status != SEC_E_OK) fail_status("Schannel decrypt", status);
        std::vector<std::uint8_t> plaintext;
        std::size_t extra{};
        for (const auto& buffer : buffers) {
            if (buffer.BufferType == SECBUFFER_DATA &&
                buffer.cbBuffer != 0 && buffer.pvBuffer != nullptr) {
                const auto* begin = static_cast<const std::uint8_t*>(
                    buffer.pvBuffer);
                plaintext.assign(begin, begin + buffer.cbBuffer);
            } else if (buffer.BufferType == SECBUFFER_EXTRA) {
                extra = buffer.cbBuffer;
            }
        }
        if (extra > encrypted.size() || (!stream && extra != 0)) {
            throw std::runtime_error("Schannel encrypted extra is invalid");
        }
        if (stream) {
            std::vector<std::uint8_t> remaining(
                encrypted.end() - static_cast<std::ptrdiff_t>(extra),
                encrypted.end());
            encrypted = std::move(remaining);
        } else {
            encrypted.clear();
        }
        if (plaintext.empty()) {
            throw std::runtime_error("Schannel decrypted empty record");
        }
        return plaintext;
    }

    SchannelFallbackClientOptions options_;
    TransportEndpoint endpoint_;
    QuicTransportSettings settings_;
    bool datagram_{};
    bool dtls_mtu_configured_{};
    unsigned short requested_dtls_mtu_{};
    std::wstring target_name_;
    SocketHandle socket_;
    StoreHandle store_;
    CertificateHandle certificate_;
    CredentialHandle credential_;
    ContextHandle context_;
    ULONG returned_attributes_{};
    SecPkgContext_StreamSizes sizes_{};
    EncryptedPlaneEvidence evidence_{};
    std::vector<std::uint8_t> encrypted_pending_;
};

struct StreamState {
    std::uint32_t id{};
    StreamPurpose purpose{StreamPurpose::control};
    bool incoming{};
    std::deque<std::vector<std::byte>> messages;
    std::size_t queued_bytes{};
};

class TlsConnection;

class SchannelReliableStream final : public ReliableStream {
public:
    SchannelReliableStream(
        std::weak_ptr<TlsConnection> connection,
        std::shared_ptr<StreamState> state)
        : connection_(std::move(connection)), state_(std::move(state)) {}
    void write(std::span<const std::byte> data) override;
    [[nodiscard]] std::vector<std::byte> read() override;

private:
    std::weak_ptr<TlsConnection> connection_;
    std::shared_ptr<StreamState> state_;
};

class TlsConnection final
    : public std::enable_shared_from_this<TlsConnection> {
public:
    TlsConnection(
        std::unique_ptr<NativeClientChannel> native,
        const SchannelFallbackClientOptions& options)
        : native_(std::move(native)), options_(options) {}

    [[nodiscard]] std::unique_ptr<ReliableStream> open(
        const StreamPurpose purpose) {
        if (!valid_purpose(purpose)) {
            throw std::invalid_argument("Schannel stream purpose is invalid");
        }
        std::shared_ptr<StreamState> state;
        {
            std::scoped_lock lock(state_mutex_);
            if (streams_.size() >= options_.maximum_streams ||
                next_stream_id_ > std::numeric_limits<std::uint32_t>::max() - 2U) {
                throw std::length_error("Schannel stream limit exceeded");
            }
            state = std::make_shared<StreamState>(StreamState{
                .id = next_stream_id_, .purpose = purpose,
                .incoming = false, .messages = {}, .queued_bytes = 0});
            next_stream_id_ += 2U;
            streams_.emplace(state->id, state);
        }
        try {
            send_frame(1, state->id, purpose, {});
        } catch (...) {
            std::scoped_lock lock(state_mutex_);
            streams_.erase(state->id);
            throw;
        }
        return std::make_unique<SchannelReliableStream>(
            weak_from_this(), std::move(state));
    }

    [[nodiscard]] AcceptedStream accept(
        const std::chrono::milliseconds timeout) {
        const auto deadline = deadline_after(timeout);
        pump_until(deadline, [this] {
            std::scoped_lock lock(state_mutex_);
            return !accepted_.empty();
        });
        std::shared_ptr<StreamState> state;
        {
            std::scoped_lock lock(state_mutex_);
            if (accepted_.empty()) {
                throw std::runtime_error("Schannel stream accept timed out");
            }
            state = std::move(accepted_.front());
            accepted_.pop_front();
        }
        return {
            .purpose = state->purpose,
            .stream = std::make_unique<SchannelReliableStream>(
                weak_from_this(), std::move(state)),
        };
    }

    void write(
        const std::shared_ptr<StreamState>& state,
        const std::span<const std::byte> data) {
        if (data.empty() || data.size() > maximum_stream_message_bytes) {
            throw std::length_error(
                "Schannel stream message is outside bounds");
        }
        {
            std::scoped_lock lock(state_mutex_);
            if (!streams_.contains(state->id)) {
                throw std::runtime_error("Schannel stream is closed");
            }
        }
        send_frame(2, state->id, state->purpose, data);
    }

    [[nodiscard]] std::vector<std::byte> read(
        const std::shared_ptr<StreamState>& state) {
        const auto deadline = deadline_after(options_.io_timeout);
        pump_until(deadline, [this, &state] {
            std::scoped_lock lock(state_mutex_);
            return !state->messages.empty();
        });
        std::scoped_lock lock(state_mutex_);
        if (state->messages.empty()) {
            throw std::runtime_error("Schannel stream read timed out");
        }
        auto result = std::move(state->messages.front());
        state->messages.pop_front();
        state->queued_bytes -= result.size();
        --queued_messages_;
        queued_bytes_ -= result.size();
        return result;
    }

private:
    template <typename Predicate>
    void pump_until(
        const std::chrono::steady_clock::time_point deadline,
        Predicate&& predicate) {
        if (predicate()) return;
        std::unique_lock receive_lock(receive_mutex_, std::defer_lock);
        if (!receive_lock.try_lock_until(deadline)) {
            throw std::runtime_error("Schannel receive serialization timed out");
        }
        while (!predicate()) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) {
                throw std::runtime_error("Schannel receive timed out");
            }
            const auto remaining =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - now);
            const auto plaintext = native_->receive_plain(
                std::max(remaining, std::chrono::milliseconds{1}));
            if (frame_buffer_.size() + plaintext.size() >
                maximum_stream_message_bytes + frame_header_bytes) {
                throw std::length_error("Schannel frame buffer exceeded bounds");
            }
            frame_buffer_.insert(
                frame_buffer_.end(), plaintext.begin(), plaintext.end());
            parse_frames();
        }
    }

    void send_frame(
        const std::uint8_t type, const std::uint32_t stream_id,
        const StreamPurpose purpose, const std::span<const std::byte> data) {
        const auto length = static_cast<std::uint32_t>(data.size());
        std::vector<std::uint8_t> frame(frame_header_bytes + data.size());
        std::copy(frame_magic.begin(), frame_magic.end(), frame.begin());
        frame[4] = type;
        frame[5] = static_cast<std::uint8_t>((stream_id >> 24U) & 0xffU);
        frame[6] = static_cast<std::uint8_t>((stream_id >> 16U) & 0xffU);
        frame[7] = static_cast<std::uint8_t>((stream_id >> 8U) & 0xffU);
        frame[8] = static_cast<std::uint8_t>(stream_id & 0xffU);
        frame[9] = static_cast<std::uint8_t>(purpose);
        frame[10] = static_cast<std::uint8_t>((length >> 24U) & 0xffU);
        frame[11] = static_cast<std::uint8_t>((length >> 16U) & 0xffU);
        frame[12] = static_cast<std::uint8_t>((length >> 8U) & 0xffU);
        frame[13] = static_cast<std::uint8_t>(length & 0xffU);
        if (!data.empty()) {
            std::memcpy(frame.data() + frame_header_bytes,
                        data.data(), data.size());
        }
        std::scoped_lock send_lock(send_mutex_);
        std::size_t offset{};
        while (offset < frame.size()) {
            const auto amount = std::min<std::size_t>(
                native_->maximum_plaintext(), frame.size() - offset);
            native_->send_plain(
                std::span<const std::uint8_t>(frame).subspan(offset, amount),
                options_.io_timeout);
            offset += amount;
        }
    }

    void parse_frames() {
        while (frame_buffer_.size() >= frame_header_bytes) {
            if (!std::equal(
                    frame_magic.begin(), frame_magic.end(),
                    frame_buffer_.begin())) {
                throw std::runtime_error("Schannel frame magic is invalid");
            }
            const auto type = frame_buffer_[4];
            const auto stream_id =
                (static_cast<std::uint32_t>(frame_buffer_[5]) << 24U) |
                (static_cast<std::uint32_t>(frame_buffer_[6]) << 16U) |
                (static_cast<std::uint32_t>(frame_buffer_[7]) << 8U) |
                static_cast<std::uint32_t>(frame_buffer_[8]);
            const auto purpose = static_cast<StreamPurpose>(frame_buffer_[9]);
            const auto length =
                (static_cast<std::uint32_t>(frame_buffer_[10]) << 24U) |
                (static_cast<std::uint32_t>(frame_buffer_[11]) << 16U) |
                (static_cast<std::uint32_t>(frame_buffer_[12]) << 8U) |
                static_cast<std::uint32_t>(frame_buffer_[13]);
            if (stream_id == 0 || length > maximum_stream_message_bytes ||
                (type == 1 && (length != 0 || !valid_purpose(purpose))) ||
                (type == 2 && length == 0) || (type != 1 && type != 2)) {
                throw std::runtime_error("Schannel frame header is invalid");
            }
            const auto frame_size = frame_header_bytes + length;
            if (frame_buffer_.size() < frame_size) return;
            if (type == 1) {
                receive_open(stream_id, purpose);
            } else {
                receive_data(stream_id, std::span<const std::uint8_t>(
                    frame_buffer_).subspan(frame_header_bytes, length));
            }
            frame_buffer_.erase(
                frame_buffer_.begin(),
                frame_buffer_.begin() +
                    static_cast<std::ptrdiff_t>(frame_size));
        }
    }

    void receive_open(
        const std::uint32_t stream_id, const StreamPurpose purpose) {
        std::scoped_lock lock(state_mutex_);
        if ((stream_id & 1U) != 0U || streams_.contains(stream_id) ||
            streams_.size() >= options_.maximum_streams ||
            accepted_.size() >= options_.maximum_streams) {
            throw std::runtime_error("Schannel peer stream is invalid");
        }
        auto state = std::make_shared<StreamState>(StreamState{
            .id = stream_id, .purpose = purpose, .incoming = true,
            .messages = {}, .queued_bytes = 0});
        streams_.emplace(stream_id, state);
        accepted_.push_back(std::move(state));
    }

    void receive_data(
        const std::uint32_t stream_id,
        const std::span<const std::uint8_t> data) {
        std::scoped_lock lock(state_mutex_);
        const auto found = streams_.find(stream_id);
        if (found == streams_.end() ||
            queued_messages_ >= options_.maximum_queued_stream_messages ||
            queued_bytes_ + data.size() >
                options_.maximum_queued_stream_bytes) {
            throw std::runtime_error("Schannel stream queue exceeded bounds");
        }
        auto message = std::vector<std::byte>(data.size());
        std::memcpy(message.data(), data.data(), data.size());
        found->second->queued_bytes += message.size();
        ++queued_messages_;
        queued_bytes_ += message.size();
        found->second->messages.push_back(std::move(message));
    }

    std::unique_ptr<NativeClientChannel> native_;
    SchannelFallbackClientOptions options_;
    std::mutex state_mutex_;
    std::mutex send_mutex_;
    std::timed_mutex receive_mutex_;
    std::unordered_map<std::uint32_t, std::shared_ptr<StreamState>> streams_;
    std::deque<std::shared_ptr<StreamState>> accepted_;
    std::vector<std::uint8_t> frame_buffer_;
    std::uint32_t next_stream_id_{1};
    std::size_t queued_messages_{};
    std::size_t queued_bytes_{};
};

void SchannelReliableStream::write(const std::span<const std::byte> data) {
    const auto connection = connection_.lock();
    if (!connection) throw std::runtime_error("Schannel stream is closed");
    connection->write(state_, data);
}

std::vector<std::byte> SchannelReliableStream::read() {
    const auto connection = connection_.lock();
    if (!connection) throw std::runtime_error("Schannel stream is closed");
    return connection->read(state_);
}

class SchannelTlsPlane final : public FallbackReliablePlane {
public:
    SchannelTlsPlane(
        std::shared_ptr<TlsConnection> connection,
        EncryptedPlaneEvidence evidence)
        : connection_(std::move(connection)), evidence_(std::move(evidence)) {}
    const EncryptedPlaneEvidence& evidence() const override {
        return evidence_;
    }
    std::unique_ptr<ReliableStream> open_stream(
        const StreamPurpose purpose) override {
        return connection_->open(purpose);
    }
    AcceptedStream accept_stream(
        const std::chrono::milliseconds timeout) override {
        return connection_->accept(timeout);
    }

private:
    std::shared_ptr<TlsConnection> connection_;
    EncryptedPlaneEvidence evidence_;
};

class SchannelDtlsPlane final : public FallbackDatagramPlane {
public:
    SchannelDtlsPlane(
        std::unique_ptr<NativeClientChannel> native,
        EncryptedPlaneEvidence evidence,
        const std::size_t maximum_datagram_bytes,
        const std::chrono::milliseconds io_timeout)
        : native_(std::move(native)), evidence_(std::move(evidence)),
          maximum_datagram_bytes_(maximum_datagram_bytes),
          io_timeout_(io_timeout) {}

    const EncryptedPlaneEvidence& evidence() const override {
        return evidence_;
    }
    void send_datagram(
        const DatagramChannel channel,
        const std::span<const std::byte> data) override {
        if (!valid_channel(channel) || data.empty() ||
            data.size() > maximum_datagram_bytes_) {
            throw std::length_error("Schannel datagram is outside bounds");
        }
        std::vector<std::uint8_t> plaintext(1U + data.size());
        plaintext[0] = static_cast<std::uint8_t>(channel);
        std::memcpy(plaintext.data() + 1U, data.data(), data.size());
        std::scoped_lock lock(io_mutex_);
        native_->send_plain(plaintext, io_timeout_);
    }
    ReceivedDatagram receive_datagram(
        const std::chrono::milliseconds timeout) override {
        std::scoped_lock lock(io_mutex_);
        const auto plaintext = native_->receive_plain(timeout);
        if (plaintext.size() < 2U ||
            plaintext.size() > maximum_datagram_bytes_ + 1U) {
            throw std::runtime_error(
                "Schannel received datagram is outside bounds");
        }
        const auto channel = static_cast<DatagramChannel>(plaintext[0]);
        if (!valid_channel(channel)) {
            throw std::runtime_error(
                "Schannel received datagram channel is invalid");
        }
        std::vector<std::byte> payload(plaintext.size() - 1U);
        std::memcpy(
            payload.data(), plaintext.data() + 1U, payload.size());
        return {.channel = channel, .payload = std::move(payload)};
    }

private:
    std::unique_ptr<NativeClientChannel> native_;
    EncryptedPlaneEvidence evidence_;
    std::size_t maximum_datagram_bytes_{};
    std::chrono::milliseconds io_timeout_{};
    std::mutex io_mutex_;
};

[[nodiscard]] std::vector<std::uint8_t> binding_proof(
    const std::array<std::uint8_t, 32>& binding) {
    std::vector<std::uint8_t> result(
        binding_magic.size() + binding.size());
    std::copy(binding_magic.begin(), binding_magic.end(), result.begin());
    std::copy(binding.begin(), binding.end(),
              result.begin() + static_cast<std::ptrdiff_t>(binding_magic.size()));
    return result;
}

}  // namespace

void validate_schannel_fallback_client_options(
    const SchannelFallbackClientOptions& options) {
    if (all_zero(options.client_certificate_sha1) ||
        options.allowed_server_certificate_sha256.empty() ||
        options.allowed_server_certificate_sha256.size() > 64U ||
        options.certificate_store_name != L"MY" ||
        options.connect_timeout < std::chrono::milliseconds{100} ||
        options.connect_timeout > std::chrono::minutes{2} ||
        options.io_timeout < std::chrono::milliseconds{100} ||
        options.io_timeout > std::chrono::minutes{5} ||
        options.maximum_streams == 0 || options.maximum_streams > 256U ||
        options.maximum_queued_stream_messages == 0 ||
        options.maximum_queued_stream_messages > 4096U ||
        options.maximum_queued_stream_bytes < maximum_stream_message_bytes ||
        options.maximum_queued_stream_bytes > 256U * 1024U * 1024U) {
        throw std::invalid_argument(
            "Schannel fallback client options are invalid");
    }
    for (const auto& fingerprint :
         options.allowed_server_certificate_sha256) {
        if (all_zero(fingerprint)) {
            throw std::invalid_argument(
                "Schannel server certificate fingerprint is zero");
        }
    }
    auto sorted = options.allowed_server_certificate_sha256;
    std::ranges::sort(sorted);
    if (std::ranges::adjacent_find(sorted) != sorted.end()) {
        throw std::invalid_argument(
            "Schannel server certificate fingerprint is duplicated");
    }
}

std::array<std::uint8_t, 20> parse_schannel_sha1_thumbprint(
    const std::string_view value) {
    return parse_hex<20>(value);
}

std::array<std::uint8_t, 32> parse_schannel_sha256_fingerprint(
    const std::string_view value) {
    return parse_hex<32>(value);
}

class SchannelFallbackClientProvider::Impl {
public:
    explicit Impl(SchannelFallbackClientOptions options)
        : options_(std::move(options)) {
        validate_schannel_fallback_client_options(options_);
    }

    std::unique_ptr<FallbackReliablePlane> connect_tls13(
        const TransportEndpoint& endpoint,
        const QuicTransportSettings& settings) {
        rwn::transport::validate_transport_endpoint(endpoint);
        rwn::transport::validate_quic_transport_settings(settings);
        if (!settings.require_tls13 || !settings.enable_fallback) {
            throw std::invalid_argument(
                "Schannel TLS fallback settings are invalid");
        }
        {
            std::scoped_lock lock(binding_mutex_);
            if (pending_binding_) {
                throw std::logic_error(
                    "Schannel fallback already has a pending TLS plane");
            }
        }
        auto native = std::make_unique<NativeClientChannel>(
            options_, endpoint, settings, false);
        auto evidence = native->evidence();
        evidence.channel_binding = native->export_binding();
        {
            std::scoped_lock lock(binding_mutex_);
            pending_binding_ = evidence.channel_binding;
            pending_peer_ = evidence.peer_certificate_sha256;
        }
        auto connection = std::make_shared<TlsConnection>(
            std::move(native), options_);
        return std::make_unique<SchannelTlsPlane>(
            std::move(connection), std::move(evidence));
    }

    std::unique_ptr<FallbackDatagramPlane> connect_dtls12(
        const TransportEndpoint& endpoint,
        const QuicTransportSettings& settings) {
        rwn::transport::validate_transport_endpoint(endpoint);
        rwn::transport::validate_quic_transport_settings(settings);
        std::array<std::uint8_t, 32> binding{};
        std::array<std::uint8_t, 32> peer{};
        {
            std::scoped_lock lock(binding_mutex_);
            if (!pending_binding_ || !pending_peer_) {
                throw std::logic_error(
                    "Schannel DTLS requires a new TLS binding");
            }
            binding = *pending_binding_;
            peer = *pending_peer_;
            pending_binding_.reset();
            pending_peer_.reset();
        }
        auto native = std::make_unique<NativeClientChannel>(
            options_, endpoint, settings, true);
        if (native->evidence().peer_certificate_sha256 != peer) {
            throw std::runtime_error(
                "Schannel TLS and DTLS peers do not match");
        }
        const auto proof = binding_proof(binding);
        if (proof.size() > native->maximum_plaintext()) {
            throw std::runtime_error(
                "Schannel DTLS binding proof exceeds negotiated bounds");
        }
        native->send_plain(proof, options_.io_timeout);
        if (native->receive_plain(options_.io_timeout) != proof) {
            throw std::runtime_error(
                "Schannel DTLS binding proof was not confirmed");
        }
        if (settings.maximum_datagram_bytes + 1U >
            native->maximum_plaintext()) {
            throw std::runtime_error(
                "Schannel DTLS negotiated datagram bound is too small");
        }
        native->set_binding(binding);
        auto evidence = native->evidence();
        return std::make_unique<SchannelDtlsPlane>(
            std::move(native), std::move(evidence),
            settings.maximum_datagram_bytes, options_.io_timeout);
    }

private:
    SchannelFallbackClientOptions options_;
    std::mutex binding_mutex_;
    std::optional<std::array<std::uint8_t, 32>> pending_binding_;
    std::optional<std::array<std::uint8_t, 32>> pending_peer_;
};

SchannelFallbackClientProvider::SchannelFallbackClientProvider(
    SchannelFallbackClientOptions options)
    : impl_(std::make_unique<Impl>(std::move(options))) {}

SchannelFallbackClientProvider::~SchannelFallbackClientProvider() = default;
SchannelFallbackClientProvider::SchannelFallbackClientProvider(
    SchannelFallbackClientProvider&&) noexcept = default;
SchannelFallbackClientProvider& SchannelFallbackClientProvider::operator=(
    SchannelFallbackClientProvider&&) noexcept = default;

std::unique_ptr<FallbackReliablePlane>
SchannelFallbackClientProvider::connect_tls13(
    const TransportEndpoint& endpoint,
    const QuicTransportSettings& settings) {
    return impl_->connect_tls13(endpoint, settings);
}

std::unique_ptr<FallbackDatagramPlane>
SchannelFallbackClientProvider::connect_dtls12(
    const TransportEndpoint& endpoint,
    const QuicTransportSettings& settings) {
    return impl_->connect_dtls12(endpoint, settings);
}

}  // namespace rwn::platform::windows
