#include "rwn/platform/macos/network_transport.hpp"

#include "rwn/core/content_hash.hpp"

#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>

#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <iomanip>
#include <iostream>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace std::chrono_literals;

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
    throw std::invalid_argument("persistent reference is not hexadecimal");
}

[[nodiscard]] std::vector<std::byte> parse_reference(
    const std::string_view value) {
    if (value.empty() || value.size() > 8192 || value.size() % 2 != 0) {
        throw std::invalid_argument("persistent reference hex is invalid");
    }
    std::vector<std::byte> result(value.size() / 2);
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = static_cast<std::byte>(
            (hex_nibble(value[index * 2]) << 4U) |
            hex_nibble(value[index * 2 + 1]));
    }
    return result;
}

[[nodiscard]] std::string hex(const std::span<const std::byte> value) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const auto byte : value) {
        output << std::setw(2) << std::to_integer<unsigned int>(byte);
    }
    return output.str();
}

[[nodiscard]] std::uint16_t parse_port(const std::string_view value) {
    std::uint32_t parsed{};
    const auto [end, error] = std::from_chars(
        value.data(), value.data() + value.size(), parsed);
    if (error != std::errc{} || end != value.data() + value.size() ||
        parsed == 0 || parsed > 65'535U) {
        throw std::invalid_argument("port is invalid");
    }
    return static_cast<std::uint16_t>(parsed);
}

[[nodiscard]] rwn::transport::CertificateSha256 certificate_fingerprint(
    SecCertificateRef certificate) {
    const CfOwner<CFDataRef> data(SecCertificateCopyData(certificate));
    if (data.get() == nullptr) return {};
    const auto length = static_cast<std::size_t>(CFDataGetLength(data.get()));
    const auto* bytes = reinterpret_cast<const std::byte*>(
        CFDataGetBytePtr(data.get()));
    if (length == 0 || bytes == nullptr) return {};
    const auto digest = rwn::core::sha256(std::span{bytes, length});
    rwn::transport::CertificateSha256 result{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = std::to_integer<std::uint8_t>(digest[index]);
    }
    return result;
}

int print_identity_reference(const std::string_view fingerprint_text) {
    const auto expected =
        rwn::transport::parse_apple_network_sha256_fingerprint(
            fingerprint_text);
    const void* keys[]{kSecClass, kSecReturnRef, kSecMatchLimit};
    const void* values[]{kSecClassIdentity, kCFBooleanTrue, kSecMatchLimitAll};
    const CfOwner<CFDictionaryRef> query(CFDictionaryCreate(
        kCFAllocatorDefault, keys, values, 3,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks));
    CFTypeRef raw_identities{};
    const auto status = SecItemCopyMatching(query.get(), &raw_identities);
    const CfOwner<CFTypeRef> identities(raw_identities);
    if (status != errSecSuccess || identities.get() == nullptr ||
        CFGetTypeID(identities.get()) != CFArrayGetTypeID()) {
        throw std::runtime_error(
            "Keychain identity enumeration failed; OSStatus=" +
            std::to_string(status));
    }
    const auto array = static_cast<CFArrayRef>(identities.get());
    for (CFIndex index = 0; index < CFArrayGetCount(array); ++index) {
        const auto identity = static_cast<SecIdentityRef>(
            const_cast<void*>(CFArrayGetValueAtIndex(array, index)));
        SecCertificateRef raw_certificate{};
        if (SecIdentityCopyCertificate(identity, &raw_certificate) !=
            errSecSuccess) continue;
        const CfOwner<SecCertificateRef> certificate(raw_certificate);
        if (certificate_fingerprint(certificate.get()) != expected) continue;

        const void* reference_keys[]{
            kSecValueRef, kSecReturnPersistentRef, kSecMatchLimit};
        const void* reference_values[]{
            identity, kCFBooleanTrue, kSecMatchLimitOne};
        const CfOwner<CFDictionaryRef> reference_query(CFDictionaryCreate(
            kCFAllocatorDefault, reference_keys, reference_values, 3,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks));
        CFTypeRef raw_reference{};
        const auto reference_status =
            SecItemCopyMatching(reference_query.get(), &raw_reference);
        const CfOwner<CFTypeRef> reference(raw_reference);
        if (reference_status != errSecSuccess || reference.get() == nullptr ||
            CFGetTypeID(reference.get()) != CFDataGetTypeID()) {
            throw std::runtime_error(
                "Keychain persistent reference lookup failed; OSStatus=" +
                std::to_string(reference_status));
        }
        const auto data = static_cast<CFDataRef>(reference.get());
        const auto length = static_cast<std::size_t>(CFDataGetLength(data));
        const auto* bytes = reinterpret_cast<const std::byte*>(
            CFDataGetBytePtr(data));
        std::cout << "keychain_persistent_ref="
                  << hex(std::span{bytes, length}) << '\n';
        return 0;
    }
    throw std::runtime_error("matching Keychain identity was not found");
}

[[nodiscard]] rwn::transport::QuicTransportSettings settings() {
    auto result = rwn::transport::QuicTransportSettings{};
    result.enable_fallback = false;
    result.maximum_datagram_bytes = 1200;
    return result;
}

constexpr std::array ping{
    std::byte{'p'}, std::byte{'i'}, std::byte{'n'}, std::byte{'g'}};
constexpr std::array pong{
    std::byte{'p'}, std::byte{'o'}, std::byte{'n'}, std::byte{'g'}};
constexpr std::array done{
    std::byte{'d'}, std::byte{'o'}, std::byte{'n'}, std::byte{'e'}};
constexpr std::array audio{
    std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
constexpr std::array video{
    std::byte{0x10}, std::byte{0x20}, std::byte{0x30}};

[[nodiscard]] rwn::transport::AppleNetworkIdentityOptions identity(
    const char* reference, const char* peer) {
    return {
        .keychain_persistent_reference = parse_reference(reference),
        .allowed_peer_certificate_sha256 = {
            rwn::transport::parse_apple_network_sha256_fingerprint(peer)},
    };
}

int run_server(char** argv) {
    rwn::platform::macos::NetworkFrameworkServerListener listener({
        .identity = identity(argv[2], argv[3]),
        .listen_port = parse_port(argv[4]),
    }, settings());
    std::cout << "provider=network-framework role=server port="
              << listener.listen_port() << " state=listening\n" << std::flush;
    auto accepted = listener.accept(2min);
    auto& connection = accepted.transport;
    auto stream = connection->accept_stream(30s);
    if (stream.purpose != rwn::transport::StreamPurpose::control ||
        stream.stream->read() !=
            std::vector<std::byte>(ping.begin(), ping.end())) {
        throw std::runtime_error("server received invalid control ping");
    }
    const auto datagram = connection->receive_datagram(30s);
    if (datagram.channel != rwn::transport::DatagramChannel::audio ||
        datagram.payload !=
            std::vector<std::byte>(audio.begin(), audio.end())) {
        throw std::runtime_error("server received invalid audio datagram");
    }
    stream.stream->write(pong);
    connection->send_datagram(rwn::transport::DatagramChannel::video, video);
    if (stream.stream->read() !=
        std::vector<std::byte>(done.begin(), done.end())) {
        throw std::runtime_error("server did not receive completion acknowledgement");
    }
    std::cout << "provider=network-framework role=server mtls=1 stream=1 "
                 "datagram=1 passed=1\n";
    return 0;
}

int run_client(char** argv) {
    rwn::platform::macos::NetworkFrameworkClientConnector connector({
        .identity = identity(argv[2], argv[3]),
    });
    auto connection = connector.connect(
        rwn::transport::TransportMode::quic,
        {.host = argv[4], .port = parse_port(argv[5]),
         .path = rwn::transport::NetworkPath::lan},
        settings());
    auto* duplex = dynamic_cast<rwn::transport::DuplexTransport*>(
        connection.get());
    if (duplex == nullptr) {
        throw std::runtime_error("Network.framework client is not duplex");
    }
    auto stream = connection->open_stream(
        rwn::transport::StreamPurpose::control);
    stream->write(ping);
    connection->send_datagram(rwn::transport::DatagramChannel::audio, audio);
    if (stream->read() != std::vector<std::byte>(pong.begin(), pong.end())) {
        throw std::runtime_error("client received invalid control pong");
    }
    const auto datagram = duplex->receive_datagram(30s);
    if (datagram.channel != rwn::transport::DatagramChannel::video ||
        datagram.payload !=
            std::vector<std::byte>(video.begin(), video.end())) {
        throw std::runtime_error("client received invalid video datagram");
    }
    stream->write(done);
    std::cout << "provider=network-framework role=client mtls=1 stream=1 "
                 "datagram=1 passed=1\n";
    return 0;
}

void usage() {
    std::cerr
        << "usage:\n"
           "  rwn-network-peer-probe identity-ref <certificate-sha256>\n"
           "  rwn-network-peer-probe server <persistent-ref-hex> "
           "<allowed-client-cert-sha256> <port>\n"
           "  rwn-network-peer-probe client <persistent-ref-hex> "
           "<allowed-server-cert-sha256> <host> <port>\n";
}

}  // namespace

int main(const int argc, char** argv) {
    try {
        const auto role = argc > 1 ? std::string_view(argv[1]) : std::string_view{};
        if (role == "identity-ref" && argc == 3) {
            return print_identity_reference(argv[2]);
        }
        if (role == "server" && argc == 5) return run_server(argv);
        if (role == "client" && argc == 6) return run_client(argv);
        usage();
        return 64;
    } catch (const std::exception& error) {
        std::cerr << "rwn-network-peer-probe: " << error.what() << '\n';
        return 1;
    }
}
