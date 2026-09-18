#include "rwn/platform/windows/schannel_transport.hpp"

#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {

std::uint16_t port(const std::string_view value) {
    std::uint32_t parsed{};
    const auto result = std::from_chars(
        value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc{} ||
        result.ptr != value.data() + value.size() ||
        parsed == 0 || parsed > 65'535) {
        throw std::invalid_argument("port is invalid");
    }
    return static_cast<std::uint16_t>(parsed);
}

}  // namespace

int main(const int argc, const char* const argv[]) {
    if (argc != 5) {
        std::cerr << "usage: rwn-schannel-fallback-loopback-probe "
                     "<host> <port> <client-cert-sha1> "
                     "<server-cert-sha256>\n";
        return 64;
    }
    try {
        rwn::platform::windows::SchannelFallbackClientProvider provider({
            .client_certificate_sha1 =
                rwn::platform::windows::parse_schannel_sha1_thumbprint(
                    argv[3]),
            .allowed_server_certificate_sha256 = {
                rwn::platform::windows::parse_schannel_sha256_fingerprint(
                    argv[4])},
        });
        rwn::transport::EncryptedFallbackConnector connector(provider);
        auto transport = connector.connect(
            rwn::transport::TransportMode::tls_tcp_udp_fallback,
            {.host = argv[1], .port = port(argv[2]),
             .path = rwn::transport::NetworkPath::lan},
            {});
        auto* duplex = dynamic_cast<rwn::transport::DuplexTransport*>(
            transport.get());
        if (duplex == nullptr) {
            throw std::runtime_error("fallback is not duplex");
        }

        auto control = duplex->open_stream(
            rwn::transport::StreamPurpose::control);
        const std::array request{
            std::byte{'R'}, std::byte{'W'}, std::byte{'N'}, std::byte{1}};
        control->write(request);
        const auto response = control->read();
        if (response != std::vector<std::byte>(
                            request.begin(), request.end())) {
            throw std::runtime_error("control echo mismatch");
        }
        const std::array audio{std::byte{0x11}, std::byte{0x22}};
        duplex->send_datagram(
            rwn::transport::DatagramChannel::audio, audio);
        const auto datagram = duplex->receive_datagram(
            std::chrono::seconds{5});
        if (datagram.channel != rwn::transport::DatagramChannel::audio ||
            datagram.payload != std::vector<std::byte>(
                                    audio.begin(), audio.end())) {
            throw std::runtime_error("datagram echo mismatch");
        }
        std::cout << "provider=schannel-fallback tls=1.3 dtls=1.2 "
                     "stream_echo=1 datagram_echo=1\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "rwn-schannel-fallback-loopback-probe: "
                  << error.what() << '\n';
        return 1;
    }
}
