#include "rwn/transport/msquic_client.hpp"
#include "rwn/transport/msquic_server.hpp"

#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {

using namespace std::chrono_literals;

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

int run_server(char** argv) {
    rwn::transport::MsQuicServerListener listener({
        .runtime_library = std::filesystem::path(argv[2]),
        .server_certificate_sha1 =
            rwn::transport::parse_sha1_thumbprint(argv[3]),
        .allowed_client_certificate_sha256 = {
            rwn::transport::parse_sha256_fingerprint(argv[4])},
        .listen_port = parse_port(argv[5]),
        .certificate_in_machine_store = false,
        .stream_read_timeout = 10s,
        .maximum_pending_connections = 4,
    }, settings());
    std::cout << "provider=msquic role=server port="
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
    std::cout << "provider=msquic role=server mtls=1 stream=1 datagram=1 passed=1\n";
    return 0;
}

int run_client(char** argv) {
    const auto port = parse_port(argv[6]);
    rwn::transport::MsQuicClientConnector connector({
        .runtime_library = std::filesystem::path(argv[2]),
        .client_certificate_sha1 =
            rwn::transport::parse_sha1_thumbprint(argv[3]),
        .allowed_server_certificate_sha256 = {
            rwn::transport::parse_sha256_fingerprint(argv[4])},
        .connect_timeout = 30s,
        .stream_read_timeout = 10s,
    });
    auto connection = connector.connect(
        rwn::transport::TransportMode::quic,
        {.host = argv[5], .port = port,
         .path = rwn::transport::NetworkPath::lan},
        settings());
    auto* duplex = dynamic_cast<rwn::transport::DuplexTransport*>(
        connection.get());
    if (duplex == nullptr) {
        throw std::runtime_error("MsQuic client is not duplex");
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
    std::cout << "provider=msquic role=client mtls=1 stream=1 datagram=1 passed=1\n";
    return 0;
}

void usage() {
    std::cerr
        << "usage:\n"
           "  rwn-msquic-peer-probe server <absolute-msquic.dll> "
           "<server-cert-sha1> <allowed-client-cert-sha256> <port>\n"
           "  rwn-msquic-peer-probe client <absolute-msquic.dll> "
           "<client-cert-sha1> <allowed-server-cert-sha256> <host> <port>\n";
}

}  // namespace

int main(const int argc, char** argv) {
    try {
        if (argc != 6 && argc != 7) {
            usage();
            return 64;
        }
        const auto role = std::string_view(argv[1]);
        if (role == "server" && argc == 6) return run_server(argv);
        if (role == "client" && argc == 7) return run_client(argv);
        usage();
        return 64;
    } catch (const std::exception& error) {
        std::cerr << "rwn-msquic-peer-probe: " << error.what() << '\n';
        return 1;
    }
}
