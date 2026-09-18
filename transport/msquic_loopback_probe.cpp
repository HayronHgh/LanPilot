#include "rwn/transport/msquic_client.hpp"
#include "rwn/transport/msquic_server.hpp"

#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <future>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {

[[nodiscard]] std::uint16_t parse_port(const std::string_view value) {
    std::uint32_t parsed{};
    const auto [end, error] = std::from_chars(
        value.data(), value.data() + value.size(), parsed);
    if (error != std::errc{} || end != value.data() + value.size() ||
        parsed == 0 || parsed > 65'535U) {
        throw std::invalid_argument("listen port is invalid");
    }
    return static_cast<std::uint16_t>(parsed);
}

}  // namespace

int main(const int argc, char** argv) {
    try {
        if (argc != 7) {
            std::cerr
                << "usage: rwn-msquic-loopback-probe <absolute-msquic.dll> "
                   "<server-cert-sha1> <server-cert-sha256> "
                   "<client-cert-sha1> <client-cert-sha256> <port>\n";
            return 64;
        }
        const auto runtime = std::filesystem::path(argv[1]);
        const auto server_sha1 =
            rwn::transport::parse_sha1_thumbprint(argv[2]);
        const auto server_sha256 =
            rwn::transport::parse_sha256_fingerprint(argv[3]);
        const auto client_sha1 =
            rwn::transport::parse_sha1_thumbprint(argv[4]);
        const auto client_sha256 =
            rwn::transport::parse_sha256_fingerprint(argv[5]);
        const auto port = parse_port(argv[6]);

        auto settings = rwn::transport::QuicTransportSettings{};
        settings.enable_fallback = false;
        settings.maximum_datagram_bytes = 1200;
        rwn::transport::MsQuicServerListener listener({
            .runtime_library = runtime,
            .server_certificate_sha1 = server_sha1,
            .allowed_client_certificate_sha256 = {client_sha256},
            .listen_port = port,
            .certificate_in_machine_store = false,
            .stream_read_timeout = std::chrono::seconds{5},
            .maximum_pending_connections = 4,
        }, settings);

        const std::array ping{
            std::byte{'p'}, std::byte{'i'}, std::byte{'n'}, std::byte{'g'}};
        const std::array pong{
            std::byte{'p'}, std::byte{'o'}, std::byte{'n'}, std::byte{'g'}};
        const std::array done{
            std::byte{'d'}, std::byte{'o'}, std::byte{'n'}, std::byte{'e'}};
        const std::array audio{
            std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
        const std::array video{
            std::byte{0x10}, std::byte{0x20}, std::byte{0x30}};

        auto server = std::async(std::launch::async, [&] {
            auto accepted = listener.accept(std::chrono::seconds{10});
            auto& connection = accepted.transport;
            auto stream = connection->accept_stream(std::chrono::seconds{5});
            if (stream.purpose != rwn::transport::StreamPurpose::control ||
                stream.stream->read() !=
                    std::vector<std::byte>(ping.begin(), ping.end())) {
                throw std::runtime_error(
                    "server received invalid stream payload");
            }
            const auto datagram =
                connection->receive_datagram(std::chrono::seconds{5});
            if (datagram.channel != rwn::transport::DatagramChannel::audio ||
                datagram.payload !=
                    std::vector<std::byte>(audio.begin(), audio.end())) {
                throw std::runtime_error(
                    "server received invalid datagram payload");
            }
            stream.stream->write(pong);
            connection->send_datagram(
                rwn::transport::DatagramChannel::video, video);
            if (stream.stream->read() !=
                std::vector<std::byte>(done.begin(), done.end())) {
                throw std::runtime_error(
                    "server did not receive completion acknowledgement");
            }
        });

        std::exception_ptr client_error;
        try {
            rwn::transport::MsQuicClientConnector connector({
                .runtime_library = runtime,
                .client_certificate_sha1 = client_sha1,
                .allowed_server_certificate_sha256 = {server_sha256},
                .connect_timeout = std::chrono::seconds{10},
                .stream_read_timeout = std::chrono::seconds{5},
            });
            auto connection = connector.connect(
                rwn::transport::TransportMode::quic,
                {.host = "localhost", .port = port,
                 .path = rwn::transport::NetworkPath::lan},
                settings);
            auto* duplex = dynamic_cast<rwn::transport::DuplexTransport*>(
                connection.get());
            if (duplex == nullptr) {
                throw std::runtime_error(
                    "MsQuic client did not provide duplex transport");
            }
            auto stream = connection->open_stream(
                rwn::transport::StreamPurpose::control);
            stream->write(ping);
            connection->send_datagram(
                rwn::transport::DatagramChannel::audio, audio);
            if (stream->read() !=
                std::vector<std::byte>(pong.begin(), pong.end())) {
                throw std::runtime_error(
                    "client received invalid stream payload");
            }
            const auto datagram =
                duplex->receive_datagram(std::chrono::seconds{5});
            if (datagram.channel != rwn::transport::DatagramChannel::video ||
                datagram.payload !=
                    std::vector<std::byte>(video.begin(), video.end())) {
                throw std::runtime_error(
                    "client received invalid datagram payload");
            }
            stream->write(done);
        } catch (...) {
            client_error = std::current_exception();
        }
        std::exception_ptr server_error;
        try {
            server.get();
        } catch (...) {
            server_error = std::current_exception();
        }
        if (server_error) std::rethrow_exception(server_error);
        if (client_error) std::rethrow_exception(client_error);
        std::cout << "provider=msquic role=loopback-mtls "
                     "stream=bidirectional datagram=bidirectional passed=1\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "rwn-msquic-loopback-probe: " << error.what() << '\n';
        return 1;
    }
}
