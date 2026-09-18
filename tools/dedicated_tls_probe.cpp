#include "rwn/transport/tls_byte_channel.hpp"
#include "rwn/transport/channel_session.hpp"
#include "rwn/transport/tls_stream_io.hpp"
#ifdef _WIN32
#include "rwn/platform/windows/schannel_transport.hpp"
#else
#include "rwn/platform/macos/tcp_listener.hpp"
#endif
#include <array>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {
using namespace std::chrono_literals;
using rwn::transport::TlsByteChannel;
std::vector<std::byte> read_root(const std::filesystem::path& path) {
    if (!path.is_absolute() || !std::filesystem::is_regular_file(path))
        throw std::invalid_argument("root must be an absolute certificate file");
    const auto size = std::filesystem::file_size(path);
    if (size == 0 || size > 64U*1024U) throw std::invalid_argument("root size outside bounds");
    std::ifstream input(path, std::ios::binary);
    std::vector<std::byte> result(static_cast<std::size_t>(size));
    if (!input.read(reinterpret_cast<char*>(result.data()), static_cast<std::streamsize>(size)) ||
        input.peek() != std::char_traits<char>::eof()) throw std::runtime_error("root read failed");
    return result;
}
std::uint16_t port(std::string_view text) {
    unsigned value{};
    const auto [end, error] = std::from_chars(text.data(), text.data()+text.size(), value);
    if (error != std::errc{} || end != text.data()+text.size() || value == 0 || value > 65535)
        throw std::invalid_argument("invalid port");
    return static_cast<std::uint16_t>(value);
}
std::vector<std::byte> receive(rwn::transport::TlsStreamIo& stream, std::size_t length) {
    std::vector<std::byte> result(length);
    stream.read_exact(result, 10s);
    return result;
}
#ifndef _WIN32
std::vector<std::byte> reference(std::string_view text) {
    if (text.empty() || text.size() > 8192 || text.size()%2 != 0)
        throw std::invalid_argument("invalid identity reference");
    std::vector<std::byte> result;
    for (std::size_t i=0; i<text.size(); i+=2) {
        unsigned value{};
        const auto [end, error] = std::from_chars(text.data()+i, text.data()+i+2, value, 16);
        if (error != std::errc{} || end != text.data()+i+2) throw std::invalid_argument("invalid identity reference");
        result.push_back(static_cast<std::byte>(value));
    }
    return result;
}
#endif
}

// Explicit opt-in runtime probe: synthetic bytes only, never screen/input.
// No certificate installation, trust changes, firewall changes or Agent shell.
int main(int argc, char** argv) {
    try {
        if (argc != 5 && argc != 6 && argc != 7) {
            std::cerr << "usage: rwn-dedicated-tls-probe <numeric-bind-or-host> <port> <local-cert-sha1-or-keychain-ref-hex> <peer-cert-sha256> [absolute-exclusive-root.der]\n";
            return 2;
        }
        std::array<std::unique_ptr<TlsByteChannel>, 2> channels;
        const auto exclusive_root = argc >= 6 ? read_root(argv[5]) : std::vector<std::byte>{};
#ifdef _WIN32
        rwn::platform::windows::SchannelFallbackClientOptions options;
        options.exclusive_root_der = exclusive_root;
        if (argc == 7) options.exclusive_crl_der = read_root(argv[6]);
        options.client_certificate_sha1 = rwn::platform::windows::parse_schannel_sha1_thumbprint(argv[3]);
        options.allowed_server_certificate_sha256 = {rwn::platform::windows::parse_schannel_sha256_fingerprint(argv[4])};
        const rwn::transport::TransportEndpoint endpoint{argv[1], port(argv[2]), rwn::transport::NetworkPath::lan};
        for (std::size_t i=0; i<channels.size(); ++i) {
            std::cout << "tls_connect_begin=" << i << std::endl;
            channels[i] = rwn::platform::windows::connect_dedicated_tls_channel(options, endpoint);
            std::cout << "tls_connected=" << i << std::endl;
        }
#else
        rwn::transport::AppleNetworkServerOptions options;
        options.listen_port = port(argv[2]);
        options.maximum_pending_connections = 2;
        options.identity.keychain_persistent_reference = reference(argv[3]);
        options.identity.allowed_peer_certificate_sha256 = {rwn::transport::parse_apple_network_sha256_fingerprint(argv[4])};
        rwn::platform::macos::DedicatedTlsListener listener(options, argv[1], exclusive_root);
        const bool idle_test = argc == 7 && std::string_view(argv[6]) == "--idle-listener-test";
        if (argc == 7 && !idle_test) throw std::invalid_argument("unknown Mac probe option");
        if (idle_test) {
            for (const auto bad : {0ms, 30001ms}) {
                bool idle_rejected = false, handshake_rejected = false;
                try { (void)listener.try_accept(bad, 1s); }
                catch (const std::invalid_argument&) { idle_rejected = true; }
                try { (void)listener.try_accept(1s, bad); }
                catch (const std::invalid_argument&) { handshake_rejected = true; }
                if (!idle_rejected || !handshake_rejected)
                    throw std::runtime_error("listener accepted invalid deadline");
            }
            const auto begin = std::chrono::steady_clock::now();
            std::cout << "tls_idle_test_begin=1 do_not_connect_yet=1" << std::endl;
            for (int poll = 0; poll < 7; ++poll) {
                if (listener.try_accept(5s, 1s))
                    throw std::runtime_error("unexpected client during idle test");
            }
            const auto elapsed = std::chrono::steady_clock::now() - begin;
            if (elapsed < 35s) throw std::runtime_error("idle polls returned prematurely");
            std::cout << "tls_idle_test_passed=1 polls=7 elapsed_ms="
                      << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()
                      << std::endl;
        }
        for (std::size_t i=0; i<channels.size(); ++i) {
            std::cout << "tls_accept_begin=" << i << std::endl;
            channels[i] = idle_test ? listener.try_accept(30s, 10s) : listener.accept(30s);
            if (!channels[i]) throw std::runtime_error("probe client did not connect");
            std::cout << "tls_accepted=" << i << std::endl;
        }
        if (idle_test) {
            auto waiting = std::async(std::launch::async, [&listener] {
                try { (void)listener.try_accept(10s, 1s); }
                catch (const std::runtime_error& error) {
                    return std::string_view(error.what()) == "TCP listener closed";
                }
                return false;
            });
            listener.cancel();
            listener.cancel();
            if (waiting.wait_for(2s) != std::future_status::ready || !waiting.get())
                throw std::runtime_error("listener cancellation did not wake idle accept");
            bool closed_rejected = false;
            try { (void)listener.try_accept(1s, 1s); }
            catch (const std::runtime_error& error) {
                closed_rejected = std::string_view(error.what()) == "TCP listener closed";
            }
            if (!closed_rejected) throw std::runtime_error("cancelled listener accepted work");
            // The subsequent byte round trips also prove that listener
            // cancellation does not revoke already accepted channel owners.
            std::cout << "tls_listener_cancel_passed=1" << std::endl;
        }
#endif
        // Server issues a fresh identity only over the authenticated visual
        // socket. Grants remain local; an issued ID is never a capability.
        std::array streams{rwn::transport::TlsStreamIo{*channels[0]},
                           rwn::transport::TlsStreamIo{*channels[1]}};
#ifdef _WIN32
        const auto issued = rwn::transport::decode_channel_hello(
            receive(streams[0], rwn::transport::channel_hello_bytes));
        if (issued.channel != rwn::transport::TcpChannel::visual)
            throw std::runtime_error("session issue on wrong role");
        const auto session_id = issued.session_id;
        const auto generation = issued.generation;
#else
        const auto session_id = rwn::platform::macos::new_tcp_session_id();
        constexpr std::uint64_t generation = 1;
        channels[0]->write(rwn::transport::encode_channel_hello(
            {rwn::transport::TcpChannel::visual, session_id, generation}), 10s);
#endif
        rwn::transport::TcpChannelSession session(session_id, generation,
            channels[0]->peer().certificate_sha256, {true, true},
            rwn::transport::TcpChannelSession::Clock::now() + 30s);
        for (std::size_t index=0; index<channels.size(); ++index) {
            const auto role = index == 0 ? rwn::transport::TcpChannel::visual
                                         : rwn::transport::TcpChannel::control;
            const auto hello = rwn::transport::encode_channel_hello({role, session_id, generation});
#ifdef _WIN32
            channels[index]->write(hello, 10s);
            const auto remote = receive(streams[index], hello.size());
#else
            const auto remote = receive(streams[index], hello.size());
#endif
            if (!session.attach(rwn::transport::decode_channel_hello(remote),
                    channels[index]->peer(), index+1,
                    rwn::transport::TcpChannelSession::Clock::now()))
                throw std::runtime_error("TLS session admission rejected");
#ifndef _WIN32
            channels[index]->write(hello, 10s);
#endif
            std::cout << "tls_session_admitted=" << index << std::endl;
        }
        if (session.input_allowed(2, rwn::transport::TcpChannelSession::Clock::now()))
            throw std::runtime_error("view-only session acquired input");
        constexpr std::size_t size = 128U*1024U+13;
        for (std::size_t index=0; index<channels.size(); ++index) {
            std::vector<std::byte> expected(size);
            for (std::size_t i=0; i<size; ++i) expected[i] = static_cast<std::byte>((i+index*31)%251);
#ifdef _WIN32
            streams[index].write_all(expected, 10s);
            if (receive(streams[index], size) != expected) throw std::runtime_error("TLS echo byte mismatch");
            channels[index]->write(std::array{std::byte{0xAC}}, 10s);
#else
            const auto received = receive(streams[index], size);
            if (received != expected) throw std::runtime_error("TLS incoming byte mismatch");
            streams[index].write_all(received, 10s);
            if (receive(streams[index], 1) != std::vector{std::byte{0xAC}})
                throw std::runtime_error("TLS echo receipt missing");
#endif
            std::cout << "tls_roundtrip_complete=" << index << std::endl;
        }
        session.disconnect(1);
        if (!session.revoked() || session.active(rwn::transport::TcpChannel::control,
                2, rwn::transport::TcpChannelSession::Clock::now()))
            throw std::runtime_error("TLS session disconnect did not revoke sibling");
        for (auto& channel : channels) {
            channel->cancel();
            bool rejected = false;
            try { channel->write(std::array{std::byte{1}}, 1s); }
            catch (const std::exception&) { rejected = true; }
            if (!rejected) throw std::runtime_error("cancelled TLS channel accepted write");
        }
        std::cout << "dedicated_tls_probe=passed connections=2 admitted_roles=2 sibling_revoked=1 byte_mismatch=0 cancelled_write_rejected=2\n";
        return 0;
    } catch (const std::exception& error) {
        // No endpoints, identities or command line echoed into diagnostics.
        std::cerr << "dedicated_tls_probe=failed reason=" << error.what() << '\n';
        return 1;
    }
}
