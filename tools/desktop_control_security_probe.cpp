#include "../viewer/tls_preview.hpp"
#include "rwn/desktop/desktop.hpp"
#include <charconv>
#include <iostream>

// Explicit native negative probe. No INPUT_EVENT, keyboard/mouse injection,
// pixel capture files, credential provisioning or system configuration changes.
int main(int argc, char** argv) {
    using namespace rwn;
    using namespace std::chrono_literals;
    try {
        if (argc != 8) throw std::invalid_argument(
            "expected host port client-sha1 server-sha256 root.der crl.der case");
        unsigned port{};
        const std::string_view port_text = argv[2];
        const auto [end, ec] = std::from_chars(port_text.data(), port_text.data()+port_text.size(), port);
        if (ec != std::errc{} || end != port_text.data()+port_text.size() || !port || port > 65535)
            throw std::invalid_argument("invalid port");
        const std::string_view test_case = argv[7];
        if (test_case != "sequence-gap" && test_case != "view-only-release" &&
            test_case != "admission-denied")
            throw std::invalid_argument("unknown negative case");
        platform::windows::SchannelFallbackClientOptions options;
        options.client_certificate_sha1 = platform::windows::parse_schannel_sha1_thumbprint(argv[3]);
        options.allowed_server_certificate_sha256 = {platform::windows::parse_schannel_sha256_fingerprint(argv[4])};
        options.exclusive_root_der = viewer::TlsPreviewConnection::read_der(argv[5]);
        options.exclusive_crl_der = viewer::TlsPreviewConnection::read_der(argv[6]);
        transport::TransportEndpoint endpoint{argv[1], static_cast<std::uint16_t>(port), transport::NetworkPath::lan};
        if (test_case == "admission-denied") {
            // Invoke the actual Viewer connection constructor, not a duplicate
            // test parser. No window/hook/input worker exists in this process.
            bool denied = false;
            try { viewer::TlsPreviewConnection connection(options,endpoint,true); }
            catch (const std::invalid_argument& error) {
                if (std::string_view(error.what()) !=
                    "Mac grants view-only; interactive control was not authorized") throw;
                denied = true;
            }
            if (!denied) throw std::runtime_error("interactive request unexpectedly admitted");
            std::cout << "control_negative=admission-denied explicit_denial=1 input_events_sent=0\n";
            return 0;
        }
        std::array<std::unique_ptr<transport::TlsByteChannel>,2> channels;
        for (auto& channel : channels)
            channel = platform::windows::connect_dedicated_tls_channel(options, endpoint);
        transport::TlsStreamIo visual(*channels[0]), control(*channels[1]);
        std::array<std::byte,transport::channel_hello_bytes> bytes{};
        visual.read_exact(bytes,5s);
        const auto issued = transport::decode_channel_hello(bytes);
        if (issued.channel != transport::TcpChannel::visual) throw std::runtime_error("invalid issue role");
        for (unsigned i=0; i<2; ++i) {
            auto& io = i == 0 ? visual : control;
            const auto hello = transport::encode_channel_hello({
                i == 0 ? transport::TcpChannel::visual : transport::TcpChannel::control,
                issued.session_id, issued.generation});
            io.write_all(hello,5s);
            io.read_exact(bytes,5s);
            if (bytes != hello) throw std::runtime_error("role admission mismatch");
        }
        std::array<std::byte,transport::channel_admission_bytes> admission{};
        control.read_exact(admission,5s);
        const auto grants = transport::decode_channel_admission(admission);
        transport::validate_channel_admission(grants,issued,false);
        if (grants.grants.desktop_input)
            throw std::runtime_error("negative probe requires server view-only grant");
        const auto header = desktop::encode_reverse_control_header({
            .type = test_case == "sequence-gap" ? desktop::ReverseControlType::ping
                : desktop::ReverseControlType::release_all_input,
            .input_epoch = 1,
            .sequence = test_case == "sequence-gap" ? 2U : 1U,
            .occurred_at_us = 1,
        });
        control.write_all(header,5s);
        bool closed = false;
        try { static_cast<void>(channels[1]->read_some(5s)); }
        catch (const std::exception& error) {
            const std::string_view reason = error.what();
            // Timeout/auth failure is NOT evidence of protocol rejection.
            closed = reason == "Schannel TCP peer closed" ||
                     reason == "Schannel peer closed securely" ||
                     reason == "Schannel TCP receive failed; wsa=10054";
            if (!closed) throw;
        }
        for (auto& channel : channels) channel->cancel();
        if (!closed) throw std::runtime_error("peer did not reject negative control case");
        std::cout << "control_negative=" << test_case << " peer_closed=1 input_events_sent=0\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "control_negative_failed=" << error.what() << '\n';
        return 1;
    }
}
