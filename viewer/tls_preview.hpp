#pragma once
#include "rwn/platform/windows/schannel_transport.hpp"
#include "rwn/transport/channel_session.hpp"
#include "rwn/transport/tls_stream_io.hpp"
#include <filesystem>
#include <fstream>
#include <memory>

namespace rwn::viewer {
class TlsPreviewConnection {
    std::array<std::unique_ptr<transport::TlsByteChannel>,2> channels_;
    std::array<std::unique_ptr<transport::TlsStreamIo>,2> io_;
public:
    static std::string ascii(std::wstring_view value) {
        std::string result;
        for (auto ch : value) {
            if (ch < 33 || ch > 126) throw std::invalid_argument("TLS host/identity must be ASCII");
            result.push_back(static_cast<char>(ch));
        }
        return result;
    }
    static std::vector<std::byte> read_der(const std::filesystem::path& path) {
        if (!path.is_absolute() || !std::filesystem::is_regular_file(path))
            throw std::invalid_argument("TLS trust file must be absolute and regular");
        const auto size = std::filesystem::file_size(path);
        if (!size || size > 65536) throw std::invalid_argument("TLS trust file outside bounds");
        std::vector<std::byte> bytes(static_cast<std::size_t>(size));
        std::ifstream file(path,std::ios::binary);
        if (!file.read(reinterpret_cast<char*>(bytes.data()),static_cast<std::streamsize>(size)) ||
            file.peek() != std::char_traits<char>::eof()) throw std::runtime_error("TLS trust file read failed");
        return bytes;
    }
    TlsPreviewConnection(const platform::windows::SchannelFallbackClientOptions& options,
                         const transport::TransportEndpoint& endpoint, bool request_input = false) {
        using namespace std::chrono_literals;
        for (std::size_t i=0;i<2;++i) {
            channels_[i] = platform::windows::connect_dedicated_tls_channel(options,endpoint);
            io_[i] = std::make_unique<transport::TlsStreamIo>(*channels_[i]);
        }
        std::array<std::byte,transport::channel_hello_bytes> wire{};
        io_[0]->read_exact(wire,10s);
        const auto issued = transport::decode_channel_hello(wire);
        if (issued.channel != transport::TcpChannel::visual)
            throw std::runtime_error("unexpected TLS issue role");
        transport::TcpChannelSession session(issued.session_id,issued.generation,
            channels_[0]->peer().certificate_sha256,{true,true},
            transport::TcpChannelSession::Clock::now()+30s);
        for (std::size_t i=0;i<2;++i) {
            const auto role = i == 0 ? transport::TcpChannel::visual : transport::TcpChannel::control;
            const auto hello = transport::encode_channel_hello({role,issued.session_id,issued.generation});
            io_[i]->write_all(hello,10s);
            io_[i]->read_exact(wire,10s);
            if (wire != hello || !session.attach(transport::decode_channel_hello(wire),
                    channels_[i]->peer(),i+1,transport::TcpChannelSession::Clock::now()))
                throw std::runtime_error("TLS desktop admission rejected");
        }
        std::array<std::byte,transport::channel_admission_bytes> admission{};
        io_[1]->read_exact(admission,10s);
        transport::validate_channel_admission(
            transport::decode_channel_admission(admission), issued, request_input);
    }
    bool read(std::span<std::byte> bytes, bool message_start = false) {
        try {
            if (message_start) {
                while (!io_[0]->wait_message_start(std::chrono::milliseconds(500))) {}
            }
            io_[0]->read_exact(bytes,std::chrono::seconds(30)); return true;
        }
        catch (...) { cancel(); throw; }
    }
    void write(std::span<const std::byte> bytes) {
        try { io_[1]->write_all(bytes,std::chrono::seconds(10)); }
        catch (...) { cancel(); throw; }
    }
    void cancel() noexcept { for (auto& channel : channels_) if (channel) channel->cancel(); }
    ~TlsPreviewConnection() { cancel(); }
};
}
