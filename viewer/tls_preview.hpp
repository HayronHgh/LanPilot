#pragma once
#include "rwn/platform/windows/schannel_transport.hpp"
#include "rwn/transport/channel_session.hpp"
#include "rwn/transport/tls_stream_io.hpp"
#include "rwn/desktop/text_clipboard.hpp"
#include "rwn/audio/audio.hpp"
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>

namespace rwn::viewer {
class TlsPreviewConnection {
    std::array<std::unique_ptr<transport::TlsByteChannel>,2> channels_;
    std::array<std::unique_ptr<transport::TlsStreamIo>,2> io_;
    bool clipboard_allowed_{};
    // Optional third channel for Mac system audio, opened after admission.
    platform::windows::SchannelFallbackClientOptions audio_options_;
    transport::TransportEndpoint audio_endpoint_;
    transport::ChannelHello issued_{};
    core::CancellationSource audio_stop_;
    std::mutex audio_mutex_;
    std::unique_ptr<transport::TlsByteChannel> audio_channel_;
    std::unique_ptr<transport::TlsStreamIo> audio_io_;
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
                         const transport::TransportEndpoint& endpoint, bool request_input = false)
        : audio_options_(options), audio_endpoint_(endpoint) {
        audio_options_.establishment_stop = audio_stop_.token();
        using namespace std::chrono_literals;
        auto check_stop=[&]{if(options.establishment_stop.stop_requested())throw transport::TlsTransportInterrupted(transport::TlsTransportInterrupted::Reason::cancelled,"TLS admission cancelled");};
        check_stop();channels_[0]=platform::windows::connect_dedicated_tls_channel(options,endpoint);
        core::CancellationCallback first(options.establishment_stop,[channel=channels_[0].get()]()noexcept{channel->cancel();});
        check_stop();channels_[1]=platform::windows::connect_dedicated_tls_channel(options,endpoint);
        core::CancellationCallback second(options.establishment_stop,[channel=channels_[1].get()]()noexcept{channel->cancel();});
        for(std::size_t i=0;i<2;++i)io_[i]=std::make_unique<transport::TlsStreamIo>(*channels_[i]);
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
        clipboard_allowed_=request_input && transport::decode_channel_admission(admission).grants.text_clipboard;
        issued_=issued;
        check_stop();
    }
    // Throws when the Mac does not offer audio (for example an older agent);
    // callers treat that as "no audio", never as a desktop session failure.
    void open_audio() {
        using namespace std::chrono_literals;
        auto channel=platform::windows::connect_dedicated_tls_channel(audio_options_,audio_endpoint_);
        auto io=std::make_unique<transport::TlsStreamIo>(*channel);
        {
            std::lock_guard lock(audio_mutex_);
            if(audio_stop_.token().stop_requested())throw std::runtime_error("audio channel cancelled");
            audio_channel_=std::move(channel);
        }
        const auto hello=transport::encode_channel_hello({transport::TcpChannel::audio,issued_.session_id,issued_.generation});
        io->write_all(hello,5s);
        std::array<std::byte,transport::channel_hello_bytes> echo{};
        io->read_exact(echo,5s);
        if(echo!=hello)throw std::runtime_error("TLS audio admission rejected");
        audio_io_=std::move(io);
    }
    // Waits in short slices so an idle (silent) Mac never times the channel out.
    std::optional<audio::PcmStreamFrame> read_audio(const std::stop_token& stop){
        if(!audio_io_)throw std::logic_error("audio channel is not open");
        while(!audio_io_->wait_message_start(std::chrono::milliseconds(500)))
            if(stop.stop_requested())return {};
        std::vector<std::byte> wire(audio::pcm_stream_frame_size);
        audio_io_->read_exact(wire,std::chrono::seconds(5));
        return audio::decode_pcm_stream_frame(wire);
    }
    bool clipboard_allowed()const noexcept{return clipboard_allowed_;}
    std::optional<desktop::TextClipboardMessage> read_clipboard(){
        if(!clipboard_allowed_)throw std::logic_error("clipboard is not granted");
        if(!io_[1]->wait_message_start(std::chrono::milliseconds(500)))return {};
        std::array<std::byte,desktop::text_clipboard_header_size> header{};
        io_[1]->read_exact(header,std::chrono::seconds(5));
        const auto size=desktop::text_clipboard_payload_size(header);
        std::vector<std::byte> wire(header.begin(),header.end());
        wire.resize(header.size()+size);
        if(size)io_[1]->read_exact(std::span{wire}.subspan(header.size()),std::chrono::seconds(5));
        return desktop::decode_text_clipboard(wire);
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
    void cancel() noexcept {
        for (auto& channel : channels_) if (channel) channel->cancel();
        audio_stop_.request_stop();
        std::lock_guard lock(audio_mutex_);
        if (audio_channel_) audio_channel_->cancel();
    }
    ~TlsPreviewConnection() { cancel(); }
};
}
