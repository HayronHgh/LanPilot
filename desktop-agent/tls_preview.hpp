#pragma once
#if defined(__APPLE__)
#include "rwn/platform/macos/tcp_listener.hpp"
#include "rwn/transport/tls_stream_io.hpp"
#include "rwn/desktop/text_clipboard.hpp"
#include "rwn/platform/macos/desktop_runtime.hpp"
#include "rwn/platform/macos/audio_runtime.hpp"
#include "shutdown.hpp"
#include "run_audit.hpp"
#include <charconv>
#include <fstream>
#include <iostream>
#include <streambuf>
#include <thread>
#include <atomic>
#include <filesystem>
#include <mutex>
#include "rwn/core/cancellation.hpp"

namespace rwn::preview {
// Single explicitly configured, paired-client desktop session. No shell,
// dynamic paths from the peer, plaintext fallback or implicit input grant.
class TlsPreviewSession {
    using Clock = std::chrono::steady_clock;
    using Bytes = std::vector<std::byte>;
    rwn::core::CancellationSource session_stop_;
    std::atomic_bool cancelled_{};
    std::array<std::unique_ptr<transport::TlsByteChannel>, 2> channels_;
    std::unique_ptr<transport::TcpChannelSession> admission_;
    platform::macos::MacosClipboardBackend clipboard_backend_;
    std::unique_ptr<desktop::TextClipboardPump> clipboard_;
    std::unique_ptr<rwn::agent::StopThread> expiry_;
    // Kept open only until the optional audio channel arrives or times out.
    std::unique_ptr<platform::macos::DedicatedTlsListener> listener_;
    std::unique_ptr<transport::TlsByteChannel> audio_channel_;
    std::mutex audio_mutex_;
    std::unique_ptr<rwn::agent::StopThread> audio_;
    class Output final : public std::streambuf {
        TlsPreviewSession& owner_;
        transport::TlsStreamIo io_;
        std::streamsize xsputn(const char* data, std::streamsize length) override {
            if (length <= 0) return 0;
            try {
                io_.write_all({reinterpret_cast<const std::byte*>(data),
                    static_cast<std::size_t>(length)}, std::chrono::seconds(10));
                return length;
            } catch (...) { owner_.cancel(); return 0; }
        }
        int_type overflow(int_type value) override {
            if (traits_type::eq_int_type(value, traits_type::eof())) return traits_type::not_eof(value);
            const char byte = traits_type::to_char_type(value);
            return xsputn(&byte, 1) == 1 ? value : traits_type::eof();
        }
    public:
        Output(TlsPreviewSession& owner, transport::TlsByteChannel& channel) : owner_(owner), io_(channel) {}
    };
    class Input final : public std::streambuf {
        TlsPreviewSession& owner_;
        transport::TlsByteChannel& channel_;
        Bytes pending_;
        int_type underflow() override {
            if (gptr() && gptr() < egptr()) return traits_type::to_int_type(*gptr());
            try {
                pending_ = channel_.read_some(std::chrono::seconds(30));
                if (pending_.empty() || pending_.size() > transport::tls_channel_write_limit)
                    throw std::runtime_error("TLS control record outside bounds");
                auto* begin = reinterpret_cast<char*>(pending_.data());
                setg(begin, begin, begin+pending_.size());
                return traits_type::to_int_type(*gptr());
            } catch (...) { owner_.cancel(); return traits_type::eof(); }
        }
    public:
        Input(TlsPreviewSession& owner, transport::TlsByteChannel& channel) : owner_(owner), channel_(channel) {}
    };
    std::unique_ptr<Output> output_;
    std::unique_ptr<Input> input_;
    std::streambuf* old_out_{};
    std::streambuf* old_in_{};
    std::ostream* old_tie_{};
public:
    static Bytes read_root(const std::filesystem::path& path) {
        if (!path.is_absolute() || !std::filesystem::is_regular_file(path))
            throw std::invalid_argument("TLS root requires absolute regular file");
        const auto size = std::filesystem::file_size(path);
        if (!size || size > 65536) throw std::invalid_argument("TLS root outside bounds");
        Bytes bytes(static_cast<std::size_t>(size));
        std::ifstream file(path, std::ios::binary);
        if (!file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size)) ||
            file.peek() != std::char_traits<char>::eof()) throw std::runtime_error("TLS root read failed");
        return bytes;
    }
    static Bytes identity(std::string_view text) {
        if (text.empty() || text.size() > 8192 || text.size()%2)
            throw std::invalid_argument("invalid TLS identity reference");
        Bytes result;
        for (std::size_t i=0; i<text.size(); i+=2) {
            unsigned value{};
            const auto [end, error] = std::from_chars(text.data()+i,text.data()+i+2,value,16);
            if (error != std::errc{} || end != text.data()+i+2)
                throw std::invalid_argument("invalid TLS identity reference");
            result.push_back(static_cast<std::byte>(value));
        }
        return result;
    }
    TlsPreviewSession(transport::AppleNetworkServerOptions options, std::string bind,
                      Bytes root, bool interactive, Bytes client_ocsp_response = {}, bool allow_clipboard = false,
                      rwn::core::CancellationToken process_stop = {},std::function<Bytes()> native_client_status = {}) {
        if (process_stop.stop_requested()) throw std::runtime_error("desktop service stopping");
        listener_ = std::make_unique<platform::macos::DedicatedTlsListener>(options, std::move(bind),
            std::move(root), std::move(client_ocsp_response),std::move(native_client_status));
        auto& listener = *listener_;
        listener.wait_ready(std::chrono::seconds(3), process_stop);
        rwn::agent::observe_listener_ready();
        // No session/capture/input exists while waiting. Idle polls do not
        // restart the listener or suppress TLS authentication failures.
        do {
            channels_[0] = listener.try_accept(std::chrono::seconds(10),
                                               std::chrono::seconds(10), process_stop);
        } while (!channels_[0]);
        rwn::core::CancellationCallback interrupt_first(process_stop, [&] { channels_[0]->cancel(); });
        // A connected peer cannot retain a half-session indefinitely.
        channels_[1] = listener.accept(std::chrono::seconds(30), process_stop);
        rwn::core::CancellationCallback interrupt_second(process_stop, [&] { channels_[1]->cancel(); });
        const auto id = platform::macos::new_tcp_session_id();
        const auto expires = Clock::now()+std::chrono::minutes(30);
        const transport::ChannelHello issued{transport::TcpChannel::visual,id,1};
        admission_ = std::make_unique<transport::TcpChannelSession>(id, 1,
            channels_[0]->peer().certificate_sha256,
            transport::ChannelGrants{true,true,interactive,interactive && allow_clipboard}, expires);
        channels_[0]->write(transport::encode_channel_hello({transport::TcpChannel::visual,id,1}),
                            std::chrono::seconds(10));
        for (std::size_t i=0; i<2; ++i) {
            const auto role = i == 0 ? transport::TcpChannel::visual : transport::TcpChannel::control;
            transport::TlsStreamIo io(*channels_[i]);
            std::array<std::byte, transport::channel_hello_bytes> wire{};
            io.read_exact(wire, std::chrono::seconds(10));
            const auto hello = transport::decode_channel_hello(wire);
            if (hello.channel != role || io.buffered_bytes() != 0 ||
                !admission_->attach(hello,channels_[i]->peer(),i+1,Clock::now()))
                throw std::runtime_error("desktop TLS admission rejected");
            channels_[i]->write(wire,std::chrono::seconds(10));
        }
        if (interactive && !admission_->input_allowed(2, Clock::now()))
            throw std::runtime_error("desktop TLS input not authorized");
        channels_[1]->write(transport::encode_channel_admission({
            id, 1, {true,true,admission_->input_allowed(2,Clock::now()),
                admission_->clipboard_allowed(2,Clock::now())}}),
            std::chrono::seconds(10));
        output_ = std::make_unique<Output>(*this,*channels_[0]);
        input_ = std::make_unique<Input>(*this,*channels_[1]);
        // Expiration actively interrupts both sockets, including idle reads.
        expiry_ = std::make_unique<rwn::agent::StopThread>([this,expires](rwn::core::CancellationToken stop) {
            while (!stop.stop_requested() && Clock::now()<expires)
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            if (!stop.stop_requested()) cancel();
        });
        if(admission_->clipboard_allowed(2,Clock::now())){
            clipboard_=std::make_unique<desktop::TextClipboardPump>(true,true,desktop::TextClipboardCallbacks{
                [this]{return clipboard_backend_.change_token();},
                [this]{return clipboard_backend_.read_available_utf8_text();},
                [this](std::string_view value){clipboard_backend_.write_utf8_text(value);},
                [this](const desktop::TextClipboardMessage& message){
                    const auto wire=desktop::encode_text_clipboard(message);
                    transport::TlsStreamIo io(*channels_[1]);
                    io.write_all(wire,std::chrono::seconds(5));
                }});
        }
        audio_ = std::make_unique<rwn::agent::StopThread>(
            [this,issued,peer=channels_[0]->peer().certificate_sha256,expires](rwn::core::CancellationToken stop) {
                try { stream_audio(stop,issued,peer,expires); }
                catch (const std::exception& error) {
                    if (!stop.stop_requested() && !cancelled_.load())
                        std::cerr << "desktop_audio_stopped reason=" << error.what() << '\n';
                }
                std::lock_guard lock(audio_mutex_);
                listener_.reset();
            });
        // Last fallible initialization is complete before global stream buffers
        // reference this object. Failed setup cannot leave dangling stdio.
        old_out_ = std::cout.rdbuf(output_.get());
        old_in_ = std::cin.rdbuf(input_.get());
        old_tie_ = std::cin.tie(nullptr);
    }
    // Optional, Viewer-initiated system audio. Failure ends only the audio
    // channel; the desktop session never depends on it.
    void stream_audio(rwn::core::CancellationToken stop, const transport::ChannelHello& issued,
                      const transport::CertificateSha256& peer, Clock::time_point expires) {
        const auto stopping = [&]{ return stop.stop_requested() || cancelled_.load(); };
        // Only this thread resets listener_, so the pointer stays valid while
        // accepting without the lock; cancel() may still interrupt it.
        platform::macos::DedicatedTlsListener* listener{};
        {
            std::lock_guard lock(audio_mutex_);
            listener = listener_.get();
        }
        if (!listener) return;
        std::unique_ptr<transport::TlsByteChannel> channel;
        const auto deadline = Clock::now()+std::chrono::seconds(10);
        while (!channel && !stopping() && Clock::now()<deadline)
            channel = listener->try_accept(std::chrono::milliseconds(250),
                                           std::chrono::seconds(10), stop);
        {
            std::lock_guard lock(audio_mutex_);
            listener_.reset();
            if (!channel || stopping()) return;
            audio_channel_ = std::move(channel);
        }
        auto& audio_channel = *audio_channel_;
        transport::TlsStreamIo io(audio_channel);
        std::array<std::byte, transport::channel_hello_bytes> wire{};
        io.read_exact(wire, std::chrono::seconds(5));
        if (io.buffered_bytes() != 0 || !transport::audio_channel_admissible(
                transport::decode_channel_hello(wire), issued, peer,
                audio_channel.peer(), expires, Clock::now()))
            throw std::runtime_error("desktop audio admission rejected");
        audio_channel.write(wire, std::chrono::seconds(5));
        platform::macos::MacosSystemAudioCapture capture;
        std::uint64_t sequence{};
        while (!stopping()) {
            auto captured = capture.capture(std::chrono::milliseconds(200));
            if (!captured) continue;
            io.write_all(audio::encode_pcm_stream_frame({++sequence,
                captured->captured_at_us, std::move(captured->frame)}), std::chrono::seconds(2));
        }
    }
    void receive_clipboard(std::span<const std::byte> payload){
        if(!clipboard_ || !admission_->clipboard_allowed(2,Clock::now()))
            throw std::invalid_argument("Mac clipboard policy denies synchronization");
        clipboard_->receive(desktop::decode_text_clipboard(payload));
    }
    [[nodiscard]] rwn::core::CancellationToken token() const noexcept { return session_stop_.token(); }
    void cancel() noexcept {
        if (cancelled_.exchange(true)) return;
        session_stop_.request_stop();
        for (auto& channel : channels_) if (channel) channel->cancel();
        std::lock_guard lock(audio_mutex_);
        if (listener_) listener_->cancel();
        if (audio_channel_) audio_channel_->cancel();
    }
    ~TlsPreviewSession() {
        cancel();
        audio_.reset();
        clipboard_.reset();
        expiry_.reset();
        if (old_out_) std::cout.rdbuf(old_out_);
        if (old_in_) std::cin.rdbuf(old_in_);
        std::cin.tie(old_tie_);
    }
};
} // namespace rwn::preview
#endif
