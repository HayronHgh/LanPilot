#pragma once
#if defined(__APPLE__)
#include "rwn/platform/macos/tcp_listener.hpp"
#include "rwn/transport/tls_stream_io.hpp"
#include <charconv>
#include <fstream>
#include <iostream>
#include <streambuf>
#include <thread>
#include <atomic>
#include <filesystem>

namespace rwn::preview {
// Single explicitly configured, paired-client desktop session. No shell,
// dynamic paths from the peer, plaintext fallback or implicit input grant.
class TlsPreviewSession {
    using Clock = std::chrono::steady_clock;
    using Bytes = std::vector<std::byte>;
    std::array<std::unique_ptr<transport::TlsByteChannel>, 2> channels_;
    std::unique_ptr<transport::TcpChannelSession> admission_;
    std::thread expiry_;
    std::atomic_bool stop_expiry_{};
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
                      Bytes root, bool interactive, Bytes client_ocsp_response = {}) {
        platform::macos::DedicatedTlsListener listener(options, std::move(bind),
            std::move(root), std::move(client_ocsp_response));
        // No session/capture/input exists while waiting. Idle polls do not
        // restart the listener or suppress TLS authentication failures.
        do {
            channels_[0] = listener.try_accept(std::chrono::seconds(10),
                                               std::chrono::seconds(10));
        } while (!channels_[0]);
        // A connected peer cannot retain a half-session indefinitely.
        channels_[1] = listener.accept(std::chrono::seconds(30));
        const auto id = platform::macos::new_tcp_session_id();
        const auto expires = Clock::now()+std::chrono::minutes(30);
        admission_ = std::make_unique<transport::TcpChannelSession>(id, 1,
            channels_[0]->peer().certificate_sha256,
            transport::ChannelGrants{true,true,interactive}, expires);
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
            id, 1, {true,true,admission_->input_allowed(2,Clock::now())}}),
            std::chrono::seconds(10));
        output_ = std::make_unique<Output>(*this,*channels_[0]);
        input_ = std::make_unique<Input>(*this,*channels_[1]);
        // Expiration actively interrupts both sockets, including idle reads.
        expiry_ = std::thread([this,expires] {
            while (!stop_expiry_.load() && Clock::now()<expires)
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            if (!stop_expiry_.load()) cancel();
        });
        old_out_ = std::cout.rdbuf(output_.get());
        old_in_ = std::cin.rdbuf(input_.get());
        old_tie_ = std::cin.tie(nullptr); // Control reads must not flush the visual writer.
    }
    void cancel() noexcept { for (auto& channel : channels_) if (channel) channel->cancel(); }
    ~TlsPreviewSession() {
        cancel();
        stop_expiry_.store(true);
        if (expiry_.joinable()) expiry_.join();
        if (old_out_) std::cout.rdbuf(old_out_);
        if (old_in_) std::cin.rdbuf(old_in_);
        std::cin.tie(old_tie_);
    }
};
} // namespace rwn::preview
#endif
