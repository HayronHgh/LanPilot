#pragma once

#include "rwn/transport/tls_byte_channel.hpp"
#include <algorithm>
#include <stdexcept>

namespace rwn::transport {
// Bounded byte-stream adapter for existing RWV2/RWC1 parsers. TLS records are
// neither packet headers nor application message boundaries. One reader and
// one writer may operate concurrently; caller joins both before destruction.
// The caller owns the channel and validates protocol lengths before allocating.
class TlsStreamIo {
public:
    explicit TlsStreamIo(TlsByteChannel& channel) : channel_(channel) {}
    TlsStreamIo(const TlsStreamIo&) = delete;
    TlsStreamIo& operator=(const TlsStreamIo&) = delete;

    void read_exact(std::span<std::byte> destination, std::chrono::milliseconds timeout) {
        const auto deadline = checked_deadline(timeout);
        try {
            while (!destination.empty()) {
                if (offset_ == pending_.size()) {
                    pending_ = channel_.read_some(remaining(deadline));
                    offset_ = 0;
                    if (pending_.empty() || pending_.size() > tls_channel_write_limit)
                        throw std::runtime_error("TLS stream read outside bounds");
                }
                const auto amount = std::min(destination.size(), pending_.size()-offset_);
                std::copy_n(pending_.begin()+static_cast<std::ptrdiff_t>(offset_), amount,
                            destination.begin());
                offset_ += amount;
                destination = destination.subspan(amount);
            }
        } catch (...) { channel_.cancel(); throw; }
    }
    void write_all(std::span<const std::byte> source, std::chrono::milliseconds timeout) {
        const auto deadline = checked_deadline(timeout);
        try {
            while (!source.empty()) {
                const auto amount = std::min(source.size(), tls_channel_write_limit);
                channel_.write(source.first(amount), remaining(deadline));
                source = source.subspan(amount);
            }
        } catch (...) { channel_.cancel(); throw; }
    }
    [[nodiscard]] std::size_t buffered_bytes() const noexcept { return pending_.size()-offset_; }
    [[nodiscard]] bool wait_message_start(std::chrono::milliseconds interval) {
        static_cast<void>(checked_deadline(interval));
        if (buffered_bytes() != 0) return true;
        try { return channel_.wait_readable(interval); }
        catch (...) { channel_.cancel(); throw; }
    }
private:
    using Clock = std::chrono::steady_clock;
    static Clock::time_point checked_deadline(std::chrono::milliseconds timeout) {
        if (timeout.count() <= 0 || timeout > std::chrono::seconds(30))
            throw std::invalid_argument("TLS stream timeout outside bounds");
        return Clock::now()+timeout;
    }
    static std::chrono::milliseconds remaining(Clock::time_point deadline) {
        const auto result = std::chrono::ceil<std::chrono::milliseconds>(deadline-Clock::now());
        if (result.count() <= 0) throw std::runtime_error("TLS stream deadline expired");
        return result;
    }
    TlsByteChannel& channel_;
    std::vector<std::byte> pending_;
    std::size_t offset_{};
};
} // namespace rwn::transport
