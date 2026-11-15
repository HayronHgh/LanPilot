#pragma once
#if defined(__APPLE__)
#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <poll.h>
#include <span>
#include <stdexcept>
#include "rwn/core/cancellation.hpp"
#include <streambuf>
#include <unistd.h>

namespace rwn::agent {
// Poll only when blocked; ready data has no timer gate. The stop observer never
// closes another thread's descriptor (which need not interrupt a blocked read).
inline bool wait_descriptor(int fd, short events, rwn::core::CancellationToken stop) {
    while (!stop.stop_requested()) {
        pollfd item{fd, events, 0};
        const auto result = ::poll(&item, 1, 10);
        if (result < 0 && errno == EINTR) continue;
        if (result < 0) return false;
        if (result > 0) return !stop.stop_requested() &&
            (item.revents & (events | POLLHUP | POLLERR)) != 0;
    }
    return false;
}
inline bool read_control_fd(int fd, std::span<std::byte> output, rwn::core::CancellationToken stop) {
    while (!output.empty()) {
        if (!wait_descriptor(fd, POLLIN, stop)) return false;
        const auto count = ::read(fd, output.data(), output.size());
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0) return false;
        output = output.subspan(static_cast<std::size_t>(count));
    }
    return !stop.stop_requested();
}
// Only the SSH visual writer owns this stream buffer. Writes stay bounded even
// if the peer stops reading. No pixels, diagnostics or newline are added.
class StoppableOutput final : public std::streambuf {
public:
    StoppableOutput(int fd, rwn::core::CancellationToken stop) : fd_(fd), stop_(stop) {
        original_flags_ = fcntl(fd_, F_GETFL);
        if (original_flags_ < 0 || fcntl(fd_, F_SETFL, original_flags_ | O_NONBLOCK) < 0)
            throw std::runtime_error("cannot make visual output interruptible");
    }
    ~StoppableOutput() override { fcntl(fd_, F_SETFL, original_flags_); }
private:
    std::streamsize xsputn(const char* data, std::streamsize count) override {
        std::streamsize done{};
        while (done < count && wait_descriptor(fd_, POLLOUT, stop_)) {
            const auto size = static_cast<std::size_t>(std::min<std::streamsize>(count-done, 65536));
            const auto wrote = ::write(fd_, data+done, size);
            if (wrote < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            if (wrote <= 0) break;
            done += static_cast<std::streamsize>(wrote);
        }
        return done;
    }
    int_type overflow(int_type value) override {
        if (traits_type::eq_int_type(value, traits_type::eof())) return traits_type::not_eof(value);
        const auto byte = traits_type::to_char_type(value);
        return xsputn(&byte,1)==1 ? value : traits_type::eof();
    }
    int fd_;
    int original_flags_{};
    rwn::core::CancellationToken stop_;
};
} // namespace rwn::agent
#endif
