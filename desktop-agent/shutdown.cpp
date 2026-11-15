#include "shutdown.hpp"
#if defined(__APPLE__)
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <stdexcept>
#include <thread>

namespace rwn::agent {
namespace {
static_assert(std::atomic_bool::is_always_lock_free);
std::atomic_bool signalled{};
std::atomic_flag installed = ATOMIC_FLAG_INIT;
extern "C" void request_shutdown(int) {
    const auto previous_errno = errno;
    signalled.store(true, std::memory_order_relaxed);
    errno = previous_errno;
}
}
class ProcessShutdown::Impl {
public:
    Impl() {
        if (installed.test_and_set()) throw std::logic_error("stream signal owner already exists");
        signalled.store(false, std::memory_order_relaxed);
        struct sigaction action{};
        sigemptyset(&action.sa_mask);
        action.sa_handler = request_shutdown;
        if (sigaction(SIGTERM, &action, &previous_term_) != 0) {
            installed.clear();
            throw std::runtime_error("cannot observe stream termination");
        }
        if (sigaction(SIGINT, &action, &previous_int_) != 0) {
            sigaction(SIGTERM, &previous_term_, nullptr);
            installed.clear();
            throw std::runtime_error("cannot observe stream interruption");
        }
        // A closed SSH output must become an I/O error and drain input, rather
        // than terminating the process before the input owner gets to release.
        action.sa_handler = SIG_IGN;
        if (sigaction(SIGPIPE, &action, &previous_pipe_) != 0) {
            restore();
            throw std::runtime_error("cannot observe closed stream output");
        }
        try {
            observer_ = std::make_unique<StopThread>([this](rwn::core::CancellationToken stop) {
                while (!stop.stop_requested()) {
                    if (signalled.load(std::memory_order_relaxed)) {
                        source_.request_stop();
                        return;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                }
            });
        } catch (...) {
            sigaction(SIGPIPE, &previous_pipe_, nullptr);
            restore();
            throw;
        }
    }
    ~Impl() {
        observer_.reset();
        sigaction(SIGPIPE, &previous_pipe_, nullptr);
        restore();
    }
    rwn::core::CancellationSource source_;
private:
    void restore() noexcept {
        sigaction(SIGINT, &previous_int_, nullptr);
        sigaction(SIGTERM, &previous_term_, nullptr);
        installed.clear();
    }
    struct sigaction previous_term_{}, previous_int_{}, previous_pipe_{};
    std::unique_ptr<StopThread> observer_;
};
ProcessShutdown::ProcessShutdown() : impl_(new Impl) {}
ProcessShutdown::~ProcessShutdown() { delete impl_; }
rwn::core::CancellationToken ProcessShutdown::token() const noexcept { return impl_->source_.token(); }
} // namespace rwn::agent
#endif
