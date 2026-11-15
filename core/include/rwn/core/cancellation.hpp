#pragma once

#include <array>
#include <atomic>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace rwn::core {
namespace detail {
struct CancellationHook { virtual void invoke() noexcept = 0; protected: ~CancellationHook() = default; };
struct CancellationState {
    std::atomic_bool stopped{};
    std::recursive_mutex mutex;
    std::array<CancellationHook*,8> callbacks{};
};
}
class CancellationToken {
public:
    CancellationToken() = default;
    [[nodiscard]] bool stop_possible()const noexcept{return static_cast<bool>(state_);}
    [[nodiscard]] bool stop_requested() const noexcept {
        return state_ && state_->stopped.load(std::memory_order_acquire);
    }
private:
    friend class CancellationSource;
    template<class Action> friend class CancellationCallback;
    explicit CancellationToken(std::shared_ptr<detail::CancellationState> state) : state_(std::move(state)) {}
    std::shared_ptr<detail::CancellationState> state_;
};
// Callbacks run on the requesting normal thread, never a POSIX signal handler.
// An already-stopped source returns before taking a lock, including reentrant
// or cross-source cancellation. Registration destruction waits for invocation.
class CancellationSource {
public:
    CancellationSource() : state_(std::make_shared<detail::CancellationState>()) {}
    [[nodiscard]] CancellationToken token() const { return CancellationToken(state_); }
    bool request_stop() noexcept {
        if (state_->stopped.exchange(true,std::memory_order_acq_rel)) return false;
        std::lock_guard lock(state_->mutex);
        for (auto* callback : state_->callbacks) if (callback) callback->invoke();
        return true;
    }
private:
    std::shared_ptr<detail::CancellationState> state_;
};
// Fixed fan-out prevents unbounded registration/allocation during cancellation.
// Actions must be bounded, noexcept, and must not join a thread which is trying
// to unregister a callback on this source. Self-unregistration is supported.
template<class Action> class CancellationCallback final : detail::CancellationHook {
public:
    CancellationCallback(CancellationToken token, Action action)
        : state_(std::move(token.state_)),action_(std::move(action)) {
        if (!state_) return;
        std::lock_guard lock(state_->mutex);
        if (state_->stopped.load(std::memory_order_acquire)) { invoke(); return; }
        for (auto& slot : state_->callbacks) if (!slot) { slot=this; return; }
        throw std::length_error("too many cancellation registrations");
    }
    CancellationCallback(const CancellationCallback&) = delete;
    CancellationCallback& operator=(const CancellationCallback&) = delete;
    ~CancellationCallback() {
        if (!state_) return;
        std::lock_guard lock(state_->mutex);
        for (auto& slot : state_->callbacks) if (slot==this) slot=nullptr;
    }
private:
    void invoke() noexcept override { action_(); }
    std::shared_ptr<detail::CancellationState> state_;
    Action action_;
};
} // namespace rwn::core
