#pragma once

#include "rwn/core/cancellation.hpp"
#include <thread>
#include <utility>

namespace rwn::agent {
class StopThread {
public:
    template<class Action> explicit StopThread(Action action)
        : source_(),thread_([token=source_.token(),action=std::move(action)] { action(token); }) {}
    StopThread(const StopThread&) = delete;
    StopThread& operator=(const StopThread&) = delete;
    ~StopThread() { source_.request_stop(); if (thread_.joinable()) thread_.join(); }
private:
    rwn::core::CancellationSource source_;
    std::thread thread_;
};
// Every worker owns its cleanup before it starts. This also covers exceptions
// during startup, before the ordinary stream shutdown block can be reached.
template<class Action> class OnExit {
public:
    explicit OnExit(Action action) : action_(std::move(action)) {}
    OnExit(const OnExit&) = delete;
    OnExit& operator=(const OnExit&) = delete;
    ~OnExit() { run(); }
    void run() noexcept {
        if (!active_) return;
        active_ = false;
        action_();
    }
private:
    Action action_;
    bool active_{true};
};

#if defined(__APPLE__)
// Streaming endpoint only: native setup/consent commands retain their existing
// signal behavior. The handler only sets a lock-free flag; normal threads cancel
// I/O and the single input owner releases its own tracked keys/buttons.
class ProcessShutdown {
public:
    ProcessShutdown();
    ~ProcessShutdown();
    ProcessShutdown(const ProcessShutdown&) = delete;
    ProcessShutdown& operator=(const ProcessShutdown&) = delete;
    [[nodiscard]] rwn::core::CancellationToken token() const noexcept;
private:
    class Impl;
    Impl* impl_{};
};
#endif
} // namespace rwn::agent
