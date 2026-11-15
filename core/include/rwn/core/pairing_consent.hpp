#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <stdexcept>

namespace rwn::core {

// UI consent only, NOT a TLS verifier, bootstrap protocol, or capability grant.
// The adapter must authenticate peer confirmation and bind its channel, both
// public identities, roles and fresh nonces to this transcript before calling
// authenticated_peer_confirmed(). Never feed this method raw network booleans.
class PairingConsent final {
public:
    using Clock = std::chrono::steady_clock;
    using Binding = std::array<std::uint8_t, 32>;
    enum class State {
        awaiting_both, awaiting_local, awaiting_peer, ready_to_persist,
        persisting, paired, denied, cancelled, expired, failed
    };

    PairingConsent(Binding binding, Clock::time_point now,
                   std::chrono::seconds lifetime = std::chrono::seconds{120})
        : binding_(binding), last_now_(now) {
        bool nonzero = false;
        for (auto byte : binding) nonzero |= byte != 0;
        if (!nonzero || lifetime <= std::chrono::seconds::zero() ||
            lifetime > std::chrono::seconds{120} || Clock::time_point::max() - lifetime < now)
            throw std::invalid_argument("invalid pairing consent window");
        deadline_ = now + lifetime;
    }

    [[nodiscard]] State state(Clock::time_point now) {
        const std::lock_guard lock(mutex_);
        refresh(now);
        return state_;
    }

    [[nodiscard]] Binding binding() const { return binding_; }

    // Called ONLY by this endpoint's local UI. Remote messages cannot supply
    // local approval. A rejected/mismatched transcript terminates this attempt.
    bool local_decision(const Binding& binding, bool allow, Clock::time_point now) {
        const std::lock_guard lock(mutex_);
        if (!check(binding, now) || !waiting()) return false;
        if (!allow) { state_ = State::denied; return true; }
        local_ = true;
        advance();
        return true;
    }

    bool authenticated_peer_confirmed(const Binding& binding, Clock::time_point now) {
        const std::lock_guard lock(mutex_);
        if (!check(binding, now) || !waiting()) return false;
        peer_ = true;
        advance();
        return true;
    }

    // One-shot reservation. The adapter stages native identities/records;
    // transport admission is still forbidden until durable completion.
    bool begin_persistence(const Binding& binding, Clock::time_point now) {
        const std::lock_guard lock(mutex_);
        if (!check(binding, now) || state_ != State::ready_to_persist) return false;
        state_ = State::persisting;
        return true;
    }

    bool persistence_finished(const Binding& binding, bool success, Clock::time_point now) {
        const std::lock_guard lock(mutex_);
        if (!check(binding, now) || state_ != State::persisting) return false;
        state_ = success ? State::paired : State::failed;
        return success;
    }

    // Adapter must discard staged records if cancellation/expiry wins the race
    // with persistence; a failed callback cannot activate a paired identity.
    void cancel(Clock::time_point now) {
        const std::lock_guard lock(mutex_);
        refresh(now);
        if (!terminal()) state_ = State::cancelled;
    }

private:
    bool terminal() const {
        return state_ == State::paired || state_ == State::denied ||
               state_ == State::cancelled || state_ == State::expired || state_ == State::failed;
    }
    bool waiting() const {
        return state_ == State::awaiting_both || state_ == State::awaiting_local ||
               state_ == State::awaiting_peer;
    }
    void refresh(Clock::time_point now) {
        if (terminal()) return;
        if (now < last_now_) state_ = State::failed;
        else if (now >= deadline_) state_ = State::expired;
        last_now_ = now;
    }
    bool check(const Binding& binding, Clock::time_point now) {
        refresh(now);
        if (terminal()) return false;
        if (binding != binding_) { state_ = State::failed; return false; }
        return true;
    }
    void advance() {
        state_ = local_ && peer_ ? State::ready_to_persist :
                 local_ ? State::awaiting_peer : State::awaiting_local;
    }
    const Binding binding_;
    Clock::time_point deadline_{};
    Clock::time_point last_now_{};
    State state_{State::awaiting_both};
    bool local_{};
    bool peer_{};
    std::mutex mutex_;
};

} // namespace rwn::core
