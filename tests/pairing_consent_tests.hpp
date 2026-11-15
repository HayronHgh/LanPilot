#pragma once
#include "rwn/core/pairing_consent.hpp"
#include "test_support.hpp"

namespace pairing_consent_tests {
using Consent = rwn::core::PairingConsent;
using State = Consent::State;
using namespace std::chrono_literals;
inline Consent::Binding binding() { Consent::Binding value{}; value[0] = 1; return value; }

inline void workflow() {
    const auto now = Consent::Clock::time_point{};
    for (bool local_first : {false, true}) {
        Consent consent(binding(), now);
        RWN_CHECK(consent.state(now) == State::awaiting_both);
        if (local_first) {
            RWN_CHECK(consent.local_decision(binding(), true, now));
            RWN_CHECK(consent.state(now) == State::awaiting_peer);
            RWN_CHECK(consent.authenticated_peer_confirmed(binding(), now));
        } else {
            RWN_CHECK(consent.authenticated_peer_confirmed(binding(), now));
            RWN_CHECK(consent.state(now) == State::awaiting_local);
            RWN_CHECK(consent.local_decision(binding(), true, now));
        }
        RWN_CHECK(consent.state(now) == State::ready_to_persist);
        RWN_CHECK(!consent.persistence_finished(binding(), true, now));
        RWN_CHECK(consent.begin_persistence(binding(), now));
        RWN_CHECK(!consent.begin_persistence(binding(), now));
        RWN_CHECK(consent.state(now) == State::persisting);
        RWN_CHECK(consent.persistence_finished(binding(), true, now));
        RWN_CHECK(consent.state(now + 121s) == State::paired);
        RWN_CHECK(!consent.authenticated_peer_confirmed(binding(), now + 121s));
    }
}

inline void security() {
    const auto now = Consent::Clock::time_point{};
    rwn::test::require_throws<std::invalid_argument>([&] { Consent invalid({}, now); }, "empty binding");
    rwn::test::require_throws<std::invalid_argument>([&] { Consent invalid(binding(), now, 121s); }, "unbounded window");
    for (int failure = 0; failure < 5; ++failure) {
        Consent consent(binding(), now);
        RWN_CHECK(!consent.begin_persistence(binding(), now));
        RWN_CHECK(consent.authenticated_peer_confirmed(binding(), now));
        RWN_CHECK(!consent.begin_persistence(binding(), now)); // peer alone never grants local consent
        if (failure == 0) {
            RWN_CHECK(consent.local_decision(binding(), false, now));
            RWN_CHECK(consent.state(now) == State::denied);
        } else if (failure == 1) {
            consent.cancel(now);
            RWN_CHECK(consent.state(now) == State::cancelled);
        } else if (failure == 2) {
            RWN_CHECK(consent.state(now + 120s) == State::expired);
        } else if (failure == 3) {
            auto other = binding(); other[1] = 1;
            RWN_CHECK(!consent.local_decision(other, true, now));
            RWN_CHECK(consent.state(now) == State::failed);
        } else {
            RWN_CHECK(consent.state(now - 1s) == State::failed);
        }
        RWN_CHECK(!consent.local_decision(binding(), true, now + 121s));
        RWN_CHECK(!consent.begin_persistence(binding(), now + 121s));
        RWN_CHECK(!consent.persistence_finished(binding(), true, now + 121s));
    }
    for (int failure = 0; failure < 3; ++failure) {
        Consent consent(binding(), now);
        RWN_CHECK(consent.local_decision(binding(), true, now));
        RWN_CHECK(consent.authenticated_peer_confirmed(binding(), now));
        RWN_CHECK(consent.begin_persistence(binding(), now));
        if (failure == 0) consent.cancel(now);
        if (failure == 1) RWN_CHECK(consent.state(now + 120s) == State::expired);
        if (failure == 2) RWN_CHECK(!consent.persistence_finished(binding(), false, now));
        RWN_CHECK(!consent.persistence_finished(binding(), true, now + 121s));
        RWN_CHECK(consent.state(now + 121s) != State::paired);
    }
}
} // namespace pairing_consent_tests
