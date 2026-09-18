#include "rwn/core/session.hpp"

#include <stdexcept>
#include <utility>

namespace rwn::core {

Session::Session(std::string id) : id_(std::move(id)) {
    if (id_.empty()) {
        throw std::invalid_argument("session id must not be empty");
    }
}

void Session::authenticate(const bool peer_certificate_verified) {
    if (state_ != SessionState::created || !peer_certificate_verified) {
        throw std::logic_error("session authentication rejected");
    }
    state_ = SessionState::authenticated;
}

void Session::authenticate(const PeerCertificate& certificate, const DeviceRegistry& registry, const TimePoint now) {
    authenticate(registry.verify(certificate, now) == PeerVerification::accepted);
}

void Session::open(const AuthorizationResult& authorization) {
    if (state_ != SessionState::authenticated || !authorization.principal_matched ||
        !authorization.workspace_allowed || authorization.granted.empty()) {
        throw std::logic_error("session open rejected");
    }
    state_ = SessionState::open;
}

void Session::renew(const TimePoint now, const std::chrono::minutes extension) {
    if (!active_at(now) || extension <= std::chrono::minutes::zero()) {
        throw std::logic_error("session renewal rejected");
    }
    expires_at_ = now + extension;
}

void Session::close() {
    if (state_ == SessionState::closed) {
        return;
    }
    state_ = SessionState::closed;
    expires_at_.reset();
}

bool Session::active_at(const TimePoint now) const {
    return state_ == SessionState::open && (!expires_at_.has_value() || now < *expires_at_);
}

}  // namespace rwn::core
