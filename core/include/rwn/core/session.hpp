#pragma once

#include "rwn/core/authorization.hpp"
#include "rwn/core/identity.hpp"

#include <chrono>
#include <optional>
#include <string>

namespace rwn::core {

enum class SessionState { created, authenticated, open, closed };

class Session {
public:
    explicit Session(std::string id);

    void authenticate(bool peer_certificate_verified);
    void authenticate(const PeerCertificate& certificate, const DeviceRegistry& registry, TimePoint now);
    void open(const AuthorizationResult& authorization);
    void renew(TimePoint now, std::chrono::minutes extension);
    void close();

    [[nodiscard]] const std::string& id() const { return id_; }
    [[nodiscard]] SessionState state() const { return state_; }
    [[nodiscard]] bool active_at(TimePoint now) const;
    [[nodiscard]] const std::optional<TimePoint>& expires_at() const { return expires_at_; }

private:
    std::string id_;
    SessionState state_{SessionState::created};
    std::optional<TimePoint> expires_at_;
};

}  // namespace rwn::core
