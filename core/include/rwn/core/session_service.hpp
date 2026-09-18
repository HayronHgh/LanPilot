#pragma once

#include "rwn/core/audit.hpp"
#include "rwn/core/authorization.hpp"
#include "rwn/core/identity.hpp"
#include "rwn/core/session.hpp"

#include <chrono>
#include <map>
#include <string>
#include <string_view>

namespace rwn::core {

struct SessionOpenRequest {
    std::string session_id;
    MtlsPeerEvidence peer;
    CapabilityRequest capabilities;
    std::chrono::minutes lease{std::chrono::minutes{15}};
};

class SessionService {
public:
    SessionService(DeviceRegistry& devices, AuditLog& audit) : devices_(devices), audit_(audit) {}

    [[nodiscard]] AuthorizationResult open(
        SessionOpenRequest request, const Policy& policy, TimePoint now);
    [[nodiscard]] bool permits(
        std::string_view session_id, Capability capability, std::string_view workspace, TimePoint now);
    void renew(std::string_view session_id, TimePoint now, std::chrono::minutes extension);
    void close(std::string_view session_id, TimePoint now);
    [[nodiscard]] SessionState state(std::string_view session_id) const;

private:
    struct ActiveSession {
        Session session;
        PeerCertificate certificate;
        std::string principal_id;
        std::string workspace;
        AuthorizationResult authorization;
    };

    [[nodiscard]] ActiveSession& require_session(std::string_view session_id);
    void append_event(
        const ActiveSession& record, AuditAction action, AuditResult result, TimePoint now);

    DeviceRegistry& devices_;
    AuditLog& audit_;
    MtlsTrustGate trust_gate_;
    std::map<std::string, ActiveSession, std::less<>> sessions_;
};

}  // namespace rwn::core
