#include "rwn/core/session_service.hpp"

#include <stdexcept>
#include <utility>

namespace rwn::core {
namespace {

std::string resolved_actor(const SessionOpenRequest& request) {
    if (!request.peer.certificate.device_id.empty()) {
        return request.peer.certificate.device_id;
    }
    if (!request.capabilities.principal.id.empty()) {
        return request.capabilities.principal.id;
    }
    return "unresolved";
}

}  // namespace

AuthorizationResult SessionService::open(
    SessionOpenRequest request, const Policy& policy, const TimePoint now) {
    if (request.session_id.empty() || request.lease <= std::chrono::minutes::zero()) {
        throw std::invalid_argument("invalid session open request");
    }
    if (sessions_.contains(request.session_id)) {
        throw std::invalid_argument("session id already exists");
    }

    const auto actor = resolved_actor(request);
    const auto workspace = request.capabilities.workspace;
    const auto peer_accepted =
        trust_gate_.verify(request.peer, devices_, now) == MtlsVerification::accepted;
    const auto identity_bound =
        request.capabilities.principal.kind == PrincipalKind::device &&
        request.capabilities.principal.id == request.peer.certificate.device_id;
    if (!peer_accepted || !identity_bound) {
        audit_.append({
            .occurred_at = now,
            .principal_id = actor,
            .device_id = actor,
            .session_id = request.session_id,
            .workspace_id = workspace,
            .reason_code = "mtls_authentication_denied",
            .action = AuditAction::session_authenticated,
            .result = AuditResult::denied,
        });
        throw std::logic_error("mTLS session authentication rejected");
    }

    const auto authorization = authorize(request.capabilities, policy);
    if (!authorization.principal_matched || !authorization.workspace_allowed ||
        authorization.granted.empty()) {
        audit_.append({
            .occurred_at = now,
            .principal_id = actor,
            .device_id = actor,
            .session_id = request.session_id,
            .workspace_id = workspace,
            .reason_code = "capability_authorization_denied",
            .action = AuditAction::session_opened,
            .result = AuditResult::denied,
        });
        throw std::logic_error("session authorization rejected");
    }

    Session session(request.session_id);
    session.authenticate(request.peer.certificate, devices_, now);
    session.open(authorization);
    session.renew(now, request.lease);
    const auto session_id = request.session_id;
    const auto [iterator, inserted] = sessions_.emplace(
        session_id,
        ActiveSession{
            .session = std::move(session),
            .certificate = std::move(request.peer.certificate),
            .principal_id = actor,
            .workspace = workspace,
            .authorization = authorization,
        });
    if (!inserted) {
        throw std::logic_error("session insertion failed");
    }
    append_event(iterator->second, AuditAction::session_authenticated, AuditResult::allowed, now);
    append_event(iterator->second, AuditAction::session_opened, AuditResult::allowed, now);
    return authorization;
}

bool SessionService::permits(
    const std::string_view session_id, const Capability capability,
    const std::string_view workspace, const TimePoint now) {
    auto& record = require_session(session_id);
    const auto certificate_valid =
        devices_.verify(record.certificate, now) == PeerVerification::accepted;
    const auto allowed = certificate_valid && record.session.active_at(now) &&
        workspace == record.workspace && record.authorization.permits(capability);
    if (!certificate_valid && record.session.state() != SessionState::closed) {
        record.session.close();
    }
    return allowed;
}

void SessionService::renew(
    const std::string_view session_id, const TimePoint now,
    const std::chrono::minutes extension) {
    auto& record = require_session(session_id);
    if (devices_.verify(record.certificate, now) != PeerVerification::accepted) {
        record.session.close();
        append_event(record, AuditAction::session_renewed, AuditResult::denied, now);
        throw std::logic_error("session peer is no longer trusted");
    }
    try {
        record.session.renew(now, extension);
        append_event(record, AuditAction::session_renewed, AuditResult::allowed, now);
    } catch (...) {
        append_event(record, AuditAction::session_renewed, AuditResult::denied, now);
        throw;
    }
}

void SessionService::close(const std::string_view session_id, const TimePoint now) {
    auto& record = require_session(session_id);
    record.session.close();
    append_event(record, AuditAction::session_closed, AuditResult::allowed, now);
}

SessionState SessionService::state(const std::string_view session_id) const {
    const auto found = sessions_.find(session_id);
    if (found == sessions_.end()) {
        throw std::out_of_range("unknown session");
    }
    return found->second.session.state();
}

SessionService::ActiveSession& SessionService::require_session(
    const std::string_view session_id) {
    const auto found = sessions_.find(session_id);
    if (found == sessions_.end()) {
        throw std::out_of_range("unknown session");
    }
    return found->second;
}

void SessionService::append_event(
    const ActiveSession& record, const AuditAction action,
    const AuditResult result, const TimePoint now) {
    audit_.append({
        .occurred_at = now,
        .principal_id = record.principal_id,
        .device_id = record.certificate.device_id,
        .session_id = record.session.id(),
        .workspace_id = record.workspace,
        .action = action,
        .result = result,
    });
}

}  // namespace rwn::core
