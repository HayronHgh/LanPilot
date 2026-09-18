#include "rwn/node/control_service.hpp"

#include "rwn/protocol/envelope.hpp"

#include <algorithm>
#include <ranges>
#include <set>
#include <stdexcept>
#include <utility>
#include <vector>

namespace rwn::node {
namespace {

[[nodiscard]] std::vector<std::string> capability_names(
    const std::set<rwn::core::Capability>& capabilities) {
    std::vector<std::string> result;
    result.reserve(capabilities.size());
    for (const auto capability : capabilities) {
        result.emplace_back(rwn::core::to_string(capability));
    }
    return result;
}

[[nodiscard]] std::set<rwn::core::Capability> requested_capabilities(
    const std::vector<std::string>& names) {
    std::set<rwn::core::Capability> result;
    for (const auto& name : names) {
        const auto capability = rwn::core::capability_from_string(name);
        if (!capability.has_value() || !result.insert(*capability).second) {
            throw std::invalid_argument(
                "session request contains an unknown or duplicate capability");
        }
    }
    return result;
}

}  // namespace

NodeControlService::NodeControlService(
    rwn::core::Policy policy,
    const std::size_t maximum_active_sessions,
    rwn::core::AuditSink* const audit_sink)
    : policy_(std::move(policy)),
      maximum_active_sessions_(maximum_active_sessions),
      audit_({}, audit_sink),
      sessions_(devices_, audit_) {
    if (policy_.principal_id.empty() || policy_.workspaces.empty() ||
        policy_.allowed.empty() || maximum_active_sessions_ == 0 ||
        maximum_active_sessions_ > 1024) {
        throw std::invalid_argument("node control service options are invalid");
    }
}

void NodeControlService::pair_device(rwn::core::PairedDevice device) {
    if (device.id != policy_.principal_id) {
        throw std::invalid_argument(
            "paired device must match the configured service principal");
    }
    devices_.pair(std::move(device));
}

rwn::protocol::SessionOpenReply NodeControlService::open_session(
    const rwn::protocol::SessionOpenCommand& command,
    rwn::core::MtlsPeerEvidence peer,
    const rwn::core::TimePoint now) {
    rwn::protocol::validate_session_open_command(command);
    const auto requested = requested_capabilities(
        command.requested_capabilities);
    prune_expired(now);
    if (active_.contains(command.session_id)) {
        record_session_denial(command, "session_duplicate", now);
        return {
            .accepted = false,
            .granted_capabilities = {},
            .denied_capabilities = command.requested_capabilities,
            .reason_code = "session_duplicate",
        };
    }
    if (active_.size() >= maximum_active_sessions_) {
        record_session_denial(command, "session_capacity", now);
        return {
            .accepted = false,
            .granted_capabilities = {},
            .denied_capabilities = command.requested_capabilities,
            .reason_code = "session_capacity",
        };
    }
    if (command.device_id != peer.certificate.device_id) {
        record_session_denial(command, "identity_binding_denied", now);
        return {
            .accepted = false,
            .granted_capabilities = {},
            .denied_capabilities = command.requested_capabilities,
            .reason_code = "identity_binding_denied",
        };
    }
    try {
        const auto authorization = sessions_.open(
            {
                .session_id = command.session_id,
                .peer = std::move(peer),
                .capabilities = {
                    .principal = {
                        .id = command.device_id,
                        .kind = rwn::core::PrincipalKind::device,
                    },
                    .workspace = command.workspace_id,
                    .requested = requested,
                },
                .lease = std::chrono::minutes{command.lease_minutes},
            },
            policy_, now);
        const auto [_, inserted] = active_.emplace(
            command.session_id,
            ActiveSession{
                .workspace_id = command.workspace_id,
                .granted = authorization.granted,
                .expires_at = now +
                    std::chrono::minutes{command.lease_minutes},
            });
        if (!inserted) {
            throw std::logic_error("node active-session insertion failed");
        }
        return {
            .accepted = true,
            .granted_capabilities = capability_names(authorization.granted),
            .denied_capabilities = capability_names(authorization.denied),
            .reason_code = "session_opened",
        };
    } catch (const std::logic_error&) {
        return {
            .accepted = false,
            .granted_capabilities = {},
            .denied_capabilities = command.requested_capabilities,
            .reason_code = "session_denied",
        };
    }
}

rwn::protocol::SessionOpenReply NodeControlService::open_session(
    const rwn::protocol::SessionOpenCommand& command,
    const rwn::transport::AuthenticatedPeerEvidence& peer,
    const rwn::core::TimePoint now) {
    return open_session(command, bind_peer(command.device_id, peer), now);
}

ServedSessionOpen NodeControlService::serve_session_open(
    rwn::transport::ReliableStream& control_stream,
    const rwn::transport::AuthenticatedPeerEvidence& peer,
    const rwn::core::TimePoint now) {
    try {
        const auto envelope = rwn::protocol::decode(control_stream.read());
        if (envelope.version != 1 ||
            envelope.type != rwn::protocol::MessageType::authenticate ||
            envelope.correlation_id.empty() ||
            !envelope.unknown_fields.empty()) {
            throw std::invalid_argument(
                "node control envelope is not a canonical authentication request");
        }
        const auto command =
            rwn::protocol::decode_session_open_command(envelope.payload);
        const auto reply = open_session(command, peer, now);
        control_stream.write(rwn::protocol::encode({
            .version = 1,
            .type = rwn::protocol::MessageType::session_open,
            .correlation_id = envelope.correlation_id,
            .payload = rwn::protocol::encode_session_open_reply(reply),
            .unknown_fields = {},
        }));
        return {.command = command, .reply = reply};
    } catch (...) {
        record_protocol_denial("protocol_invalid", now);
        throw;
    }
}

bool NodeControlService::permits_session(
    const std::string_view session_id,
    const rwn::core::Capability capability,
    const std::string_view workspace_id,
    const rwn::core::TimePoint now) {
    prune_expired(now);
    if (!active_.contains(session_id)) return false;
    return sessions_.permits(session_id, capability, workspace_id, now);
}

void NodeControlService::record_workspace_sync(
    const std::string_view session_id,
    const std::string_view workspace_id,
    const std::uint64_t revision,
    const rwn::core::AuditAction action,
    const rwn::core::AuditResult result,
    std::string reason_code,
    const rwn::core::TimePoint now) {
    if (action != rwn::core::AuditAction::workspace_sync_started &&
        action != rwn::core::AuditAction::workspace_sync_committed &&
        action != rwn::core::AuditAction::workspace_sync_failed) {
        throw std::invalid_argument("workspace sync audit action is invalid");
    }
    const auto active = active_.find(session_id);
    if (active == active_.end() || active->second.workspace_id != workspace_id) {
        throw std::invalid_argument("workspace sync audit session is invalid");
    }
    audit_.append({
        .occurred_at = now,
        .principal_id = policy_.principal_id,
        .device_id = policy_.principal_id,
        .session_id = std::string(session_id),
        .workspace_id = std::string(workspace_id),
        .source_revision = revision,
        .reason_code = std::move(reason_code),
        .action = action,
        .result = result,
    });
}

void NodeControlService::record_build(
    const std::string_view session_id,
    const std::string_view workspace_id,
    const std::string_view build_id,
    const std::uint64_t revision,
    const rwn::core::AuditAction action,
    const rwn::core::AuditResult result,
    std::string reason_code,
    std::string evidence_id,
    const rwn::core::TimePoint now) {
    if (action != rwn::core::AuditAction::build_submitted &&
        action != rwn::core::AuditAction::build_completed) {
        throw std::invalid_argument("build audit action is invalid");
    }
    const auto active = active_.find(session_id);
    if (active == active_.end() || active->second.workspace_id != workspace_id) {
        throw std::invalid_argument("build audit session is invalid");
    }
    audit_.append({
        .occurred_at = now,
        .principal_id = policy_.principal_id,
        .device_id = policy_.principal_id,
        .session_id = std::string(session_id),
        .workspace_id = std::string(workspace_id),
        .build_id = std::string(build_id),
        .source_revision = revision,
        .process_role = "build_worker",
        .reason_code = std::move(reason_code),
        .evidence_id = std::move(evidence_id),
        .action = action,
        .result = result,
    });
}

void NodeControlService::record_artifact(
    const std::string_view session_id,
    const std::string_view workspace_id,
    const std::string_view build_id,
    const std::string_view artifact_id,
    std::string artifact_sha256,
    const std::uint64_t revision,
    const rwn::core::AuditAction action,
    const rwn::core::AuditResult result,
    std::string reason_code,
    const rwn::core::TimePoint now) {
    if (action != rwn::core::AuditAction::artifact_published &&
        action != rwn::core::AuditAction::artifact_downloaded) {
        throw std::invalid_argument("artifact audit action is invalid");
    }
    const auto active = active_.find(session_id);
    if (active == active_.end() || active->second.workspace_id != workspace_id) {
        throw std::invalid_argument("artifact audit session is invalid");
    }
    audit_.append({
        .occurred_at = now,
        .principal_id = policy_.principal_id,
        .device_id = policy_.principal_id,
        .session_id = std::string(session_id),
        .workspace_id = std::string(workspace_id),
        .build_id = std::string(build_id),
        .artifact_id = std::string(artifact_id),
        .artifact_sha256 = std::move(artifact_sha256),
        .source_revision = revision,
        .process_role = "build_worker",
        .reason_code = std::move(reason_code),
        .action = action,
        .result = result,
    });
}

void NodeControlService::record_deployment(
    const std::string_view session_id,
    const std::string_view workspace_id,
    const rwn::protocol::DeployStatusReply& reply,
    const rwn::core::TimePoint now) {
    rwn::protocol::validate_deploy_status_reply(reply);
    if (!reply.accepted)
        throw std::invalid_argument("deployment audit requires runtime evidence");
    const auto active = active_.find(session_id);
    if (active == active_.end() || active->second.workspace_id != workspace_id)
        throw std::invalid_argument("deployment audit session is invalid");
    auto action = rwn::core::AuditAction::deployment_failed;
    auto result = rwn::core::AuditResult::failed;
    if (reply.status == rwn::protocol::DeploymentWireStatus::active) {
        action = rwn::core::AuditAction::deployment_active;
        result = rwn::core::AuditResult::allowed;
    } else if (reply.status ==
               rwn::protocol::DeploymentWireStatus::rolled_back) {
        action = rwn::core::AuditAction::deployment_rolled_back;
    }
    audit_.append({
        .occurred_at = now,
        .principal_id = policy_.principal_id,
        .device_id = policy_.principal_id,
        .session_id = std::string(session_id),
        .workspace_id = std::string(workspace_id),
        .build_id = reply.build_id,
        .artifact_id = reply.artifact_id,
        .artifact_sha256 = reply.artifact_sha256,
        .source_revision = reply.source_revision,
        .deployment_id = reply.deployment_id,
        .process_role = "privileged_broker",
        .reason_code = reply.reason_code,
        .evidence_id = reply.evidence_sha256,
        .action = action,
        .result = result,
    });
}

rwn::core::MtlsPeerEvidence NodeControlService::bind_peer(
    const std::string_view claimed_device_id,
    const rwn::transport::AuthenticatedPeerEvidence& peer) const {
    rwn::transport::validate_authenticated_peer_evidence(peer);
    const auto fingerprint =
        rwn::transport::certificate_sha256_hex(peer.certificate_sha256);
    const auto* paired = devices_.find(claimed_device_id);
    auto certificate = paired == nullptr
        ? rwn::core::PeerCertificate{
              .device_id = std::string(claimed_device_id),
              .fingerprint = fingerprint,
              .serial = "unresolved",
          }
        : paired->certificate;
    certificate.fingerprint = fingerprint;
    return {
        .tls_1_3_negotiated = peer.tls_1_3_negotiated,
        .client_certificate_present = true,
        .certificate_chain_valid = peer.certificate_chain_valid,
        .revocation_checked = peer.revocation_checked,
        .certificate = std::move(certificate),
    };
}

void NodeControlService::close_session(
    const std::string_view session_id, const rwn::core::TimePoint now) {
    sessions_.close(session_id, now);
    active_.erase(std::string(session_id));
}

NodeServiceHealth NodeControlService::health(
    const std::string_view session_id, const rwn::core::TimePoint now) {
    prune_expired(now);
    const auto found = active_.find(session_id);
    if (found == active_.end()) {
        throw std::logic_error("node health requires an active session");
    }
    const auto permitted = std::ranges::any_of(
        found->second.granted, [&](const auto capability) {
            return sessions_.permits(
                session_id, capability, found->second.workspace_id, now);
        });
    if (!permitted) {
        active_.erase(found);
        throw std::logic_error("node health session is no longer authorized");
    }
    return {
        .ready = true,
        .active_sessions = active_.size(),
        .audit_events = audit_.events().size(),
    };
}

void NodeControlService::prune_expired(const rwn::core::TimePoint now) {
    for (auto current = active_.begin(); current != active_.end();) {
        if (now < current->second.expires_at) {
            ++current;
            continue;
        }
        try {
            sessions_.close(current->first, now);
        } catch (...) {
        }
        current = active_.erase(current);
    }
}

void NodeControlService::record_session_denial(
    const rwn::protocol::SessionOpenCommand& command,
    std::string reason_code, const rwn::core::TimePoint now) {
    audit_.append({
        .occurred_at = now,
        .principal_id = command.device_id,
        .device_id = command.device_id,
        .session_id = command.session_id,
        .workspace_id = command.workspace_id,
        .reason_code = std::move(reason_code),
        .action = rwn::core::AuditAction::session_opened,
        .result = rwn::core::AuditResult::denied,
    });
}

void NodeControlService::record_protocol_denial(
    std::string reason_code, const rwn::core::TimePoint now) {
    audit_.append({
        .occurred_at = now,
        .principal_id = "unresolved",
        .device_id = "unresolved",
        .session_id = "unresolved",
        .workspace_id = "unresolved",
        .reason_code = std::move(reason_code),
        .action = rwn::core::AuditAction::session_opened,
        .result = rwn::core::AuditResult::denied,
    });
}

}  // namespace rwn::node
