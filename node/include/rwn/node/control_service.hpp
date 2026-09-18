#pragma once

#include "rwn/core/audit.hpp"
#include "rwn/core/identity.hpp"
#include "rwn/core/session_service.hpp"
#include "rwn/protocol/session_control.hpp"
#include "rwn/protocol/build_control.hpp"
#include "rwn/transport/transport.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <string_view>

namespace rwn::node {

struct NodeServiceHealth {
    bool ready{};
    std::size_t active_sessions{};
    std::size_t audit_events{};
};

struct ServedSessionOpen {
    rwn::protocol::SessionOpenCommand command;
    rwn::protocol::SessionOpenReply reply;
};

class NodeControlService {
public:
    explicit NodeControlService(
        rwn::core::Policy policy,
        std::size_t maximum_active_sessions = 64,
        rwn::core::AuditSink* audit_sink = nullptr);

    void pair_device(rwn::core::PairedDevice device);
    [[nodiscard]] rwn::protocol::SessionOpenReply open_session(
        const rwn::protocol::SessionOpenCommand& command,
        rwn::core::MtlsPeerEvidence peer,
        rwn::core::TimePoint now);
    [[nodiscard]] rwn::protocol::SessionOpenReply open_session(
        const rwn::protocol::SessionOpenCommand& command,
        const rwn::transport::AuthenticatedPeerEvidence& peer,
        rwn::core::TimePoint now);
    [[nodiscard]] ServedSessionOpen serve_session_open(
        rwn::transport::ReliableStream& control_stream,
        const rwn::transport::AuthenticatedPeerEvidence& peer,
        rwn::core::TimePoint now);
    [[nodiscard]] bool permits_session(
        std::string_view session_id,
        rwn::core::Capability capability,
        std::string_view workspace_id,
        rwn::core::TimePoint now);
    void record_workspace_sync(
        std::string_view session_id,
        std::string_view workspace_id,
        std::uint64_t revision,
        rwn::core::AuditAction action,
        rwn::core::AuditResult result,
        std::string reason_code,
        rwn::core::TimePoint now);
    void record_build(
        std::string_view session_id,
        std::string_view workspace_id,
        std::string_view build_id,
        std::uint64_t revision,
        rwn::core::AuditAction action,
        rwn::core::AuditResult result,
        std::string reason_code,
        std::string evidence_id,
        rwn::core::TimePoint now);
    void record_artifact(
        std::string_view session_id,
        std::string_view workspace_id,
        std::string_view build_id,
        std::string_view artifact_id,
        std::string artifact_sha256,
        std::uint64_t revision,
        rwn::core::AuditAction action,
        rwn::core::AuditResult result,
        std::string reason_code,
        rwn::core::TimePoint now);
    void record_deployment(
        std::string_view session_id,
        std::string_view workspace_id,
        const rwn::protocol::DeployStatusReply& reply,
        rwn::core::TimePoint now);
    void close_session(
        std::string_view session_id, rwn::core::TimePoint now);
    [[nodiscard]] NodeServiceHealth health(
        std::string_view session_id, rwn::core::TimePoint now);

    [[nodiscard]] const rwn::core::AuditLog& audit() const noexcept {
        return audit_;
    }

private:
    struct ActiveSession {
        std::string workspace_id;
        std::set<rwn::core::Capability> granted;
        rwn::core::TimePoint expires_at{};
    };

    void prune_expired(rwn::core::TimePoint now);
    void record_session_denial(
        const rwn::protocol::SessionOpenCommand& command,
        std::string reason_code, rwn::core::TimePoint now);
    void record_protocol_denial(
        std::string reason_code, rwn::core::TimePoint now);
    [[nodiscard]] rwn::core::MtlsPeerEvidence bind_peer(
        std::string_view claimed_device_id,
        const rwn::transport::AuthenticatedPeerEvidence& peer) const;

    rwn::core::Policy policy_;
    std::size_t maximum_active_sessions_{};
    rwn::core::DeviceRegistry devices_;
    rwn::core::AuditLog audit_;
    rwn::core::SessionService sessions_;
    std::map<std::string, ActiveSession, std::less<>> active_;
};

}  // namespace rwn::node
