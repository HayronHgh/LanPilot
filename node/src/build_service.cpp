#include "rwn/node/build_service.hpp"

#include "rwn/protocol/envelope.hpp"

#include <chrono>
#include <exception>
#include <stdexcept>
#include <utility>

namespace rwn::node {
namespace {

[[nodiscard]] rwn::protocol::BuildWireState state(
    const rwn::core::BuildEvidence& evidence) {
    if (evidence.cancelled) return rwn::protocol::BuildWireState::cancelled;
    if (evidence.exit_code == 0 && !evidence.timed_out)
        return rwn::protocol::BuildWireState::succeeded;
    return rwn::protocol::BuildWireState::failed;
}

void bound_logs(rwn::core::BuildEvidence& evidence) {
    if (evidence.stdout_log.size() > rwn::protocol::max_build_log_bytes) {
        evidence.stdout_log.resize(rwn::protocol::max_build_log_bytes);
        evidence.stdout_truncated = true;
    }
    if (evidence.stderr_log.size() > rwn::protocol::max_build_log_bytes) {
        evidence.stderr_log.resize(rwn::protocol::max_build_log_bytes);
        evidence.stderr_truncated = true;
    }
}

[[nodiscard]] std::string reason(const rwn::core::BuildEvidence& evidence) {
    if (evidence.cancelled) return "build_cancelled";
    if (evidence.timed_out) return "build_timed_out";
    return evidence.exit_code == 0 ? "build_succeeded" : "build_failed";
}

[[nodiscard]] rwn::protocol::BuildStatusReply rejected(
    const std::string& build_id, std::string reason) {
    return {
        .accepted = false,
        .build_id = build_id,
        .state = rwn::protocol::BuildWireState::rejected,
        .exit_code = 0,
        .elapsed_ms = 0,
        .timed_out = false,
        .cancelled = false,
        .stdout_truncated = false,
        .stderr_truncated = false,
        .stdout_log = {},
        .stderr_log = {},
        .evidence_sha256 = {},
        .artifact_ids = {},
        .reason_code = std::move(reason),
    };
}

}  // namespace

NodeBuildService::NodeBuildService(
    rwn::core::RemoteWorkspaceConfig config,
    const std::uint64_t current_revision,
    BuildWorkerBoundary& worker)
    : config_(std::move(config)),
      current_revision_(current_revision),
      worker_(worker) {
    if (current_revision_ == 0 || config_.workspace_id.empty())
        throw std::invalid_argument("Node build service state is invalid");
}

ServedBuild NodeBuildService::serve(
    rwn::transport::ReliableStream& stream,
    NodeControlService& control,
    const rwn::core::TimePoint now) {
    const auto envelope = rwn::protocol::decode(stream.read());
    if (envelope.version != 1 ||
        envelope.type != rwn::protocol::MessageType::build_submit ||
        envelope.correlation_id.empty() || !envelope.unknown_fields.empty()) {
        throw std::invalid_argument("Node build envelope is invalid");
    }
    const auto command =
        rwn::protocol::decode_build_submit_command(envelope.payload);
    auto reply = rejected(command.build_id, "build_denied");
    if (command.workspace_id != config_.workspace_id) {
        reply.reason_code = "workspace_denied";
    } else if (command.revision != current_revision_) {
        reply.reason_code = "revision_mismatch";
    } else if (!control.permits_session(
                   command.session_id, rwn::core::Capability::build_submit,
                   command.workspace_id, now)) {
        reply.reason_code = "capability_denied";
    } else {
        const rwn::core::BuildProfile* profile{};
        rwn::core::BuildRequest request;
        try {
            profile = &config_.profile(command.profile);
            request = config_.make_build_request(
                command.build_id, command.revision, command.profile);
        } catch (const std::exception&) {
            reply.reason_code = "build_request_invalid";
            profile = nullptr;
        }
        if (profile != nullptr) {
            control.record_build(
                command.session_id, command.workspace_id, command.build_id,
                command.revision, rwn::core::AuditAction::build_submitted,
                rwn::core::AuditResult::allowed, "build_submitted", {}, now);
            rwn::core::BuildExecutionResult execution;
            try {
                execution = worker_.execute(request, *profile);
            } catch (const std::exception& error) {
                execution.evidence = {
                    .exit_code = -1,
                    .stdout_log = {},
                    .stderr_log = error.what(),
                    .elapsed = std::chrono::milliseconds::zero(),
                    .timed_out = false,
                    .cancelled = false,
                    .stdout_truncated = false,
                    .stderr_truncated = false,
                };
            }
            auto& evidence = execution.evidence;
            bound_logs(evidence);
            const auto hash = rwn::core::build_evidence_sha256(request, evidence);
            reply = {
                .accepted = true,
                .build_id = command.build_id,
                .state = state(evidence),
                .exit_code = evidence.exit_code,
                .elapsed_ms = static_cast<std::uint64_t>(evidence.elapsed.count()),
                .timed_out = evidence.timed_out,
                .cancelled = evidence.cancelled,
                .stdout_truncated = evidence.stdout_truncated,
                .stderr_truncated = evidence.stderr_truncated,
                .stdout_log = std::move(evidence.stdout_log),
                .stderr_log = std::move(evidence.stderr_log),
                .evidence_sha256 = hash,
                .artifact_ids = std::move(execution.artifact_ids),
                .reason_code = reason(evidence),
            };
            control.record_build(
                command.session_id, command.workspace_id, command.build_id,
                command.revision, rwn::core::AuditAction::build_completed,
                reply.state == rwn::protocol::BuildWireState::succeeded
                    ? rwn::core::AuditResult::allowed
                    : rwn::core::AuditResult::failed,
                reply.reason_code, hash, rwn::core::WallClock::now());
        }
    }
    rwn::protocol::validate_build_status_reply(reply);
    stream.write(rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::build_status,
        .correlation_id = envelope.correlation_id,
        .payload = rwn::protocol::encode_build_status_reply(reply),
        .unknown_fields = {},
    }));
    return {.command = command, .reply = reply};
}

}  // namespace rwn::node
