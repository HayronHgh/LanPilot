#include "rwn/node/deployment_service.hpp"

#include "rwn/core/content_hash.hpp"
#include "rwn/protocol/envelope.hpp"

#include <stdexcept>

namespace rwn::node {

rwn::protocol::DeployStatusReply serve_deployment(
    rwn::transport::ReliableStream& stream,
    NodeControlService& control,
    const std::uint64_t current_revision,
    DeploymentWorkerBoundary& worker,
    const rwn::core::TimePoint now) {
    const auto envelope = rwn::protocol::decode(stream.read());
    if (envelope.version != 1 ||
        envelope.type != rwn::protocol::MessageType::deploy_submit ||
        envelope.correlation_id.empty() || !envelope.unknown_fields.empty()) {
        throw std::invalid_argument("Node deployment envelope is invalid");
    }
    const auto command = rwn::protocol::decode_deploy_submit_command(
        envelope.payload);
    rwn::protocol::DeployStatusReply reply{
        .accepted = false, .deployment_id = command.deployment_id,
        .artifact_id = command.artifact_id, .artifact_sha256 = {},
        .build_id = {}, .source_revision = 0,
        .status = rwn::protocol::DeploymentWireStatus::rejected,
        .steps = {}, .evidence_sha256 = {},
        .reason_code = "deployment_denied"};
    if (command.revision != current_revision) {
        reply.reason_code = "revision_mismatch";
    } else if (!control.permits_session(
                   command.session_id, rwn::core::Capability::deploy_execute,
                   command.workspace_id, now)) {
        reply.reason_code = "capability_denied";
    } else {
        reply = worker.execute(command);
        rwn::protocol::validate_deploy_status_reply(reply);
        if (!reply.accepted || reply.deployment_id != command.deployment_id ||
            reply.artifact_id != command.artifact_id ||
            reply.source_revision != command.revision ||
            rwn::core::sha256_hex(
                rwn::protocol::encode_deploy_evidence_binding(reply)) !=
                reply.evidence_sha256) {
            throw std::invalid_argument("deployment worker evidence is not bound");
        }
        control.record_deployment(
            command.session_id, command.workspace_id, reply,
            rwn::core::WallClock::now());
    }
    stream.write(rwn::protocol::encode({
        .version = 1, .type = rwn::protocol::MessageType::deploy_status,
        .correlation_id = envelope.correlation_id,
        .payload = rwn::protocol::encode_deploy_status_reply(reply),
        .unknown_fields = {},
    }));
    return reply;
}

}  // namespace rwn::node
