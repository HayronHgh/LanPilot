#include "rwn/client/deployment_client.hpp"

#include "rwn/core/content_hash.hpp"
#include "rwn/protocol/envelope.hpp"

#include <stdexcept>

namespace rwn::client {

rwn::protocol::DeployStatusReply submit_deployment(
    rwn::transport::ReliableStream& stream,
    const rwn::protocol::DeploySubmitCommand& command) {
    rwn::protocol::validate_deploy_submit_command(command);
    const auto correlation = "deploy-" + command.deployment_id;
    stream.write(rwn::protocol::encode({
        .version = 1, .type = rwn::protocol::MessageType::deploy_submit,
        .correlation_id = correlation,
        .payload = rwn::protocol::encode_deploy_submit_command(command),
        .unknown_fields = {},
    }));
    const auto envelope = rwn::protocol::decode(stream.read());
    if (envelope.version != 1 ||
        envelope.type != rwn::protocol::MessageType::deploy_status ||
        envelope.correlation_id != correlation ||
        !envelope.unknown_fields.empty()) {
        throw std::invalid_argument("deployment reply envelope is invalid");
    }
    auto reply = rwn::protocol::decode_deploy_status_reply(envelope.payload);
    if (reply.deployment_id != command.deployment_id ||
        reply.artifact_id != command.artifact_id) {
        throw std::invalid_argument("deployment reply identity is invalid");
    }
    if (reply.accepted &&
        (reply.source_revision != command.revision ||
         rwn::core::sha256_hex(
             rwn::protocol::encode_deploy_evidence_binding(reply)) !=
             reply.evidence_sha256)) {
        throw std::invalid_argument("deployment runtime evidence is invalid");
    }
    return reply;
}

}  // namespace rwn::client
