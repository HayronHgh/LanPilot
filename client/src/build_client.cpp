#include "rwn/client/build_client.hpp"

#include "rwn/protocol/envelope.hpp"

#include <stdexcept>

namespace rwn::client {

rwn::protocol::BuildStatusReply submit_build(
    rwn::transport::ReliableStream& stream,
    const rwn::protocol::BuildSubmitCommand& command) {
    rwn::protocol::validate_build_submit_command(command);
    const auto correlation = "build-" + command.build_id;
    stream.write(rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::build_submit,
        .correlation_id = correlation,
        .payload = rwn::protocol::encode_build_submit_command(command),
        .unknown_fields = {},
    }));
    const auto envelope = rwn::protocol::decode(stream.read());
    if (envelope.version != 1 ||
        envelope.type != rwn::protocol::MessageType::build_status ||
        envelope.correlation_id != correlation ||
        !envelope.unknown_fields.empty()) {
        throw std::invalid_argument("build reply envelope is invalid");
    }
    auto reply = rwn::protocol::decode_build_status_reply(envelope.payload);
    if (reply.build_id != command.build_id)
        throw std::invalid_argument("build reply identity is invalid");
    return reply;
}

rwn::core::BuildEvidence verify_build_evidence(
    const rwn::core::BuildRequest& request,
    const rwn::protocol::BuildStatusReply& reply) {
    rwn::protocol::validate_build_status_reply(reply);
    if (!reply.accepted || reply.build_id != request.id) {
        throw std::invalid_argument("build evidence identity is invalid");
    }
    rwn::core::BuildEvidence evidence{
        .exit_code = reply.exit_code,
        .stdout_log = reply.stdout_log,
        .stderr_log = reply.stderr_log,
        .elapsed = std::chrono::milliseconds{reply.elapsed_ms},
        .timed_out = reply.timed_out,
        .cancelled = reply.cancelled,
        .stdout_truncated = reply.stdout_truncated,
        .stderr_truncated = reply.stderr_truncated,
    };
    if (rwn::core::build_evidence_sha256(request, evidence) !=
        reply.evidence_sha256) {
        throw std::invalid_argument(
            "build evidence does not bind the fixed request");
    }
    return evidence;
}

}  // namespace rwn::client
