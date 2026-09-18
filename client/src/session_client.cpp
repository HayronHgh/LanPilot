#include "rwn/client/session_client.hpp"

#include "rwn/protocol/envelope.hpp"

#include <stdexcept>

namespace rwn::client {

rwn::protocol::PairingConfirmReply confirm_remote_pairing(
    rwn::transport::ReliableStream& control_stream,
    const rwn::protocol::PairingConfirmCommand& command) {
    rwn::protocol::validate_pairing_confirm_command(command);
    const auto correlation_id = "pairing-" + command.device_id;
    control_stream.write(rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::pairing_confirm,
        .correlation_id = correlation_id,
        .payload = rwn::protocol::encode_pairing_confirm_command(command),
        .unknown_fields = {},
    }));
    const auto reply_envelope = rwn::protocol::decode(control_stream.read());
    if (reply_envelope.version != 1 ||
        reply_envelope.type != rwn::protocol::MessageType::pairing_result ||
        reply_envelope.correlation_id != correlation_id ||
        !reply_envelope.unknown_fields.empty()) {
        throw std::invalid_argument("pairing reply envelope is invalid");
    }
    return rwn::protocol::decode_pairing_confirm_reply(
        reply_envelope.payload);
}

rwn::protocol::SessionOpenReply open_remote_session(
    rwn::transport::ReliableStream& control_stream,
    const rwn::protocol::SessionOpenCommand& command) {
    rwn::protocol::validate_session_open_command(command);
    const auto correlation_id = "session-" + command.session_id;
    control_stream.write(rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::authenticate,
        .correlation_id = correlation_id,
        .payload = rwn::protocol::encode_session_open_command(command),
        .unknown_fields = {},
    }));
    const auto reply_envelope = rwn::protocol::decode(control_stream.read());
    if (reply_envelope.version != 1 ||
        reply_envelope.type != rwn::protocol::MessageType::session_open ||
        reply_envelope.correlation_id != correlation_id ||
        !reply_envelope.unknown_fields.empty()) {
        throw std::invalid_argument("session reply envelope is invalid");
    }
    return rwn::protocol::decode_session_open_reply(reply_envelope.payload);
}

}  // namespace rwn::client
