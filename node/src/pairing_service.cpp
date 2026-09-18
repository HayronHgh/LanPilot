#include "rwn/node/pairing_service.hpp"

#include "rwn/protocol/envelope.hpp"

#include <stdexcept>
#include <utility>

namespace rwn::node {

NodePairingService::NodePairingService(
    rwn::core::PairingChallenge challenge,
    std::string expected_device_id,
    rwn::core::PairingStore& store,
    const std::chrono::hours pairing_record_lifetime)
    : challenge_(std::move(challenge)),
      expected_device_id_(std::move(expected_device_id)),
      store_(store),
      pairing_record_lifetime_(pairing_record_lifetime) {
    if (challenge_.id.empty() || expected_device_id_.empty() ||
        expected_device_id_.size() > 64 ||
        challenge_.six_digit_code.size() != 6 ||
        pairing_record_lifetime_ <= std::chrono::hours::zero()) {
        throw std::invalid_argument("Node pairing service options are invalid");
    }
}

ServedPairingConfirmation NodePairingService::serve_confirmation(
    rwn::transport::ReliableStream& control_stream,
    const rwn::transport::AuthenticatedPeerEvidence& peer,
    const rwn::core::TimePoint now) {
    rwn::transport::validate_authenticated_peer_evidence(peer);
    const auto envelope = rwn::protocol::decode(control_stream.read());
    if (envelope.version != 1 ||
        envelope.type != rwn::protocol::MessageType::pairing_confirm ||
        envelope.correlation_id.empty() || !envelope.unknown_fields.empty()) {
        throw std::invalid_argument(
            "Node pairing envelope is not a canonical confirmation");
    }
    const auto command =
        rwn::protocol::decode_pairing_confirm_command(envelope.payload);
    auto reply = rwn::protocol::PairingConfirmReply{
        .accepted = false,
        .device_id = command.device_id,
        .reason_code = "pairing_denied",
    };
    const auto observed =
        rwn::transport::certificate_sha256_hex(peer.certificate_sha256);
    if (command.device_id == expected_device_id_ &&
        command.certificate_sha256 == observed) {
        try {
            rwn::core::DeviceRegistry registry;
            rwn::core::PairingService pairing(registry);
            auto certificate = pairing.confirm(
                challenge_, command.six_digit_code, command.device_id,
                command.display_name, observed, now,
                pairing_record_lifetime_);
            certificate.serial = "paired-" + observed.substr(0, 32);
            auto device = rwn::core::PairedDevice{
                .id = command.device_id,
                .display_name = command.display_name,
                .fingerprint = observed,
                .certificate = std::move(certificate),
                .revoked = false,
            };
            if (store_.exists()) {
                store_.replace_revoked(device);
            } else {
                store_.create(device);
            }
            reply.accepted = true;
            reply.reason_code = "pairing_completed";
        } catch (const std::invalid_argument&) {
            reply.reason_code = "pairing_denied";
        }
    } else {
        reply.reason_code = "identity_binding_denied";
    }
    control_stream.write(rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::pairing_result,
        .correlation_id = envelope.correlation_id,
        .payload = rwn::protocol::encode_pairing_confirm_reply(reply),
        .unknown_fields = {},
    }));
    return {.command = command, .reply = reply};
}

}  // namespace rwn::node
