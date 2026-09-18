#pragma once

#include "rwn/core/identity.hpp"
#include "rwn/core/pairing_store.hpp"
#include "rwn/protocol/session_control.hpp"
#include "rwn/transport/transport.hpp"

#include <chrono>
#include <mutex>
#include <string>

namespace rwn::node {

struct ServedPairingConfirmation {
    rwn::protocol::PairingConfirmCommand command;
    rwn::protocol::PairingConfirmReply reply;
};

class NodePairingService {
public:
    NodePairingService(
        rwn::core::PairingChallenge challenge,
        std::string expected_device_id,
        rwn::core::PairingStore& store,
        std::chrono::hours pairing_record_lifetime);

    [[nodiscard]] ServedPairingConfirmation serve_confirmation(
        rwn::transport::ReliableStream& control_stream,
        const rwn::transport::AuthenticatedPeerEvidence& peer,
        rwn::core::TimePoint now);

private:
    rwn::core::PairingChallenge challenge_;
    std::string expected_device_id_;
    rwn::core::PairingStore& store_;
    std::chrono::hours pairing_record_lifetime_;
    std::mutex confirmation_mutex_;
    unsigned attempts_{};
    bool consumed_{};
};

}  // namespace rwn::node
