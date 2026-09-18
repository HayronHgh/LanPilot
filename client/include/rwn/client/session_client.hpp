#pragma once

#include "rwn/protocol/session_control.hpp"
#include "rwn/transport/transport.hpp"

namespace rwn::client {

[[nodiscard]] rwn::protocol::PairingConfirmReply confirm_remote_pairing(
    rwn::transport::ReliableStream& control_stream,
    const rwn::protocol::PairingConfirmCommand& command);

[[nodiscard]] rwn::protocol::SessionOpenReply open_remote_session(
    rwn::transport::ReliableStream& control_stream,
    const rwn::protocol::SessionOpenCommand& command);

}  // namespace rwn::client
