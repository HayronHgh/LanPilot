#pragma once

#include "rwn/protocol/build_control.hpp"
#include "rwn/transport/transport.hpp"

namespace rwn::client {

[[nodiscard]] rwn::protocol::DeployStatusReply submit_deployment(
    rwn::transport::ReliableStream& stream,
    const rwn::protocol::DeploySubmitCommand& command);

}  // namespace rwn::client
