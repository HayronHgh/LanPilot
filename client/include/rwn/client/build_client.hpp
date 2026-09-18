#pragma once

#include "rwn/protocol/build_control.hpp"
#include "rwn/transport/transport.hpp"
#include "rwn/core/build.hpp"

namespace rwn::client {

[[nodiscard]] rwn::protocol::BuildStatusReply submit_build(
    rwn::transport::ReliableStream& stream,
    const rwn::protocol::BuildSubmitCommand& command);
[[nodiscard]] rwn::core::BuildEvidence verify_build_evidence(
    const rwn::core::BuildRequest& request,
    const rwn::protocol::BuildStatusReply& reply);

}  // namespace rwn::client
