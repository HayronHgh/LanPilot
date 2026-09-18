#pragma once

#include "rwn/node/control_service.hpp"
#include "rwn/protocol/build_control.hpp"
#include "rwn/transport/transport.hpp"

namespace rwn::node {

class DeploymentWorkerBoundary {
public:
    virtual ~DeploymentWorkerBoundary() = default;
    [[nodiscard]] virtual rwn::protocol::DeployStatusReply execute(
        const rwn::protocol::DeploySubmitCommand& command) = 0;
};

[[nodiscard]] rwn::protocol::DeployStatusReply serve_deployment(
    rwn::transport::ReliableStream& stream,
    NodeControlService& control,
    std::uint64_t current_revision,
    DeploymentWorkerBoundary& worker,
    rwn::core::TimePoint now);

}  // namespace rwn::node
