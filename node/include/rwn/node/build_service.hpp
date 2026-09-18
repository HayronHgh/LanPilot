#pragma once

#include "rwn/core/build.hpp"
#include "rwn/core/build_config.hpp"
#include "rwn/node/control_service.hpp"
#include "rwn/protocol/build_control.hpp"
#include "rwn/transport/transport.hpp"

namespace rwn::node {

class BuildWorkerBoundary {
public:
    virtual ~BuildWorkerBoundary() = default;
    [[nodiscard]] virtual rwn::core::BuildExecutionResult execute(
        const rwn::core::BuildRequest& request,
        const rwn::core::BuildProfile& profile) = 0;
};

struct ServedBuild {
    rwn::protocol::BuildSubmitCommand command;
    rwn::protocol::BuildStatusReply reply;
};

class NodeBuildService {
public:
    NodeBuildService(
        rwn::core::RemoteWorkspaceConfig config,
        std::uint64_t current_revision,
        BuildWorkerBoundary& worker);

    [[nodiscard]] ServedBuild serve(
        rwn::transport::ReliableStream& stream,
        NodeControlService& control,
        rwn::core::TimePoint now);

private:
    rwn::core::RemoteWorkspaceConfig config_;
    std::uint64_t current_revision_{};
    BuildWorkerBoundary& worker_;
};

}  // namespace rwn::node
