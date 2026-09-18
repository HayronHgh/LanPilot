#pragma once

#include "rwn/node/control_service.hpp"
#include "rwn/protocol/build_control.hpp"
#include "rwn/transport/transport.hpp"

namespace rwn::node {

class ArtifactSourceBoundary {
public:
    virtual ~ArtifactSourceBoundary() = default;
    [[nodiscard]] virtual rwn::protocol::ArtifactManifestReply prepare(
        const rwn::protocol::ArtifactFetchCommand& command) = 0;
    virtual void request_chunks(
        const rwn::protocol::ArtifactResumeCommand& command) = 0;
    [[nodiscard]] virtual rwn::protocol::ArtifactChunkCommand read_chunk() = 0;
};

[[nodiscard]] rwn::protocol::ArtifactManifestReply serve_artifact_download(
    rwn::transport::ReliableStream& stream,
    NodeControlService& control,
    std::uint64_t current_revision,
    ArtifactSourceBoundary& source,
    rwn::core::TimePoint now);

}  // namespace rwn::node
