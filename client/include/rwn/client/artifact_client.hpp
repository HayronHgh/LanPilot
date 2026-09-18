#pragma once

#include "rwn/core/file_transfer.hpp"
#include "rwn/protocol/build_control.hpp"
#include "rwn/transport/transport.hpp"

#include <filesystem>

namespace rwn::client {

struct ArtifactDownloadResult {
    rwn::protocol::ArtifactManifestReply manifest;
    std::filesystem::path destination;
};

[[nodiscard]] ArtifactDownloadResult download_artifact(
    rwn::transport::ReliableStream& stream,
    const rwn::protocol::ArtifactFetchCommand& command,
    const std::filesystem::path& destination_root,
    const std::filesystem::path& destination_relative_path,
    rwn::core::DurableFileSystem& filesystem);

}  // namespace rwn::client
