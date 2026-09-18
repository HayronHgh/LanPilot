#pragma once

#include "rwn/core/workspace_sync.hpp"
#include "rwn/protocol/workspace_control.hpp"
#include "rwn/transport/transport.hpp"

#include <filesystem>
#include <optional>
#include <string_view>

namespace rwn::client {

struct WorkspaceSyncResult {
    rwn::protocol::WorkspaceDiffReply diff;
    std::optional<rwn::protocol::WorkspaceCommitReply> commit;
};

[[nodiscard]] WorkspaceSyncResult sync_workspace(
    rwn::transport::ReliableStream& stream,
    const std::filesystem::path& source_root,
    const rwn::core::WorkspaceManifest& manifest,
    std::string_view session_id);

}  // namespace rwn::client
