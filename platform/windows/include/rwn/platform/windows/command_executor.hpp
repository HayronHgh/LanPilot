#pragma once

#include "rwn/core/build.hpp"
#include "rwn/core/workspace_scope.hpp"

#include <filesystem>

namespace rwn::platform::windows {

class WindowsCommandExecutor final : public rwn::core::CommandExecutor {
public:
    explicit WindowsCommandExecutor(const std::filesystem::path& workspace_root)
        : scope_(workspace_root) {}

    [[nodiscard]] rwn::core::BuildEvidence execute(
        const rwn::core::CommandSpec& command,
        rwn::core::CancellationToken stop_token = {}) override;

private:
    rwn::core::WorkspaceScope scope_;
};

}  // namespace rwn::platform::windows
