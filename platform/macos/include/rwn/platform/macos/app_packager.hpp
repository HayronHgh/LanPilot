#pragma once

#include "rwn/core/build.hpp"
#include "rwn/core/workspace_scope.hpp"

#include <filesystem>

namespace rwn::platform::macos {

class AppPackager {
public:
    AppPackager(
        const std::filesystem::path& workspace_root,
        rwn::core::CommandExecutor& executor)
        : scope_(workspace_root), executor_(executor) {}

    [[nodiscard]] rwn::core::BuildEvidence package(
        const std::filesystem::path& app_relative_path,
        const std::filesystem::path& archive_relative_path);

private:
    rwn::core::WorkspaceScope scope_;
    rwn::core::CommandExecutor& executor_;
};

}  // namespace rwn::platform::macos
