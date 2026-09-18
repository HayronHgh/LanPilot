#pragma once

#include "rwn/core/ignore_rules.hpp"
#include "rwn/core/workspace_sync.hpp"

#include <filesystem>
#include <set>
#include <string>
#include <string_view>

namespace rwn::core {

struct ManifestBuildOptions {
    std::string workspace_id;
    std::uint64_t revision{};
    IgnoreRules ignore_rules;
    std::set<std::string, std::less<>> executable_paths;
};

[[nodiscard]] WorkspaceManifest build_workspace_manifest(
    const std::filesystem::path& root, ManifestBuildOptions options);
void reject_case_collisions(const WorkspaceManifest& manifest);
[[nodiscard]] std::set<std::string, std::less<>> parse_git_stage_executable_paths(
    std::string_view git_ls_files_stage_output);

}  // namespace rwn::core
