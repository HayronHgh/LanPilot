#pragma once

#include "rwn/core/build.hpp"

#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace rwn::core {

struct ArtifactProfile {
    std::vector<std::string> paths;
    std::string platform;
    std::string architecture;
    bool archive_app_bundles{true};
};

struct BuildProfile {
    std::string name;
    std::string node;
    CommandSpec command;
    std::set<std::string, std::less<>> environment_allowlist;
    ArtifactProfile artifacts;
};

struct RemoteWorkspaceConfig {
    std::string workspace_id;
    std::string workspace_name;
    std::string source;
    std::string mirror;
    std::string sync_direction;
    std::vector<std::string> sync_excludes;
    std::map<std::string, BuildProfile, std::less<>> profiles;

    [[nodiscard]] const BuildProfile& profile(std::string_view name) const;
    [[nodiscard]] BuildRequest make_build_request(
        std::string build_id, std::uint64_t pinned_revision,
        std::string_view profile_name,
        std::map<std::string, std::string, std::less<>> environment = {}) const;
};

[[nodiscard]] RemoteWorkspaceConfig parse_remote_workspace_config(
    std::string_view text);
[[nodiscard]] RemoteWorkspaceConfig load_remote_workspace_config(
    const std::filesystem::path& path);
[[nodiscard]] std::vector<std::filesystem::path> discover_build_artifacts(
    const std::filesystem::path& workspace_root,
    const BuildProfile& profile,
    std::size_t maximum_artifacts = 64);

}  // namespace rwn::core
