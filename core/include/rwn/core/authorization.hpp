#pragma once

#include <set>
#include <optional>
#include <string>
#include <string_view>

namespace rwn::core {

enum class PrincipalKind { human, device, agent };

struct Principal {
    std::string id{};
    PrincipalKind kind{PrincipalKind::device};
};

enum class Capability {
    desktop_view,
    desktop_control,
    clipboard_read,
    clipboard_write,
    workspace_read,
    workspace_write,
    workspace_sync,
    terminal_open,
    command_exec,
    build_submit,
    test_run,
    artifact_read,
    artifact_download,
    deploy_execute,
    agent_run,
    git_status,
    git_diff,
    system_admin,
};

[[nodiscard]] std::string_view to_string(Capability capability);
[[nodiscard]] std::optional<Capability> capability_from_string(std::string_view name);

struct CapabilityRequest {
    Principal principal{};
    std::string workspace{};
    std::set<Capability> requested{};
};

struct Policy {
    std::string principal_id{};
    std::set<std::string> workspaces{};
    std::set<Capability> allowed{};
};

struct AuthorizationResult {
    bool principal_matched{};
    bool workspace_allowed{};
    std::set<Capability> granted{};
    std::set<Capability> denied{};

    [[nodiscard]] bool permits(Capability capability) const;
};

[[nodiscard]] AuthorizationResult authorize(const CapabilityRequest& request, const Policy& policy);
[[nodiscard]] Policy default_agent_policy(std::string principal_id, std::string workspace);

}  // namespace rwn::core
