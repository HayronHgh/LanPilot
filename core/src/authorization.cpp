#include "rwn/core/authorization.hpp"

#include <utility>

namespace rwn::core {

std::string_view to_string(const Capability capability) {
    switch (capability) {
        case Capability::desktop_view: return "desktop.view";
        case Capability::desktop_control: return "desktop.control";
        case Capability::clipboard_read: return "clipboard.read";
        case Capability::clipboard_write: return "clipboard.write";
        case Capability::workspace_read: return "workspace.read";
        case Capability::workspace_write: return "workspace.write";
        case Capability::workspace_sync: return "workspace.sync";
        case Capability::terminal_open: return "terminal.open";
        case Capability::command_exec: return "command.exec";
        case Capability::build_submit: return "build.submit";
        case Capability::test_run: return "test.run";
        case Capability::artifact_read: return "artifact.read";
        case Capability::artifact_download: return "artifact.download";
        case Capability::deploy_execute: return "deploy.execute";
        case Capability::agent_run: return "agent.run";
        case Capability::git_status: return "git.status";
        case Capability::git_diff: return "git.diff";
        case Capability::system_admin: return "system.admin";
    }
    return "unknown";
}

std::optional<Capability> capability_from_string(const std::string_view name) {
    constexpr Capability capabilities[]{
        Capability::desktop_view, Capability::desktop_control,
        Capability::clipboard_read, Capability::clipboard_write,
        Capability::workspace_read, Capability::workspace_write,
        Capability::workspace_sync, Capability::terminal_open,
        Capability::command_exec, Capability::build_submit,
        Capability::test_run, Capability::artifact_read,
        Capability::artifact_download, Capability::deploy_execute,
        Capability::agent_run, Capability::git_status,
        Capability::git_diff, Capability::system_admin,
    };
    for (const auto capability : capabilities) {
        if (to_string(capability) == name) {
            return capability;
        }
    }
    return std::nullopt;
}

bool AuthorizationResult::permits(const Capability capability) const {
    return principal_matched && workspace_allowed && granted.contains(capability);
}

AuthorizationResult authorize(const CapabilityRequest& request, const Policy& policy) {
    AuthorizationResult result;
    result.principal_matched = !request.principal.id.empty() && request.principal.id == policy.principal_id;
    result.workspace_allowed = !request.workspace.empty() && policy.workspaces.contains(request.workspace);

    for (const auto capability : request.requested) {
        if (result.principal_matched && result.workspace_allowed && policy.allowed.contains(capability)) {
            result.granted.insert(capability);
        } else {
            result.denied.insert(capability);
        }
    }
    return result;
}

Policy default_agent_policy(std::string principal_id, std::string workspace) {
    return Policy{
        .principal_id = std::move(principal_id),
        .workspaces = {std::move(workspace)},
        .allowed = {
            Capability::workspace_read,
            Capability::workspace_write,
            Capability::build_submit,
            Capability::test_run,
            Capability::artifact_read,
            Capability::git_status,
            Capability::git_diff,
        },
    };
}

}  // namespace rwn::core
