#include "rwn/core/process_isolation.hpp"

#include <stdexcept>
#include <utility>

namespace rwn::core {

std::string_view to_string(const ProcessRole role) {
    switch (role) {
        case ProcessRole::privileged_broker: return "privileged_broker";
        case ProcessRole::desktop_agent: return "desktop_agent";
        case ProcessRole::build_worker: return "build_worker";
    }
    return "unknown";
}

ProcessPolicy default_process_policy(const ProcessRole role) {
    switch (role) {
        case ProcessRole::privileged_broker:
            return {
                .role = role,
                .allowed_capabilities = {
                    Capability::deploy_execute, Capability::system_admin},
                .workspace_access = false,
            };
        case ProcessRole::desktop_agent:
            return {
                .role = role,
                .allowed_capabilities = {
                    Capability::desktop_view, Capability::desktop_control,
                    Capability::clipboard_read, Capability::clipboard_write},
                .workspace_access = false,
            };
        case ProcessRole::build_worker:
            return {
                .role = role,
                .allowed_capabilities = {
                    Capability::workspace_read, Capability::workspace_write,
                    Capability::workspace_sync, Capability::terminal_open,
                    Capability::command_exec, Capability::build_submit,
                    Capability::test_run, Capability::artifact_read,
                    Capability::artifact_download, Capability::git_status,
                    Capability::git_diff},
                .workspace_access = true,
            };
    }
    throw std::invalid_argument("unknown process role");
}

ProcessBoundary::ProcessBoundary(
    ProcessPolicy policy, std::filesystem::path workspace_root,
    AuditLog& audit)
    : policy_(std::move(policy)),
      workspace_scope_(std::move(workspace_root)),
      audit_(audit) {
    if (policy_.allowed_capabilities.empty()) {
        throw std::invalid_argument("process policy must allow an explicit capability set");
    }
}

bool ProcessBoundary::permits(
    const Capability capability,
    const AuthorizationResult& session_authorization) const {
    return policy_.allowed_capabilities.contains(capability) &&
           session_authorization.permits(capability);
}

std::filesystem::path ProcessBoundary::resolve_workspace_access(
    const ScopedAccessRequest& request) {
    if (request.principal_id.empty() || request.device_id.empty() ||
        request.session_id.empty() || request.workspace_id.empty()) {
        throw std::invalid_argument("scoped access actor metadata is incomplete");
    }
    if (!policy_.workspace_access) {
        deny(request, "role_has_no_workspace_access");
    }
    if (!permits(request.capability, request.authorization)) {
        deny(request, "capability_not_granted");
    }
    try {
        return workspace_scope_.resolve(request.relative_path);
    } catch (const std::invalid_argument&) {
        deny(request, "workspace_scope_escape");
    }
}

void ProcessBoundary::deny(
    const ScopedAccessRequest& request, std::string reason_code) {
    audit_.append({
        .occurred_at = request.occurred_at,
        .principal_id = request.principal_id,
        .device_id = request.device_id,
        .session_id = request.session_id,
        .workspace_id = request.workspace_id,
        .process_role = std::string(to_string(policy_.role)),
        .reason_code = std::move(reason_code),
        .agent_job_id = request.agent_job_id,
        .action = AuditAction::scope_access_denied,
        .result = AuditResult::denied,
    });
    throw std::logic_error("process workspace access denied");
}

}  // namespace rwn::core
