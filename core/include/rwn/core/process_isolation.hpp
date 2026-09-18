#pragma once

#include "rwn/core/audit.hpp"
#include "rwn/core/authorization.hpp"
#include "rwn/core/workspace_scope.hpp"

#include <filesystem>
#include <set>
#include <string>
#include <string_view>

namespace rwn::core {

enum class ProcessRole { privileged_broker, desktop_agent, build_worker };

[[nodiscard]] std::string_view to_string(ProcessRole role);

struct ProcessPolicy {
    ProcessRole role{ProcessRole::build_worker};
    std::set<Capability> allowed_capabilities;
    bool workspace_access{};
};

[[nodiscard]] ProcessPolicy default_process_policy(ProcessRole role);

struct ScopedAccessRequest {
    std::string principal_id;
    std::string device_id;
    std::string session_id;
    std::string workspace_id;
    Capability capability{Capability::workspace_read};
    std::filesystem::path relative_path;
    AuthorizationResult authorization;
    TimePoint occurred_at{};
    std::string agent_job_id;
};

class ProcessBoundary {
public:
    ProcessBoundary(
        ProcessPolicy policy, std::filesystem::path workspace_root,
        AuditLog& audit);

    [[nodiscard]] bool permits(
        Capability capability,
        const AuthorizationResult& session_authorization) const;
    [[nodiscard]] std::filesystem::path resolve_workspace_access(
        const ScopedAccessRequest& request);
    [[nodiscard]] ProcessRole role() const { return policy_.role; }

private:
    [[noreturn]] void deny(
        const ScopedAccessRequest& request, std::string reason_code);

    ProcessPolicy policy_;
    WorkspaceScope workspace_scope_;
    AuditLog& audit_;
};

}  // namespace rwn::core
