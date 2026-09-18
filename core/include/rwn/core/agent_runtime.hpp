#pragma once

#include "rwn/core/artifact_store.hpp"
#include "rwn/core/audit.hpp"
#include "rwn/core/build_config.hpp"
#include "rwn/core/file_transfer.hpp"
#include "rwn/core/process_isolation.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace rwn::core {

enum class AgentTool {
    workspace_read,
    workspace_patch,
    build_submit,
    test_run,
    git_status,
    git_diff,
    artifact_inspect,
};

[[nodiscard]] std::string_view to_string(AgentTool tool);
[[nodiscard]] Capability required_capability(AgentTool tool);

enum class AgentJobState {
    running,
    waiting_review,
    succeeded,
    failed,
    cancelled,
    timed_out,
};

struct AgentRuntimeLimits {
    std::size_t maximum_parallel_jobs{2};
    std::size_t maximum_jobs_per_minute{8};
    std::size_t maximum_tool_calls_per_job{32};
    std::size_t maximum_read_bytes{1024U * 1024U};
    std::size_t maximum_patch_bytes{1024U * 1024U};
    std::chrono::minutes job_timeout{15};
};

struct AgentJobRequest {
    std::string job_id;
    std::string principal_id;
    std::string device_id;
    std::string session_id;
    std::string workspace_id;
    PrincipalKind principal_kind{PrincipalKind::agent};
    std::uint64_t source_revision{};
    AuthorizationResult authorization;
    TimePoint occurred_at{};
};

struct AgentToolRequest {
    AgentTool tool{AgentTool::workspace_read};
    std::filesystem::path relative_path;
    std::string expected_sha256;
    std::string replacement;
    std::string profile;
    std::string operation_id;
    std::string artifact_id;
    std::size_t maximum_bytes{};
    TimePoint occurred_at{};
};

struct AgentEvidence {
    std::string id;
    std::string job_id;
    AgentTool tool{AgentTool::workspace_read};
    bool succeeded{};
    int exit_code{};
    bool timed_out{};
    bool cancelled{};
    bool stdout_truncated{};
    bool stderr_truncated{};
    std::string stdout_log;
    std::string stderr_log;
    std::string before_sha256;
    std::string after_sha256;
    std::string diff_summary;
    std::string build_id;
    std::string artifact_id;
    std::string artifact_sha256;
    std::uint64_t source_revision{};
    std::chrono::milliseconds elapsed{};
};

struct AgentJobRecord {
    AgentJobRequest request;
    AgentJobState state{AgentJobState::running};
    TimePoint started_at{};
    std::optional<TimePoint> finished_at;
    std::size_t tool_calls{};
    bool patch_review_granted{};
    std::vector<std::string> evidence_ids;
    TimePoint last_event_at{};
};

struct AgentReviewGrant {
    std::string reviewer_id;
    std::string device_id;
    std::string session_id;
    PrincipalKind reviewer_kind{PrincipalKind::human};
    AuthorizationResult authorization;
    TimePoint occurred_at{};
};

enum class AgentClaim {
    tool_succeeded,
    build_succeeded,
    test_succeeded,
    patch_applied,
    artifact_verified,
};

[[nodiscard]] std::string render_agent_evidence(
    const AgentEvidence& evidence);

class AgentRuntime {
public:
    AgentRuntime(
        std::filesystem::path workspace_root,
        RemoteWorkspaceConfig config,
        BuildQueue& builds,
        CommandExecutor& command_executor,
        DurableFileSystem& filesystem,
        ArtifactStore* artifacts,
        AuditLog& audit,
        std::filesystem::path git_executable,
        std::set<std::string, std::less<>> build_profiles,
        std::set<std::string, std::less<>> test_profiles,
        AgentRuntimeLimits limits = {});

    void create_job(AgentJobRequest request);
    void approve_patch(
        std::string_view job_id, const AgentReviewGrant& grant);
    [[nodiscard]] AgentEvidence execute(
        std::string_view job_id, const AgentToolRequest& request);
    void complete_job(std::string_view job_id, TimePoint now);
    void cancel_job(std::string_view job_id, TimePoint now);

    [[nodiscard]] const AgentJobRecord& job(std::string_view job_id) const;
    [[nodiscard]] const AgentEvidence& evidence(
        std::string_view evidence_id) const;
    [[nodiscard]] bool verify_claim(
        std::string_view evidence_id, AgentClaim claim) const;

private:
    [[nodiscard]] AgentJobRecord& active_job(
        std::string_view job_id, TimePoint now);
    [[nodiscard]] AgentEvidence workspace_read(
        AgentJobRecord& job, const AgentToolRequest& request,
        std::string evidence_id);
    [[nodiscard]] AgentEvidence workspace_patch(
        AgentJobRecord& job, const AgentToolRequest& request,
        std::string evidence_id);
    [[nodiscard]] AgentEvidence build_or_test(
        AgentJobRecord& job, const AgentToolRequest& request,
        std::string evidence_id, bool test);
    [[nodiscard]] AgentEvidence git_query(
        AgentJobRecord& job, const AgentToolRequest& request,
        std::string evidence_id);
    [[nodiscard]] AgentEvidence artifact_inspect(
        AgentJobRecord& job, const AgentToolRequest& request,
        std::string evidence_id);
    [[nodiscard]] ScopedAccessRequest scoped_request(
        const AgentJobRecord& job, Capability capability,
        const std::filesystem::path& relative_path,
        TimePoint now) const;
    void append_tool_audit(
        const AgentJobRecord& job, const AgentEvidence& evidence,
        TimePoint now);
    void require_event_time(AgentJobRecord& job, TimePoint now);

    std::filesystem::path workspace_root_;
    RemoteWorkspaceConfig config_;
    BuildQueue& builds_;
    CommandExecutor& command_executor_;
    DurableFileSystem& filesystem_;
    ArtifactStore* artifacts_{};
    AuditLog& audit_;
    ProcessBoundary boundary_;
    std::filesystem::path git_executable_;
    std::set<std::string, std::less<>> build_profiles_;
    std::set<std::string, std::less<>> test_profiles_;
    AgentRuntimeLimits limits_;
    std::map<std::string, AgentJobRecord, std::less<>> jobs_;
    std::map<std::string, AgentEvidence, std::less<>> evidence_;
    std::vector<TimePoint> job_starts_;
};

}  // namespace rwn::core
