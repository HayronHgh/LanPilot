#include "rwn/core/agent_runtime.hpp"

#include "rwn/core/content_hash.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace rwn::core {
namespace {

bool valid_identifier(const std::string_view value) {
    return !value.empty() && value.size() <= 64 &&
           std::ranges::all_of(value, [](const unsigned char character) {
               return std::isalnum(character) != 0 || character == '-' ||
                      character == '_' || character == '.';
           });
}

bool active(const AgentJobState state) {
    return state == AgentJobState::running ||
           state == AgentJobState::waiting_review;
}

void bound_log(std::string& value, bool& truncated) {
    constexpr std::size_t maximum_evidence_log = 1024U * 1024U;
    if (value.size() > maximum_evidence_log) {
        value.resize(maximum_evidence_log);
        truncated = true;
    }
}

std::string build_diff_summary(
    const std::string_view before, const std::string_view after,
    const std::size_t bytes) {
    return "before_sha256=" + std::string(before) +
           ";after_sha256=" + std::string(after) +
           ";replacement_bytes=" + std::to_string(bytes);
}

}  // namespace

std::string_view to_string(const AgentTool tool) {
    switch (tool) {
        case AgentTool::workspace_read: return "workspace.read";
        case AgentTool::workspace_patch: return "workspace.patch";
        case AgentTool::build_submit: return "build.submit";
        case AgentTool::test_run: return "test.run";
        case AgentTool::git_status: return "git.status";
        case AgentTool::git_diff: return "git.diff";
        case AgentTool::artifact_inspect: return "artifact.inspect";
    }
    return "unknown";
}

Capability required_capability(const AgentTool tool) {
    switch (tool) {
        case AgentTool::workspace_read: return Capability::workspace_read;
        case AgentTool::workspace_patch: return Capability::workspace_write;
        case AgentTool::build_submit: return Capability::build_submit;
        case AgentTool::test_run: return Capability::test_run;
        case AgentTool::git_status: return Capability::git_status;
        case AgentTool::git_diff: return Capability::git_diff;
        case AgentTool::artifact_inspect: return Capability::artifact_read;
    }
    throw std::invalid_argument("unknown Agent tool");
}

std::string render_agent_evidence(const AgentEvidence& evidence) {
    if (!valid_identifier(evidence.id) || !valid_identifier(evidence.job_id)) {
        throw std::invalid_argument("Agent evidence identifiers are invalid");
    }
    std::ostringstream output;
    output << "evidence_id=" << evidence.id << '\n'
           << "job_id=" << evidence.job_id << '\n'
           << "tool=" << to_string(evidence.tool) << '\n'
           << "succeeded=" << evidence.succeeded << '\n'
           << "exit_code=" << evidence.exit_code << '\n'
           << "timed_out=" << evidence.timed_out << '\n'
           << "cancelled=" << evidence.cancelled << '\n'
           << "elapsed_ms=" << evidence.elapsed.count() << '\n'
           << "source_revision=" << evidence.source_revision << '\n'
           << "build_id=" << evidence.build_id << '\n'
           << "artifact_id=" << evidence.artifact_id << '\n'
           << "artifact_sha256=" << evidence.artifact_sha256 << '\n'
           << "before_sha256=" << evidence.before_sha256 << '\n'
           << "after_sha256=" << evidence.after_sha256 << '\n'
           << "diff_summary=" << evidence.diff_summary << '\n'
           << "stdout_truncated=" << evidence.stdout_truncated << '\n'
           << "stderr_truncated=" << evidence.stderr_truncated << '\n'
           << "--- stdout ---\n" << evidence.stdout_log
           << "\n--- stderr ---\n" << evidence.stderr_log << '\n';
    return output.str();
}

AgentRuntime::AgentRuntime(
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
    AgentRuntimeLimits limits)
    : workspace_root_(std::filesystem::weakly_canonical(workspace_root)),
      config_(std::move(config)),
      builds_(builds),
      command_executor_(command_executor),
      filesystem_(filesystem),
      artifacts_(artifacts),
      audit_(audit),
      boundary_(
          default_process_policy(ProcessRole::build_worker),
          workspace_root_, audit),
      git_executable_(std::filesystem::weakly_canonical(git_executable)),
      build_profiles_(std::move(build_profiles)),
      test_profiles_(std::move(test_profiles)),
      limits_(limits) {
    if (!std::filesystem::is_directory(workspace_root_) ||
        !git_executable.is_absolute() ||
        !std::filesystem::is_regular_file(git_executable_) ||
        config_.workspace_id.empty() ||
        limits_.maximum_parallel_jobs == 0 ||
        limits_.maximum_parallel_jobs > 32 ||
        limits_.maximum_jobs_per_minute == 0 ||
        limits_.maximum_jobs_per_minute > 1000 ||
        limits_.maximum_tool_calls_per_job == 0 ||
        limits_.maximum_tool_calls_per_job > 1000 ||
        limits_.maximum_read_bytes == 0 ||
        limits_.maximum_read_bytes > 16U * 1024U * 1024U ||
        limits_.maximum_patch_bytes == 0 ||
        limits_.maximum_patch_bytes > 16U * 1024U * 1024U ||
        limits_.job_timeout <= std::chrono::minutes::zero() ||
        limits_.job_timeout > std::chrono::hours{24}) {
        throw std::invalid_argument("Agent runtime configuration is invalid");
    }
    for (const auto& profile : build_profiles_) {
        static_cast<void>(config_.profile(profile));
    }
    for (const auto& profile : test_profiles_) {
        static_cast<void>(config_.profile(profile));
    }
}

void AgentRuntime::create_job(AgentJobRequest request) {
    if (!valid_identifier(request.job_id) ||
        !valid_identifier(request.principal_id) ||
        !valid_identifier(request.device_id) ||
        !valid_identifier(request.session_id) ||
        request.workspace_id != config_.workspace_id ||
        request.principal_kind != PrincipalKind::agent ||
        request.source_revision == 0 || request.occurred_at == TimePoint{}) {
        throw std::invalid_argument("Agent job metadata is invalid");
    }
    for (auto& [unused_id, existing] : jobs_) {
        static_cast<void>(unused_id);
        if (!active(existing.state)) continue;
        if (request.occurred_at < existing.last_event_at) {
            throw std::invalid_argument(
                "Agent job creation time precedes an active job event");
        }
        if (request.occurred_at - existing.started_at > limits_.job_timeout) {
            existing.state = AgentJobState::timed_out;
            existing.finished_at = request.occurred_at;
            existing.last_event_at = request.occurred_at;
            audit_.append({
                .occurred_at = request.occurred_at,
                .principal_id = existing.request.principal_id,
                .device_id = existing.request.device_id,
                .session_id = existing.request.session_id,
                .workspace_id = existing.request.workspace_id,
                .source_revision = existing.request.source_revision,
                .process_role = std::string(to_string(ProcessRole::build_worker)),
                .reason_code = "job_timeout",
                .agent_job_id = existing.request.job_id,
                .action = AuditAction::agent_job_completed,
                .result = AuditResult::failed,
            });
        }
    }
    job_starts_.erase(
        std::remove_if(job_starts_.begin(), job_starts_.end(),
            [&](const TimePoint started) {
                return started < request.occurred_at - std::chrono::minutes{1};
            }),
        job_starts_.end());
    const auto active_jobs = std::ranges::count_if(
        jobs_, [](const auto& item) { return active(item.second.state); });
    if (static_cast<std::size_t>(active_jobs) >= limits_.maximum_parallel_jobs ||
        job_starts_.size() >= limits_.maximum_jobs_per_minute) {
        throw std::runtime_error("Agent job rate or parallel limit reached");
    }
    if (jobs_.contains(request.job_id)) {
        throw std::invalid_argument("duplicate Agent job id");
    }
    if (!request.authorization.permits(Capability::agent_run)) {
        audit_.append({
            .occurred_at = request.occurred_at,
            .principal_id = request.principal_id,
            .device_id = request.device_id,
            .session_id = request.session_id,
            .workspace_id = request.workspace_id,
            .process_role = std::string(to_string(ProcessRole::build_worker)),
            .reason_code = "capability_not_granted",
            .agent_job_id = request.job_id,
            .action = AuditAction::agent_job_started,
            .result = AuditResult::denied,
        });
        throw std::logic_error("agent.run capability is required");
    }
    const auto job_id = request.job_id;
    const auto started_at = request.occurred_at;
    jobs_.emplace(job_id, AgentJobRecord{
        .request = std::move(request),
        .state = AgentJobState::running,
        .started_at = started_at,
        .finished_at = std::nullopt,
        .tool_calls = 0,
        .patch_review_granted = false,
        .evidence_ids = {},
        .last_event_at = started_at,
    });
    job_starts_.push_back(started_at);
    const auto& job = jobs_.at(job_id);
    audit_.append({
        .occurred_at = started_at,
        .principal_id = job.request.principal_id,
        .device_id = job.request.device_id,
        .session_id = job.request.session_id,
        .workspace_id = job.request.workspace_id,
        .source_revision = job.request.source_revision,
        .process_role = std::string(to_string(ProcessRole::build_worker)),
        .agent_job_id = job_id,
        .action = AuditAction::agent_job_started,
        .result = AuditResult::allowed,
    });
}

void AgentRuntime::require_event_time(AgentJobRecord& job, const TimePoint now) {
    if (now == TimePoint{} || now < job.last_event_at) {
        throw std::invalid_argument("Agent job event time is not monotonic");
    }
    job.last_event_at = now;
}

AgentJobRecord& AgentRuntime::active_job(
    const std::string_view job_id, const TimePoint now) {
    auto found = jobs_.find(job_id);
    if (found == jobs_.end()) {
        throw std::out_of_range("unknown Agent job");
    }
    auto& job = found->second;
    if (!active(job.state)) {
        throw std::logic_error("Agent job is not active");
    }
    if (now == TimePoint{} || now < job.last_event_at) {
        throw std::invalid_argument("Agent job event time is not monotonic");
    }
    if (now - job.started_at > limits_.job_timeout) {
        job.state = AgentJobState::timed_out;
        job.finished_at = now;
        job.last_event_at = now;
        audit_.append({
            .occurred_at = now,
            .principal_id = job.request.principal_id,
            .device_id = job.request.device_id,
            .session_id = job.request.session_id,
            .workspace_id = job.request.workspace_id,
            .source_revision = job.request.source_revision,
            .process_role = std::string(to_string(ProcessRole::build_worker)),
            .reason_code = "job_timeout",
            .agent_job_id = job.request.job_id,
            .action = AuditAction::agent_job_completed,
            .result = AuditResult::failed,
        });
        throw std::runtime_error("Agent job timed out");
    }
    return job;
}

void AgentRuntime::approve_patch(
    const std::string_view job_id, const AgentReviewGrant& grant) {
    auto& job = active_job(job_id, grant.occurred_at);
    if (job.state != AgentJobState::waiting_review ||
        !valid_identifier(grant.reviewer_id) ||
        !valid_identifier(grant.device_id) ||
        !valid_identifier(grant.session_id) ||
        grant.reviewer_kind != PrincipalKind::human ||
        !grant.authorization.permits(Capability::workspace_write)) {
        throw std::invalid_argument("Agent patch review grant is invalid");
    }
    require_event_time(job, grant.occurred_at);
    job.patch_review_granted = true;
    job.state = AgentJobState::running;
    audit_.append({
        .occurred_at = grant.occurred_at,
        .principal_id = grant.reviewer_id,
        .device_id = grant.device_id,
        .session_id = grant.session_id,
        .workspace_id = job.request.workspace_id,
        .source_revision = job.request.source_revision,
        .process_role = std::string(to_string(ProcessRole::build_worker)),
        .reason_code = "one_patch",
        .agent_job_id = job.request.job_id,
        .action = AuditAction::agent_review_granted,
        .result = AuditResult::allowed,
    });
}

AgentEvidence AgentRuntime::execute(
    const std::string_view job_id, const AgentToolRequest& request) {
    auto& job = active_job(job_id, request.occurred_at);
    if (job.state != AgentJobState::running) {
        throw std::logic_error("Agent job is waiting for review");
    }
    require_event_time(job, request.occurred_at);
    if (job.tool_calls >= limits_.maximum_tool_calls_per_job) {
        throw std::runtime_error("Agent tool-call limit reached");
    }
    const auto evidence_id = job.request.job_id + "-e" +
                             std::to_string(job.tool_calls + 1U);
    const auto capability = required_capability(request.tool);
    if (!boundary_.permits(capability, job.request.authorization)) {
        AgentEvidence denied{
            .id = evidence_id,
            .job_id = job.request.job_id,
            .tool = request.tool,
            .succeeded = false,
            .exit_code = -1,
            .stdout_log = {},
            .stderr_log = "capability_not_granted",
            .before_sha256 = {},
            .after_sha256 = {},
            .diff_summary = {},
            .build_id = {},
            .artifact_id = {},
            .artifact_sha256 = {},
            .source_revision = job.request.source_revision,
        };
        evidence_.emplace(evidence_id, denied);
        job.evidence_ids.push_back(evidence_id);
        ++job.tool_calls;
        append_tool_audit(job, denied, request.occurred_at);
        throw std::logic_error("Agent tool capability is not granted");
    }
    if (request.tool == AgentTool::workspace_patch &&
        !job.patch_review_granted) {
        job.state = AgentJobState::waiting_review;
        audit_.append({
            .occurred_at = request.occurred_at,
            .principal_id = job.request.principal_id,
            .device_id = job.request.device_id,
            .session_id = job.request.session_id,
            .workspace_id = job.request.workspace_id,
            .source_revision = job.request.source_revision,
            .process_role = std::string(to_string(ProcessRole::build_worker)),
            .reason_code = "workspace_patch",
            .agent_job_id = job.request.job_id,
            .action = AuditAction::agent_review_requested,
            .result = AuditResult::allowed,
        });
        throw std::logic_error("workspace patch requires one-shot human review");
    }

    AgentEvidence result;
    try {
        switch (request.tool) {
            case AgentTool::workspace_read:
                result = workspace_read(job, request, evidence_id);
                break;
            case AgentTool::workspace_patch:
                job.patch_review_granted = false;
                result = workspace_patch(job, request, evidence_id);
                break;
            case AgentTool::build_submit:
                result = build_or_test(job, request, evidence_id, false);
                break;
            case AgentTool::test_run:
                result = build_or_test(job, request, evidence_id, true);
                break;
            case AgentTool::git_status:
            case AgentTool::git_diff:
                result = git_query(job, request, evidence_id);
                break;
            case AgentTool::artifact_inspect:
                result = artifact_inspect(job, request, evidence_id);
                break;
        }
    } catch (const std::exception& error) {
        result = {
            .id = evidence_id,
            .job_id = job.request.job_id,
            .tool = request.tool,
            .succeeded = false,
            .exit_code = -1,
            .stdout_log = {},
            .stderr_log = error.what(),
            .before_sha256 = {},
            .after_sha256 = {},
            .diff_summary = {},
            .build_id = {},
            .artifact_id = {},
            .artifact_sha256 = {},
            .source_revision = job.request.source_revision,
        };
    }
    bound_log(result.stdout_log, result.stdout_truncated);
    bound_log(result.stderr_log, result.stderr_truncated);
    evidence_.emplace(evidence_id, result);
    job.evidence_ids.push_back(evidence_id);
    ++job.tool_calls;
    append_tool_audit(job, result, request.occurred_at);
    return result;
}

ScopedAccessRequest AgentRuntime::scoped_request(
    const AgentJobRecord& job, const Capability capability,
    const std::filesystem::path& relative_path, const TimePoint now) const {
    return {
        .principal_id = job.request.principal_id,
        .device_id = job.request.device_id,
        .session_id = job.request.session_id,
        .workspace_id = job.request.workspace_id,
        .capability = capability,
        .relative_path = relative_path,
        .authorization = job.request.authorization,
        .occurred_at = now,
        .agent_job_id = job.request.job_id,
    };
}

AgentEvidence AgentRuntime::workspace_read(
    AgentJobRecord& job, const AgentToolRequest& request,
    std::string evidence_id) {
    const auto maximum = request.maximum_bytes == 0
        ? limits_.maximum_read_bytes : request.maximum_bytes;
    if (maximum == 0 || maximum > limits_.maximum_read_bytes ||
        request.relative_path.empty()) {
        throw std::invalid_argument("Agent workspace read bounds are invalid");
    }
    const auto path = boundary_.resolve_workspace_access(scoped_request(
        job, Capability::workspace_read, request.relative_path,
        request.occurred_at));
    if (!std::filesystem::is_regular_file(path) ||
        std::filesystem::file_size(path) > maximum) {
        throw std::invalid_argument("Agent workspace read target is not a bounded file");
    }
    std::ifstream input(path, std::ios::binary);
    const std::string content{
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()};
    if (input.bad()) {
        throw std::runtime_error("Agent workspace read failed");
    }
    return {
        .id = std::move(evidence_id),
        .job_id = job.request.job_id,
        .tool = AgentTool::workspace_read,
        .succeeded = true,
        .exit_code = 0,
        .stdout_log = content,
        .stderr_log = {},
        .before_sha256 = {},
        .after_sha256 = sha256_hex(content),
        .diff_summary = {},
        .build_id = {},
        .artifact_id = {},
        .artifact_sha256 = {},
        .source_revision = job.request.source_revision,
    };
}

AgentEvidence AgentRuntime::workspace_patch(
    AgentJobRecord& job, const AgentToolRequest& request,
    std::string evidence_id) {
    if (request.relative_path.empty() ||
        request.replacement.size() > limits_.maximum_patch_bytes ||
        !is_sha256_hex(request.expected_sha256)) {
        throw std::invalid_argument("Agent workspace patch is invalid");
    }
    const auto destination = boundary_.resolve_workspace_access(scoped_request(
        job, Capability::workspace_write, request.relative_path,
        request.occurred_at));
    if (!std::filesystem::is_regular_file(destination)) {
        throw std::invalid_argument("Agent patch target must be an existing regular file");
    }
    const auto before = sha256_file(destination);
    if (before != request.expected_sha256) {
        throw std::runtime_error("Agent patch compare-and-swap hash mismatch");
    }
    const auto after = sha256_hex(request.replacement);
    if (after == before) {
        throw std::invalid_argument("Agent patch must change file content");
    }
    const auto staging_relative = request.relative_path.parent_path() /
        (request.relative_path.filename().string() + ".rwn-agent-" +
         job.request.job_id + "-" + evidence_id + ".staging");
    const auto staging = boundary_.resolve_workspace_access(scoped_request(
        job, Capability::workspace_write, staging_relative,
        request.occurred_at));
    try {
        std::ofstream output(staging, std::ios::binary | std::ios::trunc);
        output.write(
            request.replacement.data(),
            static_cast<std::streamsize>(request.replacement.size()));
        output.flush();
        if (!output) {
            throw std::runtime_error("Agent patch staging write failed");
        }
        output.close();
        filesystem_.flush_file(staging);
        filesystem_.atomic_replace(staging, destination);
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(staging, ignored);
        throw;
    }
    if (sha256_file(destination) != after) {
        throw std::runtime_error("Agent patch durable replacement hash mismatch");
    }
    return {
        .id = std::move(evidence_id),
        .job_id = job.request.job_id,
        .tool = AgentTool::workspace_patch,
        .succeeded = true,
        .exit_code = 0,
        .stdout_log = {},
        .stderr_log = {},
        .before_sha256 = before,
        .after_sha256 = after,
        .diff_summary = build_diff_summary(
            before, after, request.replacement.size()),
        .build_id = {},
        .artifact_id = {},
        .artifact_sha256 = {},
        .source_revision = job.request.source_revision,
    };
}

AgentEvidence AgentRuntime::build_or_test(
    AgentJobRecord& job, const AgentToolRequest& request,
    std::string evidence_id, const bool test) {
    const auto& allowed = test ? test_profiles_ : build_profiles_;
    if (!allowed.contains(request.profile) ||
        !valid_identifier(request.operation_id)) {
        throw std::invalid_argument("Agent build/test profile or operation id is not allowlisted");
    }
    auto build_request = config_.make_build_request(
        request.operation_id, job.request.source_revision, request.profile);
    const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
        job.started_at + limits_.job_timeout - request.occurred_at);
    build_request.command.timeout = std::min(
        build_request.command.timeout,
        std::max(std::chrono::seconds{1}, remaining));
    const auto& profile = config_.profile(request.profile);
    builds_.submit(std::move(build_request), profile.environment_allowlist);
    BuildRunner runner(builds_, command_executor_);
    auto runtime = runner.run(request.operation_id);
    const bool succeeded = runtime.exit_code == 0 && !runtime.timed_out &&
                           !runtime.cancelled;
    return {
        .id = std::move(evidence_id),
        .job_id = job.request.job_id,
        .tool = test ? AgentTool::test_run : AgentTool::build_submit,
        .succeeded = succeeded,
        .exit_code = runtime.exit_code,
        .timed_out = runtime.timed_out,
        .cancelled = runtime.cancelled,
        .stdout_truncated = runtime.stdout_truncated,
        .stderr_truncated = runtime.stderr_truncated,
        .stdout_log = std::move(runtime.stdout_log),
        .stderr_log = std::move(runtime.stderr_log),
        .before_sha256 = {},
        .after_sha256 = {},
        .diff_summary = {},
        .build_id = request.operation_id,
        .artifact_id = {},
        .artifact_sha256 = {},
        .source_revision = job.request.source_revision,
        .elapsed = runtime.elapsed,
    };
}

AgentEvidence AgentRuntime::git_query(
    AgentJobRecord& job, const AgentToolRequest& request,
    std::string evidence_id) {
    if (!request.relative_path.empty() || !request.profile.empty() ||
        !request.operation_id.empty() || !request.artifact_id.empty() ||
        !request.expected_sha256.empty() || !request.replacement.empty()) {
        throw std::invalid_argument("Git Agent tools accept no user-controlled arguments");
    }
    CommandSpec command{
        .argv = {
            git_executable_.string(), "--no-optional-locks", "-c",
            "core.fsmonitor=false", "-c", "core.untrackedCache=false"},
        .working_directory = ".",
        .timeout = std::chrono::seconds{30},
        .environment = {},
    };
    const auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
        job.started_at + limits_.job_timeout - request.occurred_at);
    command.timeout = std::min(
        command.timeout, std::max(std::chrono::seconds{1}, remaining));
    if (request.tool == AgentTool::git_status) {
        command.argv.insert(
            command.argv.end(),
            {"status", "--porcelain=v1", "--untracked-files=no"});
    } else {
        command.argv.insert(
            command.argv.end(),
            {"diff", "--no-ext-diff", "--no-textconv",
             "--src-prefix=a/", "--dst-prefix=b/", "--"});
    }
    auto runtime = command_executor_.execute(command);
    return {
        .id = std::move(evidence_id),
        .job_id = job.request.job_id,
        .tool = request.tool,
        .succeeded = runtime.exit_code == 0 && !runtime.timed_out &&
                     !runtime.cancelled,
        .exit_code = runtime.exit_code,
        .timed_out = runtime.timed_out,
        .cancelled = runtime.cancelled,
        .stdout_truncated = runtime.stdout_truncated,
        .stderr_truncated = runtime.stderr_truncated,
        .stdout_log = std::move(runtime.stdout_log),
        .stderr_log = std::move(runtime.stderr_log),
        .before_sha256 = {},
        .after_sha256 = {},
        .diff_summary = {},
        .build_id = {},
        .artifact_id = {},
        .artifact_sha256 = {},
        .source_revision = job.request.source_revision,
        .elapsed = runtime.elapsed,
    };
}

AgentEvidence AgentRuntime::artifact_inspect(
    AgentJobRecord& job, const AgentToolRequest& request,
    std::string evidence_id) {
    if (artifacts_ == nullptr || !valid_identifier(request.artifact_id)) {
        throw std::invalid_argument("Agent artifact store or artifact id is unavailable");
    }
    const auto& artifact = artifacts_->metadata(request.artifact_id);
    if (artifact.workspace_id != job.request.workspace_id ||
        artifact.source_revision != job.request.source_revision) {
        throw std::logic_error("Agent artifact is outside the pinned workspace revision");
    }
    const bool verified = artifacts_->verify(request.artifact_id);
    std::ostringstream summary;
    summary << "artifact_id=" << artifact.id << '\n'
            << "build_id=" << artifact.build_id << '\n'
            << "source_revision=" << artifact.source_revision << '\n'
            << "sha256=" << artifact.sha256 << '\n'
            << "size=" << artifact.size << '\n';
    return {
        .id = std::move(evidence_id),
        .job_id = job.request.job_id,
        .tool = AgentTool::artifact_inspect,
        .succeeded = verified,
        .exit_code = verified ? 0 : 1,
        .stdout_log = summary.str(),
        .stderr_log = {},
        .before_sha256 = {},
        .after_sha256 = {},
        .diff_summary = {},
        .build_id = artifact.build_id,
        .artifact_id = artifact.id,
        .artifact_sha256 = artifact.sha256,
        .source_revision = artifact.source_revision,
    };
}

void AgentRuntime::append_tool_audit(
    const AgentJobRecord& job, const AgentEvidence& evidence,
    const TimePoint now) {
    audit_.append({
        .occurred_at = now,
        .principal_id = job.request.principal_id,
        .device_id = job.request.device_id,
        .session_id = job.request.session_id,
        .workspace_id = job.request.workspace_id,
        .build_id = evidence.build_id,
        .artifact_id = evidence.artifact_id,
        .artifact_sha256 = evidence.artifact_sha256,
        .source_revision = evidence.source_revision,
        .process_role = std::string(to_string(ProcessRole::build_worker)),
        .reason_code = evidence.succeeded ? "runtime_verified" : "runtime_failed",
        .agent_job_id = job.request.job_id,
        .tool_name = std::string(to_string(evidence.tool)),
        .evidence_id = evidence.id,
        .action = AuditAction::agent_tool_completed,
        .result = evidence.succeeded ? AuditResult::allowed : AuditResult::failed,
    });
}

void AgentRuntime::complete_job(
    const std::string_view job_id, const TimePoint now) {
    auto& job = active_job(job_id, now);
    if (job.state != AgentJobState::running || job.evidence_ids.empty()) {
        throw std::logic_error("Agent job cannot complete without reviewed evidence");
    }
    require_event_time(job, now);
    const bool succeeded = std::ranges::all_of(
        job.evidence_ids, [&](const std::string& id) {
            return evidence_.at(id).succeeded;
        });
    job.state = succeeded ? AgentJobState::succeeded : AgentJobState::failed;
    job.finished_at = now;
    audit_.append({
        .occurred_at = now,
        .principal_id = job.request.principal_id,
        .device_id = job.request.device_id,
        .session_id = job.request.session_id,
        .workspace_id = job.request.workspace_id,
        .source_revision = job.request.source_revision,
        .process_role = std::string(to_string(ProcessRole::build_worker)),
        .reason_code = succeeded ? "evidence_verified" : "evidence_failed",
        .agent_job_id = job.request.job_id,
        .action = AuditAction::agent_job_completed,
        .result = succeeded ? AuditResult::allowed : AuditResult::failed,
    });
}

void AgentRuntime::cancel_job(
    const std::string_view job_id, const TimePoint now) {
    auto& job = active_job(job_id, now);
    require_event_time(job, now);
    job.state = AgentJobState::cancelled;
    job.finished_at = now;
    audit_.append({
        .occurred_at = now,
        .principal_id = job.request.principal_id,
        .device_id = job.request.device_id,
        .session_id = job.request.session_id,
        .workspace_id = job.request.workspace_id,
        .source_revision = job.request.source_revision,
        .process_role = std::string(to_string(ProcessRole::build_worker)),
        .reason_code = "cancelled",
        .agent_job_id = job.request.job_id,
        .action = AuditAction::agent_job_completed,
        .result = AuditResult::failed,
    });
}

const AgentJobRecord& AgentRuntime::job(const std::string_view job_id) const {
    return jobs_.at(std::string(job_id));
}

const AgentEvidence& AgentRuntime::evidence(
    const std::string_view evidence_id) const {
    return evidence_.at(std::string(evidence_id));
}

bool AgentRuntime::verify_claim(
    const std::string_view evidence_id, const AgentClaim claim) const {
    const auto& item = evidence(evidence_id);
    if (!item.succeeded) return false;
    switch (claim) {
        case AgentClaim::tool_succeeded:
            return item.exit_code == 0 && !item.timed_out && !item.cancelled;
        case AgentClaim::build_succeeded:
            return item.tool == AgentTool::build_submit && item.exit_code == 0 &&
                   !item.build_id.empty();
        case AgentClaim::test_succeeded:
            return item.tool == AgentTool::test_run && item.exit_code == 0 &&
                   !item.build_id.empty();
        case AgentClaim::patch_applied:
            return item.tool == AgentTool::workspace_patch &&
                   is_sha256_hex(item.before_sha256) &&
                   is_sha256_hex(item.after_sha256) &&
                   item.before_sha256 != item.after_sha256 &&
                   !item.diff_summary.empty();
        case AgentClaim::artifact_verified:
            return item.tool == AgentTool::artifact_inspect &&
                   !item.artifact_id.empty() &&
                   is_sha256_hex(item.artifact_sha256);
    }
    return false;
}

}  // namespace rwn::core
