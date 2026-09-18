#include "rwn/core/deployment.hpp"

#include "rwn/core/content_hash.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <stdexcept>
#include <utility>

namespace rwn::core {
namespace {

bool valid_id(const std::string_view value) {
    return !value.empty() && value.size() <= 64 &&
           std::ranges::all_of(value, [](const unsigned char character) {
               return std::isalnum(character) != 0 || character == '-' ||
                      character == '_';
           });
}

bool command_succeeded(const BuildEvidence& evidence) {
    return evidence.exit_code == 0 && !evidence.timed_out && !evidence.cancelled;
}

BuildEvidence file_evidence(
    const std::chrono::steady_clock::time_point start,
    const int exit_code = 0) {
    return {
        .exit_code = exit_code,
        .stdout_log = {},
        .stderr_log = {},
        .elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start),
        .timed_out = false,
        .cancelled = false,
        .stdout_truncated = false,
        .stderr_truncated = false,
    };
}

std::string step_failure_reason(const DeploymentStep step) {
    switch (step) {
        case DeploymentStep::stop: return "stop_failed";
        case DeploymentStep::stage_previous: return "stage_previous_failed";
        case DeploymentStep::install: return "install_failed";
        case DeploymentStep::start: return "start_failed";
        case DeploymentStep::health_check: return "health_check_failed";
        case DeploymentStep::rollback_stop: return "rollback_stop_failed";
        case DeploymentStep::rollback_restore: return "rollback_restore_failed";
        case DeploymentStep::rollback_start: return "rollback_start_failed";
        case DeploymentStep::rollback_health_check:
            return "rollback_health_check_failed";
    }
    return "deployment_step_failed";
}

void require_command(const BuildEvidence& evidence) {
    if (!command_succeeded(evidence)) {
        throw std::runtime_error("deployment process step failed");
    }
}

}  // namespace

FileDeploymentBackend::FileDeploymentBackend(
    std::filesystem::path runtime_root,
    std::filesystem::path active_relative_path,
    CommandExecutor& executor, DurableFileSystem& filesystem,
    CommandSpec stop_command, CommandSpec start_command,
    CommandSpec health_command)
    : runtime_scope_(std::move(runtime_root)),
      active_path_(runtime_scope_.resolve(active_relative_path)),
      executor_(executor),
      filesystem_(filesystem),
      stop_command_(std::move(stop_command)),
      start_command_(std::move(start_command)),
      health_command_(std::move(health_command)) {
    if (!std::filesystem::is_regular_file(active_path_)) {
        throw std::invalid_argument(
            "deployment runtime requires an existing active regular file");
    }
    validate_command(stop_command_, {});
    validate_command(start_command_, {});
    validate_command(health_command_, {});
}

BuildEvidence FileDeploymentBackend::stop() {
    return executor_.execute(stop_command_);
}

std::filesystem::path FileDeploymentBackend::rollback_path(
    const std::string_view deployment_id) const {
    return runtime_scope_.resolve(
        std::filesystem::path("rollback") /
        (std::string(deployment_id) + ".previous"));
}

std::filesystem::path FileDeploymentBackend::failed_path(
    const std::string_view deployment_id) const {
    return runtime_scope_.resolve(
        std::filesystem::path("failed") /
        (std::string(deployment_id) + ".failed"));
}

void FileDeploymentBackend::stage_previous(
    const std::string_view deployment_id) {
    const auto destination = rollback_path(deployment_id);
    if (!std::filesystem::is_regular_file(active_path_) ||
        std::filesystem::exists(destination)) {
        throw std::logic_error("deployment rollback slot is unavailable");
    }
    std::filesystem::create_directories(destination.parent_path());
    filesystem_.flush_file(active_path_);
    filesystem_.atomic_replace(active_path_, destination);
}

void FileDeploymentBackend::install(
    const std::string_view deployment_id,
    const std::filesystem::path& immutable_artifact,
    const Artifact& metadata) {
    if (!std::filesystem::is_regular_file(immutable_artifact) ||
        std::filesystem::file_size(immutable_artifact) != metadata.size ||
        sha256_file(immutable_artifact) != metadata.sha256) {
        throw std::invalid_argument("deployment artifact failed verification");
    }
    std::filesystem::create_directories(active_path_.parent_path());
    const auto staging = active_path_.parent_path() /
        ("." + active_path_.filename().string() + ".deploy-" +
         std::string(deployment_id) + ".part");
    if (!runtime_scope_.contains_resolved(staging) ||
        std::filesystem::exists(staging)) {
        throw std::logic_error("deployment staging path is unavailable");
    }
    if (!std::filesystem::copy_file(
            immutable_artifact, staging,
            std::filesystem::copy_options::none)) {
        throw std::runtime_error("deployment artifact staging copy failed");
    }
    if (std::filesystem::file_size(staging) != metadata.size ||
        sha256_file(staging) != metadata.sha256) {
        throw std::runtime_error("deployment staged artifact verification failed");
    }
    filesystem_.flush_file(staging);
    filesystem_.atomic_replace(staging, active_path_);
}

BuildEvidence FileDeploymentBackend::start() {
    return executor_.execute(start_command_);
}

BuildEvidence FileDeploymentBackend::health_check() {
    return executor_.execute(health_command_);
}

void FileDeploymentBackend::restore_previous(
    const std::string_view deployment_id) {
    const auto rollback = rollback_path(deployment_id);
    if (!std::filesystem::is_regular_file(rollback)) {
        throw std::logic_error("deployment rollback artifact is missing");
    }
    if (std::filesystem::exists(active_path_)) {
        const auto failed = failed_path(deployment_id);
        if (std::filesystem::exists(failed)) {
            throw std::logic_error("failed deployment quarantine already exists");
        }
        std::filesystem::create_directories(failed.parent_path());
        filesystem_.flush_file(active_path_);
        filesystem_.atomic_replace(active_path_, failed);
    }
    filesystem_.atomic_replace(rollback, active_path_);
}

DeploymentRecord DeploymentService::deploy(const DeploymentRequest& request) {
    if (!valid_id(request.deployment_id) || request.principal_id.empty() ||
        request.device_id.empty() || request.session_id.empty() ||
        request.workspace_id.empty() || records_.contains(request.deployment_id)) {
        throw std::invalid_argument("deployment request is incomplete or duplicated");
    }
    const auto& artifact = artifacts_.metadata(request.artifact_id);
    if (request.workspace_id != artifact.workspace_id ||
        !artifacts_.verify(request.artifact_id)) {
        throw std::invalid_argument("deployment artifact is unavailable or corrupt");
    }
    const auto audit_event = [&](const AuditAction action, const AuditResult result,
                                 const TimePoint occurred_at,
                                 std::string reason_code = {}) {
        audit_.append({
            .occurred_at = occurred_at,
            .principal_id = request.principal_id,
            .device_id = request.device_id,
            .session_id = request.session_id,
            .workspace_id = request.workspace_id,
            .build_id = artifact.build_id,
            .artifact_id = artifact.id,
            .artifact_sha256 = artifact.sha256,
            .source_revision = artifact.source_revision,
            .deployment_id = request.deployment_id,
            .process_role = "privileged_broker",
            .reason_code = std::move(reason_code),
            .action = action,
            .result = result,
        });
    };
    if (!request.authorization.permits(Capability::deploy_execute)) {
        audit_event(
            AuditAction::deployment_failed, AuditResult::denied,
            request.occurred_at, "deploy_capability_denied");
        throw std::logic_error("deployment capability is not granted");
    }

    DeploymentRecord record{
        .id = request.deployment_id,
        .workspace_id = request.workspace_id,
        .workspace_revision = artifact.source_revision,
        .artifact_id = artifact.id,
        .artifact_sha256 = artifact.sha256,
        .build_id = artifact.build_id,
        .created_at = request.occurred_at,
        .completed_at = {},
        .status = DeploymentStatus::deploying,
        .failure_reason = {},
        .evidence = {},
    };
    const auto pipeline_start = std::chrono::steady_clock::now();
    audit_event(
        AuditAction::deployment_started, AuditResult::allowed,
        request.occurred_at);
    DeploymentStep current_step = DeploymentStep::stop;
    const auto process_step = [&](const DeploymentStep step,
                                  auto&& operation) {
        current_step = step;
        const auto start = std::chrono::steady_clock::now();
        try {
            auto evidence = operation();
            const auto success = command_succeeded(evidence);
            record.evidence.push_back({
                .step = step,
                .succeeded = success,
                .process = evidence,
                .reason_code = success ? "" : step_failure_reason(step),
            });
            require_command(evidence);
        } catch (...) {
            if (record.evidence.empty() ||
                record.evidence.back().step != step) {
                record.evidence.push_back({
                    .step = step,
                    .succeeded = false,
                    .process = file_evidence(start, -1),
                    .reason_code = step_failure_reason(step),
                });
            }
            throw;
        }
    };
    const auto file_step = [&](const DeploymentStep step,
                               auto&& operation) {
        current_step = step;
        const auto start = std::chrono::steady_clock::now();
        try {
            operation();
            record.evidence.push_back({
                .step = step,
                .succeeded = true,
                .process = file_evidence(start),
                .reason_code = {},
            });
        } catch (...) {
            record.evidence.push_back({
                .step = step,
                .succeeded = false,
                .process = file_evidence(start, -1),
                .reason_code = step_failure_reason(step),
            });
            throw;
        }
    };

    try {
        process_step(DeploymentStep::stop, [&] { return backend_.stop(); });
        file_step(DeploymentStep::stage_previous, [&] {
            backend_.stage_previous(request.deployment_id);
        });
        file_step(DeploymentStep::install, [&] {
            backend_.install(
                request.deployment_id, artifacts_.object_path(artifact.id), artifact);
        });
        process_step(DeploymentStep::start, [&] { return backend_.start(); });
        process_step(
            DeploymentStep::health_check,
            [&] { return backend_.health_check(); });
        record.status = DeploymentStatus::active;
    } catch (const std::exception&) {
        record.failure_reason = step_failure_reason(current_step);
        try {
            process_step(
                DeploymentStep::rollback_stop,
                [&] { return backend_.stop(); });
            file_step(DeploymentStep::rollback_restore, [&] {
                backend_.restore_previous(request.deployment_id);
            });
            process_step(
                DeploymentStep::rollback_start,
                [&] { return backend_.start(); });
            process_step(
                DeploymentStep::rollback_health_check,
                [&] { return backend_.health_check(); });
            record.status = DeploymentStatus::rolled_back;
        } catch (const std::exception&) {
            record.status = DeploymentStatus::failed;
        }
    }
    const auto pipeline_elapsed =
        std::chrono::duration_cast<WallClock::duration>(
            std::chrono::steady_clock::now() - pipeline_start);
    record.completed_at = request.occurred_at + pipeline_elapsed;
    const auto [iterator, inserted] = records_.emplace(record.id, record);
    if (!inserted) {
        throw std::logic_error("deployment record insertion failed");
    }
    if (record.status == DeploymentStatus::active) {
        audit_event(
            AuditAction::deployment_active, AuditResult::allowed,
            record.completed_at);
    } else if (record.status == DeploymentStatus::rolled_back) {
        audit_event(
            AuditAction::deployment_rolled_back, AuditResult::failed,
            record.completed_at, record.failure_reason);
    } else {
        audit_event(
            AuditAction::deployment_failed, AuditResult::failed,
            record.completed_at, record.failure_reason);
    }
    return iterator->second;
}

DeploymentRecord DeploymentService::rollback(const RollbackRequest& request) {
    if (!valid_id(request.deployment_id) || request.principal_id.empty() ||
        request.device_id.empty() || request.session_id.empty()) {
        throw std::invalid_argument("rollback request is incomplete");
    }
    auto found = records_.find(request.deployment_id);
    if (found == records_.end() ||
        found->second.status != DeploymentStatus::active) {
        throw std::logic_error("only an active deployment can be rolled back");
    }
    auto& record = found->second;
    const auto append_audit = [&](const AuditResult result,
                                  std::string reason_code) {
        audit_.append({
            .occurred_at = request.occurred_at,
            .principal_id = request.principal_id,
            .device_id = request.device_id,
            .session_id = request.session_id,
            .workspace_id = record.workspace_id,
            .build_id = record.build_id,
            .artifact_id = record.artifact_id,
            .artifact_sha256 = record.artifact_sha256,
            .source_revision = record.workspace_revision,
            .deployment_id = record.id,
            .process_role = "privileged_broker",
            .reason_code = std::move(reason_code),
            .action = result == AuditResult::allowed
                ? AuditAction::deployment_rolled_back
                : AuditAction::deployment_failed,
            .result = result,
        });
    };
    if (!request.authorization.permits(Capability::deploy_execute)) {
        append_audit(AuditResult::denied, "deploy_capability_denied");
        throw std::logic_error("rollback capability is not granted");
    }
    const auto process = [&](const DeploymentStep step, auto&& operation) {
        auto evidence = operation();
        const auto success = command_succeeded(evidence);
        record.evidence.push_back({
            .step = step,
            .succeeded = success,
            .process = evidence,
            .reason_code = success ? "" : step_failure_reason(step),
        });
        require_command(evidence);
    };
    try {
        process(DeploymentStep::rollback_stop,
                [&] { return backend_.stop(); });
        const auto restore_start = std::chrono::steady_clock::now();
        backend_.restore_previous(request.deployment_id);
        record.evidence.push_back({
            .step = DeploymentStep::rollback_restore,
            .succeeded = true,
            .process = file_evidence(restore_start),
            .reason_code = {},
        });
        process(DeploymentStep::rollback_start,
                [&] { return backend_.start(); });
        process(DeploymentStep::rollback_health_check,
                [&] { return backend_.health_check(); });
        record.status = DeploymentStatus::rolled_back;
        record.failure_reason = "manual_rollback";
        record.completed_at = request.occurred_at;
        append_audit(AuditResult::allowed, "manual_rollback");
    } catch (const std::exception&) {
        record.status = DeploymentStatus::failed;
        record.failure_reason = "manual_rollback_failed";
        record.completed_at = request.occurred_at;
        append_audit(AuditResult::failed, record.failure_reason);
    }
    return record;
}

const DeploymentRecord& DeploymentService::record(
    const std::string_view deployment_id) const {
    return records_.at(std::string(deployment_id));
}

}  // namespace rwn::core
