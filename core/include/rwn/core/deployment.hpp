#pragma once

#include "rwn/core/artifact_store.hpp"
#include "rwn/core/audit.hpp"
#include "rwn/core/authorization.hpp"
#include "rwn/core/build.hpp"
#include "rwn/core/file_transfer.hpp"
#include "rwn/core/workspace_scope.hpp"

#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace rwn::core {

enum class DeploymentStatus { deploying, active, rolled_back, failed };
enum class DeploymentStep {
    stop,
    stage_previous,
    install,
    start,
    health_check,
    rollback_stop,
    rollback_restore,
    rollback_start,
    rollback_health_check,
};

struct DeploymentStepEvidence {
    DeploymentStep step{DeploymentStep::stop};
    bool succeeded{};
    BuildEvidence process;
    std::string reason_code;
};

struct DeploymentRecord {
    std::string id;
    std::string workspace_id;
    std::uint64_t workspace_revision{};
    std::string artifact_id;
    std::string artifact_sha256;
    std::string build_id;
    TimePoint created_at{};
    TimePoint completed_at{};
    DeploymentStatus status{DeploymentStatus::deploying};
    std::string failure_reason;
    std::vector<DeploymentStepEvidence> evidence;
};

struct DeploymentRequest {
    std::string deployment_id;
    std::string artifact_id;
    std::string principal_id;
    std::string device_id;
    std::string session_id;
    std::string workspace_id;
    AuthorizationResult authorization;
    TimePoint occurred_at{};
};

struct RollbackRequest {
    std::string deployment_id;
    std::string principal_id;
    std::string device_id;
    std::string session_id;
    AuthorizationResult authorization;
    TimePoint occurred_at{};
};

class DeploymentBackend {
public:
    virtual ~DeploymentBackend() = default;
    [[nodiscard]] virtual BuildEvidence stop() = 0;
    virtual void stage_previous(std::string_view deployment_id) = 0;
    virtual void install(
        std::string_view deployment_id,
        const std::filesystem::path& immutable_artifact,
        const Artifact& metadata) = 0;
    [[nodiscard]] virtual BuildEvidence start() = 0;
    [[nodiscard]] virtual BuildEvidence health_check() = 0;
    virtual void restore_previous(std::string_view deployment_id) = 0;
};

class FileDeploymentBackend final : public DeploymentBackend {
public:
    FileDeploymentBackend(
        std::filesystem::path runtime_root,
        std::filesystem::path active_relative_path,
        CommandExecutor& executor, DurableFileSystem& filesystem,
        CommandSpec stop_command, CommandSpec start_command,
        CommandSpec health_command);

    [[nodiscard]] BuildEvidence stop() override;
    void stage_previous(std::string_view deployment_id) override;
    void install(
        std::string_view deployment_id,
        const std::filesystem::path& immutable_artifact,
        const Artifact& metadata) override;
    [[nodiscard]] BuildEvidence start() override;
    [[nodiscard]] BuildEvidence health_check() override;
    void restore_previous(std::string_view deployment_id) override;

    [[nodiscard]] const std::filesystem::path& active_path() const {
        return active_path_;
    }

private:
    [[nodiscard]] std::filesystem::path rollback_path(
        std::string_view deployment_id) const;
    [[nodiscard]] std::filesystem::path failed_path(
        std::string_view deployment_id) const;

    WorkspaceScope runtime_scope_;
    std::filesystem::path active_path_;
    CommandExecutor& executor_;
    DurableFileSystem& filesystem_;
    CommandSpec stop_command_;
    CommandSpec start_command_;
    CommandSpec health_command_;
};

class DeploymentService {
public:
    DeploymentService(
        const ArtifactStore& artifacts, DeploymentBackend& backend,
        AuditLog& audit)
        : artifacts_(artifacts), backend_(backend), audit_(audit) {}

    [[nodiscard]] DeploymentRecord deploy(const DeploymentRequest& request);
    [[nodiscard]] DeploymentRecord rollback(const RollbackRequest& request);
    [[nodiscard]] const DeploymentRecord& record(
        std::string_view deployment_id) const;

private:
    const ArtifactStore& artifacts_;
    DeploymentBackend& backend_;
    AuditLog& audit_;
    std::map<std::string, DeploymentRecord, std::less<>> records_;
};

}  // namespace rwn::core
