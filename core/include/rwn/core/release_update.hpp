#pragma once

#include "rwn/core/build.hpp"
#include "rwn/core/file_transfer.hpp"
#include "rwn/core/release_compatibility.hpp"

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace rwn::core {

struct ProtectedStateLimits {
    std::size_t maximum_entries{100'000};
    std::uint64_t maximum_file_bytes{1024ULL * 1024ULL * 1024ULL};
    std::uint64_t maximum_total_bytes{8ULL * 1024ULL * 1024ULL * 1024ULL};
};

enum class ProtectedStateEntryKind { directory, file };

struct ProtectedStateEntry {
    std::string relative_path;
    ProtectedStateEntryKind kind{ProtectedStateEntryKind::file};
    std::uint64_t size{};
    std::string sha256;
    [[nodiscard]] bool operator==(const ProtectedStateEntry&) const = default;
};

struct ProtectedStateSnapshot {
    std::vector<ProtectedStateEntry> entries;
    std::uint64_t total_bytes{};
    std::string inventory_sha256;
    [[nodiscard]] bool operator==(const ProtectedStateSnapshot&) const = default;
};

[[nodiscard]] ProtectedStateSnapshot capture_protected_state(
    const std::filesystem::path& state_root,
    ProtectedStateLimits limits = {});

enum class ReleaseUpdateStatus { updating, active, rolled_back, failed };

enum class ReleaseUpdateStep {
    snapshot_before,
    backup_state,
    stop,
    stage_current,
    activate,
    start,
    health_check,
    snapshot_after,
    rollback_stop,
    rollback_restore,
    rollback_state_restore,
    rollback_start,
    rollback_health_check,
    rollback_state_verify,
};

struct ReleaseUpdateStepEvidence {
    ReleaseUpdateStep step{ReleaseUpdateStep::snapshot_before};
    bool succeeded{};
    BuildEvidence runtime;
    std::string state_inventory_sha256;
    std::string reason_code;
};

struct ReleaseUpdateRecord {
    std::string id;
    SemanticVersion installed_before;
    SemanticVersion target_version;
    std::string package_sha256;
    ReleaseUpdateStatus status{ReleaseUpdateStatus::updating};
    std::string protected_state_before_sha256;
    std::string protected_state_after_sha256;
    std::string failure_reason;
    std::vector<ReleaseUpdateStepEvidence> evidence;
};

class ReleaseUpdateBackend {
public:
    virtual ~ReleaseUpdateBackend() = default;
    [[nodiscard]] virtual ProtectedStateSnapshot snapshot_state() const = 0;
    virtual void backup_state(
        std::string_view transaction_id,
        const ProtectedStateSnapshot& expected) = 0;
    [[nodiscard]] virtual BuildEvidence stop() = 0;
    virtual void stage_current(std::string_view update_id) = 0;
    virtual void activate(
        std::string_view update_id, const VerifiedUpdate& update) = 0;
    [[nodiscard]] virtual BuildEvidence start() = 0;
    [[nodiscard]] virtual BuildEvidence health_check() = 0;
    virtual void restore_previous(std::string_view update_id) = 0;
    virtual void restore_state(
        std::string_view transaction_id,
        const ProtectedStateSnapshot& expected) = 0;
};

class FileReleaseUpdateBackend final : public ReleaseUpdateBackend {
public:
    FileReleaseUpdateBackend(
        std::filesystem::path install_root,
        std::filesystem::path active_relative_path,
        std::filesystem::path protected_state_root,
        std::filesystem::path transaction_root,
        CommandExecutor& executor, DurableFileSystem& filesystem,
        CommandSpec stop_command, CommandSpec start_command,
        CommandSpec health_command, ProtectedStateLimits limits = {});

    [[nodiscard]] ProtectedStateSnapshot snapshot_state() const override;
    void backup_state(
        std::string_view transaction_id,
        const ProtectedStateSnapshot& expected) override;
    [[nodiscard]] BuildEvidence stop() override;
    void stage_current(std::string_view update_id) override;
    void activate(
        std::string_view update_id, const VerifiedUpdate& update) override;
    [[nodiscard]] BuildEvidence start() override;
    [[nodiscard]] BuildEvidence health_check() override;
    void restore_previous(std::string_view update_id) override;
    void restore_state(
        std::string_view transaction_id,
        const ProtectedStateSnapshot& expected) override;

    [[nodiscard]] const std::filesystem::path& active_path() const {
        return active_path_;
    }

private:
    [[nodiscard]] std::filesystem::path rollback_path(
        std::string_view update_id) const;
    [[nodiscard]] std::filesystem::path failed_path(
        std::string_view update_id) const;
    [[nodiscard]] std::filesystem::path backup_path(
        std::string_view transaction_id) const;

    std::filesystem::path install_root_;
    std::filesystem::path active_path_;
    std::filesystem::path state_root_;
    std::filesystem::path transaction_root_;
    CommandExecutor& executor_;
    DurableFileSystem& filesystem_;
    CommandSpec stop_command_;
    CommandSpec start_command_;
    CommandSpec health_command_;
    ProtectedStateLimits limits_;
};

class ReleaseUpdateService {
public:
    explicit ReleaseUpdateService(ReleaseUpdateBackend& backend)
        : backend_(backend) {}

    [[nodiscard]] ReleaseUpdateRecord apply(
        std::string update_id, SemanticVersion installed_version,
        VerifiedUpdate update);
    [[nodiscard]] ReleaseUpdateRecord rollback(std::string_view update_id);
    [[nodiscard]] const ReleaseUpdateRecord& record(
        std::string_view update_id) const;

private:
    ReleaseUpdateBackend& backend_;
    std::map<std::string, ReleaseUpdateRecord, std::less<>> records_;
};

}  // namespace rwn::core
