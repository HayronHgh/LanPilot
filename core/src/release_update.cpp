#include "rwn/core/release_update.hpp"

#include "rwn/core/content_hash.hpp"
#include "rwn/core/workspace_sync.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <fstream>
#include <ranges>
#include <stdexcept>
#include <utility>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace rwn::core {
namespace {

constexpr std::array<std::string_view, 3> protected_directories{
    "pairing", "workspaces", "audit"};

[[nodiscard]] bool valid_transaction_id(const std::string_view value) {
    return !value.empty() && value.size() <= 48U &&
           std::ranges::all_of(value, [](const unsigned char character) {
               return std::isalnum(character) != 0 || character == '-' ||
                      character == '_';
           });
}

[[nodiscard]] bool has_path_prefix(
    const std::filesystem::path& path,
    const std::filesystem::path& prefix) {
    auto item = path.begin();
    for (auto expected = prefix.begin(); expected != prefix.end();
         ++expected, ++item) {
        if (item == path.end() || *item != *expected) return false;
    }
    return true;
}

[[nodiscard]] bool roots_overlap(
    const std::filesystem::path& left,
    const std::filesystem::path& right) {
    return has_path_prefix(left, right) || has_path_prefix(right, left);
}

[[nodiscard]] bool is_platform_redirect(
    const std::filesystem::path& path) {
#if defined(_WIN32)
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        throw std::runtime_error(
            "protected state attributes could not be read");
    }
    return (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
#else
    return std::filesystem::is_symlink(std::filesystem::symlink_status(path));
#endif
}

[[nodiscard]] std::filesystem::path canonical_existing_directory(
    const std::filesystem::path& path) {
    if (!path.is_absolute() || !std::filesystem::is_directory(path)) {
        throw std::invalid_argument(
            "release update root must be an existing absolute directory");
    }
    return std::filesystem::canonical(path);
}

[[nodiscard]] BuildEvidence filesystem_evidence(
    const std::chrono::steady_clock::time_point started,
    const int exit_code = 0) {
    return {
        .exit_code = exit_code,
        .stdout_log = {},
        .stderr_log = {},
        .elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started),
        .timed_out = false,
        .cancelled = false,
        .stdout_truncated = false,
        .stderr_truncated = false,
    };
}

[[nodiscard]] bool runtime_succeeded(const BuildEvidence& evidence) {
    return evidence.exit_code == 0 && !evidence.timed_out &&
           !evidence.cancelled;
}

[[nodiscard]] std::string failure_reason(const ReleaseUpdateStep step) {
    switch (step) {
        case ReleaseUpdateStep::snapshot_before:
            return "protected_state_snapshot_failed";
        case ReleaseUpdateStep::backup_state:
            return "protected_state_backup_failed";
        case ReleaseUpdateStep::stop: return "update_stop_failed";
        case ReleaseUpdateStep::stage_current:
            return "update_stage_current_failed";
        case ReleaseUpdateStep::activate: return "update_activate_failed";
        case ReleaseUpdateStep::start: return "update_start_failed";
        case ReleaseUpdateStep::health_check:
            return "update_health_check_failed";
        case ReleaseUpdateStep::snapshot_after:
            return "protected_state_changed";
        case ReleaseUpdateStep::rollback_stop:
            return "update_rollback_stop_failed";
        case ReleaseUpdateStep::rollback_restore:
            return "update_rollback_restore_failed";
        case ReleaseUpdateStep::rollback_state_restore:
            return "protected_state_restore_failed";
        case ReleaseUpdateStep::rollback_start:
            return "update_rollback_start_failed";
        case ReleaseUpdateStep::rollback_health_check:
            return "update_rollback_health_failed";
        case ReleaseUpdateStep::rollback_state_verify:
            return "protected_state_restore_mismatch";
    }
    return "release_update_failed";
}

void copy_protected_snapshot(
    const std::filesystem::path& source_root,
    const std::filesystem::path& destination_root,
    const ProtectedStateSnapshot& expected,
    DurableFileSystem& filesystem,
    const ProtectedStateLimits limits) {
    if (std::filesystem::exists(destination_root)) {
        throw std::logic_error("protected state copy destination exists");
    }
    std::filesystem::create_directories(destination_root);
    for (const auto& entry : expected.entries) {
        const auto source = source_root / entry.relative_path;
        const auto destination = destination_root / entry.relative_path;
        if (entry.kind == ProtectedStateEntryKind::directory) {
            if (!std::filesystem::create_directories(destination) &&
                !std::filesystem::is_directory(destination)) {
                throw std::runtime_error(
                    "protected state directory copy failed");
            }
            continue;
        }
        std::filesystem::create_directories(destination.parent_path());
        if (!std::filesystem::copy_file(
                source, destination, std::filesystem::copy_options::none)) {
            throw std::runtime_error("protected state file copy failed");
        }
        filesystem.flush_file(destination);
    }
    if (capture_protected_state(destination_root, limits) != expected) {
        throw std::runtime_error("protected state copy verification failed");
    }
}

}  // namespace

ProtectedStateSnapshot capture_protected_state(
    const std::filesystem::path& state_root,
    const ProtectedStateLimits limits) {
    if (limits.maximum_entries < protected_directories.size() ||
        limits.maximum_file_bytes == 0 || limits.maximum_total_bytes == 0 ||
        limits.maximum_file_bytes > limits.maximum_total_bytes) {
        throw std::invalid_argument("protected state limits are invalid");
    }
    const auto root = canonical_existing_directory(state_root);
    ProtectedStateSnapshot snapshot;
    for (const auto directory : protected_directories) {
        const auto top = root / directory;
        if (!std::filesystem::is_directory(top) ||
            is_platform_redirect(top) ||
            std::filesystem::canonical(top).parent_path() != root) {
            throw std::invalid_argument(
                "protected state directory is missing or redirected");
        }
        for (std::filesystem::recursive_directory_iterator iterator(top), end;
             iterator != end; ++iterator) {
            const auto path = iterator->path();
            const auto status = std::filesystem::symlink_status(path);
            if (is_platform_redirect(path) ||
                (!std::filesystem::is_directory(status) &&
                 !std::filesystem::is_regular_file(status))) {
                throw std::invalid_argument(
                    "protected state contains a link or special entry");
            }
            const auto canonical = std::filesystem::canonical(path);
            if (!has_path_prefix(canonical, root)) {
                throw std::invalid_argument("protected state entry escapes root");
            }
            const auto relative =
                std::filesystem::relative(path, root).generic_string();
            if (!is_canonical_workspace_path(relative)) {
                throw std::invalid_argument(
                    "protected state entry path is noncanonical");
            }
            if (snapshot.entries.size() >= limits.maximum_entries) {
                throw std::length_error("protected state entry limit exceeded");
            }
            if (std::filesystem::is_directory(status)) {
                snapshot.entries.push_back({
                    .relative_path = relative,
                    .kind = ProtectedStateEntryKind::directory,
                    .size = 0,
                    .sha256 = {},
                });
                continue;
            }
            const auto size = std::filesystem::file_size(path);
            if (std::filesystem::hard_link_count(path) != 1U) {
                throw std::invalid_argument(
                    "protected state hard links are not allowed");
            }
            if (size > limits.maximum_file_bytes ||
                size > limits.maximum_total_bytes - snapshot.total_bytes) {
                throw std::length_error("protected state byte limit exceeded");
            }
            const auto hash = sha256_file(path);
            if (std::filesystem::file_size(path) != size) {
                throw std::runtime_error(
                    "protected state changed while hashing");
            }
            snapshot.total_bytes += size;
            snapshot.entries.push_back({
                .relative_path = relative,
                .kind = ProtectedStateEntryKind::file,
                .size = size,
                .sha256 = hash,
            });
        }
        if (snapshot.entries.size() >= limits.maximum_entries) {
            throw std::length_error("protected state entry limit exceeded");
        }
        snapshot.entries.push_back({
            .relative_path = std::string(directory),
            .kind = ProtectedStateEntryKind::directory,
            .size = 0,
            .sha256 = {},
        });
    }
    std::ranges::sort(
        snapshot.entries, {}, &ProtectedStateEntry::relative_path);
    std::string inventory;
    for (const auto& entry : snapshot.entries) {
        inventory += entry.kind == ProtectedStateEntryKind::directory ? "D\0" : "F\0";
        inventory.append(entry.relative_path);
        inventory.push_back('\0');
        inventory.append(std::to_string(entry.size));
        inventory.push_back('\0');
        inventory.append(entry.sha256);
        inventory.push_back('\0');
    }
    snapshot.inventory_sha256 = sha256_hex(
        std::as_bytes(std::span{inventory.data(), inventory.size()}));
    return snapshot;
}

FileReleaseUpdateBackend::FileReleaseUpdateBackend(
    std::filesystem::path install_root,
    std::filesystem::path active_relative_path,
    std::filesystem::path protected_state_root,
    std::filesystem::path transaction_root,
    CommandExecutor& executor, DurableFileSystem& filesystem,
    CommandSpec stop_command, CommandSpec start_command,
    CommandSpec health_command, const ProtectedStateLimits limits)
    : install_root_(canonical_existing_directory(install_root)),
      state_root_(canonical_existing_directory(protected_state_root)),
      transaction_root_(canonical_existing_directory(transaction_root)),
      executor_(executor),
      filesystem_(filesystem),
      stop_command_(std::move(stop_command)),
      start_command_(std::move(start_command)),
      health_command_(std::move(health_command)),
      limits_(limits) {
    if (active_relative_path.empty() || active_relative_path.is_absolute() ||
        !is_canonical_workspace_path(active_relative_path.generic_string())) {
        throw std::invalid_argument("active update package path is invalid");
    }
    active_path_ = std::filesystem::weakly_canonical(
        install_root_ / active_relative_path);
    if (!has_path_prefix(active_path_, install_root_) ||
        !std::filesystem::is_regular_file(active_path_) ||
        roots_overlap(install_root_, state_root_) ||
        roots_overlap(install_root_, transaction_root_) ||
        roots_overlap(state_root_, transaction_root_) ||
        install_root_.root_name() != transaction_root_.root_name() ||
        state_root_.root_name() != transaction_root_.root_name()) {
        throw std::invalid_argument("release update roots are unsafe");
    }
    static_cast<void>(capture_protected_state(state_root_, limits_));
    validate_command(stop_command_, {});
    validate_command(start_command_, {});
    validate_command(health_command_, {});
}

ProtectedStateSnapshot FileReleaseUpdateBackend::snapshot_state() const {
    return capture_protected_state(state_root_, limits_);
}

std::filesystem::path FileReleaseUpdateBackend::rollback_path(
    const std::string_view update_id) const {
    if (!valid_transaction_id(update_id)) {
        throw std::invalid_argument("release update id is invalid");
    }
    return install_root_ / "rollback" /
           (std::string(update_id) + ".previous");
}

std::filesystem::path FileReleaseUpdateBackend::failed_path(
    const std::string_view update_id) const {
    if (!valid_transaction_id(update_id)) {
        throw std::invalid_argument("release update id is invalid");
    }
    return install_root_ / "failed" /
           (std::string(update_id) + ".failed");
}

std::filesystem::path FileReleaseUpdateBackend::backup_path(
    const std::string_view transaction_id) const {
    if (!valid_transaction_id(transaction_id)) {
        throw std::invalid_argument("release transaction id is invalid");
    }
    return transaction_root_ / "backups" / std::string(transaction_id);
}

void FileReleaseUpdateBackend::backup_state(
    const std::string_view transaction_id,
    const ProtectedStateSnapshot& expected) {
    if (snapshot_state() != expected) {
        throw std::runtime_error("protected state changed before backup");
    }
    copy_protected_snapshot(
        state_root_, backup_path(transaction_id), expected, filesystem_, limits_);
}

BuildEvidence FileReleaseUpdateBackend::stop() {
    return executor_.execute(stop_command_);
}

void FileReleaseUpdateBackend::stage_current(
    const std::string_view update_id) {
    const auto rollback = rollback_path(update_id);
    if (!std::filesystem::is_regular_file(active_path_) ||
        std::filesystem::exists(rollback)) {
        throw std::logic_error("release rollback slot is unavailable");
    }
    std::filesystem::create_directories(rollback.parent_path());
    filesystem_.flush_file(active_path_);
    filesystem_.atomic_replace(active_path_, rollback);
}

void FileReleaseUpdateBackend::activate(
    const std::string_view update_id, const VerifiedUpdate& update) {
    if (!valid_transaction_id(update_id) || update_id.size() > 40U ||
        !update.package_path().is_absolute() ||
        !std::filesystem::is_regular_file(update.package_path()) ||
        std::filesystem::file_size(update.package_path()) !=
            update.manifest().package_size ||
        sha256_file(update.package_path()) != update.manifest().package_sha256) {
        throw std::invalid_argument("verified update package is unavailable");
    }
    const auto staging = install_root_ / "staging" /
                         (std::string(update_id) + ".package.part");
    if (std::filesystem::exists(staging)) {
        throw std::logic_error("release staging package already exists");
    }
    std::filesystem::create_directories(staging.parent_path());
    if (!std::filesystem::copy_file(
            update.package_path(), staging, std::filesystem::copy_options::none)) {
        throw std::runtime_error("release package staging failed");
    }
    if (std::filesystem::file_size(staging) != update.manifest().package_size ||
        sha256_file(staging) != update.manifest().package_sha256) {
        throw std::runtime_error("staged release package verification failed");
    }
    filesystem_.flush_file(staging);
    filesystem_.atomic_replace(staging, active_path_);
}

BuildEvidence FileReleaseUpdateBackend::start() {
    return executor_.execute(start_command_);
}

BuildEvidence FileReleaseUpdateBackend::health_check() {
    return executor_.execute(health_command_);
}

void FileReleaseUpdateBackend::restore_previous(
    const std::string_view update_id) {
    const auto rollback = rollback_path(update_id);
    if (!std::filesystem::is_regular_file(rollback)) {
        throw std::logic_error("release rollback package is missing");
    }
    if (std::filesystem::exists(active_path_)) {
        const auto failed = failed_path(update_id);
        if (std::filesystem::exists(failed)) {
            throw std::logic_error("failed release quarantine exists");
        }
        std::filesystem::create_directories(failed.parent_path());
        filesystem_.flush_file(active_path_);
        filesystem_.atomic_replace(active_path_, failed);
    }
    filesystem_.atomic_replace(rollback, active_path_);
}

void FileReleaseUpdateBackend::restore_state(
    const std::string_view transaction_id,
    const ProtectedStateSnapshot& expected) {
    const auto backup = backup_path(transaction_id);
    if (capture_protected_state(backup, limits_) != expected) {
        throw std::runtime_error("protected state backup is corrupt");
    }
    const auto staging =
        transaction_root_ / "restores" / std::string(transaction_id);
    copy_protected_snapshot(
        backup, staging, expected, filesystem_, limits_);
    const auto damaged =
        transaction_root_ / "damaged" / std::string(transaction_id);
    if (std::filesystem::exists(damaged)) {
        throw std::logic_error("protected state damaged slot exists");
    }
    std::filesystem::create_directories(damaged);
    std::vector<std::string_view> moved_current;
    std::vector<std::string_view> installed_restores;
    try {
        for (const auto directory : protected_directories) {
            std::filesystem::rename(
                state_root_ / directory, damaged / directory);
            moved_current.push_back(directory);
        }
        for (const auto directory : protected_directories) {
            std::filesystem::rename(staging / directory, state_root_ / directory);
            installed_restores.push_back(directory);
        }
    } catch (...) {
        std::error_code ignored;
        for (const auto directory : std::views::reverse(installed_restores)) {
            std::filesystem::rename(
                state_root_ / directory, staging / directory, ignored);
        }
        for (const auto directory : std::views::reverse(moved_current)) {
            std::filesystem::rename(
                damaged / directory, state_root_ / directory, ignored);
        }
        throw;
    }
    if (snapshot_state() != expected) {
        throw std::runtime_error("protected state restore verification failed");
    }
}

ReleaseUpdateRecord ReleaseUpdateService::apply(
    std::string update_id, const SemanticVersion installed_version,
    VerifiedUpdate update) {
    if (!valid_transaction_id(update_id) ||
        records_.contains(update_id) ||
        installed_version >= update.manifest().version ||
        !update.package_path().is_absolute() ||
        !std::filesystem::is_regular_file(update.package_path()) ||
        std::filesystem::file_size(update.package_path()) !=
            update.manifest().package_size ||
        sha256_file(update.package_path()) !=
            update.manifest().package_sha256) {
        throw std::invalid_argument("release update request is invalid");
    }
    ReleaseUpdateRecord result{
        .id = std::move(update_id),
        .installed_before = installed_version,
        .target_version = update.manifest().version,
        .package_sha256 = update.manifest().package_sha256,
        .status = ReleaseUpdateStatus::updating,
        .protected_state_before_sha256 = {},
        .protected_state_after_sha256 = {},
        .failure_reason = {},
        .evidence = {},
    };
    ProtectedStateSnapshot before;
    ReleaseUpdateStep current = ReleaseUpdateStep::snapshot_before;
    bool stop_attempted{};
    bool staged{};
    const auto file_step = [&](const ReleaseUpdateStep step, auto&& operation,
                               std::string state_hash = {}) {
        current = step;
        const auto started = std::chrono::steady_clock::now();
        try {
            operation();
            result.evidence.push_back({
                .step = step,
                .succeeded = true,
                .runtime = filesystem_evidence(started),
                .state_inventory_sha256 = std::move(state_hash),
                .reason_code = {},
            });
        } catch (...) {
            result.evidence.push_back({
                .step = step,
                .succeeded = false,
                .runtime = filesystem_evidence(started, -1),
                .state_inventory_sha256 = std::move(state_hash),
                .reason_code = failure_reason(step),
            });
            throw;
        }
    };
    const auto process_step = [&](const ReleaseUpdateStep step,
                                  auto&& operation) {
        current = step;
        const auto started = std::chrono::steady_clock::now();
        try {
            auto evidence = operation();
            const auto succeeded = runtime_succeeded(evidence);
            result.evidence.push_back({
                .step = step,
                .succeeded = succeeded,
                .runtime = evidence,
                .state_inventory_sha256 = {},
                .reason_code = succeeded ? "" : failure_reason(step),
            });
            if (!succeeded) {
                throw std::runtime_error("release update runtime step failed");
            }
        } catch (...) {
            if (result.evidence.empty() ||
                result.evidence.back().step != step) {
                result.evidence.push_back({
                    .step = step,
                    .succeeded = false,
                    .runtime = filesystem_evidence(started, -1),
                    .state_inventory_sha256 = {},
                    .reason_code = failure_reason(step),
                });
            }
            throw;
        }
    };
    try {
        file_step(ReleaseUpdateStep::snapshot_before, [&] {
            before = backend_.snapshot_state();
            result.protected_state_before_sha256 = before.inventory_sha256;
        });
        result.evidence.back().state_inventory_sha256 =
            result.protected_state_before_sha256;
        file_step(ReleaseUpdateStep::backup_state, [&] {
            backend_.backup_state(result.id, before);
        }, before.inventory_sha256);
        stop_attempted = true;
        process_step(ReleaseUpdateStep::stop, [&] { return backend_.stop(); });
        file_step(ReleaseUpdateStep::stage_current, [&] {
            backend_.stage_current(result.id);
            staged = true;
        });
        file_step(ReleaseUpdateStep::activate, [&] {
            backend_.activate(result.id, update);
        });
        process_step(ReleaseUpdateStep::start, [&] { return backend_.start(); });
        process_step(
            ReleaseUpdateStep::health_check,
            [&] { return backend_.health_check(); });
        ProtectedStateSnapshot after;
        file_step(ReleaseUpdateStep::snapshot_after, [&] {
            after = backend_.snapshot_state();
            if (after != before) {
                throw std::runtime_error(
                    "protected state changed during update");
            }
            result.protected_state_after_sha256 = after.inventory_sha256;
        });
        result.evidence.back().state_inventory_sha256 =
            result.protected_state_after_sha256;
        result.status = ReleaseUpdateStatus::active;
    } catch (...) {
        result.failure_reason = failure_reason(current);
        try {
            if (staged) {
                process_step(
                    ReleaseUpdateStep::rollback_stop,
                    [&] { return backend_.stop(); });
                file_step(ReleaseUpdateStep::rollback_restore, [&] {
                    backend_.restore_previous(result.id);
                });
                file_step(
                    ReleaseUpdateStep::rollback_state_restore, [&] {
                        backend_.restore_state(result.id, before);
                    },
                    before.inventory_sha256);
                process_step(
                    ReleaseUpdateStep::rollback_start,
                    [&] { return backend_.start(); });
                process_step(
                    ReleaseUpdateStep::rollback_health_check,
                    [&] { return backend_.health_check(); });
                file_step(ReleaseUpdateStep::rollback_state_verify, [&] {
                    const auto restored = backend_.snapshot_state();
                    if (restored != before) {
                        throw std::runtime_error(
                            "protected state rollback verification failed");
                    }
                    result.protected_state_after_sha256 =
                        restored.inventory_sha256;
                });
                result.evidence.back().state_inventory_sha256 =
                    result.protected_state_after_sha256;
                result.status = ReleaseUpdateStatus::rolled_back;
            } else {
                if (stop_attempted) {
                    process_step(
                        ReleaseUpdateStep::rollback_start,
                        [&] { return backend_.start(); });
                    process_step(
                        ReleaseUpdateStep::rollback_health_check,
                        [&] { return backend_.health_check(); });
                }
                result.status = ReleaseUpdateStatus::failed;
            }
        } catch (...) {
            result.status = ReleaseUpdateStatus::failed;
        }
    }
    const auto [iterator, inserted] = records_.emplace(result.id, result);
    if (!inserted) {
        throw std::logic_error("release update record insertion failed");
    }
    return iterator->second;
}

ReleaseUpdateRecord ReleaseUpdateService::rollback(
    const std::string_view update_id) {
    const auto found = records_.find(std::string(update_id));
    if (found == records_.end() ||
        found->second.status != ReleaseUpdateStatus::active) {
        throw std::logic_error("only an active release update can roll back");
    }
    auto& result = found->second;
    const auto transaction_id = result.id + "-manual";
    ProtectedStateSnapshot before;
    const auto file_step = [&](const ReleaseUpdateStep step, auto&& operation,
                               std::string state_hash = {}) {
        const auto started = std::chrono::steady_clock::now();
        try {
            operation();
            result.evidence.push_back({
                .step = step,
                .succeeded = true,
                .runtime = filesystem_evidence(started),
                .state_inventory_sha256 = std::move(state_hash),
                .reason_code = {},
            });
        } catch (...) {
            result.evidence.push_back({
                .step = step,
                .succeeded = false,
                .runtime = filesystem_evidence(started, -1),
                .state_inventory_sha256 = std::move(state_hash),
                .reason_code = failure_reason(step),
            });
            throw;
        }
    };
    const auto process_step = [&](const ReleaseUpdateStep step,
                                  auto&& operation) {
        const auto started = std::chrono::steady_clock::now();
        try {
            auto evidence = operation();
            const auto succeeded = runtime_succeeded(evidence);
            result.evidence.push_back({
                .step = step,
                .succeeded = succeeded,
                .runtime = evidence,
                .state_inventory_sha256 = {},
                .reason_code = succeeded ? "" : failure_reason(step),
            });
            if (!succeeded) {
                throw std::runtime_error(
                    "manual rollback runtime step failed");
            }
        } catch (...) {
            if (result.evidence.empty() ||
                result.evidence.back().step != step) {
                result.evidence.push_back({
                    .step = step,
                    .succeeded = false,
                    .runtime = filesystem_evidence(started, -1),
                    .state_inventory_sha256 = {},
                    .reason_code = failure_reason(step),
                });
            }
            throw;
        }
    };
    try {
        file_step(ReleaseUpdateStep::snapshot_before, [&] {
            before = backend_.snapshot_state();
        });
        result.evidence.back().state_inventory_sha256 = before.inventory_sha256;
        file_step(ReleaseUpdateStep::backup_state, [&] {
            backend_.backup_state(transaction_id, before);
        }, before.inventory_sha256);
        process_step(
            ReleaseUpdateStep::rollback_stop,
            [&] { return backend_.stop(); });
        file_step(ReleaseUpdateStep::rollback_restore, [&] {
            backend_.restore_previous(result.id);
        });
        file_step(ReleaseUpdateStep::rollback_state_restore, [&] {
            backend_.restore_state(transaction_id, before);
        }, before.inventory_sha256);
        process_step(
            ReleaseUpdateStep::rollback_start,
            [&] { return backend_.start(); });
        process_step(
            ReleaseUpdateStep::rollback_health_check,
            [&] { return backend_.health_check(); });
        file_step(ReleaseUpdateStep::rollback_state_verify, [&] {
            if (backend_.snapshot_state() != before) {
                throw std::runtime_error("manual rollback verification failed");
            }
        }, before.inventory_sha256);
        result.status = ReleaseUpdateStatus::rolled_back;
        result.failure_reason = "manual_rollback";
        result.protected_state_after_sha256 = before.inventory_sha256;
    } catch (...) {
        result.status = ReleaseUpdateStatus::failed;
        result.failure_reason = "manual_rollback_failed";
    }
    return result;
}

const ReleaseUpdateRecord& ReleaseUpdateService::record(
    const std::string_view update_id) const {
    return records_.at(std::string(update_id));
}

}  // namespace rwn::core
