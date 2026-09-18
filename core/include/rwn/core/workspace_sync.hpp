#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace rwn::core {

enum class WorkspaceEntryKind { file, directory, symlink };

struct WorkspaceEntry {
    std::string path;
    WorkspaceEntryKind kind{WorkspaceEntryKind::file};
    std::uint64_t size{};
    std::string content_hash;
    std::uint32_t mode{};
    std::string symlink_target;
    [[nodiscard]] bool operator==(const WorkspaceEntry&) const = default;
};

struct WorkspaceManifest {
    std::string workspace_id;
    std::uint64_t revision{};
    std::vector<WorkspaceEntry> entries;
};

enum class WorkspaceChangeKind { create, update, remove, rename, metadata };
struct WorkspaceChange {
    WorkspaceChangeKind kind{};
    std::string path;
    std::string previous_path;
    [[nodiscard]] bool operator==(const WorkspaceChange&) const = default;
};

[[nodiscard]] bool is_canonical_workspace_path(std::string_view path);
void validate_manifest(const WorkspaceManifest& manifest);
[[nodiscard]] std::vector<WorkspaceChange> diff_manifests(const WorkspaceManifest& source, const WorkspaceManifest& destination);
[[nodiscard]] WorkspaceManifest apply_manifest_diff(
    const WorkspaceManifest& source, const WorkspaceManifest& destination,
    const std::vector<WorkspaceChange>& changes);
[[nodiscard]] std::string manifest_content_hash(const WorkspaceManifest& manifest);

enum class WorkspaceSyncState { idle, synchronizing, synced, failed };

struct WorkspaceRevisionRecord {
    std::uint64_t revision{};
    std::string manifest_hash;
    std::size_t entry_count{};
};

class WorkspaceRevisionHistory {
public:
    explicit WorkspaceRevisionHistory(std::string workspace_id, std::size_t capacity = 32);
    void begin(std::uint64_t revision);
    void commit(WorkspaceManifest manifest);
    void fail(std::string reason);

    [[nodiscard]] WorkspaceSyncState state() const { return state_; }
    [[nodiscard]] std::uint64_t current_revision() const;
    [[nodiscard]] const std::vector<WorkspaceRevisionRecord>& records() const {
        return records_;
    }
    [[nodiscard]] const std::string& failure_reason() const { return failure_reason_; }

private:
    std::string workspace_id_;
    std::size_t capacity_{};
    WorkspaceSyncState state_{WorkspaceSyncState::idle};
    std::optional<std::uint64_t> pending_revision_;
    std::vector<WorkspaceRevisionRecord> records_;
    std::string failure_reason_;
};

class ChunkResumeLedger {
public:
    static constexpr std::size_t max_chunk_size = 4U * 1024U * 1024U;
    explicit ChunkResumeLedger(std::size_t chunk_count);
    void confirm(std::size_t chunk_index, std::size_t byte_count, std::string_view verified_chunk_hash);
    [[nodiscard]] bool complete() const;
    [[nodiscard]] std::vector<std::size_t> missing() const;

private:
    std::vector<bool> confirmed_;
};

}  // namespace rwn::core
