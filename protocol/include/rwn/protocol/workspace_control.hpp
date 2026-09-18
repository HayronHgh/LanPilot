#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace rwn::protocol {

inline constexpr std::size_t max_workspace_wire_entries = 100'000;
inline constexpr std::size_t max_workspace_wire_chunks = 4096;
inline constexpr std::size_t max_workspace_chunk_bytes = 4U * 1024U * 1024U;

enum class WorkspaceWireEntryKind : std::uint8_t {
    file = 0,
    directory = 1,
    symlink = 2,
};

struct WorkspaceWireEntry {
    std::string path;
    WorkspaceWireEntryKind kind{WorkspaceWireEntryKind::file};
    std::uint64_t size{};
    std::string sha256;
    std::uint32_t mode{};
    std::string symlink_target;
    [[nodiscard]] bool operator==(const WorkspaceWireEntry&) const = default;
};

struct WorkspaceManifestCommand {
    std::string session_id;
    std::string workspace_id;
    std::uint64_t revision{};
    std::string manifest_sha256;
    std::vector<WorkspaceWireEntry> entries;
    [[nodiscard]] bool operator==(const WorkspaceManifestCommand&) const = default;
};

struct WorkspaceDiffReply {
    bool accepted{};
    std::uint64_t current_revision{};
    std::vector<std::string> requested_file_paths;
    std::string reason_code;
    [[nodiscard]] bool operator==(const WorkspaceDiffReply&) const = default;
};

struct WorkspaceWireChunkDescriptor {
    std::uint32_t index{};
    std::uint64_t offset{};
    std::uint32_t size{};
    std::string sha256;
    [[nodiscard]] bool operator==(
        const WorkspaceWireChunkDescriptor&) const = default;
};

struct WorkspaceFilePlanCommand {
    std::string session_id;
    std::string workspace_id;
    std::uint64_t revision{};
    std::string transfer_id;
    std::string path;
    std::uint64_t total_size{};
    std::string sha256;
    std::vector<WorkspaceWireChunkDescriptor> chunks;
    [[nodiscard]] bool operator==(
        const WorkspaceFilePlanCommand&) const = default;
};

struct WorkspaceFilePlanReply {
    bool accepted{};
    std::vector<std::uint32_t> missing_chunks;
    std::string reason_code;
    [[nodiscard]] bool operator==(
        const WorkspaceFilePlanReply&) const = default;
};

struct WorkspaceFileChunkCommand {
    std::string session_id;
    std::string workspace_id;
    std::uint64_t revision{};
    std::string transfer_id;
    std::uint32_t index{};
    std::vector<std::byte> bytes;
    [[nodiscard]] bool operator==(
        const WorkspaceFileChunkCommand&) const = default;
};

struct WorkspaceCommitCommand {
    std::string session_id;
    std::string workspace_id;
    std::uint64_t revision{};
    std::string manifest_sha256;
    [[nodiscard]] bool operator==(const WorkspaceCommitCommand&) const = default;
};

struct WorkspaceCommitReply {
    bool accepted{};
    std::uint64_t revision{};
    std::string manifest_sha256;
    std::string reason_code;
    [[nodiscard]] bool operator==(const WorkspaceCommitReply&) const = default;
};

void validate_workspace_manifest_command(const WorkspaceManifestCommand& value);
void validate_workspace_diff_reply(const WorkspaceDiffReply& value);
void validate_workspace_file_plan_command(const WorkspaceFilePlanCommand& value);
void validate_workspace_file_plan_reply(const WorkspaceFilePlanReply& value);
void validate_workspace_file_chunk_command(const WorkspaceFileChunkCommand& value);
void validate_workspace_commit_command(const WorkspaceCommitCommand& value);
void validate_workspace_commit_reply(const WorkspaceCommitReply& value);

[[nodiscard]] std::vector<std::byte> encode_workspace_manifest_command(
    const WorkspaceManifestCommand& value);
[[nodiscard]] WorkspaceManifestCommand decode_workspace_manifest_command(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_workspace_diff_reply(
    const WorkspaceDiffReply& value);
[[nodiscard]] WorkspaceDiffReply decode_workspace_diff_reply(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_workspace_file_plan_command(
    const WorkspaceFilePlanCommand& value);
[[nodiscard]] WorkspaceFilePlanCommand decode_workspace_file_plan_command(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_workspace_file_plan_reply(
    const WorkspaceFilePlanReply& value);
[[nodiscard]] WorkspaceFilePlanReply decode_workspace_file_plan_reply(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_workspace_file_chunk_command(
    const WorkspaceFileChunkCommand& value);
[[nodiscard]] WorkspaceFileChunkCommand decode_workspace_file_chunk_command(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_workspace_commit_command(
    const WorkspaceCommitCommand& value);
[[nodiscard]] WorkspaceCommitCommand decode_workspace_commit_command(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_workspace_commit_reply(
    const WorkspaceCommitReply& value);
[[nodiscard]] WorkspaceCommitReply decode_workspace_commit_reply(
    std::span<const std::byte> payload);

}  // namespace rwn::protocol
