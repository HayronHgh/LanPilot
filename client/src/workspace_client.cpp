#include "rwn/client/workspace_client.hpp"

#include "rwn/core/content_hash.hpp"
#include "rwn/core/workspace_scope.hpp"
#include "rwn/core/workspace_manifest.hpp"
#include "rwn/protocol/envelope.hpp"

#include <fstream>
#include <limits>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace rwn::client {
namespace {

[[nodiscard]] rwn::protocol::WorkspaceWireEntryKind wire_kind(
    const rwn::core::WorkspaceEntryKind kind) {
    switch (kind) {
        case rwn::core::WorkspaceEntryKind::file:
            return rwn::protocol::WorkspaceWireEntryKind::file;
        case rwn::core::WorkspaceEntryKind::directory:
            return rwn::protocol::WorkspaceWireEntryKind::directory;
        case rwn::core::WorkspaceEntryKind::symlink:
            return rwn::protocol::WorkspaceWireEntryKind::symlink;
    }
    throw std::invalid_argument("unsupported workspace entry kind");
}

[[nodiscard]] rwn::protocol::WorkspaceManifestCommand wire_manifest(
    const rwn::core::WorkspaceManifest& manifest,
    const std::string_view session_id) {
    rwn::core::validate_manifest(manifest);
    rwn::core::reject_case_collisions(manifest);
    rwn::protocol::WorkspaceManifestCommand result{
        .session_id = std::string(session_id),
        .workspace_id = manifest.workspace_id,
        .revision = manifest.revision,
        .manifest_sha256 = rwn::core::manifest_content_hash(manifest),
        .entries = {},
    };
    result.entries.reserve(manifest.entries.size());
    for (const auto& entry : manifest.entries) {
        result.entries.push_back({
            .path = entry.path,
            .kind = wire_kind(entry.kind),
            .size = entry.size,
            .sha256 = entry.content_hash,
            .mode = entry.mode,
            .symlink_target = entry.symlink_target,
        });
    }
    rwn::protocol::validate_workspace_manifest_command(result);
    return result;
}

[[nodiscard]] rwn::protocol::Envelope require_reply(
    rwn::transport::ReliableStream& stream,
    const rwn::protocol::MessageType type,
    const std::string_view correlation_id) {
    auto reply = rwn::protocol::decode(stream.read());
    if (reply.version != 1 || reply.type != type ||
        reply.correlation_id != correlation_id ||
        !reply.unknown_fields.empty()) {
        throw std::invalid_argument("workspace reply envelope is invalid");
    }
    return reply;
}

[[nodiscard]] std::vector<std::byte> read_chunk(
    const std::filesystem::path& path,
    const std::uint64_t offset,
    const std::size_t size) {
    if (offset > static_cast<std::uint64_t>(
                     std::numeric_limits<std::streamoff>::max())) {
        throw std::length_error("workspace source offset exceeds stream limit");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("workspace source file could not open");
    input.seekg(static_cast<std::streamoff>(offset));
    std::vector<std::byte> bytes(size);
    input.read(
        reinterpret_cast<char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
    if (input.gcount() != static_cast<std::streamsize>(bytes.size())) {
        throw std::runtime_error("workspace source file changed during sync");
    }
    return bytes;
}

[[nodiscard]] rwn::protocol::WorkspaceFilePlanCommand make_plan(
    const std::filesystem::path& path,
    const rwn::core::WorkspaceEntry& entry,
    const std::string_view session_id,
    const std::string_view workspace_id,
    const std::uint64_t revision,
    std::string transfer_id) {
    if (entry.size == 0 || std::filesystem::file_size(path) != entry.size ||
        rwn::core::sha256_file(path) != entry.content_hash) {
        throw std::runtime_error("workspace source changed after manifest scan");
    }
    rwn::protocol::WorkspaceFilePlanCommand plan{
        .session_id = std::string(session_id),
        .workspace_id = std::string(workspace_id),
        .revision = revision,
        .transfer_id = std::move(transfer_id),
        .path = entry.path,
        .total_size = entry.size,
        .sha256 = entry.content_hash,
        .chunks = {},
    };
    std::uint64_t offset{};
    std::uint32_t index{};
    while (offset < entry.size) {
        const auto remaining = entry.size - offset;
        const auto size = static_cast<std::size_t>(std::min<std::uint64_t>(
            remaining, rwn::protocol::max_workspace_chunk_bytes));
        const auto bytes = read_chunk(path, offset, size);
        plan.chunks.push_back({
            .index = index++,
            .offset = offset,
            .size = static_cast<std::uint32_t>(size),
            .sha256 = rwn::core::sha256_hex(bytes),
        });
        offset += size;
    }
    rwn::protocol::validate_workspace_file_plan_command(plan);
    return plan;
}

}  // namespace

WorkspaceSyncResult sync_workspace(
    rwn::transport::ReliableStream& stream,
    const std::filesystem::path& source_root,
    const rwn::core::WorkspaceManifest& manifest,
    const std::string_view session_id) {
    const auto command = wire_manifest(manifest, session_id);
    const auto manifest_correlation =
        "manifest-" + std::string(session_id);
    stream.write(rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::workspace_manifest,
        .correlation_id = manifest_correlation,
        .payload = rwn::protocol::encode_workspace_manifest_command(command),
        .unknown_fields = {},
    }));
    const auto diff = rwn::protocol::decode_workspace_diff_reply(
        require_reply(
            stream, rwn::protocol::MessageType::workspace_diff,
            manifest_correlation).payload);
    if (!diff.accepted) return {.diff = diff, .commit = std::nullopt};

    rwn::core::WorkspaceScope source(source_root);
    std::map<std::string, const rwn::core::WorkspaceEntry*, std::less<>> files;
    for (const auto& entry : manifest.entries) {
        if (entry.kind == rwn::core::WorkspaceEntryKind::file) {
            files.emplace(entry.path, &entry);
        }
    }
    std::size_t transfer_number{};
    for (const auto& requested : diff.requested_file_paths) {
        const auto found = files.find(requested);
        if (found == files.end()) {
            throw std::invalid_argument(
                "Node requested a file outside the source manifest");
        }
        const auto& entry = *found->second;
        if (entry.size == 0) continue;
        const auto transfer_id = "file-" + std::to_string(manifest.revision) +
            "-" + std::to_string(transfer_number++);
        const auto plan = make_plan(
            source.resolve(entry.path), entry, session_id,
            manifest.workspace_id, manifest.revision, transfer_id);
        const auto correlation = "plan-" + transfer_id;
        stream.write(rwn::protocol::encode({
            .version = 1,
            .type = rwn::protocol::MessageType::workspace_file_plan,
            .correlation_id = correlation,
            .payload =
                rwn::protocol::encode_workspace_file_plan_command(plan),
            .unknown_fields = {},
        }));
        const auto reply = rwn::protocol::decode_workspace_file_plan_reply(
            require_reply(
                stream, rwn::protocol::MessageType::workspace_file_plan,
                correlation).payload);
        if (!reply.accepted) {
            throw std::runtime_error("Node rejected workspace file plan");
        }
        for (const auto index : reply.missing_chunks) {
            if (index >= plan.chunks.size()) {
                throw std::invalid_argument(
                    "Node requested an out-of-range workspace chunk");
            }
            const auto& chunk = plan.chunks[index];
            stream.write(rwn::protocol::encode({
                .version = 1,
                .type = rwn::protocol::MessageType::workspace_file_chunk,
                .correlation_id = transfer_id,
                .payload = rwn::protocol::encode_workspace_file_chunk_command({
                    .session_id = std::string(session_id),
                    .workspace_id = manifest.workspace_id,
                    .revision = manifest.revision,
                    .transfer_id = transfer_id,
                    .index = index,
                    .bytes = read_chunk(
                        source.resolve(entry.path), chunk.offset, chunk.size),
                }),
                .unknown_fields = {},
            }));
        }
    }

    const auto commit_correlation = "commit-" + std::string(session_id);
    stream.write(rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::workspace_commit,
        .correlation_id = commit_correlation,
        .payload = rwn::protocol::encode_workspace_commit_command({
            .session_id = std::string(session_id),
            .workspace_id = manifest.workspace_id,
            .revision = manifest.revision,
            .manifest_sha256 = command.manifest_sha256,
        }),
        .unknown_fields = {},
    }));
    const auto committed = rwn::protocol::decode_workspace_commit_reply(
        require_reply(
            stream, rwn::protocol::MessageType::workspace_commit,
            commit_correlation).payload);
    return {.diff = diff, .commit = committed};
}

}  // namespace rwn::client
