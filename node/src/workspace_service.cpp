#include "rwn/node/workspace_service.hpp"

#include "rwn/core/content_hash.hpp"
#include "rwn/core/ignore_rules.hpp"
#include "rwn/core/workspace_manifest.hpp"
#include "rwn/protocol/envelope.hpp"

#include <algorithm>
#include <charconv>
#include <fstream>
#include <iterator>
#include <ranges>
#include <stdexcept>
#include <utility>
#include <vector>

namespace rwn::node {
namespace {

[[nodiscard]] rwn::core::WorkspaceEntryKind core_kind(
    const rwn::protocol::WorkspaceWireEntryKind kind) {
    switch (kind) {
        case rwn::protocol::WorkspaceWireEntryKind::file:
            return rwn::core::WorkspaceEntryKind::file;
        case rwn::protocol::WorkspaceWireEntryKind::directory:
            return rwn::core::WorkspaceEntryKind::directory;
        case rwn::protocol::WorkspaceWireEntryKind::symlink:
            return rwn::core::WorkspaceEntryKind::symlink;
    }
    throw std::invalid_argument("unsupported workspace entry kind");
}

[[nodiscard]] rwn::core::WorkspaceManifest core_manifest(
    const rwn::protocol::WorkspaceManifestCommand& command) {
    rwn::core::WorkspaceManifest result{
        .workspace_id = command.workspace_id,
        .revision = command.revision,
        .entries = {},
    };
    result.entries.reserve(command.entries.size());
    for (const auto& entry : command.entries) {
        result.entries.push_back({
            .path = entry.path,
            .kind = core_kind(entry.kind),
            .size = entry.size,
            .content_hash = entry.sha256,
            .mode = entry.mode,
            .symlink_target = entry.symlink_target,
        });
    }
    rwn::core::validate_manifest(result);
    rwn::core::reject_case_collisions(result);
    return result;
}

[[nodiscard]] bool same_file(
    const std::filesystem::path& path,
    const rwn::core::WorkspaceEntry& entry) {
    const auto status = std::filesystem::symlink_status(path);
    return std::filesystem::is_regular_file(status) &&
        std::filesystem::file_size(path) == entry.size &&
        rwn::core::sha256_file(path) == entry.content_hash;
}

[[nodiscard]] bool expected_type(
    const std::filesystem::file_status status,
    const rwn::core::WorkspaceEntryKind kind) {
    switch (kind) {
        case rwn::core::WorkspaceEntryKind::file:
            return std::filesystem::is_regular_file(status);
        case rwn::core::WorkspaceEntryKind::directory:
            return std::filesystem::is_directory(status);
        case rwn::core::WorkspaceEntryKind::symlink:
            return std::filesystem::is_symlink(status);
    }
    return false;
}

[[nodiscard]] const rwn::core::WorkspaceEntry& require_entry(
    const rwn::core::WorkspaceManifest& manifest,
    const std::string_view path) {
    const auto found = std::ranges::lower_bound(
        manifest.entries, path, {}, &rwn::core::WorkspaceEntry::path);
    if (found == manifest.entries.end() || found->path != path) {
        throw std::invalid_argument("workspace plan path is not in manifest");
    }
    return *found;
}

[[nodiscard]] std::size_t depth(const std::filesystem::path& path) {
    return static_cast<std::size_t>(std::ranges::distance(path));
}

[[nodiscard]] WorkspaceMirrorState load_state(
    const std::filesystem::path& path,
    const std::string_view expected_workspace_id) {
    if (!std::filesystem::exists(path)) {
        return {
            .workspace_id = std::string(expected_workspace_id),
            .revision = 0,
            .manifest_sha256 = {},
        };
    }
    if (!std::filesystem::is_regular_file(path) ||
        std::filesystem::file_size(path) > 16U * 1024U) {
        throw std::invalid_argument("workspace state file is invalid");
    }
    std::ifstream input(path, std::ios::binary);
    const std::string text{
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()};
    if (input.bad()) {
        throw std::runtime_error("workspace state file could not be read");
    }
    const auto first = text.find('\n');
    const auto second = first == std::string::npos
        ? std::string::npos
        : text.find('\n', first + 1);
    const auto third = second == std::string::npos
        ? std::string::npos
        : text.find('\n', second + 1);
    if (first == std::string::npos || second == std::string::npos ||
        third != text.size() - 1 ||
        !text.starts_with("workspace_id=") ||
        text.substr(first + 1, 9) != "revision=" ||
        text.substr(second + 1, 16) != "manifest_sha256=") {
        throw std::invalid_argument("workspace state schema is invalid");
    }
    WorkspaceMirrorState result{
        .workspace_id = text.substr(13, first - 13),
        .revision = 0,
        .manifest_sha256 = text.substr(second + 17, third - second - 17),
    };
    const auto revision_text = std::string_view(text).substr(
        first + 10, second - first - 10);
    const auto parsed = std::from_chars(
        revision_text.data(), revision_text.data() + revision_text.size(),
        result.revision);
    if (result.workspace_id != expected_workspace_id ||
        result.revision == 0 ||
        !rwn::core::is_sha256_hex(result.manifest_sha256) ||
        parsed.ec != std::errc{} ||
        parsed.ptr != revision_text.data() + revision_text.size()) {
        throw std::invalid_argument("workspace state values are invalid");
    }
    return result;
}

}  // namespace

WorkspaceMirrorStateFile::WorkspaceMirrorStateFile(
    std::filesystem::path state_root,
    std::filesystem::path relative_path,
    std::string workspace_id,
    rwn::core::DurableFileSystem& filesystem)
    : scope_(std::move(state_root)),
      path_(scope_.resolve(relative_path)),
      filesystem_(filesystem),
      state_(load_state(path_, workspace_id)) {
    if (!rwn::core::is_canonical_workspace_path(
            relative_path.generic_string()) || workspace_id.empty() ||
        workspace_id.size() > 64) {
        throw std::invalid_argument("workspace state options are invalid");
    }
}

void WorkspaceMirrorStateFile::persist(
    const std::uint64_t revision,
    std::string manifest_sha256) {
    if (revision == 0 || revision <= state_.revision ||
        !rwn::core::is_sha256_hex(manifest_sha256)) {
        throw std::invalid_argument("workspace state advance is invalid");
    }
    std::filesystem::create_directories(path_.parent_path());
    const auto staging = path_.parent_path() /
        ("." + path_.filename().string() + ".rwn-state.part");
    {
        std::ofstream output(staging, std::ios::binary | std::ios::trunc);
        output << "workspace_id=" << state_.workspace_id << '\n'
               << "revision=" << revision << '\n'
               << "manifest_sha256=" << manifest_sha256 << '\n';
        output.flush();
        if (!output) {
            throw std::runtime_error("workspace state staging write failed");
        }
    }
    filesystem_.flush_file(staging);
    filesystem_.atomic_replace(staging, path_);
    state_.revision = revision;
    state_.manifest_sha256 = std::move(manifest_sha256);
}

WorkspaceMirrorService::WorkspaceMirrorService(
    std::filesystem::path mirror_root,
    std::string workspace_id,
    const std::uint64_t current_revision,
    rwn::core::DurableFileSystem& filesystem)
    : scope_(std::move(mirror_root)),
      workspace_id_(std::move(workspace_id)),
      current_revision_(current_revision),
      filesystem_(filesystem) {
    if (workspace_id_.empty() || workspace_id_.size() > 64) {
        throw std::invalid_argument("workspace mirror identity is invalid");
    }
    std::filesystem::create_directories(scope_.root());
    if (!std::filesystem::is_directory(scope_.root())) {
        throw std::invalid_argument("workspace mirror root is not a directory");
    }
}

rwn::protocol::WorkspaceDiffReply WorkspaceMirrorService::begin(
    const rwn::protocol::WorkspaceManifestCommand& command) {
    rwn::protocol::validate_workspace_manifest_command(command);
    if (pending_manifest_.has_value()) {
        throw std::logic_error("workspace transaction is already active");
    }
    if (command.workspace_id != workspace_id_) {
        return {
            .accepted = false,
            .current_revision = current_revision_,
            .requested_file_paths = {},
            .reason_code = "workspace_scope_denied",
        };
    }
    if (command.revision != current_revision_ + 1) {
        return {
            .accepted = false,
            .current_revision = current_revision_,
            .requested_file_paths = {},
            .reason_code = "revision_conflict",
        };
    }
    auto manifest = core_manifest(command);
    if (rwn::core::manifest_content_hash(manifest) != command.manifest_sha256) {
        throw std::invalid_argument("workspace manifest hash binding failed");
    }

    std::set<std::string, std::less<>> requested;
    for (const auto& entry : manifest.entries) {
        if (entry.kind != rwn::core::WorkspaceEntryKind::file) continue;
        reject_symlink_ancestor(entry.path);
        const auto path = scope_.root() / entry.path;
        if (!same_file(path, entry)) requested.insert(entry.path);
    }
    pending_session_id_ = command.session_id;
    pending_manifest_sha256_ = command.manifest_sha256;
    requested_files_ = requested;
    pending_manifest_ = std::move(manifest);
    return {
        .accepted = true,
        .current_revision = current_revision_,
        .requested_file_paths = {requested.begin(), requested.end()},
        .reason_code = "workspace_diff_ready",
    };
}

rwn::protocol::WorkspaceFilePlanReply WorkspaceMirrorService::accept_plan(
    const rwn::protocol::WorkspaceFilePlanCommand& command) {
    rwn::protocol::validate_workspace_file_plan_command(command);
    require_transaction_identity(
        command.session_id, command.workspace_id, command.revision);
    if (!requested_files_.contains(command.path)) {
        throw std::invalid_argument("workspace file was not requested");
    }
    const auto& entry = require_entry(*pending_manifest_, command.path);
    if (entry.kind != rwn::core::WorkspaceEntryKind::file ||
        entry.size != command.total_size ||
        entry.content_hash != command.sha256 ||
        command.total_size == 0) {
        throw std::invalid_argument("workspace file plan disagrees with manifest");
    }
    if (transfer_by_path_.contains(command.path) ||
        transfers_.contains(command.transfer_id)) {
        throw std::invalid_argument("workspace file plan is duplicated");
    }
    rwn::core::FileTransferPlan plan{
        .transfer_id = command.transfer_id,
        .relative_path = command.path,
        .total_size = command.total_size,
        .sha256 = command.sha256,
        .chunks = {},
    };
    plan.chunks.reserve(command.chunks.size());
    for (const auto& chunk : command.chunks) {
        plan.chunks.push_back({
            .index = chunk.index,
            .offset = chunk.offset,
            .size = chunk.size,
            .sha256 = chunk.sha256,
        });
    }
    auto transfer = std::make_unique<rwn::core::FileTransfer>(
        scope_, std::move(plan), filesystem_);
    const auto missing = transfer->missing_chunks();
    std::vector<std::uint32_t> wire_missing;
    wire_missing.reserve(missing.size());
    for (const auto index : missing) {
        wire_missing.push_back(static_cast<std::uint32_t>(index));
    }
    transfer_by_path_.emplace(command.path, command.transfer_id);
    transfers_.emplace(command.transfer_id, std::move(transfer));
    return {
        .accepted = true,
        .missing_chunks = std::move(wire_missing),
        .reason_code = "file_plan_ready",
    };
}

void WorkspaceMirrorService::accept_chunk(
    const rwn::protocol::WorkspaceFileChunkCommand& command) {
    rwn::protocol::validate_workspace_file_chunk_command(command);
    require_transaction_identity(
        command.session_id, command.workspace_id, command.revision);
    const auto found = transfers_.find(command.transfer_id);
    if (found == transfers_.end()) {
        throw std::invalid_argument("workspace chunk transfer is unknown");
    }
    found->second->accept_chunk(command.index, command.bytes);
}

rwn::protocol::WorkspaceCommitReply WorkspaceMirrorService::commit(
    const rwn::protocol::WorkspaceCommitCommand& command) {
    rwn::protocol::validate_workspace_commit_command(command);
    require_transaction_identity(
        command.session_id, command.workspace_id, command.revision);
    if (command.manifest_sha256 != pending_manifest_sha256_) {
        throw std::invalid_argument("workspace commit hash binding failed");
    }
    for (const auto& path : requested_files_) {
        const auto& entry = require_entry(*pending_manifest_, path);
        if (entry.size == 0) continue;
        const auto transfer = transfer_by_path_.find(path);
        if (transfer == transfer_by_path_.end() ||
            !transfers_.at(transfer->second)->complete()) {
            return {
                .accepted = false,
                .revision = current_revision_,
                .manifest_sha256 = current_manifest_sha256_,
                .reason_code = "workspace_incomplete",
            };
        }
    }

    prepare_destination_types();
    materialize_directories();
    finalize_requested_files();
    materialize_empty_files_and_symlinks();
    remove_extra_entries();
    apply_modes();
    verify_final_manifest();

    current_revision_ = pending_manifest_->revision;
    current_manifest_sha256_ = pending_manifest_sha256_;
    pending_manifest_.reset();
    pending_session_id_.clear();
    pending_manifest_sha256_.clear();
    requested_files_.clear();
    transfer_by_path_.clear();
    transfers_.clear();
    return {
        .accepted = true,
        .revision = current_revision_,
        .manifest_sha256 = current_manifest_sha256_,
        .reason_code = "workspace_committed",
    };
}

void WorkspaceMirrorService::require_transaction_identity(
    const std::string_view session_id,
    const std::string_view workspace_id,
    const std::uint64_t revision) const {
    if (!pending_manifest_.has_value() || session_id != pending_session_id_ ||
        workspace_id != workspace_id_ ||
        revision != pending_manifest_->revision) {
        throw std::invalid_argument("workspace transaction identity mismatch");
    }
}

void WorkspaceMirrorService::reject_symlink_ancestor(
    const std::filesystem::path& relative) const {
    std::filesystem::path current = scope_.root();
    auto part = relative.begin();
    const auto end = relative.end();
    for (; part != end; ++part) {
        const auto next = std::next(part);
        if (next == end) break;
        current /= *part;
        if (std::filesystem::is_symlink(
                std::filesystem::symlink_status(current))) {
            throw std::invalid_argument(
                "workspace destination has a symlink ancestor");
        }
    }
}

void WorkspaceMirrorService::prepare_destination_types() {
    for (const auto& entry : pending_manifest_->entries) {
        reject_symlink_ancestor(entry.path);
        const auto path = scope_.root() / entry.path;
        const auto status = std::filesystem::symlink_status(path);
        if (std::filesystem::exists(status) &&
            !expected_type(status, entry.kind)) {
            std::filesystem::remove_all(path);
        }
    }
}

void WorkspaceMirrorService::materialize_directories() {
    for (const auto& entry : pending_manifest_->entries) {
        if (entry.kind == rwn::core::WorkspaceEntryKind::directory) {
            std::filesystem::create_directories(scope_.root() / entry.path);
        }
    }
}

void WorkspaceMirrorService::finalize_requested_files() {
    for (const auto& [path, transfer_id] : transfer_by_path_) {
        static_cast<void>(path);
        transfers_.at(transfer_id)->finalize();
    }
}

void WorkspaceMirrorService::materialize_empty_files_and_symlinks() {
    for (const auto& entry : pending_manifest_->entries) {
        if (entry.kind == rwn::core::WorkspaceEntryKind::file &&
            entry.size == 0 && requested_files_.contains(entry.path)) {
            const auto destination = scope_.root() / entry.path;
            std::filesystem::create_directories(destination.parent_path());
            const auto staging = destination.parent_path() /
                ("." + destination.filename().string() + ".rwn-empty.part");
            {
                std::ofstream output(staging, std::ios::binary | std::ios::trunc);
                if (!output) {
                    throw std::runtime_error("empty workspace staging failed");
                }
            }
            filesystem_.flush_file(staging);
            filesystem_.atomic_replace(staging, destination);
        } else if (entry.kind == rwn::core::WorkspaceEntryKind::symlink) {
            const auto destination = scope_.root() / entry.path;
            std::filesystem::create_directories(destination.parent_path());
            const auto target_relative =
                (std::filesystem::path(entry.path).parent_path() /
                 entry.symlink_target).lexically_normal();
            if (target_relative.empty() || target_relative.is_absolute() ||
                !scope_.contains_resolved(scope_.root() / target_relative)) {
                throw std::invalid_argument("workspace symlink target escapes mirror");
            }
            reject_symlink_ancestor(target_relative);
            const auto staging = destination.parent_path() /
                ("." + destination.filename().string() + ".rwn-link.part");
            std::filesystem::remove(staging);
            std::filesystem::create_symlink(entry.symlink_target, staging);
            filesystem_.atomic_replace(staging, destination);
        }
    }
}

void WorkspaceMirrorService::remove_extra_entries() {
    std::set<std::string, std::less<>> desired;
    for (const auto& entry : pending_manifest_->entries) {
        desired.insert(entry.path);
    }
    std::vector<std::filesystem::path> extras;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(
             scope_.root(),
             std::filesystem::directory_options::skip_permission_denied)) {
        const auto relative = entry.path().lexically_relative(scope_.root());
        if (!desired.contains(relative.generic_string())) {
            extras.push_back(relative);
        }
    }
    std::ranges::sort(extras, [](const auto& left, const auto& right) {
        const auto left_depth = depth(left);
        const auto right_depth = depth(right);
        return left_depth != right_depth ? left_depth > right_depth
                                         : left.generic_string() >
                                               right.generic_string();
    });
    for (const auto& relative : extras) {
        std::filesystem::remove_all(scope_.root() / relative);
    }
}

void WorkspaceMirrorService::apply_modes() {
    for (const auto& entry : pending_manifest_->entries) {
        if (entry.kind == rwn::core::WorkspaceEntryKind::symlink) continue;
        const auto permissions = entry.mode == 0755U
            ? std::filesystem::perms::owner_all |
                  std::filesystem::perms::group_read |
                  std::filesystem::perms::group_exec |
                  std::filesystem::perms::others_read |
                  std::filesystem::perms::others_exec
            : std::filesystem::perms::owner_read |
                  std::filesystem::perms::owner_write |
                  std::filesystem::perms::group_read |
                  std::filesystem::perms::others_read;
        std::filesystem::permissions(
            scope_.root() / entry.path, permissions,
            std::filesystem::perm_options::replace);
    }
}

void WorkspaceMirrorService::verify_final_manifest() const {
    std::set<std::string, std::less<>> executable;
    for (const auto& entry : pending_manifest_->entries) {
        if (entry.kind == rwn::core::WorkspaceEntryKind::file &&
            entry.mode == 0755U) {
            executable.insert(entry.path);
        }
    }
    const auto actual = rwn::core::build_workspace_manifest(
        scope_.root(),
        {
            .workspace_id = workspace_id_,
            .revision = pending_manifest_->revision,
            .ignore_rules = {},
            .executable_paths = std::move(executable),
        });
    if (actual.entries != pending_manifest_->entries ||
        rwn::core::manifest_content_hash(actual) != pending_manifest_sha256_) {
        throw std::runtime_error(
            "workspace mirror verification differs from source manifest");
    }
}

void serve_workspace_sync(
    WorkspaceMirrorService& service,
    rwn::transport::ReliableStream& stream) {
    const auto manifest_envelope = rwn::protocol::decode(stream.read());
    if (manifest_envelope.version != 1 ||
        manifest_envelope.type !=
            rwn::protocol::MessageType::workspace_manifest ||
        manifest_envelope.correlation_id.empty() ||
        !manifest_envelope.unknown_fields.empty()) {
        throw std::invalid_argument("workspace manifest envelope is invalid");
    }
    const auto diff = service.begin(
        rwn::protocol::decode_workspace_manifest_command(
            manifest_envelope.payload));
    stream.write(rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::workspace_diff,
        .correlation_id = manifest_envelope.correlation_id,
        .payload = rwn::protocol::encode_workspace_diff_reply(diff),
        .unknown_fields = {},
    }));
    if (!diff.accepted) return;

    constexpr std::size_t maximum_transaction_messages = 1'000'000;
    for (std::size_t count = 0; count < maximum_transaction_messages; ++count) {
        const auto envelope = rwn::protocol::decode(stream.read());
        if (envelope.version != 1 || envelope.correlation_id.empty() ||
            !envelope.unknown_fields.empty()) {
            throw std::invalid_argument("workspace transaction envelope is invalid");
        }
        switch (envelope.type) {
            case rwn::protocol::MessageType::workspace_file_plan: {
                const auto reply = service.accept_plan(
                    rwn::protocol::decode_workspace_file_plan_command(
                        envelope.payload));
                stream.write(rwn::protocol::encode({
                    .version = 1,
                    .type = rwn::protocol::MessageType::workspace_file_plan,
                    .correlation_id = envelope.correlation_id,
                    .payload =
                        rwn::protocol::encode_workspace_file_plan_reply(reply),
                    .unknown_fields = {},
                }));
                break;
            }
            case rwn::protocol::MessageType::workspace_file_chunk:
                service.accept_chunk(
                    rwn::protocol::decode_workspace_file_chunk_command(
                        envelope.payload));
                break;
            case rwn::protocol::MessageType::workspace_commit: {
                const auto reply = service.commit(
                    rwn::protocol::decode_workspace_commit_command(
                        envelope.payload));
                stream.write(rwn::protocol::encode({
                    .version = 1,
                    .type = rwn::protocol::MessageType::workspace_commit,
                    .correlation_id = envelope.correlation_id,
                    .payload = rwn::protocol::encode_workspace_commit_reply(
                        reply),
                    .unknown_fields = {},
                }));
                return;
            }
            default:
                throw std::invalid_argument(
                    "workspace transaction message type is invalid");
        }
    }
    throw std::length_error("workspace transaction message count exceeded");
}

}  // namespace rwn::node
