#pragma once

#include "rwn/core/file_transfer.hpp"
#include "rwn/core/workspace_scope.hpp"
#include "rwn/core/workspace_sync.hpp"
#include "rwn/protocol/workspace_control.hpp"
#include "rwn/transport/transport.hpp"

#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>

namespace rwn::node {

struct WorkspaceMirrorState {
    std::string workspace_id;
    std::uint64_t revision{};
    std::string manifest_sha256;
};

class WorkspaceMirrorStateFile {
public:
    WorkspaceMirrorStateFile(
        std::filesystem::path state_root,
        std::filesystem::path relative_path,
        std::string workspace_id,
        rwn::core::DurableFileSystem& filesystem);

    [[nodiscard]] const WorkspaceMirrorState& state() const noexcept {
        return state_;
    }
    void persist(std::uint64_t revision, std::string manifest_sha256);

private:
    rwn::core::WorkspaceScope scope_;
    std::filesystem::path path_;
    rwn::core::DurableFileSystem& filesystem_;
    WorkspaceMirrorState state_;
};

class WorkspaceMirrorService {
public:
    WorkspaceMirrorService(
        std::filesystem::path mirror_root,
        std::string workspace_id,
        std::uint64_t current_revision,
        rwn::core::DurableFileSystem& filesystem);

    [[nodiscard]] rwn::protocol::WorkspaceDiffReply begin(
        const rwn::protocol::WorkspaceManifestCommand& command);
    [[nodiscard]] rwn::protocol::WorkspaceFilePlanReply accept_plan(
        const rwn::protocol::WorkspaceFilePlanCommand& command);
    void accept_chunk(
        const rwn::protocol::WorkspaceFileChunkCommand& command);
    [[nodiscard]] rwn::protocol::WorkspaceCommitReply commit(
        const rwn::protocol::WorkspaceCommitCommand& command);

    [[nodiscard]] std::uint64_t current_revision() const noexcept {
        return current_revision_;
    }
    [[nodiscard]] const std::string& current_manifest_sha256() const noexcept {
        return current_manifest_sha256_;
    }

private:
    void require_transaction_identity(
        std::string_view session_id,
        std::string_view workspace_id,
        std::uint64_t revision) const;
    void reject_symlink_ancestor(const std::filesystem::path& relative) const;
    void prepare_destination_types();
    void materialize_directories();
    void finalize_requested_files();
    void materialize_empty_files_and_symlinks();
    void remove_extra_entries();
    void apply_modes();
    void verify_final_manifest() const;

    rwn::core::WorkspaceScope scope_;
    std::string workspace_id_;
    std::uint64_t current_revision_{};
    std::string current_manifest_sha256_;
    rwn::core::DurableFileSystem& filesystem_;
    std::optional<rwn::core::WorkspaceManifest> pending_manifest_;
    std::string pending_session_id_;
    std::string pending_manifest_sha256_;
    std::set<std::string, std::less<>> requested_files_;
    std::map<std::string, std::string, std::less<>> transfer_by_path_;
    std::map<std::string, std::unique_ptr<rwn::core::FileTransfer>, std::less<>>
        transfers_;
};

void serve_workspace_sync(
    WorkspaceMirrorService& service,
    rwn::transport::ReliableStream& stream);

}  // namespace rwn::node
