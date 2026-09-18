#pragma once

#include "rwn/core/build.hpp"
#include "rwn/core/audit.hpp"
#include "rwn/core/file_transfer.hpp"
#include "rwn/core/workspace_scope.hpp"
#include "rwn/core/workspace_sync.hpp"

#include <filesystem>
#include <map>
#include <string>

namespace rwn::core {

struct ArtifactPublishRequest {
    std::string id;
    std::string build_id;
    std::uint64_t source_revision{};
    std::string name;
    std::string platform;
    std::string architecture;
    std::filesystem::path source_relative_path;
    std::string principal_id;
    std::string device_id;
    std::string session_id;
    TimePoint occurred_at{};
};

class ArtifactStore {
public:
    ArtifactStore(
        const BuildQueue& builds, std::filesystem::path build_workspace_root,
        std::filesystem::path storage_root, DurableFileSystem& filesystem,
        AuditLog& audit);

    [[nodiscard]] Artifact publish(const ArtifactPublishRequest& request);
    [[nodiscard]] const Artifact& metadata(const std::string& artifact_id) const;
    [[nodiscard]] std::filesystem::path object_path(
        const std::string& artifact_id) const;
    [[nodiscard]] bool verify(const std::string& artifact_id) const;
    [[nodiscard]] FileTransferPlan download_plan(
        const std::string& artifact_id, std::string transfer_id,
        std::filesystem::path destination_relative_path,
        std::size_t chunk_size = ChunkResumeLedger::max_chunk_size) const;

private:
    struct Record {
        Artifact metadata;
        std::filesystem::path object_relative_path;
    };

    void load_records();
    [[nodiscard]] std::filesystem::path stage_record(
        const Record& record) const;
    void commit_record(
        const Record& record,
        const std::filesystem::path& staging) const;

    const BuildQueue& builds_;
    WorkspaceScope build_scope_;
    WorkspaceScope storage_scope_;
    DurableFileSystem& filesystem_;
    AuditLog& audit_;
    std::map<std::string, Record, std::less<>> records_;
};

}  // namespace rwn::core
