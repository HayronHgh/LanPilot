#pragma once

#include "rwn/core/workspace_scope.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace rwn::core {

enum class TransferEncoding { identity, zstd };

[[nodiscard]] TransferEncoding choose_transfer_encoding(
    const std::filesystem::path& path, bool zstd_available);

struct ChunkDescriptor {
    std::size_t index{};
    std::uint64_t offset{};
    std::size_t size{};
    std::string sha256;
};

struct FileTransferPlan {
    std::string transfer_id;
    std::filesystem::path relative_path;
    std::uint64_t total_size{};
    std::string sha256;
    std::vector<ChunkDescriptor> chunks;
};

class DurableFileSystem {
public:
    virtual ~DurableFileSystem() = default;
    virtual void flush_file(const std::filesystem::path& path) = 0;
    virtual void atomic_replace(
        const std::filesystem::path& staging,
        const std::filesystem::path& destination) = 0;
};

class FileTransfer {
public:
    FileTransfer(
        WorkspaceScope scope, FileTransferPlan plan, DurableFileSystem& filesystem);

    void accept_chunk(std::size_t index, std::span<const std::byte> bytes);
    [[nodiscard]] std::vector<std::size_t> missing_chunks() const;
    [[nodiscard]] bool complete() const;
    void finalize();

    [[nodiscard]] const std::filesystem::path& destination_path() const {
        return destination_path_;
    }
    [[nodiscard]] const std::filesystem::path& staging_path() const {
        return staging_path_;
    }

private:
    void validate_plan() const;
    void recover_verified_chunks();
    [[nodiscard]] const ChunkDescriptor& descriptor(std::size_t index) const;

    WorkspaceScope scope_;
    FileTransferPlan plan_;
    DurableFileSystem& filesystem_;
    std::filesystem::path destination_path_;
    std::filesystem::path staging_path_;
    std::set<std::size_t> confirmed_;
};

}  // namespace rwn::core
