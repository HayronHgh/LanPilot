#include "rwn/core/file_transfer.hpp"

#include "rwn/core/content_hash.hpp"
#include "rwn/core/workspace_sync.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <utility>

namespace rwn::core {
namespace {

bool valid_transfer_id(const std::string_view value) {
    return !value.empty() && value.size() <= 64 &&
           std::ranges::all_of(value, [](const unsigned char character) {
               return std::isalnum(character) != 0 || character == '-';
           });
}

std::vector<std::byte> read_range(
    const std::filesystem::path& path, const std::uint64_t offset,
    const std::size_t size) {
    if (offset > static_cast<std::uint64_t>(
                     std::numeric_limits<std::streamoff>::max())) {
        throw std::length_error("chunk offset exceeds stream limit");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("staging file could not be opened");
    }
    input.seekg(static_cast<std::streamoff>(offset));
    std::vector<std::byte> result(size);
    input.read(reinterpret_cast<char*>(result.data()),
               static_cast<std::streamsize>(size));
    if (input.gcount() != static_cast<std::streamsize>(size)) {
        throw std::runtime_error("staging chunk could not be read");
    }
    return result;
}

}  // namespace

TransferEncoding choose_transfer_encoding(
    const std::filesystem::path& path, const bool zstd_available) {
    if (!zstd_available) {
        return TransferEncoding::identity;
    }
    auto extension = path.extension().string();
    std::ranges::transform(extension, extension.begin(), [](const unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    constexpr std::string_view already_compressed[]{
        ".png", ".jpg", ".jpeg", ".zip", ".gz", ".zst", ".mp4", ".dmg",
    };
    return std::ranges::find(already_compressed, extension) ==
                   std::end(already_compressed)
        ? TransferEncoding::zstd
        : TransferEncoding::identity;
}

FileTransfer::FileTransfer(
    WorkspaceScope scope, FileTransferPlan plan, DurableFileSystem& filesystem)
    : scope_(std::move(scope)), plan_(std::move(plan)), filesystem_(filesystem) {
    validate_plan();
    destination_path_ = scope_.resolve(plan_.relative_path);
    const auto staging_name = "." + destination_path_.filename().string() +
                              ".rwn-" + plan_.transfer_id + ".part";
    staging_path_ = destination_path_.parent_path() / staging_name;
    if (!scope_.contains_resolved(staging_path_)) {
        throw std::invalid_argument("staging file escapes workspace scope");
    }
    recover_verified_chunks();
}

void FileTransfer::validate_plan() const {
    if (!valid_transfer_id(plan_.transfer_id) ||
        !is_canonical_workspace_path(plan_.relative_path.generic_string()) ||
        plan_.total_size == 0 || !is_sha256_hex(plan_.sha256) ||
        plan_.chunks.empty()) {
        throw std::invalid_argument("invalid file transfer plan");
    }
    std::uint64_t expected_offset{};
    for (std::size_t index = 0; index < plan_.chunks.size(); ++index) {
        const auto& chunk = plan_.chunks[index];
        if (chunk.index != index || chunk.offset != expected_offset ||
            chunk.size == 0 || chunk.size > ChunkResumeLedger::max_chunk_size ||
            !is_sha256_hex(chunk.sha256)) {
            throw std::invalid_argument("invalid file transfer chunk layout");
        }
        expected_offset += chunk.size;
    }
    if (expected_offset != plan_.total_size) {
        throw std::invalid_argument("file transfer chunks do not cover total size");
    }
}

void FileTransfer::recover_verified_chunks() {
    if (!std::filesystem::exists(staging_path_)) {
        return;
    }
    if (!std::filesystem::is_regular_file(staging_path_)) {
        throw std::invalid_argument("staging path is not a regular file");
    }
    const auto existing_size = std::filesystem::file_size(staging_path_);
    for (const auto& chunk : plan_.chunks) {
        if (chunk.offset + chunk.size > existing_size) {
            continue;
        }
        const auto bytes = read_range(staging_path_, chunk.offset, chunk.size);
        if (sha256_hex(bytes) == chunk.sha256) {
            confirmed_.insert(chunk.index);
        }
    }
}

const ChunkDescriptor& FileTransfer::descriptor(const std::size_t index) const {
    if (index >= plan_.chunks.size()) {
        throw std::out_of_range("chunk index is outside transfer plan");
    }
    return plan_.chunks[index];
}

void FileTransfer::accept_chunk(
    const std::size_t index, const std::span<const std::byte> bytes) {
    const auto& chunk = descriptor(index);
    if (bytes.size() != chunk.size || sha256_hex(bytes) != chunk.sha256) {
        throw std::invalid_argument("chunk content hash mismatch");
    }
    std::filesystem::create_directories(destination_path_.parent_path());
    if (!std::filesystem::exists(staging_path_)) {
        std::ofstream create(staging_path_, std::ios::binary);
        if (!create) {
            throw std::runtime_error("staging file could not be created");
        }
    }
    if (chunk.offset > static_cast<std::uint64_t>(
                           std::numeric_limits<std::streamoff>::max())) {
        throw std::length_error("chunk offset exceeds stream limit");
    }
    std::fstream output(
        staging_path_, std::ios::binary | std::ios::in | std::ios::out);
    if (!output) {
        throw std::runtime_error("staging file could not be opened for update");
    }
    output.seekp(static_cast<std::streamoff>(chunk.offset));
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    output.flush();
    if (!output) {
        throw std::runtime_error("staging chunk could not be written");
    }
    output.close();
    filesystem_.flush_file(staging_path_);
    confirmed_.insert(index);
}

std::vector<std::size_t> FileTransfer::missing_chunks() const {
    std::vector<std::size_t> result;
    for (std::size_t index = 0; index < plan_.chunks.size(); ++index) {
        if (!confirmed_.contains(index)) {
            result.push_back(index);
        }
    }
    return result;
}

bool FileTransfer::complete() const {
    return confirmed_.size() == plan_.chunks.size();
}

void FileTransfer::finalize() {
    if (!complete()) {
        throw std::logic_error("incomplete transfer cannot be finalized");
    }
    if (std::filesystem::file_size(staging_path_) != plan_.total_size ||
        sha256_file(staging_path_) != plan_.sha256) {
        throw std::invalid_argument("complete file content hash mismatch");
    }
    filesystem_.flush_file(staging_path_);
    filesystem_.atomic_replace(staging_path_, destination_path_);
}

}  // namespace rwn::core
