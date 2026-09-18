#pragma once

#include "rwn/core/workspace_sync.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace rwn::core {

enum class ArchiveEntryKind { file, directory, symlink };

struct ArchiveEntry {
    ArchiveEntryKind kind{ArchiveEntryKind::file};
    std::string path;
    std::uint64_t uncompressed_size{};
    std::uint64_t compressed_size{};
    std::uint32_t mode{};
    std::string symlink_target;
};

struct ReleaseSecurityLimits {
    std::size_t maximum_entries{200'000};
    std::uint64_t maximum_total_bytes{16ULL * 1024ULL * 1024ULL * 1024ULL};
    std::uint64_t maximum_file_bytes{4ULL * 1024ULL * 1024ULL * 1024ULL};
    std::uint32_t maximum_compression_ratio{1000};
    std::size_t maximum_symlinks{4096};
};

struct ReleaseSecurityReport {
    std::string gate;
    std::size_t entries{};
    std::size_t files{};
    std::size_t directories{};
    std::size_t symlinks{};
    std::uint64_t total_uncompressed_bytes{};
    bool passed{};
};

[[nodiscard]] std::vector<ArchiveEntry> parse_archive_manifest(
    std::string_view content);
[[nodiscard]] ReleaseSecurityReport validate_archive_manifest(
    const std::vector<ArchiveEntry>& entries,
    ReleaseSecurityLimits limits = {});
[[nodiscard]] ReleaseSecurityReport validate_repository_release(
    const WorkspaceManifest& manifest,
    ReleaseSecurityLimits limits = {});
[[nodiscard]] std::string render_release_security_json(
    const ReleaseSecurityReport& report);

}  // namespace rwn::core
