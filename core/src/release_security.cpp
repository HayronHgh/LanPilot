#include "rwn/core/release_security.hpp"

#include "rwn/core/workspace_manifest.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <map>
#include <ranges>
#include <set>
#include <sstream>
#include <stdexcept>

namespace rwn::core {
namespace {

constexpr std::size_t maximum_manifest_bytes = 16U * 1024U * 1024U;

[[nodiscard]] std::string ascii_lower(std::string value) {
    std::ranges::transform(
        value, value.begin(), [](const unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return value;
}

[[nodiscard]] bool contains_release_metadata(const std::string_view path) {
    std::size_t offset{};
    while (offset < path.size()) {
        const auto separator = path.find('/', offset);
        const auto component = path.substr(
            offset, separator == std::string_view::npos
                        ? path.size() - offset
                        : separator - offset);
        const auto folded = ascii_lower(std::string(component));
        if (folded == ".git" || folded == ".gitmodules" ||
            folded == ".svn" || folded == ".hg") {
            return true;
        }
        if (separator == std::string_view::npos) break;
        offset = separator + 1U;
    }
    return false;
}

template <typename Integer>
[[nodiscard]] Integer decimal(const std::string_view value) {
    Integer result{};
    const auto parsed = std::from_chars(
        value.data(), value.data() + value.size(), result);
    if (value.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != value.data() + value.size()) {
        throw std::invalid_argument("archive manifest integer is invalid");
    }
    return result;
}

[[nodiscard]] std::uint32_t mode(const std::string_view value) {
    if (value == "0644") return 0644U;
    if (value == "0755") return 0755U;
    if (value == "0777") return 0777U;
    throw std::invalid_argument("archive manifest mode is invalid");
}

[[nodiscard]] std::array<std::string_view, 6> fields(
    const std::string_view line) {
    std::array<std::string_view, 6> result;
    std::size_t offset{};
    for (std::size_t index = 0; index < result.size(); ++index) {
        const auto separator = line.find('\t', offset);
        if ((index + 1U == result.size()) !=
            (separator == std::string_view::npos)) {
            throw std::invalid_argument(
                "archive manifest record must have six fields");
        }
        result[index] = line.substr(
            offset, separator == std::string_view::npos
                        ? line.size() - offset
                        : separator - offset);
        offset = separator == std::string_view::npos
                     ? line.size()
                     : separator + 1U;
    }
    return result;
}

void validate_limits(const ReleaseSecurityLimits& limits) {
    if (limits.maximum_entries == 0 ||
        limits.maximum_entries > 1'000'000 ||
        limits.maximum_total_bytes == 0 ||
        limits.maximum_file_bytes == 0 ||
        limits.maximum_file_bytes > limits.maximum_total_bytes ||
        limits.maximum_compression_ratio == 0 ||
        limits.maximum_compression_ratio > 10'000 ||
        limits.maximum_symlinks > limits.maximum_entries) {
        throw std::invalid_argument("release security limits are invalid");
    }
}

void add_size(
    std::uint64_t& total, const std::uint64_t size,
    const ReleaseSecurityLimits& limits) {
    if (size > limits.maximum_file_bytes ||
        total > limits.maximum_total_bytes - size) {
        throw std::length_error("release content exceeds size limits");
    }
    total += size;
}

void reject_case_duplicate(
    std::map<std::string, std::string, std::less<>>& paths,
    const std::string& path) {
    const auto [found, inserted] = paths.emplace(ascii_lower(path), path);
    if (!inserted) {
        throw std::invalid_argument(
            found->second == path ? "release manifest contains duplicate path"
                                  : "release manifest contains case collision");
    }
}

}  // namespace

std::vector<ArchiveEntry> parse_archive_manifest(
    const std::string_view content) {
    if (content.empty() || content.size() > maximum_manifest_bytes ||
        content.back() != '\n') {
        throw std::invalid_argument("archive manifest content is invalid");
    }
    std::vector<ArchiveEntry> result;
    std::size_t offset{};
    while (offset < content.size()) {
        const auto terminator = content.find('\n', offset);
        auto line = content.substr(offset, terminator - offset);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.empty()) {
            throw std::invalid_argument("archive manifest contains empty record");
        }
        const auto record = fields(line);
        ArchiveEntry entry;
        if (record[0] == "file") {
            entry.kind = ArchiveEntryKind::file;
        } else if (record[0] == "directory") {
            entry.kind = ArchiveEntryKind::directory;
        } else if (record[0] == "symlink") {
            entry.kind = ArchiveEntryKind::symlink;
        } else {
            throw std::invalid_argument("archive manifest kind is invalid");
        }
        entry.path = record[1];
        entry.uncompressed_size = decimal<std::uint64_t>(record[2]);
        entry.compressed_size = decimal<std::uint64_t>(record[3]);
        entry.mode = mode(record[4]);
        entry.symlink_target = record[5] == "-" ? "" : std::string(record[5]);
        result.push_back(std::move(entry));
        offset = terminator + 1U;
    }
    return result;
}

ReleaseSecurityReport validate_archive_manifest(
    const std::vector<ArchiveEntry>& entries,
    const ReleaseSecurityLimits limits) {
    validate_limits(limits);
    if (entries.empty() || entries.size() > limits.maximum_entries) {
        throw std::length_error("archive entry count is outside limits");
    }
    ReleaseSecurityReport report{
        .gate = "archive_manifest",
        .entries = entries.size(),
        .passed = false,
    };
    std::map<std::string, std::string, std::less<>> paths;
    for (const auto& entry : entries) {
        if (!is_canonical_workspace_path(entry.path) ||
            contains_release_metadata(entry.path)) {
            throw std::invalid_argument("archive path is unsafe for release");
        }
        reject_case_duplicate(paths, entry.path);
    }
    std::map<std::string, ArchiveEntryKind, std::less<>> entry_kinds;
    for (const auto& entry : entries) {
        entry_kinds.emplace(entry.path, entry.kind);
    }
    for (const auto& entry : entries) {
        switch (entry.kind) {
            case ArchiveEntryKind::file:
                if (entry.mode != 0644U && entry.mode != 0755U) {
                    throw std::invalid_argument("archive file mode is unsafe");
                }
                if (!entry.symlink_target.empty() ||
                    (entry.uncompressed_size != 0 && entry.compressed_size == 0)) {
                    throw std::invalid_argument("archive file metadata is invalid");
                }
                if (entry.compressed_size != 0) {
                    const auto ratio =
                        entry.uncompressed_size / entry.compressed_size;
                    const auto remainder =
                        entry.uncompressed_size % entry.compressed_size;
                    if (ratio > limits.maximum_compression_ratio ||
                        (ratio == limits.maximum_compression_ratio &&
                         remainder != 0)) {
                        throw std::length_error(
                            "archive compression ratio exceeds limit");
                    }
                }
                add_size(
                    report.total_uncompressed_bytes,
                    entry.uncompressed_size, limits);
                ++report.files;
                break;
            case ArchiveEntryKind::directory:
                if (entry.mode != 0755U || entry.uncompressed_size != 0 ||
                    entry.compressed_size != 0 ||
                    !entry.symlink_target.empty()) {
                    throw std::invalid_argument(
                        "archive directory metadata is invalid");
                }
                ++report.directories;
                break;
            case ArchiveEntryKind::symlink:
                if (entry.mode != 0777U || entry.uncompressed_size != 0 ||
                    entry.compressed_size != 0 ||
                    !is_canonical_workspace_path(entry.symlink_target) ||
                    contains_release_metadata(entry.symlink_target) ||
                    !entry_kinds.contains(entry.symlink_target) ||
                    entry_kinds.at(entry.symlink_target) ==
                        ArchiveEntryKind::symlink) {
                    throw std::invalid_argument(
                        "archive symlink metadata is invalid");
                }
                if (++report.symlinks > limits.maximum_symlinks) {
                    throw std::length_error("archive symlink count exceeds limit");
                }
                break;
        }
    }
    report.passed = true;
    return report;
}

ReleaseSecurityReport validate_repository_release(
    const WorkspaceManifest& manifest, const ReleaseSecurityLimits limits) {
    validate_limits(limits);
    validate_manifest(manifest);
    reject_case_collisions(manifest);
    if (manifest.entries.empty() ||
        manifest.entries.size() > limits.maximum_entries) {
        throw std::length_error("repository entry count is outside limits");
    }
    ReleaseSecurityReport report{
        .gate = "repository_manifest",
        .entries = manifest.entries.size(),
        .passed = false,
    };
    std::map<std::string, WorkspaceEntryKind, std::less<>> entry_kinds;
    for (const auto& entry : manifest.entries) {
        entry_kinds.emplace(entry.path, entry.kind);
    }
    for (const auto& entry : manifest.entries) {
        if (contains_release_metadata(entry.path)) {
            throw std::invalid_argument("repository metadata is not releasable");
        }
        switch (entry.kind) {
            case WorkspaceEntryKind::file:
                if ((entry.mode != 0644U && entry.mode != 0755U) ||
                    !entry.symlink_target.empty()) {
                    throw std::invalid_argument("repository file mode is unsafe");
                }
                add_size(
                    report.total_uncompressed_bytes, entry.size, limits);
                ++report.files;
                break;
            case WorkspaceEntryKind::directory:
                if (entry.mode != 0755U || entry.size != 0 ||
                    !entry.content_hash.empty() ||
                    !entry.symlink_target.empty()) {
                    throw std::invalid_argument(
                        "repository directory metadata is invalid");
                }
                ++report.directories;
                break;
            case WorkspaceEntryKind::symlink:
                if (entry.mode != 0777U || entry.size != 0 ||
                    !entry.content_hash.empty() ||
                    contains_release_metadata(entry.symlink_target) ||
                    !entry_kinds.contains(entry.symlink_target) ||
                    entry_kinds.at(entry.symlink_target) ==
                        WorkspaceEntryKind::symlink) {
                    throw std::invalid_argument(
                        "repository symlink target is unsafe or dangling");
                }
                if (++report.symlinks > limits.maximum_symlinks) {
                    throw std::length_error(
                        "repository symlink count exceeds limit");
                }
                break;
        }
    }
    report.passed = true;
    return report;
}

std::string render_release_security_json(
    const ReleaseSecurityReport& report) {
    if ((report.gate != "archive_manifest" &&
         report.gate != "repository_manifest") ||
        report.entries == 0 ||
        report.files + report.directories + report.symlinks != report.entries ||
        !report.passed) {
        throw std::invalid_argument("release security report is inconsistent");
    }
    std::ostringstream output;
    output << "{\n"
           << "  \"schema_version\": 1,\n"
           << "  \"gate\": \"" << report.gate << "\",\n"
           << "  \"entries\": " << report.entries << ",\n"
           << "  \"files\": " << report.files << ",\n"
           << "  \"directories\": " << report.directories << ",\n"
           << "  \"symlinks\": " << report.symlinks << ",\n"
           << "  \"total_uncompressed_bytes\": "
           << report.total_uncompressed_bytes << ",\n"
           << "  \"passed\": true\n"
           << "}\n";
    return output.str();
}

}  // namespace rwn::core
