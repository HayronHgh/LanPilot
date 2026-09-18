#include "rwn/core/workspace_manifest.hpp"

#include "rwn/core/content_hash.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <stdexcept>
#include <utility>

namespace rwn::core {
namespace {

std::string canonical_relative(
    const std::filesystem::path& path, const std::filesystem::path& root) {
    const auto relative = path.lexically_relative(root).generic_string();
    if (!is_canonical_workspace_path(relative)) {
        throw std::invalid_argument("filesystem entry has a non-canonical path");
    }
    return relative;
}

std::string ascii_lower(std::string value) {
    std::ranges::transform(value, value.begin(), [](const unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

}  // namespace

WorkspaceManifest build_workspace_manifest(
    const std::filesystem::path& root, ManifestBuildOptions options) {
    if (options.workspace_id.empty() || options.revision == 0) {
        throw std::invalid_argument("manifest build identity is invalid");
    }
    const auto canonical_root = std::filesystem::weakly_canonical(
        std::filesystem::absolute(root));
    if (!std::filesystem::is_directory(canonical_root)) {
        throw std::invalid_argument("workspace root is not a directory");
    }

    WorkspaceManifest manifest{
        .workspace_id = std::move(options.workspace_id),
        .revision = options.revision,
        .entries = {},
    };
    std::filesystem::recursive_directory_iterator iterator(
        canonical_root, std::filesystem::directory_options::skip_permission_denied);
    const std::filesystem::recursive_directory_iterator end;
    for (; iterator != end; ++iterator) {
        const auto path = iterator->path();
        const auto relative = canonical_relative(path, canonical_root);
        const auto symlink_status = iterator->symlink_status();
        const auto directory = std::filesystem::is_directory(symlink_status);
        if (options.ignore_rules.ignores(relative, directory)) {
            if (directory) {
                iterator.disable_recursion_pending();
            }
            continue;
        }

        WorkspaceEntry entry{
            .path = relative,
            .kind = WorkspaceEntryKind::file,
            .size = 0,
            .content_hash = {},
            .mode = 0,
            .symlink_target = {},
        };
        if (std::filesystem::is_symlink(symlink_status)) {
            entry.kind = WorkspaceEntryKind::symlink;
            entry.mode = 0777U;
            entry.symlink_target = std::filesystem::read_symlink(path).generic_string();
            if (!is_canonical_workspace_path(entry.symlink_target)) {
                throw std::invalid_argument("workspace symlink target is unsafe");
            }
        } else if (directory) {
            entry.kind = WorkspaceEntryKind::directory;
            entry.mode = 0755U;
        } else if (std::filesystem::is_regular_file(symlink_status)) {
            entry.kind = WorkspaceEntryKind::file;
            entry.size = std::filesystem::file_size(path);
            entry.content_hash = sha256_file(path);
            entry.mode = options.executable_paths.contains(relative) ? 0755U : 0644U;
        } else {
            throw std::invalid_argument("unsupported workspace filesystem entry");
        }
        manifest.entries.push_back(std::move(entry));
    }
    std::ranges::sort(manifest.entries, {}, &WorkspaceEntry::path);
    reject_case_collisions(manifest);
    validate_manifest(manifest);
    return manifest;
}

void reject_case_collisions(const WorkspaceManifest& manifest) {
    std::map<std::string, std::string, std::less<>> folded_paths;
    for (const auto& entry : manifest.entries) {
        const auto folded = ascii_lower(entry.path);
        const auto [found, inserted] = folded_paths.emplace(folded, entry.path);
        if (!inserted && found->second != entry.path) {
            throw std::invalid_argument("workspace contains a case-colliding path");
        }
    }
}

std::set<std::string, std::less<>> parse_git_stage_executable_paths(
    const std::string_view output) {
    std::set<std::string, std::less<>> result;
    std::size_t offset{};
    while (offset < output.size()) {
        const auto terminator = output.find('\0', offset);
        const auto record = output.substr(
            offset, terminator == std::string_view::npos ? output.size() - offset
                                                        : terminator - offset);
        const auto separator = record.find('\t');
        if (separator == std::string_view::npos || record.size() < 7) {
            throw std::invalid_argument("invalid git stage record");
        }
        const auto mode = record.substr(0, 6);
        const auto path = record.substr(separator + 1);
        if (!is_canonical_workspace_path(path)) {
            throw std::invalid_argument("git stage path is not canonical");
        }
        if (mode == "100755") {
            result.insert(std::string(path));
        } else if (mode != "100644" && mode != "120000" && mode != "160000") {
            throw std::invalid_argument("unsupported git stage mode");
        }
        if (terminator == std::string_view::npos) {
            break;
        }
        offset = terminator + 1;
    }
    return result;
}

}  // namespace rwn::core
