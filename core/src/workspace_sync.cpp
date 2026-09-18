#include "rwn/core/workspace_sync.hpp"

#include "rwn/core/content_hash.hpp"

#include "rwn/core/workspace_manifest.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <utility>

namespace rwn::core {
namespace {

bool equivalent_content(const WorkspaceEntry& left, const WorkspaceEntry& right) {
    return left.kind == WorkspaceEntryKind::file && right.kind == WorkspaceEntryKind::file &&
           left.size == right.size && !left.content_hash.empty() && left.content_hash == right.content_hash;
}

const WorkspaceEntry& require_source_entry(
    const std::map<std::string, const WorkspaceEntry*, std::less<>>& source,
    const std::string& path) {
    const auto found = source.find(path);
    if (found == source.end()) {
        throw std::invalid_argument("manifest change references missing source entry");
    }
    return *found->second;
}

void append_u64(std::vector<std::byte>& output, const std::uint64_t value) {
    for (unsigned int shift = 0; shift < 64; shift += 8) {
        output.push_back(static_cast<std::byte>(value >> shift));
    }
}

void append_string(std::vector<std::byte>& output, const std::string_view value) {
    append_u64(output, value.size());
    const auto bytes = std::as_bytes(std::span{value.data(), value.size()});
    output.insert(output.end(), bytes.begin(), bytes.end());
}

std::map<std::string, const WorkspaceEntry*, std::less<>> indexed(const WorkspaceManifest& manifest) {
    std::map<std::string, const WorkspaceEntry*, std::less<>> result;
    for (const auto& entry : manifest.entries) {
        if (!result.emplace(entry.path, &entry).second) { throw std::invalid_argument("manifest contains duplicate paths"); }
    }
    return result;
}

}  // namespace

bool is_canonical_workspace_path(const std::string_view path) {
    if (path.empty() || path.size() > 4096 || path.front() == '/' ||
        path.back() == '/' || path.find('\\') != std::string_view::npos) {
        return false;
    }
    std::size_t start{};
    while (start < path.size()) {
        const auto end = path.find('/', start);
        const auto component = path.substr(start, end == std::string_view::npos ? path.size() - start : end - start);
        if (component.empty() || component.size() > 255 || component == "." ||
            component == ".." || component.front() == ' ' ||
            component.back() == ' ' || component.back() == '.' ||
            component.find_first_of(":*?\"<>|") != std::string_view::npos ||
            std::ranges::any_of(component, [](const unsigned char character) {
                return character < 0x20U || character == 0x7fU;
            })) {
            return false;
        }
        const auto extension = component.find('.');
        std::string device(component.substr(0, extension));
        std::ranges::transform(
            device, device.begin(), [](const unsigned char character) {
                return static_cast<char>(std::toupper(character));
            });
        const auto numbered_device = [&device](const std::string_view prefix) {
            return device.size() == 4 && device.starts_with(prefix) &&
                   device[3] >= '1' && device[3] <= '9';
        };
        if (device == "CON" || device == "PRN" || device == "AUX" ||
            device == "NUL" || device == "CLOCK$" || device == "CONIN$" ||
            device == "CONOUT$" || numbered_device("COM") ||
            numbered_device("LPT")) {
            return false;
        }
        start = end == std::string_view::npos ? path.size() : end + 1;
    }
    return true;
}

void validate_manifest(const WorkspaceManifest& manifest) {
    if (manifest.workspace_id.empty() || manifest.revision == 0) { throw std::invalid_argument("invalid workspace manifest identity"); }
    std::set<std::string, std::less<>> paths;
    std::string_view previous_path;
    for (const auto& entry : manifest.entries) {
        if (!is_canonical_workspace_path(entry.path) || !paths.insert(entry.path).second ||
            (!previous_path.empty() && previous_path >= entry.path) ||
            (entry.kind == WorkspaceEntryKind::file && !is_sha256_hex(entry.content_hash)) ||
            (entry.kind != WorkspaceEntryKind::symlink && !entry.symlink_target.empty()) ||
            (entry.kind == WorkspaceEntryKind::symlink && !is_canonical_workspace_path(entry.symlink_target))) {
            throw std::invalid_argument("invalid workspace manifest entry");
        }
        previous_path = entry.path;
    }
}

std::vector<WorkspaceChange> diff_manifests(const WorkspaceManifest& source, const WorkspaceManifest& destination) {
    validate_manifest(source); validate_manifest(destination);
    if (source.workspace_id != destination.workspace_id || source.revision <= destination.revision) {
        throw std::invalid_argument("invalid one-way manifest revision");
    }
    const auto source_index = indexed(source); const auto destination_index = indexed(destination);
    std::vector<WorkspaceChange> result; std::set<std::string, std::less<>> consumed_destination;
    for (const auto& [path, source_entry] : source_index) {
        const auto old = destination_index.find(path);
        if (old == destination_index.end()) {
            const auto rename = std::find_if(destination_index.begin(), destination_index.end(), [&](const auto& candidate) {
                return !source_index.contains(candidate.first) &&
                       !consumed_destination.contains(candidate.first) &&
                       equivalent_content(*source_entry, *candidate.second);
            });
            if (rename != destination_index.end()) { consumed_destination.insert(rename->first); result.push_back({WorkspaceChangeKind::rename, path, rename->first}); }
            else { result.push_back({WorkspaceChangeKind::create, path, {}}); }
        } else if (*source_entry != *old->second) {
            const auto kind = source_entry->content_hash == old->second->content_hash && source_entry->size == old->second->size
                ? WorkspaceChangeKind::metadata : WorkspaceChangeKind::update;
            result.push_back({kind, path, {}});
        }
    }
    for (const auto& [path, _] : destination_index) { if (!source_index.contains(path) && !consumed_destination.contains(path)) { result.push_back({WorkspaceChangeKind::remove, path, {}}); } }
    return result;
}

WorkspaceManifest apply_manifest_diff(
    const WorkspaceManifest& source, const WorkspaceManifest& destination,
    const std::vector<WorkspaceChange>& changes) {
    const auto expected = diff_manifests(source, destination);
    if (changes != expected) {
        throw std::invalid_argument("manifest changes do not match authoritative diff");
    }
    const auto source_index = indexed(source);
    std::map<std::string, WorkspaceEntry, std::less<>> result;
    for (const auto& entry : destination.entries) {
        result.emplace(entry.path, entry);
    }
    for (const auto& change : changes) {
        switch (change.kind) {
            case WorkspaceChangeKind::remove:
                if (result.erase(change.path) != 1) {
                    throw std::invalid_argument("remove change references missing entry");
                }
                break;
            case WorkspaceChangeKind::rename:
                if (result.erase(change.previous_path) != 1) {
                    throw std::invalid_argument("rename change references missing entry");
                }
                result.insert_or_assign(
                    change.path, require_source_entry(source_index, change.path));
                break;
            case WorkspaceChangeKind::create:
            case WorkspaceChangeKind::update:
            case WorkspaceChangeKind::metadata:
                result.insert_or_assign(
                    change.path, require_source_entry(source_index, change.path));
                break;
        }
    }
    WorkspaceManifest applied{
        .workspace_id = source.workspace_id,
        .revision = source.revision,
        .entries = {},
    };
    applied.entries.reserve(result.size());
    for (auto& [_, entry] : result) {
        applied.entries.push_back(std::move(entry));
    }
    validate_manifest(applied);
    if (applied.entries != source.entries) {
        throw std::logic_error("applied destination manifest differs from source");
    }
    return applied;
}

std::string manifest_content_hash(const WorkspaceManifest& manifest) {
    validate_manifest(manifest);
    std::vector<std::byte> serialized;
    append_string(serialized, manifest.workspace_id);
    append_u64(serialized, manifest.revision);
    append_u64(serialized, manifest.entries.size());
    for (const auto& entry : manifest.entries) {
        append_string(serialized, entry.path);
        append_u64(serialized, static_cast<std::uint64_t>(entry.kind));
        append_u64(serialized, entry.size);
        append_string(serialized, entry.content_hash);
        append_u64(serialized, entry.mode);
        append_string(serialized, entry.symlink_target);
    }
    return sha256_hex(serialized);
}

WorkspaceRevisionHistory::WorkspaceRevisionHistory(
    std::string workspace_id, const std::size_t capacity)
    : workspace_id_(std::move(workspace_id)), capacity_(capacity) {
    if (workspace_id_.empty() || capacity_ == 0) {
        throw std::invalid_argument("invalid workspace revision history");
    }
}

void WorkspaceRevisionHistory::begin(const std::uint64_t revision) {
    if (state_ == WorkspaceSyncState::synchronizing ||
        revision != current_revision() + 1) {
        throw std::logic_error("workspace revision cannot begin");
    }
    pending_revision_ = revision;
    state_ = WorkspaceSyncState::synchronizing;
    failure_reason_.clear();
}

void WorkspaceRevisionHistory::commit(WorkspaceManifest manifest) {
    validate_manifest(manifest);
    reject_case_collisions(manifest);
    if (state_ != WorkspaceSyncState::synchronizing ||
        !pending_revision_.has_value() || manifest.workspace_id != workspace_id_ ||
        manifest.revision != *pending_revision_) {
        throw std::logic_error("workspace revision commit rejected");
    }
    records_.push_back({
        .revision = manifest.revision,
        .manifest_hash = manifest_content_hash(manifest),
        .entry_count = manifest.entries.size(),
    });
    if (records_.size() > capacity_) {
        records_.erase(records_.begin());
    }
    pending_revision_.reset();
    state_ = WorkspaceSyncState::synced;
}

void WorkspaceRevisionHistory::fail(std::string reason) {
    if (state_ != WorkspaceSyncState::synchronizing || reason.empty()) {
        throw std::logic_error("workspace revision failure rejected");
    }
    pending_revision_.reset();
    failure_reason_ = std::move(reason);
    state_ = WorkspaceSyncState::failed;
}

std::uint64_t WorkspaceRevisionHistory::current_revision() const {
    return records_.empty() ? 0 : records_.back().revision;
}

ChunkResumeLedger::ChunkResumeLedger(const std::size_t chunk_count) : confirmed_(chunk_count) {
    if (chunk_count == 0) { throw std::invalid_argument("transfer must have at least one chunk"); }
}
void ChunkResumeLedger::confirm(const std::size_t chunk_index, const std::size_t byte_count, const std::string_view verified_chunk_hash) {
    if (chunk_index >= confirmed_.size() || byte_count == 0 || byte_count > max_chunk_size || verified_chunk_hash.empty()) { throw std::invalid_argument("invalid verified chunk"); }
    confirmed_[chunk_index] = true;
}
bool ChunkResumeLedger::complete() const { return std::ranges::all_of(confirmed_, [](const bool value) { return value; }); }
std::vector<std::size_t> ChunkResumeLedger::missing() const { std::vector<std::size_t> result; for (std::size_t i{}; i < confirmed_.size(); ++i) { if (!confirmed_[i]) { result.push_back(i); } } return result; }

}  // namespace rwn::core
