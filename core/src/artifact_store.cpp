#include "rwn/core/artifact_store.hpp"

#include "rwn/core/content_hash.hpp"
#include "rwn/core/workspace_sync.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <charconv>
#include <limits>
#include <map>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace rwn::core {
namespace {

bool valid_id(const std::string_view value) {
    return !value.empty() && value.size() <= 64 &&
           std::ranges::all_of(value, [](const unsigned char character) {
               return std::isalnum(character) != 0 || character == '-' ||
                      character == '_';
           });
}

void validate_name(const std::string_view value) {
    if (value.empty() || value == "." || value == ".." ||
        value.find_first_of("/\\=\r\n\0") != std::string_view::npos ||
        std::ranges::any_of(value, [](const unsigned char character) {
            return character < 0x20U || character == 0x7fU;
        })) {
        throw std::invalid_argument("artifact name must be a single safe filename");
    }
}

constexpr std::size_t max_artifact_records = 100'000;
constexpr std::size_t max_metadata_bytes = 64U * 1024U;

[[nodiscard]] std::uint64_t positive_integer(
    const std::string_view value, const std::string_view label) {
    std::uint64_t result{};
    const auto parsed = std::from_chars(
        value.data(), value.data() + value.size(), result);
    if (value.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != value.data() + value.size() || result == 0) {
        throw std::invalid_argument(
            "artifact metadata " + std::string(label) + " is invalid");
    }
    return result;
}

[[nodiscard]] std::map<std::string, std::string, std::less<>> metadata_fields(
    const std::filesystem::path& path) {
    if (!std::filesystem::is_regular_file(path) ||
        std::filesystem::file_size(path) > max_metadata_bytes) {
        throw std::invalid_argument("artifact metadata file is invalid");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("artifact metadata could not be opened");
    std::map<std::string, std::string, std::less<>> result;
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto equals = line.find('=');
        if (equals == std::string::npos || equals == 0 ||
            equals + 1 == line.size() ||
            !result.emplace(line.substr(0, equals), line.substr(equals + 1)).second) {
            throw std::invalid_argument("artifact metadata schema is invalid");
        }
    }
    if (input.bad()) throw std::runtime_error("artifact metadata read failed");
    return result;
}

[[nodiscard]] std::string take(
    std::map<std::string, std::string, std::less<>>& fields,
    const std::string_view key) {
    const auto found = fields.find(key);
    if (found == fields.end())
        throw std::invalid_argument("artifact metadata field is missing");
    auto result = std::move(found->second);
    fields.erase(found);
    return result;
}

[[nodiscard]] Artifact parse_metadata(const std::filesystem::path& path) {
    auto fields = metadata_fields(path);
    if (take(fields, "schema") != "1")
        throw std::invalid_argument("artifact metadata schema is unsupported");
    const auto created_at_ns = positive_integer(
        take(fields, "created_at_ns"), "created_at_ns");
    if (created_at_ns > static_cast<std::uint64_t>(
            std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument("artifact creation time is out of range");
    }
    Artifact artifact{
        .id = take(fields, "id"),
        .workspace_id = take(fields, "workspace_id"),
        .build_id = take(fields, "build_id"),
        .source_revision = positive_integer(
            take(fields, "source_revision"), "source_revision"),
        .name = take(fields, "name"),
        .sha256 = take(fields, "sha256"),
        .size = positive_integer(take(fields, "size"), "size"),
        .platform = take(fields, "platform"),
        .architecture = take(fields, "architecture"),
        .created_at = std::chrono::system_clock::time_point{
            std::chrono::duration_cast<std::chrono::system_clock::duration>(
                std::chrono::nanoseconds{
                    static_cast<std::int64_t>(created_at_ns)})},
    };
    if (!fields.empty() || path.stem().string() != artifact.id)
        throw std::invalid_argument("artifact metadata has unknown or mismatched fields");
    validate_name(artifact.name);
    validate_artifact(artifact);
    return artifact;
}

[[nodiscard]] std::string render_metadata(const Artifact& artifact) {
    validate_name(artifact.name);
    validate_artifact(artifact);
    const auto created = std::chrono::duration_cast<std::chrono::nanoseconds>(
        artifact.created_at.time_since_epoch()).count();
    if (created <= 0) throw std::invalid_argument("artifact creation time is invalid");
    return "schema=1\nid=" + artifact.id +
        "\nworkspace_id=" + artifact.workspace_id +
        "\nbuild_id=" + artifact.build_id +
        "\nsource_revision=" + std::to_string(artifact.source_revision) +
        "\nname=" + artifact.name +
        "\nsha256=" + artifact.sha256 +
        "\nsize=" + std::to_string(artifact.size) +
        "\nplatform=" + artifact.platform +
        "\narchitecture=" + artifact.architecture +
        "\ncreated_at_ns=" + std::to_string(created) + "\n";
}

std::vector<std::byte> read_chunk(
    std::ifstream& input, const std::size_t requested) {
    std::vector<std::byte> bytes(requested);
    input.read(reinterpret_cast<char*>(bytes.data()),
               static_cast<std::streamsize>(requested));
    const auto count = input.gcount();
    if (count <= 0) {
        throw std::runtime_error("artifact source ended before its declared size");
    }
    bytes.resize(static_cast<std::size_t>(count));
    return bytes;
}

FileTransferPlan plan_file(
    const std::filesystem::path& source, std::string transfer_id,
    std::filesystem::path destination, const std::size_t chunk_size) {
    if (!std::filesystem::is_regular_file(source) ||
        chunk_size == 0 || chunk_size > ChunkResumeLedger::max_chunk_size ||
        !is_canonical_workspace_path(destination.generic_string())) {
        throw std::invalid_argument("artifact transfer plan is invalid");
    }
    const auto size = std::filesystem::file_size(source);
    if (size == 0 ||
        size > static_cast<std::uint64_t>(
                   std::numeric_limits<std::streamoff>::max())) {
        throw std::invalid_argument("artifact file size is unsupported");
    }
    FileTransferPlan plan{
        .transfer_id = std::move(transfer_id),
        .relative_path = std::move(destination),
        .total_size = size,
        .sha256 = sha256_file(source),
        .chunks = {},
    };
    std::ifstream input(source, std::ios::binary);
    if (!input) {
        throw std::runtime_error("artifact source could not be opened");
    }
    std::uint64_t offset{};
    while (offset < size) {
        const auto remaining = size - offset;
        const auto count = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, chunk_size));
        const auto bytes = read_chunk(input, count);
        plan.chunks.push_back({
            .index = plan.chunks.size(),
            .offset = offset,
            .size = bytes.size(),
            .sha256 = sha256_hex(bytes),
        });
        offset += bytes.size();
    }
    return plan;
}

void transfer_file(
    const std::filesystem::path& source, WorkspaceScope storage_scope,
    const FileTransferPlan& plan, DurableFileSystem& filesystem) {
    FileTransfer transfer(std::move(storage_scope), plan, filesystem);
    if (transfer.complete()) {
        transfer.finalize();
        return;
    }
    std::ifstream input(source, std::ios::binary);
    if (!input) {
        throw std::runtime_error("artifact source could not be reopened");
    }
    const auto missing = transfer.missing_chunks();
    for (const auto& chunk : plan.chunks) {
        const auto bytes = read_chunk(input, chunk.size);
        if (std::ranges::find(missing, chunk.index) != missing.end()) {
            transfer.accept_chunk(chunk.index, bytes);
        }
    }
    transfer.finalize();
}

}  // namespace

ArtifactStore::ArtifactStore(
    const BuildQueue& builds, std::filesystem::path build_workspace_root,
    std::filesystem::path storage_root, DurableFileSystem& filesystem,
    AuditLog& audit)
    : builds_(builds),
      build_scope_(std::move(build_workspace_root)),
      storage_scope_(std::move(storage_root)),
      filesystem_(filesystem),
      audit_(audit) {
    load_records();
}

void ArtifactStore::load_records() {
    const auto directory = storage_scope_.root() / "metadata";
    if (!std::filesystem::exists(directory)) return;
    if (!std::filesystem::is_directory(directory))
        throw std::invalid_argument("artifact metadata root is not a directory");
    std::size_t count{};
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (entry.path().extension() == ".pending") continue;
        if (++count > max_artifact_records || entry.path().extension() != ".toml" ||
            entry.is_symlink() || !entry.is_regular_file()) {
            throw std::invalid_argument("artifact metadata directory is invalid");
        }
        auto metadata = parse_metadata(entry.path());
        const auto artifact_id = metadata.id;
        const auto relative = std::filesystem::path("objects") /
            metadata.sha256.substr(0, 2) / metadata.sha256;
        if (!records_.emplace(
                artifact_id,
                Record{.metadata = std::move(metadata),
                       .object_relative_path = relative}).second) {
            throw std::invalid_argument("duplicate durable artifact id");
        }
    }
}

std::filesystem::path ArtifactStore::stage_record(const Record& record) const {
    const auto directory = storage_scope_.resolve("metadata");
    std::filesystem::create_directories(directory);
    const auto staging = storage_scope_.resolve(
        std::filesystem::path("metadata") /
        (record.metadata.id + ".pending"));
    const auto destination = storage_scope_.resolve(
        std::filesystem::path("metadata") /
        (record.metadata.id + ".toml"));
    if (std::filesystem::exists(staging) || std::filesystem::exists(destination))
        throw std::invalid_argument("artifact metadata id already exists");
    const auto contents = render_metadata(record.metadata);
    {
        std::ofstream output(staging, std::ios::binary | std::ios::trunc);
        if (!output) throw std::runtime_error("artifact metadata staging failed");
        output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
        output.flush();
        if (!output) throw std::runtime_error("artifact metadata write failed");
    }
    filesystem_.flush_file(staging);
    return staging;
}

void ArtifactStore::commit_record(
    const Record& record, const std::filesystem::path& staging) const {
    filesystem_.atomic_replace(
        staging,
        storage_scope_.resolve(std::filesystem::path("metadata") /
            (record.metadata.id + ".toml")));
}

Artifact ArtifactStore::publish(const ArtifactPublishRequest& request) {
    if (!valid_id(request.id) || !valid_id(request.build_id) ||
        request.source_revision == 0 || request.principal_id.empty() ||
        request.device_id.empty() || request.session_id.empty()) {
        throw std::invalid_argument("artifact publication identity is invalid");
    }
    validate_name(request.name);
    if (records_.contains(request.id)) {
        throw std::invalid_argument("artifact id is immutable and already exists");
    }
    const auto& build = builds_.request(request.build_id);
    if (builds_.state(request.build_id) != BuildState::succeeded ||
        build.pinned_revision != request.source_revision) {
        throw std::logic_error("artifact requires a successful matching build");
    }
    const auto source = build_scope_.resolve(request.source_relative_path);
    if (!std::filesystem::is_regular_file(source)) {
        throw std::invalid_argument(
            "artifact source must be a regular file; package bundles first");
    }
    const auto hash = sha256_file(source);
    const auto relative = std::filesystem::path("objects") /
                          hash.substr(0, 2) / hash;
    const auto destination = storage_scope_.resolve(relative);
    const auto size = std::filesystem::file_size(source);
    if (std::filesystem::exists(destination)) {
        if (!std::filesystem::is_regular_file(destination) ||
            std::filesystem::file_size(destination) != size ||
            sha256_file(destination) != hash) {
            throw std::runtime_error("content-addressed artifact object is corrupt");
        }
    } else {
        const auto plan = plan_file(
            source, "publish-" + hash.substr(0, 32), relative,
            ChunkResumeLedger::max_chunk_size);
        transfer_file(source, storage_scope_, plan, filesystem_);
    }
    Artifact metadata{
        .id = request.id,
        .workspace_id = build.workspace_id,
        .build_id = request.build_id,
        .source_revision = request.source_revision,
        .name = request.name,
        .sha256 = hash,
        .size = size,
        .platform = request.platform,
        .architecture = request.architecture,
        .created_at = std::chrono::system_clock::now(),
    };
    validate_artifact(metadata);
    const auto [record, inserted] = records_.emplace(
        metadata.id,
        Record{.metadata = metadata, .object_relative_path = relative});
    if (!inserted) {
        throw std::logic_error("artifact record insertion failed");
    }
    std::filesystem::path staging;
    try {
        staging = stage_record(record->second);
        audit_.append({
            .occurred_at = request.occurred_at,
            .principal_id = request.principal_id,
            .device_id = request.device_id,
            .session_id = request.session_id,
            .workspace_id = metadata.workspace_id,
            .build_id = metadata.build_id,
            .artifact_id = metadata.id,
            .artifact_sha256 = metadata.sha256,
            .source_revision = metadata.source_revision,
            .process_role = "build_worker",
            .action = AuditAction::artifact_published,
            .result = AuditResult::allowed,
        });
        commit_record(record->second, staging);
    } catch (...) {
        records_.erase(record);
        throw;
    }
    return metadata;
}

const Artifact& ArtifactStore::metadata(const std::string& artifact_id) const {
    return records_.at(artifact_id).metadata;
}

std::filesystem::path ArtifactStore::object_path(
    const std::string& artifact_id) const {
    return storage_scope_.resolve(records_.at(artifact_id).object_relative_path);
}

bool ArtifactStore::verify(const std::string& artifact_id) const {
    const auto& artifact = metadata(artifact_id);
    const auto path = object_path(artifact_id);
    return std::filesystem::is_regular_file(path) &&
           std::filesystem::file_size(path) == artifact.size &&
           sha256_file(path) == artifact.sha256;
}

FileTransferPlan ArtifactStore::download_plan(
    const std::string& artifact_id, std::string transfer_id,
    std::filesystem::path destination_relative_path,
    const std::size_t chunk_size) const {
    if (!verify(artifact_id)) {
        throw std::runtime_error("artifact object failed immutable verification");
    }
    return plan_file(
        object_path(artifact_id), std::move(transfer_id),
        std::move(destination_relative_path), chunk_size);
}

}  // namespace rwn::core
