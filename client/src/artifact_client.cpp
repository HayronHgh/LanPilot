#include "rwn/client/artifact_client.hpp"

#include "rwn/core/content_hash.hpp"
#include "rwn/core/workspace_scope.hpp"
#include "rwn/protocol/envelope.hpp"

#include <set>
#include <stdexcept>

namespace rwn::client {

ArtifactDownloadResult download_artifact(
    rwn::transport::ReliableStream& stream,
    const rwn::protocol::ArtifactFetchCommand& command,
    const std::filesystem::path& destination_root,
    const std::filesystem::path& destination_relative_path,
    rwn::core::DurableFileSystem& filesystem) {
    rwn::protocol::validate_artifact_fetch_command(command);
    const auto correlation = "artifact-" + command.transfer_id;
    stream.write(rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::artifact_manifest,
        .correlation_id = correlation,
        .payload = rwn::protocol::encode_artifact_fetch_command(command),
        .unknown_fields = {},
    }));
    const auto manifest_envelope = rwn::protocol::decode(stream.read());
    if (manifest_envelope.version != 1 ||
        manifest_envelope.type != rwn::protocol::MessageType::artifact_manifest ||
        manifest_envelope.correlation_id != correlation ||
        !manifest_envelope.unknown_fields.empty()) {
        throw std::invalid_argument("artifact manifest envelope is invalid");
    }
    auto manifest = rwn::protocol::decode_artifact_manifest_reply(
        manifest_envelope.payload);
    if (manifest.artifact_id != command.artifact_id ||
        manifest.transfer_id != command.transfer_id) {
        throw std::invalid_argument("artifact manifest identity is invalid");
    }
    if (!manifest.accepted) return {
        .manifest = std::move(manifest), .destination = {}};
    if (manifest.source_revision != command.revision) {
        throw std::invalid_argument("artifact manifest revision is invalid");
    }
    rwn::core::FileTransferPlan plan{
        .transfer_id = command.transfer_id,
        .relative_path = destination_relative_path,
        .total_size = manifest.size,
        .sha256 = manifest.sha256,
        .chunks = {},
    };
    plan.chunks.reserve(manifest.chunks.size());
    for (const auto& chunk : manifest.chunks) {
        plan.chunks.push_back({
            .index = chunk.index, .offset = chunk.offset,
            .size = chunk.size, .sha256 = chunk.sha256});
    }
    rwn::core::WorkspaceScope destination_scope(destination_root);
    rwn::core::FileTransfer transfer(destination_scope, plan, filesystem);
    const auto missing_size_t = transfer.missing_chunks();
    rwn::protocol::ArtifactResumeCommand resume{
        .session_id = command.session_id,
        .workspace_id = command.workspace_id,
        .revision = command.revision,
        .artifact_id = command.artifact_id,
        .transfer_id = command.transfer_id,
        .missing_chunks = {},
    };
    std::set<std::uint32_t> expected;
    for (const auto index : missing_size_t) {
        const auto wire = static_cast<std::uint32_t>(index);
        resume.missing_chunks.push_back(wire);
        expected.insert(wire);
    }
    const auto resume_correlation = "resume-" + command.transfer_id;
    stream.write(rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::artifact_resume,
        .correlation_id = resume_correlation,
        .payload = rwn::protocol::encode_artifact_resume_command(resume),
        .unknown_fields = {},
    }));
    for (std::size_t received = 0; received < expected.size(); ++received) {
        const auto envelope = rwn::protocol::decode(stream.read());
        if (envelope.version != 1 ||
            envelope.type != rwn::protocol::MessageType::artifact_chunk ||
            !envelope.unknown_fields.empty()) {
            throw std::invalid_argument("artifact chunk envelope is invalid");
        }
        const auto chunk = rwn::protocol::decode_artifact_chunk_command(
            envelope.payload);
        if (chunk.session_id != command.session_id ||
            chunk.workspace_id != command.workspace_id ||
            chunk.revision != command.revision ||
            chunk.artifact_id != command.artifact_id ||
            chunk.transfer_id != command.transfer_id ||
            envelope.correlation_id != "chunk-" + command.transfer_id + "-" +
                std::to_string(chunk.index) ||
            !expected.erase(chunk.index)) {
            throw std::invalid_argument("artifact chunk identity is invalid");
        }
        transfer.accept_chunk(chunk.index, chunk.bytes);
    }
    if (!expected.empty())
        throw std::invalid_argument("artifact transfer omitted requested chunks");
    transfer.finalize();
    const auto destination = destination_scope.resolve(destination_relative_path);
    if (!std::filesystem::is_regular_file(destination) ||
        rwn::core::sha256_file(destination) != manifest.sha256) {
        throw std::runtime_error("downloaded artifact failed final verification");
    }
    return {.manifest = std::move(manifest), .destination = destination};
}

}  // namespace rwn::client
