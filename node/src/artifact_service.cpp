#include "rwn/node/artifact_service.hpp"

#include "rwn/core/content_hash.hpp"
#include "rwn/protocol/envelope.hpp"

#include <set>
#include <stdexcept>

namespace rwn::node {

rwn::protocol::ArtifactManifestReply serve_artifact_download(
    rwn::transport::ReliableStream& stream,
    NodeControlService& control,
    const std::uint64_t current_revision,
    ArtifactSourceBoundary& source,
    const rwn::core::TimePoint now) {
    const auto envelope = rwn::protocol::decode(stream.read());
    if (envelope.version != 1 ||
        envelope.type != rwn::protocol::MessageType::artifact_manifest ||
        envelope.correlation_id.empty() || !envelope.unknown_fields.empty()) {
        throw std::invalid_argument("Node artifact request envelope is invalid");
    }
    const auto command = rwn::protocol::decode_artifact_fetch_command(
        envelope.payload);
    rwn::protocol::ArtifactManifestReply manifest{
        .accepted = false,
        .artifact_id = command.artifact_id,
        .transfer_id = command.transfer_id,
        .build_id = {}, .source_revision = 0, .name = {}, .sha256 = {},
        .size = 0, .platform = {}, .architecture = {}, .chunks = {},
        .reason_code = "artifact_denied",
    };
    if (command.revision != current_revision) {
        manifest.reason_code = "revision_mismatch";
    } else if (!control.permits_session(
                   command.session_id,
                   rwn::core::Capability::artifact_download,
                   command.workspace_id, now)) {
        manifest.reason_code = "capability_denied";
    } else {
        manifest = source.prepare(command);
        rwn::protocol::validate_artifact_manifest_reply(manifest);
        if (!manifest.accepted || manifest.artifact_id != command.artifact_id ||
            manifest.transfer_id != command.transfer_id ||
            manifest.source_revision != command.revision) {
            throw std::invalid_argument("artifact source manifest is not bound");
        }
        control.record_artifact(
            command.session_id, command.workspace_id, manifest.build_id,
            manifest.artifact_id, manifest.sha256, manifest.source_revision,
            rwn::core::AuditAction::artifact_published,
            rwn::core::AuditResult::allowed, "artifact_manifest_verified", now);
    }
    stream.write(rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::artifact_manifest,
        .correlation_id = envelope.correlation_id,
        .payload = rwn::protocol::encode_artifact_manifest_reply(manifest),
        .unknown_fields = {},
    }));
    if (!manifest.accepted) return manifest;

    const auto resume_envelope = rwn::protocol::decode(stream.read());
    const auto expected_correlation = "resume-" + command.transfer_id;
    if (resume_envelope.version != 1 ||
        resume_envelope.type != rwn::protocol::MessageType::artifact_resume ||
        resume_envelope.correlation_id != expected_correlation ||
        !resume_envelope.unknown_fields.empty()) {
        throw std::invalid_argument("Node artifact resume envelope is invalid");
    }
    const auto resume = rwn::protocol::decode_artifact_resume_command(
        resume_envelope.payload);
    if (resume.session_id != command.session_id ||
        resume.workspace_id != command.workspace_id ||
        resume.revision != command.revision ||
        resume.artifact_id != command.artifact_id ||
        resume.transfer_id != command.transfer_id) {
        throw std::invalid_argument("Node artifact resume identity is invalid");
    }
    std::set<std::uint32_t> expected;
    for (const auto index : resume.missing_chunks) {
        if (index >= manifest.chunks.size())
            throw std::invalid_argument("artifact resume index is out of range");
        expected.insert(index);
    }
    source.request_chunks(resume);
    while (!expected.empty()) {
        const auto chunk = source.read_chunk();
        rwn::protocol::validate_artifact_chunk_command(chunk);
        if (chunk.session_id != command.session_id ||
            chunk.workspace_id != command.workspace_id ||
            chunk.revision != command.revision ||
            chunk.artifact_id != command.artifact_id ||
            chunk.transfer_id != command.transfer_id ||
            !expected.erase(chunk.index) ||
            rwn::core::sha256_hex(chunk.bytes) !=
                manifest.chunks.at(chunk.index).sha256) {
            throw std::invalid_argument("artifact source chunk is not bound");
        }
        stream.write(rwn::protocol::encode({
            .version = 1,
            .type = rwn::protocol::MessageType::artifact_chunk,
            .correlation_id = "chunk-" + command.transfer_id + "-" +
                std::to_string(chunk.index),
            .payload = rwn::protocol::encode_artifact_chunk_command(chunk),
            .unknown_fields = {},
        }));
    }
    control.record_artifact(
        command.session_id, command.workspace_id, manifest.build_id,
        manifest.artifact_id, manifest.sha256, manifest.source_revision,
        rwn::core::AuditAction::artifact_downloaded,
        rwn::core::AuditResult::allowed, "artifact_download_completed",
        rwn::core::WallClock::now());
    return manifest;
}

}  // namespace rwn::node
