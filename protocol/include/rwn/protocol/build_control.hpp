#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace rwn::protocol {

inline constexpr std::size_t max_build_log_bytes = 4U * 1024U * 1024U;
inline constexpr std::size_t max_build_artifact_ids = 64;
inline constexpr std::size_t max_artifact_chunks = 4096;
inline constexpr std::size_t max_artifact_chunk_bytes = 4U * 1024U * 1024U;
inline constexpr std::size_t max_deployment_steps = 16;

enum class BuildWireState : std::uint8_t {
    succeeded = 0,
    failed = 1,
    cancelled = 2,
    rejected = 3,
};

struct BuildSubmitCommand {
    std::string session_id;
    std::string workspace_id;
    std::uint64_t revision{};
    std::string build_id;
    std::string profile;
    [[nodiscard]] bool operator==(const BuildSubmitCommand&) const = default;
};

struct BuildStatusReply {
    bool accepted{};
    std::string build_id;
    BuildWireState state{BuildWireState::rejected};
    std::int32_t exit_code{};
    std::uint64_t elapsed_ms{};
    bool timed_out{};
    bool cancelled{};
    bool stdout_truncated{};
    bool stderr_truncated{};
    std::string stdout_log;
    std::string stderr_log;
    std::string evidence_sha256;
    std::vector<std::string> artifact_ids;
    std::string reason_code;
    [[nodiscard]] bool operator==(const BuildStatusReply&) const = default;
};

struct ArtifactWireChunkDescriptor {
    std::uint32_t index{};
    std::uint64_t offset{};
    std::uint32_t size{};
    std::string sha256;
    [[nodiscard]] bool operator==(
        const ArtifactWireChunkDescriptor&) const = default;
};

struct ArtifactFetchCommand {
    std::string session_id;
    std::string workspace_id;
    std::uint64_t revision{};
    std::string artifact_id;
    std::string transfer_id;
    [[nodiscard]] bool operator==(const ArtifactFetchCommand&) const = default;
};

struct ArtifactManifestReply {
    bool accepted{};
    std::string artifact_id;
    std::string transfer_id;
    std::string build_id;
    std::uint64_t source_revision{};
    std::string name;
    std::string sha256;
    std::uint64_t size{};
    std::string platform;
    std::string architecture;
    std::vector<ArtifactWireChunkDescriptor> chunks;
    std::string reason_code;
    [[nodiscard]] bool operator==(const ArtifactManifestReply&) const = default;
};

struct ArtifactChunkCommand {
    std::string session_id;
    std::string workspace_id;
    std::uint64_t revision{};
    std::string artifact_id;
    std::string transfer_id;
    std::uint32_t index{};
    std::vector<std::byte> bytes;
    [[nodiscard]] bool operator==(const ArtifactChunkCommand&) const = default;
};

struct ArtifactResumeCommand {
    std::string session_id;
    std::string workspace_id;
    std::uint64_t revision{};
    std::string artifact_id;
    std::string transfer_id;
    std::vector<std::uint32_t> missing_chunks;
    [[nodiscard]] bool operator==(const ArtifactResumeCommand&) const = default;
};

enum class DeploymentWireStatus : std::uint8_t {
    active = 0,
    rolled_back = 1,
    failed = 2,
    rejected = 3,
};

struct DeploySubmitCommand {
    std::string session_id;
    std::string workspace_id;
    std::uint64_t revision{};
    std::string artifact_id;
    std::string deployment_id;
    [[nodiscard]] bool operator==(const DeploySubmitCommand&) const = default;
};

struct DeploymentWireStepEvidence {
    std::uint8_t step{};
    bool succeeded{};
    std::int32_t exit_code{};
    std::uint64_t elapsed_ms{};
    bool timed_out{};
    bool cancelled{};
    std::string reason_code;
    [[nodiscard]] bool operator==(
        const DeploymentWireStepEvidence&) const = default;
};

struct DeployStatusReply {
    bool accepted{};
    std::string deployment_id;
    std::string artifact_id;
    std::string artifact_sha256;
    std::string build_id;
    std::uint64_t source_revision{};
    DeploymentWireStatus status{DeploymentWireStatus::rejected};
    std::vector<DeploymentWireStepEvidence> steps;
    std::string evidence_sha256;
    std::string reason_code;
    [[nodiscard]] bool operator==(const DeployStatusReply&) const = default;
};

void validate_build_submit_command(const BuildSubmitCommand& value);
void validate_build_status_reply(const BuildStatusReply& value);
void validate_artifact_fetch_command(const ArtifactFetchCommand& value);
void validate_artifact_manifest_reply(const ArtifactManifestReply& value);
void validate_artifact_chunk_command(const ArtifactChunkCommand& value);
void validate_artifact_resume_command(const ArtifactResumeCommand& value);
void validate_deploy_submit_command(const DeploySubmitCommand& value);
void validate_deploy_status_reply(const DeployStatusReply& value);

[[nodiscard]] std::vector<std::byte> encode_build_submit_command(
    const BuildSubmitCommand& value);
[[nodiscard]] BuildSubmitCommand decode_build_submit_command(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_build_status_reply(
    const BuildStatusReply& value);
[[nodiscard]] BuildStatusReply decode_build_status_reply(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_artifact_fetch_command(
    const ArtifactFetchCommand& value);
[[nodiscard]] ArtifactFetchCommand decode_artifact_fetch_command(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_artifact_manifest_reply(
    const ArtifactManifestReply& value);
[[nodiscard]] ArtifactManifestReply decode_artifact_manifest_reply(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_artifact_chunk_command(
    const ArtifactChunkCommand& value);
[[nodiscard]] ArtifactChunkCommand decode_artifact_chunk_command(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_artifact_resume_command(
    const ArtifactResumeCommand& value);
[[nodiscard]] ArtifactResumeCommand decode_artifact_resume_command(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_deploy_submit_command(
    const DeploySubmitCommand& value);
[[nodiscard]] DeploySubmitCommand decode_deploy_submit_command(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_deploy_status_reply(
    const DeployStatusReply& value);
[[nodiscard]] DeployStatusReply decode_deploy_status_reply(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_deploy_evidence_binding(
    const DeployStatusReply& value);

}  // namespace rwn::protocol
