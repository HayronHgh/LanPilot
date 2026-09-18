#include "rwn/protocol/build_control.hpp"

#include "rwn/protocol/envelope.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <ranges>
#include <set>
#include <stdexcept>
#include <string_view>

namespace rwn::protocol {
namespace {

[[nodiscard]] bool identifier(const std::string_view value) {
    return !value.empty() && value.size() <= 64 &&
        std::ranges::all_of(value, [](const unsigned char character) {
            return std::isalnum(character) != 0 || character == '-' ||
                character == '_' || character == '.';
        });
}

[[nodiscard]] bool sha256(const std::string_view value) {
    return value.size() == 64 &&
        std::ranges::all_of(value, [](const unsigned char character) {
            return std::isdigit(character) != 0 ||
                (character >= 'a' && character <= 'f');
        });
}

[[nodiscard]] bool safe_filename(const std::string_view value) {
    return !value.empty() && value.size() <= 255 && value != "." &&
        value != ".." && value.find_first_of("/\\\r\n\0") ==
            std::string_view::npos;
}

void require_identity(
    const std::string_view session_id, const std::string_view workspace_id,
    const std::uint64_t revision) {
    if (!identifier(session_id) || !identifier(workspace_id) || revision == 0) {
        throw std::invalid_argument("build wire identity is invalid");
    }
}

void append_u8(std::vector<std::byte>& out, const std::uint8_t value) {
    out.push_back(static_cast<std::byte>(value));
}
void append_u32(std::vector<std::byte>& out, const std::uint32_t value) {
    for (const unsigned shift : {24U, 16U, 8U, 0U})
        out.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
}
void append_u64(std::vector<std::byte>& out, const std::uint64_t value) {
    for (const unsigned shift : {56U, 48U, 40U, 32U, 24U, 16U, 8U, 0U})
        out.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
}
void append_string(std::vector<std::byte>& out, const std::string_view value) {
    if (value.size() > std::numeric_limits<std::uint32_t>::max())
        throw std::length_error("build wire string exceeds limit");
    append_u32(out, static_cast<std::uint32_t>(value.size()));
    const auto bytes = std::as_bytes(std::span{value.data(), value.size()});
    out.insert(out.end(), bytes.begin(), bytes.end());
}
void append_bytes(
    std::vector<std::byte>& out, const std::span<const std::byte> value) {
    if (value.size() > std::numeric_limits<std::uint32_t>::max())
        throw std::length_error("artifact wire bytes exceed limit");
    append_u32(out, static_cast<std::uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}
void require_limit(const std::vector<std::byte>& out) {
    if (out.size() > max_payload_size)
        throw std::length_error("build wire payload exceeds envelope limit");
}

class Reader {
public:
    explicit Reader(const std::span<const std::byte> payload) : payload_(payload) {
        if (payload.size() > max_payload_size)
            throw std::length_error("build wire payload exceeds limit");
    }
    [[nodiscard]] std::uint8_t u8() {
        require(1); return std::to_integer<std::uint8_t>(payload_[offset_++]);
    }
    [[nodiscard]] std::uint32_t u32() {
        require(4); std::uint32_t value{};
        for (int index = 0; index < 4; ++index)
            value = (value << 8U) |
                std::to_integer<std::uint32_t>(payload_[offset_++]);
        return value;
    }
    [[nodiscard]] std::uint64_t u64() {
        require(8); std::uint64_t value{};
        for (int index = 0; index < 8; ++index)
            value = (value << 8U) |
                std::to_integer<std::uint64_t>(payload_[offset_++]);
        return value;
    }
    [[nodiscard]] std::string string(
        const std::size_t maximum, const bool allow_empty = false) {
        const auto size = u32();
        if ((!allow_empty && size == 0) || size > maximum)
            throw std::invalid_argument("build wire string size is invalid");
        require(size);
        const auto* data = reinterpret_cast<const char*>(payload_.data() + offset_);
        offset_ += size;
        return std::string(data, size);
    }
    [[nodiscard]] std::vector<std::byte> bytes(const std::size_t maximum) {
        const auto size = u32();
        if (size == 0 || size > maximum)
            throw std::invalid_argument("artifact wire byte count is invalid");
        require(size);
        std::vector<std::byte> result(
            payload_.begin() + static_cast<std::ptrdiff_t>(offset_),
            payload_.begin() + static_cast<std::ptrdiff_t>(offset_ + size));
        offset_ += size;
        return result;
    }
    [[nodiscard]] bool empty() const noexcept { return offset_ == payload_.size(); }
private:
    void require(const std::size_t size) const {
        if (size > payload_.size() - offset_)
            throw std::invalid_argument("truncated build control payload");
    }
    std::span<const std::byte> payload_; std::size_t offset_{};
};

void require_end(const Reader& reader) {
    if (!reader.empty()) throw std::invalid_argument("trailing build control bytes");
}

}  // namespace

void validate_build_submit_command(const BuildSubmitCommand& value) {
    require_identity(value.session_id, value.workspace_id, value.revision);
    if (!identifier(value.build_id) || !identifier(value.profile))
        throw std::invalid_argument("build submit command is invalid");
}

void validate_build_status_reply(const BuildStatusReply& value) {
    if (!identifier(value.build_id) || !identifier(value.reason_code) ||
        value.elapsed_ms > 86'400'000U ||
        value.stdout_log.size() > max_build_log_bytes ||
        value.stderr_log.size() > max_build_log_bytes ||
        static_cast<std::uint8_t>(value.state) >
            static_cast<std::uint8_t>(BuildWireState::rejected))
        throw std::invalid_argument("build status reply is invalid");
    if (value.artifact_ids.size() > max_build_artifact_ids ||
        !std::ranges::all_of(value.artifact_ids, identifier) ||
        std::set<std::string, std::less<>>(
            value.artifact_ids.begin(), value.artifact_ids.end()).size() !=
            value.artifact_ids.size() ||
        (!value.artifact_ids.empty() &&
         value.state != BuildWireState::succeeded)) {
        throw std::invalid_argument("build artifact identity list is invalid");
    }
    if (value.accepted) {
        if (!sha256(value.evidence_sha256) ||
            value.state == BuildWireState::rejected ||
            (value.state == BuildWireState::succeeded &&
             (value.exit_code != 0 || value.timed_out || value.cancelled)) ||
            (value.state == BuildWireState::cancelled && !value.cancelled) ||
            (value.state == BuildWireState::failed &&
             (value.cancelled || (value.exit_code == 0 && !value.timed_out))))
            throw std::invalid_argument("accepted build evidence is inconsistent");
    } else if (value.state != BuildWireState::rejected ||
               !value.evidence_sha256.empty() || !value.stdout_log.empty() ||
               !value.stderr_log.empty() || value.exit_code != 0 ||
               value.elapsed_ms != 0 || value.timed_out || value.cancelled ||
               value.stdout_truncated || value.stderr_truncated ||
               !value.artifact_ids.empty()) {
        throw std::invalid_argument("rejected build reply contains evidence");
    }
}

void validate_artifact_fetch_command(const ArtifactFetchCommand& value) {
    require_identity(value.session_id, value.workspace_id, value.revision);
    if (!identifier(value.artifact_id) || !identifier(value.transfer_id))
        throw std::invalid_argument("artifact fetch command is invalid");
}

void validate_artifact_manifest_reply(const ArtifactManifestReply& value) {
    if (!identifier(value.artifact_id) || !identifier(value.transfer_id) ||
        !identifier(value.reason_code))
        throw std::invalid_argument("artifact manifest identity is invalid");
    if (!value.accepted) {
        if (!value.build_id.empty() || value.source_revision != 0 ||
            !value.name.empty() || !value.sha256.empty() || value.size != 0 ||
            !value.platform.empty() || !value.architecture.empty() ||
            !value.chunks.empty())
            throw std::invalid_argument("rejected artifact manifest contains metadata");
        return;
    }
    if (!identifier(value.build_id) || value.source_revision == 0 ||
        !safe_filename(value.name) || !sha256(value.sha256) || value.size == 0 ||
        !identifier(value.platform) || !identifier(value.architecture) ||
        value.chunks.empty() || value.chunks.size() > max_artifact_chunks)
        throw std::invalid_argument("accepted artifact manifest is invalid");
    std::uint64_t offset{};
    for (std::size_t index = 0; index < value.chunks.size(); ++index) {
        const auto& chunk = value.chunks[index];
        if (chunk.index != index || chunk.offset != offset || chunk.size == 0 ||
            chunk.size > max_artifact_chunk_bytes || !sha256(chunk.sha256) ||
            chunk.size > value.size - offset)
            throw std::invalid_argument("artifact chunk plan is invalid");
        offset += chunk.size;
    }
    if (offset != value.size)
        throw std::invalid_argument("artifact chunk plan size does not match");
}

void validate_artifact_chunk_command(const ArtifactChunkCommand& value) {
    require_identity(value.session_id, value.workspace_id, value.revision);
    if (!identifier(value.artifact_id) || !identifier(value.transfer_id) ||
        value.bytes.empty() || value.bytes.size() > max_artifact_chunk_bytes)
        throw std::invalid_argument("artifact chunk command is invalid");
}

void validate_artifact_resume_command(const ArtifactResumeCommand& value) {
    require_identity(value.session_id, value.workspace_id, value.revision);
    if (!identifier(value.artifact_id) || !identifier(value.transfer_id) ||
        value.missing_chunks.size() > max_artifact_chunks ||
        !std::ranges::is_sorted(value.missing_chunks) ||
        std::ranges::adjacent_find(value.missing_chunks) !=
            value.missing_chunks.end()) {
        throw std::invalid_argument("artifact resume command is invalid");
    }
}

void validate_deploy_submit_command(const DeploySubmitCommand& value) {
    require_identity(value.session_id, value.workspace_id, value.revision);
    if (!identifier(value.artifact_id) || !identifier(value.deployment_id))
        throw std::invalid_argument("deploy submit command is invalid");
}

void validate_deploy_status_reply(const DeployStatusReply& value) {
    if (!identifier(value.deployment_id) || !identifier(value.artifact_id) ||
        !identifier(value.reason_code) ||
        static_cast<std::uint8_t>(value.status) >
            static_cast<std::uint8_t>(DeploymentWireStatus::rejected) ||
        value.steps.size() > max_deployment_steps) {
        throw std::invalid_argument("deploy status reply is invalid");
    }
    if (!value.accepted) {
        if (!value.artifact_sha256.empty() || !value.build_id.empty() ||
            value.source_revision != 0 || !value.steps.empty() ||
            !value.evidence_sha256.empty() ||
            value.status != DeploymentWireStatus::rejected) {
            throw std::invalid_argument("rejected deploy reply contains evidence");
        }
        return;
    }
    if (!sha256(value.artifact_sha256) || !identifier(value.build_id) ||
        value.source_revision == 0 || value.steps.empty() ||
        !sha256(value.evidence_sha256) ||
        value.status == DeploymentWireStatus::rejected) {
        throw std::invalid_argument("accepted deploy evidence is incomplete");
    }
    for (const auto& step : value.steps) {
        if (step.step > 8 || step.elapsed_ms > 3'600'000U ||
            !identifier(step.reason_code) ||
            (step.succeeded && (step.exit_code != 0 || step.timed_out ||
                                step.cancelled))) {
            throw std::invalid_argument("deployment step evidence is invalid");
        }
    }
}

std::vector<std::byte> encode_build_submit_command(const BuildSubmitCommand& value) {
    validate_build_submit_command(value); std::vector<std::byte> out;
    append_string(out, value.session_id); append_string(out, value.workspace_id);
    append_u64(out, value.revision); append_string(out, value.build_id);
    append_string(out, value.profile); return out;
}
BuildSubmitCommand decode_build_submit_command(const std::span<const std::byte> payload) {
    Reader reader(payload); BuildSubmitCommand value{
        .session_id=reader.string(64), .workspace_id=reader.string(64),
        .revision=reader.u64(), .build_id=reader.string(64),
        .profile=reader.string(64)};
    require_end(reader); validate_build_submit_command(value); return value;
}

std::vector<std::byte> encode_build_status_reply(const BuildStatusReply& value) {
    validate_build_status_reply(value); std::vector<std::byte> out;
    append_u8(out, value.accepted ? 1U : 0U); append_string(out, value.build_id);
    append_u8(out, static_cast<std::uint8_t>(value.state));
    append_u32(out, static_cast<std::uint32_t>(value.exit_code));
    append_u64(out, value.elapsed_ms);
    append_u8(out, static_cast<std::uint8_t>(
        (value.timed_out ? 1U : 0U) | (value.cancelled ? 2U : 0U) |
        (value.stdout_truncated ? 4U : 0U) | (value.stderr_truncated ? 8U : 0U)));
    append_string(out, value.stdout_log); append_string(out, value.stderr_log);
    append_string(out, value.evidence_sha256);
    append_u32(out, static_cast<std::uint32_t>(value.artifact_ids.size()));
    for (const auto& artifact_id : value.artifact_ids)
        append_string(out, artifact_id);
    append_string(out, value.reason_code);
    require_limit(out); return out;
}
BuildStatusReply decode_build_status_reply(const std::span<const std::byte> payload) {
    Reader reader(payload); const auto accepted=reader.u8();
    const auto build_id=reader.string(64); const auto state=reader.u8();
    if (accepted > 1 || state > static_cast<std::uint8_t>(BuildWireState::rejected))
        throw std::invalid_argument("build status enum is invalid");
    const auto raw_exit=reader.u32(); const auto elapsed=reader.u64();
    const auto flags=reader.u8(); if ((flags & 0xf0U) != 0)
        throw std::invalid_argument("build status flags are invalid");
    BuildStatusReply value{
        .accepted=accepted == 1, .build_id=build_id,
        .state=static_cast<BuildWireState>(state),
        .exit_code=static_cast<std::int32_t>(raw_exit), .elapsed_ms=elapsed,
        .timed_out=(flags & 1U) != 0, .cancelled=(flags & 2U) != 0,
        .stdout_truncated=(flags & 4U) != 0, .stderr_truncated=(flags & 8U) != 0,
        .stdout_log=reader.string(max_build_log_bytes, true),
        .stderr_log=reader.string(max_build_log_bytes, true),
        .evidence_sha256=reader.string(64, true), .artifact_ids={},
        .reason_code={}};
    const auto artifact_count = reader.u32();
    if (artifact_count > max_build_artifact_ids)
        throw std::invalid_argument("build artifact identity count is invalid");
    value.artifact_ids.reserve(artifact_count);
    for (std::uint32_t index = 0; index < artifact_count; ++index)
        value.artifact_ids.push_back(reader.string(64));
    value.reason_code = reader.string(64);
    require_end(reader); validate_build_status_reply(value); return value;
}

std::vector<std::byte> encode_artifact_fetch_command(const ArtifactFetchCommand& value) {
    validate_artifact_fetch_command(value); std::vector<std::byte> out;
    append_string(out, value.session_id); append_string(out, value.workspace_id);
    append_u64(out, value.revision); append_string(out, value.artifact_id);
    append_string(out, value.transfer_id); return out;
}
ArtifactFetchCommand decode_artifact_fetch_command(const std::span<const std::byte> payload) {
    Reader reader(payload); ArtifactFetchCommand value{
        .session_id=reader.string(64), .workspace_id=reader.string(64),
        .revision=reader.u64(), .artifact_id=reader.string(64),
        .transfer_id=reader.string(64)};
    require_end(reader); validate_artifact_fetch_command(value); return value;
}

std::vector<std::byte> encode_artifact_manifest_reply(const ArtifactManifestReply& value) {
    validate_artifact_manifest_reply(value); std::vector<std::byte> out;
    append_u8(out, value.accepted ? 1U : 0U); append_string(out, value.artifact_id);
    append_string(out, value.transfer_id); append_string(out, value.build_id);
    append_u64(out, value.source_revision); append_string(out, value.name);
    append_string(out, value.sha256); append_u64(out, value.size);
    append_string(out, value.platform); append_string(out, value.architecture);
    append_u32(out, static_cast<std::uint32_t>(value.chunks.size()));
    for (const auto& chunk : value.chunks) {
        append_u32(out, chunk.index); append_u64(out, chunk.offset);
        append_u32(out, chunk.size); append_string(out, chunk.sha256);
    }
    append_string(out, value.reason_code); require_limit(out); return out;
}
ArtifactManifestReply decode_artifact_manifest_reply(const std::span<const std::byte> payload) {
    Reader reader(payload); const auto accepted=reader.u8(); if (accepted > 1)
        throw std::invalid_argument("artifact manifest flag is invalid");
    ArtifactManifestReply value{
        .accepted=accepted == 1, .artifact_id=reader.string(64),
        .transfer_id=reader.string(64), .build_id=reader.string(64, true),
        .source_revision=reader.u64(), .name=reader.string(255, true),
        .sha256=reader.string(64, true), .size=reader.u64(),
        .platform=reader.string(64, true), .architecture=reader.string(64, true),
        .chunks={}, .reason_code={}};
    const auto count=reader.u32(); if (count > max_artifact_chunks)
        throw std::invalid_argument("artifact chunk count is invalid");
    value.chunks.reserve(count);
    for (std::uint32_t index=0; index<count; ++index)
        value.chunks.push_back({.index=reader.u32(), .offset=reader.u64(),
            .size=reader.u32(), .sha256=reader.string(64)});
    value.reason_code=reader.string(64); require_end(reader);
    validate_artifact_manifest_reply(value); return value;
}

std::vector<std::byte> encode_artifact_chunk_command(const ArtifactChunkCommand& value) {
    validate_artifact_chunk_command(value); std::vector<std::byte> out;
    append_string(out, value.session_id); append_string(out, value.workspace_id);
    append_u64(out, value.revision); append_string(out, value.artifact_id);
    append_string(out, value.transfer_id); append_u32(out, value.index);
    append_bytes(out, value.bytes); require_limit(out); return out;
}
ArtifactChunkCommand decode_artifact_chunk_command(const std::span<const std::byte> payload) {
    Reader reader(payload); ArtifactChunkCommand value{
        .session_id=reader.string(64), .workspace_id=reader.string(64),
        .revision=reader.u64(), .artifact_id=reader.string(64),
        .transfer_id=reader.string(64), .index=reader.u32(),
        .bytes=reader.bytes(max_artifact_chunk_bytes)};
    require_end(reader); validate_artifact_chunk_command(value); return value;
}

std::vector<std::byte> encode_artifact_resume_command(
    const ArtifactResumeCommand& value) {
    validate_artifact_resume_command(value); std::vector<std::byte> out;
    append_string(out, value.session_id); append_string(out, value.workspace_id);
    append_u64(out, value.revision); append_string(out, value.artifact_id);
    append_string(out, value.transfer_id);
    append_u32(out, static_cast<std::uint32_t>(value.missing_chunks.size()));
    for (const auto index : value.missing_chunks) append_u32(out, index);
    require_limit(out); return out;
}
ArtifactResumeCommand decode_artifact_resume_command(
    const std::span<const std::byte> payload) {
    Reader reader(payload); ArtifactResumeCommand value{
        .session_id=reader.string(64), .workspace_id=reader.string(64),
        .revision=reader.u64(), .artifact_id=reader.string(64),
        .transfer_id=reader.string(64), .missing_chunks={}};
    const auto count=reader.u32(); if (count > max_artifact_chunks)
        throw std::invalid_argument("artifact resume count is invalid");
    value.missing_chunks.reserve(count);
    for (std::uint32_t index=0; index<count; ++index)
        value.missing_chunks.push_back(reader.u32());
    require_end(reader); validate_artifact_resume_command(value); return value;
}

std::vector<std::byte> encode_deploy_submit_command(
    const DeploySubmitCommand& value) {
    validate_deploy_submit_command(value); std::vector<std::byte> out;
    append_string(out, value.session_id); append_string(out, value.workspace_id);
    append_u64(out, value.revision); append_string(out, value.artifact_id);
    append_string(out, value.deployment_id); return out;
}

DeploySubmitCommand decode_deploy_submit_command(
    const std::span<const std::byte> payload) {
    Reader reader(payload); DeploySubmitCommand value{
        .session_id=reader.string(64), .workspace_id=reader.string(64),
        .revision=reader.u64(), .artifact_id=reader.string(64),
        .deployment_id=reader.string(64)};
    require_end(reader); validate_deploy_submit_command(value); return value;
}

std::vector<std::byte> encode_deploy_status_reply(
    const DeployStatusReply& value) {
    validate_deploy_status_reply(value); std::vector<std::byte> out;
    append_u8(out, value.accepted ? 1U : 0U);
    append_string(out, value.deployment_id); append_string(out, value.artifact_id);
    append_string(out, value.artifact_sha256); append_string(out, value.build_id);
    append_u64(out, value.source_revision);
    append_u8(out, static_cast<std::uint8_t>(value.status));
    append_u32(out, static_cast<std::uint32_t>(value.steps.size()));
    for (const auto& step : value.steps) {
        append_u8(out, step.step); append_u8(out, step.succeeded ? 1U : 0U);
        append_u32(out, static_cast<std::uint32_t>(step.exit_code));
        append_u64(out, step.elapsed_ms);
        append_u8(out, static_cast<std::uint8_t>(
            (step.timed_out ? 1U : 0U) | (step.cancelled ? 2U : 0U)));
        append_string(out, step.reason_code);
    }
    append_string(out, value.evidence_sha256);
    append_string(out, value.reason_code); require_limit(out); return out;
}

DeployStatusReply decode_deploy_status_reply(
    const std::span<const std::byte> payload) {
    Reader reader(payload); const auto accepted=reader.u8();
    if (accepted > 1) throw std::invalid_argument("deploy accepted flag is invalid");
    DeployStatusReply value{
        .accepted=accepted == 1, .deployment_id=reader.string(64),
        .artifact_id=reader.string(64),
        .artifact_sha256=reader.string(64, true),
        .build_id=reader.string(64, true), .source_revision=reader.u64(),
        .status=DeploymentWireStatus::rejected, .steps={},
        .evidence_sha256={}, .reason_code={}};
    const auto status=reader.u8();
    if (status > static_cast<std::uint8_t>(DeploymentWireStatus::rejected))
        throw std::invalid_argument("deploy status enum is invalid");
    value.status=static_cast<DeploymentWireStatus>(status);
    const auto count=reader.u32();
    if (count > max_deployment_steps)
        throw std::invalid_argument("deployment step count is invalid");
    value.steps.reserve(count);
    for (std::uint32_t index=0; index<count; ++index) {
        const auto step=reader.u8(); const auto succeeded=reader.u8();
        const auto exit=reader.u32(); const auto elapsed=reader.u64();
        const auto flags=reader.u8();
        if (succeeded > 1 || (flags & 0xfcU) != 0)
            throw std::invalid_argument("deployment step flags are invalid");
        value.steps.push_back({
            .step=step, .succeeded=succeeded == 1,
            .exit_code=static_cast<std::int32_t>(exit), .elapsed_ms=elapsed,
            .timed_out=(flags & 1U) != 0, .cancelled=(flags & 2U) != 0,
            .reason_code=reader.string(64)});
    }
    value.evidence_sha256=reader.string(64, true);
    value.reason_code=reader.string(64);
    require_end(reader); validate_deploy_status_reply(value); return value;
}

std::vector<std::byte> encode_deploy_evidence_binding(
    const DeployStatusReply& value) {
    auto checked = value;
    checked.evidence_sha256 = std::string(64, '0');
    validate_deploy_status_reply(checked);
    std::vector<std::byte> out;
    append_u8(out, checked.accepted ? 1U : 0U);
    append_string(out, checked.deployment_id);
    append_string(out, checked.artifact_id);
    append_string(out, checked.artifact_sha256);
    append_string(out, checked.build_id);
    append_u64(out, checked.source_revision);
    append_u8(out, static_cast<std::uint8_t>(checked.status));
    append_u32(out, static_cast<std::uint32_t>(checked.steps.size()));
    for (const auto& step : checked.steps) {
        append_u8(out, step.step); append_u8(out, step.succeeded ? 1U : 0U);
        append_u32(out, static_cast<std::uint32_t>(step.exit_code));
        append_u64(out, step.elapsed_ms);
        append_u8(out, static_cast<std::uint8_t>(
            (step.timed_out ? 1U : 0U) | (step.cancelled ? 2U : 0U)));
        append_string(out, step.reason_code);
    }
    append_string(out, checked.reason_code); require_limit(out); return out;
}

}  // namespace rwn::protocol
