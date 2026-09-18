#include "rwn/protocol/workspace_control.hpp"

#include "rwn/protocol/envelope.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <ranges>
#include <set>
#include <stdexcept>
#include <string_view>
#include <utility>

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

[[nodiscard]] bool workspace_path(const std::string_view path) {
    if (path.empty() || path.size() > 4096 || path.front() == '/' ||
        path.back() == '/' || path.find('\\') != std::string_view::npos) {
        return false;
    }
    std::size_t start{};
    while (start < path.size()) {
        const auto end = path.find('/', start);
        const auto part = path.substr(
            start, end == std::string_view::npos ? path.size() - start
                                                 : end - start);
        if (part.empty() || part.size() > 255 || part == "." || part == ".." ||
            part.front() == ' ' || part.back() == ' ' || part.back() == '.' ||
            part.find_first_of(":*?\"<>|") != std::string_view::npos ||
            std::ranges::any_of(part, [](const unsigned char character) {
                return character < 0x20U || character == 0x7fU;
            })) {
            return false;
        }
        const auto extension = part.find('.');
        std::string device(part.substr(0, extension));
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

void require_identity(
    const std::string_view session_id,
    const std::string_view workspace_id,
    const std::uint64_t revision) {
    if (!identifier(session_id) || !identifier(workspace_id) || revision == 0) {
        throw std::invalid_argument("workspace wire identity is invalid");
    }
}

void require_reason(const std::string_view value) {
    if (!identifier(value)) {
        throw std::invalid_argument("workspace reason code is invalid");
    }
}

void append_u8(std::vector<std::byte>& output, const std::uint8_t value) {
    output.push_back(static_cast<std::byte>(value));
}

void append_u32(std::vector<std::byte>& output, const std::uint32_t value) {
    for (const unsigned int shift : {24U, 16U, 8U, 0U}) {
        output.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
    }
}

void append_u64(std::vector<std::byte>& output, const std::uint64_t value) {
    for (const unsigned int shift : {56U, 48U, 40U, 32U, 24U, 16U, 8U, 0U}) {
        output.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
    }
}

void append_string(
    std::vector<std::byte>& output, const std::string_view value) {
    if (value.size() > std::numeric_limits<std::uint16_t>::max()) {
        throw std::length_error("workspace wire string exceeds limit");
    }
    output.push_back(static_cast<std::byte>((value.size() >> 8U) & 0xffU));
    output.push_back(static_cast<std::byte>(value.size() & 0xffU));
    const auto bytes = std::as_bytes(std::span{value.data(), value.size()});
    output.insert(output.end(), bytes.begin(), bytes.end());
}

void append_bytes(
    std::vector<std::byte>& output, const std::span<const std::byte> value) {
    if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("workspace wire bytes exceed limit");
    }
    append_u32(output, static_cast<std::uint32_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
}

void require_payload_limit(const std::vector<std::byte>& output) {
    if (output.size() > max_payload_size) {
        throw std::length_error("workspace wire payload exceeds envelope limit");
    }
}

class Reader {
public:
    explicit Reader(const std::span<const std::byte> payload)
        : payload_(payload) {
        if (payload.size() > max_payload_size) {
            throw std::length_error("workspace wire payload exceeds limit");
        }
    }

    [[nodiscard]] std::uint8_t u8() {
        require(1);
        return std::to_integer<std::uint8_t>(payload_[offset_++]);
    }

    [[nodiscard]] std::uint16_t u16() {
        require(2);
        const auto result = static_cast<std::uint16_t>(
            (std::to_integer<std::uint16_t>(payload_[offset_]) << 8U) |
            std::to_integer<std::uint16_t>(payload_[offset_ + 1]));
        offset_ += 2;
        return result;
    }

    [[nodiscard]] std::uint32_t u32() {
        require(4);
        std::uint32_t result{};
        for (int index = 0; index < 4; ++index) {
            result = (result << 8U) |
                std::to_integer<std::uint32_t>(payload_[offset_++]);
        }
        return result;
    }

    [[nodiscard]] std::uint64_t u64() {
        require(8);
        std::uint64_t result{};
        for (int index = 0; index < 8; ++index) {
            result = (result << 8U) |
                std::to_integer<std::uint64_t>(payload_[offset_++]);
        }
        return result;
    }

    [[nodiscard]] std::string string(
        const std::size_t maximum, const bool allow_empty = false) {
        const auto size = u16();
        if ((!allow_empty && size == 0) || size > maximum) {
            throw std::invalid_argument("workspace wire string size is invalid");
        }
        require(size);
        const auto* data = reinterpret_cast<const char*>(
            payload_.data() + offset_);
        offset_ += size;
        return std::string(data, size);
    }

    [[nodiscard]] std::vector<std::byte> bytes(const std::size_t maximum) {
        const auto size = u32();
        if (size == 0 || size > maximum) {
            throw std::invalid_argument("workspace wire byte count is invalid");
        }
        require(size);
        std::vector<std::byte> result(
            payload_.begin() + static_cast<std::ptrdiff_t>(offset_),
            payload_.begin() + static_cast<std::ptrdiff_t>(offset_ + size));
        offset_ += size;
        return result;
    }

    [[nodiscard]] bool empty() const noexcept {
        return offset_ == payload_.size();
    }

private:
    void require(const std::size_t size) const {
        if (size > payload_.size() - offset_) {
            throw std::invalid_argument("truncated workspace control payload");
        }
    }

    std::span<const std::byte> payload_;
    std::size_t offset_{};
};

void require_end(const Reader& reader) {
    if (!reader.empty()) {
        throw std::invalid_argument("trailing workspace control bytes");
    }
}

void append_identity(
    std::vector<std::byte>& output, const std::string_view session_id,
    const std::string_view workspace_id, const std::uint64_t revision) {
    append_string(output, session_id);
    append_string(output, workspace_id);
    append_u64(output, revision);
}

}  // namespace

void validate_workspace_manifest_command(
    const WorkspaceManifestCommand& value) {
    require_identity(value.session_id, value.workspace_id, value.revision);
    if (!sha256(value.manifest_sha256) ||
        value.entries.size() > max_workspace_wire_entries) {
        throw std::invalid_argument("workspace manifest command is invalid");
    }
    std::string_view previous;
    for (const auto& entry : value.entries) {
        if (!workspace_path(entry.path) ||
            (!previous.empty() && previous >= entry.path)) {
            throw std::invalid_argument(
                "workspace manifest paths must be canonical and sorted");
        }
        previous = entry.path;
        switch (entry.kind) {
            case WorkspaceWireEntryKind::file:
                if (!sha256(entry.sha256) || !entry.symlink_target.empty() ||
                    (entry.mode != 0644U && entry.mode != 0755U)) {
                    throw std::invalid_argument("workspace file entry is invalid");
                }
                break;
            case WorkspaceWireEntryKind::directory:
                if (entry.size != 0 || !entry.sha256.empty() ||
                    !entry.symlink_target.empty() || entry.mode != 0755U) {
                    throw std::invalid_argument(
                        "workspace directory entry is invalid");
                }
                break;
            case WorkspaceWireEntryKind::symlink:
                if (entry.size != 0 || !entry.sha256.empty() ||
                    !workspace_path(entry.symlink_target) ||
                    entry.mode != 0777U) {
                    throw std::invalid_argument(
                        "workspace symlink entry is invalid");
                }
                break;
        }
    }
}

void validate_workspace_diff_reply(const WorkspaceDiffReply& value) {
    require_reason(value.reason_code);
    if (value.requested_file_paths.size() > max_workspace_wire_entries ||
        (!value.accepted && !value.requested_file_paths.empty())) {
        throw std::invalid_argument("workspace diff reply is invalid");
    }
    std::string_view previous;
    for (const auto& path : value.requested_file_paths) {
        if (!workspace_path(path) || (!previous.empty() && previous >= path)) {
            throw std::invalid_argument(
                "workspace requested paths must be canonical and sorted");
        }
        previous = path;
    }
}

void validate_workspace_file_plan_command(
    const WorkspaceFilePlanCommand& value) {
    require_identity(value.session_id, value.workspace_id, value.revision);
    if (!identifier(value.transfer_id) || !workspace_path(value.path) ||
        value.total_size == 0 || !sha256(value.sha256) ||
        value.chunks.empty() ||
        value.chunks.size() > max_workspace_wire_chunks) {
        throw std::invalid_argument("workspace file plan is invalid");
    }
    std::uint64_t offset{};
    for (std::size_t index = 0; index < value.chunks.size(); ++index) {
        const auto& chunk = value.chunks[index];
        if (chunk.index != index || chunk.offset != offset || chunk.size == 0 ||
            chunk.size > max_workspace_chunk_bytes || !sha256(chunk.sha256)) {
            throw std::invalid_argument("workspace chunk plan is invalid");
        }
        if (offset > std::numeric_limits<std::uint64_t>::max() - chunk.size) {
            throw std::overflow_error("workspace chunk plan size overflow");
        }
        offset += chunk.size;
    }
    if (offset != value.total_size) {
        throw std::invalid_argument("workspace chunks do not cover file");
    }
}

void validate_workspace_file_plan_reply(
    const WorkspaceFilePlanReply& value) {
    require_reason(value.reason_code);
    if (value.missing_chunks.size() > max_workspace_wire_chunks ||
        (!value.accepted && !value.missing_chunks.empty()) ||
        !std::ranges::is_sorted(value.missing_chunks) ||
        std::adjacent_find(
            value.missing_chunks.begin(), value.missing_chunks.end()) !=
            value.missing_chunks.end()) {
        throw std::invalid_argument("workspace file plan reply is invalid");
    }
    if (!value.missing_chunks.empty() &&
        value.missing_chunks.back() >= max_workspace_wire_chunks) {
        throw std::invalid_argument("workspace missing chunk index is invalid");
    }
}

void validate_workspace_file_chunk_command(
    const WorkspaceFileChunkCommand& value) {
    require_identity(value.session_id, value.workspace_id, value.revision);
    if (!identifier(value.transfer_id) ||
        value.index >= max_workspace_wire_chunks || value.bytes.empty() ||
        value.bytes.size() > max_workspace_chunk_bytes) {
        throw std::invalid_argument("workspace file chunk is invalid");
    }
}

void validate_workspace_commit_command(const WorkspaceCommitCommand& value) {
    require_identity(value.session_id, value.workspace_id, value.revision);
    if (!sha256(value.manifest_sha256)) {
        throw std::invalid_argument("workspace commit command is invalid");
    }
}

void validate_workspace_commit_reply(const WorkspaceCommitReply& value) {
    require_reason(value.reason_code);
    if ((value.accepted &&
         (value.revision == 0 || !sha256(value.manifest_sha256))) ||
        (!value.manifest_sha256.empty() && !sha256(value.manifest_sha256))) {
        throw std::invalid_argument("workspace commit reply is invalid");
    }
}

std::vector<std::byte> encode_workspace_manifest_command(
    const WorkspaceManifestCommand& value) {
    validate_workspace_manifest_command(value);
    std::vector<std::byte> output;
    append_identity(output, value.session_id, value.workspace_id, value.revision);
    append_string(output, value.manifest_sha256);
    append_u32(output, static_cast<std::uint32_t>(value.entries.size()));
    for (const auto& entry : value.entries) {
        append_string(output, entry.path);
        append_u8(output, static_cast<std::uint8_t>(entry.kind));
        append_u64(output, entry.size);
        append_string(output, entry.sha256);
        append_u32(output, entry.mode);
        append_string(output, entry.symlink_target);
    }
    require_payload_limit(output);
    return output;
}

WorkspaceManifestCommand decode_workspace_manifest_command(
    const std::span<const std::byte> payload) {
    Reader reader(payload);
    WorkspaceManifestCommand value;
    value.session_id = reader.string(64);
    value.workspace_id = reader.string(64);
    value.revision = reader.u64();
    value.manifest_sha256 = reader.string(64);
    const auto count = reader.u32();
    if (count > max_workspace_wire_entries) {
        throw std::length_error("workspace manifest entry count exceeds limit");
    }
    value.entries.reserve(count);
    for (std::uint32_t index = 0; index < count; ++index) {
        auto path = reader.string(4096);
        const auto kind = reader.u8();
        if (kind > static_cast<std::uint8_t>(WorkspaceWireEntryKind::symlink)) {
            throw std::invalid_argument("workspace entry kind is invalid");
        }
        value.entries.push_back({
            .path = std::move(path),
            .kind = static_cast<WorkspaceWireEntryKind>(kind),
            .size = reader.u64(),
            .sha256 = reader.string(64, true),
            .mode = reader.u32(),
            .symlink_target = reader.string(4096, true),
        });
    }
    require_end(reader);
    validate_workspace_manifest_command(value);
    return value;
}

std::vector<std::byte> encode_workspace_diff_reply(
    const WorkspaceDiffReply& value) {
    validate_workspace_diff_reply(value);
    std::vector<std::byte> output;
    append_u8(output, value.accepted ? 1 : 0);
    append_u64(output, value.current_revision);
    append_u32(
        output, static_cast<std::uint32_t>(value.requested_file_paths.size()));
    for (const auto& path : value.requested_file_paths) append_string(output, path);
    append_string(output, value.reason_code);
    require_payload_limit(output);
    return output;
}

WorkspaceDiffReply decode_workspace_diff_reply(
    const std::span<const std::byte> payload) {
    Reader reader(payload);
    const auto accepted = reader.u8();
    if (accepted > 1) throw std::invalid_argument("workspace accepted flag invalid");
    WorkspaceDiffReply value{
        .accepted = accepted == 1,
        .current_revision = reader.u64(),
        .requested_file_paths = {},
        .reason_code = {},
    };
    const auto count = reader.u32();
    if (count > max_workspace_wire_entries) {
        throw std::length_error("workspace requested path count exceeds limit");
    }
    value.requested_file_paths.reserve(count);
    for (std::uint32_t index = 0; index < count; ++index) {
        value.requested_file_paths.push_back(reader.string(4096));
    }
    value.reason_code = reader.string(64);
    require_end(reader);
    validate_workspace_diff_reply(value);
    return value;
}

std::vector<std::byte> encode_workspace_file_plan_command(
    const WorkspaceFilePlanCommand& value) {
    validate_workspace_file_plan_command(value);
    std::vector<std::byte> output;
    append_identity(output, value.session_id, value.workspace_id, value.revision);
    append_string(output, value.transfer_id);
    append_string(output, value.path);
    append_u64(output, value.total_size);
    append_string(output, value.sha256);
    append_u32(output, static_cast<std::uint32_t>(value.chunks.size()));
    for (const auto& chunk : value.chunks) {
        append_u32(output, chunk.index);
        append_u64(output, chunk.offset);
        append_u32(output, chunk.size);
        append_string(output, chunk.sha256);
    }
    require_payload_limit(output);
    return output;
}

WorkspaceFilePlanCommand decode_workspace_file_plan_command(
    const std::span<const std::byte> payload) {
    Reader reader(payload);
    WorkspaceFilePlanCommand value;
    value.session_id = reader.string(64);
    value.workspace_id = reader.string(64);
    value.revision = reader.u64();
    value.transfer_id = reader.string(64);
    value.path = reader.string(4096);
    value.total_size = reader.u64();
    value.sha256 = reader.string(64);
    const auto count = reader.u32();
    if (count == 0 || count > max_workspace_wire_chunks) {
        throw std::length_error("workspace file chunk count exceeds limit");
    }
    value.chunks.reserve(count);
    for (std::uint32_t index = 0; index < count; ++index) {
        value.chunks.push_back({
            .index = reader.u32(),
            .offset = reader.u64(),
            .size = reader.u32(),
            .sha256 = reader.string(64),
        });
    }
    require_end(reader);
    validate_workspace_file_plan_command(value);
    return value;
}

std::vector<std::byte> encode_workspace_file_plan_reply(
    const WorkspaceFilePlanReply& value) {
    validate_workspace_file_plan_reply(value);
    std::vector<std::byte> output;
    append_u8(output, value.accepted ? 1 : 0);
    append_u32(output, static_cast<std::uint32_t>(value.missing_chunks.size()));
    for (const auto index : value.missing_chunks) append_u32(output, index);
    append_string(output, value.reason_code);
    return output;
}

WorkspaceFilePlanReply decode_workspace_file_plan_reply(
    const std::span<const std::byte> payload) {
    Reader reader(payload);
    const auto accepted = reader.u8();
    if (accepted > 1) throw std::invalid_argument("workspace accepted flag invalid");
    WorkspaceFilePlanReply value{
        .accepted = accepted == 1,
        .missing_chunks = {},
        .reason_code = {},
    };
    const auto count = reader.u32();
    if (count > max_workspace_wire_chunks) {
        throw std::length_error("workspace missing chunk count exceeds limit");
    }
    value.missing_chunks.reserve(count);
    for (std::uint32_t index = 0; index < count; ++index) {
        value.missing_chunks.push_back(reader.u32());
    }
    value.reason_code = reader.string(64);
    require_end(reader);
    validate_workspace_file_plan_reply(value);
    return value;
}

std::vector<std::byte> encode_workspace_file_chunk_command(
    const WorkspaceFileChunkCommand& value) {
    validate_workspace_file_chunk_command(value);
    std::vector<std::byte> output;
    append_identity(output, value.session_id, value.workspace_id, value.revision);
    append_string(output, value.transfer_id);
    append_u32(output, value.index);
    append_bytes(output, value.bytes);
    require_payload_limit(output);
    return output;
}

WorkspaceFileChunkCommand decode_workspace_file_chunk_command(
    const std::span<const std::byte> payload) {
    Reader reader(payload);
    WorkspaceFileChunkCommand value{
        .session_id = reader.string(64),
        .workspace_id = reader.string(64),
        .revision = reader.u64(),
        .transfer_id = reader.string(64),
        .index = reader.u32(),
        .bytes = reader.bytes(max_workspace_chunk_bytes),
    };
    require_end(reader);
    validate_workspace_file_chunk_command(value);
    return value;
}

std::vector<std::byte> encode_workspace_commit_command(
    const WorkspaceCommitCommand& value) {
    validate_workspace_commit_command(value);
    std::vector<std::byte> output;
    append_identity(output, value.session_id, value.workspace_id, value.revision);
    append_string(output, value.manifest_sha256);
    return output;
}

WorkspaceCommitCommand decode_workspace_commit_command(
    const std::span<const std::byte> payload) {
    Reader reader(payload);
    WorkspaceCommitCommand value{
        .session_id = reader.string(64),
        .workspace_id = reader.string(64),
        .revision = reader.u64(),
        .manifest_sha256 = reader.string(64),
    };
    require_end(reader);
    validate_workspace_commit_command(value);
    return value;
}

std::vector<std::byte> encode_workspace_commit_reply(
    const WorkspaceCommitReply& value) {
    validate_workspace_commit_reply(value);
    std::vector<std::byte> output;
    append_u8(output, value.accepted ? 1 : 0);
    append_u64(output, value.revision);
    append_string(output, value.manifest_sha256);
    append_string(output, value.reason_code);
    return output;
}

WorkspaceCommitReply decode_workspace_commit_reply(
    const std::span<const std::byte> payload) {
    Reader reader(payload);
    const auto accepted = reader.u8();
    if (accepted > 1) throw std::invalid_argument("workspace accepted flag invalid");
    WorkspaceCommitReply value{
        .accepted = accepted == 1,
        .revision = reader.u64(),
        .manifest_sha256 = reader.string(64, true),
        .reason_code = reader.string(64),
    };
    require_end(reader);
    validate_workspace_commit_reply(value);
    return value;
}

}  // namespace rwn::protocol
