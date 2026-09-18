#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace rwn::protocol {

enum class MessageType : std::uint16_t {
    hello = 1,
    authenticate = 2,
    session_open = 3,
    capability_request = 4,
    pairing_confirm = 5,
    pairing_result = 6,
    workspace_manifest = 10,
    workspace_diff = 11,
    workspace_file_plan = 12,
    workspace_file_chunk = 13,
    workspace_commit = 14,
    command_exec = 20,
    command_result = 21,
    build_submit = 30,
    build_status = 31,
    artifact_manifest = 40,
    artifact_chunk = 41,
    artifact_resume = 42,
    deploy_submit = 43,
    deploy_status = 44,
    desktop_keyframe_request = 50,
    desktop_input = 51,
    clipboard_update = 52,
    desktop_permission_status = 53,
    desktop_latency = 54,
    transport_capabilities = 70,
    transport_recovery = 71,
    transport_status = 72,
};

struct UnknownField {
    std::uint16_t tag{};
    std::vector<std::byte> value;

    [[nodiscard]] bool operator==(const UnknownField&) const = default;
};

struct Envelope {
    std::uint16_t version{1};
    MessageType type{MessageType::hello};
    std::string correlation_id;
    std::vector<std::byte> payload;
    std::vector<UnknownField> unknown_fields;

    [[nodiscard]] bool operator==(const Envelope&) const = default;
};

inline constexpr std::size_t max_correlation_id_size = 1024;
inline constexpr std::size_t max_payload_size = 16U * 1024U * 1024U;
inline constexpr std::size_t max_unknown_field_size = 1024U * 1024U;
inline constexpr std::size_t max_unknown_field_count = 128;

[[nodiscard]] std::vector<std::byte> encode(const Envelope& envelope);
[[nodiscard]] Envelope decode(std::span<const std::byte> bytes);

}  // namespace rwn::protocol
