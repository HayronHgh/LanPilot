#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace rwn::protocol {

inline constexpr std::size_t max_session_identifier_size = 64;
inline constexpr std::size_t max_session_capability_count = 32;

struct SessionOpenCommand {
    std::string device_id;
    std::string session_id;
    std::string workspace_id;
    std::vector<std::string> requested_capabilities;
    std::uint16_t lease_minutes{15};

    [[nodiscard]] bool operator==(const SessionOpenCommand&) const = default;
};

struct SessionOpenReply {
    bool accepted{};
    std::vector<std::string> granted_capabilities;
    std::vector<std::string> denied_capabilities;
    std::string reason_code;

    [[nodiscard]] bool operator==(const SessionOpenReply&) const = default;
};

struct PairingConfirmCommand {
    std::string six_digit_code;
    std::string device_id;
    std::string display_name;
    std::string certificate_sha256;

    [[nodiscard]] bool operator==(const PairingConfirmCommand&) const = default;
};

struct PairingConfirmReply {
    bool accepted{};
    std::string device_id;
    std::string reason_code;

    [[nodiscard]] bool operator==(const PairingConfirmReply&) const = default;
};

void validate_session_open_command(const SessionOpenCommand& command);
void validate_session_open_reply(const SessionOpenReply& reply);
[[nodiscard]] std::vector<std::byte> encode_session_open_command(
    const SessionOpenCommand& command);
[[nodiscard]] SessionOpenCommand decode_session_open_command(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_session_open_reply(
    const SessionOpenReply& reply);
[[nodiscard]] SessionOpenReply decode_session_open_reply(
    std::span<const std::byte> payload);
void validate_pairing_confirm_command(const PairingConfirmCommand& command);
void validate_pairing_confirm_reply(const PairingConfirmReply& reply);
[[nodiscard]] std::vector<std::byte> encode_pairing_confirm_command(
    const PairingConfirmCommand& command);
[[nodiscard]] PairingConfirmCommand decode_pairing_confirm_command(
    std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_pairing_confirm_reply(
    const PairingConfirmReply& reply);
[[nodiscard]] PairingConfirmReply decode_pairing_confirm_reply(
    std::span<const std::byte> payload);

}  // namespace rwn::protocol
