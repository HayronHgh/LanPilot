#include "rwn/protocol/session_control.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <ranges>
#include <set>
#include <stdexcept>
#include <string_view>

namespace rwn::protocol {
namespace {

[[nodiscard]] bool valid_identifier(const std::string_view value) {
    return !value.empty() && value.size() <= max_session_identifier_size &&
        std::ranges::all_of(value, [](const unsigned char character) {
            return std::isalnum(character) != 0 || character == '-' ||
                character == '_' || character == '.';
        });
}

[[nodiscard]] bool valid_display_name(const std::string_view value) {
    return !value.empty() && value.size() <= max_session_identifier_size &&
        std::ranges::all_of(value, [](const unsigned char character) {
            return character >= 0x20U && character != 0x7fU;
        });
}

[[nodiscard]] bool valid_fingerprint(const std::string_view value) {
    return value.size() == 64 &&
        std::ranges::all_of(value, [](const unsigned char character) {
            return std::isdigit(character) != 0 ||
                (character >= 'a' && character <= 'f');
        });
}

void require_capabilities(const std::vector<std::string>& values) {
    if (values.empty() || values.size() > max_session_capability_count) {
        throw std::invalid_argument("session capability count is invalid");
    }
    std::set<std::string, std::less<>> unique;
    for (const auto& value : values) {
        if (!valid_identifier(value) || !unique.insert(value).second) {
            throw std::invalid_argument(
                "session capabilities must be unique identifiers");
        }
    }
}

void append_u16(std::vector<std::byte>& output, const std::uint16_t value) {
    output.push_back(static_cast<std::byte>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::byte>(value & 0xffU));
}

void append_string(
    std::vector<std::byte>& output, const std::string_view value) {
    if (value.size() > std::numeric_limits<std::uint16_t>::max()) {
        throw std::length_error("session string exceeds wire limit");
    }
    append_u16(output, static_cast<std::uint16_t>(value.size()));
    output.insert(
        output.end(), reinterpret_cast<const std::byte*>(value.data()),
        reinterpret_cast<const std::byte*>(value.data() + value.size()));
}

void append_strings(
    std::vector<std::byte>& output,
    const std::vector<std::string>& values) {
    output.push_back(static_cast<std::byte>(values.size()));
    for (const auto& value : values) append_string(output, value);
}

class Reader {
public:
    explicit Reader(const std::span<const std::byte> payload)
        : payload_(payload) {}

    [[nodiscard]] std::uint8_t read_u8() {
        require(1);
        return std::to_integer<std::uint8_t>(payload_[offset_++]);
    }

    [[nodiscard]] std::uint16_t read_u16() {
        require(2);
        const auto result = static_cast<std::uint16_t>(
            (std::to_integer<std::uint16_t>(payload_[offset_]) << 8U) |
            std::to_integer<std::uint16_t>(payload_[offset_ + 1]));
        offset_ += 2;
        return result;
    }

    [[nodiscard]] std::string read_string() {
        const auto size = read_u16();
        if (size == 0 || size > max_session_identifier_size) {
            throw std::invalid_argument("session wire string size is invalid");
        }
        require(size);
        const auto* data = reinterpret_cast<const char*>(
            payload_.data() + offset_);
        offset_ += size;
        return std::string(data, size);
    }

    [[nodiscard]] std::vector<std::string> read_strings(
        const bool allow_empty) {
        const auto count = read_u8();
        if ((!allow_empty && count == 0) ||
            count > max_session_capability_count) {
            throw std::invalid_argument(
                "session wire capability count is invalid");
        }
        std::vector<std::string> result;
        result.reserve(count);
        for (std::uint8_t index = 0; index < count; ++index) {
            result.push_back(read_string());
        }
        return result;
    }

    [[nodiscard]] bool empty() const noexcept {
        return offset_ == payload_.size();
    }

private:
    void require(const std::size_t size) const {
        if (size > payload_.size() - offset_) {
            throw std::invalid_argument("truncated session control payload");
        }
    }

    std::span<const std::byte> payload_;
    std::size_t offset_{};
};

}  // namespace

void validate_session_open_command(const SessionOpenCommand& command) {
    if (!valid_identifier(command.device_id) ||
        !valid_identifier(command.session_id) ||
        !valid_identifier(command.workspace_id) ||
        command.lease_minutes == 0 || command.lease_minutes > 60) {
        throw std::invalid_argument("session open command is invalid");
    }
    require_capabilities(command.requested_capabilities);
}

void validate_session_open_reply(const SessionOpenReply& reply) {
    if (!valid_identifier(reply.reason_code)) {
        throw std::invalid_argument("session reply reason code is invalid");
    }
    if (!reply.granted_capabilities.empty()) {
        require_capabilities(reply.granted_capabilities);
    }
    if (!reply.denied_capabilities.empty()) {
        require_capabilities(reply.denied_capabilities);
    }
    if (reply.accepted && reply.granted_capabilities.empty()) {
        throw std::invalid_argument(
            "accepted session reply requires a granted capability");
    }
    if (!reply.accepted && !reply.granted_capabilities.empty()) {
        throw std::invalid_argument(
            "denied session reply cannot grant capabilities");
    }
    if (!reply.accepted && reply.denied_capabilities.empty()) {
        throw std::invalid_argument(
            "denied session reply requires a denied capability");
    }
    std::set<std::string, std::less<>> partition{
        reply.granted_capabilities.begin(), reply.granted_capabilities.end()};
    for (const auto& capability : reply.denied_capabilities) {
        if (!partition.insert(capability).second) {
            throw std::invalid_argument(
                "session reply capability sets must not overlap");
        }
    }
}

std::vector<std::byte> encode_session_open_command(
    const SessionOpenCommand& command) {
    validate_session_open_command(command);
    std::vector<std::byte> output;
    append_string(output, command.device_id);
    append_string(output, command.session_id);
    append_string(output, command.workspace_id);
    append_strings(output, command.requested_capabilities);
    append_u16(output, command.lease_minutes);
    return output;
}

SessionOpenCommand decode_session_open_command(
    const std::span<const std::byte> payload) {
    Reader reader(payload);
    SessionOpenCommand command{
        .device_id = reader.read_string(),
        .session_id = reader.read_string(),
        .workspace_id = reader.read_string(),
        .requested_capabilities = reader.read_strings(false),
        .lease_minutes = reader.read_u16(),
    };
    if (!reader.empty()) {
        throw std::invalid_argument("trailing session command bytes");
    }
    validate_session_open_command(command);
    return command;
}

std::vector<std::byte> encode_session_open_reply(
    const SessionOpenReply& reply) {
    validate_session_open_reply(reply);
    std::vector<std::byte> output{
        reply.accepted ? std::byte{1} : std::byte{0}};
    append_strings(output, reply.granted_capabilities);
    append_strings(output, reply.denied_capabilities);
    append_string(output, reply.reason_code);
    return output;
}

SessionOpenReply decode_session_open_reply(
    const std::span<const std::byte> payload) {
    Reader reader(payload);
    const auto accepted = reader.read_u8();
    if (accepted > 1) {
        throw std::invalid_argument("session reply accepted flag is invalid");
    }
    SessionOpenReply reply{
        .accepted = accepted == 1,
        .granted_capabilities = reader.read_strings(true),
        .denied_capabilities = reader.read_strings(true),
        .reason_code = reader.read_string(),
    };
    if (!reader.empty()) {
        throw std::invalid_argument("trailing session reply bytes");
    }
    validate_session_open_reply(reply);
    return reply;
}

void validate_pairing_confirm_command(const PairingConfirmCommand& command) {
    const auto code_valid = command.six_digit_code.size() == 6 &&
        std::ranges::all_of(
            command.six_digit_code, [](const unsigned char character) {
                return std::isdigit(character) != 0;
            });
    if (!code_valid || !valid_identifier(command.device_id) ||
        !valid_display_name(command.display_name) ||
        !valid_fingerprint(command.certificate_sha256)) {
        throw std::invalid_argument("pairing confirmation command is invalid");
    }
}

void validate_pairing_confirm_reply(const PairingConfirmReply& reply) {
    if (!valid_identifier(reply.device_id) ||
        !valid_identifier(reply.reason_code)) {
        throw std::invalid_argument("pairing confirmation reply is invalid");
    }
    if (reply.accepted && reply.reason_code != "pairing_completed") {
        throw std::invalid_argument("accepted pairing reply reason is invalid");
    }
    if (!reply.accepted && reply.reason_code == "pairing_completed") {
        throw std::invalid_argument("rejected pairing reply reason is invalid");
    }
}

std::vector<std::byte> encode_pairing_confirm_command(
    const PairingConfirmCommand& command) {
    validate_pairing_confirm_command(command);
    std::vector<std::byte> output;
    append_string(output, command.six_digit_code);
    append_string(output, command.device_id);
    append_string(output, command.display_name);
    append_string(output, command.certificate_sha256);
    return output;
}

PairingConfirmCommand decode_pairing_confirm_command(
    const std::span<const std::byte> payload) {
    Reader reader(payload);
    PairingConfirmCommand command{
        .six_digit_code = reader.read_string(),
        .device_id = reader.read_string(),
        .display_name = reader.read_string(),
        .certificate_sha256 = reader.read_string(),
    };
    if (!reader.empty())
        throw std::invalid_argument("trailing pairing command bytes");
    validate_pairing_confirm_command(command);
    return command;
}

std::vector<std::byte> encode_pairing_confirm_reply(
    const PairingConfirmReply& reply) {
    validate_pairing_confirm_reply(reply);
    std::vector<std::byte> output{
        reply.accepted ? std::byte{1} : std::byte{0}};
    append_string(output, reply.device_id);
    append_string(output, reply.reason_code);
    return output;
}

PairingConfirmReply decode_pairing_confirm_reply(
    const std::span<const std::byte> payload) {
    Reader reader(payload);
    const auto accepted = reader.read_u8();
    if (accepted > 1)
        throw std::invalid_argument("pairing reply accepted flag is invalid");
    PairingConfirmReply reply{
        .accepted = accepted == 1,
        .device_id = reader.read_string(),
        .reason_code = reader.read_string(),
    };
    if (!reader.empty())
        throw std::invalid_argument("trailing pairing reply bytes");
    validate_pairing_confirm_reply(reply);
    return reply;
}

}  // namespace rwn::protocol
