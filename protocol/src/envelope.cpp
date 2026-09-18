#include "rwn/protocol/envelope.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace rwn::protocol {
namespace {

constexpr std::array<std::byte, 4> magic{
    std::byte{'R'}, std::byte{'W'}, std::byte{'N'}, std::byte{'1'}};

void append_u16(std::vector<std::byte>& output, const std::uint16_t value) {
    output.push_back(static_cast<std::byte>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::byte>(value & 0xffU));
}

void append_u32(std::vector<std::byte>& output, const std::uint32_t value) {
    for (const unsigned shift : {24U, 16U, 8U, 0U}) {
        output.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
    }
}

void append_bytes(std::vector<std::byte>& output, const std::span<const std::byte> bytes) {
    output.insert(output.end(), bytes.begin(), bytes.end());
}

class Reader {
public:
    explicit Reader(const std::span<const std::byte> bytes) : bytes_(bytes) {}

    [[nodiscard]] std::uint16_t read_u16() {
        require(2);
        const auto high = std::to_integer<std::uint16_t>(bytes_[offset_]);
        const auto low = std::to_integer<std::uint16_t>(bytes_[offset_ + 1]);
        offset_ += 2;
        return static_cast<std::uint16_t>((high << 8U) | low);
    }

    [[nodiscard]] std::uint32_t read_u32() {
        require(4);
        std::uint32_t result{};
        for (int index = 0; index < 4; ++index) {
            result = (result << 8U) | std::to_integer<std::uint32_t>(bytes_[offset_++]);
        }
        return result;
    }

    [[nodiscard]] std::span<const std::byte> read_bytes(const std::size_t size) {
        require(size);
        const auto result = bytes_.subspan(offset_, size);
        offset_ += size;
        return result;
    }

    [[nodiscard]] bool empty() const { return offset_ == bytes_.size(); }

private:
    void require(const std::size_t size) const {
        if (size > bytes_.size() - offset_) {
            throw std::invalid_argument("truncated protocol envelope");
        }
    }

    std::span<const std::byte> bytes_;
    std::size_t offset_{};
};

std::uint32_t checked_u32(const std::size_t value, const std::string_view field) {
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error(std::string(field) + " exceeds wire limit");
    }
    return static_cast<std::uint32_t>(value);
}

void validate(const Envelope& envelope) {
    if (envelope.version == 0) {
        throw std::invalid_argument("protocol version must be non-zero");
    }
    if (envelope.correlation_id.size() > max_correlation_id_size) {
        throw std::length_error("correlation id exceeds limit");
    }
    if (envelope.payload.size() > max_payload_size) {
        throw std::length_error("payload exceeds limit");
    }
    if (envelope.unknown_fields.size() > max_unknown_field_count) {
        throw std::length_error("too many unknown fields");
    }
    for (const auto& field : envelope.unknown_fields) {
        if (field.value.size() > max_unknown_field_size) {
            throw std::length_error("unknown field exceeds limit");
        }
    }
}

}  // namespace

std::vector<std::byte> encode(const Envelope& envelope) {
    validate(envelope);
    std::vector<std::byte> output;
    output.reserve(18 + envelope.correlation_id.size() + envelope.payload.size());
    append_bytes(output, magic);
    append_u16(output, envelope.version);
    append_u16(output, static_cast<std::uint16_t>(envelope.type));
    append_u32(output, checked_u32(envelope.correlation_id.size(), "correlation id"));
    append_u32(output, checked_u32(envelope.payload.size(), "payload"));
    append_u16(output, static_cast<std::uint16_t>(envelope.unknown_fields.size()));
    append_bytes(output, std::as_bytes(std::span{envelope.correlation_id}));
    append_bytes(output, envelope.payload);
    for (const auto& field : envelope.unknown_fields) {
        append_u16(output, field.tag);
        append_u32(output, checked_u32(field.value.size(), "unknown field"));
        append_bytes(output, field.value);
    }
    return output;
}

Envelope decode(const std::span<const std::byte> bytes) {
    Reader reader(bytes);
    if (!std::ranges::equal(reader.read_bytes(magic.size()), magic)) {
        throw std::invalid_argument("invalid protocol magic");
    }

    Envelope envelope;
    envelope.version = reader.read_u16();
    envelope.type = static_cast<MessageType>(reader.read_u16());
    const auto correlation_size = reader.read_u32();
    const auto payload_size = reader.read_u32();
    const auto unknown_count = reader.read_u16();

    if (correlation_size > max_correlation_id_size || payload_size > max_payload_size ||
        unknown_count > max_unknown_field_count) {
        throw std::length_error("declared envelope field exceeds limit");
    }

    const auto correlation = reader.read_bytes(correlation_size);
    envelope.correlation_id.assign(
        reinterpret_cast<const char*>(correlation.data()), correlation.size());
    const auto payload = reader.read_bytes(payload_size);
    envelope.payload.assign(payload.begin(), payload.end());

    envelope.unknown_fields.reserve(unknown_count);
    for (std::uint16_t index = 0; index < unknown_count; ++index) {
        UnknownField field;
        field.tag = reader.read_u16();
        const auto field_size = reader.read_u32();
        if (field_size > max_unknown_field_size) {
            throw std::length_error("declared unknown field exceeds limit");
        }
        const auto value = reader.read_bytes(field_size);
        field.value.assign(value.begin(), value.end());
        envelope.unknown_fields.push_back(std::move(field));
    }

    if (!reader.empty()) {
        throw std::invalid_argument("trailing bytes in protocol envelope");
    }
    validate(envelope);
    return envelope;
}

}  // namespace rwn::protocol
