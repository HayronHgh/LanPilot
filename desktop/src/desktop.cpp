#include "rwn/desktop/desktop.hpp"

#include "rwn/core/content_hash.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <limits>
#include <stdexcept>
#include <utility>

namespace rwn::desktop {

bool visual_message_allowed(
    const VisualRuntimeMode mode, const VisualMessageType type) noexcept {
    switch (type) {
        case VisualMessageType::cursor_position:
        case VisualMessageType::cursor_shape:
        case VisualMessageType::state_reset:
            return true;
        case VisualMessageType::h264_access_unit:
            return mode != VisualRuntimeMode::exact_only;
        case VisualMessageType::full_snapshot:
        case VisualMessageType::raw_rect:
        case VisualMessageType::frame_commit:
            return mode != VisualRuntimeMode::h264;
        case VisualMessageType::lz4_rect:
        case VisualMessageType::copy_rect:
            return false;
    }
    return false;
}
namespace {

constexpr std::array<std::byte, 4> video_magic{
    std::byte{'R'}, std::byte{'W'}, std::byte{'V'}, std::byte{'1'}};
constexpr std::array<std::byte, 4> input_magic{
    std::byte{'R'}, std::byte{'W'}, std::byte{'I'}, std::byte{'1'}};
constexpr std::array<std::byte, 4> clipboard_magic{
    std::byte{'R'}, std::byte{'W'}, std::byte{'C'}, std::byte{'1'}};
constexpr std::array<std::byte, 4> keyframe_magic{
    std::byte{'R'}, std::byte{'W'}, std::byte{'K'}, std::byte{'1'}};
constexpr std::array<std::byte, 4> preview_magic{
    std::byte{'R'}, std::byte{'W'}, std::byte{'P'}, std::byte{'1'}};
constexpr std::array<std::byte, 4> encoded_preview_magic{
    std::byte{'R'}, std::byte{'W'}, std::byte{'H'}, std::byte{'1'}};
constexpr std::array<std::byte, 4> visual_message_magic{
    std::byte{'R'}, std::byte{'W'}, std::byte{'V'}, std::byte{'2'}};
constexpr std::array<std::byte, 4> reverse_control_magic{
    std::byte{'R'}, std::byte{'W'}, std::byte{'C'}, std::byte{'1'}};
constexpr std::size_t video_header_size = 42;
constexpr std::size_t maximum_video_payload =
    maximum_media_datagram_size - video_header_size;

class Writer {
public:
    void bytes(const std::span<const std::byte> value) {
        output_.insert(output_.end(), value.begin(), value.end());
    }
    void u8(const std::uint8_t value) {
        output_.push_back(static_cast<std::byte>(value));
    }
    void u16(const std::uint16_t value) {
        output_.push_back(static_cast<std::byte>((value >> 8U) & 0xffU));
        output_.push_back(static_cast<std::byte>(value & 0xffU));
    }
    void u32(const std::uint32_t value) {
        for (const unsigned shift : {24U, 16U, 8U, 0U}) {
            output_.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
        }
    }
    void u64(const std::uint64_t value) {
        for (const unsigned shift : {56U, 48U, 40U, 32U, 24U, 16U, 8U, 0U}) {
            output_.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
        }
    }
    [[nodiscard]] std::vector<std::byte> finish() { return std::move(output_); }

private:
    std::vector<std::byte> output_;
};

class Reader {
public:
    explicit Reader(const std::span<const std::byte> bytes) : bytes_(bytes) {}
    [[nodiscard]] std::uint8_t u8() {
        require(1);
        return std::to_integer<std::uint8_t>(bytes_[offset_++]);
    }
    [[nodiscard]] std::uint16_t u16() {
        require(2);
        std::uint16_t result{};
        for (int index = 0; index < 2; ++index) {
            result = static_cast<std::uint16_t>(
                (result << 8U) | std::to_integer<std::uint16_t>(bytes_[offset_++]));
        }
        return result;
    }
    [[nodiscard]] std::uint32_t u32() {
        require(4);
        std::uint32_t result{};
        for (int index = 0; index < 4; ++index) {
            result = (result << 8U) |
                     std::to_integer<std::uint32_t>(bytes_[offset_++]);
        }
        return result;
    }
    [[nodiscard]] std::uint64_t u64() {
        require(8);
        std::uint64_t result{};
        for (int index = 0; index < 8; ++index) {
            result = (result << 8U) |
                     std::to_integer<std::uint64_t>(bytes_[offset_++]);
        }
        return result;
    }
    [[nodiscard]] std::span<const std::byte> bytes(const std::size_t size) {
        require(size);
        const auto value = bytes_.subspan(offset_, size);
        offset_ += size;
        return value;
    }
    [[nodiscard]] bool empty() const noexcept { return offset_ == bytes_.size(); }

private:
    void require(const std::size_t size) const {
        if (size > bytes_.size() - offset_) {
            throw std::invalid_argument("truncated desktop protocol message");
        }
    }
    std::span<const std::byte> bytes_;
    std::size_t offset_{};
};

void require_magic(Reader& reader, const std::span<const std::byte> magic) {
    if (!std::ranges::equal(reader.bytes(magic.size()), magic)) {
        throw std::invalid_argument("invalid desktop protocol magic");
    }
}

void validate_dimensions(const std::uint32_t width, const std::uint32_t height) {
    if (width == 0 || height == 0 || width > 7680 || height > 4320) {
        throw std::invalid_argument("video dimensions exceed bounds");
    }
}

void validate_raw_frame(const RawFrame& frame) {
    validate_dimensions(frame.width, frame.height);
    const auto packed_stride = static_cast<std::size_t>(frame.width) * 4U;
    const auto expected_size =
        static_cast<std::size_t>(frame.row_stride) * frame.height;
    if (frame.frame_id == 0 || frame.captured_at_us == 0 ||
        frame.row_stride < packed_stride || frame.bgra.size() != expected_size) {
        throw std::invalid_argument("invalid raw preview frame");
    }
}

void validate_preview_header(const PreviewFrameHeader& header) {
    if (header.frame_id == 0 || header.captured_at_us == 0 ||
        header.width == 0 || header.height == 0 ||
        header.width > maximum_preview_width ||
        header.height > maximum_preview_height) {
        throw std::invalid_argument("invalid preview frame header");
    }
    const auto expected = static_cast<std::size_t>(header.width) *
                          header.height * 4U;
    if (expected > maximum_preview_frame_size ||
        header.payload_size != expected) {
        throw std::invalid_argument("invalid preview frame payload size");
    }
}

void validate_encoded_preview_header(
    const EncodedPreviewFrameHeader& header) {
    if (header.frame_id == 0 || header.captured_at_us == 0 ||
        header.width == 0 || header.height == 0 ||
        header.width > maximum_preview_width ||
        header.height > maximum_preview_height ||
        header.payload_size == 0 ||
        header.payload_size > maximum_encoded_frame_size) {
        throw std::invalid_argument("invalid encoded preview frame header");
    }
}

void validate_visual_header(const VisualMessageHeader& header) {
    const auto type = static_cast<std::uint8_t>(header.type);
    if (type < static_cast<std::uint8_t>(VisualMessageType::h264_access_unit) ||
        type > static_cast<std::uint8_t>(VisualMessageType::state_reset) ||
        header.session_generation == 0 || header.representation_epoch == 0 ||
        header.visual_sequence == 0 ||
        header.captured_at_us == 0) {
        throw std::invalid_argument("invalid visual message header");
    }
    const auto known_flags = visual_flag_frame_final | visual_flag_keyframe;
    if ((header.flags & ~known_flags) != 0) {
        throw std::invalid_argument("unknown visual message flags");
    }
    if (header.type == VisualMessageType::h264_access_unit) {
        if (header.frame_id == 0 ||
            (header.flags & visual_flag_frame_final) == 0 ||
            header.payload_size < 9U ||
            header.payload_size > maximum_encoded_frame_size + 8U) {
            throw std::invalid_argument("invalid H.264 visual message header");
        }
    } else if (header.type == VisualMessageType::cursor_position) {
        if (header.flags != 0 || header.payload_size != 20U) {
            throw std::invalid_argument("invalid cursor position header");
        }
    } else if (header.type == VisualMessageType::cursor_shape) {
        if (header.flags != 0 || header.payload_size < 20U ||
            header.payload_size > 20U + 256U * 256U * 4U) {
            throw std::invalid_argument("invalid cursor shape header");
        }
    } else if (header.payload_size > maximum_preview_frame_size + 64U) {
        throw std::invalid_argument("visual message payload exceeds bounds");
    }
}

void validate_reverse_control_header(const ReverseControlHeader& header) {
    const auto type = static_cast<std::uint8_t>(header.type);
    if (type < static_cast<std::uint8_t>(ReverseControlType::input_event) ||
        type > static_cast<std::uint8_t>(ReverseControlType::ping) ||
        header.flags != 0 || header.input_epoch == 0 || header.sequence == 0 ||
        header.occurred_at_us == 0 ||
        header.payload_size > maximum_reverse_control_payload) {
        throw std::invalid_argument("invalid reverse control header");
    }
}

void validate_fragment(const VideoFragment& fragment) {
    validate_dimensions(fragment.width, fragment.height);
    if (fragment.frame_id == 0 || fragment.captured_at_us == 0 ||
        fragment.codec != VideoCodec::h264 || fragment.fragment_count == 0 ||
        fragment.fragment_index >= fragment.fragment_count ||
        fragment.total_size == 0 ||
        fragment.total_size > maximum_encoded_frame_size ||
        fragment.payload.empty() || fragment.payload.size() > maximum_video_payload) {
        throw std::invalid_argument("invalid video fragment");
    }
    const auto maximum_count =
        (maximum_encoded_frame_size + maximum_video_payload - 1U) /
        maximum_video_payload;
    if (fragment.fragment_count > maximum_count ||
        fragment.payload.size() > fragment.total_size) {
        throw std::invalid_argument("video fragment allocation exceeds bounds");
    }
}

void validate_clipboard(const ClipboardUpdate& update) {
    if (update.origin.empty() || update.origin.size() > 128 ||
        update.origin.find('\0') != std::string::npos || update.revision == 0 ||
        update.utf8_text.size() > maximum_clipboard_text_size ||
        !valid_utf8(update.utf8_text) || update.content_sha256.size() != 64 ||
        update.content_sha256 != core::sha256_hex(update.utf8_text)) {
        throw std::invalid_argument("invalid clipboard update");
    }
}

[[nodiscard]] std::uint32_t checked_u32(const std::size_t value) {
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("desktop message field exceeds wire limit");
    }
    return static_cast<std::uint32_t>(value);
}

}  // namespace

RawFrame fit_preview_frame(
    const RawFrame& frame, const std::uint32_t maximum_width,
    const std::uint32_t maximum_height) {
    validate_raw_frame(frame);
    if (maximum_width == 0 || maximum_height == 0 ||
        maximum_width > maximum_preview_width ||
        maximum_height > maximum_preview_height) {
        throw std::invalid_argument("preview dimensions exceed bounds");
    }

    const auto width_scale = static_cast<double>(maximum_width) / frame.width;
    const auto height_scale = static_cast<double>(maximum_height) / frame.height;
    const auto scale = std::min({1.0, width_scale, height_scale});
    const auto output_width = std::max(
        1U, static_cast<std::uint32_t>(static_cast<double>(frame.width) * scale));
    const auto output_height = std::max(
        1U, static_cast<std::uint32_t>(static_cast<double>(frame.height) * scale));
    const auto output_stride = output_width * 4U;
    RawFrame result{
        .frame_id = frame.frame_id,
        .captured_at_us = frame.captured_at_us,
        .width = output_width,
        .height = output_height,
        .row_stride = output_stride,
        .bgra = std::vector<std::byte>(
            static_cast<std::size_t>(output_stride) * output_height),
    };
    for (std::uint32_t y = 0; y < output_height; ++y) {
        const auto source_y = static_cast<std::uint32_t>(
            static_cast<std::uint64_t>(y) * frame.height / output_height);
        for (std::uint32_t x = 0; x < output_width; ++x) {
            const auto source_x = static_cast<std::uint32_t>(
                static_cast<std::uint64_t>(x) * frame.width / output_width);
            const auto source_offset =
                static_cast<std::size_t>(source_y) * frame.row_stride +
                static_cast<std::size_t>(source_x) * 4U;
            const auto destination_offset =
                static_cast<std::size_t>(y) * output_stride +
                static_cast<std::size_t>(x) * 4U;
            std::copy_n(
                frame.bgra.begin() + static_cast<std::ptrdiff_t>(source_offset),
                4, result.bgra.begin() +
                       static_cast<std::ptrdiff_t>(destination_offset));
        }
    }
    return result;
}

std::vector<std::byte> encode_preview_frame_header(
    const PreviewFrameHeader& header) {
    validate_preview_header(header);
    Writer writer;
    writer.bytes(preview_magic);
    writer.u16(preview_protocol_version);
    writer.u16(0);
    writer.u64(header.frame_id);
    writer.u64(header.captured_at_us);
    writer.u32(header.width);
    writer.u32(header.height);
    writer.u32(header.payload_size);
    auto encoded = writer.finish();
    if (encoded.size() != preview_frame_header_size) {
        throw std::logic_error("preview frame header size mismatch");
    }
    return encoded;
}

PreviewFrameHeader decode_preview_frame_header(
    const std::span<const std::byte> bytes) {
    if (bytes.size() != preview_frame_header_size) {
        throw std::invalid_argument("invalid preview frame header size");
    }
    Reader reader(bytes);
    require_magic(reader, preview_magic);
    if (reader.u16() != preview_protocol_version || reader.u16() != 0) {
        throw std::invalid_argument("unsupported preview frame header");
    }
    PreviewFrameHeader header{
        .frame_id = reader.u64(),
        .captured_at_us = reader.u64(),
        .width = reader.u32(),
        .height = reader.u32(),
        .payload_size = reader.u32(),
    };
    if (!reader.empty()) {
        throw std::invalid_argument("trailing preview frame header bytes");
    }
    validate_preview_header(header);
    return header;
}

std::vector<std::byte> encode_encoded_preview_frame_header(
    const EncodedPreviewFrameHeader& header) {
    validate_encoded_preview_header(header);
    Writer writer;
    writer.bytes(encoded_preview_magic);
    writer.u16(preview_protocol_version);
    writer.u16(header.keyframe ? 1U : 0U);
    writer.u64(header.frame_id);
    writer.u64(header.captured_at_us);
    writer.u32(header.width);
    writer.u32(header.height);
    writer.u32(header.payload_size);
    auto encoded = writer.finish();
    if (encoded.size() != encoded_preview_frame_header_size) {
        throw std::logic_error("encoded preview frame header size mismatch");
    }
    return encoded;
}

EncodedPreviewFrameHeader decode_encoded_preview_frame_header(
    const std::span<const std::byte> bytes) {
    if (bytes.size() != encoded_preview_frame_header_size) {
        throw std::invalid_argument(
            "invalid encoded preview frame header size");
    }
    Reader reader(bytes);
    require_magic(reader, encoded_preview_magic);
    if (reader.u16() != preview_protocol_version) {
        throw std::invalid_argument(
            "unsupported encoded preview frame header");
    }
    const auto flags = reader.u16();
    if ((flags & 0xfffeU) != 0) {
        throw std::invalid_argument("unknown encoded preview frame flags");
    }
    EncodedPreviewFrameHeader header{
        .frame_id = reader.u64(),
        .captured_at_us = reader.u64(),
        .width = reader.u32(),
        .height = reader.u32(),
        .payload_size = reader.u32(),
        .keyframe = (flags & 1U) != 0,
    };
    if (!reader.empty()) {
        throw std::invalid_argument(
            "trailing encoded preview frame header bytes");
    }
    validate_encoded_preview_header(header);
    return header;
}

std::vector<std::byte> encode_visual_message_header(
    const VisualMessageHeader& header) {
    validate_visual_header(header);
    Writer writer;
    writer.bytes(visual_message_magic);
    writer.u16(visual_protocol_version);
    writer.u8(static_cast<std::uint8_t>(header.type));
    writer.u8(header.flags);
    writer.u16(static_cast<std::uint16_t>(visual_message_header_size));
    writer.u16(0);
    writer.u32(header.payload_size);
    writer.u64(header.session_generation);
    writer.u64(header.representation_epoch);
    writer.u64(header.visual_sequence);
    writer.u64(header.frame_id);
    writer.u64(header.captured_at_us);
    auto encoded = writer.finish();
    if (encoded.size() != visual_message_header_size) {
        throw std::logic_error("visual message header size mismatch");
    }
    return encoded;
}

VisualMessageHeader decode_visual_message_header(
    const std::span<const std::byte> bytes) {
    if (bytes.size() != visual_message_header_size) {
        throw std::invalid_argument("invalid visual message header size");
    }
    Reader reader(bytes);
    require_magic(reader, visual_message_magic);
    if (reader.u16() != visual_protocol_version) {
        throw std::invalid_argument("unsupported visual message header");
    }
    const auto type = static_cast<VisualMessageType>(reader.u8());
    const auto flags = reader.u8();
    if (reader.u16() != visual_message_header_size || reader.u16() != 0) {
        throw std::invalid_argument("unsupported visual message layout");
    }
    VisualMessageHeader header{
        .type = type,
        .flags = flags,
        .payload_size = reader.u32(),
        .session_generation = reader.u64(),
        .representation_epoch = reader.u64(),
        .visual_sequence = reader.u64(),
        .frame_id = reader.u64(),
        .captured_at_us = reader.u64(),
    };
    if (!reader.empty()) {
        throw std::invalid_argument("trailing visual message header bytes");
    }
    validate_visual_header(header);
    return header;
}

std::vector<std::byte> encode_reverse_control_header(
    const ReverseControlHeader& header) {
    validate_reverse_control_header(header);
    Writer writer;
    writer.bytes(reverse_control_magic);
    writer.u16(reverse_control_protocol_version);
    writer.u8(static_cast<std::uint8_t>(header.type));
    writer.u8(header.flags);
    writer.u32(header.payload_size);
    writer.u64(header.input_epoch);
    writer.u64(header.sequence);
    writer.u64(header.occurred_at_us);
    writer.u32(0);
    auto encoded = writer.finish();
    if (encoded.size() != reverse_control_header_size) {
        throw std::logic_error("reverse control header size mismatch");
    }
    return encoded;
}

ReverseControlHeader decode_reverse_control_header(
    const std::span<const std::byte> bytes) {
    if (bytes.size() != reverse_control_header_size) {
        throw std::invalid_argument("invalid reverse control header size");
    }
    Reader reader(bytes);
    require_magic(reader, reverse_control_magic);
    if (reader.u16() != reverse_control_protocol_version) {
        throw std::invalid_argument("unsupported reverse control protocol");
    }
    ReverseControlHeader header{
        .type = static_cast<ReverseControlType>(reader.u8()),
        .flags = reader.u8(),
        .payload_size = reader.u32(),
        .input_epoch = reader.u64(),
        .sequence = reader.u64(),
        .occurred_at_us = reader.u64(),
    };
    if (reader.u32() != 0 || !reader.empty()) {
        throw std::invalid_argument("unsupported reverse control layout");
    }
    validate_reverse_control_header(header);
    return header;
}

void validate_reverse_control_payload(
    const ReverseControlHeader& header,
    const std::span<const std::byte> payload) {
    validate_reverse_control_header(header);
    if (payload.size() != header.payload_size) {
        throw std::invalid_argument("reverse control payload size mismatch");
    }
    switch (header.type) {
        case ReverseControlType::input_event:
            if (payload.empty()) {
                throw std::invalid_argument("input control payload is empty");
            }
            static_cast<void>(decode_input_event(payload));
            return;
        case ReverseControlType::release_all_input:
        case ReverseControlType::request_full_snapshot:
        case ReverseControlType::ping:
            if (!payload.empty()) {
                throw std::invalid_argument(
                    "reverse control message requires an empty payload");
            }
            return;
        case ReverseControlType::frame_commit_ack:
            static_cast<void>(decode_frame_commit_ack(payload));
            return;
    }
    throw std::invalid_argument("unknown reverse control type");
}

void validate_visual_message_payload(
    const VisualMessageHeader& header,
    const std::span<const std::byte> payload) {
    validate_visual_header(header);
    if (payload.size() != header.payload_size) {
        throw std::invalid_argument("visual message payload size mismatch");
    }
    switch (header.type) {
        case VisualMessageType::h264_access_unit:
            static_cast<void>(decode_visual_h264_access_unit(payload));
            return;
        case VisualMessageType::cursor_position:
            static_cast<void>(decode_visual_cursor_position(payload));
            return;
        case VisualMessageType::full_snapshot:
            static_cast<void>(decode_visual_full_snapshot_chunk(payload));
            return;
        case VisualMessageType::raw_rect:
            static_cast<void>(decode_visual_raw_rect(payload));
            return;
        case VisualMessageType::lz4_rect:
            throw std::invalid_argument("LZ4 rectangle is not enabled");
        case VisualMessageType::copy_rect:
            if (payload.size() != 24U) {
                throw std::invalid_argument("invalid copy rectangle payload");
            }
            return;
        case VisualMessageType::cursor_shape:
            if (payload.size() < 20U ||
                payload.size() > 20U + 256U * 256U * 4U) {
                throw std::invalid_argument("invalid cursor shape payload");
            }
            static_cast<void>(decode_visual_cursor_shape(payload));
            return;
        case VisualMessageType::frame_commit:
            static_cast<void>(decode_visual_frame_commit(payload));
            return;
        case VisualMessageType::state_reset:
            static_cast<void>(decode_visual_state_reset(payload));
            return;
    }
    throw std::invalid_argument("unknown visual message type");
}

std::vector<std::byte> encode_visual_full_snapshot_chunk(
    const VisualFullSnapshotChunk& chunk) {
    validate_dimensions(chunk.surface_width, chunk.surface_height);
    const auto packed_stride = static_cast<std::uint64_t>(chunk.surface_width) * 4U;
    const auto expected_total = packed_stride * chunk.surface_height;
    if (chunk.pixel_format != CanonicalPixelFormat::bgra8_premultiplied_srgb ||
        chunk.row_stride != packed_stride || expected_total == 0 ||
        expected_total > maximum_snapshot_total_bytes ||
        chunk.total_bytes != expected_total || chunk.chunk.empty() ||
        chunk.chunk.size() > maximum_snapshot_wire_chunk_bytes ||
        chunk.chunk_offset > chunk.total_bytes ||
        chunk.chunk.size() > chunk.total_bytes - chunk.chunk_offset) {
        throw std::invalid_argument("invalid full snapshot chunk");
    }
    Writer writer;
    writer.u32(chunk.surface_width);
    writer.u32(chunk.surface_height);
    writer.u32(chunk.row_stride);
    writer.u32(static_cast<std::uint32_t>(chunk.pixel_format));
    writer.u32(chunk.total_bytes);
    writer.u32(chunk.chunk_offset);
    writer.u32(checked_u32(chunk.chunk.size()));
    writer.bytes(chunk.chunk);
    return writer.finish();
}

VisualFullSnapshotChunk decode_visual_full_snapshot_chunk(
    const std::span<const std::byte> payload) {
    if (payload.size() < 29U ||
        payload.size() > 28U + maximum_snapshot_wire_chunk_bytes) {
        throw std::invalid_argument("invalid full snapshot chunk size");
    }
    Reader reader(payload);
    VisualFullSnapshotChunk chunk{
        .surface_width = reader.u32(),
        .surface_height = reader.u32(),
        .row_stride = reader.u32(),
        .pixel_format = static_cast<CanonicalPixelFormat>(reader.u32()),
        .total_bytes = reader.u32(),
        .chunk_offset = reader.u32(),
        .chunk = {},
    };
    const auto chunk_size = reader.u32();
    const auto bytes = reader.bytes(chunk_size);
    if (!reader.empty()) {
        throw std::invalid_argument("trailing full snapshot chunk bytes");
    }
    chunk.chunk.assign(bytes.begin(), bytes.end());
    static_cast<void>(encode_visual_full_snapshot_chunk(chunk));
    return chunk;
}

std::vector<std::byte> encode_visual_raw_rect(const VisualRawRect& rect) {
    validate_dimensions(rect.surface_width, rect.surface_height);
    const auto packed_stride = static_cast<std::uint64_t>(rect.width) * 4U;
    const auto expected_size = packed_stride * rect.height;
    if (rect.pixel_format != CanonicalPixelFormat::bgra8_premultiplied_srgb ||
        rect.width == 0 || rect.height == 0 ||
        rect.x >= rect.surface_width || rect.y >= rect.surface_height ||
        rect.width > rect.surface_width - rect.x ||
        rect.height > rect.surface_height - rect.y ||
        rect.row_stride != packed_stride || expected_size == 0 ||
        expected_size > maximum_raw_rect_protocol_bytes ||
        rect.bgra.size() != expected_size || rect.base_frame_id == 0) {
        throw std::invalid_argument("invalid raw rectangle");
    }
    Writer writer;
    writer.u64(rect.base_frame_id);
    writer.u32(rect.surface_width);
    writer.u32(rect.surface_height);
    writer.u32(rect.x);
    writer.u32(rect.y);
    writer.u32(rect.width);
    writer.u32(rect.height);
    writer.u32(rect.row_stride);
    writer.u32(static_cast<std::uint32_t>(rect.pixel_format));
    writer.bytes(rect.bgra);
    return writer.finish();
}

VisualRawRect decode_visual_raw_rect(
    const std::span<const std::byte> payload) {
    if (payload.size() < 44U ||
        payload.size() > 40U + maximum_raw_rect_protocol_bytes) {
        throw std::invalid_argument("invalid raw rectangle size");
    }
    Reader reader(payload);
    VisualRawRect rect{
        .base_frame_id = reader.u64(),
        .surface_width = reader.u32(),
        .surface_height = reader.u32(),
        .x = reader.u32(),
        .y = reader.u32(),
        .width = reader.u32(),
        .height = reader.u32(),
        .row_stride = reader.u32(),
        .pixel_format = static_cast<CanonicalPixelFormat>(reader.u32()),
        .bgra = {},
    };
    const auto bytes = reader.bytes(payload.size() - 40U);
    rect.bgra.assign(bytes.begin(), bytes.end());
    static_cast<void>(encode_visual_raw_rect(rect));
    return rect;
}

std::array<std::byte, 32> advance_canonical_rect_digest(
    const std::array<std::byte, 32>& base_digest,
    const std::uint64_t target_frame_id,
    const std::span<const VisualRawRect> rectangles) {
    if (target_frame_id == 0 || rectangles.empty() ||
        rectangles.size() > maximum_raw_rect_transaction_count) {
        throw std::invalid_argument("invalid canonical rectangle digest input");
    }
    constexpr std::string_view domain{"RWN-CANONICAL-RECT-V1"};
    core::Sha256Accumulator accumulator;
    accumulator.update(std::as_bytes(std::span{domain}));
    accumulator.update(base_digest);
    Writer target;
    target.u64(target_frame_id);
    accumulator.update(target.finish());
    std::size_t total_bytes{};
    for (const auto& rectangle : rectangles) {
        auto encoded = encode_visual_raw_rect(rectangle);
        if (encoded.size() > maximum_raw_rect_protocol_bytes - total_bytes) {
            throw std::invalid_argument(
                "canonical rectangle transaction exceeds protocol limit");
        }
        total_bytes += encoded.size();
        Writer length;
        length.u32(static_cast<std::uint32_t>(encoded.size()));
        accumulator.update(length.finish());
        accumulator.update(encoded);
    }
    return accumulator.finish();
}

std::vector<std::byte> encode_visual_frame_commit(
    const VisualFrameCommit& commit) {
    Writer writer;
    writer.u64(commit.base_frame_id);
    return writer.finish();
}

VisualFrameCommit decode_visual_frame_commit(
    const std::span<const std::byte> payload) {
    if (payload.size() != 8U) {
        throw std::invalid_argument("invalid frame commit payload");
    }
    Reader reader(payload);
    VisualFrameCommit commit{.base_frame_id = reader.u64()};
    return commit;
}

std::vector<std::byte> encode_visual_state_reset(
    const VisualStateReset& reset) {
    const auto reason = static_cast<std::uint32_t>(reset.reason);
    if (reason < static_cast<std::uint32_t>(
                     VisualStateResetReason::representation_transition) ||
        reason > static_cast<std::uint32_t>(
                     VisualStateResetReason::snapshot_required)) {
        throw std::invalid_argument("unknown visual state reset reason");
    }
    Writer writer;
    writer.u32(reason);
    return writer.finish();
}

VisualStateReset decode_visual_state_reset(
    const std::span<const std::byte> payload) {
    if (payload.size() != 4U) {
        throw std::invalid_argument("invalid state reset payload");
    }
    Reader reader(payload);
    VisualStateReset reset{
        .reason = static_cast<VisualStateResetReason>(reader.u32())};
    static_cast<void>(encode_visual_state_reset(reset));
    return reset;
}

std::vector<std::byte> encode_frame_commit_ack(const FrameCommitAck& ack) {
    if (ack.session_generation == 0 || ack.representation_epoch == 0 ||
        ack.frame_id == 0) {
        throw std::invalid_argument("invalid frame commit ACK");
    }
    Writer writer;
    writer.u64(ack.session_generation);
    writer.u64(ack.representation_epoch);
    writer.u64(ack.frame_id);
    writer.bytes(ack.canonical_sha256);
    return writer.finish();
}

FrameCommitAck decode_frame_commit_ack(
    const std::span<const std::byte> payload) {
    if (payload.size() != 56U) {
        throw std::invalid_argument("invalid frame commit ACK payload");
    }
    Reader reader(payload);
    FrameCommitAck ack{
        .session_generation = reader.u64(),
        .representation_epoch = reader.u64(),
        .frame_id = reader.u64(),
    };
    const auto digest = reader.bytes(ack.canonical_sha256.size());
    std::copy(digest.begin(), digest.end(), ack.canonical_sha256.begin());
    static_cast<void>(encode_frame_commit_ack(ack));
    return ack;
}

bool frame_commit_ack_matches(
    const FrameCommitAck& ack,
    const std::uint64_t session_generation,
    const std::uint64_t representation_epoch,
    const std::uint64_t frame_id,
    const std::array<std::byte, 32>& canonical_sha256) noexcept {
    return session_generation != 0 && representation_epoch != 0 &&
        frame_id != 0 && ack.session_generation == session_generation &&
        ack.representation_epoch == representation_epoch &&
        ack.frame_id == frame_id &&
        ack.canonical_sha256 == canonical_sha256;
}

std::vector<std::byte> encode_visual_h264_access_unit(
    const VisualH264AccessUnit& access_unit) {
    validate_dimensions(access_unit.width, access_unit.height);
    if (access_unit.width > maximum_preview_width ||
        access_unit.height > maximum_preview_height ||
        access_unit.encoded.empty() ||
        access_unit.encoded.size() > maximum_encoded_frame_size) {
        throw std::invalid_argument("invalid visual H.264 access unit");
    }
    Writer writer;
    writer.u32(access_unit.width);
    writer.u32(access_unit.height);
    writer.bytes(access_unit.encoded);
    return writer.finish();
}

VisualH264AccessUnit decode_visual_h264_access_unit(
    const std::span<const std::byte> payload) {
    if (payload.size() < 9U ||
        payload.size() > maximum_encoded_frame_size + 8U) {
        throw std::invalid_argument("invalid visual H.264 payload size");
    }
    Reader reader(payload);
    VisualH264AccessUnit result{
        .width = reader.u32(),
        .height = reader.u32(),
        .encoded = {},
    };
    result.encoded.assign(
        payload.begin() + 8, payload.end());
    validate_dimensions(result.width, result.height);
    if (result.width > maximum_preview_width ||
        result.height > maximum_preview_height || result.encoded.empty()) {
        throw std::invalid_argument("invalid visual H.264 access unit");
    }
    return result;
}

std::vector<std::byte> encode_visual_cursor_position(
    const VisualCursorPosition& cursor) {
    if (cursor.x > 7680U || cursor.y > 4320U) {
        throw std::invalid_argument("cursor position exceeds bounds");
    }
    Writer writer;
    writer.u32(cursor.x);
    writer.u32(cursor.y);
    writer.u8(cursor.visible ? 1U : 0U);
    writer.u8(0);
    writer.u16(0);
    writer.u64(cursor.shape_id);
    return writer.finish();
}

VisualCursorPosition decode_visual_cursor_position(
    const std::span<const std::byte> payload) {
    if (payload.size() != 20U) {
        throw std::invalid_argument("invalid cursor position payload size");
    }
    Reader reader(payload);
    VisualCursorPosition result{
        .x = reader.u32(),
        .y = reader.u32(),
    };
    const auto visible = reader.u8();
    if (visible > 1U || reader.u8() != 0 || reader.u16() != 0) {
        throw std::invalid_argument("invalid cursor position payload");
    }
    result.visible = visible != 0;
    result.shape_id = reader.u64();
    if (result.x > 7680U || result.y > 4320U || !reader.empty()) {
        throw std::invalid_argument("cursor position exceeds bounds");
    }
    return result;
}

std::vector<std::byte> encode_visual_cursor_shape(
    const VisualCursorShape& cursor) {
    const auto expected = static_cast<std::size_t>(cursor.width) *
        cursor.height * 4U;
    if (cursor.shape_id == 0 || cursor.width == 0 || cursor.height == 0 ||
        cursor.width > 256U || cursor.height > 256U ||
        cursor.hotspot_x >= cursor.width || cursor.hotspot_y >= cursor.height ||
        cursor.bgra.size() != expected) {
        throw std::invalid_argument("invalid cursor shape");
    }
    Writer writer;
    writer.u64(cursor.shape_id);
    writer.u16(cursor.width);
    writer.u16(cursor.height);
    writer.u16(cursor.hotspot_x);
    writer.u16(cursor.hotspot_y);
    writer.u32(checked_u32(cursor.bgra.size()));
    writer.bytes(cursor.bgra);
    return writer.finish();
}

VisualCursorShape decode_visual_cursor_shape(
    const std::span<const std::byte> payload) {
    if (payload.size() < 20U ||
        payload.size() > 20U + 256U * 256U * 4U) {
        throw std::invalid_argument("invalid cursor shape payload size");
    }
    Reader reader(payload);
    VisualCursorShape result{
        .shape_id = reader.u64(),
        .width = reader.u16(),
        .height = reader.u16(),
        .hotspot_x = reader.u16(),
        .hotspot_y = reader.u16(),
        .bgra = {},
    };
    const auto size = reader.u32();
    const auto bytes = reader.bytes(size);
    result.bgra.assign(bytes.begin(), bytes.end());
    if (!reader.empty()) {
        throw std::invalid_argument("trailing cursor shape bytes");
    }
    static_cast<void>(encode_visual_cursor_shape(result));
    return result;
}

VisualSequenceResult VisualSequenceTracker::receive(
    const VisualMessageHeader& header) noexcept {
    if (generation_ == 0 || header.session_generation != generation_) {
        generation_ = header.session_generation;
        last_sequence_ = 0;
        if (header.visual_sequence != 1) return VisualSequenceResult::gap;
        last_sequence_ = 1;
        return VisualSequenceResult::new_generation;
    }
    if (header.visual_sequence != last_sequence_ + 1U) {
        return VisualSequenceResult::gap;
    }
    last_sequence_ = header.visual_sequence;
    return VisualSequenceResult::accepted;
}

void VisualSequenceTracker::reset() noexcept {
    generation_ = 0;
    last_sequence_ = 0;
}

std::vector<VideoFragment> fragment_frame(const VideoFrame& frame) {
    validate_dimensions(frame.width, frame.height);
    if (frame.frame_id == 0 || frame.captured_at_us == 0 ||
        frame.codec != VideoCodec::h264 || frame.encoded.empty() ||
        frame.encoded.size() > maximum_encoded_frame_size) {
        throw std::invalid_argument("invalid encoded video frame");
    }
    const auto count =
        (frame.encoded.size() + maximum_video_payload - 1U) /
        maximum_video_payload;
    if (count > std::numeric_limits<std::uint16_t>::max()) {
        throw std::length_error("encoded frame has too many fragments");
    }

    std::vector<VideoFragment> result;
    result.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        const auto offset = index * maximum_video_payload;
        const auto size = std::min(maximum_video_payload, frame.encoded.size() - offset);
        result.push_back({
            .frame_id = frame.frame_id,
            .captured_at_us = frame.captured_at_us,
            .width = frame.width,
            .height = frame.height,
            .codec = frame.codec,
            .keyframe = frame.keyframe,
            .fragment_index = static_cast<std::uint16_t>(index),
            .fragment_count = static_cast<std::uint16_t>(count),
            .total_size = checked_u32(frame.encoded.size()),
            .payload = std::vector<std::byte>(
                frame.encoded.begin() + static_cast<std::ptrdiff_t>(offset),
                frame.encoded.begin() + static_cast<std::ptrdiff_t>(offset + size)),
        });
    }
    return result;
}

std::vector<std::byte> encode_video_fragment(const VideoFragment& fragment) {
    validate_fragment(fragment);
    Writer writer;
    writer.bytes(video_magic);
    writer.u16(media_protocol_version);
    writer.u8(static_cast<std::uint8_t>(fragment.codec));
    writer.u8(fragment.keyframe ? 1U : 0U);
    writer.u64(fragment.frame_id);
    writer.u64(fragment.captured_at_us);
    writer.u32(fragment.width);
    writer.u32(fragment.height);
    writer.u16(fragment.fragment_index);
    writer.u16(fragment.fragment_count);
    writer.u32(fragment.total_size);
    writer.u16(static_cast<std::uint16_t>(fragment.payload.size()));
    writer.bytes(fragment.payload);
    auto encoded = writer.finish();
    if (encoded.size() > maximum_media_datagram_size) {
        throw std::length_error("video fragment exceeds datagram budget");
    }
    return encoded;
}

VideoFragment decode_video_fragment(const std::span<const std::byte> bytes) {
    if (bytes.size() > maximum_media_datagram_size) {
        throw std::length_error("video datagram exceeds limit");
    }
    Reader reader(bytes);
    require_magic(reader, video_magic);
    if (reader.u16() != media_protocol_version) {
        throw std::invalid_argument("unsupported media protocol version");
    }
    VideoFragment fragment;
    fragment.codec = static_cast<VideoCodec>(reader.u8());
    const auto flags = reader.u8();
    if ((flags & 0xfeU) != 0) {
        throw std::invalid_argument("unknown video fragment flags");
    }
    fragment.keyframe = (flags & 1U) != 0;
    fragment.frame_id = reader.u64();
    fragment.captured_at_us = reader.u64();
    fragment.width = reader.u32();
    fragment.height = reader.u32();
    fragment.fragment_index = reader.u16();
    fragment.fragment_count = reader.u16();
    fragment.total_size = reader.u32();
    const auto payload_size = reader.u16();
    const auto payload = reader.bytes(payload_size);
    fragment.payload.assign(payload.begin(), payload.end());
    if (!reader.empty()) {
        throw std::invalid_argument("trailing bytes in video datagram");
    }
    validate_fragment(fragment);
    return fragment;
}

void FrameReassembler::begin(VideoFragment fragment) {
    validate_fragment(fragment);
    fragments_.clear();
    fragments_.resize(fragment.fragment_count);
    received_bytes_ = 0;
    received_count_ = 0;
    current_ = std::move(fragment);
}

void FrameReassembler::abandon_incomplete() noexcept {
    if (current_ && received_count_ != current_->fragment_count) {
        ++dropped_frames_;
    }
    current_.reset();
    fragments_.clear();
    received_bytes_ = 0;
    received_count_ = 0;
}

std::optional<VideoFrame> FrameReassembler::receive(VideoFragment fragment) {
    validate_fragment(fragment);
    if (fragment.frame_id <= last_completed_frame_id_) {
        return std::nullopt;
    }
    if (current_ && fragment.frame_id < current_->frame_id) {
        return std::nullopt;
    }
    if (!current_ || fragment.frame_id > current_->frame_id) {
        if (current_) {
            abandon_incomplete();
            keyframe_required_ = true;
        }
        if (keyframe_required_ && !fragment.keyframe) {
            if (fragment.fragment_index == 0) {
                ++dropped_frames_;
            }
            return std::nullopt;
        }
        begin(fragment);
    }

    if (fragment.frame_id != current_->frame_id ||
        fragment.captured_at_us != current_->captured_at_us ||
        fragment.width != current_->width || fragment.height != current_->height ||
        fragment.codec != current_->codec || fragment.keyframe != current_->keyframe ||
        fragment.fragment_count != current_->fragment_count ||
        fragment.total_size != current_->total_size) {
        throw std::invalid_argument("inconsistent video frame fragments");
    }

    auto& destination = fragments_.at(fragment.fragment_index);
    if (!destination) {
        received_bytes_ += fragment.payload.size();
        if (received_bytes_ > current_->total_size) {
            abandon_incomplete();
            keyframe_required_ = true;
            throw std::invalid_argument("video fragments exceed declared frame size");
        }
        destination = std::move(fragment.payload);
        ++received_count_;
    }
    if (received_count_ != current_->fragment_count) {
        return std::nullopt;
    }
    if (received_bytes_ != current_->total_size) {
        abandon_incomplete();
        keyframe_required_ = true;
        throw std::invalid_argument("video fragments do not match declared frame size");
    }

    VideoFrame frame{
        .frame_id = current_->frame_id,
        .captured_at_us = current_->captured_at_us,
        .width = current_->width,
        .height = current_->height,
        .codec = current_->codec,
        .keyframe = current_->keyframe,
        .encoded = {},
    };
    frame.encoded.reserve(received_bytes_);
    for (auto& part : fragments_) {
        frame.encoded.insert(frame.encoded.end(), part->begin(), part->end());
    }
    if (frame.keyframe) {
        keyframe_required_ = false;
    }
    last_completed_frame_id_ = frame.frame_id;
    current_.reset();
    fragments_.clear();
    received_bytes_ = 0;
    received_count_ = 0;
    return frame;
}

void FrameReassembler::notify_loss() noexcept {
    abandon_incomplete();
    keyframe_required_ = true;
}

void LatestFrameQueue::push(VideoFrame frame) {
    if (pending_ && frame.frame_id <= pending_->frame_id) {
        ++dropped_frames_;
        return;
    }
    if (pending_) {
        ++dropped_frames_;
    }
    pending_ = std::move(frame);
}

std::vector<std::byte> encode_keyframe_request(
    const KeyframeRequest& request) {
    if (request.after_frame_id == 0 || request.reason_code.empty() ||
        request.reason_code.size() > 64 ||
        !std::ranges::all_of(request.reason_code, [](const char value) {
            return (value >= 'a' && value <= 'z') || value == '_';
        })) {
        throw std::invalid_argument("invalid keyframe request");
    }
    Writer writer;
    writer.bytes(keyframe_magic);
    writer.u8(1);
    writer.u8(0);
    writer.u64(request.after_frame_id);
    writer.u16(static_cast<std::uint16_t>(request.reason_code.size()));
    writer.bytes(std::as_bytes(std::span{request.reason_code}));
    return writer.finish();
}

KeyframeRequest decode_keyframe_request(const std::span<const std::byte> bytes) {
    Reader reader(bytes);
    require_magic(reader, keyframe_magic);
    if (reader.u8() != 1 || reader.u8() != 0) {
        throw std::invalid_argument("unsupported keyframe request version");
    }
    KeyframeRequest request;
    request.after_frame_id = reader.u64();
    const auto reason_size = reader.u16();
    if (reason_size == 0 || reason_size > 64) {
        throw std::length_error("keyframe request reason exceeds limit");
    }
    const auto reason = reader.bytes(reason_size);
    request.reason_code.assign(
        reinterpret_cast<const char*>(reason.data()), reason.size());
    if (!reader.empty()) {
        throw std::invalid_argument("trailing bytes in keyframe request");
    }
    static_cast<void>(encode_keyframe_request(request));
    return request;
}

std::optional<VideoFrame> LatestFrameQueue::take() {
    auto result = std::move(pending_);
    pending_.reset();
    return result;
}

bool valid_utf8(const std::string_view text) noexcept {
    std::size_t index{};
    while (index < text.size()) {
        const auto first = static_cast<unsigned char>(text[index]);
        std::size_t continuation{};
        std::uint32_t codepoint{};
        if (first <= 0x7fU) {
            ++index;
            continue;
        }
        if ((first & 0xe0U) == 0xc0U) {
            continuation = 1;
            codepoint = first & 0x1fU;
        } else if ((first & 0xf0U) == 0xe0U) {
            continuation = 2;
            codepoint = first & 0x0fU;
        } else if ((first & 0xf8U) == 0xf0U) {
            continuation = 3;
            codepoint = first & 0x07U;
        } else {
            return false;
        }
        if (index + continuation >= text.size()) {
            return false;
        }
        for (std::size_t offset = 1; offset <= continuation; ++offset) {
            const auto next = static_cast<unsigned char>(text[index + offset]);
            if ((next & 0xc0U) != 0x80U) {
                return false;
            }
            codepoint = (codepoint << 6U) | (next & 0x3fU);
        }
        if ((continuation == 1 && codepoint < 0x80U) ||
            (continuation == 2 && codepoint < 0x800U) ||
            (continuation == 3 && codepoint < 0x10000U) ||
            codepoint > 0x10ffffU ||
            (codepoint >= 0xd800U && codepoint <= 0xdfffU)) {
            return false;
        }
        index += continuation + 1;
    }
    return true;
}

void validate_input_event(const InputEvent& event) {
    if (event.sequence == 0 || event.occurred_at_us == 0) {
        throw std::invalid_argument("input event sequence and timestamp are required");
    }
    switch (event.kind) {
        case InputKind::raw_key:
            if (event.value_a == 0 || event.value_a > 0xffffU ||
                event.value_b != 0 || !event.text.empty()) {
                throw std::invalid_argument("invalid raw key event");
            }
            break;
        case InputKind::text_commit:
            if (event.value_a != 0 || event.value_b != 0 || event.pressed ||
                event.text.empty() || event.text.size() > maximum_input_text_size ||
                event.text.find('\0') != std::string::npos || !valid_utf8(event.text)) {
                throw std::invalid_argument("invalid text commit event");
            }
            break;
        case InputKind::pointer_move:
            if (event.value_a > 0xffffU || event.value_b > 0xffffU ||
                event.pressed || !event.text.empty()) {
                throw std::invalid_argument("invalid pointer move event");
            }
            break;
        case InputKind::pointer_button:
            if (event.value_a == 0 || event.value_a > 8 || event.value_b != 0 ||
                !event.text.empty()) {
                throw std::invalid_argument("invalid pointer button event");
            }
            break;
        case InputKind::vertical_wheel:
        case InputKind::horizontal_wheel:
            if (event.value_a == 0 || event.value_b != 0 || event.pressed ||
                !event.text.empty()) {
                throw std::invalid_argument("invalid pointer wheel event");
            }
            break;
        default:
            throw std::invalid_argument("unknown input event kind");
    }
}

std::vector<std::byte> encode_input_event(const InputEvent& event) {
    validate_input_event(event);
    Writer writer;
    writer.bytes(input_magic);
    writer.u8(1);
    writer.u8(static_cast<std::uint8_t>(event.kind));
    writer.u8(event.pressed ? 1U : 0U);
    writer.u8(0);
    writer.u64(event.sequence);
    writer.u64(event.occurred_at_us);
    writer.u32(event.value_a);
    writer.u32(event.value_b);
    writer.u32(checked_u32(event.text.size()));
    writer.bytes(std::as_bytes(std::span{event.text}));
    return writer.finish();
}

InputEvent decode_input_event(const std::span<const std::byte> bytes) {
    Reader reader(bytes);
    require_magic(reader, input_magic);
    if (reader.u8() != 1) {
        throw std::invalid_argument("unsupported input protocol version");
    }
    InputEvent event;
    event.kind = static_cast<InputKind>(reader.u8());
    const auto flags = reader.u8();
    if ((flags & 0xfeU) != 0 || reader.u8() != 0) {
        throw std::invalid_argument("unknown input event flags");
    }
    event.pressed = (flags & 1U) != 0;
    event.sequence = reader.u64();
    event.occurred_at_us = reader.u64();
    event.value_a = reader.u32();
    event.value_b = reader.u32();
    const auto text_size = reader.u32();
    if (text_size > maximum_input_text_size) {
        throw std::length_error("input text exceeds limit");
    }
    const auto text = reader.bytes(text_size);
    event.text.assign(reinterpret_cast<const char*>(text.data()), text.size());
    if (!reader.empty()) {
        throw std::invalid_argument("trailing bytes in input event");
    }
    validate_input_event(event);
    return event;
}

bool InputReceiver::receive(
    const InputEvent& event, const bool reliable,
    const core::AuthorizationResult& authorization) {
    if (!authorization.permits(core::Capability::desktop_control)) {
        throw std::logic_error("desktop control capability is required");
    }
    validate_input_event(event);
    if (event.kind == InputKind::pointer_move) {
        if (last_pointer_sequence_ && event.sequence <= *last_pointer_sequence_) {
            return false;
        }
        last_pointer_sequence_ = event.sequence;
        backend_.pointer_move(
            static_cast<std::uint16_t>(event.value_a),
            static_cast<std::uint16_t>(event.value_b));
        return true;
    }
    if (!reliable) {
        throw std::invalid_argument("input event requires reliable ordered transport");
    }
    if (last_reliable_sequence_) {
        if (event.sequence <= *last_reliable_sequence_) {
            return false;
        }
        if (event.sequence != *last_reliable_sequence_ + 1U) {
            throw std::invalid_argument("reliable input sequence has a gap");
        }
    }
    last_reliable_sequence_ = event.sequence;
    switch (event.kind) {
        case InputKind::raw_key:
            backend_.raw_key(event.value_a, event.pressed);
            if (event.pressed) {
                pressed_keys_[event.value_a] = event.occurred_at_us;
            } else {
                pressed_keys_.erase(event.value_a);
            }
            break;
        case InputKind::text_commit:
            backend_.text_commit(event.text);
            break;
        case InputKind::pointer_button:
            backend_.pointer_button(
                static_cast<std::uint8_t>(event.value_a), event.pressed);
            if (event.pressed) {
                pressed_buttons_.insert(
                    static_cast<std::uint8_t>(event.value_a));
            } else {
                pressed_buttons_.erase(
                    static_cast<std::uint8_t>(event.value_a));
            }
            break;
        case InputKind::vertical_wheel:
        case InputKind::horizontal_wheel:
            backend_.pointer_wheel(
                std::bit_cast<std::int32_t>(event.value_a),
                event.kind == InputKind::horizontal_wheel);
            break;
        case InputKind::pointer_move:
            break;
    }
    return true;
}

std::size_t InputReceiver::release_stuck_keys(
    const std::uint64_t now_us, const std::chrono::milliseconds maximum_hold) {
    if (maximum_hold <= std::chrono::milliseconds::zero()) {
        throw std::invalid_argument("stuck key hold duration must be positive");
    }
    const auto maximum_hold_us = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(maximum_hold).count());
    std::vector<std::uint32_t> stale;
    for (const auto& [usage, pressed_at] : pressed_keys_) {
        if (now_us >= pressed_at && now_us - pressed_at >= maximum_hold_us) {
            stale.push_back(usage);
        }
    }
    for (const auto usage : stale) {
        backend_.raw_key(usage, false);
        pressed_keys_.erase(usage);
    }
    return stale.size();
}

std::size_t InputReceiver::release_all_keys() {
    const auto count = pressed_keys_.size();
    for (const auto& [usage, unused] : pressed_keys_) {
        static_cast<void>(unused);
        backend_.raw_key(usage, false);
    }
    pressed_keys_.clear();
    return count;
}

std::size_t InputReceiver::release_all_input() {
    const auto key_count = release_all_keys();
    const auto button_count = pressed_buttons_.size();
    for (const auto button : pressed_buttons_) {
        backend_.pointer_button(button, false);
    }
    pressed_buttons_.clear();
    return key_count + button_count;
}

bool InputReceiver::accept_input_epoch(
    const std::uint64_t epoch, const bool release_all) {
    if (epoch == 0) {
        throw std::invalid_argument("input epoch is zero");
    }
    if (epoch < input_epoch_) return false;
    if (epoch == input_epoch_) return true;
    if (!release_all) {
        throw std::invalid_argument(
            "new input epoch must begin with RELEASE_ALL_INPUT");
    }
    static_cast<void>(release_all_input());
    input_epoch_ = epoch;
    last_reliable_sequence_.reset();
    last_pointer_sequence_.reset();
    return true;
}

bool CanonicalFramebufferState::enter_representation(
    const VisualRepresentation representation, const std::uint64_t epoch) noexcept {
    if (epoch == 0 || epoch < representation_epoch_) return false;
    if (epoch == representation_epoch_) {
        return representation == representation_;
    }
    representation_ = representation;
    representation_epoch_ = epoch;
    pending_rect_base_ = 0;
    pending_rect_target_ = 0;
    ack_frame_id_.reset();
    return true;
}

bool CanonicalFramebufferState::commit_video(
    const std::uint64_t epoch, const std::uint64_t frame_id) noexcept {
    if (epoch != representation_epoch_ ||
        representation_ != VisualRepresentation::video || frame_id == 0 ||
        frame_id < committed_frame_id_) {
        return false;
    }
    committed_frame_id_ = frame_id;
    quality_ = FramebufferQuality::lossy;
    pending_rect_base_ = 0;
    pending_rect_target_ = 0;
    ack_frame_id_.reset();
    return true;
}

bool CanonicalFramebufferState::commit_snapshot(
    const std::uint64_t epoch, const std::uint64_t frame_id) noexcept {
    if (!can_commit_snapshot(epoch, frame_id)) return false;
    committed_frame_id_ = frame_id;
    quality_ = FramebufferQuality::exact;
    pending_rect_base_ = 0;
    pending_rect_target_ = 0;
    ack_frame_id_ = frame_id;
    return true;
}

bool CanonicalFramebufferState::can_commit_snapshot(
    const std::uint64_t epoch, const std::uint64_t frame_id) const noexcept {
    return epoch == representation_epoch_ &&
        representation_ == VisualRepresentation::snapshot && frame_id != 0 &&
        frame_id >= committed_frame_id_;
}

bool CanonicalFramebufferState::begin_rect(
    const std::uint64_t epoch, const std::uint64_t base_frame_id,
    const std::uint64_t target_frame_id) noexcept {
    if (epoch != representation_epoch_ ||
        representation_ != VisualRepresentation::rect ||
        quality_ != FramebufferQuality::exact || base_frame_id == 0 ||
        target_frame_id <= base_frame_id ||
        committed_frame_id_ != base_frame_id || pending_rect_target_ != 0) {
        return false;
    }
    pending_rect_base_ = base_frame_id;
    pending_rect_target_ = target_frame_id;
    return true;
}

bool CanonicalFramebufferState::commit_rect(
    const std::uint64_t epoch, const std::uint64_t base_frame_id,
    const std::uint64_t target_frame_id) noexcept {
    if (epoch != representation_epoch_ ||
        representation_ != VisualRepresentation::rect ||
        quality_ != FramebufferQuality::exact ||
        pending_rect_base_ != base_frame_id ||
        pending_rect_target_ != target_frame_id ||
        committed_frame_id_ != base_frame_id) {
        return false;
    }
    committed_frame_id_ = target_frame_id;
    pending_rect_base_ = 0;
    pending_rect_target_ = 0;
    ack_frame_id_ = target_frame_id;
    return true;
}

void CanonicalFramebufferState::cancel_rect(const std::uint64_t epoch) noexcept {
    if (epoch != representation_epoch_) return;
    pending_rect_base_ = 0;
    pending_rect_target_ = 0;
    ack_frame_id_.reset();
}

void CanonicalFramebufferState::present_submitted(
    const std::uint64_t frame_id) noexcept {
    if (frame_id <= committed_frame_id_) {
        present_submitted_frame_id_ =
            std::max(present_submitted_frame_id_, frame_id);
    }
}

std::optional<FrameCommitAck> CanonicalFramebufferState::take_commit_ack(
    const std::uint64_t session_generation,
    const std::array<std::byte, 32> canonical_sha256) noexcept {
    if (session_generation == 0 || !ack_frame_id_) return std::nullopt;
    FrameCommitAck result{
        .session_generation = session_generation,
        .representation_epoch = representation_epoch_,
        .frame_id = *ack_frame_id_,
        .canonical_sha256 = canonical_sha256,
    };
    ack_frame_id_.reset();
    return result;
}

bool FullSnapshotAssemblyGuard::begin(
    const VisualMessageHeader& header,
    const VisualFullSnapshotChunk& first) noexcept {
    const auto expected_stride =
        static_cast<std::uint64_t>(first.surface_width) * 4U;
    const auto expected_total =
        expected_stride * first.surface_height;
    if (active_ || header.type != VisualMessageType::full_snapshot ||
        header.session_generation == 0 || header.representation_epoch == 0 ||
        header.frame_id == 0 || first.chunk_offset != 0 ||
        first.chunk.empty() || first.total_bytes == 0 ||
        first.chunk.size() > first.total_bytes ||
        first.pixel_format !=
            CanonicalPixelFormat::bgra8_premultiplied_srgb ||
        first.surface_width == 0 || first.surface_height == 0 ||
        first.surface_width > maximum_preview_width ||
        first.surface_height > maximum_preview_height ||
        expected_stride != first.row_stride ||
        expected_total != first.total_bytes ||
        expected_total > maximum_snapshot_total_bytes) {
        return false;
    }
    session_generation_ = header.session_generation;
    representation_epoch_ = header.representation_epoch;
    frame_id_ = header.frame_id;
    width_ = first.surface_width;
    height_ = first.surface_height;
    row_stride_ = first.row_stride;
    total_bytes_ = first.total_bytes;
    next_offset_ = static_cast<std::uint32_t>(first.chunk.size());
    active_ = true;
    return true;
}

bool FullSnapshotAssemblyGuard::matches(
    const VisualMessageHeader& header,
    const VisualFullSnapshotChunk& chunk) const noexcept {
    return active_ && header.type == VisualMessageType::full_snapshot &&
        header.session_generation == session_generation_ &&
        header.representation_epoch == representation_epoch_ &&
        header.frame_id == frame_id_ && chunk.surface_width == width_ &&
        chunk.surface_height == height_ && chunk.row_stride == row_stride_ &&
        chunk.total_bytes == total_bytes_;
}

bool FullSnapshotAssemblyGuard::accept(
    const VisualMessageHeader& header,
    const VisualFullSnapshotChunk& chunk) noexcept {
    if (!matches(header, chunk) || chunk.chunk_offset != next_offset_ ||
        chunk.chunk.empty() || next_offset_ > total_bytes_ ||
        chunk.chunk.size() > total_bytes_ - next_offset_) {
        return false;
    }
    next_offset_ += static_cast<std::uint32_t>(chunk.chunk.size());
    return true;
}

bool FullSnapshotAssemblyGuard::ready_to_commit(
    const VisualMessageHeader& header,
    const VisualFrameCommit& commit) const noexcept {
    return active_ && header.type == VisualMessageType::frame_commit &&
        header.session_generation == session_generation_ &&
        header.representation_epoch == representation_epoch_ &&
        header.frame_id == frame_id_ && commit.base_frame_id == 0 &&
        next_offset_ == total_bytes_;
}

void FullSnapshotAssemblyGuard::cancel() noexcept {
    *this = FullSnapshotAssemblyGuard{};
}

bool SnapshotWireDrainPlan::begin(
    const std::uint64_t source_frame_id,
    const std::uint32_t total_bytes,
    const std::uint32_t row_stride,
    const std::uint32_t chunk_limit,
    const std::uint32_t burst_limit) noexcept {
    if (active_ || source_frame_id == 0 || total_bytes == 0 ||
        total_bytes > maximum_snapshot_total_bytes || row_stride == 0 ||
        total_bytes % row_stride != 0 || chunk_limit < row_stride ||
        chunk_limit > maximum_snapshot_wire_chunk_bytes ||
        burst_limit < row_stride) {
        return false;
    }
    const auto rows_per_chunk = chunk_limit / row_stride;
    if (rows_per_chunk == 0) return false;
    const auto chunk_bytes = rows_per_chunk * row_stride;
    source_frame_id_ = source_frame_id;
    latest_source_frame_id_ = source_frame_id;
    total_bytes_ = total_bytes;
    row_stride_ = row_stride;
    chunk_bytes_ = chunk_bytes;
    burst_limit_ = std::max(burst_limit, chunk_bytes);
    active_ = true;
    return true;
}

std::vector<SnapshotWireRange> SnapshotWireDrainPlan::take_burst() {
    std::vector<SnapshotWireRange> result;
    if (!active_ || complete()) return result;
    std::uint32_t burst_bytes{};
    while (next_offset_ < total_bytes_) {
        const auto remaining = total_bytes_ - next_offset_;
        const auto size = std::min(chunk_bytes_, remaining);
        if (!result.empty() && size > burst_limit_ - burst_bytes) break;
        result.push_back({
            .offset = next_offset_,
            .size = size,
            .final = size == remaining,
        });
        next_offset_ += size;
        burst_bytes += size;
        if (burst_bytes >= burst_limit_) break;
    }
    return result;
}

void SnapshotWireDrainPlan::observe_latest_source(
    const std::uint64_t frame_id) noexcept {
    if (!active_ || frame_id <= latest_source_frame_id_) return;
    latest_source_frame_id_ = frame_id;
    ++superseded_sources_;
}

void SnapshotWireDrainPlan::cancel() noexcept {
    *this = SnapshotWireDrainPlan{};
}

bool RawRectTransactionGuard::accept(
    const VisualMessageHeader& header,
    const VisualRawRect& rectangle) noexcept {
    if (header.type != VisualMessageType::raw_rect ||
        header.session_generation == 0 || header.representation_epoch == 0 ||
        header.frame_id == 0 || rectangle.base_frame_id == 0 ||
        header.frame_id <= rectangle.base_frame_id ||
        rectangle.surface_width == 0 || rectangle.surface_height == 0 ||
        rectangle.width == 0 || rectangle.height == 0 ||
        rectangles_.size() >= maximum_raw_rect_transaction_count ||
        rectangle.bgra.size() >
            maximum_raw_rect_protocol_bytes - packed_bytes_) {
        return false;
    }
    if (!active_) {
        active_ = true;
        session_generation_ = header.session_generation;
        representation_epoch_ = header.representation_epoch;
        base_frame_id_ = rectangle.base_frame_id;
        target_frame_id_ = header.frame_id;
        width_ = rectangle.surface_width;
        height_ = rectangle.surface_height;
    } else if (header.session_generation != session_generation_ ||
               header.representation_epoch != representation_epoch_ ||
               header.frame_id != target_frame_id_ ||
               rectangle.base_frame_id != base_frame_id_ ||
               rectangle.surface_width != width_ ||
               rectangle.surface_height != height_) {
        return false;
    }
    const Bounds bounds{
        .left = rectangle.x,
        .top = rectangle.y,
        .right = rectangle.x + rectangle.width,
        .bottom = rectangle.y + rectangle.height,
    };
    const auto overlaps = std::ranges::any_of(
        rectangles_, [&](const Bounds& existing) {
            return bounds.left < existing.right &&
                bounds.right > existing.left &&
                bounds.top < existing.bottom &&
                bounds.bottom > existing.top;
        });
    if (overlaps) return false;
    rectangles_.push_back(bounds);
    packed_bytes_ += rectangle.bgra.size();
    return true;
}

bool RawRectTransactionGuard::ready_to_commit(
    const VisualMessageHeader& header,
    const VisualFrameCommit& commit) const noexcept {
    return active_ && !rectangles_.empty() &&
        header.type == VisualMessageType::frame_commit &&
        header.session_generation == session_generation_ &&
        header.representation_epoch == representation_epoch_ &&
        header.frame_id == target_frame_id_ &&
        commit.base_frame_id == base_frame_id_;
}

void RawRectTransactionGuard::cancel() noexcept {
    *this = RawRectTransactionGuard{};
}

void InputFocusReleaseGate::focus_acquired() noexcept {
    focused_ = true;
}

bool InputFocusReleaseGate::focus_lost() noexcept {
    if (!focused_) return false;
    focused_ = false;
    return true;
}

std::optional<SurfacePoint> map_pointer_to_surface(
    const std::uint16_t normalized_x, const std::uint16_t normalized_y,
    const Viewport viewer, const Viewport surface) {
    if (viewer.width == 0 || viewer.height == 0 ||
        surface.width == 0 || surface.height == 0) {
        throw std::invalid_argument("viewport dimensions must be non-zero");
    }
    const auto scale = std::min(
        static_cast<long double>(viewer.width) / surface.width,
        static_cast<long double>(viewer.height) / surface.height);
    const auto content_width = static_cast<long double>(surface.width) * scale;
    const auto content_height = static_cast<long double>(surface.height) * scale;
    const auto offset_x = (static_cast<long double>(viewer.width) - content_width) / 2.0L;
    const auto offset_y = (static_cast<long double>(viewer.height) - content_height) / 2.0L;
    const auto viewer_x = static_cast<long double>(normalized_x) *
                          static_cast<long double>(viewer.width - 1U) / 65535.0L;
    const auto viewer_y = static_cast<long double>(normalized_y) *
                          static_cast<long double>(viewer.height - 1U) / 65535.0L;
    if (viewer_x < offset_x || viewer_y < offset_y ||
        viewer_x >= offset_x + content_width || viewer_y >= offset_y + content_height) {
        return std::nullopt;
    }
    const auto source_x = std::min(
        surface.width - 1U,
        static_cast<std::uint32_t>((viewer_x - offset_x) / scale));
    const auto source_y = std::min(
        surface.height - 1U,
        static_cast<std::uint32_t>((viewer_y - offset_y) / scale));
    return SurfacePoint{.x = source_x, .y = source_y};
}

std::vector<std::byte> encode_clipboard_update(const ClipboardUpdate& update) {
    validate_clipboard(update);
    Writer writer;
    writer.bytes(clipboard_magic);
    writer.u16(1);
    writer.u16(static_cast<std::uint16_t>(update.origin.size()));
    writer.u64(update.revision);
    writer.u16(static_cast<std::uint16_t>(update.content_sha256.size()));
    writer.u32(checked_u32(update.utf8_text.size()));
    writer.bytes(std::as_bytes(std::span{update.origin}));
    writer.bytes(std::as_bytes(std::span{update.content_sha256}));
    writer.bytes(std::as_bytes(std::span{update.utf8_text}));
    return writer.finish();
}

ClipboardUpdate decode_clipboard_update(const std::span<const std::byte> bytes) {
    if (bytes.size() > maximum_clipboard_text_size + 256U) {
        throw std::length_error("clipboard message exceeds limit");
    }
    Reader reader(bytes);
    require_magic(reader, clipboard_magic);
    if (reader.u16() != 1) {
        throw std::invalid_argument("unsupported clipboard protocol version");
    }
    const auto origin_size = reader.u16();
    const auto revision = reader.u64();
    const auto hash_size = reader.u16();
    const auto text_size = reader.u32();
    if (origin_size == 0 || origin_size > 128 || hash_size != 64 ||
        text_size > maximum_clipboard_text_size) {
        throw std::length_error("clipboard field exceeds limit");
    }
    const auto origin = reader.bytes(origin_size);
    const auto hash = reader.bytes(hash_size);
    const auto text = reader.bytes(text_size);
    if (!reader.empty()) {
        throw std::invalid_argument("trailing bytes in clipboard update");
    }
    ClipboardUpdate update{
        .origin = std::string(reinterpret_cast<const char*>(origin.data()), origin.size()),
        .revision = revision,
        .content_sha256 = std::string(reinterpret_cast<const char*>(hash.data()), hash.size()),
        .utf8_text = std::string(reinterpret_cast<const char*>(text.data()), text.size()),
    };
    validate_clipboard(update);
    return update;
}

ClipboardSynchronizer::ClipboardSynchronizer(std::string local_origin)
    : local_origin_(std::move(local_origin)) {
    if (local_origin_.empty() || local_origin_.size() > 128 ||
        local_origin_.find('\0') != std::string::npos) {
        throw std::invalid_argument("clipboard origin is invalid");
    }
}

ClipboardUpdate ClipboardSynchronizer::make_update(
    std::string text, const std::uint64_t revision,
    const core::AuthorizationResult& authorization) {
    if (!authorization.permits(core::Capability::clipboard_read)) {
        throw std::logic_error("clipboard read capability is required");
    }
    ClipboardUpdate update{
        .origin = local_origin_,
        .revision = revision,
        .content_sha256 = core::sha256_hex(text),
        .utf8_text = std::move(text),
    };
    validate_clipboard(update);
    const auto previous = revisions_[local_origin_];
    if (revision <= previous) {
        throw std::invalid_argument("clipboard revision must increase");
    }
    revisions_[local_origin_] = revision;
    latest_hash_ = update.content_sha256;
    latest_text_ = update.utf8_text;
    return update;
}

bool ClipboardSynchronizer::apply(
    const ClipboardUpdate& update,
    const core::AuthorizationResult& authorization) {
    if (!authorization.permits(core::Capability::clipboard_write)) {
        throw std::logic_error("clipboard write capability is required");
    }
    validate_clipboard(update);
    if (update.origin == local_origin_) {
        return false;
    }
    auto& previous_revision = revisions_[update.origin];
    if (update.revision <= previous_revision) {
        return false;
    }
    previous_revision = update.revision;
    if (latest_hash_ && *latest_hash_ == update.content_sha256) {
        return false;
    }
    latest_hash_ = update.content_sha256;
    latest_text_ = update.utf8_text;
    return true;
}

VideoSettings adapt_video_settings(
    VideoSettings current, const NetworkTelemetry telemetry) {
    validate_dimensions(current.width, current.height);
    if (current.frames_per_second == 0 || current.frames_per_second > 120 ||
        current.bitrate_kbps < 500 || current.bitrate_kbps > 100000 ||
        current.keyframe_interval == 0 || current.keyframe_interval > 600) {
        throw std::invalid_argument("invalid video settings");
    }
    const bool congested = telemetry.loss_basis_points >= 200 ||
                           telemetry.send_queue_ms > 25 ||
                           telemetry.round_trip_ms > 80;
    const bool severe = telemetry.loss_basis_points >= 500 ||
                        telemetry.send_queue_ms > 60;
    if (congested) {
        current.bitrate_kbps = std::max(1500U, current.bitrate_kbps * 3U / 4U);
        current.frames_per_second = std::max(30U, current.frames_per_second * 3U / 4U);
        if (severe && (current.width > 1280 || current.height > 720)) {
            current.width = 1280;
            current.height = 720;
        }
        current.keyframe_interval = std::min(current.keyframe_interval, current.frames_per_second);
    } else if (telemetry.loss_basis_points < 20 && telemetry.send_queue_ms < 5 &&
               telemetry.round_trip_ms < 20) {
        current.bitrate_kbps = std::min(20000U, current.bitrate_kbps +
            std::max(250U, current.bitrate_kbps / 10U));
        current.frames_per_second = std::min(60U, current.frames_per_second + 5U);
        if (current.width < 1920 || current.height < 1080) {
            current.width = 1920;
            current.height = 1080;
        }
    }
    return current;
}

void LatencyTelemetry::record(const LatencySample& sample) {
    if (sample.captured_at_us == 0 || sample.encoded_at_us < sample.captured_at_us ||
        sample.received_at_us < sample.encoded_at_us ||
        sample.decoded_at_us < sample.received_at_us ||
        sample.displayed_at_us < sample.decoded_at_us) {
        throw std::invalid_argument("latency timestamps must be monotonic");
    }
    if (end_to_end_us_.size() >= 10000) {
        end_to_end_us_.erase(end_to_end_us_.begin());
    }
    end_to_end_us_.push_back(sample.displayed_at_us - sample.captured_at_us);
}

std::uint64_t LatencyTelemetry::percentile_end_to_end(const double percentile) const {
    if (end_to_end_us_.empty() || percentile <= 0.0 || percentile > 1.0) {
        throw std::invalid_argument("latency percentile is invalid");
    }
    auto sorted = end_to_end_us_;
    std::ranges::sort(sorted);
    const auto rank = static_cast<std::size_t>(
        std::ceil(percentile * static_cast<double>(sorted.size())));
    return sorted.at(std::max<std::size_t>(1, rank) - 1U);
}

DesktopTransportSession::DesktopTransportSession(
    transport::Transport& transport,
    core::AuthorizationResult authorization)
    : transport_(transport), authorization_(std::move(authorization)) {}

void DesktopTransportSession::send_frame(const VideoFrame& frame) {
    if (!authorization_.permits(core::Capability::desktop_view)) {
        throw std::logic_error("desktop view capability is required");
    }
    for (const auto& fragment : fragment_frame(frame)) {
        const auto encoded = encode_video_fragment(fragment);
        transport_.send_datagram(transport::DatagramChannel::video, encoded);
    }
}

void DesktopTransportSession::request_keyframe(const KeyframeRequest& request) {
    if (!authorization_.permits(core::Capability::desktop_view)) {
        throw std::logic_error("desktop view capability is required");
    }
    const auto encoded = encode_keyframe_request(request);
    if (!control_stream_) {
        control_stream_ = transport_.open_stream(transport::StreamPurpose::control);
        if (!control_stream_) {
            throw std::runtime_error("transport did not create control stream");
        }
    }
    control_stream_->write(encoded);
}

void DesktopTransportSession::send_input(const InputEvent& event) {
    if (!authorization_.permits(core::Capability::desktop_control)) {
        throw std::logic_error("desktop control capability is required");
    }
    const auto encoded = encode_input_event(event);
    if (event.kind == InputKind::pointer_move) {
        transport_.send_datagram(transport::DatagramChannel::pointer, encoded);
        return;
    }
    if (!input_stream_) {
        input_stream_ = transport_.open_stream(transport::StreamPurpose::input);
        if (!input_stream_) {
            throw std::runtime_error("transport did not create input stream");
        }
    }
    input_stream_->write(encoded);
}

void DesktopTransportSession::send_clipboard(const ClipboardUpdate& update) {
    if (!authorization_.permits(core::Capability::clipboard_read)) {
        throw std::logic_error("clipboard read capability is required");
    }
    const auto encoded = encode_clipboard_update(update);
    if (!clipboard_stream_) {
        clipboard_stream_ = transport_.open_stream(transport::StreamPurpose::clipboard);
        if (!clipboard_stream_) {
            throw std::runtime_error("transport did not create clipboard stream");
        }
    }
    clipboard_stream_->write(encoded);
}

}  // namespace rwn::desktop
