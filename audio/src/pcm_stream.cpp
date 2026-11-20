#include "rwn/audio/audio.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace rwn::audio {
namespace {

constexpr std::array magic{std::byte{'R'}, std::byte{'W'}, std::byte{'A'}, std::byte{'1'}};
constexpr std::uint16_t version = 1;

void put(std::vector<std::byte>& out, const std::uint64_t value, const std::size_t bytes) {
    for (std::size_t i = 0; i < bytes; ++i) {
        out.push_back(static_cast<std::byte>(value >> (8U * i)));
    }
}

std::uint64_t get(const std::span<const std::byte> in, const std::size_t offset,
                  const std::size_t bytes) {
    std::uint64_t value{};
    for (std::size_t i = 0; i < bytes; ++i) {
        value |= static_cast<std::uint64_t>(
            std::to_integer<std::uint8_t>(in[offset + i])) << (8U * i);
    }
    return value;
}

void validate_stream_frame(const PcmStreamFrame& frame) {
    validate_pcm_frame(frame.frame);
    if (frame.sequence == 0 || frame.frame.channels != opus_channels ||
        frame.frame.samples_per_channel != opus_frame_samples) {
        throw std::invalid_argument("invalid PCM stream frame");
    }
}

}  // namespace

std::vector<std::byte> encode_pcm_stream_frame(const PcmStreamFrame& frame) {
    validate_stream_frame(frame);
    std::vector<std::byte> out(magic.begin(), magic.end());
    out.reserve(pcm_stream_frame_size);
    put(out, version, 2);
    put(out, frame.frame.channels, 2);
    put(out, frame.frame.sample_rate, 4);
    put(out, frame.frame.samples_per_channel, 2);
    put(out, 0, 2);
    put(out, frame.sequence, 8);
    put(out, frame.captured_at_us, 8);
    for (const auto sample : frame.frame.interleaved_samples) {
        put(out, static_cast<std::uint16_t>(sample), 2);
    }
    if (out.size() != pcm_stream_frame_size) {
        throw std::logic_error("PCM stream frame size mismatch");
    }
    return out;
}

PcmStreamFrame decode_pcm_stream_frame(const std::span<const std::byte> wire) {
    if (wire.size() != pcm_stream_frame_size ||
        !std::equal(magic.begin(), magic.end(), wire.begin()) ||
        get(wire, 4, 2) != version || get(wire, 14, 2) != 0) {
        throw std::invalid_argument("invalid PCM stream framing");
    }
    PcmStreamFrame frame{
        .sequence = get(wire, 16, 8),
        .captured_at_us = get(wire, 24, 8),
        .frame = {
            .sample_rate = static_cast<std::uint32_t>(get(wire, 8, 4)),
            .channels = static_cast<std::uint16_t>(get(wire, 6, 2)),
            .samples_per_channel = static_cast<std::uint16_t>(get(wire, 12, 2)),
            .interleaved_samples = {},
        },
    };
    const auto samples = (wire.size() - pcm_stream_header_size) / 2U;
    frame.frame.interleaved_samples.reserve(samples);
    for (std::size_t i = 0; i < samples; ++i) {
        frame.frame.interleaved_samples.push_back(static_cast<std::int16_t>(
            static_cast<std::uint16_t>(get(wire, pcm_stream_header_size + i * 2U, 2))));
    }
    validate_stream_frame(frame);
    return frame;
}

}  // namespace rwn::audio
