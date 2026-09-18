#include "rwn/audio/audio.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <stdexcept>
#include <utility>

namespace rwn::audio {
namespace {

constexpr std::array<std::byte, 4> magic{
    std::byte{'R'}, std::byte{'W'}, std::byte{'A'}, std::byte{'1'}};

class Reader {
public:
    explicit Reader(const std::span<const std::byte> bytes) : bytes_(bytes) {}
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
    [[nodiscard]] std::span<const std::byte> bytes(const std::size_t count) {
        require(count);
        const auto value = bytes_.subspan(offset_, count);
        offset_ += count;
        return value;
    }
    [[nodiscard]] bool empty() const noexcept { return offset_ == bytes_.size(); }

private:
    void require(const std::size_t count) const {
        if (count > bytes_.size() - offset_) {
            throw std::invalid_argument("truncated audio datagram");
        }
    }
    std::span<const std::byte> bytes_;
    std::size_t offset_{};
};

void append_u16(std::vector<std::byte>& output, const std::uint16_t value) {
    output.push_back(static_cast<std::byte>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::byte>(value & 0xffU));
}

void append_u32(std::vector<std::byte>& output, const std::uint32_t value) {
    for (const unsigned shift : {24U, 16U, 8U, 0U}) {
        output.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
    }
}

void append_u64(std::vector<std::byte>& output, const std::uint64_t value) {
    for (const unsigned shift : {56U, 48U, 40U, 32U, 24U, 16U, 8U, 0U}) {
        output.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
    }
}

void validate_packet(const AudioPacket& packet) {
    if (packet.sequence == 0 || packet.captured_at_us == 0 ||
        packet.sample_rate != opus_sample_rate ||
        (packet.channels != 1 && packet.channels != opus_channels) ||
        (packet.samples_per_channel != 120 && packet.samples_per_channel != 240 &&
         packet.samples_per_channel != 480 &&
         packet.samples_per_channel != opus_frame_samples &&
         packet.samples_per_channel != 1920 && packet.samples_per_channel != 2880) ||
        packet.opus.empty() || packet.opus.size() > maximum_opus_packet_size) {
        throw std::invalid_argument("invalid Opus audio packet");
    }
}

}  // namespace

void validate_pcm_frame(const PcmFrame& frame) {
    if (frame.sample_rate != opus_sample_rate ||
        (frame.channels != 1 && frame.channels != opus_channels) ||
        (frame.samples_per_channel != 120 && frame.samples_per_channel != 240 &&
         frame.samples_per_channel != 480 &&
         frame.samples_per_channel != opus_frame_samples &&
         frame.samples_per_channel != 1920 && frame.samples_per_channel != 2880) ||
        frame.interleaved_samples.size() !=
            static_cast<std::size_t>(frame.channels) * frame.samples_per_channel) {
        throw std::invalid_argument("invalid PCM frame for Opus");
    }
}

std::vector<std::byte> encode_packet(const AudioPacket& packet) {
    validate_packet(packet);
    std::vector<std::byte> output;
    output.reserve(32U + packet.opus.size());
    output.insert(output.end(), magic.begin(), magic.end());
    append_u16(output, 1);
    append_u16(output, 0);
    append_u64(output, packet.sequence);
    append_u64(output, packet.captured_at_us);
    append_u32(output, packet.sample_rate);
    append_u16(output, packet.channels);
    append_u16(output, packet.samples_per_channel);
    append_u16(output, static_cast<std::uint16_t>(packet.opus.size()));
    output.insert(output.end(), packet.opus.begin(), packet.opus.end());
    if (output.size() > maximum_audio_datagram_size) {
        throw std::length_error("audio datagram exceeds limit");
    }
    return output;
}

AudioPacket decode_packet(const std::span<const std::byte> bytes) {
    if (bytes.size() > maximum_audio_datagram_size) {
        throw std::length_error("audio datagram exceeds limit");
    }
    Reader reader(bytes);
    if (!std::ranges::equal(reader.bytes(magic.size()), magic) ||
        reader.u16() != 1 || reader.u16() != 0) {
        throw std::invalid_argument("invalid audio datagram header");
    }
    AudioPacket packet;
    packet.sequence = reader.u64();
    packet.captured_at_us = reader.u64();
    packet.sample_rate = reader.u32();
    packet.channels = reader.u16();
    packet.samples_per_channel = reader.u16();
    const auto payload_size = reader.u16();
    if (payload_size == 0 || payload_size > maximum_opus_packet_size) {
        throw std::length_error("Opus payload exceeds limit");
    }
    const auto payload = reader.bytes(payload_size);
    packet.opus.assign(payload.begin(), payload.end());
    if (!reader.empty()) {
        throw std::invalid_argument("trailing bytes in audio datagram");
    }
    validate_packet(packet);
    return packet;
}

AudioJitterBuffer::AudioJitterBuffer(
    const std::size_t target_packets, const std::size_t maximum_packets)
    : target_packets_(target_packets), maximum_packets_(maximum_packets) {
    if (target_packets_ == 0 || maximum_packets_ < target_packets_ ||
        maximum_packets_ > 50) {
        throw std::invalid_argument("audio jitter buffer bounds are invalid");
    }
}

bool AudioJitterBuffer::push(AudioPacket packet) {
    validate_packet(packet);
    if (expected_sequence_ && packet.sequence < *expected_sequence_) {
        ++telemetry_.late;
        return false;
    }
    if (packets_.contains(packet.sequence)) {
        ++telemetry_.duplicates;
        return false;
    }
    if (packets_.size() >= maximum_packets_) {
        ++telemetry_.overflow;
        return false;
    }
    packets_.emplace(packet.sequence, std::move(packet));
    ++telemetry_.accepted;
    telemetry_.depth = packets_.size();
    return true;
}

std::optional<PlayoutPacket> AudioJitterBuffer::pop(const bool deadline_expired) {
    if (!expected_sequence_) {
        if (packets_.size() < target_packets_) {
            return std::nullopt;
        }
        expected_sequence_ = packets_.begin()->first;
    }
    const auto expected = *expected_sequence_;
    const auto found = packets_.find(expected);
    if (found != packets_.end()) {
        auto packet = std::move(found->second);
        packets_.erase(found);
        ++*expected_sequence_;
        telemetry_.depth = packets_.size();
        return PlayoutPacket{
            .sequence = expected,
            .packet_loss_concealment = false,
            .packet = std::move(packet),
        };
    }
    if (!deadline_expired &&
        (packets_.empty() || packets_.begin()->first <= expected)) {
        return std::nullopt;
    }
    ++*expected_sequence_;
    ++telemetry_.plc_frames;
    telemetry_.depth = packets_.size();
    return PlayoutPacket{
        .sequence = expected,
        .packet_loss_concealment = true,
        .packet = std::nullopt,
    };
}

JitterTelemetry AudioJitterBuffer::telemetry() const noexcept {
    auto result = telemetry_;
    result.depth = packets_.size();
    return result;
}

void AudioJitterBuffer::reset() noexcept {
    packets_.clear();
    expected_sequence_.reset();
    telemetry_.depth = 0;
}

void AudioSender::send(
    const PcmFrame& frame, const std::uint64_t captured_at_us) {
    if (!authorization_.permits(core::Capability::desktop_view)) {
        throw std::logic_error("desktop view capability is required for audio");
    }
    validate_pcm_frame(frame);
    if (captured_at_us == 0) {
        throw std::invalid_argument("audio capture timestamp is required");
    }
    auto opus = codec_.encode(frame);
    AudioPacket packet{
        .sequence = next_sequence_++,
        .captured_at_us = captured_at_us,
        .sample_rate = frame.sample_rate,
        .channels = frame.channels,
        .samples_per_channel = frame.samples_per_channel,
        .opus = std::move(opus),
    };
    const auto wire = encode_packet(packet);
    transport_.send_datagram(transport::DatagramChannel::audio, wire);
}

bool AudioReceiver::receive(const std::span<const std::byte> datagram) {
    if (!authorization_.permits(core::Capability::desktop_view)) {
        throw std::logic_error("desktop view capability is required for audio");
    }
    return jitter_.push(decode_packet(datagram));
}

std::optional<PcmFrame> AudioReceiver::playout(const bool deadline_expired) {
    if (!authorization_.permits(core::Capability::desktop_view)) {
        throw std::logic_error("desktop view capability is required for audio");
    }
    const auto next = jitter_.pop(deadline_expired);
    if (!next) return std::nullopt;
    if (next->packet_loss_concealment) {
        auto concealed = codec_.conceal_loss(opus_frame_samples);
        validate_pcm_frame(concealed);
        return concealed;
    }
    auto decoded = codec_.decode(*next->packet);
    validate_pcm_frame(decoded);
    return decoded;
}

bool AudioCaptureRelay::pump(const std::chrono::milliseconds timeout) {
    const auto captured = capture_.capture(timeout);
    if (!captured) return false;
    validate_pcm_frame(captured->frame);
    if (captured->captured_at_us == 0) {
        throw std::invalid_argument("captured audio timestamp is required");
    }
    sender_.send(captured->frame, captured->captured_at_us);
    return true;
}

bool AudioPlaybackRelay::pump(
    const bool deadline_expired,
    const std::chrono::milliseconds timeout) {
    const auto frame = receiver_.playout(deadline_expired);
    if (!frame) return false;
    playback_.play(*frame, timeout);
    return true;
}

}  // namespace rwn::audio
