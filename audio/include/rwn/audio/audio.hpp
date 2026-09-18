#pragma once

#include "rwn/core/authorization.hpp"
#include "rwn/transport/transport.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace rwn::audio {

inline constexpr std::uint32_t opus_sample_rate = 48000;
inline constexpr std::uint16_t opus_channels = 2;
inline constexpr std::uint16_t opus_frame_samples = 960;
inline constexpr std::size_t maximum_opus_packet_size = 1275;
inline constexpr std::size_t maximum_audio_datagram_size = 1400;

struct PcmFrame {
    std::uint32_t sample_rate{opus_sample_rate};
    std::uint16_t channels{opus_channels};
    std::uint16_t samples_per_channel{opus_frame_samples};
    std::vector<std::int16_t> interleaved_samples;
};

struct CapturedPcmFrame {
    PcmFrame frame;
    std::uint64_t captured_at_us{};
};

class AudioCaptureBackend {
public:
    virtual ~AudioCaptureBackend() = default;
    [[nodiscard]] virtual std::optional<CapturedPcmFrame> capture(
        std::chrono::milliseconds timeout) = 0;
};

class AudioPlaybackBackend {
public:
    virtual ~AudioPlaybackBackend() = default;
    virtual void play(
        const PcmFrame& frame, std::chrono::milliseconds timeout) = 0;
};

struct AudioPacket {
    std::uint64_t sequence{};
    std::uint64_t captured_at_us{};
    std::uint32_t sample_rate{opus_sample_rate};
    std::uint16_t channels{opus_channels};
    std::uint16_t samples_per_channel{opus_frame_samples};
    std::vector<std::byte> opus;

    [[nodiscard]] bool operator==(const AudioPacket&) const = default;
};

void validate_pcm_frame(const PcmFrame& frame);
[[nodiscard]] std::vector<std::byte> encode_packet(const AudioPacket& packet);
[[nodiscard]] AudioPacket decode_packet(std::span<const std::byte> bytes);

class OpusCodec {
public:
    virtual ~OpusCodec() = default;
    [[nodiscard]] virtual std::vector<std::byte> encode(const PcmFrame& frame) = 0;
    [[nodiscard]] virtual PcmFrame decode(const AudioPacket& packet) = 0;
    [[nodiscard]] virtual PcmFrame conceal_loss(
        std::uint16_t samples_per_channel) = 0;
};

class DynamicOpusCodec final : public OpusCodec {
public:
    explicit DynamicOpusCodec(
        std::filesystem::path absolute_library_path,
        std::uint16_t channels = opus_channels);
    ~DynamicOpusCodec() override;
    DynamicOpusCodec(const DynamicOpusCodec&) = delete;
    DynamicOpusCodec& operator=(const DynamicOpusCodec&) = delete;

    [[nodiscard]] std::vector<std::byte> encode(const PcmFrame& frame) override;
    [[nodiscard]] PcmFrame decode(const AudioPacket& packet) override;
    [[nodiscard]] PcmFrame conceal_loss(
        std::uint16_t samples_per_channel) override;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

struct JitterTelemetry {
    std::uint64_t accepted{};
    std::uint64_t duplicates{};
    std::uint64_t late{};
    std::uint64_t overflow{};
    std::uint64_t plc_frames{};
    std::size_t depth{};
};

struct PlayoutPacket {
    std::uint64_t sequence{};
    bool packet_loss_concealment{};
    std::optional<AudioPacket> packet;
};

class AudioJitterBuffer {
public:
    explicit AudioJitterBuffer(
        std::size_t target_packets = 3,
        std::size_t maximum_packets = 10);
    [[nodiscard]] bool push(AudioPacket packet);
    [[nodiscard]] std::optional<PlayoutPacket> pop(bool deadline_expired = false);
    [[nodiscard]] JitterTelemetry telemetry() const noexcept;
    void reset() noexcept;

private:
    std::size_t target_packets_{};
    std::size_t maximum_packets_{};
    std::map<std::uint64_t, AudioPacket> packets_;
    std::optional<std::uint64_t> expected_sequence_;
    JitterTelemetry telemetry_;
};

class AudioSender {
public:
    AudioSender(
        transport::Transport& transport, OpusCodec& codec,
        core::AuthorizationResult authorization)
        : transport_(transport), codec_(codec),
          authorization_(std::move(authorization)) {}
    void send(const PcmFrame& frame, std::uint64_t captured_at_us);

private:
    transport::Transport& transport_;
    OpusCodec& codec_;
    core::AuthorizationResult authorization_;
    std::uint64_t next_sequence_{1};
};

class AudioReceiver {
public:
    AudioReceiver(
        OpusCodec& codec, core::AuthorizationResult authorization,
        std::size_t target_packets = 3,
        std::size_t maximum_packets = 10)
        : codec_(codec), authorization_(std::move(authorization)),
          jitter_(target_packets, maximum_packets) {}
    [[nodiscard]] bool receive(std::span<const std::byte> datagram);
    [[nodiscard]] std::optional<PcmFrame> playout(bool deadline_expired = false);
    [[nodiscard]] JitterTelemetry telemetry() const noexcept {
        return jitter_.telemetry();
    }

private:
    OpusCodec& codec_;
    core::AuthorizationResult authorization_;
    AudioJitterBuffer jitter_;
};

class AudioCaptureRelay {
public:
    AudioCaptureRelay(AudioCaptureBackend& capture, AudioSender& sender)
        : capture_(capture), sender_(sender) {}
    [[nodiscard]] bool pump(std::chrono::milliseconds timeout);

private:
    AudioCaptureBackend& capture_;
    AudioSender& sender_;
};

class AudioPlaybackRelay {
public:
    AudioPlaybackRelay(
        AudioReceiver& receiver, AudioPlaybackBackend& playback)
        : receiver_(receiver), playback_(playback) {}
    [[nodiscard]] bool pump(
        bool deadline_expired, std::chrono::milliseconds timeout);

private:
    AudioReceiver& receiver_;
    AudioPlaybackBackend& playback_;
};

}  // namespace rwn::audio
