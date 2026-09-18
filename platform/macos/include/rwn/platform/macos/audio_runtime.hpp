#pragma once

#include "rwn/audio/audio.hpp"

#include <memory>

namespace rwn::platform::macos {

class MacosSystemAudioCapture final : public audio::AudioCaptureBackend {
public:
    MacosSystemAudioCapture();
    ~MacosSystemAudioCapture() override;
    MacosSystemAudioCapture(const MacosSystemAudioCapture&) = delete;
    MacosSystemAudioCapture& operator=(const MacosSystemAudioCapture&) = delete;

    [[nodiscard]] std::optional<audio::CapturedPcmFrame> capture(
        std::chrono::milliseconds timeout) override;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

class MacosAudioPlayback final : public audio::AudioPlaybackBackend {
public:
    MacosAudioPlayback();
    ~MacosAudioPlayback() override;
    MacosAudioPlayback(const MacosAudioPlayback&) = delete;
    MacosAudioPlayback& operator=(const MacosAudioPlayback&) = delete;

    void play(
        const audio::PcmFrame& frame,
        std::chrono::milliseconds timeout) override;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace rwn::platform::macos
