#pragma once

#include "rwn/audio/audio.hpp"

#include <memory>

namespace rwn::platform::windows {

class WindowsAudioLoopbackCapture final : public audio::AudioCaptureBackend {
public:
    WindowsAudioLoopbackCapture();
    ~WindowsAudioLoopbackCapture() override;
    WindowsAudioLoopbackCapture(const WindowsAudioLoopbackCapture&) = delete;
    WindowsAudioLoopbackCapture& operator=(
        const WindowsAudioLoopbackCapture&) = delete;

    [[nodiscard]] std::optional<audio::CapturedPcmFrame> capture(
        std::chrono::milliseconds timeout) override;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

class WindowsAudioPlayback final : public audio::AudioPlaybackBackend {
public:
    WindowsAudioPlayback();
    ~WindowsAudioPlayback() override;
    WindowsAudioPlayback(const WindowsAudioPlayback&) = delete;
    WindowsAudioPlayback& operator=(const WindowsAudioPlayback&) = delete;

    void play(
        const audio::PcmFrame& frame,
        std::chrono::milliseconds timeout) override;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace rwn::platform::windows
