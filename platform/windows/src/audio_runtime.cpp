#include "rwn/platform/windows/audio_runtime.hpp"

#include <Windows.h>
#include <audioclient.h>
#include <mmdeviceapi.h>
#include <wrl/client.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace rwn::platform::windows {
namespace {

using Microsoft::WRL::ComPtr;

constexpr auto maximum_audio_wait = std::chrono::seconds{10};

void require_hresult(const HRESULT result, const char* operation) {
    if (FAILED(result)) {
        throw std::runtime_error(
            std::string(operation) + " failed with HRESULT " +
            std::to_string(static_cast<unsigned long>(result)));
    }
}

class ComApartment {
public:
    ComApartment() {
        const auto result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (result == S_OK || result == S_FALSE) {
            uninitialize_ = true;
        } else if (result != RPC_E_CHANGED_MODE) {
            require_hresult(result, "initialize WASAPI COM apartment");
        }
    }
    ~ComApartment() {
        if (uninitialize_) CoUninitialize();
    }
    ComApartment(const ComApartment&) = delete;
    ComApartment& operator=(const ComApartment&) = delete;

private:
    bool uninitialize_{};
};

class EventHandle {
public:
    EventHandle() : handle_(CreateEventW(nullptr, FALSE, FALSE, nullptr)) {
        if (handle_ == nullptr) {
            throw std::runtime_error("create WASAPI event failed");
        }
    }
    ~EventHandle() {
        if (handle_ != nullptr) CloseHandle(handle_);
    }
    EventHandle(const EventHandle&) = delete;
    EventHandle& operator=(const EventHandle&) = delete;
    [[nodiscard]] HANDLE get() const noexcept { return handle_; }

private:
    HANDLE handle_{};
};

WAVEFORMATEX opus_pcm_format() {
    WAVEFORMATEX format{};
    format.wFormatTag = WAVE_FORMAT_PCM;
    format.nChannels = audio::opus_channels;
    format.nSamplesPerSec = audio::opus_sample_rate;
    format.wBitsPerSample = 16;
    format.nBlockAlign = static_cast<WORD>(
        format.nChannels * format.wBitsPerSample / 8U);
    format.nAvgBytesPerSec = format.nSamplesPerSec * format.nBlockAlign;
    return format;
}

ComPtr<IMMDevice> default_render_device() {
    ComPtr<IMMDeviceEnumerator> enumerator;
    require_hresult(CoCreateInstance(
        __uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
        IID_PPV_ARGS(&enumerator)), "create WASAPI device enumerator");
    ComPtr<IMMDevice> device;
    require_hresult(enumerator->GetDefaultAudioEndpoint(
        eRender, eConsole, &device), "get default render endpoint");
    return device;
}

void validate_timeout(const std::chrono::milliseconds timeout) {
    if (timeout <= std::chrono::milliseconds::zero() ||
        timeout > maximum_audio_wait) {
        throw std::invalid_argument("WASAPI timeout is outside bounds");
    }
}

DWORD remaining_wait_ms(
    const std::chrono::steady_clock::time_point deadline) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) return 0;
    const auto remaining = std::chrono::ceil<std::chrono::milliseconds>(
        deadline - now);
    return static_cast<DWORD>(std::min<std::int64_t>(
        remaining.count(), std::numeric_limits<DWORD>::max()));
}

std::uint64_t steady_timestamp_us() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

}  // namespace

class WindowsAudioLoopbackCapture::Impl {
public:
    Impl() {
        const auto device = default_render_device();
        require_hresult(device->Activate(
            __uuidof(IAudioClient), CLSCTX_ALL, nullptr,
            reinterpret_cast<void**>(client_.GetAddressOf())),
            "activate WASAPI loopback client");
        auto format = opus_pcm_format();
        constexpr DWORD flags =
            AUDCLNT_STREAMFLAGS_LOOPBACK |
            AUDCLNT_STREAMFLAGS_EVENTCALLBACK |
            AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM |
            AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY;
        require_hresult(client_->Initialize(
            AUDCLNT_SHAREMODE_SHARED, flags, 0, 0, &format, nullptr),
            "initialize WASAPI loopback stream");
        require_hresult(client_->SetEventHandle(event_.get()),
                        "set WASAPI loopback event");
        require_hresult(client_->GetService(IID_PPV_ARGS(&capture_)),
                        "get WASAPI capture service");
        require_hresult(client_->Start(), "start WASAPI loopback stream");
        started_ = true;
    }

    ~Impl() {
        if (started_) static_cast<void>(client_->Stop());
    }

    [[nodiscard]] std::optional<audio::CapturedPcmFrame> capture(
        const std::chrono::milliseconds timeout) {
        validate_timeout(timeout);
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        constexpr auto target_samples =
            static_cast<std::size_t>(audio::opus_channels) *
            audio::opus_frame_samples;
        while (pending_.size() < target_samples) {
            drain_packets();
            if (pending_.size() >= target_samples) break;
            const auto wait = remaining_wait_ms(deadline);
            if (wait == 0) return std::nullopt;
            const auto result = WaitForSingleObject(event_.get(), wait);
            if (result == WAIT_TIMEOUT) return std::nullopt;
            if (result != WAIT_OBJECT_0) {
                throw std::runtime_error("wait for WASAPI loopback event failed");
            }
        }
        audio::CapturedPcmFrame result{
            .frame = {
                .sample_rate = audio::opus_sample_rate,
                .channels = audio::opus_channels,
                .samples_per_channel = audio::opus_frame_samples,
                .interleaved_samples = std::vector<std::int16_t>(
                    pending_.begin(), pending_.begin() +
                        static_cast<std::ptrdiff_t>(target_samples)),
            },
            .captured_at_us = first_sample_at_us_ == 0
                ? steady_timestamp_us() : first_sample_at_us_,
        };
        pending_.erase(
            pending_.begin(), pending_.begin() +
                static_cast<std::ptrdiff_t>(target_samples));
        first_sample_at_us_ = pending_.empty() ? 0 : steady_timestamp_us();
        audio::validate_pcm_frame(result.frame);
        return result;
    }

private:
    void drain_packets() {
        UINT32 packet_frames{};
        require_hresult(capture_->GetNextPacketSize(&packet_frames),
                        "query WASAPI loopback packet");
        while (packet_frames != 0) {
            BYTE* data{};
            DWORD flags{};
            UINT64 device_position{};
            UINT64 qpc_position{};
            require_hresult(capture_->GetBuffer(
                &data, &packet_frames, &flags, &device_position,
                &qpc_position), "read WASAPI loopback packet");
            static_cast<void>(device_position);
            if (packet_frames > audio::opus_sample_rate) {
                static_cast<void>(capture_->ReleaseBuffer(packet_frames));
                throw std::length_error("WASAPI loopback packet exceeds bound");
            }
            if ((flags & AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY) != 0) {
                pending_.clear();
                first_sample_at_us_ = 0;
            }
            if (pending_.empty()) {
                first_sample_at_us_ =
                    (flags & AUDCLNT_BUFFERFLAGS_TIMESTAMP_ERROR) == 0 &&
                            qpc_position != 0
                        ? qpc_position / 10U : steady_timestamp_us();
            }
            const auto samples = static_cast<std::size_t>(packet_frames) *
                                 audio::opus_channels;
            if (pending_.size() + samples >
                static_cast<std::size_t>(audio::opus_sample_rate) *
                    audio::opus_channels) {
                static_cast<void>(capture_->ReleaseBuffer(packet_frames));
                throw std::length_error("WASAPI pending audio exceeds one second");
            }
            if ((flags & AUDCLNT_BUFFERFLAGS_SILENT) != 0 || data == nullptr) {
                pending_.insert(pending_.end(), samples, 0);
            } else {
                const auto* begin = reinterpret_cast<const std::int16_t*>(data);
                pending_.insert(pending_.end(), begin, begin + samples);
            }
            require_hresult(capture_->ReleaseBuffer(packet_frames),
                            "release WASAPI loopback packet");
            require_hresult(capture_->GetNextPacketSize(&packet_frames),
                            "query next WASAPI loopback packet");
        }
    }

    ComApartment apartment_;
    EventHandle event_;
    ComPtr<IAudioClient> client_;
    ComPtr<IAudioCaptureClient> capture_;
    std::vector<std::int16_t> pending_;
    std::uint64_t first_sample_at_us_{};
    bool started_{};
};

class WindowsAudioPlayback::Impl {
public:
    Impl() {
        const auto device = default_render_device();
        require_hresult(device->Activate(
            __uuidof(IAudioClient), CLSCTX_ALL, nullptr,
            reinterpret_cast<void**>(client_.GetAddressOf())),
            "activate WASAPI render client");
        auto format = opus_pcm_format();
        constexpr DWORD flags =
            AUDCLNT_STREAMFLAGS_EVENTCALLBACK |
            AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM |
            AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY;
        require_hresult(client_->Initialize(
            AUDCLNT_SHAREMODE_SHARED, flags, 0, 0, &format, nullptr),
            "initialize WASAPI render stream");
        require_hresult(client_->SetEventHandle(event_.get()),
                        "set WASAPI render event");
        require_hresult(client_->GetBufferSize(&buffer_frames_),
                        "get WASAPI render buffer size");
        require_hresult(client_->GetService(IID_PPV_ARGS(&render_)),
                        "get WASAPI render service");
        require_hresult(client_->Start(), "start WASAPI render stream");
        started_ = true;
    }

    ~Impl() {
        if (started_) static_cast<void>(client_->Stop());
    }

    void play(
        const audio::PcmFrame& frame,
        const std::chrono::milliseconds timeout) {
        validate_timeout(timeout);
        audio::validate_pcm_frame(frame);
        std::vector<std::int16_t> stereo;
        const std::int16_t* samples = frame.interleaved_samples.data();
        if (frame.channels == 1) {
            stereo.reserve(
                static_cast<std::size_t>(frame.samples_per_channel) * 2U);
            for (const auto sample : frame.interleaved_samples) {
                stereo.push_back(sample);
                stereo.push_back(sample);
            }
            samples = stereo.data();
        }
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        UINT32 written{};
        while (written < frame.samples_per_channel) {
            UINT32 padding{};
            require_hresult(client_->GetCurrentPadding(&padding),
                            "get WASAPI render padding");
            if (padding > buffer_frames_) {
                throw std::runtime_error("WASAPI render padding is invalid");
            }
            const auto available = buffer_frames_ - padding;
            if (available == 0) {
                const auto wait = remaining_wait_ms(deadline);
                if (wait == 0 || WaitForSingleObject(event_.get(), wait) !=
                                     WAIT_OBJECT_0) {
                    throw std::runtime_error("WASAPI render timed out");
                }
                continue;
            }
            const auto frames = std::min<UINT32>(
                available, frame.samples_per_channel - written);
            BYTE* destination{};
            require_hresult(render_->GetBuffer(frames, &destination),
                            "acquire WASAPI render buffer");
            const auto bytes = static_cast<std::size_t>(frames) *
                               audio::opus_channels * sizeof(std::int16_t);
            std::memcpy(
                destination,
                samples + static_cast<std::size_t>(written) *
                    audio::opus_channels,
                bytes);
            require_hresult(render_->ReleaseBuffer(frames, 0),
                            "release WASAPI render buffer");
            written += frames;
        }
    }

private:
    ComApartment apartment_;
    EventHandle event_;
    ComPtr<IAudioClient> client_;
    ComPtr<IAudioRenderClient> render_;
    UINT32 buffer_frames_{};
    bool started_{};
};

WindowsAudioLoopbackCapture::WindowsAudioLoopbackCapture()
    : impl_(std::make_unique<Impl>()) {}
WindowsAudioLoopbackCapture::~WindowsAudioLoopbackCapture() = default;

std::optional<audio::CapturedPcmFrame> WindowsAudioLoopbackCapture::capture(
    const std::chrono::milliseconds timeout) {
    return impl_->capture(timeout);
}

WindowsAudioPlayback::WindowsAudioPlayback()
    : impl_(std::make_unique<Impl>()) {}
WindowsAudioPlayback::~WindowsAudioPlayback() = default;

void WindowsAudioPlayback::play(
    const audio::PcmFrame& frame,
    const std::chrono::milliseconds timeout) {
    impl_->play(frame, timeout);
}

}  // namespace rwn::platform::windows
