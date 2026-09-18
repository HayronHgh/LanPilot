#pragma once

#include "rwn/desktop/desktop.hpp"

#include <d3d11.h>
#include <wrl/client.h>

#include <memory>
#include <span>

namespace rwn::platform::windows {

struct WindowsNv12Frame {
    std::uint64_t frame_id{};
    std::uint64_t representation_epoch{1};
    bool keyframe{};
    std::uint64_t captured_at_us{};
    std::uint32_t width{};
    std::uint32_t height{};
    std::uint32_t row_stride{};
    std::vector<std::byte> nv12;
    Microsoft::WRL::ComPtr<ID3D11Texture2D> d3d11_texture;
    std::uint32_t d3d11_subresource{};
    // Media Foundation values; zero means absent/unspecified.
    std::uint32_t nominal_range{};
    std::uint32_t yuv_matrix{};

    [[nodiscard]] bool gpu_backed() const noexcept {
        return d3d11_texture != nullptr;
    }
};

[[nodiscard]] std::vector<std::byte> repack_padded_nv12(
    std::span<const std::byte> source,
    std::uint32_t width,
    std::uint32_t height,
    std::uint32_t source_stride,
    std::uint32_t source_luma_rows);

[[nodiscard]] std::optional<std::uint32_t>
map_windows_raw_keyboard_to_hid_usage(
    std::uint16_t make_code,
    std::uint16_t flags,
    std::uint16_t virtual_key) noexcept;

struct WindowsH264QueueDepths {
    std::size_t compressed_lineage{};
    std::size_t decoded_ready{};
    bool low_latency_enabled{};
    bool d3d11_output_active{};
};

class WindowsDesktopCaptureBackend final : public desktop::CaptureBackend {
public:
    WindowsDesktopCaptureBackend();
    ~WindowsDesktopCaptureBackend() override;
    WindowsDesktopCaptureBackend(const WindowsDesktopCaptureBackend&) = delete;
    WindowsDesktopCaptureBackend& operator=(const WindowsDesktopCaptureBackend&) = delete;

    [[nodiscard]] std::optional<desktop::RawFrame> capture(
        std::chrono::milliseconds timeout) override;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

class WindowsMediaFoundationH264Decoder final
    : public desktop::VideoDecoder {
public:
    WindowsMediaFoundationH264Decoder();
    explicit WindowsMediaFoundationH264Decoder(ID3D11Device* device);
    ~WindowsMediaFoundationH264Decoder() override;
    WindowsMediaFoundationH264Decoder(
        const WindowsMediaFoundationH264Decoder&) = delete;
    WindowsMediaFoundationH264Decoder& operator=(
        const WindowsMediaFoundationH264Decoder&) = delete;

    [[nodiscard]] desktop::RawFrame decode(
        const desktop::VideoFrame& frame) override;
    [[nodiscard]] std::optional<desktop::RawFrame> submit(
        const desktop::VideoFrame& frame);
    [[nodiscard]] std::optional<WindowsNv12Frame> submit_nv12(
        const desktop::VideoFrame& frame);
    void flush_representation();
    // Non-blocking output pump, without submitting a new compressed sample.
    [[nodiscard]] std::optional<WindowsNv12Frame> poll_nv12();
    [[nodiscard]] std::optional<std::uint32_t> low_latency_readback() const;
    [[nodiscard]] WindowsH264QueueDepths queue_depths() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

class WindowsInputBackend final : public desktop::InputBackend {
public:
    void raw_key(std::uint32_t hid_usage, bool pressed) override;
    void text_commit(std::string_view utf8) override;
    void pointer_move(std::uint16_t normalized_x, std::uint16_t normalized_y) override;
    void pointer_button(std::uint8_t button, bool pressed) override;
    void pointer_wheel(std::int32_t delta, bool horizontal) override;
};

class WindowsClipboardBackend final : public desktop::ClipboardBackend {
public:
    [[nodiscard]] std::string read_utf8_text() override;
    void write_utf8_text(std::string_view text) override;
};

class WindowsDesktopPermissionBackend final : public desktop::DesktopPermissionBackend {
public:
    [[nodiscard]] desktop::DesktopPermissionStatus status() const override;
    void request_capture() override;
    void request_input() override;
};

struct WindowsH264Capabilities {
    bool hardware_encoder{};
    bool hardware_decoder{};
};

[[nodiscard]] WindowsH264Capabilities probe_h264_capabilities();

}  // namespace rwn::platform::windows
