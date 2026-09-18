#pragma once

#include "rwn/desktop/desktop.hpp"
#include "rwn/platform/windows/desktop_runtime.hpp"

#include <Windows.h>

#include <memory>
#include <array>
#include <span>
#include <vector>

namespace rwn::viewer {

enum class D3D11ScaleMode {
    fit,
    one_to_one,
};

enum class D3D11PresentMode {
    balanced,
    extreme,
};

struct D3D11RenderReceipt {
    std::uint64_t frame_id{};
    std::uint64_t framebuffer_committed_at_us{};
    std::uint64_t present_submitted_at_us{};
};

struct D3D11PixelVerificationReceipt {
    std::uint64_t duration_us{};
    std::uint64_t verified_bytes{};
    std::uint64_t mismatched_bytes{};
    std::uint64_t absolute_error_sum{};
    std::uint64_t squared_error_sum{};
};

class D3D11Nv12Renderer final {
public:
    D3D11Nv12Renderer();
    ~D3D11Nv12Renderer();
    D3D11Nv12Renderer(const D3D11Nv12Renderer&) = delete;
    D3D11Nv12Renderer& operator=(const D3D11Nv12Renderer&) = delete;

    void set_scale_mode(D3D11ScaleMode mode) noexcept;
    [[nodiscard]] D3D11ScaleMode scale_mode() const noexcept;
    void set_present_mode(D3D11PresentMode mode);
    [[nodiscard]] D3D11PresentMode present_mode() const noexcept;
    void initialize(HWND window);
    [[nodiscard]] ID3D11Device* native_device() const noexcept;

    void render(
        HWND window,
        const platform::windows::WindowsNv12Frame& frame);
    [[nodiscard]] D3D11RenderReceipt render_persistent(
        HWND window,
        const platform::windows::WindowsNv12Frame& frame);
    void begin_framebuffer_update();
    void patch_bgra(
        std::uint32_t x, std::uint32_t y,
        std::uint32_t width, std::uint32_t height,
        std::uint32_t row_stride,
        std::span<const std::byte> bgra);
    void copy_rect(
        std::uint32_t source_x, std::uint32_t source_y,
        std::uint32_t destination_x, std::uint32_t destination_y,
        std::uint32_t width, std::uint32_t height);
    [[nodiscard]] D3D11RenderReceipt commit_framebuffer(
        HWND window, std::uint64_t frame_id);
    void cancel_framebuffer_update() noexcept;
    void begin_full_snapshot(
        std::uint32_t width, std::uint32_t height);
    void write_full_snapshot_chunk(
        std::uint32_t chunk_offset,
        std::span<const std::byte> bgra);
    [[nodiscard]] D3D11RenderReceipt commit_full_snapshot(
        HWND window, std::uint64_t frame_id);
    void cancel_full_snapshot() noexcept;
    [[nodiscard]] std::array<std::byte, 32>
        committed_framebuffer_sha256();
    [[nodiscard]] std::vector<std::byte> committed_framebuffer_bgra();
    [[nodiscard]] D3D11PixelVerificationReceipt
        verify_working_bgra(
            std::span<const desktop::VisualRawRect> rectangles);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace rwn::viewer
