#include "d3d11_renderer.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <iostream>
#include <stdexcept>

// Hidden synthetic runtime probe: actual NV12 video processor and GPU readback.
// No capture, input injection, network, or saved desktop pixels.
int main() {
    HWND window{};
    try {
        window = CreateWindowExW(0, L"STATIC", L"RWN hidden color probe", WS_POPUP,
            0, 0, 320, 180, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
        if (!window) throw std::runtime_error("window creation failed");
        rwn::viewer::D3D11Nv12Renderer renderer;
        renderer.initialize(window);
        constexpr std::array<std::array<int, 3>, 8> patches{{
            {16,128,128}, {235,128,128}, {64,128,128}, {126,128,128},
            {180,128,128}, {100,90,180}, {130,180,90}, {170,80,90}}};
        int max_error = 0;
        for (const auto range : {0U, 2U, 1U}) {
        for (std::size_t i = 0; i < patches.size(); ++i) {
            const auto [y,u,v] = patches[i];
            rwn::platform::windows::WindowsNv12Frame frame;
            frame.frame_id = i + 1;
            frame.nominal_range = range;
            frame.yuv_matrix = 1; // MFVideoTransferMatrix_BT709
            frame.width = 320; frame.height = 180; frame.row_stride = 320;
            frame.nv12.resize(320U * 180U * 3U / 2U);
            std::fill_n(frame.nv12.begin(), 320U * 180U, static_cast<std::byte>(y));
            for (std::size_t j = 320U * 180U; j < frame.nv12.size(); j += 2) {
                frame.nv12[j] = static_cast<std::byte>(u);
                frame.nv12[j+1] = static_cast<std::byte>(v);
            }
            static_cast<void>(renderer.render_persistent(window, frame));
            const auto pixels = renderer.committed_framebuffer_bgra();
            const auto quantize = [](double value) {
                return std::clamp(static_cast<int>(std::lround(value)), 0, 255);
            };
            const double luma = range == 1 ? y : (y - 16) * 255.0 / 219.0;
            const double cb = (u - 128) * (range == 1 ? 1.0 : 255.0 / 224.0);
            const double cr = (v - 128) * (range == 1 ? 1.0 : 255.0 / 224.0);
            const std::array<int,3> expected{quantize(luma + 1.8556 * cb),
                quantize(luma - 0.187324 * cb - 0.468124 * cr),
                quantize(luma + 1.5748 * cr)};
            std::cout << "range=" << range << " patch=" << i << " expected_bgr=";
            for (auto value : expected) std::cout << value << ',';
            std::cout << " actual_bgr=";
            for (std::size_t channel = 0; channel < 3; ++channel) {
                const auto actual = std::to_integer<int>(pixels[(90U * 320U + 160U) * 4U + channel]);
                max_error = std::max(max_error, std::abs(actual - expected[channel]));
                std::cout << actual << ',';
            }
            std::cout << '\n';
        }
        }
        DestroyWindow(window);
        std::cout << "bt709_max_channel_error=" << max_error << " tolerance=2\n";
        return max_error <= 2 ? 0 : 1;
    } catch (const std::exception& error) {
        if (window) DestroyWindow(window);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
