#include "d3d11_renderer.hpp"
#include "rwn/desktop/snapshot_upload.hpp"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <stdexcept>

int main() {
    HWND window{};
    try {
        window = CreateWindowExW(0, L"STATIC", L"RWN hidden GPU probe", WS_POPUP,
            0, 0, 320, 180, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
        if (!window) throw std::runtime_error("hidden probe window creation failed");
        rwn::viewer::D3D11Nv12Renderer renderer;
        renderer.initialize(window);
        std::vector<std::byte> pixels(1920U * 1080U * 4U);
        for (std::size_t i = 0; i < pixels.size(); ++i)
            pixels[i] = i % 4 == 3 ? std::byte{255} : static_cast<std::byte>((i * 37U + i / 7680U) % 256U);
        const auto batch = rwn::desktop::snapshot_upload_batch_size(7680, 1024U * 1024U);
        renderer.begin_full_snapshot(1920, 1080);
        renderer.cancel_full_snapshot();
        bool unavailable = false;
        try { static_cast<void>(renderer.committed_framebuffer_bgra()); }
        catch (const std::logic_error&) { unavailable = true; }
        if (!unavailable) throw std::runtime_error("cold cancel exposed uncommitted pixels");
        renderer.begin_full_snapshot(1920, 1080);
        for (std::size_t offset = 0; offset < pixels.size(); offset += batch)
            renderer.write_full_snapshot_chunk(static_cast<std::uint32_t>(offset),
                std::span(pixels).subspan(offset, std::min(batch, pixels.size() - offset)));
        static_cast<void>(renderer.commit_full_snapshot(window, 1));
        const auto original = renderer.committed_framebuffer_bgra();
        if (original != pixels) throw std::runtime_error("cold snapshot pixel mismatch");
        std::cout << "cold_snapshot=PASS video_seed=0 mismatch_bytes=0\n";
        // A resize never needs a new visual packet. The committed pixels stay
        // intact while the swap chain follows wide, tall and maximized shapes.
        for (const auto& [width, height] : {
                 std::pair{800, 600}, std::pair{600, 900},
                 std::pair{1440, 900}, std::pair{2560, 1440}}) {
            if (!SetWindowPos(window, nullptr, 0, 0, width, height,
                              SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE) ||
                !renderer.present_framebuffer(window) ||
                renderer.committed_framebuffer_bgra() != original)
                throw std::runtime_error("resize changed or failed to present committed pixels");
        }
        std::cout << "resize_represent=PASS sizes=4 new_visual_packets=0 mismatch_bytes=0\n";
        for (std::size_t i = 0; i < pixels.size(); i += 4) pixels[i] ^= std::byte{127};
        bool resize_rejected = false;
        try { renderer.begin_full_snapshot(1280, 720); }
        catch (const std::logic_error&) { resize_rejected = true; }
        if (!resize_rejected || renderer.committed_framebuffer_bgra() != original)
            throw std::runtime_error("incompatible resize destroyed committed pixels");
        renderer.begin_full_snapshot(1920, 1080);
        renderer.write_full_snapshot_chunk(0, std::span(pixels).first(batch));
        bool rejected = false;
        try { static_cast<void>(renderer.commit_full_snapshot(window, 2)); }
        catch (const std::logic_error&) { rejected = true; }
        if (!rejected || renderer.committed_framebuffer_bgra() != original)
            throw std::runtime_error("incomplete snapshot changed committed state");
        renderer.cancel_full_snapshot();
        if (renderer.committed_framebuffer_bgra() != original)
            throw std::runtime_error("cancel changed committed state");
        renderer.begin_full_snapshot(1920, 1080);
        auto start = std::chrono::steady_clock::now();
        for (std::size_t offset = 0; offset < pixels.size(); offset += batch)
            renderer.write_full_snapshot_chunk(static_cast<std::uint32_t>(offset),
                std::span(pixels).subspan(offset, std::min(batch, pixels.size() - offset)));
        const auto receipt = renderer.commit_full_snapshot(window, 3);
        const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start).count();
        if (receipt.frame_id != 3 || renderer.committed_framebuffer_bgra() != pixels)
            throw std::runtime_error("GPU canonical pixels differ");
        std::cout << "warm_snapshot=PASS bytes=" << pixels.size()
                  << " batch=" << batch << " upload_commit_us=" << elapsed
                  << " incomplete_rejected=1 cancel_preserved=1 mismatch_bytes=0\n";
        // Exercise the real GPU working/committed textures, not a CPU model.
        // Readbacks are validation-only and deliberately outside timed commits.
        std::vector<long long> recovery_us;
        const auto batch_count = (pixels.size() + batch - 1U) / batch;
        for (std::size_t cycle = 0; cycle < 32; ++cycle) {
            const auto previous = pixels;
            for (std::size_t i = 0; i < pixels.size(); i += 4)
                pixels[i + cycle % 3U] ^= static_cast<std::byte>(cycle + 1U);
            renderer.begin_full_snapshot(1920, 1080);
            const auto stop = std::min(pixels.size(), (cycle % (batch_count + 1U)) * batch);
            for (std::size_t offset = 0; offset < stop; offset += batch)
                renderer.write_full_snapshot_chunk(static_cast<std::uint32_t>(offset),
                    std::span(pixels).subspan(offset, std::min(batch, stop - offset)));
            bool bad_offset_rejected = false;
            try {
                renderer.write_full_snapshot_chunk(static_cast<std::uint32_t>(stop + 7680U),
                    std::span(pixels).first(7680));
            } catch (const std::logic_error&) { bad_offset_rejected = true; }
            if (!bad_offset_rejected || renderer.committed_framebuffer_bgra() != previous)
                throw std::runtime_error("partial or invalid upload corrupted committed pixels");
            renderer.cancel_full_snapshot();
            renderer.cancel_full_snapshot(); // Cancellation must be idempotent.
            bool stale_commit_rejected = false;
            try { static_cast<void>(renderer.commit_full_snapshot(window, 4U + cycle)); }
            catch (const std::logic_error&) { stale_commit_rejected = true; }
            if (!stale_commit_rejected || renderer.committed_framebuffer_bgra() != previous)
                throw std::runtime_error("cancelled transaction became visible");
            renderer.begin_full_snapshot(1920, 1080);
            const auto recovery_start = std::chrono::steady_clock::now();
            for (std::size_t offset = 0; offset < pixels.size(); offset += batch)
                renderer.write_full_snapshot_chunk(static_cast<std::uint32_t>(offset),
                    std::span(pixels).subspan(offset, std::min(batch, pixels.size() - offset)));
            const auto recovered = renderer.commit_full_snapshot(window, 100U + cycle);
            recovery_us.push_back(std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - recovery_start).count());
            if (recovered.frame_id != 100U + cycle || renderer.committed_framebuffer_bgra() != pixels)
                throw std::runtime_error("recovery snapshot differs from intended canonical pixels");
        }
        std::sort(recovery_us.begin(), recovery_us.end());
        std::cout << "recovery_cycles=32 invalid_offset_rejected=32 stale_commit_rejected=32"
                  << " mismatch_bytes=0 upload_commit_p50_us=" << recovery_us[15]
                  << " upload_commit_p95_us=" << recovery_us[30]
                  << " upload_commit_max_us=" << recovery_us.back()
                  << " timing=API_only_not_readback_or_scanout\n";
        DestroyWindow(window);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        if (window) DestroyWindow(window);
        return 1;
    }
}
