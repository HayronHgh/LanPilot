#include "d3d11_renderer.hpp"
#include "rwn/core/content_hash.hpp"

#include <d3d10.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <dxgi1_5.h>
#include <wrl/client.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace rwn::viewer {
namespace {

using Microsoft::WRL::ComPtr;

void require_hresult(const HRESULT result, const char* operation) {
    if (FAILED(result)) {
        throw std::runtime_error(
            std::string(operation) + " failed with HRESULT " +
            std::to_string(static_cast<unsigned long>(result)));
    }
}

std::uint64_t steady_timestamp_us() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

}  // namespace

class D3D11Nv12Renderer::Impl {
public:
    void set_scale_mode(const D3D11ScaleMode mode) noexcept {
        scale_mode_.store(mode, std::memory_order_relaxed);
    }

    [[nodiscard]] D3D11ScaleMode scale_mode() const noexcept {
        return scale_mode_.load(std::memory_order_relaxed);
    }

    void set_present_mode(const D3D11PresentMode mode) {
        if (swap_chain_ != nullptr && present_mode_.load() != mode) {
            throw std::logic_error(
                "Direct3D present mode cannot change after initialization");
        }
        present_mode_.store(mode, std::memory_order_relaxed);
    }

    [[nodiscard]] D3D11PresentMode present_mode() const noexcept {
        return present_mode_.load(std::memory_order_relaxed);
    }

    void initialize(const HWND window) {
        RECT client{};
        GetClientRect(window, &client);
        const auto width = static_cast<std::uint32_t>(
            std::max<LONG>(1, client.right - client.left));
        const auto height = static_cast<std::uint32_t>(
            std::max<LONG>(1, client.bottom - client.top));
        ensure_device(window);
        ensure_swap_chain(width, height);
    }

    [[nodiscard]] ID3D11Device* native_device() const noexcept {
        return device_.Get();
    }

    void render(
        const HWND window,
        const platform::windows::WindowsNv12Frame& frame) {
        if (frame.width == 0 || frame.height == 0 ||
            (!frame.gpu_backed() &&
             (frame.row_stride < frame.width ||
              frame.nv12.size() <
                  static_cast<std::size_t>(frame.row_stride) *
                      frame.height * 3U / 2U))) {
            throw std::invalid_argument("invalid NV12 frame for Direct3D");
        }
        RECT client{};
        GetClientRect(window, &client);
        const auto output_width = static_cast<std::uint32_t>(
            std::max<LONG>(1, client.right - client.left));
        const auto output_height = static_cast<std::uint32_t>(
            std::max<LONG>(1, client.bottom - client.top));
        ensure_device(window);
        ensure_swap_chain(output_width, output_height);
        ensure_processor(
            frame.width, frame.height, output_width, output_height);

        ID3D11Texture2D* render_input = frame.d3d11_texture.Get();
        auto input_slice = frame.d3d11_subresource;
        if (!frame.gpu_backed()) {
            context_->UpdateSubresource(
                input_texture_.Get(), 0, nullptr, frame.nv12.data(),
                frame.row_stride, 0);
            render_input = input_texture_.Get();
            input_slice = 0;
        }

        D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC input_description{};
        input_description.ViewDimension = D3D11_VPIV_DIMENSION_TEXTURE2D;
        input_description.Texture2D.ArraySlice = input_slice;
        ComPtr<ID3D11VideoProcessorInputView> input_view;
        require_hresult(
            video_device_->CreateVideoProcessorInputView(
                render_input, enumerator_.Get(),
                &input_description, &input_view),
            "create Direct3D video input view");

        wait_for_present_capacity();
        ComPtr<ID3D11Texture2D> back_buffer;
        require_hresult(
            swap_chain_->GetBuffer(0, IID_PPV_ARGS(&back_buffer)),
            "read Direct3D back buffer");
        D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC output_description{};
        output_description.ViewDimension = D3D11_VPOV_DIMENSION_TEXTURE2D;
        ComPtr<ID3D11VideoProcessorOutputView> output_view;
        require_hresult(
            video_device_->CreateVideoProcessorOutputView(
                back_buffer.Get(), enumerator_.Get(),
                &output_description, &output_view),
            "create Direct3D video output view");

        const RECT source{
            0, 0, static_cast<LONG>(frame.width),
            static_cast<LONG>(frame.height)};
        const auto scale = scale_mode_.load(std::memory_order_relaxed) ==
                    D3D11ScaleMode::one_to_one &&
                output_width >= frame.width && output_height >= frame.height
            ? 1.0
            : std::min(
                static_cast<double>(output_width) / frame.width,
                static_cast<double>(output_height) / frame.height);
        const auto destination_width = static_cast<LONG>(frame.width * scale);
        const auto destination_height = static_cast<LONG>(frame.height * scale);
        const RECT destination{
            (static_cast<LONG>(output_width) - destination_width) / 2,
            (static_cast<LONG>(output_height) - destination_height) / 2,
            (static_cast<LONG>(output_width) + destination_width) / 2,
            (static_cast<LONG>(output_height) + destination_height) / 2};
        const RECT target{
            0, 0, static_cast<LONG>(output_width),
            static_cast<LONG>(output_height)};
        const D3D11_VIDEO_COLOR black{};
        set_nv12_color_space(processor_.Get(), frame);
        video_context_->VideoProcessorSetOutputBackgroundColor(
            processor_.Get(), FALSE, &black);
        video_context_->VideoProcessorSetOutputTargetRect(
            processor_.Get(), TRUE, &target);
        video_context_->VideoProcessorSetStreamSourceRect(
            processor_.Get(), 0, TRUE, &source);
        video_context_->VideoProcessorSetStreamDestRect(
            processor_.Get(), 0, TRUE, &destination);
        D3D11_VIDEO_PROCESSOR_STREAM stream{};
        stream.Enable = TRUE;
        stream.pInputSurface = input_view.Get();
        require_hresult(
            video_context_->VideoProcessorBlt(
                processor_.Get(), output_view.Get(), 0, 1, &stream),
            "render NV12 frame with Direct3D");
        const auto presented = swap_chain_->Present(
            0, present_mode_.load(std::memory_order_relaxed) ==
                       D3D11PresentMode::extreme
                   ? DXGI_PRESENT_ALLOW_TEARING : 0U);
        if (presented != DXGI_STATUS_OCCLUDED) {
            require_hresult(presented, "present Direct3D frame");
        }
    }

    D3D11RenderReceipt render_persistent(
        const HWND window,
        const platform::windows::WindowsNv12Frame& frame) {
        if (frame.width == 0 || frame.height == 0 ||
            (!frame.gpu_backed() &&
             (frame.row_stride < frame.width ||
              frame.nv12.size() <
                  static_cast<std::size_t>(frame.row_stride) *
                      frame.height * 3U / 2U))) {
            throw std::invalid_argument(
                "invalid NV12 frame for persistent Direct3D compositor");
        }
        RECT client{};
        GetClientRect(window, &client);
        const auto output_width = static_cast<std::uint32_t>(
            std::max<LONG>(1, client.right - client.left));
        const auto output_height = static_cast<std::uint32_t>(
            std::max<LONG>(1, client.bottom - client.top));
        ensure_device(window);
        ensure_swap_chain(output_width, output_height);
        ensure_persistent_pipeline(
            frame.width, frame.height, output_width, output_height);
        ID3D11Texture2D* conversion_input = frame.d3d11_texture.Get();
        auto input_slice = frame.d3d11_subresource;
        if (!frame.gpu_backed()) {
            context_->UpdateSubresource(
                persistent_input_texture_.Get(), 0, nullptr,
                frame.nv12.data(), frame.row_stride, 0);
            conversion_input = persistent_input_texture_.Get();
            input_slice = 0;
        }
        set_nv12_color_space(converter_.Get(), frame);
        blit_texture(
            conversion_input, converter_enumerator_.Get(),
            converter_.Get(), working_bgra_.Get(),
            RECT{0, 0, static_cast<LONG>(frame.width),
                 static_cast<LONG>(frame.height)},
            RECT{0, 0, static_cast<LONG>(frame.width),
                 static_cast<LONG>(frame.height)},
            "convert NV12 into persistent BGRA framebuffer",
            input_slice);
        working_bgra_.Swap(committed_bgra_);
        framebuffer_initialized_ = true;
        framebuffer_update_active_ = false;
        const auto committed_at_us = steady_timestamp_us();
        const auto present_submitted_at_us =
            present_committed(output_width, output_height);
        return D3D11RenderReceipt{
            .frame_id = frame.frame_id,
            .framebuffer_committed_at_us = committed_at_us,
            .present_submitted_at_us = present_submitted_at_us,
        };
    }

    void begin_framebuffer_update() {
        if (!framebuffer_initialized_ || framebuffer_update_active_) return;
        context_->CopyResource(working_bgra_.Get(), committed_bgra_.Get());
        framebuffer_update_active_ = true;
    }

    void patch_bgra(
        const std::uint32_t x, const std::uint32_t y,
        const std::uint32_t width, const std::uint32_t height,
        const std::uint32_t row_stride,
        const std::span<const std::byte> bgra) {
        validate_rect(x, y, width, height);
        if (row_stride < width * 4U ||
            bgra.size() != static_cast<std::size_t>(row_stride) * height) {
            throw std::invalid_argument("invalid BGRA rectangle payload");
        }
        begin_framebuffer_update();
        const D3D11_BOX box{
            .left = x,
            .top = y,
            .front = 0,
            .right = x + width,
            .bottom = y + height,
            .back = 1,
        };
        context_->UpdateSubresource(
            working_bgra_.Get(), 0, &box, bgra.data(), row_stride, 0);
    }

    void copy_rect(
        const std::uint32_t source_x, const std::uint32_t source_y,
        const std::uint32_t destination_x, const std::uint32_t destination_y,
        const std::uint32_t width, const std::uint32_t height) {
        validate_rect(source_x, source_y, width, height);
        validate_rect(destination_x, destination_y, width, height);
        begin_framebuffer_update();
        const D3D11_BOX source{
            .left = source_x,
            .top = source_y,
            .front = 0,
            .right = source_x + width,
            .bottom = source_y + height,
            .back = 1,
        };
        context_->CopySubresourceRegion(
            scratch_bgra_.Get(), 0, 0, 0, 0,
            working_bgra_.Get(), 0, &source);
        const D3D11_BOX scratch{
            .left = 0,
            .top = 0,
            .front = 0,
            .right = width,
            .bottom = height,
            .back = 1,
        };
        context_->CopySubresourceRegion(
            working_bgra_.Get(), 0, destination_x, destination_y, 0,
            scratch_bgra_.Get(), 0, &scratch);
    }

    D3D11RenderReceipt commit_framebuffer(
        const HWND window, const std::uint64_t frame_id) {
        if (!framebuffer_update_active_ || frame_id == 0) {
            throw std::logic_error("no persistent framebuffer update to commit");
        }
        working_bgra_.Swap(committed_bgra_);
        framebuffer_update_active_ = false;
        const auto committed_at_us = steady_timestamp_us();
        RECT client{};
        GetClientRect(window, &client);
        const auto output_width = static_cast<std::uint32_t>(
            std::max<LONG>(1, client.right - client.left));
        const auto output_height = static_cast<std::uint32_t>(
            std::max<LONG>(1, client.bottom - client.top));
        return {
            .frame_id = frame_id,
            .framebuffer_committed_at_us = committed_at_us,
            .present_submitted_at_us =
                present_committed(output_width, output_height),
        };
    }

    void cancel_framebuffer_update() noexcept {
        framebuffer_update_active_ = false;
    }

    void begin_full_snapshot(
        const std::uint32_t width, const std::uint32_t height) {
        if (width == 0 || height == 0 ||
            static_cast<std::uint64_t>(width) * height >
                desktop::maximum_snapshot_total_bytes / 4U) {
            throw std::invalid_argument("snapshot dimensions exceed BGRA budget");
        }
        if (device_ == nullptr || swap_chain_ == nullptr ||
            framebuffer_update_active_ || snapshot_update_active_ ||
            (framebuffer_initialized_ && (width != surface_width_ ||
                                        height != surface_height_))) {
            throw std::logic_error(
                "full snapshot requires initialized device and compatible surface");
        }
        if (!framebuffer_initialized_) {
            // Allocate resources, not a committed visual state. Never seed exact
            // mode through a fabricated NV12/video frame.
            ensure_persistent_pipeline(width, height, output_width_, output_height_);
        }
        snapshot_update_active_ = true;
        snapshot_received_bytes_ = 0;
        snapshot_total_bytes_ = static_cast<std::size_t>(width) * height * 4U;
    }

    void write_full_snapshot_chunk(
        const std::uint32_t chunk_offset,
        const std::span<const std::byte> bgra) {
        if (!snapshot_update_active_ || bgra.empty() ||
            chunk_offset != snapshot_received_bytes_) {
            throw std::logic_error("full snapshot chunk is not contiguous");
        }
        const auto row_stride = static_cast<std::size_t>(surface_width_) * 4U;
        if (chunk_offset % row_stride != 0 || bgra.size() % row_stride != 0 ||
            bgra.size() > snapshot_total_bytes_ - snapshot_received_bytes_) {
            throw std::invalid_argument("full snapshot chunk is not row aligned");
        }
        const auto first_row = chunk_offset / row_stride;
        const auto row_count = bgra.size() / row_stride;
        const D3D11_BOX box{
            .left = 0,
            .top = static_cast<UINT>(first_row),
            .front = 0,
            .right = surface_width_,
            .bottom = static_cast<UINT>(first_row + row_count),
            .back = 1,
        };
        context_->UpdateSubresource(
            working_bgra_.Get(), 0, &box, bgra.data(),
            static_cast<UINT>(row_stride), 0);
        snapshot_received_bytes_ += bgra.size();
    }

    D3D11RenderReceipt commit_full_snapshot(
        const HWND window, const std::uint64_t frame_id) {
        if (!snapshot_update_active_ || frame_id == 0 ||
            snapshot_received_bytes_ != snapshot_total_bytes_) {
            throw std::logic_error("full snapshot transaction is incomplete");
        }
        working_bgra_.Swap(committed_bgra_);
        snapshot_update_active_ = false;
        framebuffer_initialized_ = true;
        const auto committed_at_us = steady_timestamp_us();
        RECT client{};
        GetClientRect(window, &client);
        const auto output_width = static_cast<std::uint32_t>(
            std::max<LONG>(1, client.right - client.left));
        const auto output_height = static_cast<std::uint32_t>(
            std::max<LONG>(1, client.bottom - client.top));
        const auto present_submitted_at_us =
            present_committed(output_width, output_height);
        return {
            .frame_id = frame_id,
            .framebuffer_committed_at_us = committed_at_us,
            .present_submitted_at_us = present_submitted_at_us,
        };
    }

    void cancel_full_snapshot() noexcept {
        snapshot_update_active_ = false;
        snapshot_received_bytes_ = 0;
        snapshot_total_bytes_ = 0;
    }

    std::vector<std::byte> committed_framebuffer_bgra() {
        if (!framebuffer_initialized_ || committed_bgra_ == nullptr ||
            hash_staging_bgra_ == nullptr) {
            throw std::logic_error("committed framebuffer is unavailable");
        }
        context_->CopyResource(
            hash_staging_bgra_.Get(), committed_bgra_.Get());
        D3D11_MAPPED_SUBRESOURCE mapped{};
        require_hresult(
            context_->Map(
                hash_staging_bgra_.Get(), 0, D3D11_MAP_READ, 0, &mapped),
            "map committed BGRA framebuffer hash staging texture");
        const auto row_stride = static_cast<std::size_t>(surface_width_) * 4U;
        std::vector<std::byte> packed(row_stride * surface_height_);
        const auto* source = static_cast<const std::byte*>(mapped.pData);
        for (std::uint32_t row = 0; row < surface_height_; ++row) {
            std::copy_n(
                source + static_cast<std::size_t>(row) * mapped.RowPitch,
                row_stride,
                packed.data() + static_cast<std::size_t>(row) * row_stride);
        }
        context_->Unmap(hash_staging_bgra_.Get(), 0);
        return packed;
    }

    std::array<std::byte, 32> committed_framebuffer_sha256() {
        return core::sha256(committed_framebuffer_bgra());
    }

    D3D11PixelVerificationReceipt verify_working_bgra(
        const std::span<const desktop::VisualRawRect> rectangles) {
        if (rectangles.empty() || !framebuffer_update_active_ ||
            working_bgra_ == nullptr) {
            throw std::invalid_argument(
                "pixel verification requires an active working framebuffer");
        }
        const auto started_at_us = steady_timestamp_us();
        D3D11PixelVerificationReceipt result;
        std::uint32_t left = surface_width_;
        std::uint32_t top = surface_height_;
        std::uint32_t right{};
        std::uint32_t bottom{};
        for (const auto& rectangle : rectangles) {
            validate_rect(
                rectangle.x, rectangle.y,
                rectangle.width, rectangle.height);
            if (rectangle.surface_width != surface_width_ ||
                rectangle.surface_height != surface_height_ ||
                rectangle.row_stride != rectangle.width * 4U ||
                rectangle.bgra.size() !=
                    static_cast<std::size_t>(rectangle.row_stride) *
                        rectangle.height) {
                throw std::invalid_argument(
                    "pixel verification rectangle is invalid");
            }
            left = std::min(left, rectangle.x);
            top = std::min(top, rectangle.y);
            right = std::max(right, rectangle.x + rectangle.width);
            bottom = std::max(bottom, rectangle.y + rectangle.height);
        }
        const D3D11_BOX region{
            .left = left,
            .top = top,
            .front = 0,
            .right = right,
            .bottom = bottom,
            .back = 1,
        };
        context_->CopySubresourceRegion(
            hash_staging_bgra_.Get(), 0, left, top, 0,
            working_bgra_.Get(), 0, &region);
        D3D11_MAPPED_SUBRESOURCE mapped{};
        require_hresult(
            context_->Map(
                hash_staging_bgra_.Get(), 0, D3D11_MAP_READ, 0, &mapped),
            "map committed BGRA rectangle verification texture");
        const auto* committed = static_cast<const std::byte*>(mapped.pData);
        for (const auto& rectangle : rectangles) {
            for (std::uint32_t row = 0; row < rectangle.height; ++row) {
                const auto* actual = committed +
                    static_cast<std::size_t>(rectangle.y + row) *
                        mapped.RowPitch +
                    static_cast<std::size_t>(rectangle.x) * 4U;
                const auto* expected = rectangle.bgra.data() +
                    static_cast<std::size_t>(row) * rectangle.row_stride;
                for (std::size_t column = 0;
                     column < rectangle.row_stride; ++column) {
                    const auto actual_value =
                        std::to_integer<unsigned>(actual[column]);
                    const auto expected_value =
                        std::to_integer<unsigned>(expected[column]);
                    const auto difference = actual_value > expected_value
                        ? actual_value - expected_value
                        : expected_value - actual_value;
                    result.mismatched_bytes += difference != 0 ? 1U : 0U;
                    result.absolute_error_sum += difference;
                    result.squared_error_sum += difference * difference;
                }
                result.verified_bytes += rectangle.row_stride;
            }
        }
        context_->Unmap(hash_staging_bgra_.Get(), 0);
        result.duration_us = steady_timestamp_us() - started_at_us;
        return result;
    }

private:
    void validate_rect(
        const std::uint32_t x, const std::uint32_t y,
        const std::uint32_t width, const std::uint32_t height) const {
        if (!framebuffer_initialized_ || width == 0 || height == 0 ||
            x > surface_width_ || y > surface_height_ ||
            width > surface_width_ - x || height > surface_height_ - y) {
            throw std::invalid_argument(
                "rectangle exceeds persistent framebuffer bounds");
        }
    }

    void ensure_device(const HWND window) {
        if (device_ != nullptr) return;
        D3D_FEATURE_LEVEL feature_level{};
        require_hresult(
            D3D11CreateDevice(
                nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
                D3D11_CREATE_DEVICE_BGRA_SUPPORT |
                    D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
                nullptr, 0, D3D11_SDK_VERSION,
                &device_, &feature_level, &context_),
            "create Direct3D video device");
        ComPtr<ID3D10Multithread> multithread;
        if (SUCCEEDED(device_.As(&multithread))) {
            multithread->SetMultithreadProtected(TRUE);
        }
        require_hresult(device_.As(&video_device_), "query Direct3D video device");
        require_hresult(context_.As(&video_context_), "query Direct3D video context");
        ComPtr<IDXGIDevice> dxgi_device;
        require_hresult(device_.As(&dxgi_device), "query DXGI device");
        ComPtr<IDXGIAdapter> adapter;
        require_hresult(dxgi_device->GetAdapter(&adapter), "read DXGI adapter");
        ComPtr<IDXGIFactory2> factory;
        require_hresult(adapter->GetParent(IID_PPV_ARGS(&factory)), "read DXGI factory");
        ComPtr<IDXGIFactory5> factory5;
        BOOL tearing_supported{};
        if (SUCCEEDED(factory.As(&factory5))) {
            static_cast<void>(factory5->CheckFeatureSupport(
                DXGI_FEATURE_PRESENT_ALLOW_TEARING,
                &tearing_supported, sizeof(tearing_supported)));
        }
        if (present_mode_.load(std::memory_order_relaxed) ==
                D3D11PresentMode::extreme &&
            tearing_supported == FALSE) {
            throw std::runtime_error(
                "Direct3D extreme present requires tearing support");
        }
        DXGI_SWAP_CHAIN_DESC1 description{};
        description.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
        description.SampleDesc.Count = 1;
        description.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        description.BufferCount = 2;
        description.Scaling = DXGI_SCALING_STRETCH;
        description.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
        description.AlphaMode = DXGI_ALPHA_MODE_IGNORE;
        description.Flags = DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT;
        if (present_mode_.load(std::memory_order_relaxed) ==
            D3D11PresentMode::extreme) {
            description.Flags |= DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING;
        }
        swap_chain_flags_ = description.Flags;
        require_hresult(
            factory->CreateSwapChainForHwnd(
                device_.Get(), window, &description, nullptr, nullptr,
                &swap_chain_),
            "create Direct3D swap chain");
        factory->MakeWindowAssociation(window, DXGI_MWA_NO_ALT_ENTER);
        ComPtr<IDXGISwapChain2> swap_chain2;
        require_hresult(
            swap_chain_.As(&swap_chain2),
            "query Direct3D frame-latency swap chain");
        require_hresult(
            swap_chain2->SetMaximumFrameLatency(1),
            "set Direct3D maximum frame latency");
        frame_latency_waitable_ =
            swap_chain2->GetFrameLatencyWaitableObject();
        if (frame_latency_waitable_ == nullptr) {
            throw std::runtime_error(
                "Direct3D frame-latency waitable object is unavailable");
        }
    }

    void ensure_swap_chain(
        const std::uint32_t width, const std::uint32_t height) {
        if (output_width_ == width && output_height_ == height) return;
        context_->ClearState();
        require_hresult(
            swap_chain_->ResizeBuffers(
                0, width, height, DXGI_FORMAT_UNKNOWN, swap_chain_flags_),
            "resize Direct3D swap chain");
        output_width_ = width;
        output_height_ = height;
        enumerator_.Reset();
        processor_.Reset();
    }

    void ensure_processor(
        const std::uint32_t input_width, const std::uint32_t input_height,
        const std::uint32_t output_width, const std::uint32_t output_height) {
        if (enumerator_ != nullptr && input_width_ == input_width &&
            input_height_ == input_height) {
            return;
        }
        input_texture_.Reset();
        enumerator_.Reset();
        processor_.Reset();
        D3D11_TEXTURE2D_DESC texture{};
        texture.Width = input_width;
        texture.Height = input_height;
        texture.MipLevels = 1;
        texture.ArraySize = 1;
        texture.Format = DXGI_FORMAT_NV12;
        texture.SampleDesc.Count = 1;
        texture.Usage = D3D11_USAGE_DEFAULT;
        texture.BindFlags = D3D11_BIND_DECODER;
        require_hresult(
            device_->CreateTexture2D(&texture, nullptr, &input_texture_),
            "create Direct3D NV12 texture");
        D3D11_VIDEO_PROCESSOR_CONTENT_DESC content{};
        content.InputFrameFormat = D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE;
        content.InputFrameRate = {60, 1};
        content.InputWidth = input_width;
        content.InputHeight = input_height;
        content.OutputFrameRate = {60, 1};
        content.OutputWidth = output_width;
        content.OutputHeight = output_height;
        content.Usage = D3D11_VIDEO_USAGE_PLAYBACK_NORMAL;
        require_hresult(
            video_device_->CreateVideoProcessorEnumerator(
                &content, &enumerator_),
            "create Direct3D video processor enumerator");
        require_hresult(
            video_device_->CreateVideoProcessor(
                enumerator_.Get(), 0, &processor_),
            "create Direct3D video processor");
        input_width_ = input_width;
        input_height_ = input_height;
    }

    void ensure_persistent_pipeline(
        const std::uint32_t surface_width,
        const std::uint32_t surface_height,
        const std::uint32_t output_width,
        const std::uint32_t output_height) {
        const auto surface_changed =
            surface_width_ != surface_width || surface_height_ != surface_height;
        if (surface_changed) {
            framebuffer_initialized_ = false;
            framebuffer_update_active_ = false;
            snapshot_update_active_ = false;
            snapshot_received_bytes_ = 0;
            snapshot_total_bytes_ = 0;
            persistent_input_texture_.Reset();
            working_bgra_.Reset();
            committed_bgra_.Reset();
            scratch_bgra_.Reset();
            hash_staging_bgra_.Reset();
            converter_enumerator_.Reset();
            converter_.Reset();
            presenter_enumerator_.Reset();
            presenter_.Reset();

            D3D11_TEXTURE2D_DESC input{};
            input.Width = surface_width;
            input.Height = surface_height;
            input.MipLevels = 1;
            input.ArraySize = 1;
            input.Format = DXGI_FORMAT_NV12;
            input.SampleDesc.Count = 1;
            input.Usage = D3D11_USAGE_DEFAULT;
            input.BindFlags = D3D11_BIND_DECODER;
            require_hresult(
                device_->CreateTexture2D(
                    &input, nullptr, &persistent_input_texture_),
                "create persistent NV12 input texture");

            D3D11_TEXTURE2D_DESC bgra{};
            bgra.Width = surface_width;
            bgra.Height = surface_height;
            bgra.MipLevels = 1;
            bgra.ArraySize = 1;
            bgra.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
            bgra.SampleDesc.Count = 1;
            bgra.Usage = D3D11_USAGE_DEFAULT;
            bgra.BindFlags = D3D11_BIND_RENDER_TARGET |
                             D3D11_BIND_SHADER_RESOURCE;
            require_hresult(
                device_->CreateTexture2D(&bgra, nullptr, &working_bgra_),
                "create persistent working framebuffer");
            require_hresult(
                device_->CreateTexture2D(&bgra, nullptr, &committed_bgra_),
                "create persistent committed framebuffer");
            require_hresult(
                device_->CreateTexture2D(&bgra, nullptr, &scratch_bgra_),
                "create persistent copy-rect scratch texture");
            auto staging = bgra;
            staging.Usage = D3D11_USAGE_STAGING;
            staging.BindFlags = 0;
            staging.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
            require_hresult(
                device_->CreateTexture2D(
                    &staging, nullptr, &hash_staging_bgra_),
                "create committed framebuffer hash staging texture");

            D3D11_VIDEO_PROCESSOR_CONTENT_DESC conversion{};
            conversion.InputFrameFormat = D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE;
            conversion.InputFrameRate = {60, 1};
            conversion.InputWidth = surface_width;
            conversion.InputHeight = surface_height;
            conversion.OutputFrameRate = {60, 1};
            conversion.OutputWidth = surface_width;
            conversion.OutputHeight = surface_height;
            conversion.Usage = D3D11_VIDEO_USAGE_PLAYBACK_NORMAL;
            require_hresult(
                video_device_->CreateVideoProcessorEnumerator(
                    &conversion, &converter_enumerator_),
                "create persistent NV12 converter enumerator");
            require_hresult(
                video_device_->CreateVideoProcessor(
                    converter_enumerator_.Get(), 0, &converter_),
                "create persistent NV12 converter");
            surface_width_ = surface_width;
            surface_height_ = surface_height;
        }

        if (presenter_enumerator_ == nullptr ||
            persistent_output_width_ != output_width ||
            persistent_output_height_ != output_height) {
            presenter_enumerator_.Reset();
            presenter_.Reset();
            D3D11_VIDEO_PROCESSOR_CONTENT_DESC presentation{};
            presentation.InputFrameFormat = D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE;
            presentation.InputFrameRate = {60, 1};
            presentation.InputWidth = surface_width;
            presentation.InputHeight = surface_height;
            presentation.OutputFrameRate = {60, 1};
            presentation.OutputWidth = output_width;
            presentation.OutputHeight = output_height;
            presentation.Usage = D3D11_VIDEO_USAGE_PLAYBACK_NORMAL;
            require_hresult(
                video_device_->CreateVideoProcessorEnumerator(
                    &presentation, &presenter_enumerator_),
                "create persistent framebuffer presenter enumerator");
            require_hresult(
                video_device_->CreateVideoProcessor(
                    presenter_enumerator_.Get(), 0, &presenter_),
                "create persistent framebuffer presenter");
            persistent_output_width_ = output_width;
            persistent_output_height_ = output_height;
        }
    }

    void set_nv12_color_space(
        ID3D11VideoProcessor* processor,
        const platform::windows::WindowsNv12Frame& frame) {
        // RWV2 Mac video is BT.709. Honor explicit MF range/matrix metadata;
        // absent metadata falls back to this stream's limited-range 709 contract.
        D3D11_VIDEO_PROCESSOR_COLOR_SPACE input{};
        input.YCbCr_Matrix = frame.yuv_matrix == 2 ? 0U : 1U;
        input.Nominal_Range = frame.nominal_range == 1
            ? D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_0_255
            : D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_16_235;
        D3D11_VIDEO_PROCESSOR_COLOR_SPACE output{};
        output.Nominal_Range = D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_0_255;
        video_context_->VideoProcessorSetStreamColorSpace(processor, 0, &input);
        video_context_->VideoProcessorSetOutputColorSpace(processor, &output);
    }

    void blit_texture(
        ID3D11Texture2D* input_texture,
        ID3D11VideoProcessorEnumerator* enumerator,
        ID3D11VideoProcessor* processor,
        ID3D11Texture2D* output_texture,
        const RECT source,
        const RECT destination,
        const char* operation,
        const std::uint32_t input_array_slice = 0) {
        D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC input_description{};
        input_description.ViewDimension = D3D11_VPIV_DIMENSION_TEXTURE2D;
        input_description.Texture2D.ArraySlice = input_array_slice;
        ComPtr<ID3D11VideoProcessorInputView> input_view;
        require_hresult(
            video_device_->CreateVideoProcessorInputView(
                input_texture, enumerator, &input_description, &input_view),
            "create persistent framebuffer input view");
        D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC output_description{};
        output_description.ViewDimension = D3D11_VPOV_DIMENSION_TEXTURE2D;
        ComPtr<ID3D11VideoProcessorOutputView> output_view;
        require_hresult(
            video_device_->CreateVideoProcessorOutputView(
                output_texture, enumerator, &output_description, &output_view),
            "create persistent framebuffer output view");
        const D3D11_VIDEO_COLOR black{};
        video_context_->VideoProcessorSetOutputBackgroundColor(
            processor, FALSE, &black);
        video_context_->VideoProcessorSetOutputTargetRect(
            processor, TRUE, &destination);
        video_context_->VideoProcessorSetStreamSourceRect(
            processor, 0, TRUE, &source);
        video_context_->VideoProcessorSetStreamDestRect(
            processor, 0, TRUE, &destination);
        D3D11_VIDEO_PROCESSOR_STREAM stream{};
        stream.Enable = TRUE;
        stream.pInputSurface = input_view.Get();
        require_hresult(
            video_context_->VideoProcessorBlt(
                processor, output_view.Get(), 0, 1, &stream),
            operation);
    }

    std::uint64_t present_committed(
        const std::uint32_t output_width,
        const std::uint32_t output_height) {
        wait_for_present_capacity();
        ComPtr<ID3D11Texture2D> back_buffer;
        require_hresult(
            swap_chain_->GetBuffer(0, IID_PPV_ARGS(&back_buffer)),
            "read persistent compositor back buffer");
        const RECT source{
            0, 0, static_cast<LONG>(surface_width_),
            static_cast<LONG>(surface_height_)};
        const auto scale = scale_mode_.load(std::memory_order_relaxed) ==
                    D3D11ScaleMode::one_to_one &&
                output_width >= surface_width_ && output_height >= surface_height_
            ? 1.0
            : std::min(
                static_cast<double>(output_width) / surface_width_,
                static_cast<double>(output_height) / surface_height_);
        const auto width = static_cast<LONG>(surface_width_ * scale);
        const auto height = static_cast<LONG>(surface_height_ * scale);
        const RECT destination{
            (static_cast<LONG>(output_width) - width) / 2,
            (static_cast<LONG>(output_height) - height) / 2,
            (static_cast<LONG>(output_width) + width) / 2,
            (static_cast<LONG>(output_height) + height) / 2};
        blit_texture(
            committed_bgra_.Get(), presenter_enumerator_.Get(),
            presenter_.Get(), back_buffer.Get(), source, destination,
            "present persistent BGRA framebuffer");
        const auto presented = swap_chain_->Present(
            0, present_mode_.load(std::memory_order_relaxed) ==
                       D3D11PresentMode::extreme
                   ? DXGI_PRESENT_ALLOW_TEARING : 0U);
        if (presented != DXGI_STATUS_OCCLUDED) {
            require_hresult(presented, "present persistent framebuffer");
        }
        return steady_timestamp_us();
    }

    void wait_for_present_capacity() const {
        if (frame_latency_waitable_ == nullptr) return;
        const auto wait = WaitForSingleObjectEx(
            frame_latency_waitable_, 100, FALSE);
        if (wait != WAIT_OBJECT_0 && wait != WAIT_TIMEOUT) {
            throw std::runtime_error(
                "wait for Direct3D present capacity failed");
        }
    }

    ComPtr<ID3D11Device> device_;
    ComPtr<ID3D11DeviceContext> context_;
    ComPtr<ID3D11VideoDevice> video_device_;
    ComPtr<ID3D11VideoContext> video_context_;
    ComPtr<IDXGISwapChain1> swap_chain_;
    ComPtr<ID3D11Texture2D> input_texture_;
    ComPtr<ID3D11VideoProcessorEnumerator> enumerator_;
    ComPtr<ID3D11VideoProcessor> processor_;
    ComPtr<ID3D11Texture2D> persistent_input_texture_;
    ComPtr<ID3D11Texture2D> working_bgra_;
    ComPtr<ID3D11Texture2D> committed_bgra_;
    ComPtr<ID3D11Texture2D> scratch_bgra_;
    ComPtr<ID3D11Texture2D> hash_staging_bgra_;
    ComPtr<ID3D11VideoProcessorEnumerator> converter_enumerator_;
    ComPtr<ID3D11VideoProcessor> converter_;
    ComPtr<ID3D11VideoProcessorEnumerator> presenter_enumerator_;
    ComPtr<ID3D11VideoProcessor> presenter_;
    std::uint32_t input_width_{};
    std::uint32_t input_height_{};
    std::uint32_t output_width_{};
    std::uint32_t output_height_{};
    std::uint32_t surface_width_{};
    std::uint32_t surface_height_{};
    std::uint32_t persistent_output_width_{};
    std::uint32_t persistent_output_height_{};
    bool framebuffer_initialized_{};
    bool framebuffer_update_active_{};
    bool snapshot_update_active_{};
    std::size_t snapshot_received_bytes_{};
    std::size_t snapshot_total_bytes_{};
    std::atomic<D3D11ScaleMode> scale_mode_{D3D11ScaleMode::fit};
    std::atomic<D3D11PresentMode> present_mode_{D3D11PresentMode::balanced};
    HANDLE frame_latency_waitable_{};
    UINT swap_chain_flags_{};
};

D3D11Nv12Renderer::D3D11Nv12Renderer()
    : impl_(std::make_unique<Impl>()) {}
D3D11Nv12Renderer::~D3D11Nv12Renderer() = default;

void D3D11Nv12Renderer::set_scale_mode(
    const D3D11ScaleMode mode) noexcept {
    impl_->set_scale_mode(mode);
}

D3D11ScaleMode D3D11Nv12Renderer::scale_mode() const noexcept {
    return impl_->scale_mode();
}
void D3D11Nv12Renderer::set_present_mode(
    const D3D11PresentMode mode) {
    impl_->set_present_mode(mode);
}
D3D11PresentMode D3D11Nv12Renderer::present_mode() const noexcept {
    return impl_->present_mode();
}
void D3D11Nv12Renderer::initialize(const HWND window) {
    impl_->initialize(window);
}
ID3D11Device* D3D11Nv12Renderer::native_device() const noexcept {
    return impl_->native_device();
}
void D3D11Nv12Renderer::render(
    const HWND window,
    const platform::windows::WindowsNv12Frame& frame) {
    impl_->render(window, frame);
}
D3D11RenderReceipt D3D11Nv12Renderer::render_persistent(
    const HWND window,
    const platform::windows::WindowsNv12Frame& frame) {
    return impl_->render_persistent(window, frame);
}
void D3D11Nv12Renderer::begin_framebuffer_update() {
    impl_->begin_framebuffer_update();
}
void D3D11Nv12Renderer::patch_bgra(
    const std::uint32_t x, const std::uint32_t y,
    const std::uint32_t width, const std::uint32_t height,
    const std::uint32_t row_stride,
    const std::span<const std::byte> bgra) {
    impl_->patch_bgra(x, y, width, height, row_stride, bgra);
}
void D3D11Nv12Renderer::copy_rect(
    const std::uint32_t source_x, const std::uint32_t source_y,
    const std::uint32_t destination_x, const std::uint32_t destination_y,
    const std::uint32_t width, const std::uint32_t height) {
    impl_->copy_rect(
        source_x, source_y, destination_x, destination_y, width, height);
}
D3D11RenderReceipt D3D11Nv12Renderer::commit_framebuffer(
    const HWND window, const std::uint64_t frame_id) {
    return impl_->commit_framebuffer(window, frame_id);
}
void D3D11Nv12Renderer::cancel_framebuffer_update() noexcept {
    impl_->cancel_framebuffer_update();
}
void D3D11Nv12Renderer::begin_full_snapshot(
    const std::uint32_t width, const std::uint32_t height) {
    impl_->begin_full_snapshot(width, height);
}
void D3D11Nv12Renderer::write_full_snapshot_chunk(
    const std::uint32_t chunk_offset,
    const std::span<const std::byte> bgra) {
    impl_->write_full_snapshot_chunk(chunk_offset, bgra);
}
D3D11RenderReceipt D3D11Nv12Renderer::commit_full_snapshot(
    const HWND window, const std::uint64_t frame_id) {
    return impl_->commit_full_snapshot(window, frame_id);
}
void D3D11Nv12Renderer::cancel_full_snapshot() noexcept {
    impl_->cancel_full_snapshot();
}
std::array<std::byte, 32>
D3D11Nv12Renderer::committed_framebuffer_sha256() {
    return impl_->committed_framebuffer_sha256();
}
std::vector<std::byte> D3D11Nv12Renderer::committed_framebuffer_bgra() {
    return impl_->committed_framebuffer_bgra();
}
D3D11PixelVerificationReceipt D3D11Nv12Renderer::verify_working_bgra(
    const std::span<const desktop::VisualRawRect> rectangles) {
    return impl_->verify_working_bgra(rectangles);
}

}  // namespace rwn::viewer
