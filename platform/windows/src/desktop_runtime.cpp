#include "rwn/platform/windows/desktop_runtime.hpp"

#include <Windows.h>
#include <codecapi.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <mfapi.h>
#include <mferror.h>
#include <mfidl.h>
#include <mftransform.h>
#include <wmcodecdsp.h>
#include <wrl/client.h>

#include <algorithm>
#include <deque>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace rwn::platform::windows {
namespace {

using Microsoft::WRL::ComPtr;

void require_hresult(const HRESULT result, const char* operation) {
    if (FAILED(result)) {
        throw std::runtime_error(
            std::string(operation) + " failed with HRESULT " +
            std::to_string(static_cast<unsigned long>(result)));
    }
}

std::wstring utf8_to_utf16(const std::string_view text) {
    if (!desktop::valid_utf8(text)) {
        throw std::invalid_argument("text is not valid UTF-8");
    }
    if (text.empty()) {
        return {};
    }
    if (text.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::length_error("UTF-8 text exceeds Windows conversion limit");
    }
    const auto source_size = static_cast<int>(text.size());
    const auto size = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), source_size, nullptr, 0);
    if (size <= 0) {
        throw std::runtime_error("UTF-8 to UTF-16 conversion failed");
    }
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    if (MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), source_size,
            result.data(), size) != size) {
        throw std::runtime_error("UTF-8 to UTF-16 conversion failed");
    }
    return result;
}

std::string utf16_to_utf8(const std::wstring_view text) {
    if (text.empty()) {
        return {};
    }
    if (text.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::length_error("UTF-16 text exceeds Windows conversion limit");
    }
    const auto source_size = static_cast<int>(text.size());
    const auto size = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), source_size,
        nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        throw std::runtime_error("UTF-16 to UTF-8 conversion failed");
    }
    std::string result(static_cast<std::size_t>(size), '\0');
    if (WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), source_size,
            result.data(), size, nullptr, nullptr) != size) {
        throw std::runtime_error("UTF-16 to UTF-8 conversion failed");
    }
    return result;
}

WORD hid_usage_to_virtual_key(const std::uint32_t usage) {
    if (usage >= 0x04U && usage <= 0x1dU) {
        return static_cast<WORD>('A' + (usage - 0x04U));
    }
    if (usage >= 0x1eU && usage <= 0x26U) {
        return static_cast<WORD>('1' + (usage - 0x1eU));
    }
    if (usage == 0x27U) return '0';
    switch (usage) {
        case 0x28U: return VK_RETURN;
        case 0x29U: return VK_ESCAPE;
        case 0x2aU: return VK_BACK;
        case 0x2bU: return VK_TAB;
        case 0x2cU: return VK_SPACE;
        case 0x4fU: return VK_RIGHT;
        case 0x50U: return VK_LEFT;
        case 0x51U: return VK_DOWN;
        case 0x52U: return VK_UP;
        case 0xe0U: return VK_LCONTROL;
        case 0xe1U: return VK_LSHIFT;
        case 0xe2U: return VK_LMENU;
        case 0xe3U: return VK_LWIN;
        case 0xe4U: return VK_RCONTROL;
        case 0xe5U: return VK_RSHIFT;
        case 0xe6U: return VK_RMENU;
        case 0xe7U: return VK_RWIN;
        default: throw std::invalid_argument("unsupported HID keyboard usage");
    }
}

void send_input_or_throw(INPUT& input) {
    if (SendInput(1, &input, sizeof(input)) != 1) {
        throw std::runtime_error("SendInput failed");
    }
}

bool has_hardware_transform(const GUID& category) {
    IMFActivate** activations{};
    UINT32 count{};
    const auto result = MFTEnumEx(
        category, MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER,
        nullptr, nullptr, &activations, &count);
    if (FAILED(result)) {
        return false;
    }
    for (UINT32 index = 0; index < count; ++index) {
        activations[index]->Release();
    }
    CoTaskMemFree(activations);
    return count != 0;
}

}  // namespace

std::optional<std::uint32_t> map_windows_raw_keyboard_to_hid_usage(
    const std::uint16_t make_code,
    const std::uint16_t flags,
    const std::uint16_t virtual_key) noexcept {
    const auto extended = (flags & RI_KEY_E0) != 0;
    if (virtual_key == 0 || virtual_key == 0xffU) return std::nullopt;
    if (virtual_key >= 'A' && virtual_key <= 'Z') {
        return 0x04U + virtual_key - 'A';
    }
    if (virtual_key >= '1' && virtual_key <= '9') {
        return 0x1eU + virtual_key - '1';
    }
    if (virtual_key >= VK_F1 && virtual_key <= VK_F12) {
        return 0x3aU + virtual_key - VK_F1;
    }
    if (virtual_key >= VK_F13 && virtual_key <= VK_F20) {
        return 0x68U + virtual_key - VK_F13;
    }
    if (!extended) {
        switch (make_code) {
            case 0x52: return 0x62U;  // Keypad 0
            case 0x4f: return 0x59U;  // Keypad 1
            case 0x50: return 0x5aU;  // Keypad 2
            case 0x51: return 0x5bU;  // Keypad 3
            case 0x4b: return 0x5cU;  // Keypad 4
            case 0x4c: return 0x5dU;  // Keypad 5
            case 0x4d: return 0x5eU;  // Keypad 6
            case 0x47: return 0x5fU;  // Keypad 7
            case 0x48: return 0x60U;  // Keypad 8
            case 0x49: return 0x61U;  // Keypad 9
            case 0x53: return 0x63U;  // Keypad decimal
            case 0x37: return 0x55U;  // Keypad multiply
            case 0x4a: return 0x56U;  // Keypad subtract
            case 0x4e: return 0x57U;  // Keypad add
            default: break;
        }
    }
    switch (virtual_key) {
        case '0': return 0x27U;
        case VK_RETURN: return extended ? 0x58U : 0x28U;
        case VK_ESCAPE: return 0x29U;
        case VK_BACK: return 0x2aU;
        case VK_TAB: return 0x2bU;
        case VK_SPACE: return 0x2cU;
        case VK_OEM_MINUS: return 0x2dU;
        case VK_OEM_PLUS: return 0x2eU;
        case VK_OEM_4: return 0x2fU;
        case VK_OEM_6: return 0x30U;
        case VK_OEM_5: return 0x31U;
        case VK_OEM_1: return 0x33U;
        case VK_OEM_7: return 0x34U;
        case VK_OEM_3: return 0x35U;
        case VK_OEM_COMMA: return 0x36U;
        case VK_OEM_PERIOD: return 0x37U;
        case VK_OEM_2: return 0x38U;
        case VK_CAPITAL: return 0x39U;
        case VK_SNAPSHOT: return 0x46U;
        case VK_SCROLL: return 0x47U;
        case VK_PAUSE: return 0x48U;
        case VK_INSERT: return 0x49U;
        case VK_HOME: return 0x4aU;
        case VK_PRIOR: return 0x4bU;
        case VK_DELETE: return 0x4cU;
        case VK_END: return 0x4dU;
        case VK_NEXT: return 0x4eU;
        case VK_RIGHT: return 0x4fU;
        case VK_LEFT: return 0x50U;
        case VK_DOWN: return 0x51U;
        case VK_UP: return 0x52U;
        case VK_NUMLOCK: return 0x53U;
        case VK_DIVIDE: return 0x54U;
        case VK_MULTIPLY: return 0x55U;
        case VK_SUBTRACT: return 0x56U;
        case VK_ADD: return 0x57U;
        case VK_NUMPAD1: return 0x59U;
        case VK_NUMPAD2: return 0x5aU;
        case VK_NUMPAD3: return 0x5bU;
        case VK_NUMPAD4: return 0x5cU;
        case VK_NUMPAD5: return 0x5dU;
        case VK_NUMPAD6: return 0x5eU;
        case VK_NUMPAD7: return 0x5fU;
        case VK_NUMPAD8: return 0x60U;
        case VK_NUMPAD9: return 0x61U;
        case VK_NUMPAD0: return 0x62U;
        case VK_DECIMAL: return 0x63U;
        case VK_OEM_102: return 0x64U;
        case VK_APPS: return 0x65U;
        case VK_VOLUME_MUTE: return 0x7fU;
        case VK_VOLUME_UP: return 0x80U;
        case VK_VOLUME_DOWN: return 0x81U;
        case VK_SHIFT: return make_code == 0x36U ? 0xe5U : 0xe1U;
        case VK_CONTROL: return extended ? 0xe4U : 0xe0U;
        case VK_MENU: return extended ? 0xe6U : 0xe2U;
        case VK_LCONTROL: return 0xe0U;
        case VK_LSHIFT: return 0xe1U;
        case VK_LMENU: return 0xe2U;
        case VK_LWIN: return 0xe3U;
        case VK_RCONTROL: return 0xe4U;
        case VK_RSHIFT: return 0xe5U;
        case VK_RMENU: return 0xe6U;
        case VK_RWIN: return 0xe7U;
        default: return std::nullopt;
    }
}

std::vector<std::byte> repack_padded_nv12(
    const std::span<const std::byte> source,
    const std::uint32_t width,
    const std::uint32_t height,
    const std::uint32_t source_stride,
    const std::uint32_t source_luma_rows) {
    if (width == 0 || height == 0 || (width & 1U) != 0 ||
        (height & 1U) != 0 || source_stride < width ||
        source_luma_rows < height || source_luma_rows > height + 64U) {
        throw std::invalid_argument("invalid padded NV12 layout");
    }
    const auto y_bytes = static_cast<std::size_t>(source_stride) *
        source_luma_rows;
    const auto uv_bytes = static_cast<std::size_t>(source_stride) *
        (height / 2U);
    if (y_bytes > source.size() || uv_bytes > source.size() - y_bytes) {
        throw std::invalid_argument("padded NV12 source is undersized");
    }
    std::vector<std::byte> packed(
        static_cast<std::size_t>(width) * height * 3U / 2U);
    for (std::uint32_t row = 0; row < height; ++row) {
        std::copy_n(
            source.data() + static_cast<std::size_t>(row) * source_stride,
            width,
            packed.data() + static_cast<std::size_t>(row) * width);
    }
    const auto packed_uv = static_cast<std::size_t>(width) * height;
    for (std::uint32_t row = 0; row < height / 2U; ++row) {
        std::copy_n(
            source.data() + y_bytes +
                static_cast<std::size_t>(row) * source_stride,
            width,
            packed.data() + packed_uv +
                static_cast<std::size_t>(row) * width);
    }
    return packed;
}

class WindowsDesktopCaptureBackend::Impl {
public:
    Impl() {
        D3D_FEATURE_LEVEL feature_level{};
        require_hresult(
            D3D11CreateDevice(
                nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
                D3D11_CREATE_DEVICE_BGRA_SUPPORT, nullptr, 0,
                D3D11_SDK_VERSION, &device_, &feature_level, &context_),
            "D3D11CreateDevice");
        ComPtr<IDXGIDevice> dxgi_device;
        require_hresult(device_.As(&dxgi_device), "query IDXGIDevice");
        ComPtr<IDXGIAdapter> adapter;
        require_hresult(dxgi_device->GetAdapter(&adapter), "get DXGI adapter");
        ComPtr<IDXGIOutput> output;
        require_hresult(adapter->EnumOutputs(0, &output), "enumerate primary output");
        ComPtr<IDXGIOutput1> output1;
        require_hresult(output.As(&output1), "query IDXGIOutput1");
        require_hresult(
            output1->DuplicateOutput(device_.Get(), &duplication_),
            "duplicate desktop output");
    }

    std::optional<desktop::RawFrame> capture(
        const std::chrono::milliseconds timeout) {
        if (timeout < std::chrono::milliseconds::zero() ||
            timeout.count() > std::numeric_limits<DWORD>::max()) {
            throw std::invalid_argument("capture timeout exceeds Windows limit");
        }
        DXGI_OUTDUPL_FRAME_INFO frame_info{};
        ComPtr<IDXGIResource> resource;
        const auto acquired = duplication_->AcquireNextFrame(
            static_cast<UINT>(timeout.count()), &frame_info, &resource);
        if (acquired == DXGI_ERROR_WAIT_TIMEOUT) {
            return std::nullopt;
        }
        require_hresult(acquired, "acquire duplicated frame");
        try {
            ComPtr<ID3D11Texture2D> texture;
            require_hresult(resource.As(&texture), "query captured texture");
            D3D11_TEXTURE2D_DESC description{};
            texture->GetDesc(&description);
            if (description.Width == 0 || description.Height == 0 ||
                description.Width > 7680 || description.Height > 4320) {
                throw std::runtime_error("captured desktop dimensions exceed limit");
            }
            if (!staging_ || width_ != description.Width || height_ != description.Height) {
                description.Usage = D3D11_USAGE_STAGING;
                description.BindFlags = 0;
                description.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
                description.MiscFlags = 0;
                require_hresult(
                    device_->CreateTexture2D(&description, nullptr, &staging_),
                    "create capture staging texture");
                width_ = description.Width;
                height_ = description.Height;
            }
            context_->CopyResource(staging_.Get(), texture.Get());
            D3D11_MAPPED_SUBRESOURCE mapped{};
            require_hresult(
                context_->Map(staging_.Get(), 0, D3D11_MAP_READ, 0, &mapped),
                "map capture staging texture");
            const auto row_size = static_cast<std::size_t>(width_) * 4U;
            desktop::RawFrame frame{
                .frame_id = ++frame_id_,
                .captured_at_us = timestamp_us(),
                .width = width_,
                .height = height_,
                .row_stride = static_cast<std::uint32_t>(row_size),
                .bgra = std::vector<std::byte>(
                    row_size * static_cast<std::size_t>(height_)),
            };
            for (std::uint32_t row = 0; row < height_; ++row) {
                const auto* source = static_cast<const std::byte*>(mapped.pData) +
                                     static_cast<std::size_t>(mapped.RowPitch) * row;
                auto* destination = frame.bgra.data() + row_size * row;
                std::copy_n(source, row_size, destination);
            }
            context_->Unmap(staging_.Get(), 0);
            duplication_->ReleaseFrame();
            return frame;
        } catch (...) {
            duplication_->ReleaseFrame();
            throw;
        }
    }

private:
    static std::uint64_t timestamp_us() {
        LARGE_INTEGER counter{};
        LARGE_INTEGER frequency{};
        QueryPerformanceCounter(&counter);
        QueryPerformanceFrequency(&frequency);
        return static_cast<std::uint64_t>(
            counter.QuadPart * 1000000LL / frequency.QuadPart);
    }

    ComPtr<ID3D11Device> device_;
    ComPtr<ID3D11DeviceContext> context_;
    ComPtr<IDXGIOutputDuplication> duplication_;
    ComPtr<ID3D11Texture2D> staging_;
    std::uint32_t width_{};
    std::uint32_t height_{};
    std::uint64_t frame_id_{};
};

WindowsDesktopCaptureBackend::WindowsDesktopCaptureBackend()
    : impl_(std::make_unique<Impl>()) {}

WindowsDesktopCaptureBackend::~WindowsDesktopCaptureBackend() = default;

std::optional<desktop::RawFrame> WindowsDesktopCaptureBackend::capture(
    const std::chrono::milliseconds timeout) {
    return impl_->capture(timeout);
}

class WindowsMediaFoundationH264Decoder::Impl {
public:
    explicit Impl(ID3D11Device* device) {
        const auto com = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (com == RPC_E_CHANGED_MODE) {
            throw std::runtime_error(
                "H.264 decoder thread uses an incompatible COM apartment");
        }
        require_hresult(com, "CoInitializeEx");
        com_initialized_ = true;
        try {
            require_hresult(
                MFStartup(MF_VERSION, MFSTARTUP_LITE), "MFStartup");
            media_foundation_started_ = true;
            if (device != nullptr) {
                require_hresult(
                    MFCreateDXGIDeviceManager(
                        &dxgi_reset_token_, &dxgi_manager_),
                    "create Media Foundation DXGI device manager");
                require_hresult(
                    dxgi_manager_->ResetDevice(device, dxgi_reset_token_),
                    "bind Direct3D device to Media Foundation");
            }
            create_transform();
        } catch (...) {
            shutdown();
            throw;
        }
    }

    ~Impl() { shutdown(); }

    std::optional<WindowsNv12Frame> submit(
        const desktop::VideoFrame& frame) {
        if (frame.codec != desktop::VideoCodec::h264 ||
            frame.frame_id == 0 || frame.captured_at_us == 0 ||
            frame.width == 0 || frame.height == 0 ||
            frame.width > desktop::maximum_preview_width ||
            frame.height > desktop::maximum_preview_height ||
            frame.encoded.empty() ||
            frame.encoded.size() > desktop::maximum_encoded_frame_size) {
            throw std::invalid_argument("invalid H.264 preview frame");
        }
        if (frame.width != width_ || frame.height != height_) {
            configure(frame.width, frame.height);
        }

        ComPtr<IMFSample> input;
        ComPtr<IMFMediaBuffer> input_buffer;
        require_hresult(MFCreateSample(&input), "create H.264 input sample");
        require_hresult(
            MFCreateMemoryBuffer(
                static_cast<DWORD>(frame.encoded.size()), &input_buffer),
            "create H.264 input buffer");
        BYTE* destination{};
        DWORD capacity{};
        require_hresult(
            input_buffer->Lock(&destination, &capacity, nullptr),
            "lock H.264 input buffer");
        if (capacity < frame.encoded.size()) {
            input_buffer->Unlock();
            throw std::runtime_error("H.264 input buffer is undersized");
        }
        std::copy(
            frame.encoded.begin(), frame.encoded.end(),
            reinterpret_cast<std::byte*>(destination));
        require_hresult(input_buffer->Unlock(), "unlock H.264 input buffer");
        require_hresult(
            input_buffer->SetCurrentLength(
                static_cast<DWORD>(frame.encoded.size())),
            "set H.264 input length");
        require_hresult(input->AddBuffer(input_buffer.Get()), "add H.264 input");
        require_hresult(
            input->SetSampleTime(
                static_cast<LONGLONG>(frame.captured_at_us * 10U)),
            "set H.264 input time");
        auto input_result = decoder_->ProcessInput(0, input.Get(), 0);
        while (input_result == MF_E_NOTACCEPTING) {
            auto decoded = take_output();
            if (!decoded) {
                throw std::runtime_error(
                    "H.264 decoder rejected input without pending output");
            }
            ready_.push_back(std::move(*decoded));
            input_result = decoder_->ProcessInput(0, input.Get(), 0);
        }
        require_hresult(input_result, "decode H.264 input");
        pending_.push_back({
            .frame_id = frame.frame_id,
            .representation_epoch = frame.representation_epoch,
            .captured_at_us = frame.captured_at_us,
            .width = frame.width,
            .height = frame.height,
            .codec = frame.codec,
            .keyframe = frame.keyframe,
            .encoded = {},
        });
        if (auto decoded = take_output()) {
            ready_.push_back(std::move(*decoded));
        }
        if (ready_.empty()) return std::nullopt;
        auto ready = std::move(ready_.front());
        ready_.pop_front();
        return ready;
    }

    WindowsH264QueueDepths queue_depths() const noexcept {
        return {
            .compressed_lineage = pending_.size(),
            .decoded_ready = ready_.size(),
            .low_latency_enabled = low_latency_enabled_,
            .d3d11_output_active = d3d11_output_active_,
        };
    }

    std::optional<WindowsNv12Frame> poll_nv12() {
        if (!ready_.empty()) {
            auto frame = std::move(ready_.front());
            ready_.pop_front();
            return frame;
        }
        if (pending_.empty()) return std::nullopt;
        return take_output();
    }

    std::optional<std::uint32_t> low_latency_readback() const {
        ComPtr<ICodecAPI> api;
        if (FAILED(decoder_->QueryInterface(IID_ICodecAPI,
                reinterpret_cast<void**>(api.GetAddressOf())))) return std::nullopt;
        VARIANT value{};
        const auto status = api->GetValue(&CODECAPI_AVLowLatencyMode, &value);
        std::optional<std::uint32_t> result;
        if (SUCCEEDED(status)) {
            if (value.vt == VT_UI4) result = value.ulVal;
            else if (value.vt == VT_BOOL) result = value.boolVal != VARIANT_FALSE ? 1U : 0U;
        }
        VariantClear(&value);
        return result;
    }

    void flush_representation() {
        require_hresult(
            decoder_->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0),
            "flush H.264 representation");
        pending_.clear();
        ready_.clear();
        require_hresult(
            decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0),
            "restart H.264 representation stream");
    }

private:
    void create_transform() {
        require_hresult(
            CoCreateInstance(
                CLSID_CMSH264DecoderMFT, nullptr, CLSCTX_INPROC_SERVER,
                IID_PPV_ARGS(&decoder_)),
            "create Windows H.264 decoder");
        if (dxgi_manager_ != nullptr) {
            require_hresult(
                decoder_->ProcessMessage(
                    MFT_MESSAGE_SET_D3D_MANAGER,
                    reinterpret_cast<ULONG_PTR>(dxgi_manager_.Get())),
                "set Media Foundation Direct3D manager");
        }
        ComPtr<ICodecAPI> codec_api;
        require_hresult(
            decoder_->QueryInterface(
                IID_ICodecAPI,
                reinterpret_cast<void**>(codec_api.GetAddressOf())),
            "query Windows H.264 codec API");
        VARIANT low_latency{};
        low_latency.vt = VT_UI4;
        low_latency.ulVal = 1;
        require_hresult(
            codec_api->SetValue(&CODECAPI_AVLowLatencyMode, &low_latency),
            "enable Windows H.264 low latency");
        ComPtr<IMFAttributes> attributes;
        if (SUCCEEDED(decoder_->GetAttributes(&attributes))) {
            require_hresult(
                attributes->SetUINT32(MF_LOW_LATENCY, TRUE),
                "set Windows H.264 low-latency attribute");
        }
        low_latency_enabled_ = true;
    }

    void configure(
        const std::uint32_t width, const std::uint32_t height) {
        if (decoder_ != nullptr) {
            static_cast<void>(
                decoder_->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0));
        }
        width_ = width;
        height_ = height;
        ComPtr<IMFMediaType> input_type;
        require_hresult(MFCreateMediaType(&input_type), "create H.264 media type");
        require_hresult(
            input_type->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video),
            "set H.264 major type");
        require_hresult(
            input_type->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264),
            "set H.264 subtype");
        require_hresult(
            MFSetAttributeSize(input_type.Get(), MF_MT_FRAME_SIZE, width, height),
            "set H.264 frame size");
        require_hresult(
            input_type->SetUINT32(
                MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive),
            "set H.264 progressive mode");
        require_hresult(
            decoder_->SetInputType(0, input_type.Get(), 0),
            "set H.264 decoder input");
        select_nv12_output();
        require_hresult(
            decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0),
            "begin H.264 decoder streaming");
        require_hresult(
            decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0),
            "start H.264 decoder stream");
        pending_.clear();
        ready_.clear();
    }

    void select_nv12_output() {
        for (DWORD index = 0;; ++index) {
            ComPtr<IMFMediaType> output_type;
            const auto result =
                decoder_->GetOutputAvailableType(0, index, &output_type);
            if (result == MF_E_NO_MORE_TYPES) break;
            require_hresult(result, "enumerate H.264 output types");
            GUID subtype{};
            if (SUCCEEDED(output_type->GetGUID(MF_MT_SUBTYPE, &subtype)) &&
                subtype == MFVideoFormat_NV12 &&
                SUCCEEDED(decoder_->SetOutputType(
                    0, output_type.Get(), 0))) {
                UINT32 stride{};
                nominal_range_ = 0;
                yuv_matrix_ = 0;
                static_cast<void>(output_type->GetUINT32(MF_MT_VIDEO_NOMINAL_RANGE, &nominal_range_));
                static_cast<void>(output_type->GetUINT32(MF_MT_YUV_MATRIX, &yuv_matrix_));
                if (SUCCEEDED(output_type->GetUINT32(
                        MF_MT_DEFAULT_STRIDE, &stride)) && stride != 0) {
                    output_stride_ = stride;
                } else {
                    LONG calculated{};
                    require_hresult(
                        MFGetStrideForBitmapInfoHeader(
                            MFVideoFormat_NV12.Data1, width_, &calculated),
                        "calculate NV12 output stride");
                    if (calculated <= 0) {
                        throw std::runtime_error(
                            "Windows H.264 decoder returned invalid NV12 stride");
                    }
                    output_stride_ = static_cast<std::uint32_t>(calculated);
                }
                return;
            }
        }
        throw std::runtime_error("Windows H.264 decoder has no NV12 output");
    }

    std::optional<WindowsNv12Frame> take_output() {
        for (int attempt = 0; attempt < 3; ++attempt) {
            MFT_OUTPUT_STREAM_INFO stream_info{};
            require_hresult(
                decoder_->GetOutputStreamInfo(0, &stream_info),
                "read H.264 output requirements");
            ComPtr<IMFSample> supplied_sample;
            if ((stream_info.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES) == 0 &&
                (stream_info.dwFlags & MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES) == 0) {
                ComPtr<IMFMediaBuffer> output_buffer;
                require_hresult(
                    MFCreateSample(&supplied_sample),
                    "create H.264 output sample");
                require_hresult(
                    MFCreateMemoryBuffer(
                        std::max<DWORD>(
                            stream_info.cbSize,
                            width_ * height_ * 3U / 2U),
                        &output_buffer),
                    "create H.264 output buffer");
                require_hresult(
                    supplied_sample->AddBuffer(output_buffer.Get()),
                    "add H.264 output buffer");
            }
            MFT_OUTPUT_DATA_BUFFER output{
                .dwStreamID = 0,
                .pSample = supplied_sample.Get(),
                .dwStatus = 0,
                .pEvents = nullptr,
            };
            DWORD status{};
            const auto result = decoder_->ProcessOutput(
                0, 1, &output, &status);
            if (output.pEvents != nullptr) output.pEvents->Release();
            if (result == MF_E_TRANSFORM_STREAM_CHANGE) {
                select_nv12_output();
                continue;
            }
            if (result == MF_E_TRANSFORM_NEED_MORE_INPUT) {
                return std::nullopt;
            }
            require_hresult(result, "decode H.264 output");
            ComPtr<IMFSample> decoded;
            if (output.pSample != nullptr) {
                if (output.pSample == supplied_sample.Get()) {
                    decoded = supplied_sample;
                } else {
                    decoded.Attach(output.pSample);
                }
            }
            if (decoded == nullptr) {
                throw std::runtime_error("H.264 decoder returned no sample");
            }
            if (pending_.empty()) {
                throw std::runtime_error(
                    "H.264 decoder output has no input lineage");
            }
            auto matched = pending_.begin();
            LONGLONG output_time{};
            if (SUCCEEDED(decoded->GetSampleTime(&output_time))) {
                matched = std::ranges::find_if(
                    pending_, [&](const desktop::VideoFrame& candidate) {
                        return output_time == static_cast<LONGLONG>(
                            candidate.captured_at_us * 10U);
                    });
                if (matched == pending_.end()) {
                    throw std::runtime_error(
                        "H.264 decoder output timestamp has no input lineage");
                }
            }
            auto frame = std::move(*matched);
            pending_.erase(pending_.begin(), std::next(matched));
            return copy_nv12(frame, decoded.Get());
        }
        throw std::runtime_error("H.264 decoder output type did not stabilize");
    }

    WindowsNv12Frame copy_nv12(
        const desktop::VideoFrame& frame, IMFSample* sample) {
        ComPtr<IMFMediaBuffer> buffer;
        require_hresult(
            sample->GetBufferByIndex(0, &buffer),
            "read Media Foundation NV12 buffer");
        ComPtr<IMFDXGIBuffer> dxgi_buffer;
        if (SUCCEEDED(buffer.As(&dxgi_buffer))) {
            ComPtr<ID3D11Texture2D> texture;
            require_hresult(
                dxgi_buffer->GetResource(IID_PPV_ARGS(&texture)),
                "read Media Foundation Direct3D texture");
            UINT subresource{};
            require_hresult(
                dxgi_buffer->GetSubresourceIndex(&subresource),
                "read Media Foundation Direct3D subresource");
            D3D11_TEXTURE2D_DESC description{};
            texture->GetDesc(&description);
            if (description.Format != DXGI_FORMAT_NV12 ||
                description.Width < width_ || description.Height < height_) {
                throw std::runtime_error(
                    "Media Foundation returned an invalid NV12 texture");
            }
            d3d11_output_active_ = true;
            return WindowsNv12Frame{
                .frame_id = frame.frame_id,
                .representation_epoch = frame.representation_epoch,
                .keyframe = frame.keyframe,
                .captured_at_us = frame.captured_at_us,
                .width = width_,
                .height = height_,
                .row_stride = 0,
                .nv12 = {},
                .d3d11_texture = std::move(texture),
                .d3d11_subresource = subresource,
                .nominal_range = nominal_range_,
                .yuv_matrix = yuv_matrix_,
            };
        }
        buffer.Reset();
        require_hresult(
            sample->ConvertToContiguousBuffer(&buffer),
            "read contiguous NV12 frame");
        BYTE* bytes{};
        DWORD length{};
        require_hresult(
            buffer->Lock(&bytes, nullptr, &length), "lock NV12 frame");
        const auto stride = output_stride_ == 0 ? width_ : output_stride_;
        auto source_luma_rows = height_;
        const auto twice_length = static_cast<std::uint64_t>(length) * 2U;
        const auto layout_denominator =
            static_cast<std::uint64_t>(stride) * 3U;
        if (layout_denominator != 0 &&
            twice_length % layout_denominator == 0) {
            const auto candidate = twice_length / layout_denominator;
            if (candidate >= height_ && candidate <= height_ + 64U) {
                source_luma_rows = static_cast<std::uint32_t>(candidate);
            }
        }
        const auto required = static_cast<std::size_t>(stride) *
            source_luma_rows +
            static_cast<std::size_t>(stride) * (height_ / 2U);
        if (length < required) {
            buffer->Unlock();
            throw std::runtime_error("decoded NV12 frame is undersized");
        }
        std::vector<std::byte> packed;
        try {
            packed = repack_padded_nv12(
                std::span{
                    reinterpret_cast<const std::byte*>(bytes),
                    static_cast<std::size_t>(length)},
                width_, height_, stride, source_luma_rows);
        } catch (...) {
            static_cast<void>(buffer->Unlock());
            throw;
        }
        WindowsNv12Frame result{
            .frame_id = frame.frame_id,
            .representation_epoch = frame.representation_epoch,
            .keyframe = frame.keyframe,
            .captured_at_us = frame.captured_at_us,
            .width = width_,
            .height = height_,
            .row_stride = width_,
            .nv12 = std::move(packed),
            .d3d11_texture = {},
            .d3d11_subresource = 0,
            .nominal_range = nominal_range_,
            .yuv_matrix = yuv_matrix_,
        };
        require_hresult(buffer->Unlock(), "unlock NV12 frame");
        return result;
    }

    void shutdown() noexcept {
        if (decoder_ != nullptr) {
            static_cast<void>(
                decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0));
            static_cast<void>(
                decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0));
            decoder_.Reset();
        }
        if (media_foundation_started_) {
            MFShutdown();
            media_foundation_started_ = false;
        }
        if (com_initialized_) {
            CoUninitialize();
            com_initialized_ = false;
        }
    }

    ComPtr<IMFTransform> decoder_;
    ComPtr<IMFDXGIDeviceManager> dxgi_manager_;
    UINT dxgi_reset_token_{};
    std::uint32_t width_{};
    std::uint32_t height_{};
    std::uint32_t output_stride_{};
    UINT32 nominal_range_{};
    UINT32 yuv_matrix_{};
    std::deque<desktop::VideoFrame> pending_;
    std::deque<WindowsNv12Frame> ready_;
    bool com_initialized_{};
    bool media_foundation_started_{};
    bool low_latency_enabled_{};
    bool d3d11_output_active_{};
};

WindowsMediaFoundationH264Decoder::WindowsMediaFoundationH264Decoder()
    : WindowsMediaFoundationH264Decoder(nullptr) {}
WindowsMediaFoundationH264Decoder::WindowsMediaFoundationH264Decoder(
    ID3D11Device* device)
    : impl_(std::make_unique<Impl>(device)) {}
WindowsMediaFoundationH264Decoder::~WindowsMediaFoundationH264Decoder() = default;
desktop::RawFrame WindowsMediaFoundationH264Decoder::decode(
    const desktop::VideoFrame& frame) {
    auto decoded = submit(frame);
    if (!decoded) {
        throw std::runtime_error("H.264 decoder needs more input");
    }
    return std::move(*decoded);
}
std::optional<desktop::RawFrame>
WindowsMediaFoundationH264Decoder::submit(
    const desktop::VideoFrame& frame) {
    auto decoded = impl_->submit(frame);
    if (!decoded) return std::nullopt;
    desktop::RawFrame result{
        .frame_id = decoded->frame_id,
        .captured_at_us = decoded->captured_at_us,
        .width = decoded->width,
        .height = decoded->height,
        .row_stride = decoded->width * 4U,
        .bgra = std::vector<std::byte>(
            static_cast<std::size_t>(decoded->width) * decoded->height * 4U),
    };
    const auto* y_plane = reinterpret_cast<const BYTE*>(decoded->nv12.data());
    const auto* uv_plane = y_plane +
        static_cast<std::size_t>(decoded->row_stride) * decoded->height;
    const auto clamp_channel = [](const int value) {
        return static_cast<std::byte>(std::clamp(value, 0, 255));
    };
    for (std::uint32_t y = 0; y < decoded->height; ++y) {
        for (std::uint32_t x = 0; x < decoded->width; ++x) {
            const auto luma = static_cast<int>(
                y_plane[static_cast<std::size_t>(y) * decoded->row_stride + x]);
            const auto uv_offset =
                static_cast<std::size_t>(y / 2U) * decoded->row_stride +
                (x & ~1U);
            const auto u = static_cast<int>(uv_plane[uv_offset]) - 128;
            const auto v = static_cast<int>(uv_plane[uv_offset + 1U]) - 128;
            const auto c = std::max(0, luma - 16);
            const auto offset =
                (static_cast<std::size_t>(y) * decoded->width + x) * 4U;
            result.bgra[offset] =
                clamp_channel((298 * c + 516 * u + 128) >> 8);
            result.bgra[offset + 1U] =
                clamp_channel((298 * c - 100 * u - 208 * v + 128) >> 8);
            result.bgra[offset + 2U] =
                clamp_channel((298 * c + 409 * v + 128) >> 8);
            result.bgra[offset + 3U] = std::byte{0xff};
        }
    }
    return result;
}
std::optional<WindowsNv12Frame>
WindowsMediaFoundationH264Decoder::submit_nv12(
    const desktop::VideoFrame& frame) {
    return impl_->submit(frame);
}
void WindowsMediaFoundationH264Decoder::flush_representation() {
    impl_->flush_representation();
}
std::optional<WindowsNv12Frame>
WindowsMediaFoundationH264Decoder::poll_nv12() {
    return impl_->poll_nv12();
}
std::optional<std::uint32_t>
WindowsMediaFoundationH264Decoder::low_latency_readback() const {
    return impl_->low_latency_readback();
}
WindowsH264QueueDepths
WindowsMediaFoundationH264Decoder::queue_depths() const noexcept {
    return impl_->queue_depths();
}

void WindowsInputBackend::raw_key(
    const std::uint32_t hid_usage, const bool pressed) {
    INPUT input{};
    input.type = INPUT_KEYBOARD;
    input.ki.wVk = hid_usage_to_virtual_key(hid_usage);
    input.ki.dwFlags = pressed ? 0U : KEYEVENTF_KEYUP;
    send_input_or_throw(input);
}

void WindowsInputBackend::text_commit(const std::string_view utf8) {
    for (const auto code_unit : utf8_to_utf16(utf8)) {
        INPUT down{};
        down.type = INPUT_KEYBOARD;
        down.ki.wScan = code_unit;
        down.ki.dwFlags = KEYEVENTF_UNICODE;
        send_input_or_throw(down);
        INPUT up = down;
        up.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
        send_input_or_throw(up);
    }
}

void WindowsInputBackend::pointer_move(
    const std::uint16_t normalized_x, const std::uint16_t normalized_y) {
    INPUT input{};
    input.type = INPUT_MOUSE;
    input.mi.dx = normalized_x;
    input.mi.dy = normalized_y;
    input.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE |
                       MOUSEEVENTF_VIRTUALDESK;
    send_input_or_throw(input);
}

void WindowsInputBackend::pointer_button(
    const std::uint8_t button, const bool pressed) {
    DWORD down{};
    DWORD up{};
    switch (button) {
        case 1: down = MOUSEEVENTF_LEFTDOWN; up = MOUSEEVENTF_LEFTUP; break;
        case 2: down = MOUSEEVENTF_RIGHTDOWN; up = MOUSEEVENTF_RIGHTUP; break;
        case 3: down = MOUSEEVENTF_MIDDLEDOWN; up = MOUSEEVENTF_MIDDLEUP; break;
        default: throw std::invalid_argument("unsupported pointer button");
    }
    INPUT input{};
    input.type = INPUT_MOUSE;
    input.mi.dwFlags = pressed ? down : up;
    send_input_or_throw(input);
}

void WindowsInputBackend::pointer_wheel(
    const std::int32_t delta, const bool horizontal) {
    if (delta == 0) {
        throw std::invalid_argument("pointer wheel delta is zero");
    }
    INPUT input{};
    input.type = INPUT_MOUSE;
    input.mi.mouseData = static_cast<DWORD>(delta);
    input.mi.dwFlags = horizontal ? MOUSEEVENTF_HWHEEL : MOUSEEVENTF_WHEEL;
    send_input_or_throw(input);
}

std::string WindowsClipboardBackend::read_utf8_text() {
    if (!OpenClipboard(nullptr)) {
        throw std::runtime_error("OpenClipboard failed");
    }
    try {
        const auto handle = GetClipboardData(CF_UNICODETEXT);
        if (handle == nullptr) {
            CloseClipboard();
            return {};
        }
        const auto* text = static_cast<const wchar_t*>(GlobalLock(handle));
        if (text == nullptr) {
            throw std::runtime_error("GlobalLock clipboard data failed");
        }
        const std::wstring value(text);
        GlobalUnlock(handle);
        CloseClipboard();
        return utf16_to_utf8(value);
    } catch (...) {
        CloseClipboard();
        throw;
    }
}

void WindowsClipboardBackend::write_utf8_text(const std::string_view text) {
    const auto wide = utf8_to_utf16(text);
    const auto bytes = (wide.size() + 1U) * sizeof(wchar_t);
    const auto handle = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (handle == nullptr) {
        throw std::runtime_error("GlobalAlloc clipboard data failed");
    }
    auto* destination = static_cast<wchar_t*>(GlobalLock(handle));
    if (destination == nullptr) {
        GlobalFree(handle);
        throw std::runtime_error("GlobalLock clipboard data failed");
    }
    std::copy(wide.begin(), wide.end(), destination);
    destination[wide.size()] = L'\0';
    GlobalUnlock(handle);
    if (!OpenClipboard(nullptr)) {
        GlobalFree(handle);
        throw std::runtime_error("OpenClipboard failed");
    }
    if (!EmptyClipboard() || SetClipboardData(CF_UNICODETEXT, handle) == nullptr) {
        CloseClipboard();
        GlobalFree(handle);
        throw std::runtime_error("SetClipboardData failed");
    }
    CloseClipboard();
}

desktop::DesktopPermissionStatus WindowsDesktopPermissionBackend::status() const {
    return {
        .capture = desktop::PermissionState::granted,
        .input = desktop::PermissionState::granted,
    };
}

void WindowsDesktopPermissionBackend::request_capture() {}
void WindowsDesktopPermissionBackend::request_input() {}

WindowsH264Capabilities probe_h264_capabilities() {
    require_hresult(MFStartup(MF_VERSION, MFSTARTUP_LITE), "MFStartup");
    const WindowsH264Capabilities result{
        .hardware_encoder = has_hardware_transform(MFT_CATEGORY_VIDEO_ENCODER),
        .hardware_decoder = has_hardware_transform(MFT_CATEGORY_VIDEO_DECODER),
    };
    MFShutdown();
    return result;
}

}  // namespace rwn::platform::windows
