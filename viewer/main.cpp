#include "rwn/desktop/desktop.hpp"
#include "rwn/desktop/snapshot_upload.hpp"
#include "rwn/desktop/visual_trace.hpp"
#include "rwn/core/content_hash.hpp"
#include "rwn/platform/windows/desktop_runtime.hpp"
#include "d3d11_renderer.hpp"
#include "tls_preview.hpp"

#include <Windows.h>
#include <shellapi.h>
#include <windowsx.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <deque>
#include <iomanip>
#include <limits>
#include <map>
#include <mutex>
#include <memory>
#include <sstream>
#include <iostream>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

constexpr UINT status_changed_message = WM_APP + 2U;
constexpr UINT cursor_changed_message = WM_APP + 3U;
constexpr std::size_t snapshot_gpu_upload_batch_bytes = 1024U * 1024U;

std::wstring utf8_to_utf16(const std::string_view value) {
    if (value.empty()) return {};
    const auto size = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) return L"Remote preview reported an unreadable error";
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    static_cast<void>(MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
        static_cast<int>(value.size()), result.data(), size));
    return result;
}

bool safe_remote_token(const std::wstring_view value, const bool absolute_path) {
    if (value.empty() || (absolute_path && value.front() != L'/')) return false;
    return std::ranges::all_of(value, [absolute_path](const wchar_t character) {
        if ((character >= L'a' && character <= L'z') ||
            (character >= L'A' && character <= L'Z') ||
            (character >= L'0' && character <= L'9')) {
            return true;
        }
        const std::wstring_view allowed = absolute_path ? L"/_-." : L"@._:-";
        return allowed.find(character) != std::wstring_view::npos;
    });
}

std::uint32_t parse_u32(
    const std::wstring_view value, const std::uint32_t minimum,
    const std::uint32_t maximum, const char* field) {
    std::size_t consumed{};
    unsigned long parsed{};
    try {
        parsed = std::stoul(std::wstring(value), &consumed, 10);
    } catch (const std::exception&) {
        throw std::invalid_argument(std::string("invalid ") + field);
    }
    if (consumed != value.size() || parsed < minimum || parsed > maximum) {
        throw std::invalid_argument(std::string("invalid ") + field);
    }
    return static_cast<std::uint32_t>(parsed);
}

struct ViewerLaunchOptions {
    bool tls{};
    rwn::platform::windows::SchannelFallbackClientOptions tls_options;
    rwn::transport::TransportEndpoint tls_endpoint;
    std::wstring host;
    std::filesystem::path identity;
    std::wstring remote_agent;
    std::uint32_t maximum_width{1280};
    std::uint32_t maximum_height{720};
    std::uint32_t frames_per_second{5};
    std::uint32_t bitrate_kbps{20'000};
    std::wstring vt_mode{L"baseline"};
    bool visual_protocol{};
    bool dirty_analysis{};
    bool visual_trace{};
    bool interactive{};
    bool extreme_present{};
    bool lan_quality{};
    bool raw_rect_experimental{};
    bool h264_only_explicit{};
    bool snapshot_only_explicit{};
    bool exact_only{};
    bool verify_exact_pixels{};
    std::uint32_t probe_seconds{};
    rwn::viewer::D3D11ScaleMode scale_mode{
        rwn::viewer::D3D11ScaleMode::fit};
    std::filesystem::path visual_trace_path;
};

ViewerLaunchOptions parse_launch_options(
    const int argc, wchar_t** argv) {
    if (argc < 4) {
        throw std::invalid_argument("viewer requires host, key and agent");
    }
    ViewerLaunchOptions options;
    if (std::wstring_view(argv[1]) == L"--tls") {
        if (argc != 10 && argc != 12) throw std::invalid_argument("TLS viewer arguments invalid");
        using Connection = rwn::viewer::TlsPreviewConnection;
        options.tls = true;
        options.tls_endpoint = {Connection::ascii(argv[2]),
            static_cast<std::uint16_t>(parse_u32(argv[3],1,65535,"TLS port")),rwn::transport::NetworkPath::lan};
        options.tls_options.client_certificate_sha1 =
            rwn::platform::windows::parse_schannel_sha1_thumbprint(Connection::ascii(argv[4]));
        options.tls_options.allowed_server_certificate_sha256 = {
            rwn::platform::windows::parse_schannel_sha256_fingerprint(Connection::ascii(argv[5]))};
        options.tls_options.exclusive_root_der = Connection::read_der(argv[6]);
        options.tls_options.exclusive_crl_der = Connection::read_der(argv[7]);
        const std::wstring_view control = argv[8], mode = argv[9];
        if ((control != L"view-only" && control != L"interactive") ||
            (mode != L"h264-only" && mode != L"exact-only"))
            throw std::invalid_argument("invalid TLS viewer mode");
        options.interactive = control == L"interactive";
        options.exact_only = mode == L"exact-only";
        options.raw_rect_experimental = options.exact_only;
        options.h264_only_explicit = !options.exact_only;
        options.visual_protocol = options.lan_quality = true;
        options.maximum_width=1920; options.maximum_height=1080; options.frames_per_second=60;
        if (argc == 12) {
            if (std::wstring_view(argv[10]) != L"--probe-seconds") throw std::invalid_argument("invalid TLS probe flag");
            options.probe_seconds = parse_u32(argv[11],1,60,"probe seconds");
        }
        return options;
    }
    options.host = argv[1];
    options.identity = std::filesystem::path(argv[2]);
    options.remote_agent = argv[3];
    if (argc == 4 || (argc >= 7 && argv[4][0] != L'-')) {
        if (argc != 4 && argc != 7 && argc != 8 && argc != 9 && argc != 10) {
            throw std::invalid_argument("invalid legacy viewer arguments");
        }
        options.maximum_width = argc >= 7
            ? parse_u32(argv[4], 320, rwn::desktop::maximum_preview_width,
                        "preview width")
            : 1280U;
        options.maximum_height = argc >= 7
            ? parse_u32(argv[5], 180, rwn::desktop::maximum_preview_height,
                        "preview height")
            : 720U;
        options.frames_per_second = argc >= 7
            ? parse_u32(argv[6], 1, 120, "preview frame rate") : 5U;
        options.vt_mode = argc >= 8 ? argv[7] : L"baseline";
        options.dirty_analysis = argc == 9 &&
            std::wstring_view(argv[8]) == L"visual-analyze";
        options.visual_trace = argc == 10 &&
            std::wstring_view(argv[8]) == L"visual-trace";
        options.visual_protocol = (argc == 9 &&
            (std::wstring_view(argv[8]) == L"visual" ||
             options.dirty_analysis)) || options.visual_trace;
        if (argc == 9 && !options.visual_protocol &&
            std::wstring_view(argv[8]) != L"legacy") {
            throw std::invalid_argument("invalid visual protocol mode");
        }
        if (argc == 10 && !options.visual_trace) {
            throw std::invalid_argument("invalid visual protocol mode");
        }
        if (options.visual_trace) options.visual_trace_path = argv[9];
        return options;
    }

    bool profile_seen{};
    bool control_seen{};
    bool present_seen{};
    bool trace_seen{};
    bool scale_seen{};
    bool hybrid_seen{};
    bool visual_mode_seen{};
    bool evidence_seen{};
    bool encoder_seen{};
    for (int index = 4; index < argc;) {
        const std::wstring_view flag(argv[index++]);
        if (index >= argc) {
            throw std::invalid_argument("viewer option requires a value");
        }
        const std::wstring_view value(argv[index++]);
        if (flag == L"--encoder" && !std::exchange(encoder_seen, true)) {
            if (value != L"baseline" && value != L"low-latency")
                throw std::invalid_argument("invalid named encoder mode");
            options.vt_mode = value;
        } else if (flag == L"--probe-seconds" && options.probe_seconds == 0) {
            options.probe_seconds = parse_u32(argv[index - 1], 1, 60, "probe seconds");
        } else if (flag == L"--profile" && !std::exchange(profile_seen, true)) {
            if (value != L"lan-quality") {
                throw std::invalid_argument("unknown viewer profile");
            }
            options.lan_quality = true;
            options.maximum_width = 1920;
            options.maximum_height = 1080;
            options.frames_per_second = 60;
            options.bitrate_kbps = 20'000;
            options.visual_protocol = true;
            options.scale_mode = rwn::viewer::D3D11ScaleMode::one_to_one;
        } else if (flag == L"--control" &&
                   !std::exchange(control_seen, true)) {
            if (value == L"view") {
                options.interactive = false;
            } else if (value == L"interactive") {
                options.interactive = true;
            } else {
                throw std::invalid_argument("invalid viewer control mode");
            }
        } else if (flag == L"--present" &&
                   !std::exchange(present_seen, true)) {
            if (value == L"balanced") {
                options.extreme_present = false;
            } else if (value == L"extreme") {
                options.extreme_present = true;
            } else {
                throw std::invalid_argument("invalid viewer present mode");
            }
        } else if (flag == L"--trace" &&
                   !std::exchange(trace_seen, true)) {
            options.visual_trace = true;
            options.dirty_analysis = true;
            options.visual_trace_path = value;
        } else if (flag == L"--scale" &&
                   !std::exchange(scale_seen, true)) {
            if (value == L"1:1") {
                options.scale_mode = rwn::viewer::D3D11ScaleMode::one_to_one;
            } else if (value == L"fit") {
                options.scale_mode = rwn::viewer::D3D11ScaleMode::fit;
            } else {
                throw std::invalid_argument("invalid viewer scale mode");
            }
        } else if (flag == L"--hybrid" &&
                   !std::exchange(hybrid_seen, true)) {
            if (visual_mode_seen) {
                throw std::invalid_argument(
                    "--hybrid and --visual-mode are mutually exclusive");
            }
            if (value == L"h264") {
                options.raw_rect_experimental = false;
                options.h264_only_explicit = true;
            } else if (value == L"snapshot-only") {
                options.snapshot_only_explicit = true;
            } else if (value == L"raw-rect-experimental") {
                options.raw_rect_experimental = true;
            } else {
                throw std::invalid_argument("invalid hybrid mode");
            }
        } else if (flag == L"--visual-mode" &&
                   !std::exchange(visual_mode_seen, true)) {
            if (hybrid_seen) {
                throw std::invalid_argument(
                    "--hybrid and --visual-mode are mutually exclusive");
            }
            if (value != L"exact") {
                throw std::invalid_argument("invalid visual mode");
            }
            options.exact_only = true;
            options.raw_rect_experimental = true;
        } else if (flag == L"--evidence" &&
                   !std::exchange(evidence_seen, true)) {
            if (value != L"pixel-quality") {
                throw std::invalid_argument("invalid evidence mode");
            }
            options.verify_exact_pixels = true;
        } else {
            throw std::invalid_argument("unknown or duplicate viewer option");
        }
    }
    if (!profile_seen) {
        throw std::invalid_argument("named viewer mode requires --profile");
    }
    if (options.raw_rect_experimental && !options.interactive) {
        throw std::invalid_argument(
            "experimental RAW_RECT requires interactive control ACK channel");
    }
    if (options.snapshot_only_explicit && !options.interactive) {
        throw std::invalid_argument(
            "snapshot-only requires interactive control ACK channel");
    }
    if (options.exact_only && !options.interactive) {
        throw std::invalid_argument(
            "exact visual mode requires the framebuffer ACK channel");
    }
    if (options.verify_exact_pixels &&
        (!options.raw_rect_experimental || !options.visual_trace)) {
        throw std::invalid_argument(
            "pixel-quality evidence requires experimental RAW_RECT and trace");
    }
    return options;
}

double percentile_ms(std::vector<double> samples, const double quantile) {
    if (samples.empty()) return 0.0;
    std::ranges::sort(samples);
    const auto index = static_cast<std::size_t>(
        quantile * static_cast<double>(samples.size() - 1U));
    return samples[index];
}

double maximum_ms(const std::vector<double>& samples) {
    return samples.empty()
        ? 0.0
        : *std::ranges::max_element(samples);
}

std::uint64_t steady_timestamp_us() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

struct DisplayFrame {
    rwn::platform::windows::WindowsNv12Frame nv12;
    std::uint64_t decoded_ready_at_us{};
    std::uint64_t session_generation{};
    std::uint64_t representation_epoch{1};
    bool keyframe{};
};

enum class SnapshotCommandKind {
    begin,
    chunk,
    commit,
    rect_transaction,
    cancel,
};

struct SnapshotCommand {
    SnapshotCommandKind kind{SnapshotCommandKind::cancel};
    std::uint64_t session_generation{};
    std::uint64_t representation_epoch{};
    std::uint64_t frame_id{};
    std::uint64_t base_frame_id{};
    std::uint32_t width{};
    std::uint32_t height{};
    std::uint32_t chunk_offset{};
    rwn::core::Sha256Digest canonical_sha256{};
    std::vector<rwn::desktop::VisualRawRect> rectangles;
    std::vector<std::byte> bytes;
};

std::wstring quote_windows_argument(const std::wstring_view value) {
    std::wstring result{L'"'};
    std::size_t backslashes{};
    for (const auto character : value) {
        if (character == L'\\') {
            ++backslashes;
            continue;
        }
        if (character == L'"') {
            result.append(backslashes * 2U + 1U, L'\\');
            result.push_back(L'"');
            backslashes = 0;
            continue;
        }
        result.append(backslashes, L'\\');
        backslashes = 0;
        result.push_back(character);
    }
    result.append(backslashes * 2U, L'\\');
    result.push_back(L'"');
    return result;
}

bool read_exact(const HANDLE pipe, const std::span<std::byte> destination) {
    std::size_t offset{};
    while (offset < destination.size()) {
        DWORD received{};
        const auto remaining = static_cast<DWORD>(std::min<std::size_t>(
            destination.size() - offset, MAXDWORD));
        if (!ReadFile(pipe, destination.data() + offset, remaining, &received, nullptr) ||
            received == 0) {
            return false;
        }
        offset += received;
    }
    return true;
}

void write_exact(const HANDLE file, const std::string_view value) {
    std::size_t offset{};
    while (offset < value.size()) {
        DWORD written{};
        const auto remaining = static_cast<DWORD>(std::min<std::size_t>(
            value.size() - offset, MAXDWORD));
        if (!WriteFile(
                file, value.data() + offset, remaining, &written, nullptr) ||
            written == 0) {
            throw std::runtime_error("write visual trace file failed");
        }
        offset += written;
    }
}

void write_exact(
    const HANDLE file, const std::span<const std::byte> value) {
    std::size_t offset{};
    while (offset < value.size()) {
        DWORD written{};
        const auto remaining = static_cast<DWORD>(std::min<std::size_t>(
            value.size() - offset, MAXDWORD));
        if (!WriteFile(
                file, value.data() + offset, remaining,
                &written, nullptr) || written == 0) {
            throw std::runtime_error("write reverse control stream failed");
        }
        offset += written;
    }
}

struct PendingControlMessage {
    rwn::desktop::ReverseControlType type{
        rwn::desktop::ReverseControlType::ping};
    std::vector<std::byte> payload;
    std::uint64_t occurred_at_us{};
    std::uint64_t order{};
    std::uint64_t input_epoch{};
    std::uint64_t trace_session_generation{};
    std::uint64_t trace_representation_epoch{};
    std::uint64_t trace_frame_id{};
    std::uint64_t input_correlation_id{};
    std::uint64_t input_sequence{};
    rwn::desktop::VisualInputTraceClass input_trace_class{
        rwn::desktop::VisualInputTraceClass::none};
};

HCURSOR create_hardware_cursor(
    const rwn::desktop::VisualCursorShape& shape) {
    BITMAPV5HEADER header{};
    header.bV5Size = sizeof(header);
    header.bV5Width = shape.width;
    header.bV5Height = -static_cast<LONG>(shape.height);
    header.bV5Planes = 1;
    header.bV5BitCount = 32;
    header.bV5Compression = BI_BITFIELDS;
    header.bV5RedMask = 0x00ff0000;
    header.bV5GreenMask = 0x0000ff00;
    header.bV5BlueMask = 0x000000ff;
    header.bV5AlphaMask = 0xff000000;
    void* pixels{};
    const auto screen = GetDC(nullptr);
    const auto color = CreateDIBSection(
        screen, reinterpret_cast<const BITMAPINFO*>(&header),
        DIB_RGB_COLORS, &pixels, nullptr, 0);
    ReleaseDC(nullptr, screen);
    if (color == nullptr || pixels == nullptr) {
        if (color != nullptr) DeleteObject(color);
        throw std::runtime_error("create Windows cursor bitmap failed");
    }
    std::copy(shape.bgra.begin(), shape.bgra.end(),
              reinterpret_cast<std::byte*>(pixels));
    const auto mask = CreateBitmap(
        shape.width, shape.height, 1, 1, nullptr);
    if (mask == nullptr) {
        DeleteObject(color);
        throw std::runtime_error("create Windows cursor mask failed");
    }
    ICONINFO info{
        .fIcon = FALSE,
        .xHotspot = shape.hotspot_x,
        .yHotspot = shape.hotspot_y,
        .hbmMask = mask,
        .hbmColor = color,
    };
    const auto cursor = CreateIconIndirect(&info);
    DeleteObject(mask);
    DeleteObject(color);
    if (cursor == nullptr) {
        throw std::runtime_error("create Windows hardware cursor failed");
    }
    return cursor;
}

struct ViewerState {
    std::mutex mutex;
    std::condition_variable_any compositor_ready;
    std::shared_ptr<const DisplayFrame> frame;
    std::uint64_t frame_revision{};
    std::deque<SnapshotCommand> snapshot_commands;
    std::atomic_uint64_t rendered_revision{};
    std::atomic_uint64_t successful_present_receipts{};
    std::atomic_bool tls_runtime_failed{};
    void record_present_receipt(const rwn::viewer::D3D11RenderReceipt& receipt) {
        if (receipt.frame_id == 0 || receipt.framebuffer_committed_at_us == 0 ||
            receipt.present_submitted_at_us < receipt.framebuffer_committed_at_us)
            throw std::runtime_error("invalid compositor Present receipt");
        successful_present_receipts.fetch_add(1,std::memory_order_relaxed);
    }
    std::wstring status{L"Connecting to Mac preview..."};
    std::wstring title{L"Remote Workspace Viewer - View Only"};
    std::wstring remote_metrics;
    std::wstring snapshot_metrics;
    HWND window{};
    HANDLE ssh_process{};
    HANDLE output_read{};
    HANDLE error_read{};
    HANDLE input_write{};
    std::unique_ptr<rwn::viewer::TlsPreviewConnection> tls;
    std::jthread tls_heartbeat;
    bool read_visual(std::span<std::byte> bytes, bool message_start = false) {
        return tls ? tls->read(bytes, message_start) : read_exact(output_read,bytes);
    }
    void write_control(std::span<const std::byte> bytes) {
        if (tls) tls->write(bytes); else write_exact(input_write,bytes);
    }
    std::unique_ptr<rwn::viewer::D3D11Nv12Renderer> renderer;
    bool visual_protocol{};
    bool visual_trace_enabled{};
    std::jthread frame_reader;
    std::jthread error_reader;
    std::jthread compositor;
    std::jthread control_writer;
    std::mutex control_mutex;
    std::condition_variable_any control_ready;
    std::deque<PendingControlMessage> reliable_control;
    std::optional<PendingControlMessage> pointer_control;
    std::uint64_t next_control_order{};
    std::uint64_t next_wire_sequence{};
    std::uint64_t next_reliable_input_sequence{};
    std::uint64_t next_pointer_input_sequence{};
    std::uint64_t input_epoch{1};
    bool interactive{};
    bool control_closing{};
    rwn::desktop::InputFocusReleaseGate input_focus;
    std::atomic_uint64_t rendered_frames{};
    std::atomic_uint64_t decoded_replacements{};
    std::atomic_bool one_to_one_scale{};
    std::atomic_uint32_t exact_surface_width{};
    std::atomic_uint32_t exact_surface_height{};
    std::vector<double> decoded_ready_to_present_ms;
    rwn::desktop::VisualCursorPosition remote_cursor{};
    std::map<std::uint64_t, HCURSOR> cursor_cache;
    HCURSOR current_cursor{};
    std::uint64_t remote_cursor_messages{};
    std::vector<double> remote_cursor_age_ms;
    std::atomic_bool stopping{};
    std::unique_ptr<rwn::desktop::VisualTraceQueue> trace_queue;
    mutable std::mutex lifecycle_mutex;
    std::shared_ptr<rwn::desktop::VisualLifecycleTracker> lifecycle;
    std::uint64_t lifecycle_session_generation{};
    HANDLE trace_file{INVALID_HANDLE_VALUE};
    std::jthread trace_writer;
    std::jthread visual_watchdog;
    std::atomic_bool video_liveness_enabled{true};
    std::atomic_uint64_t trace_write_dropped{};
    std::atomic_bool trace_invalid{};
    rwn::desktop::CanonicalFramebufferState canonical_framebuffer;
    std::uint64_t snapshot_started_at_us{};
    std::atomic_uint64_t snapshot_commits{};
    std::atomic_uint64_t snapshot_cancels{};
    std::atomic_uint64_t snapshot_commit_to_ack_us{};
    std::atomic_uint64_t rect_commits{};
    std::atomic_uint64_t rect_cancels{};
    std::atomic_uint64_t rect_commit_to_ack_us{};
    bool verify_exact_pixels{};
    std::vector<std::byte> h264_quality_reference;
    std::uint64_t h264_quality_frame_id{};
    std::uint64_t h264_quality_mismatches{};
    std::uint64_t h264_quality_absolute_error{};
    std::uint64_t h264_quality_squared_error{};

    void enqueue_snapshot_command(SnapshotCommand command) {
        std::lock_guard lock(mutex);
        if (snapshot_commands.size() >= 256U) {
            throw std::runtime_error("snapshot compositor queue exceeded bounds");
        }
        snapshot_commands.push_back(std::move(command));
        compositor_ready.notify_one();
    }

    void enqueue_heartbeat() {
        enqueue_control({
            .type = rwn::desktop::ReverseControlType::ping,
            .payload = {},
            .occurred_at_us = steady_timestamp_us(),
        }, false);
    }

    void enqueue_control(
        PendingControlMessage message, const bool pointer_latest) {
        const bool input = message.type == rwn::desktop::ReverseControlType::input_event ||
                           message.type == rwn::desktop::ReverseControlType::release_all_input;
        if ((input && !interactive) || (!tls && (!interactive || input_write == nullptr)) || stopping) return;
        std::uint64_t queued_epoch{};
        std::uint32_t queued_depth{};
        std::uint64_t superseded_correlation{};
        std::uint64_t superseded_epoch{};
        std::uint64_t superseded_sequence{};
        rwn::desktop::VisualInputTraceClass superseded_class{
            rwn::desktop::VisualInputTraceClass::none};
        const auto correlation = message.input_correlation_id;
        const auto sequence = message.input_sequence;
        const auto input_class = message.input_trace_class;
        {
            std::lock_guard lock(control_mutex);
            message.order = ++next_control_order;
            message.input_epoch = input_epoch;
            if (pointer_latest) {
                if (pointer_control && pointer_control->input_correlation_id != 0U) {
                    superseded_correlation = pointer_control->input_correlation_id;
                    superseded_epoch = pointer_control->input_epoch;
                    superseded_sequence = pointer_control->input_sequence;
                    superseded_class = pointer_control->input_trace_class;
                }
                pointer_control = std::move(message);
            } else {
                // A reliable input edge observes the pointer position before
                // it. Freeze that pending move at the barrier; later motion
                // may coalesce only with motion after this edge.
                const bool pointer_barrier = pointer_control &&
                    (message.type == rwn::desktop::ReverseControlType::input_event ||
                     message.type == rwn::desktop::ReverseControlType::release_all_input);
                const auto required = pointer_barrier ? 2U : 1U;
                if (reliable_control.size() + required > 256U) {
                    if (message.type != rwn::desktop::ReverseControlType::
                            release_all_input) {
                        throw std::runtime_error("reliable input queue is full");
                    }
                    ++input_epoch;
                    if (input_epoch == 0) {
                        throw std::overflow_error("input epoch exhausted");
                    }
                    reliable_control.clear();
                    pointer_control.reset();
                    next_reliable_input_sequence = 0;
                    next_pointer_input_sequence = 0;
                    message.input_epoch = input_epoch;
                }
                if (pointer_barrier && pointer_control) {
                    reliable_control.push_back(std::move(*pointer_control));
                    pointer_control.reset();
                }
                reliable_control.push_back(std::move(message));
            }
            queued_epoch = input_epoch;
            queued_depth = static_cast<std::uint32_t>(
                reliable_control.size() + (pointer_control ? 1U : 0U));
        }
        if (const auto trace_lifecycle = current_lifecycle();
            correlation != 0U && trace_lifecycle) {
            trace_lifecycle->record(
                rwn::desktop::VisualLifecycleStage::input_enqueued, 0,
                steady_timestamp_us(), rwn::desktop::VisualTraceEvent{
                    .queue_depth = queued_depth,
                    .input_correlation_id = correlation,
                    .input_epoch = queued_epoch,
                    .input_sequence = sequence,
                    .input_trace_class = input_class,
                });
        }
        if (const auto trace_lifecycle = current_lifecycle();
            superseded_correlation != 0U && trace_lifecycle) {
            trace_lifecycle->record(
                rwn::desktop::VisualLifecycleStage::input_superseded, 0,
                steady_timestamp_us(), rwn::desktop::VisualTraceEvent{
                    .superseded_by = correlation,
                    .input_correlation_id = superseded_correlation,
                    .input_epoch = superseded_epoch,
                    .input_sequence = superseded_sequence,
                    .input_trace_class = superseded_class,
                });
        }
        control_ready.notify_one();
    }

    void enqueue_input(rwn::desktop::InputEvent event) {
        const auto pointer_latest =
            event.kind == rwn::desktop::InputKind::pointer_move;
        event.sequence = pointer_latest
            ? ++next_pointer_input_sequence
            : ++next_reliable_input_sequence;
        event.occurred_at_us = steady_timestamp_us();
        const auto input_class = pointer_latest
            ? rwn::desktop::VisualInputTraceClass::pointer_latest
            : rwn::desktop::VisualInputTraceClass::reliable;
        if (const auto trace_lifecycle = current_lifecycle(); trace_lifecycle) {
            trace_lifecycle->record(
                rwn::desktop::VisualLifecycleStage::input_captured, 0,
                event.occurred_at_us, rwn::desktop::VisualTraceEvent{
                    .input_correlation_id = event.occurred_at_us,
                    .input_sequence = event.sequence,
                    .input_trace_class = input_class,
                });
        }
        enqueue_control({
            .type = rwn::desktop::ReverseControlType::input_event,
            .payload = rwn::desktop::encode_input_event(event),
            .occurred_at_us = event.occurred_at_us,
            .input_correlation_id = event.occurred_at_us,
            .input_sequence = event.sequence,
            .input_trace_class = input_class,
        }, pointer_latest);
    }

    void enqueue_release_all() {
        const auto occurred_at_us = steady_timestamp_us();
        enqueue_control({
            .type = rwn::desktop::ReverseControlType::release_all_input,
            .payload = {},
            .occurred_at_us = occurred_at_us,
            .input_correlation_id = occurred_at_us,
            .input_trace_class =
                rwn::desktop::VisualInputTraceClass::release_all,
        }, false);
    }

    void focus_acquired() noexcept {
        if (interactive) input_focus.focus_acquired();
    }

    void release_input_for_focus_loss() {
        if (interactive && input_focus.focus_lost()) enqueue_release_all();
    }

    void install_cursor_shape(
        const rwn::desktop::VisualCursorShape& shape) {
        if (!interactive) return;
        auto created = create_hardware_cursor(shape);
        std::lock_guard lock(mutex);
        if (const auto existing = cursor_cache.find(shape.shape_id);
            existing != cursor_cache.end()) {
            DestroyCursor(created);
            current_cursor = existing->second;
            return;
        }
        while (cursor_cache.size() >= 32U) {
            auto oldest = cursor_cache.begin();
            if (oldest->second == current_cursor &&
                std::next(oldest) != cursor_cache.end()) {
                ++oldest;
            }
            DestroyCursor(oldest->second);
            cursor_cache.erase(oldest);
        }
        cursor_cache.emplace(shape.shape_id, created);
        current_cursor = created;
    }

    void initialize_visual_trace(const std::filesystem::path& path) {
        rwn::desktop::validate_visual_trace_destination(path);
        trace_file = CreateFileW(
            path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (trace_file == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("create visual trace file failed");
        }
        visual_trace_enabled = true;
        trace_queue = std::make_unique<rwn::desktop::VisualTraceQueue>();
        trace_writer = std::jthread([this](const std::stop_token stop) {
            std::uint64_t file_bytes{};
            try {
                while (!stop.stop_requested() || trace_queue->size() != 0) {
                    auto event = trace_queue->wait_pop(
                        std::chrono::milliseconds{100});
                    if (!event) continue;
                    auto line = rwn::desktop::render_visual_trace_json(*event);
                    line.push_back('\n');
                    if (line.size() >
                        rwn::desktop::maximum_visual_trace_file_bytes -
                            file_bytes) {
                        trace_invalid.store(true);
                        trace_write_dropped.fetch_add(1);
                        continue;
                    }
                    write_exact(trace_file, line);
                    file_bytes += line.size();
                }
            } catch (const std::exception& error) {
                trace_invalid.store(true);
                set_status(utf8_to_utf16(error.what()));
            }
        });
        visual_watchdog = std::jthread([this](const std::stop_token stop) {
            std::optional<rwn::desktop::VisualLivenessWatchdog> watchdog;
            while (!stop.stop_requested()) {
                if (!video_liveness_enabled.load(std::memory_order_acquire)) {
                    watchdog.reset();
                    std::this_thread::sleep_for(std::chrono::milliseconds{10});
                    continue;
                }
                if (!watchdog) {
                    watchdog.emplace(
                        rwn::desktop::VisualLifecycleDomain::windows);
                }
                std::shared_ptr<rwn::desktop::VisualLifecycleTracker> tracker;
                {
                    std::lock_guard lock(lifecycle_mutex);
                    tracker = lifecycle;
                }
                if (tracker) {
                    const auto now_us = steady_timestamp_us();
                    if (const auto event = watchdog->poll(
                            tracker->snapshot(), now_us)) {
                        tracker->record(
                            event->recovered
                                ? rwn::desktop::VisualLifecycleStage::
                                      visual_recovered
                                : rwn::desktop::VisualLifecycleStage::
                                      visual_stall,
                            event->frame_id, now_us,
                            rwn::desktop::VisualTraceEvent{
                                .related_stage = event->related_stage,
                                .stalled_us = event->stalled_us,
                            });
                    }
                }
                std::this_thread::sleep_for(std::chrono::milliseconds{10});
            }
        });
    }

    std::shared_ptr<rwn::desktop::VisualLifecycleTracker> ensure_lifecycle(
        const std::uint64_t session_generation) {
        std::lock_guard lock(lifecycle_mutex);
        if (!visual_trace_enabled) return {};
        if (session_generation == 0) {
            throw std::invalid_argument("visual trace session is zero");
        }
        if (!lifecycle) {
            lifecycle_session_generation = session_generation;
            lifecycle =
                std::make_shared<rwn::desktop::VisualLifecycleTracker>(
                    rwn::desktop::VisualTraceHost::windows,
                    session_generation, trace_queue.get());
        } else if (session_generation != lifecycle_session_generation) {
            throw std::runtime_error(
                "visual trace session changed without state reset");
        }
        return lifecycle;
    }

    std::shared_ptr<rwn::desktop::VisualLifecycleTracker> current_lifecycle() {
        std::lock_guard lock(lifecycle_mutex);
        return lifecycle;
    }

    void enqueue_remote_trace(const std::string_view json) {
        if (!visual_trace_enabled) return;
        const auto event = rwn::desktop::decode_visual_trace_json(json);
        if (event.host != rwn::desktop::VisualTraceHost::mac) {
            throw std::invalid_argument("remote visual trace host is invalid");
        }
        if (!trace_queue->try_push(event)) trace_invalid.store(true);
    }

    void set_status(std::wstring value) {
        {
            std::lock_guard lock(mutex);
            status = std::move(value);
            title = std::wstring(L"Remote Workspace Viewer [") +
                (interactive ? L"CONTROL" : L"VIEW ONLY") + L"] - " + status;
        }
        if (window != nullptr) PostMessageW(window, status_changed_message, 0, 0);
    }

    void stop() {
        if (stopping.exchange(true)) return;
        if (tls_heartbeat.joinable()) tls_heartbeat.request_stop();
        if (tls || (interactive && input_write != nullptr)) {
            {
                std::lock_guard lock(control_mutex);
                if (interactive) reliable_control.push_back({
                    .type = rwn::desktop::ReverseControlType::
                        release_all_input,
                    .payload = {},
                    .occurred_at_us = steady_timestamp_us(),
                    .order = ++next_control_order,
                    .input_epoch = input_epoch,
                });
                control_closing = true;
            }
            control_ready.notify_all();
            if (control_writer.joinable()) control_writer.join();
        }
        if (tls) tls->cancel();
        if (tls_heartbeat.joinable()) tls_heartbeat.join();
        if (compositor.joinable()) compositor.request_stop();
        compositor_ready.notify_all();
        if (input_write != nullptr) {
            CloseHandle(input_write);
            input_write = nullptr;
        }
        if (ssh_process != nullptr) {
            if (WaitForSingleObject(ssh_process, 250) != WAIT_OBJECT_0) {
                static_cast<void>(TerminateProcess(ssh_process, 0));
                static_cast<void>(WaitForSingleObject(ssh_process, 2'000));
            }
        }
        if (output_read != nullptr) {
            CloseHandle(output_read);
            output_read = nullptr;
        }
        if (error_read != nullptr) {
            CloseHandle(error_read);
            error_read = nullptr;
        }
        if (frame_reader.joinable()) frame_reader.join();
        if (error_reader.joinable()) error_reader.join();
        if (compositor.joinable()) compositor.join();
        if (visual_watchdog.joinable()) {
            visual_watchdog.request_stop();
            visual_watchdog.join();
        }
        if (trace_queue) trace_queue->close();
        if (trace_writer.joinable()) {
            trace_writer.request_stop();
            trace_writer.join();
        }
        if (trace_file != INVALID_HANDLE_VALUE) {
            CloseHandle(trace_file);
            trace_file = INVALID_HANDLE_VALUE;
        }
        if (ssh_process != nullptr) {
            CloseHandle(ssh_process);
            ssh_process = nullptr;
        }
        for (const auto& [unused, cursor] : cursor_cache) {
            static_cast<void>(unused);
            DestroyCursor(cursor);
        }
        cursor_cache.clear();
        current_cursor = nullptr;
    }

    ~ViewerState() { stop(); }
};

void compositor_loop(ViewerState& state, const std::stop_token stop) {
    std::uint64_t handled_revision{};
    std::uint64_t last_frame_id{};
    while (!stop.stop_requested() && !state.stopping) {
        std::shared_ptr<const DisplayFrame> frame;
        std::optional<SnapshotCommand> snapshot_command;
        std::uint64_t revision{};
        {
            std::unique_lock lock(state.mutex);
            static_cast<void>(state.compositor_ready.wait_for(
                lock, stop, std::chrono::milliseconds{10}, [&] {
                    return state.stopping ||
                        !state.snapshot_commands.empty() ||
                        state.frame_revision != handled_revision;
                }));
            if (stop.stop_requested() || state.stopping) break;
            if (!state.snapshot_commands.empty()) {
                snapshot_command = std::move(state.snapshot_commands.front());
                state.snapshot_commands.pop_front();
            } else {
                frame = state.frame;
                revision = state.frame_revision;
            }
        }
        if (state.snapshot_started_at_us != 0 &&
            steady_timestamp_us() - state.snapshot_started_at_us > 1'000'000U) {
            state.renderer->cancel_full_snapshot();
            state.snapshot_started_at_us = 0;
            ++state.snapshot_cancels;
            // No future visual event is required to recover an expired upload.
            // Clearing the start time above makes this request one-shot.
            if (state.interactive) {
                try {
                    state.enqueue_control({
                        .type = rwn::desktop::ReverseControlType::request_full_snapshot,
                        .payload = {},
                        .occurred_at_us = steady_timestamp_us(),
                    }, false);
                } catch (const std::exception& error) {
                    state.set_status(utf8_to_utf16(error.what()));
                    continue;
                }
            }
            state.set_status(
                L"FULL_SNAPSHOT timed out; retained prior framebuffer");
        }
        if (snapshot_command) {
            try {
                switch (snapshot_command->kind) {
                    case SnapshotCommandKind::begin:
                        static_cast<void>(state.ensure_lifecycle(
                            snapshot_command->session_generation));
                        if (!state.canonical_framebuffer.enter_representation(
                                rwn::desktop::VisualRepresentation::snapshot,
                                snapshot_command->representation_epoch)) {
                            throw std::runtime_error(
                                "stale snapshot representation epoch");
                        }
                        state.h264_quality_reference.clear();
                        state.h264_quality_frame_id = 0;
                        state.h264_quality_mismatches = 0;
                        state.h264_quality_absolute_error = 0;
                        state.h264_quality_squared_error = 0;
                        if (state.verify_exact_pixels &&
                            state.canonical_framebuffer.quality() ==
                                rwn::desktop::FramebufferQuality::lossy &&
                            state.canonical_framebuffer.committed_frame_id() ==
                                snapshot_command->frame_id) {
                            state.h264_quality_reference =
                                state.renderer->committed_framebuffer_bgra();
                            state.h264_quality_frame_id =
                                snapshot_command->frame_id;
                        }
                        state.renderer->begin_full_snapshot(
                            snapshot_command->width,
                            snapshot_command->height);
                        state.snapshot_started_at_us = steady_timestamp_us();
                        break;
                    case SnapshotCommandKind::chunk:
                        if (!state.h264_quality_reference.empty()) {
                            if (snapshot_command->chunk_offset >
                                    state.h264_quality_reference.size() ||
                                snapshot_command->bytes.size() >
                                    state.h264_quality_reference.size() -
                                        snapshot_command->chunk_offset) {
                                throw std::runtime_error(
                                    "quality evidence chunk exceeds reference");
                            }
                            const auto* reference =
                                state.h264_quality_reference.data() +
                                snapshot_command->chunk_offset;
                            for (std::size_t index = 0;
                                 index < snapshot_command->bytes.size(); ++index) {
                                const auto actual = std::to_integer<unsigned>(
                                    reference[index]);
                                const auto expected = std::to_integer<unsigned>(
                                    snapshot_command->bytes[index]);
                                const auto difference = actual > expected
                                    ? actual - expected : expected - actual;
                                state.h264_quality_mismatches +=
                                    difference != 0 ? 1U : 0U;
                                state.h264_quality_absolute_error += difference;
                                state.h264_quality_squared_error +=
                                    difference * difference;
                            }
                        }
                        state.renderer->write_full_snapshot_chunk(
                            snapshot_command->chunk_offset,
                            snapshot_command->bytes);
                        break;
                    case SnapshotCommandKind::commit: {
                        if (!state.canonical_framebuffer.can_commit_snapshot(
                                snapshot_command->representation_epoch,
                                snapshot_command->frame_id)) {
                            throw std::runtime_error(
                                "snapshot canonical commit precondition failed");
                        }
                        const auto receipt =
                            state.renderer->commit_full_snapshot(
                                state.window, snapshot_command->frame_id);
                        state.record_present_receipt(receipt);
                        if (!state.canonical_framebuffer.commit_snapshot(
                                snapshot_command->representation_epoch,
                                snapshot_command->frame_id)) {
                            throw std::logic_error(
                                "snapshot state changed during compositor commit");
                        }
                        state.exact_surface_width.store(
                            snapshot_command->width,
                            std::memory_order_release);
                        state.exact_surface_height.store(
                            snapshot_command->height,
                            std::memory_order_release);
                        auto lifecycle = state.current_lifecycle();
                        if (lifecycle) {
                            const rwn::desktop::VisualTraceEvent metadata{
                                .representation_epoch =
                                    snapshot_command->representation_epoch,
                                .representation_mode =
                                    rwn::desktop::VisualRepresentationMode::snapshot,
                            };
                            lifecycle->record(
                                rwn::desktop::VisualLifecycleStage::framebuffer_commit,
                                receipt.frame_id,
                                receipt.framebuffer_committed_at_us,
                                metadata);
                            lifecycle->record(
                                rwn::desktop::VisualLifecycleStage::present_submitted,
                                receipt.frame_id,
                                receipt.present_submitted_at_us,
                                metadata);
                            if (!state.h264_quality_reference.empty() &&
                                state.h264_quality_frame_id == receipt.frame_id) {
                                lifecycle->record(
                                    rwn::desktop::VisualLifecycleStage::
                                        h264_quality_compare,
                                    receipt.frame_id, steady_timestamp_us(),
                                    rwn::desktop::VisualTraceEvent{
                                        .representation_epoch =
                                            snapshot_command->representation_epoch,
                                        .payload_bytes =
                                            state.h264_quality_reference.size(),
                                        .verification_mismatches =
                                            state.h264_quality_mismatches,
                                        .absolute_error_sum =
                                            state.h264_quality_absolute_error,
                                        .squared_error_sum =
                                            state.h264_quality_squared_error,
                                    });
                            }
                        }
                        state.h264_quality_reference.clear();
                        state.h264_quality_frame_id = 0;
                        const auto ack =
                            state.canonical_framebuffer.take_commit_ack(
                                snapshot_command->session_generation,
                                snapshot_command->canonical_sha256);
                        if (!ack) {
                            throw std::logic_error(
                                "snapshot commit did not produce ACK");
                        }
                        const auto ack_created_at_us = steady_timestamp_us();
                        if (lifecycle) {
                            lifecycle->record(
                                rwn::desktop::VisualLifecycleStage::ack_created,
                                ack->frame_id, ack_created_at_us,
                                rwn::desktop::VisualTraceEvent{
                                    .representation_epoch =
                                        ack->representation_epoch,
                                    .representation_mode =
                                        rwn::desktop::VisualRepresentationMode::snapshot,
                                });
                        }
                        state.enqueue_control({
                            .type = rwn::desktop::ReverseControlType::
                                frame_commit_ack,
                            .payload = rwn::desktop::encode_frame_commit_ack(*ack),
                            .occurred_at_us = ack_created_at_us,
                            .trace_session_generation =
                                ack->session_generation,
                            .trace_representation_epoch =
                                ack->representation_epoch,
                            .trace_frame_id = ack->frame_id,
                        }, false);
                        const auto ack_enqueued_at_us = steady_timestamp_us();
                        if (lifecycle) {
                            lifecycle->record(
                                rwn::desktop::VisualLifecycleStage::ack_enqueued,
                                ack->frame_id, ack_enqueued_at_us,
                                rwn::desktop::VisualTraceEvent{
                                    .representation_epoch =
                                        ack->representation_epoch,
                                    .representation_mode =
                                        rwn::desktop::VisualRepresentationMode::snapshot,
                                });
                        }
                        state.snapshot_commit_to_ack_us.store(
                            ack_enqueued_at_us -
                                receipt.framebuffer_committed_at_us,
                            std::memory_order_relaxed);
                        state.snapshot_started_at_us = 0;
                        ++state.snapshot_commits;
                        break;
                    }
                    case SnapshotCommandKind::rect_transaction: {
                        if (!state.canonical_framebuffer.enter_representation(
                                rwn::desktop::VisualRepresentation::rect,
                                snapshot_command->representation_epoch) ||
                            !state.canonical_framebuffer.begin_rect(
                                snapshot_command->representation_epoch,
                                snapshot_command->base_frame_id,
                                snapshot_command->frame_id)) {
                            throw std::runtime_error(
                                "raw rectangle canonical precondition failed");
                        }
                        const auto patch_started_at_us = steady_timestamp_us();
                        for (const auto& rectangle :
                             snapshot_command->rectangles) {
                            state.renderer->patch_bgra(
                                rectangle.x, rectangle.y,
                                rectangle.width, rectangle.height,
                                rectangle.row_stride, rectangle.bgra);
                        }
                        auto lifecycle = state.current_lifecycle();
                        const auto verification =
                            state.renderer->verify_working_bgra(
                                snapshot_command->rectangles);
                        if (lifecycle) {
                            lifecycle->record(
                                rwn::desktop::VisualLifecycleStage::
                                    gpu_exact_verify,
                                snapshot_command->frame_id,
                                steady_timestamp_us(),
                                rwn::desktop::VisualTraceEvent{
                                    .representation_epoch =
                                        snapshot_command->representation_epoch,
                                    .stage_duration_us = verification.duration_us,
                                    .payload_bytes = verification.verified_bytes,
                                    .rectangle_count =
                                        static_cast<std::uint32_t>(
                                            snapshot_command->rectangles.size()),
                                    .verification_mismatches =
                                        verification.mismatched_bytes,
                                    .absolute_error_sum =
                                        verification.absolute_error_sum,
                                    .squared_error_sum =
                                        verification.squared_error_sum,
                                });
                        }
                        if (verification.mismatched_bytes != 0) {
                            state.trace_invalid.store(true);
                            throw std::runtime_error(
                                "working RAW_RECT GPU pixels are not exact");
                        }
                        const auto receipt = state.renderer->commit_framebuffer(
                            state.window, snapshot_command->frame_id);
                        state.record_present_receipt(receipt);
                        const auto patch_finished_at_us = steady_timestamp_us();
                        if (!state.canonical_framebuffer.commit_rect(
                                snapshot_command->representation_epoch,
                                snapshot_command->base_frame_id,
                                snapshot_command->frame_id)) {
                            throw std::logic_error(
                                "raw rectangle state changed during commit");
                        }
                        if (lifecycle) {
                            const rwn::desktop::VisualTraceEvent metadata{
                                .representation_epoch =
                                    snapshot_command->representation_epoch,
                                .representation_mode =
                                    rwn::desktop::VisualRepresentationMode::rect_exact,
                            };
                            std::uint64_t patch_bytes{};
                            for (const auto& rectangle :
                                 snapshot_command->rectangles) {
                                patch_bytes += rectangle.bgra.size();
                            }
                            lifecycle->record(
                                rwn::desktop::VisualLifecycleStage::gpu_patch,
                                receipt.frame_id, patch_finished_at_us,
                                rwn::desktop::VisualTraceEvent{
                                    .representation_epoch =
                                        snapshot_command->representation_epoch,
                                    .stage_duration_us =
                                        patch_finished_at_us -
                                        patch_started_at_us,
                                    .payload_bytes = patch_bytes,
                                    .rectangle_count = static_cast<std::uint32_t>(
                                        snapshot_command->rectangles.size()),
                                });
                            lifecycle->record(
                                rwn::desktop::VisualLifecycleStage::framebuffer_commit,
                                receipt.frame_id,
                                receipt.framebuffer_committed_at_us, metadata);
                            lifecycle->record(
                                rwn::desktop::VisualLifecycleStage::present_submitted,
                                receipt.frame_id,
                                receipt.present_submitted_at_us, metadata);
                        }
                        const auto ack =
                            state.canonical_framebuffer.take_commit_ack(
                                snapshot_command->session_generation,
                                snapshot_command->canonical_sha256);
                        if (!ack) {
                            throw std::logic_error(
                                "raw rectangle commit did not produce ACK");
                        }
                        const auto ack_created_at_us = steady_timestamp_us();
                        if (lifecycle) {
                            lifecycle->record(
                                rwn::desktop::VisualLifecycleStage::ack_created,
                                ack->frame_id, ack_created_at_us,
                                rwn::desktop::VisualTraceEvent{
                                    .representation_epoch =
                                        ack->representation_epoch,
                                    .representation_mode =
                                        rwn::desktop::VisualRepresentationMode::rect_exact,
                                });
                        }
                        state.enqueue_control({
                            .type = rwn::desktop::ReverseControlType::
                                frame_commit_ack,
                            .payload = rwn::desktop::encode_frame_commit_ack(*ack),
                            .occurred_at_us = ack_created_at_us,
                            .trace_session_generation = ack->session_generation,
                            .trace_representation_epoch =
                                ack->representation_epoch,
                            .trace_frame_id = ack->frame_id,
                        }, false);
                        const auto ack_enqueued_at_us = steady_timestamp_us();
                        if (lifecycle) {
                            lifecycle->record(
                                rwn::desktop::VisualLifecycleStage::ack_enqueued,
                                ack->frame_id, ack_enqueued_at_us,
                                rwn::desktop::VisualTraceEvent{
                                    .representation_epoch =
                                        ack->representation_epoch,
                                    .representation_mode =
                                        rwn::desktop::VisualRepresentationMode::rect_exact,
                                });
                        }
                        state.rect_commit_to_ack_us.store(
                            ack_enqueued_at_us -
                                receipt.framebuffer_committed_at_us,
                            std::memory_order_relaxed);
                        ++state.rect_commits;
                        break;
                    }
                    case SnapshotCommandKind::cancel:
                        state.renderer->cancel_full_snapshot();
                        state.renderer->cancel_framebuffer_update();
                        state.canonical_framebuffer.cancel_rect(
                            snapshot_command->representation_epoch);
                        state.snapshot_started_at_us = 0;
                        state.h264_quality_reference.clear();
                        state.h264_quality_frame_id = 0;
                        ++state.snapshot_cancels;
                        break;
                }
            } catch (const std::exception& error) {
                state.renderer->cancel_full_snapshot();
                if (state.tls && !state.stopping) {
                    state.tls_runtime_failed.store(true);
                    std::cerr << "tls_runtime_error stage=snapshot reason=" << error.what() << '\n';
                }
                state.renderer->cancel_framebuffer_update();
                state.canonical_framebuffer.cancel_rect(
                    snapshot_command->representation_epoch);
                state.snapshot_started_at_us = 0;
                ++state.snapshot_cancels;
                if (snapshot_command->kind ==
                    SnapshotCommandKind::rect_transaction) {
                    ++state.rect_cancels;
                    if (state.interactive || state.tls) {
                        state.enqueue_control({
                            .type = rwn::desktop::ReverseControlType::
                                request_full_snapshot,
                            .payload = {},
                            .occurred_at_us = steady_timestamp_us(),
                        }, false);
                    }
                }
                state.set_status(utf8_to_utf16(error.what()));
            }
            continue;
        }
        if (!frame) {
            handled_revision = revision;
            state.rendered_revision.store(
                revision, std::memory_order_release);
            continue;
        }
        try {
            std::optional<rwn::viewer::D3D11RenderReceipt> receipt;
            if (state.visual_protocol) {
                const auto previous_epoch =
                    state.canonical_framebuffer.representation_epoch();
                const auto previous_representation =
                    state.canonical_framebuffer.representation();
                if (frame->representation_epoch < previous_epoch) {
                    handled_revision = revision;
                    state.rendered_revision.store(
                        revision, std::memory_order_release);
                    continue;
                }
                if (!state.canonical_framebuffer.enter_representation(
                        rwn::desktop::VisualRepresentation::video,
                        frame->representation_epoch)) {
                    throw std::runtime_error("stale H.264 representation epoch");
                }
                if ((previous_epoch != frame->representation_epoch ||
                     previous_representation !=
                         rwn::desktop::VisualRepresentation::video) &&
                    !frame->keyframe) {
                    throw std::runtime_error(
                        "video representation transition requires IDR");
                }
                receipt = state.renderer->render_persistent(
                    state.window, frame->nv12);
                if (!state.canonical_framebuffer.commit_video(
                        frame->representation_epoch, frame->nv12.frame_id)) {
                    throw std::runtime_error(
                        "H.264 canonical framebuffer commit rejected");
                }
            } else {
                state.renderer->render(state.window, frame->nv12);
            }
            handled_revision = revision;
            state.rendered_revision.store(
                revision, std::memory_order_release);
            if (last_frame_id == frame->nv12.frame_id) continue;
            last_frame_id = frame->nv12.frame_id;
            state.rendered_frames.fetch_add(1, std::memory_order_relaxed);
            const auto presented_at_us = receipt
                ? receipt->present_submitted_at_us
                : steady_timestamp_us();
            if (receipt) {
                state.record_present_receipt(*receipt);
                auto lifecycle = state.current_lifecycle();
                if (lifecycle) {
                    lifecycle->record(
                        rwn::desktop::VisualLifecycleStage::framebuffer_commit,
                        receipt->frame_id,
                        receipt->framebuffer_committed_at_us);
                    lifecycle->record(
                        rwn::desktop::VisualLifecycleStage::present_submitted,
                        receipt->frame_id,
                        receipt->present_submitted_at_us);
                }
            }
            std::lock_guard lock(state.mutex);
            state.decoded_ready_to_present_ms.push_back(
                static_cast<double>(
                    presented_at_us - frame->decoded_ready_at_us) /
                1000.0);
        } catch (const std::exception& error) {
            handled_revision = revision;
            if (state.tls && !state.stopping) {
                state.tls_runtime_failed.store(true);
                std::cerr << "tls_runtime_error stage=render reason=" << error.what() << '\n';
            }
            state.rendered_revision.store(
                revision, std::memory_order_release);
            state.set_status(utf8_to_utf16(error.what()));
        }
    }
}

void control_writer_loop(ViewerState& state) {
    try {
        while (true) {
            PendingControlMessage message;
            std::uint64_t wire_sequence{};
            {
                std::unique_lock lock(state.control_mutex);
                state.control_ready.wait(lock, [&] {
                    return state.control_closing ||
                        state.pointer_control.has_value() ||
                        !state.reliable_control.empty();
                });
                if (!state.pointer_control &&
                    state.reliable_control.empty()) {
                    if (state.control_closing) break;
                    continue;
                }
                const auto pointer_first = state.pointer_control &&
                    (state.reliable_control.empty() ||
                     state.pointer_control->order <
                         state.reliable_control.front().order);
                if (pointer_first) {
                    message = std::move(*state.pointer_control);
                    state.pointer_control.reset();
                } else {
                    message = std::move(state.reliable_control.front());
                    state.reliable_control.pop_front();
                }
                wire_sequence = ++state.next_wire_sequence;
            }
            const auto header =
                rwn::desktop::encode_reverse_control_header({
                    .type = message.type,
                    .flags = 0,
                    .payload_size = static_cast<std::uint32_t>(
                        message.payload.size()),
                    .input_epoch = message.input_epoch,
                    .sequence = wire_sequence,
                    .occurred_at_us = message.occurred_at_us,
                });
            rwn::desktop::validate_reverse_control_payload(
                rwn::desktop::decode_reverse_control_header(header),
                message.payload);
            state.write_control(header);
            state.write_control(message.payload);
            if (message.input_correlation_id != 0U) {
                if (const auto lifecycle = state.current_lifecycle(); lifecycle) {
                    lifecycle->record(
                        rwn::desktop::VisualLifecycleStage::input_write_complete,
                        0, steady_timestamp_us(),
                        rwn::desktop::VisualTraceEvent{
                            .input_correlation_id =
                                message.input_correlation_id,
                            .input_epoch = message.input_epoch,
                            .input_sequence = message.input_sequence,
                            .input_trace_class = message.input_trace_class,
                        });
                }
            }
            if (message.type ==
                    rwn::desktop::ReverseControlType::frame_commit_ack &&
                message.trace_session_generation != 0) {
                auto lifecycle = state.ensure_lifecycle(
                    message.trace_session_generation);
                if (lifecycle) {
                    lifecycle->record(
                        rwn::desktop::VisualLifecycleStage::ack_write_complete,
                        message.trace_frame_id, steady_timestamp_us(),
                        rwn::desktop::VisualTraceEvent{
                            .representation_epoch =
                                message.trace_representation_epoch,
                        });
                }
            }
        }
        if (!state.tls) static_cast<void>(FlushFileBuffers(state.input_write));
    } catch (const std::exception& error) {
        if (state.tls) {
            if (!state.stopping) {
                state.tls_runtime_failed.store(true);
                std::cerr << "tls_runtime_error stage=control reason=" << error.what() << '\n';
            }
            state.tls->cancel();
        }
        if (!state.stopping) {
            state.set_status(utf8_to_utf16(error.what()));
        }
    }
}

void frame_reader_loop(
    ViewerState& state,
    const bool visual_protocol,
    const bool raw_rect_experimental,
    const bool exact_only) {
    try {
        std::unique_ptr<
            rwn::platform::windows::WindowsMediaFoundationH264Decoder> decoder;
        if (!exact_only) {
            decoder = std::make_unique<
                rwn::platform::windows::WindowsMediaFoundationH264Decoder>(
                    state.renderer->native_device());
        } else {
            state.set_status(
                L"Exact-only: Media Foundation decoder not started");
        }
        std::array<
            std::byte,
            rwn::desktop::encoded_preview_frame_header_size> wire{};
        auto report_started = std::chrono::steady_clock::now();
        std::uint64_t report_received{};
        std::uint64_t report_decoded{};
        std::uint64_t report_bytes{};
        std::uint64_t last_rendered{};
        std::uint64_t last_replacements{};
        std::int64_t minimum_clock_delta =
            std::numeric_limits<std::int64_t>::max();
        std::vector<double> decode_ms;
        std::vector<double> receive_to_submit_ms;
        std::vector<double> dynamic_frame_age_ms;
        std::size_t maximum_mf_lineage{};
        std::size_t maximum_mf_ready{};
        bool mf_low_latency{};
        bool mf_d3d11_output{};
        rwn::desktop::VisualSequenceTracker visual_sequence;
        struct IncomingSnapshot {
            std::uint64_t session_generation{};
            std::uint64_t representation_epoch{};
            std::uint64_t frame_id{};
            std::uint32_t width{};
            std::uint32_t height{};
            std::uint32_t total_bytes{};
            std::uint32_t next_offset{};
            std::uint32_t gpu_upload_offset{};
            std::vector<std::byte> gpu_upload_bytes;
            rwn::core::Sha256Accumulator canonical_hash;
        };
        struct IncomingRect {
            std::uint64_t session_generation{};
            std::uint64_t representation_epoch{};
            std::uint64_t base_frame_id{};
            std::uint64_t target_frame_id{};
            rwn::desktop::RawRectTransactionGuard guard;
            std::vector<rwn::desktop::VisualRawRect> rectangles;
        };
        std::optional<IncomingSnapshot> incoming_snapshot;
        std::optional<IncomingRect> incoming_rect;
        std::uint64_t pixel_representation_epoch{};
        std::uint64_t pixel_frame_id{};
        rwn::core::Sha256Digest pixel_canonical_digest{};
        bool pixel_canonical_digest_valid{};
        std::optional<rwn::desktop::VisualRepresentation>
            pixel_representation;
        std::optional<std::uint64_t> reset_epoch;
        std::optional<std::uint64_t> poisoned_raw_rect_epoch;
        const auto recover_snapshot = [&](const std::wstring& reason) {
            incoming_snapshot.reset();
            incoming_rect.reset();
            state.enqueue_snapshot_command({
                .kind = SnapshotCommandKind::cancel,
                .rectangles = {},
                .bytes = {},
            });
            if (state.interactive || state.tls) {
                state.enqueue_control({
                    .type = rwn::desktop::ReverseControlType::
                        request_full_snapshot,
                    .payload = {},
                    .occurred_at_us = steady_timestamp_us(),
                }, false);
            }
            state.set_status(reason);
        };
        const auto poison_raw_rect_transaction = [&] (
            const std::uint64_t epoch, const std::wstring& reason) {
            poisoned_raw_rect_epoch = std::max(
                poisoned_raw_rect_epoch.value_or(0U), epoch);
            recover_snapshot(reason);
        };
        while (!state.stopping) {
            rwn::desktop::VideoFrame encoded;
            std::uint64_t frame_session_generation{};
            if (visual_protocol) {
                std::array<
                    std::byte,
                    rwn::desktop::visual_message_header_size> visual_wire{};
                if (!state.read_visual(visual_wire, true)) break;
                const auto header =
                    rwn::desktop::decode_visual_message_header(visual_wire);
                std::vector<std::byte> payload(header.payload_size);
                if (!state.read_visual(payload)) break;
                rwn::desktop::validate_visual_message_payload(header, payload);
                if (!rwn::desktop::visual_message_allowed(
                        exact_only
                            ? rwn::desktop::VisualRuntimeMode::exact_only
                            : rwn::desktop::VisualRuntimeMode::hybrid,
                        header.type)) {
                    throw std::runtime_error(
                        "visual message is forbidden by the selected runtime mode");
                }
                const auto sequence_result = visual_sequence.receive(header);
                if (sequence_result == rwn::desktop::VisualSequenceResult::gap) {
                    recover_snapshot(
                        L"RWV2 sequence gap; requested full snapshot");
                    continue;
                }
                if (header.type ==
                    rwn::desktop::VisualMessageType::cursor_position) {
                    const auto cursor =
                        rwn::desktop::decode_visual_cursor_position(payload);
                    const auto received_at_us = steady_timestamp_us();
                    {
                        std::lock_guard lock(state.mutex);
                        state.remote_cursor = cursor;
                        ++state.remote_cursor_messages;
                        if (received_at_us >= header.captured_at_us) {
                            state.remote_cursor_age_ms.push_back(
                                static_cast<double>(
                                    received_at_us - header.captured_at_us) /
                                1000.0);
                        }
                    }
                    PostMessageW(
                        state.window, cursor_changed_message, 0, 0);
                    continue;
                }
                if (header.type ==
                    rwn::desktop::VisualMessageType::cursor_shape) {
                    const auto shape =
                        rwn::desktop::decode_visual_cursor_shape(payload);
                    state.install_cursor_shape(shape);
                    PostMessageW(
                        state.window, cursor_changed_message, 0, 0);
                    continue;
                }
                if (header.type ==
                    rwn::desktop::VisualMessageType::state_reset) {
                    static_cast<void>(
                        rwn::desktop::decode_visual_state_reset(payload));
                    if (header.representation_epoch <=
                        pixel_representation_epoch) {
                        throw std::runtime_error(
                            "STATE_RESET did not advance representation epoch");
                    }
                    incoming_snapshot.reset();
                    incoming_rect.reset();
                    if (poisoned_raw_rect_epoch &&
                        header.representation_epoch >
                            *poisoned_raw_rect_epoch) {
                        poisoned_raw_rect_epoch.reset();
                    }
                    state.video_liveness_enabled.store(
                        false, std::memory_order_release);
                    reset_epoch = header.representation_epoch;
                    if (decoder) decoder->flush_representation();
                    {
                        std::lock_guard lock(state.mutex);
                        if (state.frame && state.frame->representation_epoch <
                                header.representation_epoch) {
                            state.frame.reset();
                            ++state.frame_revision;
                        }
                    }
                    state.compositor_ready.notify_one();
                    state.enqueue_snapshot_command({
                        .kind = SnapshotCommandKind::cancel,
                        .session_generation = header.session_generation,
                        .representation_epoch = header.representation_epoch,
                        .frame_id = header.frame_id,
                        .rectangles = {},
                        .bytes = {},
                    });
                    continue;
                }
                if (header.type ==
                    rwn::desktop::VisualMessageType::raw_rect) {
                    if (poisoned_raw_rect_epoch &&
                        header.representation_epoch <=
                            *poisoned_raw_rect_epoch) {
                        continue;
                    }
                    if (!raw_rect_experimental || incoming_snapshot ||
                        !pixel_canonical_digest_valid) {
                        poison_raw_rect_transaction(
                            header.representation_epoch,
                            L"RAW_RECT rejected outside experimental exact mode");
                        continue;
                    }
                    const auto transition = !pixel_representation ||
                        *pixel_representation !=
                            rwn::desktop::VisualRepresentation::rect;
                    if (transition &&
                        (!reset_epoch || *reset_epoch !=
                            header.representation_epoch)) {
                        poison_raw_rect_transaction(
                            header.representation_epoch,
                            L"RAW_RECT transition missing STATE_RESET");
                        continue;
                    }
                    if (!transition && header.representation_epoch !=
                            pixel_representation_epoch) {
                        poison_raw_rect_transaction(
                            header.representation_epoch,
                            L"RAW_RECT epoch mismatch; recovery requested");
                        continue;
                    }
                    auto rectangle =
                        rwn::desktop::decode_visual_raw_rect(payload);
                    if (!incoming_rect) {
                        incoming_rect = IncomingRect{
                            .session_generation = header.session_generation,
                            .representation_epoch = header.representation_epoch,
                            .base_frame_id = rectangle.base_frame_id,
                            .target_frame_id = header.frame_id,
                            .guard = {},
                            .rectangles = {},
                        };
                    }
                    if (incoming_rect->base_frame_id != pixel_frame_id ||
                        !incoming_rect->guard.accept(header, rectangle)) {
                        poison_raw_rect_transaction(
                            header.representation_epoch,
                            L"RAW_RECT transaction mismatch; recovery requested");
                        continue;
                    }
                    incoming_rect->rectangles.push_back(std::move(rectangle));
                    continue;
                }
                if (header.type ==
                    rwn::desktop::VisualMessageType::full_snapshot) {
                    auto chunk =
                        rwn::desktop::decode_visual_full_snapshot_chunk(payload);
                    if (!reset_epoch || *reset_epoch !=
                            header.representation_epoch) {
                        recover_snapshot(
                            L"Snapshot missing STATE_RESET; recovery requested");
                        continue;
                    }
                    if (!incoming_snapshot) {
                        if (chunk.chunk_offset != 0) {
                            recover_snapshot(
                                L"Snapshot offset mismatch; recovery requested");
                            continue;
                        }
                        incoming_snapshot = IncomingSnapshot{
                            .session_generation = header.session_generation,
                            .representation_epoch = header.representation_epoch,
                            .frame_id = header.frame_id,
                            .width = chunk.surface_width,
                            .height = chunk.surface_height,
                            .total_bytes = chunk.total_bytes,
                            .next_offset = 0,
                            .gpu_upload_offset = 0,
                            .gpu_upload_bytes = {},
                            .canonical_hash = {},
                        };
                        state.enqueue_snapshot_command({
                            .kind = SnapshotCommandKind::begin,
                            .session_generation = header.session_generation,
                            .representation_epoch = header.representation_epoch,
                            .frame_id = header.frame_id,
                            .width = chunk.surface_width,
                            .height = chunk.surface_height,
                            .rectangles = {},
                            .bytes = {},
                        });
                    }
                    const auto& active = *incoming_snapshot;
                    if (active.session_generation != header.session_generation ||
                        active.representation_epoch !=
                            header.representation_epoch ||
                        active.frame_id != header.frame_id ||
                        active.width != chunk.surface_width ||
                        active.height != chunk.surface_height ||
                        active.total_bytes != chunk.total_bytes ||
                        active.next_offset != chunk.chunk_offset) {
                        recover_snapshot(
                            L"Snapshot transaction mismatch; recovery requested");
                        continue;
                    }
                    incoming_snapshot->next_offset +=
                        static_cast<std::uint32_t>(chunk.chunk.size());
                    incoming_snapshot->canonical_hash.update(chunk.chunk);
                    const auto upload_limit = rwn::desktop::snapshot_upload_batch_size(
                        static_cast<std::size_t>(active.width) * 4U,
                        snapshot_gpu_upload_batch_bytes);
                    std::size_t consumed{};
                    while (consumed < chunk.chunk.size()) {
                        if (incoming_snapshot->gpu_upload_bytes.empty()) {
                            incoming_snapshot->gpu_upload_offset = chunk.chunk_offset +
                                static_cast<std::uint32_t>(consumed);
                        }
                        const auto count = std::min(chunk.chunk.size() - consumed,
                            upload_limit - incoming_snapshot->gpu_upload_bytes.size());
                        incoming_snapshot->gpu_upload_bytes.insert(
                            incoming_snapshot->gpu_upload_bytes.end(),
                            chunk.chunk.begin() + static_cast<std::ptrdiff_t>(consumed),
                            chunk.chunk.begin() + static_cast<std::ptrdiff_t>(consumed + count));
                        consumed += count;
                        const bool complete = incoming_snapshot->next_offset ==
                            incoming_snapshot->total_bytes && consumed == chunk.chunk.size();
                        if (incoming_snapshot->gpu_upload_bytes.size() != upload_limit &&
                            !complete) continue;
                        state.enqueue_snapshot_command({
                            .kind = SnapshotCommandKind::chunk,
                            .session_generation = header.session_generation,
                            .representation_epoch =
                                header.representation_epoch,
                            .frame_id = header.frame_id,
                            .chunk_offset =
                                incoming_snapshot->gpu_upload_offset,
                            .rectangles = {},
                            .bytes = std::move(
                                incoming_snapshot->gpu_upload_bytes),
                        });
                        incoming_snapshot->gpu_upload_bytes.clear();
                    }
                    continue;
                }
                if (header.type ==
                    rwn::desktop::VisualMessageType::frame_commit) {
                    const auto commit =
                        rwn::desktop::decode_visual_frame_commit(payload);
                    if (incoming_rect) {
                        if (!incoming_rect->guard.ready_to_commit(
                                header, commit)) {
                            poison_raw_rect_transaction(
                                header.representation_epoch,
                                L"Incomplete RAW_RECT commit; recovery requested");
                            continue;
                        }
                        const auto digest =
                            rwn::desktop::advance_canonical_rect_digest(
                                pixel_canonical_digest, header.frame_id,
                                incoming_rect->rectangles);
                        if (auto lifecycle = state.ensure_lifecycle(
                                header.session_generation)) {
                            lifecycle->record(
                                rwn::desktop::VisualLifecycleStage::
                                    raw_rect_receive,
                                header.frame_id, steady_timestamp_us(),
                                rwn::desktop::VisualTraceEvent{
                                    .representation_epoch =
                                        header.representation_epoch,
                                    .payload_bytes =
                                        incoming_rect->guard.packed_bytes(),
                                    .rectangle_count = static_cast<std::uint32_t>(
                                        incoming_rect->rectangles.size()),
                                });
                        }
                        state.enqueue_snapshot_command({
                            .kind = SnapshotCommandKind::rect_transaction,
                            .session_generation = header.session_generation,
                            .representation_epoch = header.representation_epoch,
                            .frame_id = header.frame_id,
                            .base_frame_id = commit.base_frame_id,
                            .canonical_sha256 = digest,
                            .rectangles = std::move(
                                incoming_rect->rectangles),
                            .bytes = {},
                        });
                        pixel_representation_epoch =
                            header.representation_epoch;
                        pixel_representation =
                            rwn::desktop::VisualRepresentation::rect;
                        pixel_frame_id = header.frame_id;
                        pixel_canonical_digest = digest;
                        reset_epoch.reset();
                        incoming_rect.reset();
                        continue;
                    }
                    if (!incoming_snapshot ||
                        incoming_snapshot->session_generation !=
                            header.session_generation ||
                        incoming_snapshot->representation_epoch !=
                            header.representation_epoch ||
                        incoming_snapshot->frame_id != header.frame_id ||
                        incoming_snapshot->next_offset !=
                            incoming_snapshot->total_bytes ||
                        !incoming_snapshot->gpu_upload_bytes.empty() ||
                        commit.base_frame_id != 0) {
                        recover_snapshot(
                            L"Incomplete snapshot commit; recovery requested");
                        continue;
                    }
                    const auto digest =
                        incoming_snapshot->canonical_hash.finish();
                    state.enqueue_snapshot_command({
                        .kind = SnapshotCommandKind::commit,
                        .session_generation = header.session_generation,
                        .representation_epoch = header.representation_epoch,
                        .frame_id = header.frame_id,
                        .width = incoming_snapshot->width,
                        .height = incoming_snapshot->height,
                        .canonical_sha256 = digest,
                        .rectangles = {},
                        .bytes = {},
                    });
                    pixel_representation_epoch = header.representation_epoch;
                    pixel_representation =
                        rwn::desktop::VisualRepresentation::snapshot;
                    pixel_frame_id = header.frame_id;
                    pixel_canonical_digest = digest;
                    pixel_canonical_digest_valid = true;
                    state.video_liveness_enabled.store(
                        false, std::memory_order_release);
                    reset_epoch.reset();
                    incoming_snapshot.reset();
                    continue;
                }
                if (header.type !=
                    rwn::desktop::VisualMessageType::h264_access_unit) {
                    state.set_status(L"RWV2 message remains frozen in this milestone");
                    continue;
                }
                if (!decoder) {
                    throw std::runtime_error(
                        "exact visual mode received an H.264 access unit");
                }
                if (incoming_snapshot) {
                    incoming_snapshot.reset();
                    state.enqueue_snapshot_command({
                        .kind = SnapshotCommandKind::cancel,
                        .rectangles = {},
                        .bytes = {},
                    });
                }
                if (incoming_rect) {
                    incoming_rect.reset();
                    state.enqueue_snapshot_command({
                        .kind = SnapshotCommandKind::cancel,
                        .representation_epoch = header.representation_epoch,
                        .rectangles = {},
                        .bytes = {},
                    });
                }
                const auto transition = !pixel_representation ||
                    *pixel_representation !=
                        rwn::desktop::VisualRepresentation::video ||
                    header.representation_epoch !=
                        pixel_representation_epoch;
                if (transition) {
                    if (pixel_representation &&
                        (!reset_epoch || *reset_epoch !=
                            header.representation_epoch)) {
                        throw std::runtime_error(
                            "video transition is missing STATE_RESET");
                    }
                    if ((header.flags &
                         rwn::desktop::visual_flag_keyframe) == 0) {
                        throw std::runtime_error(
                            "video transition did not begin with IDR");
                    }
                    pixel_representation =
                        rwn::desktop::VisualRepresentation::video;
                    pixel_representation_epoch = header.representation_epoch;
                    pixel_canonical_digest_valid = false;
                    pixel_frame_id = header.frame_id;
                    reset_epoch.reset();
                    state.video_liveness_enabled.store(
                        true, std::memory_order_release);
                } else if (header.representation_epoch !=
                           pixel_representation_epoch) {
                    throw std::runtime_error(
                        "video epoch changed without representation reset");
                }
                auto access_unit =
                    rwn::desktop::decode_visual_h264_access_unit(payload);
                frame_session_generation = header.session_generation;
                encoded = {
                    .frame_id = header.frame_id,
                    .representation_epoch = header.representation_epoch,
                    .captured_at_us = header.captured_at_us,
                    .width = access_unit.width,
                    .height = access_unit.height,
                    .codec = rwn::desktop::VideoCodec::h264,
                    .keyframe =
                        (header.flags & rwn::desktop::visual_flag_keyframe) != 0,
                    .encoded = std::move(access_unit.encoded),
                };
            } else {
                if (!state.read_visual(wire)) break;
                const auto header =
                    rwn::desktop::decode_encoded_preview_frame_header(wire);
                encoded = {
                    .frame_id = header.frame_id,
                    .captured_at_us = header.captured_at_us,
                    .width = header.width,
                    .height = header.height,
                    .codec = rwn::desktop::VideoCodec::h264,
                    .keyframe = header.keyframe,
                    .encoded = std::vector<std::byte>(header.payload_size),
                };
                if (!state.read_visual(encoded.encoded)) break;
            }
            const auto received_at_us = steady_timestamp_us();
            auto lifecycle = state.ensure_lifecycle(frame_session_generation);
            if (lifecycle) {
                lifecycle->record(
                    rwn::desktop::VisualLifecycleStage::wire_receive,
                    encoded.frame_id, received_at_us);
            }
            ++report_received;
            report_bytes += wire.size() + encoded.encoded.size();
            const auto decode_started = std::chrono::steady_clock::now();
            receive_to_submit_ms.push_back(
                static_cast<double>(steady_timestamp_us() - received_at_us) /
                1000.0);
            auto decoded = decoder->submit_nv12(encoded);
            const auto queue_depths = decoder->queue_depths();
            maximum_mf_lineage = std::max(
                maximum_mf_lineage, queue_depths.compressed_lineage);
            maximum_mf_ready = std::max(
                maximum_mf_ready, queue_depths.decoded_ready);
            mf_low_latency = queue_depths.low_latency_enabled;
            mf_d3d11_output = queue_depths.d3d11_output_active;
            const auto decode_finished = std::chrono::steady_clock::now();
            decode_ms.push_back(
                std::chrono::duration<double, std::milli>(
                    decode_finished - decode_started).count());
            if (!decoded) continue;
            ++report_decoded;
            if (lifecycle) {
                lifecycle->record(
                    rwn::desktop::VisualLifecycleStage::mf_output,
                    decoded->frame_id, steady_timestamp_us());
            }
            auto next = std::make_shared<const DisplayFrame>(DisplayFrame{
                .nv12 = std::move(*decoded),
                .decoded_ready_at_us = steady_timestamp_us(),
                .session_generation = frame_session_generation,
                .representation_epoch = decoded->representation_epoch,
                .keyframe = decoded->keyframe,
            });
            const auto now = std::chrono::steady_clock::now();
            const auto local_us =
                std::chrono::duration_cast<std::chrono::microseconds>(
                    now.time_since_epoch()).count();
            const auto clock_delta = local_us -
                static_cast<std::int64_t>(next->nv12.captured_at_us);
            minimum_clock_delta = std::min(minimum_clock_delta, clock_delta);
            const auto frame_age_ms = std::max<std::int64_t>(
                0, (clock_delta - minimum_clock_delta) / 1000);
            dynamic_frame_age_ms.push_back(
                static_cast<double>(frame_age_ms));
            const auto report_elapsed = now - report_started;
            const auto report_due = report_elapsed >= std::chrono::seconds{1};
            {
                std::lock_guard lock(state.mutex);
                if (state.frame_revision != state.rendered_revision.load(
                        std::memory_order_acquire)) {
                    state.decoded_replacements.fetch_add(
                        1, std::memory_order_relaxed);
                }
                state.frame = std::move(next);
                ++state.frame_revision;
                state.status = state.interactive
                    ? L"Live interactive preview"
                    : L"Live view-only preview";
                if (report_due) {
                    const auto elapsed_seconds =
                        std::chrono::duration<double>(report_elapsed).count();
                    const auto rendered = state.rendered_frames.load(
                        std::memory_order_relaxed);
                    const auto replacements = state.decoded_replacements.load(
                        std::memory_order_relaxed);
                    std::wostringstream title;
                    title << std::fixed << std::setprecision(1)
                          << L"Remote Workspace Viewer ["
                          << (state.interactive ? L"CONTROL" : L"VIEW ONLY")
                          << L"] - "
                          << state.frame->nv12.width << L"x"
                          << state.frame->nv12.height
                          << L" RX " << static_cast<double>(report_received) /
                                                elapsed_seconds
                          << L" Decode " << static_cast<double>(report_decoded) /
                                                    elapsed_seconds
                          << L" Render "
                          << static_cast<double>(rendered - last_rendered) /
                                 elapsed_seconds
                          << L" FPS | age+ p50/p95/max "
                          << percentile_ms(dynamic_frame_age_ms, 0.50)
                          << L"/"
                          << percentile_ms(dynamic_frame_age_ms, 0.95)
                          << L"/" << maximum_ms(dynamic_frame_age_ms)
                          << L" ms | decode p50/p95 "
                          << percentile_ms(decode_ms, 0.50) << L"/"
                          << percentile_ms(decode_ms, 0.95)
                          << L"/" << maximum_ms(decode_ms)
                          << L" ms | recv-submit p95 "
                          << percentile_ms(receive_to_submit_ms, 0.95)
                          << L" ms | ready-present p50/p95/max "
                          << percentile_ms(
                                 state.decoded_ready_to_present_ms, 0.50)
                          << L"/" << percentile_ms(
                                 state.decoded_ready_to_present_ms, 0.95)
                          << L"/" << maximum_ms(
                                 state.decoded_ready_to_present_ms)
                          << L" ms | drop-display "
                          << replacements - last_replacements
                          << L" | MF lineage/ready max "
                          << maximum_mf_lineage << L"/" << maximum_mf_ready
                          << L" low-latency=" << mf_low_latency
                          << L" output="
                          << (mf_d3d11_output ? L"d3d11" : L"cpu")
                          << L" | "
                          << static_cast<double>(report_bytes) * 8.0 /
                                  elapsed_seconds / 1'000'000.0
                          << L" Mbps";
                    title << L" | scale="
                          << (state.one_to_one_scale.load(
                                  std::memory_order_relaxed)
                                  ? L"1:1" : L"fit");
                    title << L" | present="
                          << (state.renderer->present_mode() ==
                                      rwn::viewer::D3D11PresentMode::extreme
                                  ? L"extreme" : L"balanced");
                    if (visual_protocol) {
                        title << L" | RWV2 cursor="
                              << state.remote_cursor.x << L","
                              << state.remote_cursor.y
                              << L" messages=" << state.remote_cursor_messages
                              << L" age p95="
                              << percentile_ms(
                                     state.remote_cursor_age_ms, 0.95)
                              << L" ms";
                        title << L" snapshot commits/cancels="
                              << state.snapshot_commits.load() << L"/"
                              << state.snapshot_cancels.load()
                              << L" commit-ack="
                              << static_cast<double>(
                                  state.snapshot_commit_to_ack_us.load()) /
                                     1000.0
                              << L" ms rect commits/cancels="
                              << state.rect_commits.load() << L"/"
                              << state.rect_cancels.load()
                              << L" rect commit-ack="
                              << static_cast<double>(
                                  state.rect_commit_to_ack_us.load()) /
                                  1000.0
                              << L" ms";
                        state.remote_cursor_age_ms.clear();
                    }
                    if (!state.remote_metrics.empty()) {
                        title << L" | " << state.remote_metrics;
                    }
                    if (!state.snapshot_metrics.empty()) {
                        title << L" | " << state.snapshot_metrics;
                    }
                    if (state.visual_trace_enabled) {
                        const auto tracker = state.current_lifecycle();
                        const auto snapshot = tracker
                            ? tracker->snapshot()
                            : rwn::desktop::VisualLifecycleSnapshot{};
                        title << L" | trace dropped="
                              << state.trace_queue->dropped_events() +
                                     state.trace_write_dropped.load()
                              << L" invalid=" << state.trace_invalid.load()
                              << L" gen rx/dec/commit/present="
                              << snapshot.received_generation << L"/"
                              << snapshot.decoded_generation << L"/"
                              << snapshot.committed_generation << L"/"
                              << snapshot.present_submitted_generation;
                    }
                    state.title = title.str();
                    last_rendered = rendered;
                    last_replacements = replacements;
                    state.decoded_ready_to_present_ms.clear();
                }
            }
            state.compositor_ready.notify_one();
            if (report_due) {
                report_started = now;
                report_received = 0;
                report_decoded = 0;
                report_bytes = 0;
                decode_ms.clear();
                receive_to_submit_ms.clear();
                dynamic_frame_age_ms.clear();
                maximum_mf_lineage = 0;
                maximum_mf_ready = 0;
                PostMessageW(state.window, status_changed_message, 0, 0);
            }
        }
        if (!state.stopping && (incoming_snapshot || incoming_rect)) {
            // EOF may cut a payload short after earlier chunks reached the GPU.
            // Cancel explicitly rather than relying on the snapshot watchdog;
            // the disconnected transport cannot service a recovery request.
            state.enqueue_snapshot_command({
                .kind = SnapshotCommandKind::cancel,
                .rectangles = {},
                .bytes = {},
            });
        }
        if (!state.stopping) {
            state.set_status(L"Mac preview stream ended");
            if (state.tls) state.tls_runtime_failed.store(true);
        }
        if (state.tls) state.tls->cancel();
    } catch (const std::exception& error) {
        if (state.tls && !state.stopping) {
            state.tls_runtime_failed.store(true);
            std::cerr << "tls_runtime_error stage=visual_read reason=" << error.what() << '\n';
        }
        if (!state.stopping) {
            try {
                state.enqueue_snapshot_command({
                    .kind = SnapshotCommandKind::cancel,
                    .rectangles = {},
                    .bytes = {},
                });
            } catch (const std::exception&) {
                // Preserve fail-closed parsing even if the bounded command
                // queue cannot accept cancellation; watchdog/close still owns
                // disposal and must never commit an incomplete upload.
            }
        }
        state.set_status(utf8_to_utf16(error.what()));
        if (state.tls) state.tls->cancel();
    }
}

void error_reader_loop(ViewerState& state) {
    std::array<char, 1024> buffer{};
    std::string pending;
    std::string errors;
    constexpr std::string_view trace_prefix{"RWN_VISUAL_TRACE "};
    constexpr std::string_view snapshot_prefix{"RWN_SNAPSHOT "};
    bool discard_overlong_line{};
    while (!state.stopping) {
        DWORD received{};
        if (!ReadFile(
                state.error_read, buffer.data(), static_cast<DWORD>(buffer.size()),
                &received, nullptr) || received == 0) {
            break;
        }
        if (discard_overlong_line) {
            const std::string_view incoming(buffer.data(), received);
            const auto newline = incoming.find('\n');
            if (newline == std::string_view::npos) continue;
            discard_overlong_line = false;
            pending.append(incoming.substr(newline + 1U));
        } else {
            pending.append(buffer.data(), received);
        }
        for (auto newline = pending.find('\n'); newline != std::string::npos;
             newline = pending.find('\n')) {
            auto line = pending.substr(0, newline);
            pending.erase(0, newline + 1U);
            if (line.ends_with('\r')) line.pop_back();
            if (line.starts_with(trace_prefix)) {
                try {
                    if (line.size() - trace_prefix.size() >
                        rwn::desktop::maximum_visual_trace_line_bytes) {
                        throw std::length_error(
                            "remote visual trace line exceeds limit");
                    }
                    state.enqueue_remote_trace(
                        std::string_view(line).substr(trace_prefix.size()));
                } catch (const std::exception& error) {
                    state.trace_invalid.store(true);
                    state.set_status(utf8_to_utf16(error.what()));
                }
            } else if (line.starts_with("RWN_METRICS ")) {
                {
                    std::lock_guard lock(state.mutex);
                    state.remote_metrics = utf8_to_utf16(line);
                }
                PostMessageW(state.window, status_changed_message, 0, 0);
            } else if (line.starts_with(snapshot_prefix)) {
                {
                    std::lock_guard lock(state.mutex);
                    state.snapshot_metrics = utf8_to_utf16(line);
                }
                state.set_status(utf8_to_utf16(line));
            } else if (!line.empty()) {
                errors += line + '\n';
                if (errors.size() > 4096U) {
                    errors.erase(0, errors.size() - 4096U);
                }
            }
        }
        if (pending.size() >
            trace_prefix.size() +
                rwn::desktop::maximum_visual_trace_line_bytes) {
            pending.clear();
            discard_overlong_line = true;
            state.trace_invalid.store(true);
            state.set_status(L"Remote visual trace line exceeds limit");
        }
    }
    errors += pending;
    if (!errors.empty() && !state.stopping) {
        state.set_status(utf8_to_utf16(errors));
    }
}

void start_ssh(
    ViewerState& state, const std::wstring& host,
    const std::filesystem::path& identity,
    const std::wstring& remote_agent, const std::uint32_t maximum_width,
    const std::uint32_t maximum_height,
    const std::uint32_t frames_per_second,
    const std::uint32_t bitrate_kbps,
    const std::wstring_view vt_mode,
    const bool visual_protocol,
    const bool dirty_analysis,
    const bool visual_trace,
    const bool interactive,
    const bool raw_rect_experimental,
    const bool h264_only_explicit,
    const bool snapshot_only_explicit,
    const bool exact_only) {
    const std::filesystem::path ssh =
        L"C:\\Windows\\System32\\OpenSSH\\ssh.exe";
    if (!std::filesystem::is_regular_file(ssh)) {
        throw std::runtime_error("Windows OpenSSH client is not installed");
    }
    if (!identity.is_absolute() || !std::filesystem::is_regular_file(identity)) {
        throw std::invalid_argument("SSH identity must be an existing absolute file");
    }
    if (!safe_remote_token(host, false) || !safe_remote_token(remote_agent, true)) {
        throw std::invalid_argument("unsafe SSH host or remote agent path");
    }
    if (vt_mode != L"baseline" && vt_mode != L"low-latency" &&
        vt_mode != L"delay-1" && vt_mode != L"delay-0") {
        throw std::invalid_argument("invalid VideoToolbox latency mode");
    }

    SECURITY_ATTRIBUTES security{
        .nLength = sizeof(SECURITY_ATTRIBUTES),
        .lpSecurityDescriptor = nullptr,
        .bInheritHandle = TRUE,
    };
    HANDLE output_write{};
    HANDLE error_write{};
    HANDLE child_input{};
    if (!CreatePipe(&state.output_read, &output_write, &security, 0) ||
        !CreatePipe(&state.error_read, &error_write, &security, 0)) {
        throw std::runtime_error("create SSH pipe failed");
    }
    SetHandleInformation(state.output_read, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(state.error_read, HANDLE_FLAG_INHERIT, 0);
    if (interactive) {
        if (!CreatePipe(
                &child_input, &state.input_write, &security, 0)) {
            CloseHandle(output_write);
            CloseHandle(error_write);
            throw std::runtime_error("create SSH input pipe failed");
        }
        SetHandleInformation(state.input_write, HANDLE_FLAG_INHERIT, 0);
    } else {
        child_input = CreateFileW(
            L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    if (child_input == INVALID_HANDLE_VALUE || child_input == nullptr) {
        CloseHandle(output_write);
        CloseHandle(error_write);
        throw std::runtime_error("open null input failed");
    }

    std::wstring command = quote_windows_argument(ssh.native());
    command += L" -T -o BatchMode=yes -o IdentitiesOnly=yes "
               L"-o StrictHostKeyChecking=yes -o ConnectTimeout=10 -i ";
    command += quote_windows_argument(identity.native());
    command += L" ";
    command += host;
    command += L" ";
    command += remote_agent;
    command += interactive && visual_trace
        ? L" --stream-visual-interactive-trace-stdio "
        : interactive ? L" --stream-visual-interactive-stdio "
        : visual_trace ? L" --stream-visual-trace-stdio "
        : dirty_analysis
        ? L" --stream-visual-analyze-stdio "
        : visual_protocol ? L" --stream-visual-stdio "
                          : L" --stream-h264-stdio ";
    command += std::to_wstring(maximum_width);
    command += L" ";
    command += std::to_wstring(maximum_height);
    command += L" ";
    command += std::to_wstring(frames_per_second);
    command += L" ";
    command += std::to_wstring(bitrate_kbps);
    command += L" ";
    command += vt_mode;
    if (raw_rect_experimental) {
        command += exact_only ? L" exact-only" : L" raw-rect-experimental";
    } else if (h264_only_explicit) {
        command += L" h264-only";
    } else if (snapshot_only_explicit) {
        command += L" snapshot-only";
    }

    STARTUPINFOW startup{};
    startup.cb = sizeof(STARTUPINFOW);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = child_input;
    startup.hStdOutput = output_write;
    startup.hStdError = error_write;
    PROCESS_INFORMATION process{};
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');
    const auto created = CreateProcessW(
        ssh.c_str(), mutable_command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);
    CloseHandle(child_input);
    CloseHandle(output_write);
    CloseHandle(error_write);
    if (!created) {
        if (state.input_write != nullptr) {
            CloseHandle(state.input_write);
            state.input_write = nullptr;
        }
        throw std::runtime_error("start SSH preview process failed");
    }
    CloseHandle(process.hThread);
    state.ssh_process = process.hProcess;
    state.interactive = interactive;
    if (interactive) {
        state.control_writer = std::jthread(
            [&state] { control_writer_loop(state); });
    }
    state.frame_reader = std::jthread(
        [&state, visual_protocol, raw_rect_experimental, exact_only] {
            frame_reader_loop(
                state, visual_protocol, raw_rect_experimental, exact_only);
        });
    state.error_reader = std::jthread([&state] { error_reader_loop(state); });
}

std::optional<std::pair<std::uint16_t, std::uint16_t>>
map_client_pointer_to_surface(
    ViewerState& state, const HWND window,
    const LONG client_x, const LONG client_y) {
    std::uint32_t surface_width{};
    std::uint32_t surface_height{};
    {
        std::lock_guard lock(state.mutex);
        if (state.frame) {
            surface_width = state.frame->nv12.width;
            surface_height = state.frame->nv12.height;
        }
    }
    if (surface_width == 0 || surface_height == 0) {
        surface_width = state.exact_surface_width.load(
            std::memory_order_acquire);
        surface_height = state.exact_surface_height.load(
            std::memory_order_acquire);
    }
    if (surface_width == 0 || surface_height == 0) return std::nullopt;
    RECT client{};
    GetClientRect(window, &client);
    const auto client_width = std::max<LONG>(1, client.right - client.left);
    const auto client_height = std::max<LONG>(1, client.bottom - client.top);
    const auto one_to_one = state.one_to_one_scale.load(
        std::memory_order_relaxed);
    const auto scale = one_to_one &&
            client_width >= static_cast<LONG>(surface_width) &&
            client_height >= static_cast<LONG>(surface_height)
        ? 1.0
        : std::min(
            static_cast<double>(client_width) / surface_width,
            static_cast<double>(client_height) / surface_height);
    const auto content_width = static_cast<double>(surface_width) * scale;
    const auto content_height = static_cast<double>(surface_height) * scale;
    const auto offset_x =
        (static_cast<double>(client_width) - content_width) / 2.0;
    const auto offset_y =
        (static_cast<double>(client_height) - content_height) / 2.0;
    if (client_x < offset_x || client_y < offset_y ||
        client_x >= offset_x + content_width ||
        client_y >= offset_y + content_height) {
        return std::nullopt;
    }
    const auto source_x = std::clamp(
        (static_cast<double>(client_x) - offset_x) / scale,
        0.0, static_cast<double>(surface_width - 1U));
    const auto source_y = std::clamp(
        (static_cast<double>(client_y) - offset_y) / scale,
        0.0, static_cast<double>(surface_height - 1U));
    return std::pair{
        static_cast<std::uint16_t>(
            source_x * 65535.0 /
            static_cast<double>(std::max(1U, surface_width - 1U))),
        static_cast<std::uint16_t>(
            source_y * 65535.0 /
            static_cast<double>(std::max(1U, surface_height - 1U))),
    };
}

void enqueue_input_safely(
    ViewerState& state, rwn::desktop::InputEvent event) {
    try {
        state.enqueue_input(std::move(event));
    } catch (const std::exception& error) {
        state.set_status(utf8_to_utf16(error.what()));
    }
}

class FocusedKeyboardCapture final {
public:
    explicit FocusedKeyboardCapture(const HWND window) : window_(window) {
        if (active_ != nullptr) {
            throw std::logic_error("keyboard capture is already active");
        }
        active_ = this;
        hook_ = SetWindowsHookExW(
            WH_KEYBOARD_LL, &FocusedKeyboardCapture::hook_callback,
            GetModuleHandleW(nullptr), 0);
        if (hook_ == nullptr) {
            active_ = nullptr;
            throw std::runtime_error("install focused keyboard capture failed");
        }
    }

    ~FocusedKeyboardCapture() {
        if (hook_ != nullptr) UnhookWindowsHookEx(hook_);
        if (active_ == this) active_ = nullptr;
    }

    FocusedKeyboardCapture(const FocusedKeyboardCapture&) = delete;
    FocusedKeyboardCapture& operator=(const FocusedKeyboardCapture&) = delete;

private:
    static LRESULT CALLBACK hook_callback(
        const int code, const WPARAM message, const LPARAM detail) {
        if (code < HC_ACTION || active_ == nullptr) {
            return CallNextHookEx(nullptr, code, message, detail);
        }
        return active_->handle(message, detail);
    }

    LRESULT handle(const WPARAM message, const LPARAM detail) {
        const auto pressed = message == WM_KEYDOWN || message == WM_SYSKEYDOWN;
        const auto released = message == WM_KEYUP || message == WM_SYSKEYUP;
        if (!pressed && !released) {
            return CallNextHookEx(hook_, HC_ACTION, message, detail);
        }
        const auto* key = reinterpret_cast<const KBDLLHOOKSTRUCT*>(detail);
        update_modifier_state(key->vkCode, pressed);
        if (GetForegroundWindow() != window_) {
            return CallNextHookEx(hook_, HC_ACTION, message, detail);
        }
        auto* state = reinterpret_cast<ViewerState*>(
            GetWindowLongPtrW(window_, GWLP_USERDATA));
        if (state == nullptr || !state->interactive) {
            return CallNextHookEx(hook_, HC_ACTION, message, detail);
        }

        // This is the only local keyboard escape while interactive capture is
        // focused. All other keyboard input, including Windows shortcuts, is
        // consumed locally and forwarded to the Mac.
        if (pressed && key->vkCode == VK_F12 && control_down_ &&
            alt_down_ && shift_down_) {
            PostMessageW(window_, WM_CLOSE, 0, 0);
            return 1;
        }

        const auto raw_flags = static_cast<std::uint16_t>(
            (key->flags & LLKHF_EXTENDED) != 0 ? RI_KEY_E0 : 0);
        if (const auto usage =
                rwn::platform::windows::map_windows_raw_keyboard_to_hid_usage(
                    static_cast<std::uint16_t>(key->scanCode), raw_flags,
                    static_cast<std::uint16_t>(key->vkCode))) {
            enqueue_input_safely(*state, {
                .kind = rwn::desktop::InputKind::raw_key,
                .value_a = *usage,
                .pressed = pressed,
                .text = {},
            });
        }
        return 1;
    }

    void update_modifier_state(const DWORD virtual_key, const bool pressed) {
        switch (virtual_key) {
            case VK_CONTROL:
            case VK_LCONTROL:
            case VK_RCONTROL: control_down_ = pressed; break;
            case VK_MENU:
            case VK_LMENU:
            case VK_RMENU: alt_down_ = pressed; break;
            case VK_SHIFT:
            case VK_LSHIFT:
            case VK_RSHIFT: shift_down_ = pressed; break;
            default: break;
        }
    }

    static inline FocusedKeyboardCapture* active_{};
    HWND window_{};
    HHOOK hook_{};
    bool control_down_{};
    bool alt_down_{};
    bool shift_down_{};
};

LRESULT CALLBACK window_procedure(
    const HWND window, const UINT message, const WPARAM wparam,
    const LPARAM lparam) {
    auto* state = reinterpret_cast<ViewerState*>(
        GetWindowLongPtrW(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lparam);
        state = static_cast<ViewerState*>(create->lpCreateParams);
        state->window = window;
        SetWindowLongPtrW(
            window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
    }
    switch (message) {
        case WM_NCHITTEST: {
            const auto hit = DefWindowProcW(window, message, wparam, lparam);
            // Keep the four corner grips, but do not allow single-axis stretch.
            if (hit == HTLEFT || hit == HTRIGHT ||
                hit == HTTOP || hit == HTBOTTOM) return HTBORDER;
            return hit;
        }
        case WM_GETMINMAXINFO: {
            const auto dpi = GetDpiForWindow(window);
            RECT minimum{0, 0, MulDiv(480, static_cast<int>(dpi), 96),
                         MulDiv(270, static_cast<int>(dpi), 96)};
            AdjustWindowRectExForDpi(&minimum,
                static_cast<DWORD>(GetWindowLongPtrW(window, GWL_STYLE)),
                FALSE, 0, dpi);
            auto* limits = reinterpret_cast<MINMAXINFO*>(lparam);
            limits->ptMinTrackSize = {
                minimum.right - minimum.left, minimum.bottom - minimum.top};
            return 0;
        }
        case WM_SIZING: {
            if (wparam != WMSZ_TOPLEFT && wparam != WMSZ_TOPRIGHT &&
                wparam != WMSZ_BOTTOMLEFT && wparam != WMSZ_BOTTOMRIGHT) {
                return FALSE;
            }
            double ratio = 16.0 / 9.0;
            if (state != nullptr) {
                std::lock_guard lock(state->mutex);
                if (state->frame && state->frame->nv12.height != 0) {
                    ratio = static_cast<double>(state->frame->nv12.width) /
                        state->frame->nv12.height;
                } else {
                    const auto width = state->exact_surface_width.load();
                    const auto height = state->exact_surface_height.load();
                    if (width && height) ratio = static_cast<double>(width) / height;
                }
            }
            const auto dpi = GetDpiForWindow(window);
            RECT border{};
            AdjustWindowRectExForDpi(&border,
                static_cast<DWORD>(GetWindowLongPtrW(window, GWL_STYLE)),
                FALSE, 0, dpi);
            const auto border_width = border.right - border.left;
            const auto border_height = border.bottom - border.top;
            auto& bounds = *reinterpret_cast<RECT*>(lparam);
            const auto width = bounds.right - bounds.left - border_width;
            const auto height = bounds.bottom - bounds.top - border_height;
            // Project the cursor's proposed client size onto the aspect diagonal.
            const auto min_height = std::max(
                static_cast<double>(MulDiv(270, static_cast<int>(dpi), 96)),
                MulDiv(480, static_cast<int>(dpi), 96) / ratio);
            const auto fitted_height = std::max(min_height,
                (static_cast<double>(width) * ratio + height) / (ratio * ratio + 1.0));
            const auto outer_width = static_cast<LONG>(std::lround(fitted_height * ratio)) + border_width;
            const auto outer_height = static_cast<LONG>(std::lround(fitted_height)) + border_height;
            if (wparam == WMSZ_TOPLEFT || wparam == WMSZ_BOTTOMLEFT)
                bounds.left = bounds.right - outer_width;
            else bounds.right = bounds.left + outer_width;
            if (wparam == WMSZ_TOPLEFT || wparam == WMSZ_TOPRIGHT)
                bounds.top = bounds.bottom - outer_height;
            else bounds.bottom = bounds.top + outer_height;
            return TRUE;
        }
        case WM_SIZE:
            if (state != nullptr && wparam != SIZE_MINIMIZED) {
                {
                    std::lock_guard lock(state->mutex);
                    ++state->frame_revision;
                }
                state->compositor_ready.notify_one();
            }
            return 0;
        case WM_KEYDOWN:
            if (state != nullptr &&
                (GetKeyState(VK_CONTROL) & 0x8000) != 0 &&
                (wparam == L'1' || wparam == L'F')) {
                const auto mode = wparam == L'1'
                    ? rwn::viewer::D3D11ScaleMode::one_to_one
                    : rwn::viewer::D3D11ScaleMode::fit;
                state->renderer->set_scale_mode(mode);
                state->one_to_one_scale.store(
                    mode == rwn::viewer::D3D11ScaleMode::one_to_one,
                    std::memory_order_relaxed);
                {
                    std::lock_guard lock(state->mutex);
                    ++state->frame_revision;
                }
                state->compositor_ready.notify_one();
                return 0;
            }
            break;
        case WM_MOUSEMOVE:
            if (state != nullptr && state->interactive) {
                if (const auto mapped = map_client_pointer_to_surface(
                        *state, window, GET_X_LPARAM(lparam),
                        GET_Y_LPARAM(lparam))) {
                    enqueue_input_safely(*state, {
                        .kind = rwn::desktop::InputKind::pointer_move,
                        .value_a = mapped->first,
                        .value_b = mapped->second,
                        .text = {},
                    });
                }
                return 0;
            }
            break;
        case WM_LBUTTONDOWN:
        case WM_LBUTTONUP:
        case WM_RBUTTONDOWN:
        case WM_RBUTTONUP:
        case WM_MBUTTONDOWN:
        case WM_MBUTTONUP:
            if (state != nullptr && state->interactive) {
                const auto button =
                    message == WM_LBUTTONDOWN || message == WM_LBUTTONUP
                    ? 1U : message == WM_RBUTTONDOWN ||
                               message == WM_RBUTTONUP
                    ? 2U : 3U;
                const auto pressed =
                    message == WM_LBUTTONDOWN ||
                    message == WM_RBUTTONDOWN ||
                    message == WM_MBUTTONDOWN;
                if (pressed) SetCapture(window);
                enqueue_input_safely(*state, {
                    .kind = rwn::desktop::InputKind::pointer_button,
                    .value_a = button,
                    .pressed = pressed,
                    .text = {},
                });
                if (!pressed) ReleaseCapture();
                return 0;
            }
            break;
        case WM_MOUSEWHEEL:
        case WM_MOUSEHWHEEL:
            if (state != nullptr && state->interactive) {
                const auto delta = static_cast<std::int32_t>(
                    GET_WHEEL_DELTA_WPARAM(wparam));
                enqueue_input_safely(*state, {
                    .kind = message == WM_MOUSEHWHEEL
                        ? rwn::desktop::InputKind::horizontal_wheel
                        : rwn::desktop::InputKind::vertical_wheel,
                    .value_a = std::bit_cast<std::uint32_t>(delta),
                    .text = {},
                });
                return 0;
            }
            break;
        case WM_SETFOCUS:
            if (state != nullptr) state->focus_acquired();
            break;
        case WM_ACTIVATEAPP:
            if (state != nullptr && wparam != FALSE) {
                state->focus_acquired();
            } else if (state != nullptr) {
                try {
                    state->release_input_for_focus_loss();
                } catch (const std::exception& error) {
                    state->set_status(utf8_to_utf16(error.what()));
                }
            }
            break;
        case WM_KILLFOCUS:
            if (state != nullptr) {
                try {
                    state->release_input_for_focus_loss();
                } catch (const std::exception& error) {
                    state->set_status(utf8_to_utf16(error.what()));
                }
            }
            break;
        case cursor_changed_message:
            if (state != nullptr && state->interactive) {
                HCURSOR cursor{};
                bool visible{};
                {
                    std::lock_guard lock(state->mutex);
                    cursor = state->current_cursor;
                    visible = state->remote_cursor.visible;
                }
                SetCursor(visible ? cursor : nullptr);
            }
            return 0;
        case WM_SETCURSOR:
            if (state != nullptr && state->interactive &&
                LOWORD(lparam) == HTCLIENT) {
                HCURSOR cursor{};
                bool visible{};
                {
                    std::lock_guard lock(state->mutex);
                    cursor = state->current_cursor;
                    visible = state->remote_cursor.visible;
                }
                SetCursor(visible ? cursor : nullptr);
                return TRUE;
            }
            break;
        case status_changed_message:
            if (state != nullptr) {
                std::wstring title;
                {
                    std::lock_guard lock(state->mutex);
                    title = state->title;
                }
                SetWindowTextW(window, title.c_str());
            }
            InvalidateRect(window, nullptr, FALSE);
            return 0;
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT: {
            PAINTSTRUCT paint{};
            const auto context = BeginPaint(window, &paint);
            RECT client{};
            GetClientRect(window, &client);
            std::shared_ptr<const DisplayFrame> frame;
            std::wstring status;
            if (state != nullptr) {
                std::lock_guard lock(state->mutex);
                frame = state->frame;
                status = state->status;
            }
            if (!frame) {
                FillRect(
                    context, &client,
                    static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
                SetBkMode(context, TRANSPARENT);
                SetTextColor(context, RGB(235, 235, 235));
                DrawTextW(
                    context, status.c_str(),
                    static_cast<int>(status.size()),
                    &client, DT_CENTER | DT_VCENTER | DT_WORDBREAK);
            }
            EndPaint(window, &paint);
            return 0;
        }
        case WM_DESTROY:
            if (state != nullptr) state->stop();
            PostQuitMessage(0);
            return 0;
        case WM_TIMER:
            if (wparam == 0x52574eU) {
                KillTimer(window, wparam);
                PostMessageW(window, WM_CLOSE, 0, 0);
                return 0;
            }
            break;
        default:
            return DefWindowProcW(window, message, wparam, lparam);
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

}  // namespace

int WINAPI wWinMain(
    HINSTANCE instance, HINSTANCE, PWSTR, const int show_command) {
    bool hidden_probe{};
    try {
        static_cast<void>(SetProcessDpiAwarenessContext(
            DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2));
        int argc{};
        auto** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (argv == nullptr) throw std::runtime_error("parse command line failed");
        for (int index = 1; index < argc; ++index)
            if (std::wstring_view(argv[index]) == L"--probe-seconds") hidden_probe = true;
        if (argc < 4) {
            LocalFree(argv);
            if (hidden_probe) return 64;
            MessageBoxW(
                nullptr,
                L"Usage: rwn-viewer.exe <user@host> <absolute-ssh-key> "
                L"<absolute-remote-rwn-desktop-agent> "
                 L"--profile lan-quality [--control view] "
                 L"[--present balanced] [--scale 1:1|fit] "
                 L"[--hybrid h264|snapshot-only|raw-rect-experimental] "
                 L"[--evidence pixel-quality] "
                 L"[--trace absolute-new-trace.jsonl]\n\nLegacy: "
                 L"[max-width max-height fps "
                 L"[baseline|low-latency|delay-1|delay-0] "
                 L"[legacy|visual|visual-analyze|visual-trace] "
                 L"[absolute-new-trace.jsonl]]",
                L"Remote Workspace Viewer", MB_OK | MB_ICONINFORMATION);
            return 64;
        }
        ViewerLaunchOptions options;
        try {
            options = parse_launch_options(argc, argv);
        } catch (...) {
            LocalFree(argv);
            throw;
        }
        LocalFree(argv);

        const wchar_t class_name[] = L"RwnPreviewWindow";
        WNDCLASSW window_class{};
        window_class.lpfnWndProc = window_procedure;
        window_class.hInstance = instance;
        window_class.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
        window_class.hbrBackground = static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
        window_class.lpszClassName = class_name;
        if (!RegisterClassW(&window_class)) {
            throw std::runtime_error("register viewer window failed");
        }

        ViewerState state;
        state.visual_protocol = options.visual_protocol;
        state.interactive = options.interactive;
        state.video_liveness_enabled.store(
            !options.exact_only, std::memory_order_relaxed);
        state.verify_exact_pixels = options.verify_exact_pixels;
        state.status = options.interactive
            ? L"Connecting to Mac interactive preview..."
            : L"Connecting to Mac preview...";
        state.renderer =
            std::make_unique<rwn::viewer::D3D11Nv12Renderer>();
        state.renderer->set_scale_mode(options.scale_mode);
        state.renderer->set_present_mode(
            options.extreme_present
                ? rwn::viewer::D3D11PresentMode::extreme
                : rwn::viewer::D3D11PresentMode::balanced);
        state.one_to_one_scale.store(
            options.scale_mode == rwn::viewer::D3D11ScaleMode::one_to_one,
            std::memory_order_relaxed);
        constexpr DWORD window_style = WS_OVERLAPPEDWINDOW;
        RECT desired_window{
            0, 0,
            static_cast<LONG>(options.lan_quality ? 1920U : 1280U),
            static_cast<LONG>(options.lan_quality ? 1080U : 720U)};
        if (!AdjustWindowRectExForDpi(
                &desired_window, window_style, FALSE, 0, GetDpiForSystem())) {
            throw std::runtime_error("calculate DPI-aware viewer size failed");
        }
        RECT work_area{};
        if (SystemParametersInfoW(SPI_GETWORKAREA, 0, &work_area, 0)) {
            const auto native_width = options.lan_quality ? 1920L : 1280L;
            const auto native_height = options.lan_quality ? 1080L : 720L;
            const auto border_width = desired_window.right - desired_window.left - native_width;
            const auto border_height = desired_window.bottom - desired_window.top - native_height;
            const auto scale = std::min({1.0,
                (0.9 * (work_area.right - work_area.left) - border_width) / native_width,
                (0.9 * (work_area.bottom - work_area.top) - border_height) / native_height});
            desired_window = {0, 0,
                static_cast<LONG>(std::lround(native_width * scale)) + border_width,
                static_cast<LONG>(std::lround(native_height * scale)) + border_height};
        }
        const auto window = CreateWindowExW(
            0, class_name, L"Remote Workspace Viewer - View Only",
            window_style, CW_USEDEFAULT, CW_USEDEFAULT,
            desired_window.right - desired_window.left,
            desired_window.bottom - desired_window.top,
            nullptr, nullptr, instance, &state);
        if (window == nullptr) throw std::runtime_error("create viewer window failed");
        std::optional<FocusedKeyboardCapture> keyboard_capture;
        if (!options.tls && options.interactive && options.probe_seconds == 0)
            keyboard_capture.emplace(window);
        if (options.visual_trace) {
            state.initialize_visual_trace(options.visual_trace_path);
        }
        if (options.probe_seconds == 0) {
            ShowWindow(window, show_command);
            UpdateWindow(window);
        }
        state.renderer->initialize(window);
        state.compositor = std::jthread(
            [&state](const std::stop_token stop) {
                compositor_loop(state, stop);
            });
        if (options.tls) {
            state.tls = std::make_unique<rwn::viewer::TlsPreviewConnection>(
                options.tls_options,options.tls_endpoint,options.interactive);
            if (options.interactive && options.probe_seconds == 0)
                keyboard_capture.emplace(window);
            state.control_writer = std::jthread([&state] { control_writer_loop(state); });
            state.frame_reader = std::jthread([&state,&options] {
                frame_reader_loop(state,true,options.raw_rect_experimental,options.exact_only);
            });
            state.tls_heartbeat = std::jthread([&state](std::stop_token stop) {
                unsigned ticks{};
                while (!stop.stop_requested() && !state.stopping) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    if (++ticks == 50) {
                        ticks=0;
                        try { state.enqueue_heartbeat(); }
                        catch (...) { state.tls->cancel(); break; }
                    }
                }
            });
        } else start_ssh(
            state, options.host, options.identity, options.remote_agent,
            options.maximum_width, options.maximum_height,
            options.frames_per_second, options.bitrate_kbps,
            options.vt_mode, options.visual_protocol,
            options.dirty_analysis, options.visual_trace,
            options.interactive, options.raw_rect_experimental,
            options.h264_only_explicit, options.snapshot_only_explicit,
            options.exact_only);

        if (options.probe_seconds != 0 &&
            !SetTimer(window, 0x52574eU, options.probe_seconds * 1000U, nullptr)) {
            throw std::runtime_error("start bounded probe timer failed");
        }
        MSG message{};
        while (GetMessageW(&message, nullptr, 0, 0) > 0) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        if (options.tls && options.probe_seconds) {
            std::cerr << "tls_viewer_probe present_receipts=" << state.successful_present_receipts.load()
                      << " runtime_failed=" << state.tls_runtime_failed.load()
                      << " snapshot_commits=" << state.snapshot_commits << '\n';
            return state.successful_present_receipts.load() > 0 &&
                !state.tls_runtime_failed.load() ? 0 : 3;
        }
        return static_cast<int>(message.wParam);
    } catch (const std::exception& error) {
        if (hidden_probe) {
            std::cerr << "viewer_probe_failed=" << error.what() << '\n';
            return 1; // Never block an unattended probe on a modal UI.
        }
        const auto message = utf8_to_utf16(error.what());
        MessageBoxW(
            nullptr, message.c_str(), L"Remote Workspace Viewer",
            MB_OK | MB_ICONERROR);
        return 1;
    }
}
