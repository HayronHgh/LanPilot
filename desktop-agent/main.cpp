#include "rwn/core/process_isolation.hpp"
#include "rwn/core/content_hash.hpp"

#if defined(__APPLE__)
#include "rwn/platform/macos/audio_runtime.hpp"
#include "rwn/platform/macos/desktop_runtime.hpp"
#include "rwn/platform/macos/process_identity.hpp"
#include <unistd.h>
#endif

#if defined(_WIN32)
#include "rwn/platform/windows/audio_runtime.hpp"
#include "rwn/platform/windows/desktop_runtime.hpp"
#endif

#include <chrono>
#include <algorithm>
#include <atomic>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>
#include <functional>
#include "tls_preview.hpp"

namespace {

#if defined(__APPLE__)
rwn::platform::macos::MacosVideoToolboxMode parse_vt_mode(
    const std::string_view value) {
    using enum rwn::platform::macos::MacosVideoToolboxMode;
    if (value == "baseline") return baseline;
    if (value == "low-latency") return low_latency_rate_control;
    if (value == "delay-1") return max_frame_delay_1;
    if (value == "delay-0") return max_frame_delay_0;
    throw std::invalid_argument("invalid VideoToolbox latency mode");
}

std::string_view vt_mode_name(
    const rwn::platform::macos::MacosVideoToolboxMode mode) {
    using enum rwn::platform::macos::MacosVideoToolboxMode;
    switch (mode) {
        case baseline: return "baseline";
        case low_latency_rate_control: return "low-latency";
        case max_frame_delay_1: return "delay-1";
        case max_frame_delay_0: return "delay-0";
    }
    return "unknown";
}
#endif

std::uint32_t parse_u32(
    const std::string_view value, const std::uint32_t minimum,
    const std::uint32_t maximum, const char* field) {
    std::uint32_t parsed{};
    const auto [end, error] = std::from_chars(
        value.data(), value.data() + value.size(), parsed);
    if (error != std::errc{} || end != value.data() + value.size() ||
        parsed < minimum || parsed > maximum) {
        throw std::invalid_argument(std::string("invalid ") + field);
    }
    return parsed;
}

#if defined(__APPLE__)
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

bool read_stdin_exact(const std::span<std::byte> output) {
    std::cin.read(
        reinterpret_cast<char*>(output.data()),
        static_cast<std::streamsize>(output.size()));
    return std::cin.gcount() ==
        static_cast<std::streamsize>(output.size());
}

std::uint64_t monotonic_timestamp_us() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}
#endif

int stream_preview_stdio(
    const std::uint32_t maximum_width,
    const std::uint32_t maximum_height,
    const std::uint32_t frames_per_second) {
#if defined(__APPLE__)
    rwn::platform::macos::MacosDesktopPermissionBackend permissions;
    if (permissions.status().capture != rwn::desktop::PermissionState::granted) {
        permissions.request_capture();
        std::cerr << "grant Screen Recording to rwn-desktop-agent and retry\n";
        return 2;
    }
    rwn::platform::macos::MacosScreenCaptureBackend capture(
        maximum_width, maximum_height, frames_per_second);
    const auto frame_interval =
        std::chrono::nanoseconds{1'000'000'000 / frames_per_second};
    while (std::cout.good()) {
        const auto started = std::chrono::steady_clock::now();
        const auto captured = capture.capture(std::chrono::seconds{2});
        if (!captured) {
            continue;
        }
        const auto frame = rwn::desktop::fit_preview_frame(
            *captured, maximum_width, maximum_height);
        const auto header = rwn::desktop::encode_preview_frame_header({
            .frame_id = frame.frame_id,
            .captured_at_us = frame.captured_at_us,
            .width = frame.width,
            .height = frame.height,
            .payload_size = static_cast<std::uint32_t>(frame.bgra.size()),
        });
        std::cout.write(
            reinterpret_cast<const char*>(header.data()),
            static_cast<std::streamsize>(header.size()));
        std::cout.write(
            reinterpret_cast<const char*>(frame.bgra.data()),
            static_cast<std::streamsize>(frame.bgra.size()));
        std::cout.flush();
        const auto elapsed = std::chrono::steady_clock::now() - started;
        if (elapsed < frame_interval) {
            std::this_thread::sleep_for(frame_interval - elapsed);
        }
    }
    return 0;
#else
    static_cast<void>(maximum_width);
    static_cast<void>(maximum_height);
    static_cast<void>(frames_per_second);
    std::cerr << "preview server is supported only on macOS\n";
    return 2;
#endif
}

int stream_h264_stdio(
    const std::uint32_t maximum_width,
    const std::uint32_t maximum_height,
    const std::uint32_t frames_per_second,
    const std::uint32_t bitrate_kbps,
    const std::string_view vt_mode_value,
    const bool visual_protocol,
    const bool dirty_analysis,
    const bool visual_trace,
    const bool interactive,
    const bool raw_rect_experimental,
    const bool h264_only_explicit,
    const bool exact_only,
    const std::function<void()>& cancel_network = {}) {
#if defined(__APPLE__)
    const auto vt_mode = parse_vt_mode(vt_mode_value);
    rwn::platform::macos::MacosDesktopPermissionBackend permissions;
    if (permissions.status().capture != rwn::desktop::PermissionState::granted) {
        permissions.request_capture();
        std::cerr << "grant Screen Recording to rwn-desktop-agent and retry\n";
        return 2;
    }
    if (interactive &&
        permissions.status().input != rwn::desktop::PermissionState::granted) {
        permissions.request_input();
        std::cerr << "grant Accessibility to rwn-desktop-agent and retry\n";
        return 2;
    }
    const auto session_generation = std::max<std::uint64_t>(
        1U, static_cast<std::uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    std::unique_ptr<rwn::desktop::VisualTraceQueue> trace_queue;
    std::unique_ptr<rwn::desktop::VisualLifecycleTracker> lifecycle;
    if (visual_trace) {
        trace_queue = std::make_unique<rwn::desktop::VisualTraceQueue>();
        lifecycle = std::make_unique<rwn::desktop::VisualLifecycleTracker>(
            rwn::desktop::VisualTraceHost::mac,
            session_generation, trace_queue.get());
    }
    std::unique_ptr<rwn::platform::macos::MacosCursorPositionSampler>
        cursor_sampler;
    std::optional<rwn::desktop::VisualCursorShape> initial_cursor_shape;
    if (interactive && visual_protocol) {
        try {
            cursor_sampler = std::make_unique<
                rwn::platform::macos::MacosCursorPositionSampler>(
                    maximum_width, maximum_height);
            initial_cursor_shape = cursor_sampler->sample_shape();
        } catch (const std::exception& error) {
            std::cerr << "RWN_CURSOR_FALLBACK reason="
                      << error.what() << '\n';
            cursor_sampler.reset();
        }
    }
    const auto independent_cursor = initial_cursor_shape.has_value();
    rwn::platform::macos::MacosScreenCaptureBackend capture(
        maximum_width, maximum_height, frames_per_second,
        lifecycle.get(), !independent_cursor,
        dirty_analysis || (visual_protocol && (interactive || cancel_network) && !h264_only_explicit));
    std::mutex diagnostics_mutex;
    std::atomic_bool stop_trace_writer{};
    std::thread trace_writer;
    if (visual_trace) {
        trace_writer = std::thread([&] {
            while (!stop_trace_writer.load() || trace_queue->size() != 0) {
                auto event = trace_queue->wait_pop(
                    std::chrono::milliseconds{100});
                if (!event) continue;
                std::lock_guard lock(diagnostics_mutex);
                std::cerr << "RWN_VISUAL_TRACE "
                          << rwn::desktop::render_visual_trace_json(*event)
                          << '\n';
            }
        });
    }
    rwn::platform::macos::MacosVideoToolboxEncoder encoder(vt_mode);
    const auto encoder_queue_stats = [&] {
        return exact_only
            ? rwn::platform::macos::MacosEncoderQueueStats{}
            : encoder.queue_stats();
    };
    const rwn::desktop::VideoSettings settings{
        .width = maximum_width,
        .height = maximum_height,
        .frames_per_second = frames_per_second,
        .bitrate_kbps = bitrate_kbps,
        .keyframe_interval = frames_per_second,
    };
    auto metrics_started = std::chrono::steady_clock::now();
    std::mutex capture_metrics_mutex;
    std::vector<double> capture_wait_ms;
    std::vector<double> screen_capture_age_ms;
    std::vector<double> vt_callback_ms;
    std::vector<double> ssh_write_ms;
    std::uint64_t captured_frames{};
    std::uint64_t report_encoded_frames{};
    std::uint64_t report_bytes{};
    bool hardware_active{};
    std::int32_t hardware_query_status{};
    std::int32_t max_frame_delay_status{};
    std::atomic<std::uint64_t> submitted_sequence{};
    std::atomic<std::uint64_t> tail_refresh_submitted{};
    std::atomic<std::uint64_t> representation_epoch{1};
    std::atomic_bool video_submissions_enabled{!exact_only};
    std::atomic_bool video_liveness_enabled{!exact_only};
    std::atomic_bool force_next_idr{};
    std::mutex submission_gate;
    std::mutex snapshot_ack_mutex;
    struct ReceivedSnapshotAck {
        rwn::desktop::FrameCommitAck ack;
        std::uint64_t bytes_received_at_us{};
        std::uint64_t parsed_at_us{};
    };
    std::optional<ReceivedSnapshotAck> received_snapshot_ack;
    std::atomic_bool snapshot_recovery_requested{};
    std::mutex worker_error_mutex;
    std::exception_ptr worker_error;
    std::unique_ptr<rwn::platform::macos::MacosInputBackend> input_backend;
    std::unique_ptr<rwn::desktop::InputReceiver> input_receiver;
    std::atomic_bool control_disconnected{};
    std::thread input_worker;
    if (interactive || cancel_network) {
        input_backend =
            std::make_unique<rwn::platform::macos::MacosInputBackend>();
        input_receiver =
            std::make_unique<rwn::desktop::InputReceiver>(*input_backend);
        input_worker = std::thread([&] {
            try {
                const rwn::core::AuthorizationResult authorization{
                    .principal_matched = true,
                    .workspace_allowed = true,
                    .granted = interactive
                        ? std::set{rwn::core::Capability::desktop_control}
                        : std::set<rwn::core::Capability>{},
                    .denied = {},
                };
                std::uint64_t last_sequence{};
                while (std::cin.good()) {
                    std::array<std::byte,
                        rwn::desktop::reverse_control_header_size> wire{};
                    if (!read_stdin_exact(wire)) break;
                    const auto header =
                        rwn::desktop::decode_reverse_control_header(wire);
                    if (header.sequence != last_sequence + 1U) {
                        throw std::invalid_argument(
                            "reverse control sequence has a gap");
                    }
                    last_sequence = header.sequence;
                    std::vector<std::byte> payload(header.payload_size);
                    if (!read_stdin_exact(payload)) {
                        throw std::invalid_argument(
                            "truncated reverse control payload");
                    }
                    const auto bytes_received_at_us = monotonic_timestamp_us();
                    rwn::desktop::validate_reverse_control_payload(
                        header, payload);
                    if (!interactive && (header.type == rwn::desktop::ReverseControlType::input_event ||
                        header.type == rwn::desktop::ReverseControlType::release_all_input))
                        throw std::invalid_argument("view-only TLS session forbids input");
                    const auto release_all = header.type ==
                        rwn::desktop::ReverseControlType::release_all_input;
                    std::optional<rwn::desktop::InputEvent> input_event;
                    auto input_trace_class =
                        rwn::desktop::VisualInputTraceClass::none;
                    if (header.type ==
                        rwn::desktop::ReverseControlType::input_event) {
                        input_event = rwn::desktop::decode_input_event(payload);
                        input_trace_class = input_event->kind ==
                                rwn::desktop::InputKind::pointer_move
                            ? rwn::desktop::VisualInputTraceClass::pointer_latest
                            : rwn::desktop::VisualInputTraceClass::reliable;
                    } else if (release_all) {
                        input_trace_class =
                            rwn::desktop::VisualInputTraceClass::release_all;
                    }
                    const auto record_input = [&] (
                        const rwn::desktop::VisualLifecycleStage stage,
                        const std::uint64_t timestamp) {
                        if (!lifecycle || input_trace_class ==
                                rwn::desktop::VisualInputTraceClass::none) {
                            return;
                        }
                        lifecycle->record(stage, 0, timestamp,
                            rwn::desktop::VisualTraceEvent{
                                .input_correlation_id = header.occurred_at_us,
                                .input_epoch = header.input_epoch,
                                .input_sequence = input_event
                                    ? input_event->sequence : 0,
                                .input_trace_class = input_trace_class,
                            });
                    };
                    record_input(
                        rwn::desktop::VisualLifecycleStage::input_bytes_received,
                        bytes_received_at_us);
                    if (!input_receiver->accept_input_epoch(
                            header.input_epoch, release_all)) {
                        record_input(
                            rwn::desktop::VisualLifecycleStage::input_rejected,
                            monotonic_timestamp_us());
                        continue;
                    }
                    switch (header.type) {
                        case rwn::desktop::ReverseControlType::input_event: {
                            const auto reliable = input_event->kind !=
                                rwn::desktop::InputKind::pointer_move;
                            if (input_receiver->receive(
                                    *input_event, reliable, authorization)) {
                                record_input(
                                    rwn::desktop::VisualLifecycleStage::
                                        input_injected,
                                    monotonic_timestamp_us());
                            } else {
                                record_input(
                                    rwn::desktop::VisualLifecycleStage::
                                        input_rejected,
                                    monotonic_timestamp_us());
                            }
                            break;
                        }
                        case rwn::desktop::ReverseControlType::
                                release_all_input:
                            static_cast<void>(
                                input_receiver->release_all_input());
                            record_input(
                                rwn::desktop::VisualLifecycleStage::
                                    input_release_all,
                                monotonic_timestamp_us());
                            break;
                        case rwn::desktop::ReverseControlType::ping:
                            if (cancel_network) break; // TLS keepalive must not request a snapshot.
                            [[fallthrough]];
                        case rwn::desktop::ReverseControlType::
                                request_full_snapshot:
                            snapshot_recovery_requested.store(
                                true, std::memory_order_release);
                            break;
                        case rwn::desktop::ReverseControlType::
                                frame_commit_ack: {
                            const auto ack =
                                rwn::desktop::decode_frame_commit_ack(payload);
                            const auto parsed_at_us = monotonic_timestamp_us();
                            if (ack.session_generation != session_generation) {
                                throw std::invalid_argument(
                                    "cross-session framebuffer ACK");
                            }
                            if (lifecycle) {
                                const rwn::desktop::VisualTraceEvent metadata{
                                    .representation_epoch =
                                        ack.representation_epoch,
                                };
                                lifecycle->record(
                                    rwn::desktop::VisualLifecycleStage::
                                        ack_bytes_received,
                                    ack.frame_id, bytes_received_at_us,
                                    metadata);
                                lifecycle->record(
                                    rwn::desktop::VisualLifecycleStage::
                                        ack_parsed,
                                    ack.frame_id, parsed_at_us, metadata);
                            }
                            std::lock_guard lock(snapshot_ack_mutex);
                            received_snapshot_ack = ReceivedSnapshotAck{
                                .ack = ack,
                                .bytes_received_at_us = bytes_received_at_us,
                                .parsed_at_us = parsed_at_us,
                            };
                            break;
                        }
                    }
                }
                static_cast<void>(input_receiver->release_all_input());
                // EOF ends an interactive session even on a static desktop:
                // no future encoded frame may arrive to discover broken stdout.
                control_disconnected.store(true, std::memory_order_release);
                if (cancel_network) cancel_network();
            } catch (...) {
                static_cast<void>(input_receiver->release_all_input());
                std::lock_guard lock(worker_error_mutex);
                worker_error = std::current_exception();
                control_disconnected.store(true, std::memory_order_release);
                if (cancel_network) cancel_network();
            }
        });
    }
    std::atomic_bool stop_encoder_worker{};
    std::thread encoder_worker;
    if (exact_only) {
        std::lock_guard lock(diagnostics_mutex);
        std::cerr << "RWN_EXACT_ONLY codec_encoder=not_started"
                  << " visual_transport=ssh-rwv2\n" << std::flush;
    }
    if (!exact_only) encoder_worker = std::thread([&] {
        try {
            rwn::desktop::VisualTailRefreshBudget tail_refresh;
            while (!stop_encoder_worker.load()) {
                if (!video_submissions_enabled.load(
                        std::memory_order_acquire)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds{1});
                    continue;
                }
                if (!encoder.has_submission_capacity()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds{1});
                    continue;
                }
                const auto started = std::chrono::steady_clock::now();
                const auto sequence = submitted_sequence.load();
                auto tail_repeat = false;
                bool submitted{};
                bool force_keyframe{};
                {
                    std::lock_guard gate(submission_gate);
                    if (!video_submissions_enabled.load(
                            std::memory_order_relaxed)) {
                        continue;
                    }
                    force_keyframe = force_next_idr.load(
                        std::memory_order_relaxed) || sequence == 0 ||
                        sequence % settings.keyframe_interval == 0;
                    submitted = capture.submit_latest(
                        encoder, settings, force_keyframe,
                        representation_epoch.load(std::memory_order_relaxed),
                        std::chrono::milliseconds{5});
                    if (submitted && force_next_idr.load(
                            std::memory_order_relaxed)) {
                        force_next_idr.store(false, std::memory_order_release);
                    }
                }
                if (submitted) {
                    const auto timing = capture.last_timing();
                    if (!timing) {
                        throw std::runtime_error(
                            "fresh capture submission has no timing");
                    }
                    tail_refresh.publish_visual(
                        timing->frame_id,
                        static_cast<std::uint64_t>(
                            std::chrono::duration_cast<std::chrono::microseconds>(
                                std::chrono::steady_clock::now()
                                    .time_since_epoch()).count()));
                } else if (tail_refresh.repeat_due(
                               static_cast<std::uint64_t>(
                                   std::chrono::duration_cast<
                                       std::chrono::microseconds>(
                                       std::chrono::steady_clock::now()
                                           .time_since_epoch()).count()))) {
                    std::lock_guard gate(submission_gate);
                    if (video_submissions_enabled.load(
                            std::memory_order_relaxed)) {
                        force_keyframe = force_next_idr.load(
                            std::memory_order_relaxed) || sequence == 0 ||
                            sequence % settings.keyframe_interval == 0;
                        submitted = capture.submit_tail_repeat(
                            encoder, settings, force_keyframe,
                            representation_epoch.load(
                                std::memory_order_relaxed));
                        if (submitted && force_next_idr.load(
                                std::memory_order_relaxed)) {
                            force_next_idr.store(
                                false, std::memory_order_release);
                        }
                    }
                    if (submitted) {
                        tail_repeat = true;
                        const auto timing = capture.last_timing();
                        if (!timing) {
                            throw std::runtime_error(
                                "tail refresh submission has no timing");
                        }
                        tail_refresh.repeat_completed(timing->frame_id);
                    }
                }
                if (!submitted) {
                    continue;
                }
                submitted_sequence.fetch_add(1);
                if (tail_repeat) {
                    tail_refresh_submitted.fetch_add(
                        1, std::memory_order_relaxed);
                }
                const auto finished = std::chrono::steady_clock::now();
                std::lock_guard lock(capture_metrics_mutex);
                capture_wait_ms.push_back(
                    std::chrono::duration<double, std::milli>(
                        finished - started).count());
                const auto timing = capture.last_timing();
                if (lifecycle && timing) {
                    lifecycle->record(
                        rwn::desktop::VisualLifecycleStage::vt_submit,
                        timing->frame_id,
                        static_cast<std::uint64_t>(
                            std::chrono::duration_cast<std::chrono::microseconds>(
                                std::chrono::steady_clock::now().time_since_epoch())
                                .count()));
                }
                screen_capture_age_ms.push_back(timing
                    ? static_cast<double>(timing->sample_age_us) / 1000.0
                    : 0.0);
                if (!tail_repeat) ++captured_frames;
            }
        } catch (...) {
            if (!stop_encoder_worker.load()) {
                std::lock_guard lock(worker_error_mutex);
                worker_error = std::current_exception();
            }
        }
    });
    std::mutex dirty_metrics_mutex;
    std::vector<double> dirty_analyzer_ms;
    std::vector<double> dirty_16_ratios;
    std::vector<double> dirty_32_ratios;
    std::vector<double> dirty_64_ratios;
    std::optional<rwn::platform::macos::MacosDirtyAnalysisResult>
        latest_dirty_result;
    std::uint64_t analyzed_frames{};
    std::atomic_bool stop_dirty_worker{};
    std::thread dirty_worker;
    const bool snapshot_enabled =
        visual_protocol && (interactive || cancel_network) && !h264_only_explicit;
    std::unique_ptr<
        rwn::platform::macos::MacosMetalDirtyTileAnalyzer> exact_analyzer;
    if (dirty_analysis || snapshot_enabled) {
        exact_analyzer = std::make_unique<
            rwn::platform::macos::MacosMetalDirtyTileAnalyzer>();
        capture.enable_dirty_analysis(true);
        dirty_worker = std::thread([&] {
            try {
                while (!stop_dirty_worker.load()) {
                    auto result = capture.analyze_latest(
                        *exact_analyzer, std::chrono::milliseconds{100});
                    if (!result || result->baseline_frame || !dirty_analysis) {
                        continue;
                    }
                    std::lock_guard lock(dirty_metrics_mutex);
                    dirty_analyzer_ms.push_back(
                        static_cast<double>(result->analyzer_us) / 1000.0);
                    dirty_16_ratios.push_back(result->tile_16.dirty_ratio);
                    dirty_32_ratios.push_back(result->tile_32.dirty_ratio);
                    dirty_64_ratios.push_back(result->tile_64.dirty_ratio);
                    latest_dirty_result = *result;
                    ++analyzed_frames;
                    if (lifecycle) {
                        lifecycle->record(
                            rwn::desktop::VisualLifecycleStage::metal_analysis,
                            result->frame_id,
                            static_cast<std::uint64_t>(
                                std::chrono::duration_cast<
                                    std::chrono::microseconds>(
                                    std::chrono::steady_clock::now()
                                        .time_since_epoch()).count()),
                            rwn::desktop::VisualTraceEvent{
                                .metal_dirty_tiles =
                                    result->tile_16.dirty_tiles,
                                .metal_dirty_ratio_ppm =
                                    static_cast<std::uint32_t>(std::clamp(
                                        std::llround(
                                            result->tile_16.dirty_ratio *
                                            1'000'000.0),
                                        0LL, 1'000'000LL)),
                            });
                    }
                }
            } catch (...) {
                if (!stop_dirty_worker.load()) {
                    std::lock_guard lock(worker_error_mutex);
                    worker_error = std::current_exception();
                }
            }
        });
    }
    struct PendingCursor {
        rwn::desktop::VisualCursorPosition position;
        std::uint64_t captured_at_us{};
    };
    std::mutex cursor_mutex;
    std::optional<PendingCursor> pending_cursor;
    std::optional<rwn::desktop::VisualCursorShape> pending_cursor_shape =
        initial_cursor_shape;
    std::atomic_uint64_t cursor_produced{};
    std::atomic_uint64_t cursor_replaced{};
    std::atomic_bool stop_cursor_worker{};
    std::thread cursor_worker;
    if (visual_protocol) {
        cursor_worker = std::thread([&] {
            try {
                if (!cursor_sampler) {
                    cursor_sampler = std::make_unique<
                        rwn::platform::macos::MacosCursorPositionSampler>(
                            maximum_width, maximum_height);
                }
                std::optional<rwn::desktop::VisualCursorPosition> previous;
                auto shape_id = initial_cursor_shape
                    ? initial_cursor_shape->shape_id : 0U;
                while (!stop_cursor_worker.load()) {
                    if (independent_cursor) {
                        if (auto shape = cursor_sampler->sample_shape();
                            shape && shape->shape_id != shape_id) {
                            shape_id = shape->shape_id;
                            std::lock_guard lock(cursor_mutex);
                            pending_cursor_shape = std::move(shape);
                        }
                    }
                    auto current = cursor_sampler->sample();
                    current.shape_id = shape_id;
                    if (!previous || current != *previous) {
                        const auto sampled_at_us = static_cast<std::uint64_t>(
                            std::chrono::duration_cast<std::chrono::microseconds>(
                                std::chrono::steady_clock::now().time_since_epoch())
                                .count());
                        std::lock_guard lock(cursor_mutex);
                        if (pending_cursor) cursor_replaced.fetch_add(1);
                        pending_cursor = PendingCursor{
                            .position = current,
                            .captured_at_us = sampled_at_us,
                        };
                        cursor_produced.fetch_add(1);
                        previous = current;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds{8});
                }
            } catch (...) {
                if (!stop_cursor_worker.load()) {
                    std::lock_guard lock(worker_error_mutex);
                    worker_error = std::current_exception();
                }
            }
        });
    }
    std::atomic_bool stop_visual_watchdog{};
    std::thread visual_watchdog;
    if (visual_trace) {
        visual_watchdog = std::thread([&] {
            std::optional<rwn::desktop::VisualLivenessWatchdog> watchdog;
            while (!stop_visual_watchdog.load()) {
                if (!video_liveness_enabled.load(std::memory_order_acquire)) {
                    watchdog.reset();
                    std::this_thread::sleep_for(std::chrono::milliseconds{10});
                    continue;
                }
                if (!watchdog) {
                    watchdog.emplace(
                        rwn::desktop::VisualLifecycleDomain::mac);
                }
                const auto now_us = static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now().time_since_epoch())
                        .count());
                if (auto event = watchdog->poll(
                        lifecycle->snapshot(), now_us)) {
                    lifecycle->record(
                        event->recovered
                            ? rwn::desktop::VisualLifecycleStage::visual_recovered
                            : rwn::desktop::VisualLifecycleStage::visual_stall,
                        event->frame_id, now_us,
                        rwn::desktop::VisualTraceEvent{
                            .related_stage = event->related_stage,
                            .stalled_us = event->stalled_us,
                        });
                }
                std::this_thread::sleep_for(std::chrono::milliseconds{10});
            }
        });
    }
    std::uint64_t visual_sequence{};
    enum class HybridSnapshotMode {
        video,
        quiescing,
        sending,
        awaiting_ack,
        exact,
        awaiting_rect_ack,
    };
    // Keep the representation selector deliberately conservative.  These are
    // transition timing guards, not RAW_RECT selector thresholds: a source
    // still has to remain unchanged for the quiet gate before snapshot work
    // starts, and a VIDEO recovery gets an additional dwell window so it does
    // not immediately re-enter the same expensive snapshot transaction.
    constexpr std::uint64_t snapshot_quiet_interval_us{150'000U};
    constexpr std::uint64_t snapshot_reentry_cooldown_us{500'000U};
    const auto rect_selector_ratio_ppm = exact_only
        ? 1'000'000U
        : rwn::desktop::default_raw_rect_selector_ratio_ppm;
    const auto rect_selector_count = exact_only
        ? static_cast<std::uint32_t>(
            rwn::desktop::maximum_raw_rect_transaction_count)
        : rwn::desktop::default_raw_rect_selector_count;
    const auto rect_selector_bytes = exact_only
        ? rwn::desktop::maximum_raw_rect_protocol_bytes
        : rwn::desktop::default_raw_rect_selector_bytes;
    HybridSnapshotMode hybrid_mode{HybridSnapshotMode::video};
    std::uint64_t snapshot_frame_id{};
    std::uint64_t snapshot_content_frame_id{};
    std::uint64_t snapshot_epoch{};
    std::uint64_t snapshot_sent_at_us{};
    std::uint64_t snapshot_source_updated_at_us{};
    std::uint64_t snapshot_wire_started_at_us{};
    std::optional<rwn::platform::macos::MacosExactSnapshot> pending_snapshot;
    rwn::desktop::SnapshotWireDrainPlan snapshot_wire_drain;
    std::array<std::byte, 32> snapshot_sha256{};
    std::uint64_t exact_frame_id{};
    std::uint64_t exact_content_frame_id{};
    std::uint64_t rect_epoch{};
    std::uint64_t rect_target_frame_id{};
    std::uint64_t rect_target_content_frame_id{};
    std::uint64_t rect_sent_at_us{};
    std::uint64_t rect_last_superseded_source{};
    std::uint64_t rect_last_superseded_content_frame{};
    std::uint64_t rect_last_evaluated_source{};
    std::uint64_t rect_last_evaluated_content_frame{};
    std::array<std::byte, 32> exact_digest{};
    std::array<std::byte, 32> pending_rect_digest{};
    std::uint64_t rect_transactions{};
    std::uint64_t rect_cancels{};
    std::uint64_t rect_superseded_sources{};
    std::uint64_t representation_switches{};
    std::uint64_t rect_bytes{};
    std::vector<double> rect_compare_ms;
    std::vector<double> rect_readback_ms;
    std::vector<double> rect_wire_ms;
    std::vector<double> rect_ack_ms;
    std::uint64_t rect_residency_started_at_us{};
    std::uint64_t rect_residency_accumulated_us{};
    std::uint64_t snapshot_chunks{};
    std::uint64_t snapshot_bytes{};
    std::uint64_t snapshot_attempts{};
    std::uint64_t snapshot_cancels{};
    std::uint64_t snapshot_cooldown_entries{};
    std::uint64_t snapshot_reentry_not_before_us{};
    std::uint64_t stale_snapshot_acks{};
    std::vector<double> snapshot_readback_ms;
    std::vector<double> snapshot_wire_ms;
    std::vector<double> snapshot_ack_ms;
    std::vector<double> snapshot_quiet_to_exact_ms;
    std::uint64_t snapshot_status_report_at_us{};
    const auto monotonic_us = [] { return monotonic_timestamp_us(); };
    const auto hybrid_metrics_started_at_us = monotonic_us();
    const auto representation_mode = [&] {
        switch (hybrid_mode) {
            case HybridSnapshotMode::video:
                return rwn::desktop::VisualRepresentationMode::video_lossy;
            case HybridSnapshotMode::quiescing:
            case HybridSnapshotMode::sending:
            case HybridSnapshotMode::awaiting_ack:
                return rwn::desktop::VisualRepresentationMode::snapshot;
            case HybridSnapshotMode::exact:
            case HybridSnapshotMode::awaiting_rect_ack:
                return rwn::desktop::VisualRepresentationMode::rect_exact;
        }
        return rwn::desktop::VisualRepresentationMode::unknown;
    };
    const auto trace_representation_state = [&] (
        const rwn::desktop::VisualFallbackReason fallback_reason,
        const std::uint64_t frame_id,
        const std::uint64_t epoch,
        const std::uint64_t now_us) {
        if (!lifecycle) return;
        const auto observed_source = exact_analyzer
            ? exact_analyzer->latest_source_state() : std::nullopt;
        const auto exact_us = rect_residency_accumulated_us +
            (rect_residency_started_at_us == 0 ? 0U :
                now_us - rect_residency_started_at_us);
        const auto elapsed_us = now_us - hybrid_metrics_started_at_us;
        const auto ratio_ppm = elapsed_us == 0 ? 0U :
            static_cast<std::uint32_t>(std::min<long double>(
                1'000'000.0L,
                static_cast<long double>(exact_us) * 1'000'000.0L /
                    static_cast<long double>(elapsed_us)));
        lifecycle->record(
            rwn::desktop::VisualLifecycleStage::representation_state,
            frame_id, now_us,
            rwn::desktop::VisualTraceEvent{
                .representation_epoch = epoch,
                .representation_mode = representation_mode(),
                .fallback_reason = fallback_reason,
                .exact_residency_ratio_ppm = ratio_ppm,
                .representation_switches = representation_switches,
                .rect_superseded_sources = rect_superseded_sources,
                .latest_source_frame_id = observed_source ? observed_source->frame_id : 0,
                .latest_content_frame_id = observed_source ? observed_source->content_frame_id : 0,
                .exact_base_frame_id = exact_frame_id,
                .exact_base_content_frame_id = exact_content_frame_id,
            });
    };
    const auto fallback_for_decision = [] (
        const rwn::platform::macos::MacosExactRectDecision decision) {
        switch (decision) {
            case rwn::platform::macos::MacosExactRectDecision::ratio_exceeded:
                return rwn::desktop::VisualFallbackReason::dirty_ratio;
            case rwn::platform::macos::MacosExactRectDecision::
                    rectangle_count_exceeded:
                return rwn::desktop::VisualFallbackReason::rectangle_count;
            case rwn::platform::macos::MacosExactRectDecision::
                    byte_limit_exceeded:
                return rwn::desktop::VisualFallbackReason::packed_bytes;
            default:
                return rwn::desktop::VisualFallbackReason::none;
        }
    };
    const auto report_snapshot_event = [&diagnostics_mutex](
        const std::string_view event,
        const std::uint64_t epoch,
        const std::uint64_t frame_id,
        const double readback_ms,
        const double wire_ms,
        const double ack_ms,
        const double quiet_to_exact_ms,
        const std::uint32_t reason) {
        std::lock_guard lock(diagnostics_mutex);
        std::cerr << std::fixed << std::setprecision(3)
                  << "RWN_SNAPSHOT event=" << event
                  << " epoch=" << epoch
                  << " frame=" << frame_id
                  << " readback_ms=" << readback_ms
                  << " wire_ms=" << wire_ms
                  << " ack_ms=" << ack_ms
                  << " quiet_exact_ms=" << quiet_to_exact_ms
                  << " reason=" << reason
                  << '\n' << std::flush;
    };
    const auto write_visual_message = [&] (
        const rwn::desktop::VisualMessageType type,
        const std::uint8_t flags,
        const std::uint64_t epoch,
        const std::uint64_t frame_id,
        const std::uint64_t captured_at_us,
        const std::span<const std::byte> payload,
        const bool flush_output = true) {
        const auto header = rwn::desktop::encode_visual_message_header({
            .type = type,
            .flags = flags,
            .payload_size = static_cast<std::uint32_t>(payload.size()),
            .session_generation = session_generation,
            .representation_epoch = epoch,
            .visual_sequence = ++visual_sequence,
            .frame_id = frame_id,
            .captured_at_us = captured_at_us,
        });
        std::cout.write(
            reinterpret_cast<const char*>(header.data()),
            static_cast<std::streamsize>(header.size()));
        std::cout.write(
            reinterpret_cast<const char*>(payload.data()),
            static_cast<std::streamsize>(payload.size()));
        if (flush_output) std::cout.flush();
        report_bytes += header.size() + payload.size();
    };
    const auto resume_forced_idr_video = [&] (
        const rwn::desktop::VisualStateResetReason reason,
        const rwn::desktop::VisualFallbackReason fallback_reason) {
        std::lock_guard gate(submission_gate);
        const auto transition_now_us = monotonic_us();
        video_submissions_enabled.store(false, std::memory_order_release);
        const auto old_epoch = representation_epoch.load();
        if (old_epoch == std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error("visual representation epoch exhausted");
        }
        const auto new_epoch = old_epoch + 1U;
        representation_epoch.store(new_epoch, std::memory_order_release);
        if (!exact_only) encoder.discard_before_epoch(new_epoch);
        const auto latest_source = exact_analyzer
            ? exact_analyzer->latest_source_state() : std::nullopt;
        const auto reset_frame_id = latest_source
            ? latest_source->frame_id
            : rect_target_frame_id != 0 ? rect_target_frame_id
            : snapshot_frame_id != 0 ? snapshot_frame_id : 1U;
        const auto reset_captured_at_us = latest_source
            ? latest_source->captured_at_us : monotonic_us();
        if (exact_analyzer) exact_analyzer->invalidate_exact_base();
        pending_snapshot.reset();
        snapshot_wire_drain.cancel();
        const auto reset = rwn::desktop::encode_visual_state_reset({
            .reason = reason,
        });
        write_visual_message(
            rwn::desktop::VisualMessageType::state_reset, 0, new_epoch,
            reset_frame_id, reset_captured_at_us, reset);
        ++representation_switches;
        report_snapshot_event(
            exact_only ? "exact_resync" : "forced_idr_video", new_epoch,
            snapshot_frame_id, 0.0, 0.0, 0.0, 0.0,
            static_cast<std::uint32_t>(reason));
        snapshot_frame_id = 0;
        snapshot_content_frame_id = 0;
        snapshot_epoch = 0;
        snapshot_sent_at_us = 0;
        snapshot_wire_started_at_us = 0;
        exact_frame_id = 0;
        exact_content_frame_id = 0;
        rect_epoch = 0;
        rect_target_frame_id = 0;
        rect_target_content_frame_id = 0;
        rect_sent_at_us = 0;
        rect_last_superseded_source = 0;
        rect_last_superseded_content_frame = 0;
        rect_last_evaluated_source = 0;
        rect_last_evaluated_content_frame = 0;
        if (rect_residency_started_at_us != 0) {
            rect_residency_accumulated_us +=
                transition_now_us - rect_residency_started_at_us;
            rect_residency_started_at_us = 0;
        }
        if (exact_only) {
            snapshot_epoch = new_epoch;
            video_submissions_enabled.store(false, std::memory_order_release);
            video_liveness_enabled.store(false, std::memory_order_release);
            hybrid_mode = HybridSnapshotMode::quiescing;
            snapshot_reentry_not_before_us = 0;
        } else {
            force_next_idr.store(true, std::memory_order_release);
            video_submissions_enabled.store(true, std::memory_order_release);
            video_liveness_enabled.store(true, std::memory_order_release);
            hybrid_mode = HybridSnapshotMode::video;
            ++snapshot_cooldown_entries;
            snapshot_reentry_not_before_us =
                transition_now_us >
                        std::numeric_limits<std::uint64_t>::max() -
                            snapshot_reentry_cooldown_us
                    ? std::numeric_limits<std::uint64_t>::max()
                    : transition_now_us + snapshot_reentry_cooldown_us;
        }
        trace_representation_state(
            fallback_reason, reset_frame_id, new_epoch, transition_now_us);
    };
    std::uint64_t cursor_sent{};
    std::uint64_t report_cursor_sent{};
    trace_representation_state(
        rwn::desktop::VisualFallbackReason::none, 0,
        representation_epoch.load(), monotonic_us());
    auto last_replaced_frames = capture.replaced_frame_count();
    auto last_queue_stats = encoder_queue_stats();
    while (std::cout.good() &&
           !control_disconnected.load(std::memory_order_acquire)) {
        {
            std::lock_guard lock(worker_error_mutex);
            if (worker_error) std::rethrow_exception(worker_error);
        }
        if (snapshot_enabled) {
            if (snapshot_recovery_requested.exchange(
                    false, std::memory_order_acq_rel)) {
                ++snapshot_cancels;
                resume_forced_idr_video(
                    rwn::desktop::VisualStateResetReason::snapshot_required,
                    rwn::desktop::VisualFallbackReason::recovery_request);
            }
            std::optional<ReceivedSnapshotAck> received_ack;
            {
                std::lock_guard lock(snapshot_ack_mutex);
                received_ack.swap(received_snapshot_ack);
            }
            if (received_ack) {
                const auto& ack = received_ack->ack;
                if (hybrid_mode == HybridSnapshotMode::awaiting_ack &&
                    rwn::desktop::frame_commit_ack_matches(
                        ack, session_generation, snapshot_epoch,
                        snapshot_frame_id, snapshot_sha256)) {
                    const auto now_us = monotonic_us();
                    if (!exact_analyzer->promote_pending_exact(
                            snapshot_frame_id)) {
                        ++snapshot_cancels;
                        resume_forced_idr_video(
                            rwn::desktop::VisualStateResetReason::base_mismatch,
                            rwn::desktop::VisualFallbackReason::base_mismatch);
                        continue;
                    }
                    snapshot_ack_ms.push_back(
                        static_cast<double>(now_us - snapshot_sent_at_us) /
                        1000.0);
                    snapshot_quiet_to_exact_ms.push_back(
                        static_cast<double>(
                            now_us - snapshot_source_updated_at_us) / 1000.0);
                    exact_frame_id = snapshot_frame_id;
                    exact_content_frame_id = snapshot_content_frame_id;
                    exact_digest = snapshot_sha256;
                    rect_epoch = snapshot_epoch;
                    if (raw_rect_experimental) {
                        if (snapshot_epoch ==
                            std::numeric_limits<std::uint64_t>::max()) {
                            throw std::overflow_error(
                                "visual representation epoch exhausted");
                        }
                        rect_epoch = snapshot_epoch + 1U;
                        representation_epoch.store(
                            rect_epoch, std::memory_order_release);
                        if (!exact_only) encoder.discard_before_epoch(rect_epoch);
                        const auto reset =
                            rwn::desktop::encode_visual_state_reset({
                                .reason = rwn::desktop::VisualStateResetReason::
                                    representation_transition,
                            });
                        write_visual_message(
                            rwn::desktop::VisualMessageType::state_reset, 0,
                            rect_epoch, exact_frame_id,
                            now_us, reset);
                        ++representation_switches;
                        rect_residency_started_at_us = now_us;
                    }
                    hybrid_mode = HybridSnapshotMode::exact;
                    trace_representation_state(
                        rwn::desktop::VisualFallbackReason::none,
                        exact_frame_id, rect_epoch, now_us);
                    if (lifecycle) {
                        lifecycle->record(
                            rwn::desktop::VisualLifecycleStage::ack_accepted,
                            ack.frame_id, now_us,
                            rwn::desktop::VisualTraceEvent{
                                .representation_epoch =
                                    ack.representation_epoch,
                            });
                    }
                    report_snapshot_event(
                        "exact", snapshot_epoch, snapshot_frame_id,
                        snapshot_readback_ms.empty()
                            ? 0.0 : snapshot_readback_ms.back(),
                        snapshot_wire_ms.empty()
                            ? 0.0 : snapshot_wire_ms.back(),
                        snapshot_ack_ms.back(),
                        snapshot_quiet_to_exact_ms.back(), 0);
                } else if (
                    hybrid_mode == HybridSnapshotMode::awaiting_rect_ack &&
                    rwn::desktop::frame_commit_ack_matches(
                        ack, session_generation, rect_epoch,
                        rect_target_frame_id, pending_rect_digest)) {
                    const auto now_us = monotonic_us();
                    if (!exact_analyzer->promote_pending_exact(
                            rect_target_frame_id)) {
                        ++rect_cancels;
                        resume_forced_idr_video(
                            rwn::desktop::VisualStateResetReason::base_mismatch,
                            rwn::desktop::VisualFallbackReason::base_mismatch);
                        continue;
                    }
                    rect_ack_ms.push_back(
                        static_cast<double>(now_us - rect_sent_at_us) / 1000.0);
                    exact_frame_id = rect_target_frame_id;
                    exact_content_frame_id = rect_target_content_frame_id;
                    exact_digest = pending_rect_digest;
                    rect_target_frame_id = 0;
                    rect_target_content_frame_id = 0;
                    rect_sent_at_us = 0;
                    rect_last_superseded_source = 0;
                    rect_last_superseded_content_frame = 0;
                    rect_last_evaluated_source = 0;
                    rect_last_evaluated_content_frame = 0;
                    hybrid_mode = HybridSnapshotMode::exact;
                    if (lifecycle) {
                        lifecycle->record(
                            rwn::desktop::VisualLifecycleStage::ack_accepted,
                            ack.frame_id, now_us,
                            rwn::desktop::VisualTraceEvent{
                                .representation_epoch =
                                    ack.representation_epoch,
                            });
                    }
                } else {
                    ++stale_snapshot_acks;
                    const auto active_ack_mismatch =
                        (hybrid_mode == HybridSnapshotMode::awaiting_ack &&
                         ack.representation_epoch == snapshot_epoch &&
                         ack.frame_id == snapshot_frame_id) ||
                        (hybrid_mode ==
                             HybridSnapshotMode::awaiting_rect_ack &&
                         ack.representation_epoch == rect_epoch &&
                         ack.frame_id == rect_target_frame_id);
                    if (active_ack_mismatch) {
                        ++snapshot_cancels;
                        ++rect_cancels;
                        resume_forced_idr_video(
                            rwn::desktop::VisualStateResetReason::base_mismatch,
                            rwn::desktop::VisualFallbackReason::base_mismatch);
                    }
                }
            }
            const auto exact_state = exact_analyzer->latest_source_state();
            const auto now_us = monotonic_us();
            if (now_us >= snapshot_status_report_at_us) {
                const auto queue_stats = encoder_queue_stats();
                trace_representation_state(
                    rwn::desktop::VisualFallbackReason::none,
                    exact_state ? exact_state->frame_id : 0,
                    representation_epoch.load(), now_us);
                std::lock_guard diagnostics_lock(diagnostics_mutex);
                std::cerr << "RWN_SNAPSHOT event=status mode="
                          << static_cast<unsigned>(hybrid_mode)
                          << " epoch=" << representation_epoch.load()
                          << " reserved_epoch=" << snapshot_epoch
                          << " source_frame="
                          << (exact_state ? exact_state->frame_id : 0)
                          << " quiet_us="
                          << (exact_state && now_us >= exact_state->updated_at_us
                              ? now_us - exact_state->updated_at_us : 0)
                          << " snapshot_quiet_gate_us="
                          << snapshot_quiet_interval_us
                          << " snapshot_cooldown_remaining_us="
                          << (now_us >= snapshot_reentry_not_before_us ? 0U :
                              snapshot_reentry_not_before_us - now_us)
                          << " snapshot_attempts=" << snapshot_attempts
                          << " vt_inflight="
                          << queue_stats.in_flight_current
                          << " encoded_queue="
                          << queue_stats.encoded_queue_current
                          << " stale_epoch_drops="
                          << queue_stats.stale_epoch_drops
                          << '\n' << std::flush;
                snapshot_status_report_at_us = now_us + 1'000'000U;
            }
            if (hybrid_mode == HybridSnapshotMode::awaiting_ack &&
                now_us - snapshot_sent_at_us >= 1'000'000U) {
                ++snapshot_cancels;
                resume_forced_idr_video(
                    rwn::desktop::VisualStateResetReason::snapshot_required,
                    rwn::desktop::VisualFallbackReason::ack_timeout);
            } else if (hybrid_mode == HybridSnapshotMode::sending) {
                if (!pending_snapshot || !snapshot_wire_drain.active()) {
                    ++snapshot_cancels;
                    resume_forced_idr_video(
                        rwn::desktop::VisualStateResetReason::snapshot_required,
                        rwn::desktop::VisualFallbackReason::base_mismatch);
                    continue;
                }
                if (exact_state) {
                    snapshot_wire_drain.observe_latest_source(
                        exact_state->content_frame_id);
                }
                if (!exact_only && snapshot_wire_drain.superseded()) {
                    if (lifecycle) {
                        lifecycle->record(
                            rwn::desktop::VisualLifecycleStage::superseded,
                            snapshot_frame_id, now_us,
                            rwn::desktop::VisualTraceEvent{
                                .representation_epoch = snapshot_epoch,
                                .superseded_by =
                                    snapshot_wire_drain.latest_source_frame_id(),
                            });
                    }
                    ++snapshot_cancels;
                    resume_forced_idr_video(
                        rwn::desktop::VisualStateResetReason::
                            representation_transition,
                        rwn::desktop::VisualFallbackReason::
                            newer_incompatible_source);
                    continue;
                }
                bool wrote_snapshot_chunk{};
                for (const auto& range : snapshot_wire_drain.take_burst()) {
                    const auto& snapshot = *pending_snapshot;
                    const auto offset = static_cast<std::size_t>(range.offset);
                    const auto size = static_cast<std::size_t>(range.size);
                    const auto chunk =
                        rwn::desktop::encode_visual_full_snapshot_chunk({
                            .surface_width = snapshot.width,
                            .surface_height = snapshot.height,
                            .row_stride = snapshot.row_stride,
                            .pixel_format = rwn::desktop::CanonicalPixelFormat::
                                bgra8_premultiplied_srgb,
                            .total_bytes = static_cast<std::uint32_t>(
                                snapshot.bgra.size()),
                            .chunk_offset = range.offset,
                            .chunk = std::vector<std::byte>(
                                snapshot.bgra.begin() +
                                    static_cast<std::ptrdiff_t>(offset),
                                snapshot.bgra.begin() +
                                    static_cast<std::ptrdiff_t>(offset + size)),
                        });
                    write_visual_message(
                        rwn::desktop::VisualMessageType::full_snapshot,
                        range.final
                            ? rwn::desktop::visual_flag_frame_final : 0,
                        snapshot_epoch, snapshot.frame_id,
                        snapshot.captured_at_us, chunk, false);
                    wrote_snapshot_chunk = true;
                    ++snapshot_chunks;
                    snapshot_bytes += size;
                }
                if (wrote_snapshot_chunk) std::cout.flush();
                if (snapshot_wire_drain.complete()) {
                    const auto commit =
                        rwn::desktop::encode_visual_frame_commit({
                            .base_frame_id = 0,
                        });
                    write_visual_message(
                        rwn::desktop::VisualMessageType::frame_commit,
                        rwn::desktop::visual_flag_frame_final,
                        snapshot_epoch, snapshot_frame_id,
                        pending_snapshot->captured_at_us, commit);
                    snapshot_sent_at_us = monotonic_us();
                    snapshot_wire_ms.push_back(static_cast<double>(
                        snapshot_sent_at_us - snapshot_wire_started_at_us) /
                        1000.0);
                    if (lifecycle) {
                        lifecycle->record(
                            rwn::desktop::VisualLifecycleStage::
                                snapshot_write_complete,
                            snapshot_frame_id, snapshot_sent_at_us,
                            rwn::desktop::VisualTraceEvent{
                                .representation_epoch = snapshot_epoch,
                                .stage_duration_us =
                                    snapshot_sent_at_us -
                                    snapshot_wire_started_at_us,
                                .payload_bytes = pending_snapshot->bgra.size(),
                                .superseded_by =
                                    snapshot_wire_drain.latest_source_frame_id(),
                            });
                        lifecycle->record(
                            rwn::desktop::VisualLifecycleStage::
                                frame_commit_write_complete,
                            snapshot_frame_id, snapshot_sent_at_us,
                            rwn::desktop::VisualTraceEvent{
                                .representation_epoch = snapshot_epoch,
                            });
                    }
                    pending_snapshot.reset();
                    snapshot_wire_drain.cancel();
                    hybrid_mode = HybridSnapshotMode::awaiting_ack;
                    report_snapshot_event(
                        "awaiting_ack", snapshot_epoch, snapshot_frame_id,
                        snapshot_readback_ms.back(), snapshot_wire_ms.back(),
                        0.0, 0.0, 0);
                }
            } else if (
                hybrid_mode == HybridSnapshotMode::awaiting_rect_ack &&
                now_us - rect_sent_at_us >= 100'000U) {
                ++rect_cancels;
                resume_forced_idr_video(
                    rwn::desktop::VisualStateResetReason::snapshot_required,
                    rwn::desktop::VisualFallbackReason::ack_timeout);
            } else if (
                hybrid_mode == HybridSnapshotMode::awaiting_rect_ack &&
                exact_state &&
                exact_state->content_frame_id > rect_target_content_frame_id &&
                exact_state->content_frame_id !=
                    rect_last_superseded_content_frame) {
                const auto latest = exact_analyzer->evaluate_latest_rect(
                    exact_frame_id,
                    rect_selector_ratio_ppm,
                    rect_selector_count,
                    rect_selector_bytes,
                    false);
                if (latest.target_frame_id != rect_last_superseded_source) {
                    ++rect_superseded_sources;
                    rect_last_superseded_source = latest.target_frame_id;
                    rect_last_superseded_content_frame =
                        latest.content_frame_id;
                }
                if (latest.decision == rwn::platform::macos::
                        MacosExactRectDecision::ratio_exceeded ||
                    latest.decision == rwn::platform::macos::
                        MacosExactRectDecision::rectangle_count_exceeded ||
                    latest.decision == rwn::platform::macos::
                        MacosExactRectDecision::byte_limit_exceeded) {
                    ++rect_cancels;
                    resume_forced_idr_video(
                        rwn::desktop::VisualStateResetReason::
                            representation_transition,
                        fallback_for_decision(latest.decision));
                }
            } else if (hybrid_mode == HybridSnapshotMode::exact && exact_state &&
                       exact_state->content_frame_id > exact_content_frame_id &&
                       exact_state->content_frame_id !=
                           rect_last_evaluated_content_frame) {
                if (!raw_rect_experimental) {
                    resume_forced_idr_video(
                        rwn::desktop::VisualStateResetReason::
                            representation_transition,
                        rwn::desktop::VisualFallbackReason::feature_disabled);
                } else {
                    auto candidate = exact_analyzer->evaluate_latest_rect(
                        exact_frame_id,
                        rect_selector_ratio_ppm,
                        rect_selector_count,
                        rect_selector_bytes,
                        true);
                    rect_last_evaluated_source = candidate.target_frame_id;
                    rect_last_evaluated_content_frame =
                        candidate.content_frame_id;
                    rect_compare_ms.push_back(
                        static_cast<double>(candidate.compare_us) / 1000.0);
                    if (lifecycle) {
                        lifecycle->record(
                            rwn::desktop::VisualLifecycleStage::
                                metal_rect_decision,
                            candidate.target_frame_id, monotonic_us(),
                            rwn::desktop::VisualTraceEvent{
                                .representation_epoch = rect_epoch,
                                .metal_dirty_tiles = candidate.dirty_tiles,
                                .metal_dirty_ratio_ppm =
                                    candidate.dirty_ratio_ppm,
                                .stage_duration_us = candidate.compare_us,
                                .payload_bytes = candidate.packed_bytes,
                                .rectangle_count =
                                    candidate.merged_rectangles,
                                .fallback_reason =
                                    fallback_for_decision(candidate.decision),
                            });
                    }
                    if (candidate.decision == rwn::platform::macos::
                            MacosExactRectDecision::selected) {
                        if (lifecycle) {
                            lifecycle->record(
                                rwn::desktop::VisualLifecycleStage::rect_readback,
                                candidate.target_frame_id, monotonic_us(),
                                rwn::desktop::VisualTraceEvent{
                                    .representation_epoch = rect_epoch,
                                    .stage_duration_us = candidate.readback_us,
                                    .payload_bytes = candidate.packed_bytes,
                                    .rectangle_count =
                                        candidate.merged_rectangles,
                                });
                        }
                        pending_rect_digest =
                            rwn::desktop::advance_canonical_rect_digest(
                                exact_digest, candidate.target_frame_id,
                                candidate.rectangles);
                        const auto wire_started = monotonic_us();
                        for (const auto& rectangle : candidate.rectangles) {
                            const auto payload =
                                rwn::desktop::encode_visual_raw_rect(rectangle);
                            write_visual_message(
                                rwn::desktop::VisualMessageType::raw_rect, 0,
                                rect_epoch, candidate.target_frame_id,
                                candidate.captured_at_us, payload);
                            rect_bytes += rectangle.bgra.size();
                        }
                        const auto commit =
                            rwn::desktop::encode_visual_frame_commit({
                                .base_frame_id = exact_frame_id,
                            });
                        write_visual_message(
                            rwn::desktop::VisualMessageType::frame_commit,
                            rwn::desktop::visual_flag_frame_final,
                            rect_epoch, candidate.target_frame_id,
                            candidate.captured_at_us, commit);
                        rect_sent_at_us = monotonic_us();
                        rect_wire_ms.push_back(static_cast<double>(
                            rect_sent_at_us - wire_started) / 1000.0);
                        rect_readback_ms.push_back(
                            static_cast<double>(candidate.readback_us) / 1000.0);
                        rect_target_frame_id = candidate.target_frame_id;
                        rect_target_content_frame_id =
                            candidate.content_frame_id;
                        rect_last_superseded_source = rect_target_frame_id;
                        rect_last_superseded_content_frame =
                            rect_target_content_frame_id;
                        ++rect_transactions;
                        hybrid_mode =
                            HybridSnapshotMode::awaiting_rect_ack;
                        if (lifecycle) {
                            lifecycle->record(
                                rwn::desktop::VisualLifecycleStage::
                                    raw_rect_write_complete,
                                rect_target_frame_id, rect_sent_at_us,
                                rwn::desktop::VisualTraceEvent{
                                    .representation_epoch = rect_epoch,
                                    .stage_duration_us =
                                        rect_sent_at_us - wire_started,
                                    .payload_bytes = candidate.packed_bytes,
                                    .rectangle_count =
                                        candidate.merged_rectangles,
                                });
                            lifecycle->record(
                                rwn::desktop::VisualLifecycleStage::
                                    frame_commit_write_complete,
                                rect_target_frame_id, rect_sent_at_us,
                                rwn::desktop::VisualTraceEvent{
                                    .representation_epoch = rect_epoch,
                                    .metal_dirty_tiles =
                                        candidate.dirty_tiles,
                                    .metal_dirty_ratio_ppm =
                                        candidate.dirty_ratio_ppm,
                                });
                        }
                    } else if (
                        candidate.decision != rwn::platform::macos::
                            MacosExactRectDecision::unchanged &&
                        candidate.decision != rwn::platform::macos::
                            MacosExactRectDecision::not_ready) {
                        ++rect_cancels;
                        resume_forced_idr_video(
                            rwn::desktop::VisualStateResetReason::
                                representation_transition,
                            fallback_for_decision(candidate.decision));
                    }
                }
            } else if (hybrid_mode == HybridSnapshotMode::video && exact_state &&
                       (exact_only ||
                        (now_us >= exact_state->updated_at_us &&
                         now_us - exact_state->updated_at_us >=
                             snapshot_quiet_interval_us)) &&
                       now_us >= snapshot_reentry_not_before_us) {
                // Stop the producer from reacquiring the gate while it waits
                // for a capture. Then drain any already-entered submission
                // before changing epochs; mutex fairness is not guaranteed.
                video_submissions_enabled.store(false,
                    std::memory_order_release);
                std::lock_guard gate(submission_gate);
                video_liveness_enabled.store(false,
                    std::memory_order_release);
                const auto old_epoch = representation_epoch.load(
                    std::memory_order_relaxed);
                if (old_epoch == std::numeric_limits<std::uint64_t>::max()) {
                    throw std::overflow_error(
                        "visual representation epoch exhausted");
                }
                snapshot_epoch = old_epoch + 1U;
                representation_epoch.store(
                    snapshot_epoch, std::memory_order_release);
                if (!exact_only) encoder.discard_before_epoch(snapshot_epoch);
                const auto reset = rwn::desktop::encode_visual_state_reset({
                    .reason = rwn::desktop::VisualStateResetReason::
                        representation_transition,
                });
                write_visual_message(
                    rwn::desktop::VisualMessageType::state_reset, 0,
                    snapshot_epoch, exact_state->frame_id,
                    exact_state->captured_at_us, reset);
                ++representation_switches;
                ++snapshot_attempts;
                hybrid_mode = HybridSnapshotMode::quiescing;
                trace_representation_state(
                    rwn::desktop::VisualFallbackReason::none,
                    exact_state->frame_id, snapshot_epoch, now_us);
                report_snapshot_event(
                    "quiescing", snapshot_epoch, exact_state->frame_id,
                    0.0, 0.0, 0.0, 0.0, 0);
            } else if (!exact_only &&
                       hybrid_mode == HybridSnapshotMode::quiescing && exact_state &&
                       now_us - exact_state->updated_at_us <
                           snapshot_quiet_interval_us) {
                ++snapshot_cancels;
                resume_forced_idr_video(
                    rwn::desktop::VisualStateResetReason::
                        representation_transition,
                    rwn::desktop::VisualFallbackReason::
                        newer_incompatible_source);
            }
        }
        if (visual_protocol) {
            std::optional<PendingCursor> cursor;
            std::optional<rwn::desktop::VisualCursorShape> cursor_shape;
            {
                std::lock_guard lock(cursor_mutex);
                cursor.swap(pending_cursor);
                cursor_shape.swap(pending_cursor_shape);
            }
            if (cursor_shape) {
                const auto sampled_at_us = static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now().time_since_epoch())
                        .count());
                const auto payload =
                    rwn::desktop::encode_visual_cursor_shape(*cursor_shape);
                const auto header =
                    rwn::desktop::encode_visual_message_header({
                        .type = rwn::desktop::VisualMessageType::cursor_shape,
                        .payload_size =
                            static_cast<std::uint32_t>(payload.size()),
                        .session_generation = session_generation,
                        .representation_epoch = representation_epoch.load(),
                        .visual_sequence = ++visual_sequence,
                        .captured_at_us = sampled_at_us,
                    });
                std::cout.write(
                    reinterpret_cast<const char*>(header.data()),
                    static_cast<std::streamsize>(header.size()));
                std::cout.write(
                    reinterpret_cast<const char*>(payload.data()),
                    static_cast<std::streamsize>(payload.size()));
                std::cout.flush();
                report_bytes += header.size() + payload.size();
            }
            if (cursor) {
                const auto payload =
                    rwn::desktop::encode_visual_cursor_position(
                        cursor->position);
                const auto header =
                    rwn::desktop::encode_visual_message_header({
                        .type = rwn::desktop::VisualMessageType::cursor_position,
                        .payload_size =
                            static_cast<std::uint32_t>(payload.size()),
                        .session_generation = session_generation,
                        .representation_epoch = representation_epoch.load(),
                        .visual_sequence = ++visual_sequence,
                        .captured_at_us = cursor->captured_at_us,
                    });
                std::cout.write(
                    reinterpret_cast<const char*>(header.data()),
                    static_cast<std::streamsize>(header.size()));
                std::cout.write(
                    reinterpret_cast<const char*>(payload.data()),
                    static_cast<std::streamsize>(payload.size()));
                std::cout.flush();
                ++cursor_sent;
                ++report_cursor_sent;
                report_bytes += header.size() + payload.size();
            }
        }
        const auto encoded_wait = snapshot_enabled &&
                (hybrid_mode == HybridSnapshotMode::sending ||
                 hybrid_mode == HybridSnapshotMode::awaiting_ack ||
                 hybrid_mode == HybridSnapshotMode::exact ||
                 hybrid_mode == HybridSnapshotMode::awaiting_rect_ack)
            ? std::chrono::milliseconds{1}
            : visual_protocol ? std::chrono::milliseconds{5}
                              : std::chrono::milliseconds{200};
        auto frame = exact_only
            ? std::optional<rwn::desktop::VideoFrame>{}
            : encoder.next_encoded(encoded_wait);
        if (exact_only) {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        const auto encoded_at = std::chrono::steady_clock::now();
        if (!frame) {
            if (snapshot_enabled &&
                hybrid_mode == HybridSnapshotMode::quiescing) {
                const auto queue_stats = encoder_queue_stats();
                const auto obsolete_in_flight = snapshot_epoch != 0 &&
                    snapshot_epoch > representation_epoch.load(
                        std::memory_order_acquire);
                if (queue_stats.encoded_queue_current == 0 &&
                    (queue_stats.in_flight_current == 0 ||
                     obsolete_in_flight)) {
                    auto snapshot = exact_analyzer->snapshot_latest_source();
                    if (snapshot_epoch == 0) {
                        throw std::logic_error(
                            "snapshot representation epoch was not reserved");
                    }
                    snapshot_frame_id = snapshot.frame_id;
                    snapshot_content_frame_id = snapshot.content_frame_id;
                    snapshot_sha256 = rwn::core::sha256(snapshot.bgra);
                    snapshot_source_updated_at_us =
                        snapshot.source_updated_at_us;
                    snapshot_readback_ms.push_back(
                        static_cast<double>(snapshot.readback_us) / 1000.0);
                    if (!snapshot_wire_drain.begin(
                            snapshot.content_frame_id,
                            static_cast<std::uint32_t>(snapshot.bgra.size()),
                            snapshot.row_stride)) {
                        throw std::logic_error(
                            "snapshot wire drain rejected canonical surface");
                    }
                    snapshot_wire_started_at_us = monotonic_us();
                    pending_snapshot.emplace(std::move(snapshot));
                    hybrid_mode = HybridSnapshotMode::sending;
                    report_snapshot_event(
                        "sending", snapshot_epoch, snapshot_frame_id,
                        snapshot_readback_ms.back(), 0.0, 0.0, 0.0, 0);
                }
            }
            continue;
        }
        if (frame->representation_epoch != representation_epoch.load()) {
            ++snapshot_cancels;
            continue;
        }
        if (lifecycle) {
            lifecycle->record(
                rwn::desktop::VisualLifecycleStage::vt_output,
                frame->frame_id,
                static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        encoded_at.time_since_epoch()).count()));
        }
        if (const auto timing = encoder.last_timing()) {
            vt_callback_ms.push_back(
                static_cast<double>(timing->submit_to_callback_us) / 1000.0);
            hardware_active = timing->hardware_active;
            hardware_query_status = timing->hardware_query_status;
            max_frame_delay_status = timing->max_frame_delay_status;
        }
        ++report_encoded_frames;
        std::vector<std::byte> payload;
        std::vector<std::byte> header;
        if (visual_protocol) {
            payload = rwn::desktop::encode_visual_h264_access_unit({
                .width = frame->width,
                .height = frame->height,
                .encoded = frame->encoded,
            });
            header = rwn::desktop::encode_visual_message_header({
                .type = rwn::desktop::VisualMessageType::h264_access_unit,
                .flags = static_cast<std::uint8_t>(
                    rwn::desktop::visual_flag_frame_final |
                    (frame->keyframe
                        ? rwn::desktop::visual_flag_keyframe : 0U)),
                .payload_size = static_cast<std::uint32_t>(payload.size()),
                .session_generation = session_generation,
                .representation_epoch = frame->representation_epoch,
                .visual_sequence = ++visual_sequence,
                .frame_id = frame->frame_id,
                .captured_at_us = frame->captured_at_us,
            });
        } else {
            payload = frame->encoded;
            header = rwn::desktop::encode_encoded_preview_frame_header({
                .frame_id = frame->frame_id,
                .captured_at_us = frame->captured_at_us,
                .width = frame->width,
                .height = frame->height,
                .payload_size =
                    static_cast<std::uint32_t>(payload.size()),
                .keyframe = frame->keyframe,
            });
        }
        const auto ssh_write_started = std::chrono::steady_clock::now();
        std::cout.write(
            reinterpret_cast<const char*>(header.data()),
            static_cast<std::streamsize>(header.size()));
        std::cout.write(
            reinterpret_cast<const char*>(payload.data()),
            static_cast<std::streamsize>(payload.size()));
        std::cout.flush();
        const auto ssh_write_finished = std::chrono::steady_clock::now();
        if (lifecycle && std::cout.good()) {
            lifecycle->record(
                rwn::desktop::VisualLifecycleStage::wire_write_complete,
                frame->frame_id,
                static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        ssh_write_finished.time_since_epoch()).count()),
                rwn::desktop::VisualTraceEvent{
                    .representation_epoch = frame->representation_epoch,
                    .stage_duration_us = static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::microseconds>(
                            ssh_write_finished - ssh_write_started).count()),
                    .payload_bytes = payload.size(),
                });
        }
        ssh_write_ms.push_back(
            std::chrono::duration<double, std::milli>(
                ssh_write_finished - ssh_write_started).count());
        report_bytes += header.size() + payload.size();
        const auto metrics_elapsed = encoded_at - metrics_started;
        if (metrics_elapsed >= std::chrono::seconds{1}) {
            const auto seconds =
                std::chrono::duration<double>(metrics_elapsed).count();
            std::vector<double> report_capture_wait_ms;
            std::vector<double> report_screen_capture_age_ms;
            std::uint64_t report_captured_frames{};
            {
                std::lock_guard lock(capture_metrics_mutex);
                report_capture_wait_ms.swap(capture_wait_ms);
                report_screen_capture_age_ms.swap(screen_capture_age_ms);
                report_captured_frames = std::exchange(captured_frames, 0);
            }
            std::vector<double> report_dirty_analyzer_ms;
            std::vector<double> report_dirty_16_ratios;
            std::vector<double> report_dirty_32_ratios;
            std::vector<double> report_dirty_64_ratios;
            std::optional<rwn::platform::macos::MacosDirtyAnalysisResult>
                report_latest_dirty;
            std::uint64_t report_analyzed_frames{};
            {
                std::lock_guard lock(dirty_metrics_mutex);
                report_dirty_analyzer_ms.swap(dirty_analyzer_ms);
                report_dirty_16_ratios.swap(dirty_16_ratios);
                report_dirty_32_ratios.swap(dirty_32_ratios);
                report_dirty_64_ratios.swap(dirty_64_ratios);
                report_latest_dirty = latest_dirty_result;
                report_analyzed_frames = std::exchange(analyzed_frames, 0);
            }
            const auto replaced_frames = capture.replaced_frame_count();
            const auto raw_replacements =
                replaced_frames - last_replaced_frames;
            last_replaced_frames = replaced_frames;
            const auto queue_stats = encoder_queue_stats();
            const auto submitted_since_report =
                queue_stats.submitted_frames - last_queue_stats.submitted_frames;
            const auto completed_since_report =
                queue_stats.completed_frames - last_queue_stats.completed_frames;
            const auto lifecycle_snapshot = lifecycle
                ? lifecycle->snapshot()
                : rwn::desktop::VisualLifecycleSnapshot{};
            const auto residency_now_us = monotonic_us();
            const auto total_rect_residency_us =
                rect_residency_accumulated_us +
                (rect_residency_started_at_us == 0 ? 0U :
                    residency_now_us - rect_residency_started_at_us);
            const auto residency_elapsed_us =
                residency_now_us - hybrid_metrics_started_at_us;
            const auto exact_residency_ratio = residency_elapsed_us == 0
                ? 0.0
                : static_cast<double>(total_rect_residency_us) /
                    static_cast<double>(residency_elapsed_us);
            std::lock_guard diagnostics_lock(diagnostics_mutex);
            std::cerr
                << std::fixed << std::setprecision(3)
                << "RWN_METRICS host capture_fps="
                << static_cast<double>(
                       report_captured_frames + raw_replacements) / seconds
                << " submit_fps="
                << static_cast<double>(submitted_since_report) / seconds
                << " encode_fps="
                << static_cast<double>(completed_since_report) / seconds
                << " capture_wait_p50_ms="
                << percentile_ms(report_capture_wait_ms, 0.50)
                << " capture_wait_p95_ms="
                << percentile_ms(report_capture_wait_ms, 0.95)
                << " sc_age_p50_ms="
                << percentile_ms(report_screen_capture_age_ms, 0.50)
                << " sc_age_p95_ms="
                << percentile_ms(report_screen_capture_age_ms, 0.95)
                << " sc_age_max_ms="
                << maximum_ms(report_screen_capture_age_ms)
                << " bgra_copy_p50_ms=0.000"
                << " bgra_copy_p95_ms=0.000"
                << " bgra_copy_max_ms=0.000"
                << " bgra_copy_removed=1"
                << " vt_callback_p50_ms="
                << percentile_ms(vt_callback_ms, 0.50)
                << " vt_callback_p95_ms="
                << percentile_ms(vt_callback_ms, 0.95)
                << " vt_callback_max_ms=" << maximum_ms(vt_callback_ms)
                << " ssh_write_p50_ms="
                << percentile_ms(ssh_write_ms, 0.50)
                << " ssh_write_p95_ms="
                << percentile_ms(ssh_write_ms, 0.95)
                << " ssh_write_max_ms=" << maximum_ms(ssh_write_ms)
                << " bytes_per_write="
                << (report_encoded_frames == 0 ? 0 :
                    report_bytes / report_encoded_frames)
                << " vt_mode=" << vt_mode_name(vt_mode)
                << " vt_hardware=" << hardware_active
                << " vt_hardware_query_status=" << hardware_query_status
                << " max_delay_status=" << max_frame_delay_status
                << " raw_pending=0/1"
                << " vt_inflight=" << queue_stats.in_flight_current
                << " vt_inflight_max=" << queue_stats.in_flight_max
                << " encoded_queue=" << queue_stats.encoded_queue_current
                << " encoded_queue_max=" << queue_stats.encoded_queue_max
                << " encoded_queue_overruns="
                << queue_stats.encoded_queue_overruns
                << " vt_stale_epoch_drops="
                << queue_stats.stale_epoch_drops
                << " representation_epoch="
                << representation_epoch.load()
                << " hybrid_snapshot_mode="
                << static_cast<unsigned>(hybrid_mode)
                << " snapshot_source_frame=" << snapshot_frame_id
                << " snapshot_bytes=" << snapshot_bytes
                << " snapshot_chunks=" << snapshot_chunks
                << " snapshot_attempts=" << snapshot_attempts
                << " snapshot_cancels=" << snapshot_cancels
                << " snapshot_cooldown_entries="
                << snapshot_cooldown_entries
                << " snapshot_cooldown_remaining_ms="
                << (residency_now_us >= snapshot_reentry_not_before_us
                    ? 0.0
                    : static_cast<double>(
                        snapshot_reentry_not_before_us - residency_now_us) /
                        1000.0)
                << " snapshot_attempts_per_min="
                << (residency_elapsed_us == 0 ? 0.0 :
                    static_cast<double>(snapshot_attempts) * 60'000'000.0 /
                    static_cast<double>(residency_elapsed_us))
                << " snapshot_stale_acks=" << stale_snapshot_acks
                << " snapshot_readback_p95_ms="
                << percentile_ms(snapshot_readback_ms, 0.95)
                << " snapshot_wire_p95_ms="
                << percentile_ms(snapshot_wire_ms, 0.95)
                << " snapshot_ack_p95_ms="
                << percentile_ms(snapshot_ack_ms, 0.95)
                << " snapshot_quiet_exact_p95_ms="
                << percentile_ms(snapshot_quiet_to_exact_ms, 0.95)
                << " raw_rect_experimental=" << raw_rect_experimental
                << " rect_transactions=" << rect_transactions
                << " rect_cancels=" << rect_cancels
                << " rect_bytes=" << rect_bytes
                << " rect_superseded_sources=" << rect_superseded_sources
                << " rect_compare_p95_ms="
                << percentile_ms(rect_compare_ms, 0.95)
                << " rect_readback_p95_ms="
                << percentile_ms(rect_readback_ms, 0.95)
                << " rect_wire_p95_ms="
                << percentile_ms(rect_wire_ms, 0.95)
                << " rect_ack_p95_ms="
                << percentile_ms(rect_ack_ms, 0.95)
                << " exact_residency_ratio=" << exact_residency_ratio
                << " representation_switches_per_min="
                << (residency_elapsed_us == 0 ? 0.0 :
                    static_cast<double>(representation_switches) *
                    60'000'000.0 /
                    static_cast<double>(residency_elapsed_us))
                << " visual_protocol=" << visual_protocol
                << " cursor_produced=" << cursor_produced.load()
                << " cursor_sent=" << cursor_sent
                << " cursor_sent_fps="
                << static_cast<double>(report_cursor_sent) / seconds
                << " cursor_replaced=" << cursor_replaced.load()
                << " trace_enabled=" << visual_trace
                << " trace_dropped="
                << (lifecycle ? lifecycle->trace_dropped() : 0)
                << " tail_refresh_submitted="
                << tail_refresh_submitted.load(std::memory_order_relaxed)
                << " source_generation="
                << lifecycle_snapshot.source_generation
                << " published_generation="
                << lifecycle_snapshot.published_generation
                << " submitted_generation="
                << lifecycle_snapshot.submitted_generation
                << " encoded_generation="
                << lifecycle_snapshot.encoded_generation
                << " written_generation="
                << lifecycle_snapshot.written_generation
                << " dirty_analyzer=" << dirty_analysis
                << " dirty_analysis_fps="
                << static_cast<double>(report_analyzed_frames) / seconds
                << " dirty_analyzer_p50_ms="
                << percentile_ms(report_dirty_analyzer_ms, 0.50)
                << " dirty_analyzer_p95_ms="
                << percentile_ms(report_dirty_analyzer_ms, 0.95)
                << " dirty16_ratio_p50="
                << percentile_ms(report_dirty_16_ratios, 0.50)
                << " dirty16_ratio_p95="
                << percentile_ms(report_dirty_16_ratios, 0.95)
                << " dirty32_ratio_p50="
                << percentile_ms(report_dirty_32_ratios, 0.50)
                << " dirty32_ratio_p95="
                << percentile_ms(report_dirty_32_ratios, 0.95)
                << " dirty64_ratio_p50="
                << percentile_ms(report_dirty_64_ratios, 0.50)
                << " dirty64_ratio_p95="
                << percentile_ms(report_dirty_64_ratios, 0.95)
                << " dirty16_tiles="
                << (report_latest_dirty
                    ? report_latest_dirty->tile_16.dirty_tiles : 0)
                << " dirty16_rects="
                << (report_latest_dirty
                    ? report_latest_dirty->tile_16.merged_rectangles : 0)
                << " dirty32_tiles="
                << (report_latest_dirty
                    ? report_latest_dirty->tile_32.dirty_tiles : 0)
                << " dirty32_rects="
                << (report_latest_dirty
                    ? report_latest_dirty->tile_32.merged_rectangles : 0)
                << " dirty64_tiles="
                << (report_latest_dirty
                    ? report_latest_dirty->tile_64.dirty_tiles : 0)
                << " dirty64_rects="
                << (report_latest_dirty
                    ? report_latest_dirty->tile_64.merged_rectangles : 0)
                << " dirty_analysis_replaced="
                << capture.replaced_analysis_frame_count()
                << " sc_fps=" << frames_per_second
                << " sc_queue_depth=5"
                << " dropped_raw_stale=" << raw_replacements
                << " network_mbps="
                << static_cast<double>(report_bytes) * 8.0 /
                       seconds / 1'000'000.0
                << '\n' << std::flush;
            metrics_started = encoded_at;
            vt_callback_ms.clear();
            ssh_write_ms.clear();
            report_encoded_frames = 0;
            report_cursor_sent = 0;
            report_bytes = 0;
            snapshot_bytes = 0;
            snapshot_chunks = 0;
            snapshot_readback_ms.clear();
            snapshot_wire_ms.clear();
            snapshot_ack_ms.clear();
            snapshot_quiet_to_exact_ms.clear();
            rect_compare_ms.clear();
            rect_readback_ms.clear();
            rect_wire_ms.clear();
            rect_ack_ms.clear();
            last_queue_stats = queue_stats;
        }
    }
    stop_encoder_worker.store(true);
    if (!exact_only) encoder.stop_submissions();
    if (encoder_worker.joinable()) encoder_worker.join();
    stop_dirty_worker.store(true);
    capture.enable_dirty_analysis(false);
    if (dirty_worker.joinable()) dirty_worker.join();
    stop_cursor_worker.store(true);
    if (cursor_worker.joinable()) cursor_worker.join();
    if (visual_watchdog.joinable()) {
        stop_visual_watchdog.store(true);
        visual_watchdog.join();
    }
    if (trace_queue) trace_queue->close();
    if (trace_writer.joinable()) {
        stop_trace_writer.store(true);
        trace_writer.join();
    }
    if (input_worker.joinable()) {
        if (cancel_network) cancel_network();
        else ::close(STDIN_FILENO);
        input_worker.join();
    }
    return 0;
#else
    static_cast<void>(maximum_width);
    static_cast<void>(maximum_height);
    static_cast<void>(frames_per_second);
    static_cast<void>(bitrate_kbps);
    static_cast<void>(vt_mode_value);
    static_cast<void>(visual_protocol);
    static_cast<void>(dirty_analysis);
    static_cast<void>(visual_trace);
    static_cast<void>(interactive);
    static_cast<void>(raw_rect_experimental);
    static_cast<void>(h264_only_explicit);
    static_cast<void>(exact_only);
    static_cast<void>(cancel_network);
    std::cerr << "H.264 preview server is supported only on macOS\n";
    return 2;
#endif
}

int probe_desktop_runtime() {
    using enum rwn::desktop::PermissionState;
#if defined(_WIN32)
    rwn::platform::windows::WindowsDesktopPermissionBackend permissions;
    const auto status = permissions.status();
    if (status.capture != granted || status.input != granted) {
        std::cerr << "desktop permissions are unavailable\n";
        return 2;
    }
    const auto h264 = rwn::platform::windows::probe_h264_capabilities();
    std::cout << "capture=DXGI h264_hw_encoder=" << h264.hardware_encoder
              << " h264_hw_decoder=" << h264.hardware_decoder << '\n';
    rwn::platform::windows::WindowsDesktopCaptureBackend capture;
    const auto frame = capture.capture(std::chrono::seconds{2});
    if (!frame) {
        std::cerr << "desktop capture timed out without a changed frame\n";
        return 3;
    }
    std::cout << "frame width=" << frame->width
              << " height=" << frame->height
              << " bgra_bytes=" << frame->bgra.size() << '\n';
    return h264.hardware_encoder && h264.hardware_decoder ? 0 : 4;
#elif defined(__APPLE__)
    rwn::platform::macos::MacosDesktopPermissionBackend permissions;
    const auto status = permissions.status();
    if (status.capture != granted || status.input != granted) {
        std::cerr << "grant Screen Recording and Accessibility to rwn-desktop-agent\n";
        return 2;
    }
    rwn::platform::macos::MacosScreenCaptureBackend capture;
    rwn::platform::macos::MacosVideoToolboxEncoder encoder;
    const auto raw = capture.capture(std::chrono::seconds{2});
    if (!raw) {
        std::cerr << "ScreenCaptureKit timed out\n";
        return 3;
    }
    const auto encoded = encoder.encode(*raw, {}, true);
    std::cout << "capture=ScreenCaptureKit encoder=VideoToolbox width="
              << encoded.width << " height=" << encoded.height
              << " h264_bytes=" << encoded.encoded.size()
              << " keyframe=" << encoded.keyframe << '\n';
    return encoded.keyframe ? 0 : 4;
#else
    std::cerr << "desktop probe is supported only on Windows and macOS\n";
    return 2;
#endif
}

int probe_cursor_shape_runtime() {
#if defined(__APPLE__)
    rwn::platform::macos::MacosCursorPositionSampler sampler(1920, 1080);
    const auto shape = sampler.sample_shape();
    if (!shape) {
        std::cerr << "cursor shape is unavailable; embedded fallback required\n";
        return 2;
    }
    std::uint64_t alpha_top{};
    std::uint64_t alpha_bottom{};
    std::uint64_t alpha_weight{};
    std::uint64_t alpha_weighted_y{};
    for (std::uint16_t y = 0; y < shape->height; ++y) {
        for (std::uint16_t x = 0; x < shape->width; ++x) {
            const auto offset =
                (static_cast<std::size_t>(y) * shape->width + x) * 4U;
            const auto alpha = std::to_integer<std::uint8_t>(
                shape->bgra[offset + 3U]);
            alpha_weight += alpha;
            alpha_weighted_y += static_cast<std::uint64_t>(alpha) * y;
            if (y < shape->height / 2U) {
                alpha_top += alpha;
            } else {
                alpha_bottom += alpha;
            }
        }
    }
    std::cout << "cursor_shape=public-sdk"
              << " shape_id=" << shape->shape_id
              << " width=" << shape->width
              << " height=" << shape->height
              << " hotspot=" << shape->hotspot_x << ',' << shape->hotspot_y
              << " bgra_bytes=" << shape->bgra.size()
              << " alpha_top=" << alpha_top
              << " alpha_bottom=" << alpha_bottom
              << " alpha_centroid_y="
              << (alpha_weight == 0 ? 0 : alpha_weighted_y / alpha_weight)
              << '\n';
    return 0;
#else
    std::cerr << "cursor shape probe is supported only on macOS\n";
    return 2;
#endif
}

int probe_audio_runtime(
    const std::optional<std::filesystem::path>& opus_library) {
#if defined(_WIN32)
    rwn::platform::windows::WindowsAudioLoopbackCapture capture;
    rwn::platform::windows::WindowsAudioPlayback playback;
    const rwn::audio::PcmFrame silence{
        .sample_rate = rwn::audio::opus_sample_rate,
        .channels = rwn::audio::opus_channels,
        .samples_per_channel = rwn::audio::opus_frame_samples,
        .interleaved_samples = std::vector<std::int16_t>(
            rwn::audio::opus_channels * rwn::audio::opus_frame_samples),
    };
    playback.play(silence, std::chrono::seconds{2});
    const auto captured = capture.capture(std::chrono::seconds{2});
    if (!captured) {
        std::cerr << "WASAPI loopback timed out\n";
        return 3;
    }
    std::cout << "capture=WASAPI-loopback playback=WASAPI-render"
              << " sample_rate=" << captured->frame.sample_rate
              << " channels=" << captured->frame.channels
              << " samples=" << captured->frame.samples_per_channel;
    if (opus_library) {
        rwn::audio::DynamicOpusCodec codec(*opus_library);
        const auto encoded = codec.encode(captured->frame);
        const auto decoded = codec.decode({
            .sequence = 1,
            .captured_at_us = captured->captured_at_us,
            .sample_rate = captured->frame.sample_rate,
            .channels = captured->frame.channels,
            .samples_per_channel = captured->frame.samples_per_channel,
            .opus = encoded,
        });
        const auto plc = codec.conceal_loss(
            captured->frame.samples_per_channel);
        std::cout << " opus_bytes=" << encoded.size()
                  << " decoded_samples=" << decoded.samples_per_channel
                  << " plc_samples=" << plc.samples_per_channel;
    }
    std::cout << '\n';
    return 0;
#elif defined(__APPLE__)
    rwn::platform::macos::MacosSystemAudioCapture capture;
    rwn::platform::macos::MacosAudioPlayback playback;
    const rwn::audio::PcmFrame silence{
        .sample_rate = rwn::audio::opus_sample_rate,
        .channels = rwn::audio::opus_channels,
        .samples_per_channel = rwn::audio::opus_frame_samples,
        .interleaved_samples = std::vector<std::int16_t>(
            rwn::audio::opus_channels * rwn::audio::opus_frame_samples),
    };
    playback.play(silence, std::chrono::seconds{2});
    const auto captured = capture.capture(std::chrono::seconds{2});
    if (!captured) {
        std::cerr << "ScreenCaptureKit system audio timed out\n";
        return 3;
    }
    std::cout << "capture=ScreenCaptureKit-audio playback=AudioQueue"
              << " sample_rate=" << captured->frame.sample_rate
              << " channels=" << captured->frame.channels
              << " samples=" << captured->frame.samples_per_channel;
    if (opus_library) {
        rwn::audio::DynamicOpusCodec codec(*opus_library);
        const auto encoded = codec.encode(captured->frame);
        const auto decoded = codec.decode({
            .sequence = 1,
            .captured_at_us = captured->captured_at_us,
            .sample_rate = captured->frame.sample_rate,
            .channels = captured->frame.channels,
            .samples_per_channel = captured->frame.samples_per_channel,
            .opus = encoded,
        });
        const auto plc = codec.conceal_loss(
            captured->frame.samples_per_channel);
        std::cout << " opus_bytes=" << encoded.size()
                  << " decoded_samples=" << decoded.samples_per_channel
                  << " plc_samples=" << plc.samples_per_channel;
    }
    std::cout << '\n';
    return 0;
#else
    static_cast<void>(opus_library);
    std::cerr << "audio runtime probe is currently implemented on Windows\n";
    return 2;
#endif
}

}  // namespace

int main(const int argc, char** argv) {
    try {
#if defined(__APPLE__)
        rwn::platform::macos::require_process_identity(
            rwn::core::ProcessRole::desktop_agent);
#endif
        if (argc == 3 && (std::string_view(argv[1]) == "--check-tls-identity" ||
                          std::string_view(argv[1]) == "--authorize-tls-identity")) {
#if defined(__APPLE__)
            const bool interactive = std::string_view(argv[1]) == "--authorize-tls-identity";
            if (interactive)
                std::cerr << "Approve this LanPilot agent in the native Keychain dialog, or cancel. No network listener is running.\n";
            rwn::platform::macos::verify_local_tls_identity(
                rwn::preview::TlsPreviewSession::identity(argv[2]), interactive);
            std::cout << "local_tls_identity_signing=ready private_export=0 peer_authenticated=0 listener_started=0\n";
            return 0;
#else
            throw std::invalid_argument("local TLS identity setup requires macOS");
#endif
        }
        if ((argc == 9 || argc == 10) && std::string_view(argv[1]) == "--stream-visual-tls") {
#if defined(__APPLE__)
            const std::string_view control = argv[7];
            const std::string_view mode = argv[8];
            if ((control != "view-only" && control != "interactive") ||
                (mode != "h264-only" && mode != "exact-only"))
                throw std::invalid_argument("invalid TLS desktop mode");
            rwn::transport::AppleNetworkServerOptions options;
            options.listen_port = static_cast<std::uint16_t>(parse_u32(argv[3],1,65535,"TLS port"));
            options.maximum_pending_connections = 2;
            options.identity.keychain_persistent_reference = rwn::preview::TlsPreviewSession::identity(argv[4]);
            options.identity.allowed_peer_certificate_sha256 = {
                rwn::transport::parse_apple_network_sha256_fingerprint(argv[5])};
            rwn::preview::TlsPreviewSession network(options,argv[2],
                rwn::preview::TlsPreviewSession::read_root(argv[6]),control == "interactive",
                argc == 10 ? rwn::preview::TlsPreviewSession::read_root(argv[9])
                           : std::vector<std::byte>{});
            std::cerr << "RWN_TRANSPORT visual=tls control=tls agent=ssh session_ttl_s=1800 control_idle_timeout_s=30\n";
            return stream_h264_stdio(1920,1080,60,20000,"baseline",true,false,false,
                control == "interactive",mode == "exact-only",mode == "h264-only",mode == "exact-only",
                [&] { network.cancel(); });
#else
            throw std::invalid_argument("TLS desktop server requires macOS");
#endif
        }
        if (argc == 2 && std::string_view(argv[1]) == "--probe-desktop") {
            return probe_desktop_runtime();
        }
        if (argc == 2 &&
            std::string_view(argv[1]) == "--probe-cursor-shape") {
            return probe_cursor_shape_runtime();
        }
        if (argc == 2 &&
            std::string_view(argv[1]) == "--probe-audio-runtime") {
            return probe_audio_runtime(std::nullopt);
        }
        if (argc == 3 && std::string_view(argv[1]) == "--probe-audio") {
            return probe_audio_runtime(std::filesystem::path(argv[2]));
        }
        if (argc == 5 &&
            std::string_view(argv[1]) == "--stream-preview-stdio") {
            return stream_preview_stdio(
                parse_u32(argv[2], 320, rwn::desktop::maximum_preview_width,
                          "preview width"),
                parse_u32(argv[3], 180, rwn::desktop::maximum_preview_height,
                          "preview height"),
                parse_u32(argv[4], 1, 120, "preview frame rate"));
        }
        if ((argc == 6 || argc == 7 || argc == 8) &&
            (std::string_view(argv[1]) == "--stream-h264-stdio" ||
             std::string_view(argv[1]) == "--stream-visual-stdio" ||
             std::string_view(argv[1]) ==
                 "--stream-visual-interactive-stdio" ||
             std::string_view(argv[1]) ==
                 "--stream-visual-interactive-trace-stdio" ||
             std::string_view(argv[1]) ==
                 "--stream-visual-analyze-stdio" ||
             std::string_view(argv[1]) ==
                  "--stream-visual-trace-stdio")) {
            const auto command = std::string_view(argv[1]);
            const auto hybrid_mode = argc == 8
                ? std::string_view(argv[7]) : std::string_view{};
            const auto raw_rect_experimental =
                hybrid_mode == "raw-rect-experimental";
            const auto h264_only_explicit = hybrid_mode == "h264-only";
            const auto snapshot_only_explicit = hybrid_mode == "snapshot-only";
            const auto exact_only = hybrid_mode == "exact-only";
            if (argc == 8 &&
                !raw_rect_experimental && !h264_only_explicit &&
                !snapshot_only_explicit && !exact_only) {
                throw std::invalid_argument("invalid hybrid stream mode");
            }
            if ((raw_rect_experimental || exact_only) &&
                command != "--stream-visual-interactive-stdio" &&
                command != "--stream-visual-interactive-trace-stdio") {
                throw std::invalid_argument(
                    "exact framebuffer updates require interactive stream");
            }
            return stream_h264_stdio(
                parse_u32(argv[2], 320, rwn::desktop::maximum_preview_width,
                          "preview width"),
                parse_u32(argv[3], 180, rwn::desktop::maximum_preview_height,
                          "preview height"),
                parse_u32(argv[4], 1, 60, "preview frame rate"),
                parse_u32(argv[5], 1000, 50000, "preview bitrate"),
                argc >= 7 ? std::string_view(argv[6])
                          : std::string_view("baseline"),
                command != "--stream-h264-stdio",
                command == "--stream-visual-analyze-stdio" ||
                    command == "--stream-visual-trace-stdio" ||
                    command == "--stream-visual-interactive-trace-stdio",
                command == "--stream-visual-trace-stdio" ||
                    command == "--stream-visual-interactive-trace-stdio",
                command == "--stream-visual-interactive-stdio" ||
                    command == "--stream-visual-interactive-trace-stdio",
                raw_rect_experimental || exact_only, h264_only_explicit,
                exact_only);
        }
        if (argc != 1) {
            std::cerr << "usage: rwn-desktop-agent [--probe-desktop | "
                         "--probe-cursor-shape | "
                         "--probe-audio-runtime | "
                         "--probe-audio <absolute-libopus-path> | "
                         "--stream-preview-stdio <max-width> <max-height> "
                         "<fps> | "
                         "--stream-h264-stdio <max-width> <max-height> "
                         "<fps> <bitrate-kbps> [baseline|low-latency|"
                         "delay-1|delay-0] | "
                         "--stream-visual-interactive-stdio <max-width> "
                         "<max-height> <fps> <bitrate-kbps> "
                         "[baseline|low-latency|delay-1|delay-0] | "
                         "--stream-visual-interactive-trace-stdio "
                         "<max-width> <max-height> <fps> <bitrate-kbps> "
                         "[baseline|low-latency|delay-1|delay-0] | "
                         "--stream-visual-stdio <max-width> <max-height> "
                         "<fps> <bitrate-kbps> [baseline|low-latency|"
                         "delay-1|delay-0] | "
                         "--stream-visual-analyze-stdio <max-width> "
                         "<max-height> <fps> <bitrate-kbps> "
                         "[baseline|low-latency|delay-1|delay-0] | "
                         "--stream-visual-trace-stdio <max-width> "
                         "<max-height> <fps> <bitrate-kbps> "
                         "[baseline|low-latency|delay-1|delay-0]]\n";
            return 64;
        }
        const auto policy = rwn::core::default_process_policy(
            rwn::core::ProcessRole::desktop_agent);
        std::cout << "Remote Workspace desktop agent ready; capabilities="
                  << policy.allowed_capabilities.size() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "rwn-desktop-agent: " << error.what() << '\n';
        return 1;
    }
}
