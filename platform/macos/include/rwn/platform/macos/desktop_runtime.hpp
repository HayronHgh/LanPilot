#pragma once

#include "rwn/desktop/desktop.hpp"
#include "rwn/desktop/pointer_click_tracker.hpp"
#include "rwn/desktop/visual_trace.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

namespace rwn::platform::macos {

struct MacosCaptureTiming {
    std::uint64_t frame_id{};
    std::uint64_t sample_presentation_us{};
    std::uint64_t callback_arrival_us{};
    std::int64_t sample_age_us{};
    std::uint64_t bgra_copy_us{};
    std::uint32_t configured_fps{};
    std::uint32_t queue_depth{};
};

enum class MacosVideoToolboxMode {
    baseline,
    low_latency_rate_control,
    max_frame_delay_1,
    max_frame_delay_0,
};

struct MacosEncodeTiming {
    std::uint64_t frame_id{};
    std::uint64_t representation_epoch{};
    std::uint64_t submitted_at_us{};
    std::uint64_t callback_at_us{};
    std::uint64_t submit_to_callback_us{};
    bool hardware_active{};
    std::int32_t hardware_query_status{};
    std::int32_t max_frame_delay_status{};
    MacosVideoToolboxMode mode{MacosVideoToolboxMode::baseline};
};

struct MacosEncoderQueueStats {
    std::uint64_t submitted_frames{};
    std::uint64_t completed_frames{};
    std::size_t in_flight_current{};
    std::size_t in_flight_max{};
    std::size_t encoded_queue_current{};
    std::size_t encoded_queue_max{};
    std::uint64_t encoded_queue_overruns{};
    std::uint64_t stale_epoch_drops{};
};

class MacosVideoToolboxEncoder;
class MacosMetalDirtyTileAnalyzer;

struct MacosExactBaseState {
    std::uint64_t frame_id{};
    std::uint64_t content_frame_id{};
    std::uint64_t captured_at_us{};
    std::uint64_t updated_at_us{};
    std::uint32_t width{};
    std::uint32_t height{};
};

struct MacosExactSnapshot {
    std::uint64_t frame_id{};
    std::uint64_t content_frame_id{};
    std::uint64_t captured_at_us{};
    std::uint64_t source_updated_at_us{};
    std::uint64_t readback_us{};
    std::uint32_t width{};
    std::uint32_t height{};
    std::uint32_t row_stride{};
    std::vector<std::byte> bgra;
};

enum class MacosExactRectDecision {
    not_ready,
    unchanged,
    selected,
    ratio_exceeded,
    rectangle_count_exceeded,
    byte_limit_exceeded,
};

struct MacosExactRectCandidate {
    MacosExactRectDecision decision{MacosExactRectDecision::not_ready};
    std::uint64_t base_frame_id{};
    std::uint64_t target_frame_id{};
    std::uint64_t content_frame_id{};
    std::uint64_t captured_at_us{};
    std::uint64_t compare_us{};
    std::uint64_t readback_us{};
    std::uint32_t dirty_tiles{};
    std::uint32_t dirty_ratio_ppm{};
    std::uint32_t merged_rectangles{};
    std::size_t packed_bytes{};
    std::vector<desktop::VisualRawRect> rectangles;
};

struct MacosDirtyTileStats {
    std::uint32_t tile_size{};
    std::uint32_t total_tiles{};
    std::uint32_t dirty_tiles{};
    std::uint32_t merged_rectangles{};
    double dirty_ratio{};
};

struct MacosDirtyAnalysisResult {
    std::uint64_t frame_id{};
    std::uint64_t analyzer_us{};
    bool baseline_frame{};
    MacosDirtyTileStats tile_16{};
    MacosDirtyTileStats tile_32{};
    MacosDirtyTileStats tile_64{};
};

class MacosScreenCaptureBackend final : public desktop::CaptureBackend {
public:
    MacosScreenCaptureBackend();
    MacosScreenCaptureBackend(
        std::uint32_t maximum_width,
        std::uint32_t maximum_height,
        std::uint32_t frames_per_second);
    MacosScreenCaptureBackend(
        std::uint32_t maximum_width,
        std::uint32_t maximum_height,
        std::uint32_t frames_per_second,
        desktop::VisualLifecycleTracker* lifecycle_tracker,
        bool shows_cursor = true,
        bool analyze_from_start = false);
    ~MacosScreenCaptureBackend() override;
    MacosScreenCaptureBackend(const MacosScreenCaptureBackend&) = delete;
    MacosScreenCaptureBackend& operator=(const MacosScreenCaptureBackend&) = delete;

    [[nodiscard]] std::optional<desktop::RawFrame> capture(
        std::chrono::milliseconds timeout) override;
    [[nodiscard]] bool submit_latest(
        MacosVideoToolboxEncoder& encoder,
        const desktop::VideoSettings& settings,
        bool force_keyframe,
        std::uint64_t representation_epoch,
        std::chrono::milliseconds timeout);
    [[nodiscard]] bool submit_tail_repeat(
        MacosVideoToolboxEncoder& encoder,
        const desktop::VideoSettings& settings,
        bool force_keyframe,
        std::uint64_t representation_epoch);
    [[nodiscard]] std::optional<MacosCaptureTiming> last_timing() const;
    [[nodiscard]] std::uint64_t replaced_frame_count() const;
    void enable_dirty_analysis(bool enabled);
    [[nodiscard]] std::optional<MacosDirtyAnalysisResult> analyze_latest(
        MacosMetalDirtyTileAnalyzer& analyzer,
        std::chrono::milliseconds timeout);
    [[nodiscard]] std::uint64_t replaced_analysis_frame_count() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

class MacosMetalDirtyTileAnalyzer final {
public:
    MacosMetalDirtyTileAnalyzer();
    ~MacosMetalDirtyTileAnalyzer();
    MacosMetalDirtyTileAnalyzer(const MacosMetalDirtyTileAnalyzer&) = delete;
    MacosMetalDirtyTileAnalyzer& operator=(
        const MacosMetalDirtyTileAnalyzer&) = delete;
    [[nodiscard]] std::optional<MacosExactBaseState> latest_source_state() const;
    [[nodiscard]] std::optional<MacosExactBaseState> canonical_exact_state() const;
    [[nodiscard]] MacosExactSnapshot snapshot_latest_source();
    [[nodiscard]] MacosExactRectCandidate evaluate_latest_rect(
        std::uint64_t base_frame_id,
        std::uint32_t maximum_dirty_ratio_ppm,
        std::uint32_t maximum_rectangles,
        std::size_t maximum_packed_bytes,
        bool reserve_target);
    [[nodiscard]] bool promote_pending_exact(std::uint64_t frame_id);
    void cancel_pending_exact() noexcept;
    void invalidate_exact_base() noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;

    friend class MacosScreenCaptureBackend;
};

class MacosVideoToolboxEncoder final : public desktop::VideoEncoder {
public:
    MacosVideoToolboxEncoder();
    explicit MacosVideoToolboxEncoder(MacosVideoToolboxMode mode);
    ~MacosVideoToolboxEncoder() override;
    MacosVideoToolboxEncoder(const MacosVideoToolboxEncoder&) = delete;
    MacosVideoToolboxEncoder& operator=(const MacosVideoToolboxEncoder&) = delete;

    [[nodiscard]] desktop::VideoFrame encode(
        const desktop::RawFrame& frame,
        const desktop::VideoSettings& settings,
        bool force_keyframe) override;
    [[nodiscard]] std::optional<desktop::VideoFrame> next_encoded(
        std::chrono::milliseconds timeout);
    [[nodiscard]] bool has_submission_capacity() const;
    void stop_submissions();
    [[nodiscard]] std::optional<MacosEncodeTiming> last_timing() const;
    [[nodiscard]] MacosEncoderQueueStats queue_stats() const;
    void discard_before_epoch(std::uint64_t epoch);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;

    friend class MacosScreenCaptureBackend;
};

class MacosCursorPositionSampler final {
public:
    MacosCursorPositionSampler(
        std::uint32_t surface_width,
        std::uint32_t surface_height);
    [[nodiscard]] desktop::VisualCursorPosition sample() const;
    [[nodiscard]] std::optional<desktop::VisualCursorShape>
        sample_shape() const;

private:
    std::uint32_t surface_width_{};
    std::uint32_t surface_height_{};
};

class MacosInputBackend final : public desktop::InputBackend {
public:
    void raw_key(std::uint32_t hid_usage, bool pressed) override;
    void text_commit(std::string_view utf8) override;
    void pointer_move(std::uint16_t normalized_x, std::uint16_t normalized_y) override;
    void pointer_button(std::uint8_t button, bool pressed) override;
    void pointer_wheel(std::int32_t delta, bool horizontal) override;

private:
    std::uint8_t pressed_pointer_buttons_{};
    desktop::PointerClickTracker click_tracker_;
};

class MacosClipboardBackend final : public desktop::ClipboardBackend {
public:
    [[nodiscard]] std::string read_utf8_text() override;
    void write_utf8_text(std::string_view text) override;
};

class MacosDesktopPermissionBackend final : public desktop::DesktopPermissionBackend {
public:
    [[nodiscard]] desktop::DesktopPermissionStatus status() const override;
    void request_capture() override;
    void request_input() override;
};

}  // namespace rwn::platform::macos
