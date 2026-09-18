#pragma once

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace rwn::desktop {

inline constexpr std::size_t maximum_visual_trace_line_bytes = 4096;
inline constexpr std::uint64_t maximum_visual_trace_file_bytes =
    64ULL * 1024ULL * 1024ULL;
inline constexpr std::size_t default_visual_trace_queue_capacity = 4096;
inline constexpr std::uint32_t visual_trace_schema_version = 6;
inline constexpr std::uint32_t minimum_supported_visual_trace_schema_version =
    4;

enum class VisualTraceHost { mac, windows };

enum class VisualLifecycleStage {
    none,
    sck_callback,
    latest_publish,
    superseded,
    metal_analysis,
    metal_rect_decision,
    rect_readback,
    nonvisual_pipeline_advance,
    vt_submit,
    vt_output,
    wire_write_complete,
    wire_receive,
    raw_rect_write_complete,
    snapshot_write_complete,
    raw_rect_receive,
    mf_output,
    framebuffer_commit,
    gpu_patch,
    present_submitted,
    frame_commit_write_complete,
    ack_created,
    ack_enqueued,
    ack_write_complete,
    ack_bytes_received,
    ack_parsed,
    ack_accepted,
    representation_state,
    h264_quality_compare,
    gpu_exact_verify,
    input_captured,
    input_enqueued,
    input_superseded,
    input_write_complete,
    input_bytes_received,
    input_injected,
    input_rejected,
    input_release_all,
    visual_stall,
    visual_recovered,
    trace_dropped,
};

enum class VisualSckStatus {
    unknown,
    complete,
    idle,
    blank,
    suspended,
    started,
    stopped,
};

enum class VisualRepresentationMode {
    unknown,
    video_lossy,
    snapshot,
    rect_exact,
};

enum class VisualFallbackReason {
    none,
    dirty_ratio,
    rectangle_count,
    packed_bytes,
    ack_timeout,
    base_mismatch,
    recovery_request,
    newer_incompatible_source,
    feature_disabled,
};

enum class VisualLifecycleDomain { mac, windows };

// Input trace intentionally records only scheduling class and opaque sequence
// identifiers. It never contains key values, pointer coordinates or text.
enum class VisualInputTraceClass {
    none,
    pointer_latest,
    reliable,
    release_all,
};

struct VisualLifecycleSnapshot {
    std::uint64_t source_generation{};
    std::uint64_t published_generation{};
    std::uint64_t submitted_generation{};
    std::uint64_t encoded_generation{};
    std::uint64_t written_generation{};
    std::uint64_t received_generation{};
    std::uint64_t decoded_generation{};
    std::uint64_t committed_generation{};
    std::uint64_t present_submitted_generation{};

    [[nodiscard]] bool operator==(
        const VisualLifecycleSnapshot&) const = default;
};

struct VisualTraceEvent {
    std::uint32_t schema_version{visual_trace_schema_version};
    VisualTraceHost host{VisualTraceHost::mac};
    std::uint64_t session_generation{};
    std::uint64_t representation_epoch{};
    std::uint64_t event_sequence{};
    std::uint64_t callback_sequence{};
    std::uint64_t frame_id{};
    VisualLifecycleStage stage{VisualLifecycleStage::none};
    VisualLifecycleStage related_stage{VisualLifecycleStage::none};
    std::uint64_t local_monotonic_us{};
    VisualSckStatus sck_status{VisualSckStatus::unknown};
    bool valid_image{};
    std::uint32_t content_x{};
    std::uint32_t content_y{};
    std::uint32_t content_width{};
    std::uint32_t content_height{};
    std::uint32_t sck_dirty_rect_count{};
    std::uint64_t sck_dirty_union_area{};
    std::uint32_t sck_dirty_ratio_ppm{};
    std::uint32_t metal_dirty_tiles{};
    std::uint32_t metal_dirty_ratio_ppm{};
    std::uint32_t queue_depth{};
    std::uint64_t stage_duration_us{};
    std::uint64_t payload_bytes{};
    std::uint32_t rectangle_count{};
    VisualRepresentationMode representation_mode{
        VisualRepresentationMode::unknown};
    VisualFallbackReason fallback_reason{VisualFallbackReason::none};
    std::uint32_t exact_residency_ratio_ppm{};
    std::uint64_t representation_switches{};
    std::uint64_t rect_superseded_sources{};
    std::uint64_t verification_mismatches{};
    std::uint64_t absolute_error_sum{};
    std::uint64_t squared_error_sum{};
    std::uint64_t superseded_by{};
    std::uint64_t stalled_us{};
    std::uint64_t trace_dropped{};
    std::uint64_t input_correlation_id{};
    std::uint64_t input_epoch{};
    std::uint64_t input_sequence{};
    VisualInputTraceClass input_trace_class{
        VisualInputTraceClass::none};
    // Observer identities, not synthetic Present receipts or pixel-equality proof.
    // Zero means unavailable; content IDs advance only on analyzer pixel changes.
    std::uint64_t latest_source_frame_id{};
    std::uint64_t latest_content_frame_id{};
    std::uint64_t exact_base_frame_id{};
    std::uint64_t exact_base_content_frame_id{};

    [[nodiscard]] bool operator==(const VisualTraceEvent&) const = default;
};

[[nodiscard]] std::string_view to_string(VisualTraceHost host) noexcept;
[[nodiscard]] std::string_view to_string(
    VisualLifecycleStage stage) noexcept;
[[nodiscard]] std::string_view to_string(VisualSckStatus status) noexcept;
[[nodiscard]] std::string_view to_string(
    VisualRepresentationMode mode) noexcept;
[[nodiscard]] std::string_view to_string(
    VisualFallbackReason reason) noexcept;
[[nodiscard]] std::string_view to_string(
    VisualInputTraceClass value) noexcept;
[[nodiscard]] std::string render_visual_trace_json(
    const VisualTraceEvent& event);
[[nodiscard]] VisualTraceEvent decode_visual_trace_json(
    std::string_view json);
void validate_visual_trace_destination(const std::filesystem::path& path);

class VisualTraceQueue final {
public:
    explicit VisualTraceQueue(
        std::size_t capacity = default_visual_trace_queue_capacity);

    [[nodiscard]] bool try_push(VisualTraceEvent event);
    [[nodiscard]] std::optional<VisualTraceEvent> wait_pop(
        std::chrono::milliseconds timeout);
    void close();
    [[nodiscard]] std::uint64_t dropped_events() const;
    [[nodiscard]] std::size_t size() const;

private:
    const std::size_t capacity_;
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::deque<VisualTraceEvent> events_;
    std::uint64_t dropped_events_{};
    bool closed_{};
};

class VisualLifecycleTracker final {
public:
    VisualLifecycleTracker(
        VisualTraceHost host,
        std::uint64_t session_generation,
        VisualTraceQueue* trace_queue);

    void record(
        VisualLifecycleStage stage,
        std::uint64_t frame_id,
        std::uint64_t local_monotonic_us,
        const VisualTraceEvent& metadata = {});
    [[nodiscard]] VisualLifecycleSnapshot snapshot() const;
    [[nodiscard]] std::uint64_t trace_dropped() const;

private:
    VisualTraceHost host_;
    std::uint64_t session_generation_{};
    VisualTraceQueue* trace_queue_{};
    mutable std::mutex mutex_;
    VisualLifecycleSnapshot snapshot_;
    std::uint64_t event_sequence_{};
};

struct VisualWatchdogEvent {
    bool stalled{};
    bool recovered{};
    bool hard_timeout{};
    VisualLifecycleStage related_stage{VisualLifecycleStage::none};
    std::uint64_t frame_id{};
    std::uint64_t stalled_us{};
};

class VisualLivenessWatchdog final {
public:
    explicit VisualLivenessWatchdog(VisualLifecycleDomain domain);
    [[nodiscard]] std::optional<VisualWatchdogEvent> poll(
        const VisualLifecycleSnapshot& snapshot,
        std::uint64_t now_us,
        std::uint64_t stall_threshold_us = 50'000,
        std::uint64_t hard_timeout_us = 100'000);
    [[nodiscard]] bool hard_timeout_active() const noexcept;

private:
    [[nodiscard]] std::pair<VisualLifecycleStage, std::uint64_t> gap(
        const VisualLifecycleSnapshot& snapshot) const noexcept;

    VisualLifecycleDomain domain_;
    VisualLifecycleStage observed_stage_{VisualLifecycleStage::none};
    std::uint64_t observed_frame_id_{};
    std::uint64_t observed_since_us_{};
    bool stall_reported_{};
    bool hard_timeout_reported_{};
};

class VisualTailRefreshBudget final {
public:
    VisualTailRefreshBudget(
        std::uint32_t refresh_count = 5,
        std::uint64_t quiet_delay_us = 20'000);
    void publish_visual(
        std::uint64_t frame_id,
        std::uint64_t published_at_us);
    [[nodiscard]] bool repeat_due(std::uint64_t now_us) const noexcept;
    void repeat_completed(std::uint64_t frame_id);
    [[nodiscard]] std::uint32_t remaining() const noexcept;

private:
    std::uint32_t refresh_count_{};
    std::uint64_t quiet_delay_us_{};
    std::uint64_t frame_id_{};
    std::uint64_t repeat_after_us_{};
    std::uint32_t remaining_{};
};

}  // namespace rwn::desktop
