#pragma once

#include "rwn/desktop/visual_trace.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace rwn::desktop {

inline constexpr std::size_t maximum_visual_evidence_report_bytes =
    1024U * 1024U;

struct VisualEvidenceDistribution {
    std::uint64_t count{};
    std::uint64_t p50_us{};
    std::uint64_t p95_us{};
    std::uint64_t maximum_us{};
};

struct VisualFallbackEvidence {
    VisualFallbackReason reason{VisualFallbackReason::none};
    std::uint64_t count{};
    std::uint32_t dirty_ratio_p50_ppm{};
    std::uint32_t dirty_ratio_p95_ppm{};
    std::uint32_t dirty_ratio_max_ppm{};
    std::uint32_t rectangle_count_p95{};
    std::uint64_t packed_bytes_p95{};
};

struct VisualEvidenceSummary {
    VisualEvidenceDistribution h264_mac_source_to_wire;
    VisualEvidenceDistribution h264_windows_receive_to_present;
    VisualEvidenceDistribution h264_local_pipeline;
    VisualEvidenceDistribution raw_mac_source_to_wire;
    VisualEvidenceDistribution raw_windows_receive_to_present;
    VisualEvidenceDistribution raw_local_pipeline;
    VisualEvidenceDistribution raw_ack_round_trip;
    // All values are same-host measurements. The reverse SSH transport span
    // is deliberately omitted because the Windows and macOS monotonic clocks
    // are not assumed to share an offset.
    VisualEvidenceDistribution snapshot_commit_to_ack_created;
    VisualEvidenceDistribution snapshot_ack_created_to_enqueued;
    VisualEvidenceDistribution snapshot_ack_enqueued_to_write_complete;
    VisualEvidenceDistribution snapshot_ack_bytes_received_to_parsed;
    VisualEvidenceDistribution snapshot_ack_parsed_to_accepted;
    std::uint64_t snapshot_ack_complete_paths{};
    std::uint64_t snapshot_ack_incomplete_paths{};
    VisualEvidenceDistribution input_capture_to_enqueue;
    VisualEvidenceDistribution input_enqueue_to_write_complete;
    VisualEvidenceDistribution input_bytes_received_to_injected;
    std::uint64_t input_complete_paths{};
    std::uint64_t input_incomplete_paths{};
    std::uint64_t input_pointer_superseded{};
    std::uint64_t input_rejected{};
    std::uint64_t input_release_all{};
    VisualEvidenceDistribution rect_compare;
    VisualEvidenceDistribution rect_readback;
    VisualEvidenceDistribution gpu_patch;
    VisualEvidenceDistribution gpu_exact_verify;
    std::uint32_t exact_residency_ratio_ppm{};
    std::uint64_t representation_switches{};
    std::uint64_t rect_superseded_sources{};
    std::uint64_t observed_mac_duration_us{};
    std::uint64_t h264_wire_bytes{};
    std::uint64_t raw_wire_bytes{};
    std::uint64_t snapshot_wire_bytes{};
    std::uint64_t observed_visual_bytes_per_second{};
    std::uint64_t trace_dropped{};
    std::uint64_t unrecovered_stalls{};
    std::uint64_t quality_compared_bytes{};
    std::uint64_t quality_mismatched_bytes{};
    std::uint64_t quality_absolute_error_sum{};
    std::uint64_t quality_squared_error_sum{};
    std::uint32_t quality_mismatch_ratio_ppm{};
    std::uint64_t quality_mean_absolute_error_milli{};
    std::uint64_t quality_psnr_millidb{};
    std::uint64_t exact_verified_bytes{};
    std::uint64_t exact_mismatched_bytes{};
    std::vector<VisualFallbackEvidence> fallbacks;
};

struct VisualEvidenceComparison {
    VisualEvidenceSummary baseline;
    VisualEvidenceSummary hybrid;
    std::string workload;
    bool baseline_control_valid{};
    bool hybrid_measurement_valid{};
    bool latency_gate_has_enough_samples{};
    bool latency_gate_passed{};
    bool correctness_gate_passed{};
    bool quality_gate_has_evidence{};
    bool quality_gate_passed{};
    bool promotion_gate_passed{};
    std::int64_t raw_p95_improvement_ppm{};
};

[[nodiscard]] VisualEvidenceSummary analyze_visual_evidence(
    std::span<const VisualTraceEvent> events);
[[nodiscard]] VisualEvidenceComparison compare_visual_evidence(
    std::span<const VisualTraceEvent> baseline,
    std::span<const VisualTraceEvent> hybrid,
    std::string workload,
    std::size_t minimum_latency_samples = 30,
    std::uint32_t required_improvement_ppm = 200'000);
[[nodiscard]] std::string render_visual_evidence_json(
    const VisualEvidenceComparison& comparison);
void validate_visual_evidence_input(const std::filesystem::path& path);
void validate_visual_evidence_output(const std::filesystem::path& path);
void write_visual_evidence_report_new(
    const std::filesystem::path& path,
    std::string_view report);

}  // namespace rwn::desktop
