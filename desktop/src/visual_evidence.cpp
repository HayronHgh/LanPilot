#include "rwn/desktop/visual_evidence.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <map>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <utility>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace rwn::desktop {
namespace {

using FrameKey =
    std::tuple<VisualTraceHost, std::uint64_t, std::uint64_t>;

struct FrameStages {
    std::uint64_t source{};
    std::uint64_t h264_wire{};
    std::uint64_t raw_wire{};
    std::uint64_t receive{};
    std::uint64_t raw_receive{};
    std::uint64_t present{};
};

struct AckPathStages {
    VisualRepresentationMode representation_mode{
        VisualRepresentationMode::unknown};
    std::uint64_t framebuffer_commit{};
    std::uint64_t created{};
    std::uint64_t enqueued{};
    std::uint64_t write_complete{};
    std::uint64_t bytes_received{};
    std::uint64_t parsed{};
    std::uint64_t accepted{};
};

struct InputPathStages {
    VisualInputTraceClass input_class{VisualInputTraceClass::none};
    std::uint64_t captured{};
    std::uint64_t enqueued{};
    std::uint64_t write_complete{};
    std::uint64_t bytes_received{};
    std::uint64_t injected{};
};

struct FallbackSamples {
    std::vector<std::uint64_t> dirty_ratios;
    std::vector<std::uint64_t> rectangle_counts;
    std::vector<std::uint64_t> packed_bytes;
};

VisualEvidenceDistribution distribution(std::vector<std::uint64_t> values) {
    VisualEvidenceDistribution result;
    if (values.empty()) {
        return result;
    }
    std::sort(values.begin(), values.end());
    const auto percentile = [&values](std::size_t numerator) {
        const auto index = ((values.size() - 1U) * numerator + 99U) / 100U;
        return values[index];
    };
    result.count = values.size();
    result.p50_us = percentile(50);
    result.p95_us = percentile(95);
    result.maximum_us = values.back();
    return result;
}

void keep_first(std::uint64_t& destination, std::uint64_t value) {
    if (destination == 0U || value < destination) {
        destination = value;
    }
}

void keep_last(std::uint64_t& destination, std::uint64_t value) {
    destination = std::max(destination, value);
}

void checked_add(
    std::uint64_t& destination,
    const std::uint64_t value,
    const char* field) {
    if (value > std::numeric_limits<std::uint64_t>::max() - destination) {
        throw std::invalid_argument(std::string(field) + " overflow");
    }
    destination += value;
}

void require_host(
    const VisualTraceEvent& event,
    const VisualTraceHost expected) {
    if (event.host != expected) {
        throw std::invalid_argument(
            "visual evidence stage is attributed to the wrong host");
    }
}

void append_duration(
    std::vector<std::uint64_t>& output,
    std::uint64_t begin,
    std::uint64_t end) {
    if (begin != 0U && end >= begin) {
        output.push_back(end - begin);
    }
}

std::string render_distribution(const VisualEvidenceDistribution& value) {
    std::ostringstream output;
    output << "{\"count\":" << value.count << ",\"p50_us\":"
           << value.p50_us << ",\"p95_us\":" << value.p95_us
           << ",\"max_us\":" << value.maximum_us << '}';
    return output.str();
}

void validate_workload(std::string_view workload) {
    if (workload.empty() || workload.size() > 64U) {
        throw std::invalid_argument("workload must contain 1-64 characters");
    }
    for (const char character : workload) {
        const bool allowed =
            (character >= 'a' && character <= 'z') ||
            (character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9') || character == '-' ||
            character == '_' || character == '.';
        if (!allowed) {
            throw std::invalid_argument("workload contains unsafe characters");
        }
    }
}

}  // namespace

VisualEvidenceSummary analyze_visual_evidence(
    std::span<const VisualTraceEvent> events) {
    VisualEvidenceSummary result;
    std::map<FrameKey, FrameStages> frames;
    std::map<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>,
             AckPathStages>
        ack_paths;
    std::map<std::tuple<std::uint64_t, std::uint64_t>, InputPathStages>
        input_paths;
    std::map<VisualFallbackReason, std::uint64_t> fallback_counts;
    std::map<VisualFallbackReason, FallbackSamples> fallback_samples;
    std::map<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>,
             std::uint64_t>
        raw_wire_times;
    std::vector<std::uint64_t> h264_mac;
    std::vector<std::uint64_t> h264_windows;
    std::vector<std::uint64_t> raw_mac;
    std::vector<std::uint64_t> raw_windows;
    std::vector<std::uint64_t> raw_ack;
    std::vector<std::uint64_t> snapshot_commit_to_created;
    std::vector<std::uint64_t> snapshot_created_to_enqueued;
    std::vector<std::uint64_t> snapshot_enqueued_to_write;
    std::vector<std::uint64_t> snapshot_received_to_parsed;
    std::vector<std::uint64_t> snapshot_parsed_to_accepted;
    std::vector<std::uint64_t> input_capture_to_enqueue;
    std::vector<std::uint64_t> input_enqueue_to_write;
    std::vector<std::uint64_t> input_receive_to_injected;
    std::vector<std::uint64_t> compare_times;
    std::vector<std::uint64_t> readback_times;
    std::vector<std::uint64_t> patch_times;
    std::vector<std::uint64_t> verify_times;
    std::map<std::pair<VisualTraceHost, std::uint64_t>, bool> active_stalls;
    std::uint64_t first_mac_time{};
    std::uint64_t last_mac_time{};

    for (const auto& event : events) {
        if (event.host == VisualTraceHost::mac) {
            keep_first(first_mac_time, event.local_monotonic_us);
            keep_last(last_mac_time, event.local_monotonic_us);
        }
        const FrameKey key{
            event.host, event.session_generation, event.frame_id};
        auto& frame = frames[key];
        const auto ack_key = std::tuple{
            event.session_generation, event.representation_epoch,
            event.frame_id};
        const auto input_key = std::tuple{
            event.session_generation, event.input_correlation_id};
        switch (event.stage) {
            case VisualLifecycleStage::sck_callback:
                require_host(event, VisualTraceHost::mac);
                if (event.valid_image &&
                    (event.sck_status == VisualSckStatus::complete ||
                     event.sck_status == VisualSckStatus::started)) {
                    keep_first(frame.source, event.local_monotonic_us);
                }
                break;
            case VisualLifecycleStage::wire_write_complete:
                require_host(event, VisualTraceHost::mac);
                keep_first(frame.h264_wire, event.local_monotonic_us);
                checked_add(
                    result.h264_wire_bytes, event.payload_bytes,
                    "H.264 evidence bytes");
                break;
            case VisualLifecycleStage::raw_rect_write_complete:
                require_host(event, VisualTraceHost::mac);
                keep_first(frame.raw_wire, event.local_monotonic_us);
                checked_add(
                    result.raw_wire_bytes, event.payload_bytes,
                    "RAW_RECT evidence bytes");
                raw_wire_times[{event.session_generation,
                                event.representation_epoch, event.frame_id}] =
                    event.local_monotonic_us;
                break;
            case VisualLifecycleStage::snapshot_write_complete:
                require_host(event, VisualTraceHost::mac);
                checked_add(
                    result.snapshot_wire_bytes, event.payload_bytes,
                    "snapshot evidence bytes");
                break;
            case VisualLifecycleStage::wire_receive:
                require_host(event, VisualTraceHost::windows);
                keep_first(frame.receive, event.local_monotonic_us);
                break;
            case VisualLifecycleStage::raw_rect_receive:
                require_host(event, VisualTraceHost::windows);
                keep_first(frame.raw_receive, event.local_monotonic_us);
                break;
            case VisualLifecycleStage::present_submitted:
                require_host(event, VisualTraceHost::windows);
                keep_first(frame.present, event.local_monotonic_us);
                break;
            case VisualLifecycleStage::framebuffer_commit: {
                require_host(event, VisualTraceHost::windows);
                auto& path = ack_paths[ack_key];
                keep_first(path.framebuffer_commit, event.local_monotonic_us);
                path.representation_mode = event.representation_mode;
                break;
            }
            case VisualLifecycleStage::ack_created:
                require_host(event, VisualTraceHost::windows);
                keep_first(ack_paths[ack_key].created,
                           event.local_monotonic_us);
                break;
            case VisualLifecycleStage::ack_enqueued:
                require_host(event, VisualTraceHost::windows);
                keep_first(ack_paths[ack_key].enqueued,
                           event.local_monotonic_us);
                break;
            case VisualLifecycleStage::ack_write_complete:
                require_host(event, VisualTraceHost::windows);
                keep_first(ack_paths[ack_key].write_complete,
                           event.local_monotonic_us);
                break;
            case VisualLifecycleStage::ack_bytes_received:
                require_host(event, VisualTraceHost::mac);
                keep_first(ack_paths[ack_key].bytes_received,
                           event.local_monotonic_us);
                break;
            case VisualLifecycleStage::ack_parsed:
                require_host(event, VisualTraceHost::mac);
                keep_first(ack_paths[ack_key].parsed,
                           event.local_monotonic_us);
                break;
            case VisualLifecycleStage::input_captured: {
                require_host(event, VisualTraceHost::windows);
                if (event.input_correlation_id == 0U) {
                    throw std::invalid_argument(
                        "input trace correlation is missing");
                }
                auto& path = input_paths[input_key];
                path.input_class = event.input_trace_class;
                keep_first(path.captured, event.local_monotonic_us);
                break;
            }
            case VisualLifecycleStage::input_enqueued: {
                require_host(event, VisualTraceHost::windows);
                if (event.input_correlation_id == 0U) {
                    throw std::invalid_argument(
                        "input trace correlation is missing");
                }
                auto& path = input_paths[input_key];
                path.input_class = event.input_trace_class;
                keep_first(path.enqueued, event.local_monotonic_us);
                break;
            }
            case VisualLifecycleStage::input_write_complete:
                require_host(event, VisualTraceHost::windows);
                keep_first(input_paths[input_key].write_complete,
                           event.local_monotonic_us);
                break;
            case VisualLifecycleStage::input_bytes_received:
                require_host(event, VisualTraceHost::mac);
                keep_first(input_paths[input_key].bytes_received,
                           event.local_monotonic_us);
                break;
            case VisualLifecycleStage::input_injected:
                require_host(event, VisualTraceHost::mac);
                keep_first(input_paths[input_key].injected,
                           event.local_monotonic_us);
                break;
            case VisualLifecycleStage::input_superseded:
                require_host(event, VisualTraceHost::windows);
                ++result.input_pointer_superseded;
                break;
            case VisualLifecycleStage::input_rejected:
                require_host(event, VisualTraceHost::mac);
                ++result.input_rejected;
                break;
            case VisualLifecycleStage::input_release_all:
                ++result.input_release_all;
                break;
            case VisualLifecycleStage::metal_rect_decision:
                require_host(event, VisualTraceHost::mac);
                compare_times.push_back(event.stage_duration_us);
                if (event.fallback_reason != VisualFallbackReason::none) {
                    auto& samples = fallback_samples[event.fallback_reason];
                    samples.dirty_ratios.push_back(
                        event.metal_dirty_ratio_ppm);
                    samples.rectangle_counts.push_back(event.rectangle_count);
                    samples.packed_bytes.push_back(event.payload_bytes);
                }
                break;
            case VisualLifecycleStage::rect_readback:
                require_host(event, VisualTraceHost::mac);
                readback_times.push_back(event.stage_duration_us);
                break;
            case VisualLifecycleStage::gpu_patch:
                require_host(event, VisualTraceHost::windows);
                patch_times.push_back(event.stage_duration_us);
                break;
            case VisualLifecycleStage::gpu_exact_verify:
                require_host(event, VisualTraceHost::windows);
                verify_times.push_back(event.stage_duration_us);
                checked_add(
                    result.exact_verified_bytes, event.payload_bytes,
                    "exact verified bytes");
                checked_add(
                    result.exact_mismatched_bytes,
                    event.verification_mismatches,
                    "exact mismatch bytes");
                break;
            case VisualLifecycleStage::h264_quality_compare:
                require_host(event, VisualTraceHost::windows);
                checked_add(
                    result.quality_compared_bytes, event.payload_bytes,
                    "quality compared bytes");
                checked_add(
                    result.quality_mismatched_bytes,
                    event.verification_mismatches,
                    "quality mismatch bytes");
                checked_add(
                    result.quality_absolute_error_sum,
                    event.absolute_error_sum,
                    "quality absolute error");
                checked_add(
                    result.quality_squared_error_sum,
                    event.squared_error_sum,
                    "quality squared error");
                break;
            case VisualLifecycleStage::ack_accepted: {
                require_host(event, VisualTraceHost::mac);
                keep_first(ack_paths[ack_key].accepted,
                           event.local_monotonic_us);
                const auto iterator = raw_wire_times.find(
                    {event.session_generation, event.representation_epoch,
                     event.frame_id});
                if (iterator != raw_wire_times.end() &&
                    event.local_monotonic_us >= iterator->second) {
                    raw_ack.push_back(event.local_monotonic_us -
                                      iterator->second);
                }
                break;
            }
            case VisualLifecycleStage::representation_state:
                require_host(event, VisualTraceHost::mac);
                result.exact_residency_ratio_ppm =
                    event.exact_residency_ratio_ppm;
                result.representation_switches =
                    std::max(result.representation_switches,
                             event.representation_switches);
                result.rect_superseded_sources =
                    std::max(result.rect_superseded_sources,
                             event.rect_superseded_sources);
                if (event.fallback_reason != VisualFallbackReason::none) {
                    ++fallback_counts[event.fallback_reason];
                }
                break;
            case VisualLifecycleStage::trace_dropped:
                checked_add(
                    result.trace_dropped,
                    std::max<std::uint64_t>(1U, event.trace_dropped),
                    "trace dropped count");
                break;
            case VisualLifecycleStage::visual_stall:
                active_stalls[{event.host, event.frame_id}] = true;
                break;
            case VisualLifecycleStage::visual_recovered:
                active_stalls.erase({event.host, event.frame_id});
                break;
            default:
                break;
        }
    }

    for (const auto& [unused, path] : ack_paths) {
        static_cast<void>(unused);
        if (path.representation_mode != VisualRepresentationMode::snapshot) {
            continue;
        }
        append_duration(snapshot_commit_to_created, path.framebuffer_commit,
                        path.created);
        append_duration(snapshot_created_to_enqueued, path.created,
                        path.enqueued);
        append_duration(snapshot_enqueued_to_write, path.enqueued,
                        path.write_complete);
        append_duration(snapshot_received_to_parsed, path.bytes_received,
                        path.parsed);
        append_duration(snapshot_parsed_to_accepted, path.parsed,
                        path.accepted);
        if (path.framebuffer_commit != 0U && path.created != 0U &&
            path.enqueued != 0U && path.write_complete != 0U &&
            path.bytes_received != 0U && path.parsed != 0U &&
            path.accepted != 0U) {
            ++result.snapshot_ack_complete_paths;
        } else {
            ++result.snapshot_ack_incomplete_paths;
        }
    }

    for (const auto& [unused, path] : input_paths) {
        static_cast<void>(unused);
        append_duration(input_capture_to_enqueue, path.captured,
                        path.enqueued);
        append_duration(input_enqueue_to_write, path.enqueued,
                        path.write_complete);
        append_duration(input_receive_to_injected, path.bytes_received,
                        path.injected);
        if (path.input_class == VisualInputTraceClass::release_all) {
            continue;
        }
        if (path.captured != 0U && path.enqueued != 0U &&
            path.write_complete != 0U && path.bytes_received != 0U &&
            path.injected != 0U) {
            ++result.input_complete_paths;
        } else {
            ++result.input_incomplete_paths;
        }
    }

    for (const auto& [key, frame] : frames) {
        const auto host = std::get<0>(key);
        if (host == VisualTraceHost::mac) {
            append_duration(h264_mac, frame.source, frame.h264_wire);
            append_duration(raw_mac, frame.source, frame.raw_wire);
        } else {
            append_duration(h264_windows, frame.receive, frame.present);
            append_duration(raw_windows, frame.raw_receive, frame.present);
        }
    }
    std::vector<std::uint64_t> paired_h264, paired_raw;
    for (const auto& [key, mac] : frames) {
        if (std::get<0>(key) != VisualTraceHost::mac) continue;
        const auto peer = frames.find(FrameKey{
            VisualTraceHost::windows, std::get<1>(key), std::get<2>(key)});
        if (peer == frames.end()) continue;
        const auto& windows = peer->second;
        const auto append_pair = [&](auto& values, std::uint64_t wire,
                                     std::uint64_t receive) {
            if (mac.source == 0 || wire < mac.source || receive == 0 ||
                windows.present < receive) return;
            auto duration = wire - mac.source;
            checked_add(duration, windows.present - receive, "paired duration");
            values.push_back(duration);
        };
        append_pair(paired_h264, mac.h264_wire, windows.receive);
        append_pair(paired_raw, mac.raw_wire, windows.raw_receive);
    }
    result.h264_mac_source_to_wire = distribution(std::move(h264_mac));
    result.h264_windows_receive_to_present =
        distribution(std::move(h264_windows));
    result.raw_mac_source_to_wire = distribution(std::move(raw_mac));
    result.raw_windows_receive_to_present =
        distribution(std::move(raw_windows));
    result.h264_local_pipeline = distribution(std::move(paired_h264));
    result.raw_local_pipeline = distribution(std::move(paired_raw));
    result.raw_ack_round_trip = distribution(std::move(raw_ack));
    result.snapshot_commit_to_ack_created =
        distribution(std::move(snapshot_commit_to_created));
    result.snapshot_ack_created_to_enqueued =
        distribution(std::move(snapshot_created_to_enqueued));
    result.snapshot_ack_enqueued_to_write_complete =
        distribution(std::move(snapshot_enqueued_to_write));
    result.snapshot_ack_bytes_received_to_parsed =
        distribution(std::move(snapshot_received_to_parsed));
    result.snapshot_ack_parsed_to_accepted =
        distribution(std::move(snapshot_parsed_to_accepted));
    result.input_capture_to_enqueue =
        distribution(std::move(input_capture_to_enqueue));
    result.input_enqueue_to_write_complete =
        distribution(std::move(input_enqueue_to_write));
    result.input_bytes_received_to_injected =
        distribution(std::move(input_receive_to_injected));
    result.rect_compare = distribution(std::move(compare_times));
    result.rect_readback = distribution(std::move(readback_times));
    result.gpu_patch = distribution(std::move(patch_times));
    result.gpu_exact_verify = distribution(std::move(verify_times));
    result.unrecovered_stalls = active_stalls.size();
    if (first_mac_time != 0U && last_mac_time >= first_mac_time) {
        result.observed_mac_duration_us = last_mac_time - first_mac_time;
        if (result.observed_mac_duration_us != 0U) {
            std::uint64_t visual_bytes = result.h264_wire_bytes;
            checked_add(
                visual_bytes, result.raw_wire_bytes,
                "visual evidence bytes");
            checked_add(
                visual_bytes, result.snapshot_wire_bytes,
                "visual evidence bytes");
            const auto bytes_per_second =
                static_cast<long double>(visual_bytes) * 1'000'000.0L /
                static_cast<long double>(result.observed_mac_duration_us);
            result.observed_visual_bytes_per_second =
                static_cast<std::uint64_t>(std::min<long double>(
                    bytes_per_second,
                    static_cast<long double>(
                        std::numeric_limits<std::uint64_t>::max())));
        }
    }
    if (result.quality_compared_bytes != 0U) {
        result.quality_mismatch_ratio_ppm = static_cast<std::uint32_t>(
            std::min<long double>(
                1'000'000.0L,
                static_cast<long double>(result.quality_mismatched_bytes) *
                    1'000'000.0L /
                    static_cast<long double>(result.quality_compared_bytes)));
        const auto mean_absolute_error =
            static_cast<long double>(result.quality_absolute_error_sum) *
            1'000.0L /
            static_cast<long double>(result.quality_compared_bytes);
        result.quality_mean_absolute_error_milli =
            static_cast<std::uint64_t>(std::min<long double>(
                mean_absolute_error,
                static_cast<long double>(
                    std::numeric_limits<std::uint64_t>::max())));
        if (result.quality_squared_error_sum == 0U) {
            result.quality_psnr_millidb = 99'000U;
        } else {
            const auto mean_squared_error =
                static_cast<long double>(result.quality_squared_error_sum) /
                static_cast<long double>(result.quality_compared_bytes);
            result.quality_psnr_millidb = static_cast<std::uint64_t>(
                std::max<long double>(
                    0.0L,
                    10'000.0L * std::log10(65'025.0L / mean_squared_error)));
        }
    }
    for (const auto& [reason, count] : fallback_counts) {
        VisualFallbackEvidence evidence{.reason = reason, .count = count};
        if (const auto iterator = fallback_samples.find(reason);
            iterator != fallback_samples.end()) {
            const auto dirty = distribution(iterator->second.dirty_ratios);
            const auto rectangles =
                distribution(iterator->second.rectangle_counts);
            const auto bytes = distribution(iterator->second.packed_bytes);
            evidence.dirty_ratio_p50_ppm =
                static_cast<std::uint32_t>(dirty.p50_us);
            evidence.dirty_ratio_p95_ppm =
                static_cast<std::uint32_t>(dirty.p95_us);
            evidence.dirty_ratio_max_ppm =
                static_cast<std::uint32_t>(dirty.maximum_us);
            evidence.rectangle_count_p95 =
                static_cast<std::uint32_t>(rectangles.p95_us);
            evidence.packed_bytes_p95 = bytes.p95_us;
        }
        result.fallbacks.push_back(evidence);
    }
    return result;
}

VisualEvidenceComparison compare_visual_evidence(
    std::span<const VisualTraceEvent> baseline,
    std::span<const VisualTraceEvent> hybrid,
    std::string workload,
    std::size_t minimum_latency_samples,
    std::uint32_t required_improvement_ppm) {
    validate_workload(workload);
    if (required_improvement_ppm > 1'000'000U) {
        throw std::invalid_argument("improvement ratio is outside canonical range");
    }
    VisualEvidenceComparison comparison{
        .baseline = analyze_visual_evidence(baseline),
        .hybrid = analyze_visual_evidence(hybrid),
        .workload = std::move(workload),
    };
    comparison.baseline_control_valid =
        comparison.baseline.trace_dropped == 0U &&
        comparison.baseline.unrecovered_stalls == 0U &&
        comparison.baseline.raw_local_pipeline.count == 0U &&
        comparison.baseline.raw_wire_bytes == 0U;
    comparison.latency_gate_has_enough_samples =
        comparison.baseline.h264_local_pipeline.count >=
            minimum_latency_samples &&
        comparison.hybrid.raw_local_pipeline.count >= minimum_latency_samples;
    comparison.hybrid_measurement_valid =
        comparison.hybrid.trace_dropped == 0U &&
        comparison.hybrid.unrecovered_stalls == 0U &&
        comparison.hybrid.raw_local_pipeline.count >= minimum_latency_samples &&
        comparison.hybrid.exact_verified_bytes != 0U &&
        comparison.hybrid.exact_mismatched_bytes == 0U;
    if (comparison.hybrid.raw_local_pipeline.count != 0U &&
        comparison.baseline.h264_local_pipeline.p95_us != 0U &&
        comparison.hybrid.raw_local_pipeline.p95_us <=
            comparison.baseline.h264_local_pipeline.p95_us) {
        const auto difference =
            comparison.baseline.h264_local_pipeline.p95_us -
            comparison.hybrid.raw_local_pipeline.p95_us;
        comparison.raw_p95_improvement_ppm = static_cast<std::int64_t>(
            static_cast<long double>(difference) * 1'000'000.0L /
            static_cast<long double>(
                comparison.baseline.h264_local_pipeline.p95_us));
    } else if (comparison.hybrid.raw_local_pipeline.count != 0U &&
               comparison.baseline.h264_local_pipeline.p95_us != 0U) {
        const auto regression = comparison.hybrid.raw_local_pipeline.p95_us -
                                comparison.baseline.h264_local_pipeline.p95_us;
        const auto regression_ppm =
            static_cast<long double>(regression) * 1'000'000.0L /
            static_cast<long double>(
                comparison.baseline.h264_local_pipeline.p95_us);
        comparison.raw_p95_improvement_ppm = -static_cast<std::int64_t>(
            std::min<long double>(
                regression_ppm,
                static_cast<long double>(
                    std::numeric_limits<std::int64_t>::max())));
    }
    comparison.latency_gate_passed =
        comparison.baseline_control_valid &&
        comparison.hybrid_measurement_valid &&
        comparison.latency_gate_has_enough_samples &&
        comparison.raw_p95_improvement_ppm >=
            static_cast<std::int64_t>(required_improvement_ppm);
    comparison.correctness_gate_passed =
        comparison.baseline_control_valid &&
        comparison.hybrid.trace_dropped == 0U &&
        comparison.hybrid.unrecovered_stalls == 0U &&
        comparison.hybrid.exact_verified_bytes != 0U &&
        comparison.hybrid.exact_mismatched_bytes == 0U;
    comparison.quality_gate_has_evidence =
        comparison.hybrid.quality_compared_bytes != 0U &&
        comparison.hybrid.exact_verified_bytes != 0U;
    comparison.quality_gate_passed =
        comparison.quality_gate_has_evidence &&
        comparison.hybrid.exact_mismatched_bytes == 0U;
    comparison.promotion_gate_passed = comparison.latency_gate_passed &&
        comparison.correctness_gate_passed;
    return comparison;
}

std::string render_visual_evidence_json(
    const VisualEvidenceComparison& comparison) {
    std::ostringstream output;
    const auto render_summary = [&output](const VisualEvidenceSummary& value) {
        output << "{\"h264_local_pipeline\":"
               << render_distribution(value.h264_local_pipeline)
               << ",\"raw_local_pipeline\":"
               << render_distribution(value.raw_local_pipeline)
               << ",\"raw_ack_round_trip\":"
               << render_distribution(value.raw_ack_round_trip)
               << ",\"snapshot_ack_path\":{\"commit_to_created\":"
               << render_distribution(value.snapshot_commit_to_ack_created)
               << ",\"created_to_enqueued\":"
               << render_distribution(value.snapshot_ack_created_to_enqueued)
               << ",\"enqueued_to_write_complete\":"
               << render_distribution(
                      value.snapshot_ack_enqueued_to_write_complete)
               << ",\"bytes_received_to_parsed\":"
               << render_distribution(
                      value.snapshot_ack_bytes_received_to_parsed)
               << ",\"parsed_to_accepted\":"
               << render_distribution(
                      value.snapshot_ack_parsed_to_accepted)
               << ",\"complete_paths\":"
               << value.snapshot_ack_complete_paths
               << ",\"incomplete_paths\":"
               << value.snapshot_ack_incomplete_paths
               << ",\"cross_host_transport_clock_correlated\":false}"
               << ",\"input_path\":{\"capture_to_enqueued\":"
               << render_distribution(value.input_capture_to_enqueue)
               << ",\"enqueued_to_write_complete\":"
               << render_distribution(value.input_enqueue_to_write_complete)
               << ",\"bytes_received_to_injected\":"
               << render_distribution(value.input_bytes_received_to_injected)
               << ",\"complete_paths\":" << value.input_complete_paths
               << ",\"incomplete_paths\":" << value.input_incomplete_paths
               << ",\"pointer_superseded\":"
               << value.input_pointer_superseded
               << ",\"rejected\":" << value.input_rejected
               << ",\"release_all\":" << value.input_release_all
               << ",\"cross_host_transport_clock_correlated\":false}"
               << ",\"rect_compare\":"
               << render_distribution(value.rect_compare)
               << ",\"rect_readback\":"
               << render_distribution(value.rect_readback)
               << ",\"gpu_patch\":" << render_distribution(value.gpu_patch)
               << ",\"gpu_exact_verify\":"
               << render_distribution(value.gpu_exact_verify)
               << ",\"exact_residency_ratio_ppm\":"
               << value.exact_residency_ratio_ppm
               << ",\"representation_switches\":"
               << value.representation_switches
               << ",\"rect_superseded_sources\":"
               << value.rect_superseded_sources
               << ",\"observed_mac_duration_us\":"
               << value.observed_mac_duration_us
               << ",\"h264_wire_bytes\":" << value.h264_wire_bytes
               << ",\"raw_wire_bytes\":" << value.raw_wire_bytes
               << ",\"snapshot_wire_bytes\":"
               << value.snapshot_wire_bytes
               << ",\"observed_visual_bytes_per_second\":"
               << value.observed_visual_bytes_per_second
               << ",\"trace_dropped\":"
               << value.trace_dropped << ",\"unrecovered_stalls\":"
               << value.unrecovered_stalls
               << ",\"quality_compared_bytes\":"
               << value.quality_compared_bytes
               << ",\"quality_mismatched_bytes\":"
               << value.quality_mismatched_bytes
               << ",\"quality_absolute_error_sum\":"
               << value.quality_absolute_error_sum
               << ",\"quality_squared_error_sum\":"
               << value.quality_squared_error_sum
               << ",\"quality_mismatch_ratio_ppm\":"
               << value.quality_mismatch_ratio_ppm
               << ",\"quality_mean_absolute_error_milli\":"
               << value.quality_mean_absolute_error_milli
               << ",\"quality_psnr_millidb\":"
               << value.quality_psnr_millidb
               << ",\"exact_verified_bytes\":"
               << value.exact_verified_bytes
               << ",\"exact_mismatched_bytes\":"
               << value.exact_mismatched_bytes << ",\"fallbacks\":[";
        for (std::size_t index = 0; index < value.fallbacks.size(); ++index) {
            if (index != 0U) {
                output << ',';
            }
            output << "{\"reason\":\""
                   << to_string(value.fallbacks[index].reason)
                   << "\",\"count\":" << value.fallbacks[index].count
                   << ",\"dirty_ratio_p50_ppm\":"
                   << value.fallbacks[index].dirty_ratio_p50_ppm
                   << ",\"dirty_ratio_p95_ppm\":"
                   << value.fallbacks[index].dirty_ratio_p95_ppm
                   << ",\"dirty_ratio_max_ppm\":"
                   << value.fallbacks[index].dirty_ratio_max_ppm
                   << ",\"rectangle_count_p95\":"
                   << value.fallbacks[index].rectangle_count_p95
                   << ",\"packed_bytes_p95\":"
                   << value.fallbacks[index].packed_bytes_p95 << '}';
        }
        output << "]}";
    };
    output << "{\"schema_version\":3,\"timing_scope\":\"matched_session_frame_sum_of_host_local_spans_excludes_network_and_scanout\",\"workload\":\""
           << comparison.workload << "\",\"baseline\":";
    render_summary(comparison.baseline);
    output << ",\"hybrid\":";
    render_summary(comparison.hybrid);
    output << ",\"gates\":{\"baseline_control_valid\":"
           << (comparison.baseline_control_valid ? "true" : "false")
           << ",\"hybrid_measurement_valid\":"
           << (comparison.hybrid_measurement_valid ? "true" : "false")
           << ",\"latency_has_enough_samples\":"
           << (comparison.latency_gate_has_enough_samples ? "true" : "false")
           << ",\"latency_passed\":"
           << (comparison.latency_gate_passed ? "true" : "false")
           << ",\"correctness_passed\":"
           << (comparison.correctness_gate_passed ? "true" : "false")
           << ",\"quality_has_evidence\":"
           << (comparison.quality_gate_has_evidence ? "true" : "false")
           << ",\"quality_passed\":"
           << (comparison.quality_gate_passed ? "true" : "false")
           << ",\"promotion_passed\":"
           << (comparison.promotion_gate_passed ? "true" : "false")
           << ",\"raw_p95_improvement_ppm\":"
           << comparison.raw_p95_improvement_ppm << "}}\n";
    return output.str();
}

void validate_visual_evidence_input(const std::filesystem::path& path) {
    if (!path.is_absolute() || path.extension() != ".jsonl" ||
        path.filename().empty() || !std::filesystem::is_regular_file(path) ||
        std::filesystem::file_size(path) > maximum_visual_trace_file_bytes) {
        throw std::invalid_argument(
            "evidence input must be an existing absolute JSONL file no larger than 64 MiB");
    }
}

void validate_visual_evidence_output(const std::filesystem::path& path) {
    if (!path.is_absolute() || path.extension() != ".json" ||
        path.filename().empty() || std::filesystem::exists(path) ||
        !std::filesystem::is_directory(path.parent_path())) {
        throw std::invalid_argument(
            "evidence output must be a new absolute JSON file");
    }
}

void write_visual_evidence_report_new(
    const std::filesystem::path& path,
    const std::string_view report) {
    validate_visual_evidence_output(path);
    if (report.empty() || report.size() > maximum_visual_evidence_report_bytes) {
        throw std::length_error("visual evidence report size is invalid");
    }
#if defined(_WIN32)
    const HANDLE handle = CreateFileW(
        path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("failed to create visual evidence report");
    }
    bool success = true;
    std::size_t offset = 0;
    while (offset < report.size()) {
        const auto remaining = report.size() - offset;
        const auto requested = static_cast<DWORD>(std::min<std::size_t>(
            remaining, static_cast<std::size_t>(MAXDWORD)));
        DWORD written{};
        if (!WriteFile(handle, report.data() + offset, requested, &written,
                       nullptr) || written == 0U) {
            success = false;
            break;
        }
        offset += written;
    }
    success = success && FlushFileBuffers(handle) != FALSE;
    success = CloseHandle(handle) != FALSE && success;
    if (!success) {
        DeleteFileW(path.c_str());
        throw std::runtime_error("failed to write visual evidence report");
    }
#else
    const int descriptor =
        ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (descriptor < 0) {
        throw std::runtime_error("failed to create visual evidence report");
    }
    bool success = true;
    std::size_t offset = 0;
    while (offset < report.size()) {
        const auto written =
            ::write(descriptor, report.data() + offset, report.size() - offset);
        if (written <= 0) {
            if (written < 0 && errno == EINTR) {
                continue;
            }
            success = false;
            break;
        }
        offset += static_cast<std::size_t>(written);
    }
    success = success && ::fsync(descriptor) == 0;
    success = ::close(descriptor) == 0 && success;
    if (!success) {
        static_cast<void>(::unlink(path.c_str()));
        throw std::runtime_error("failed to write visual evidence report");
    }
#endif
}

}  // namespace rwn::desktop
