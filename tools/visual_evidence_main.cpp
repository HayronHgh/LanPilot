#include "rwn/desktop/visual_evidence.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct Options {
    std::filesystem::path baseline;
    std::filesystem::path hybrid;
    std::filesystem::path quality;
    std::filesystem::path output;
    std::string workload;
};

Options parse_options(int argc, char** argv) {
    Options options;
    for (int index = 1; index < argc; index += 2) {
        if (index + 1 >= argc) {
            throw std::invalid_argument("every option requires one value");
        }
        const std::string_view option{argv[index]};
        const std::string_view value{argv[index + 1]};
        if (option == "--baseline") {
            options.baseline = value;
        } else if (option == "--hybrid") {
            options.hybrid = value;
        } else if (option == "--output") {
            options.output = value;
        } else if (option == "--quality") {
            options.quality = value;
        } else if (option == "--workload") {
            options.workload = value;
        } else {
            throw std::invalid_argument("unknown visual evidence option");
        }
    }
    if (options.baseline.empty() || options.hybrid.empty() ||
        options.output.empty() || options.workload.empty()) {
        throw std::invalid_argument(
            "usage: rwn-visual-evidence --baseline <absolute.jsonl> "
            "--hybrid <absolute.jsonl> [--quality <absolute.jsonl>] "
            "--workload <name> "
            "--output <new-absolute.json>");
    }
    return options;
}

std::vector<rwn::desktop::VisualTraceEvent> read_trace(
    const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("failed to open evidence input");
    }
    std::vector<rwn::desktop::VisualTraceEvent> events;
    std::string line;
    while (std::getline(input, line)) {
        if (line.size() > rwn::desktop::maximum_visual_trace_line_bytes) {
            throw std::invalid_argument("evidence trace line exceeds 4 KiB");
        }
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) {
            continue;
        }
        events.push_back(rwn::desktop::decode_visual_trace_json(line));
    }
    return events;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const auto options = parse_options(argc, argv);
        rwn::desktop::validate_visual_evidence_input(options.baseline);
        rwn::desktop::validate_visual_evidence_input(options.hybrid);
        if (!options.quality.empty()) {
            rwn::desktop::validate_visual_evidence_input(options.quality);
        }
        rwn::desktop::validate_visual_evidence_output(options.output);
        const auto baseline = read_trace(options.baseline);
        const auto hybrid = read_trace(options.hybrid);
        auto comparison = rwn::desktop::compare_visual_evidence(
            baseline, hybrid, options.workload);
        if (!options.quality.empty()) {
            const auto quality = read_trace(options.quality);
            const auto quality_summary =
                rwn::desktop::analyze_visual_evidence(quality);
            comparison.hybrid.quality_compared_bytes =
                quality_summary.quality_compared_bytes;
            comparison.hybrid.quality_mismatched_bytes =
                quality_summary.quality_mismatched_bytes;
            comparison.hybrid.quality_absolute_error_sum =
                quality_summary.quality_absolute_error_sum;
            comparison.hybrid.quality_squared_error_sum =
                quality_summary.quality_squared_error_sum;
            comparison.hybrid.quality_mismatch_ratio_ppm =
                quality_summary.quality_mismatch_ratio_ppm;
            comparison.hybrid.quality_mean_absolute_error_milli =
                quality_summary.quality_mean_absolute_error_milli;
            comparison.hybrid.quality_psnr_millidb =
                quality_summary.quality_psnr_millidb;
            comparison.hybrid.exact_verified_bytes =
                quality_summary.exact_verified_bytes;
            comparison.hybrid.exact_mismatched_bytes =
                quality_summary.exact_mismatched_bytes;
            comparison.hybrid.gpu_exact_verify =
                quality_summary.gpu_exact_verify;
            comparison.hybrid.trace_dropped += quality_summary.trace_dropped;
            comparison.hybrid.unrecovered_stalls +=
                quality_summary.unrecovered_stalls;
            comparison.correctness_gate_passed =
                comparison.correctness_gate_passed &&
                quality_summary.trace_dropped == 0U &&
                quality_summary.unrecovered_stalls == 0U &&
                quality_summary.exact_mismatched_bytes == 0U;
            comparison.quality_gate_has_evidence =
                comparison.hybrid.quality_compared_bytes != 0U &&
                comparison.hybrid.exact_verified_bytes != 0U;
            comparison.quality_gate_passed =
                comparison.quality_gate_has_evidence &&
                comparison.hybrid.exact_mismatched_bytes == 0U;
            comparison.promotion_gate_passed =
                comparison.latency_gate_passed &&
                comparison.correctness_gate_passed;
        }
        const auto report =
            rwn::desktop::render_visual_evidence_json(comparison);
        rwn::desktop::write_visual_evidence_report_new(options.output, report);
        std::cout << "workload=" << comparison.workload
                  << " h264_p95_us="
                  << comparison.baseline.h264_local_pipeline.p95_us
                  << " raw_p95_us="
                  << comparison.hybrid.raw_local_pipeline.p95_us
                  << " improvement_ppm="
                  << comparison.raw_p95_improvement_ppm
                  << " latency_gate="
                  << (comparison.latency_gate_passed ? "passed" : "not-passed")
                  << " correctness_gate="
                  << (comparison.correctness_gate_passed ? "passed"
                                                         : "not-passed")
                  << " promotion_gate="
                  << (comparison.promotion_gate_passed ? "passed"
                                                       : "not-passed")
                  << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Visual evidence failed: " << error.what() << '\n';
        return 1;
    }
}
