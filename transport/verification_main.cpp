#include "rwn/transport/verification.hpp"

#include <charconv>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace {

template <typename Integer>
Integer integer(const std::string_view value) {
    Integer result{};
    const auto parsed = std::from_chars(
        value.data(), value.data() + value.size(), result);
    if (value.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != value.data() + value.size()) {
        throw std::invalid_argument("numeric argument is invalid");
    }
    return result;
}

}  // namespace

int main(const int argc, const char* const argv[]) {
    if (argc != 12) {
        std::cerr
            << "usage: rwn-transport-verification <absolute-output.json> "
               "<scenario> <expected-revision> <observed-revision> "
               "<source-manifest-sha256> <mirror-manifest-sha256> <build-id> "
               "<build-evidence-sha256> <build-exit-code> "
               "<expected-artifact-sha256> <observed-artifact-sha256>\n";
        return 2;
    }
    try {
        const auto scenario =
            rwn::transport::standard_impairment_scenario(argv[2]);
        const rwn::transport::CorrectnessEvidence evidence{
            .expected_sync_revision = integer<std::uint64_t>(argv[3]),
            .observed_sync_revision = integer<std::uint64_t>(argv[4]),
            .source_manifest_sha256 = argv[5],
            .mirror_manifest_sha256 = argv[6],
            .build_id = argv[7],
            .build_evidence_sha256 = argv[8],
            .build_exit_code = integer<std::int32_t>(argv[9]),
            .expected_artifact_sha256 = argv[10],
            .observed_artifact_sha256 = argv[11],
        };
        const auto report = rwn::transport::analyze_transport_verification(
            rwn::transport::VerificationMode::deterministic_model, scenario,
            evidence,
            rwn::transport::make_deterministic_observations(scenario));
        rwn::transport::write_transport_verification_report(argv[1], report);
        std::cout << "scenario=" << report.scenario.id
                  << " mode=deterministic_model"
                  << " loss_bp=" << report.loss_basis_points
                  << " p95_us=" << report.latency_p95_us
                  << " sync_correct=" << report.sync_correct
                  << " build_correct=" << report.build_correct
                  << " passed=" << report.passed << '\n';
        return report.passed ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "transport verification failed: " << error.what() << '\n';
        return 1;
    }
}
