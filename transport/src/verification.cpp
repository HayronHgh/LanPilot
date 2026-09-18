#include "rwn/transport/verification.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <limits>
#include <ranges>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace rwn::transport {
namespace {

[[nodiscard]] bool valid_id(const std::string_view value) {
    return !value.empty() && value.size() <= 64 &&
           std::ranges::all_of(value, [](const unsigned char character) {
               return std::isalnum(character) != 0 || character == '-' ||
                      character == '_' || character == '.';
           });
}

[[nodiscard]] bool sha256_hex(const std::string_view value) {
    return value.size() == 64 &&
           std::ranges::all_of(value, [](const unsigned char character) {
               return std::isdigit(character) != 0 ||
                      (character >= 'a' && character <= 'f');
           });
}

void validate_scenario(const ImpairmentScenario& scenario) {
    if (!valid_id(scenario.id) || scenario.packet_count == 0 ||
        scenario.packet_count > 1'000'000 || scenario.payload_bytes == 0 ||
        scenario.payload_bytes > 65'506 || scenario.packet_interval_us == 0 ||
        scenario.packet_interval_us > 10'000'000 ||
        scenario.base_latency_us > 10'000'000 ||
        scenario.jitter_us > 10'000'000 ||
        (scenario.loss_every_nth == 1) ||
        (scenario.duplicate_every_nth == 1) ||
        (scenario.reorder_window == 1) || scenario.reorder_window > 1024 ||
        (scenario.migration_sequence &&
         *scenario.migration_sequence >= scenario.packet_count) ||
        scenario.migration_outage_us > 60'000'000 ||
        scenario.loss_budget_basis_points > 10'000 ||
        scenario.p95_latency_budget_us == 0 ||
        scenario.p95_latency_budget_us > 60'000'000) {
        throw std::invalid_argument("transport impairment scenario is invalid");
    }
}

void validate_evidence(const CorrectnessEvidence& evidence) {
    if (evidence.expected_sync_revision == 0 ||
        evidence.observed_sync_revision == 0 ||
        !sha256_hex(evidence.source_manifest_sha256) ||
        !sha256_hex(evidence.mirror_manifest_sha256) ||
        !valid_id(evidence.build_id) ||
        !sha256_hex(evidence.build_evidence_sha256) ||
        !sha256_hex(evidence.expected_artifact_sha256) ||
        !sha256_hex(evidence.observed_artifact_sha256)) {
        throw std::invalid_argument("transport correctness evidence is invalid");
    }
}

[[nodiscard]] std::uint64_t percentile(
    const std::vector<std::uint64_t>& sorted, const std::size_t numerator,
    const std::size_t denominator) {
    if (sorted.empty()) return 0;
    const auto rank = (sorted.size() * numerator + denominator - 1U) /
                      denominator;
    return sorted[std::max<std::size_t>(rank, 1U) - 1U];
}

[[nodiscard]] std::string_view mode_name(const VerificationMode mode) {
    switch (mode) {
        case VerificationMode::deterministic_model:
            return "deterministic_model";
        case VerificationMode::measured_network:
            return "measured_network";
    }
    throw std::logic_error("unknown transport verification mode");
}

void validate_report(const TransportVerificationReport& report) {
    validate_scenario(report.scenario);
    validate_evidence(report.evidence);
    if (report.schema_version != 1 ||
        report.packets_sent != report.scenario.packet_count ||
        report.packets_delivered > report.packets_sent ||
        report.packets_lost !=
            report.packets_sent - report.packets_delivered ||
        report.duplicate_deliveries > report.packets_delivered * 15U ||
        report.reordered_deliveries > report.packets_delivered ||
        report.packets_delivered >
            std::numeric_limits<std::uint64_t>::max() /
                report.scenario.payload_bytes ||
        report.bytes_delivered !=
            static_cast<std::uint64_t>(report.packets_delivered) *
                report.scenario.payload_bytes ||
        report.latency_p50_us > report.latency_p95_us ||
        report.latency_p95_us > report.latency_max_us ||
        report.migration_requested !=
            report.scenario.migration_sequence.has_value()) {
        throw std::invalid_argument("transport report counters are inconsistent");
    }
    const auto expected_loss_basis_points = static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(report.packets_lost) * 10'000U +
         report.packets_sent - 1U) /
        report.packets_sent);
    const auto expected_sync =
        report.evidence.expected_sync_revision ==
            report.evidence.observed_sync_revision &&
        report.evidence.source_manifest_sha256 ==
            report.evidence.mirror_manifest_sha256;
    const auto expected_build =
        report.evidence.build_exit_code == 0 &&
        report.evidence.expected_artifact_sha256 ==
            report.evidence.observed_artifact_sha256;
    const auto expected_pass =
        report.packets_delivered != 0 && report.migration_recovered &&
        expected_sync && expected_build &&
        report.loss_basis_points <=
            report.scenario.loss_budget_basis_points &&
        report.latency_p95_us <= report.scenario.p95_latency_budget_us;
    if (report.loss_basis_points != expected_loss_basis_points ||
        report.sync_correct != expected_sync ||
        report.build_correct != expected_build ||
        report.passed != expected_pass) {
        throw std::invalid_argument("transport report verdict is inconsistent");
    }
}

}  // namespace

ImpairmentScenario standard_impairment_scenario(const std::string_view id) {
    if (id == "lan-baseline") {
        return {
            .id = "lan-baseline",
            .packet_count = 10'000,
            .payload_bytes = 1200,
            .packet_interval_us = 1000,
            .base_latency_us = 2000,
            .jitter_us = 500,
            .loss_every_nth = 0,
            .duplicate_every_nth = 0,
            .reorder_window = 0,
            .migration_sequence = std::nullopt,
            .migration_outage_us = 0,
            .loss_budget_basis_points = 0,
            .p95_latency_budget_us = 3000,
        };
    }
    if (id == "wifi-loss-reorder") {
        return {
            .id = "wifi-loss-reorder",
            .packet_count = 10'000,
            .payload_bytes = 1200,
            .packet_interval_us = 1000,
            .base_latency_us = 12'000,
            .jitter_us = 8000,
            .loss_every_nth = 97,
            .duplicate_every_nth = 333,
            .reorder_window = 8,
            .migration_sequence = std::nullopt,
            .migration_outage_us = 0,
            .loss_budget_basis_points = 200,
            .p95_latency_budget_us = 30'000,
        };
    }
    if (id == "vpn-network-switch") {
        return {
            .id = "vpn-network-switch",
            .packet_count = 10'000,
            .payload_bytes = 1200,
            .packet_interval_us = 1000,
            .base_latency_us = 25'000,
            .jitter_us = 10'000,
            .loss_every_nth = 113,
            .duplicate_every_nth = 0,
            .reorder_window = 16,
            .migration_sequence = 5000,
            .migration_outage_us = 200'000,
            .loss_budget_basis_points = 150,
            .p95_latency_budget_us = 55'000,
        };
    }
    throw std::invalid_argument("unknown standard impairment scenario");
}

std::vector<PacketObservation> make_deterministic_observations(
    const ImpairmentScenario& scenario) {
    validate_scenario(scenario);
    std::vector<PacketObservation> result;
    result.reserve(scenario.packet_count);
    for (std::size_t sequence = 0; sequence < scenario.packet_count;
         ++sequence) {
        const auto sent = static_cast<std::uint64_t>(sequence) *
                          scenario.packet_interval_us;
        const auto lost = scenario.loss_every_nth != 0 &&
                          (sequence + 1U) % scenario.loss_every_nth == 0;
        PacketObservation observation{
            .sequence = sequence,
            .sent_at_us = sent,
            .first_delivered_at_us = std::nullopt,
            .delivery_count = 0,
        };
        if (!lost) {
            const auto jitter_range = scenario.jitter_us * 2U + 1U;
            const auto sample = jitter_range == 0
                                    ? 0
                                    : (static_cast<std::uint64_t>(sequence) *
                                           1'103'515'245ULL +
                                       12'345ULL) %
                                          jitter_range;
            const auto signed_jitter = static_cast<std::int64_t>(sample) -
                                       static_cast<std::int64_t>(scenario.jitter_us);
            const auto base = static_cast<std::int64_t>(scenario.base_latency_us);
            const auto latency = static_cast<std::uint64_t>(
                std::max<std::int64_t>(base + signed_jitter, 0));
            observation.first_delivered_at_us = sent + latency;
            observation.delivery_count =
                scenario.duplicate_every_nth != 0 &&
                        (sequence + 1U) % scenario.duplicate_every_nth == 0
                    ? 2U
                    : 1U;
        }
        result.push_back(observation);
    }
    if (scenario.reorder_window >= 2) {
        for (std::size_t offset = 0;
             offset + scenario.reorder_window <= result.size();
             offset += scenario.reorder_window * 2U) {
            auto first = result.begin() + static_cast<std::ptrdiff_t>(offset);
            auto last = first +
                        static_cast<std::ptrdiff_t>(scenario.reorder_window);
            std::vector<PacketObservation*> delivered;
            for (auto current = first; current != last; ++current) {
                if (current->first_delivered_at_us) {
                    delivered.push_back(&*current);
                }
            }
            if (delivered.size() >= 2) {
                const auto anchor =
                    delivered.back()->sent_at_us + scenario.base_latency_us;
                for (std::size_t index = 0; index < delivered.size(); ++index) {
                    delivered[index]->first_delivered_at_us =
                        anchor + delivered.size() - index - 1U;
                }
            }
        }
    }
    if (scenario.migration_sequence) {
        auto& migration = result[*scenario.migration_sequence];
        if (migration.first_delivered_at_us) {
            *migration.first_delivered_at_us += scenario.migration_outage_us;
        }
    }
    return result;
}

TransportVerificationReport analyze_transport_verification(
    const VerificationMode mode, const ImpairmentScenario& scenario,
    const CorrectnessEvidence& evidence,
    const std::vector<PacketObservation>& observations) {
    validate_scenario(scenario);
    validate_evidence(evidence);
    if (observations.size() != scenario.packet_count) {
        throw std::invalid_argument("transport observation count does not match scenario");
    }

    std::set<std::size_t> sequences;
    std::vector<std::uint64_t> latencies;
    std::vector<std::pair<std::uint64_t, std::size_t>> delivery_order;
    std::size_t duplicates{};
    bool migration_recovered = !scenario.migration_sequence.has_value();
    for (const auto& observation : observations) {
        if (observation.sequence >= scenario.packet_count ||
            !sequences.insert(observation.sequence).second ||
            observation.delivery_count > 16 ||
            (observation.delivery_count == 0) !=
                !observation.first_delivered_at_us.has_value() ||
            (observation.first_delivered_at_us &&
             *observation.first_delivered_at_us < observation.sent_at_us)) {
            throw std::invalid_argument("transport observation is invalid");
        }
        if (!observation.first_delivered_at_us) continue;
        latencies.push_back(
            *observation.first_delivered_at_us - observation.sent_at_us);
        delivery_order.emplace_back(
            *observation.first_delivered_at_us, observation.sequence);
        duplicates += observation.delivery_count - 1U;
        if (scenario.migration_sequence &&
            observation.sequence > *scenario.migration_sequence) {
            migration_recovered = true;
        }
    }
    std::ranges::sort(latencies);
    std::ranges::sort(delivery_order);
    std::size_t reordered{};
    std::size_t maximum_sequence{};
    bool have_sequence{};
    for (const auto& [_, sequence] : delivery_order) {
        if (have_sequence && sequence < maximum_sequence) ++reordered;
        maximum_sequence = std::max(maximum_sequence, sequence);
        have_sequence = true;
    }

    const auto delivered = latencies.size();
    const auto lost = scenario.packet_count - delivered;
    const auto loss_basis_points = static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(lost) * 10'000U +
         scenario.packet_count - 1U) /
        scenario.packet_count);
    const auto sync_correct =
        evidence.expected_sync_revision == evidence.observed_sync_revision &&
        evidence.source_manifest_sha256 == evidence.mirror_manifest_sha256;
    const auto build_correct =
        evidence.build_exit_code == 0 &&
        evidence.expected_artifact_sha256 ==
            evidence.observed_artifact_sha256;
    const auto p95 = percentile(latencies, 95, 100);

    return {
        .schema_version = 1,
        .mode = mode,
        .scenario = scenario,
        .packets_sent = scenario.packet_count,
        .packets_delivered = delivered,
        .packets_lost = lost,
        .duplicate_deliveries = duplicates,
        .reordered_deliveries = reordered,
        .bytes_delivered = static_cast<std::uint64_t>(delivered) *
                           scenario.payload_bytes,
        .loss_basis_points = loss_basis_points,
        .latency_p50_us = percentile(latencies, 50, 100),
        .latency_p95_us = p95,
        .latency_max_us = latencies.empty() ? 0 : latencies.back(),
        .migration_requested = scenario.migration_sequence.has_value(),
        .migration_recovered = migration_recovered,
        .sync_correct = sync_correct,
        .build_correct = build_correct,
        .passed = delivered != 0 && migration_recovered && sync_correct &&
                  build_correct &&
                  loss_basis_points <= scenario.loss_budget_basis_points &&
                  p95 <= scenario.p95_latency_budget_us,
        .evidence = evidence,
    };
}

std::string render_transport_verification_json(
    const TransportVerificationReport& report) {
    validate_report(report);
    std::ostringstream output;
    output << "{\n"
           << "  \"schema_version\": " << report.schema_version << ",\n"
           << "  \"mode\": \"" << mode_name(report.mode) << "\",\n"
           << "  \"scenario\": {\n"
           << "    \"id\": \"" << report.scenario.id << "\",\n"
           << "    \"packet_count\": " << report.scenario.packet_count << ",\n"
           << "    \"payload_bytes\": " << report.scenario.payload_bytes << ",\n"
           << "    \"packet_interval_us\": "
           << report.scenario.packet_interval_us << ",\n"
           << "    \"base_latency_us\": "
           << report.scenario.base_latency_us << ",\n"
           << "    \"jitter_us\": " << report.scenario.jitter_us << ",\n"
           << "    \"loss_every_nth\": "
           << report.scenario.loss_every_nth << ",\n"
           << "    \"duplicate_every_nth\": "
           << report.scenario.duplicate_every_nth << ",\n"
           << "    \"reorder_window\": "
           << report.scenario.reorder_window << ",\n"
           << "    \"migration_sequence\": ";
    if (report.scenario.migration_sequence) {
        output << *report.scenario.migration_sequence;
    } else {
        output << "null";
    }
    output << ",\n"
           << "    \"migration_outage_us\": "
           << report.scenario.migration_outage_us << ",\n"
           << "    \"loss_budget_basis_points\": "
           << report.scenario.loss_budget_basis_points << ",\n"
           << "    \"p95_latency_budget_us\": "
           << report.scenario.p95_latency_budget_us << "\n"
           << "  },\n"
           << "  \"packets_sent\": " << report.packets_sent << ",\n"
           << "  \"packets_delivered\": " << report.packets_delivered << ",\n"
           << "  \"packets_lost\": " << report.packets_lost << ",\n"
           << "  \"duplicate_deliveries\": " << report.duplicate_deliveries << ",\n"
           << "  \"reordered_deliveries\": " << report.reordered_deliveries << ",\n"
           << "  \"bytes_delivered\": " << report.bytes_delivered << ",\n"
           << "  \"loss_basis_points\": " << report.loss_basis_points << ",\n"
           << "  \"latency_p50_us\": " << report.latency_p50_us << ",\n"
           << "  \"latency_p95_us\": " << report.latency_p95_us << ",\n"
           << "  \"latency_max_us\": " << report.latency_max_us << ",\n"
           << "  \"migration_requested\": "
           << (report.migration_requested ? "true" : "false") << ",\n"
           << "  \"migration_recovered\": "
           << (report.migration_recovered ? "true" : "false") << ",\n"
           << "  \"sync_correct\": "
           << (report.sync_correct ? "true" : "false") << ",\n"
           << "  \"build_correct\": "
           << (report.build_correct ? "true" : "false") << ",\n"
           << "  \"passed\": " << (report.passed ? "true" : "false") << ",\n"
           << "  \"evidence\": {\n"
           << "    \"expected_sync_revision\": "
           << report.evidence.expected_sync_revision << ",\n"
           << "    \"observed_sync_revision\": "
           << report.evidence.observed_sync_revision << ",\n"
           << "    \"source_manifest_sha256\": \""
           << report.evidence.source_manifest_sha256 << "\",\n"
           << "    \"mirror_manifest_sha256\": \""
           << report.evidence.mirror_manifest_sha256 << "\",\n"
           << "    \"build_id\": \"" << report.evidence.build_id << "\",\n"
           << "    \"build_evidence_sha256\": \""
           << report.evidence.build_evidence_sha256 << "\",\n"
           << "    \"build_exit_code\": "
           << report.evidence.build_exit_code << ",\n"
           << "    \"expected_artifact_sha256\": \""
           << report.evidence.expected_artifact_sha256 << "\",\n"
           << "    \"observed_artifact_sha256\": \""
           << report.evidence.observed_artifact_sha256 << "\"\n"
           << "  }\n"
           << "}\n";
    return output.str();
}

void write_transport_verification_report(
    const std::filesystem::path& destination,
    const TransportVerificationReport& report) {
    if (!destination.is_absolute() || destination.extension() != ".json" ||
        destination.filename().string().find_first_of("\r\n") !=
            std::string::npos ||
        !std::filesystem::is_directory(destination.parent_path()) ||
        std::filesystem::exists(destination)) {
        throw std::invalid_argument("transport report destination is invalid");
    }
    const auto temporary = destination.string() + ".tmp";
    if (std::filesystem::exists(temporary)) {
        throw std::invalid_argument("transport report staging path already exists");
    }
    try {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output) throw std::runtime_error("transport report could not be opened");
        output << render_transport_verification_json(report);
        output.flush();
        if (!output) throw std::runtime_error("transport report write failed");
        output.close();
        std::filesystem::rename(temporary, destination);
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        throw;
    }
}

}  // namespace rwn::transport
