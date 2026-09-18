#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rwn::transport {

enum class VerificationMode { deterministic_model, measured_network };

struct ImpairmentScenario {
    std::string id;
    std::size_t packet_count{};
    std::size_t payload_bytes{};
    std::uint64_t packet_interval_us{};
    std::uint64_t base_latency_us{};
    std::uint64_t jitter_us{};
    std::size_t loss_every_nth{};
    std::size_t duplicate_every_nth{};
    std::size_t reorder_window{};
    std::optional<std::size_t> migration_sequence;
    std::uint64_t migration_outage_us{};
    std::uint32_t loss_budget_basis_points{};
    std::uint64_t p95_latency_budget_us{};
};

struct CorrectnessEvidence {
    std::uint64_t expected_sync_revision{};
    std::uint64_t observed_sync_revision{};
    std::string source_manifest_sha256;
    std::string mirror_manifest_sha256;
    std::string build_id;
    std::string build_evidence_sha256;
    std::int32_t build_exit_code{};
    std::string expected_artifact_sha256;
    std::string observed_artifact_sha256;
};

struct PacketObservation {
    std::size_t sequence{};
    std::uint64_t sent_at_us{};
    std::optional<std::uint64_t> first_delivered_at_us;
    std::size_t delivery_count{};
};

struct TransportVerificationReport {
    std::uint32_t schema_version{1};
    VerificationMode mode{VerificationMode::deterministic_model};
    ImpairmentScenario scenario;
    std::size_t packets_sent{};
    std::size_t packets_delivered{};
    std::size_t packets_lost{};
    std::size_t duplicate_deliveries{};
    std::size_t reordered_deliveries{};
    std::uint64_t bytes_delivered{};
    std::uint32_t loss_basis_points{};
    std::uint64_t latency_p50_us{};
    std::uint64_t latency_p95_us{};
    std::uint64_t latency_max_us{};
    bool migration_requested{};
    bool migration_recovered{};
    bool sync_correct{};
    bool build_correct{};
    bool passed{};
    CorrectnessEvidence evidence;
};

[[nodiscard]] ImpairmentScenario standard_impairment_scenario(
    std::string_view id);
[[nodiscard]] std::vector<PacketObservation>
make_deterministic_observations(const ImpairmentScenario& scenario);
[[nodiscard]] TransportVerificationReport analyze_transport_verification(
    VerificationMode mode, const ImpairmentScenario& scenario,
    const CorrectnessEvidence& evidence,
    const std::vector<PacketObservation>& observations);
[[nodiscard]] std::string render_transport_verification_json(
    const TransportVerificationReport& report);
void write_transport_verification_report(
    const std::filesystem::path& destination,
    const TransportVerificationReport& report);

}  // namespace rwn::transport
