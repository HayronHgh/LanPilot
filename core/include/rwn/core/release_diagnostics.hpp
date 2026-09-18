#pragma once

#include "rwn/core/build.hpp"
#include "rwn/core/file_transfer.hpp"
#include "rwn/core/release_compatibility.hpp"
#include "rwn/core/release_update.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rwn::core {

enum class DiagnosticComponent {
    client,
    node,
    broker,
    build_worker,
    desktop_agent,
    compatibility,
    protected_state,
    release_update,
};

enum class DiagnosticOperation {
    self_check,
    compatibility_load,
    state_inventory,
    update_apply,
    update_rollback,
};

enum class DiagnosticResult { passed, failed, not_run };

struct DiagnosticCheck {
    DiagnosticComponent component{DiagnosticComponent::node};
    DiagnosticOperation operation{DiagnosticOperation::self_check};
    DiagnosticResult result{DiagnosticResult::not_run};
    std::int32_t exit_code{};
    std::uint64_t elapsed_ms{};
    std::uint64_t stdout_bytes{};
    std::uint64_t stderr_bytes{};
    bool timed_out{};
    bool cancelled{};
    bool stdout_truncated{};
    bool stderr_truncated{};
};

[[nodiscard]] DiagnosticCheck make_runtime_diagnostic(
    DiagnosticComponent component, DiagnosticOperation operation,
    const BuildEvidence& evidence);
[[nodiscard]] DiagnosticCheck make_boolean_diagnostic(
    DiagnosticComponent component, DiagnosticOperation operation,
    bool passed);

struct DiagnosticCompatibilitySummary {
    bool available{};
    std::uint16_t protocol_minimum{};
    std::uint16_t protocol_maximum{};
    std::uint32_t state_schema{};
    std::uint32_t package_schema{};
};

struct DiagnosticStateSummary {
    bool available{};
    std::size_t entries{};
    std::uint64_t total_bytes{};
    std::string inventory_sha256;
};

struct DiagnosticUpdateSummary {
    ReleaseUpdateStatus status{ReleaseUpdateStatus::failed};
    SemanticVersion target_version;
    std::string package_sha256;
    bool protected_state_preserved{};
    std::size_t evidence_steps{};
};

[[nodiscard]] DiagnosticCompatibilitySummary summarize_compatibility(
    const ReleaseCompatibilityPolicy& policy);
[[nodiscard]] DiagnosticStateSummary summarize_protected_state(
    const ProtectedStateSnapshot& snapshot);
[[nodiscard]] DiagnosticUpdateSummary summarize_release_update(
    const ReleaseUpdateRecord& record);

struct ReleaseDiagnosticBundle {
    std::uint32_t schema_version{1};
    std::string bundle_id;
    SemanticVersion product_version;
    std::string platform;
    std::string architecture;
    std::uint64_t generated_at_unix_ms{};
    DiagnosticCompatibilitySummary compatibility;
    DiagnosticStateSummary protected_state;
    std::optional<DiagnosticUpdateSummary> update;
    std::vector<DiagnosticCheck> checks;
};

void validate_release_diagnostic_bundle(
    const ReleaseDiagnosticBundle& bundle);
[[nodiscard]] std::string render_release_diagnostic_json(
    const ReleaseDiagnosticBundle& bundle);
void write_release_diagnostic_bundle(
    const std::filesystem::path& destination,
    const ReleaseDiagnosticBundle& bundle,
    DurableFileSystem& filesystem);

}  // namespace rwn::core
