#include "rwn/core/release_diagnostics.hpp"

#include "rwn/core/content_hash.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <ranges>
#include <set>
#include <stdexcept>
#include <tuple>

namespace rwn::core {
namespace {

constexpr std::uint64_t maximum_diagnostic_log_bytes =
    16ULL * 1024ULL * 1024ULL;
constexpr std::uint64_t maximum_diagnostic_elapsed_ms =
    24ULL * 60ULL * 60ULL * 1000ULL;
constexpr std::size_t maximum_diagnostic_checks = 32U;
constexpr std::size_t maximum_diagnostic_json_bytes = 256U * 1024U;

[[nodiscard]] bool valid_id(const std::string_view value) {
    return !value.empty() && value.size() <= 64U &&
           std::ranges::all_of(value, [](const unsigned char character) {
               return std::isalnum(character) != 0 || character == '-' ||
                      character == '_';
           });
}

[[nodiscard]] bool valid_target(const std::string_view value) {
    return !value.empty() && value.size() <= 32U &&
           std::ranges::all_of(value, [](const unsigned char character) {
               return std::islower(character) != 0 ||
                      std::isdigit(character) != 0 || character == '-' ||
                      character == '_';
           });
}

[[nodiscard]] std::string_view component_name(
    const DiagnosticComponent component) {
    switch (component) {
        case DiagnosticComponent::client: return "client";
        case DiagnosticComponent::node: return "node";
        case DiagnosticComponent::broker: return "broker";
        case DiagnosticComponent::build_worker: return "build_worker";
        case DiagnosticComponent::desktop_agent: return "desktop_agent";
        case DiagnosticComponent::compatibility: return "compatibility";
        case DiagnosticComponent::protected_state: return "protected_state";
        case DiagnosticComponent::release_update: return "release_update";
    }
    throw std::invalid_argument("diagnostic component is invalid");
}

[[nodiscard]] std::string_view operation_name(
    const DiagnosticOperation operation) {
    switch (operation) {
        case DiagnosticOperation::self_check: return "self_check";
        case DiagnosticOperation::compatibility_load:
            return "compatibility_load";
        case DiagnosticOperation::state_inventory: return "state_inventory";
        case DiagnosticOperation::update_apply: return "update_apply";
        case DiagnosticOperation::update_rollback: return "update_rollback";
    }
    throw std::invalid_argument("diagnostic operation is invalid");
}

[[nodiscard]] std::string_view result_name(const DiagnosticResult result) {
    switch (result) {
        case DiagnosticResult::passed: return "passed";
        case DiagnosticResult::failed: return "failed";
        case DiagnosticResult::not_run: return "not_run";
    }
    throw std::invalid_argument("diagnostic result is invalid");
}

[[nodiscard]] std::string_view update_status_name(
    const ReleaseUpdateStatus status) {
    switch (status) {
        case ReleaseUpdateStatus::updating: return "updating";
        case ReleaseUpdateStatus::active: return "active";
        case ReleaseUpdateStatus::rolled_back: return "rolled_back";
        case ReleaseUpdateStatus::failed: return "failed";
    }
    throw std::invalid_argument("release update status is invalid");
}

[[nodiscard]] std::string boolean(const bool value) {
    return value ? "true" : "false";
}

void validate_check(const DiagnosticCheck& check) {
    static_cast<void>(component_name(check.component));
    static_cast<void>(operation_name(check.operation));
    static_cast<void>(result_name(check.result));
    if (check.elapsed_ms > maximum_diagnostic_elapsed_ms ||
        check.stdout_bytes > maximum_diagnostic_log_bytes ||
        check.stderr_bytes > maximum_diagnostic_log_bytes) {
        throw std::length_error("diagnostic check exceeds bounded telemetry");
    }
    if (check.result == DiagnosticResult::passed &&
        (check.exit_code != 0 || check.timed_out || check.cancelled)) {
        throw std::invalid_argument("passing diagnostic evidence is invalid");
    }
    if (check.result == DiagnosticResult::failed &&
        check.exit_code == 0 && !check.timed_out && !check.cancelled) {
        throw std::invalid_argument("failed diagnostic evidence is invalid");
    }
    if (check.result == DiagnosticResult::not_run &&
        (check.exit_code != 0 || check.elapsed_ms != 0 ||
         check.stdout_bytes != 0 || check.stderr_bytes != 0 ||
         check.timed_out || check.cancelled || check.stdout_truncated ||
         check.stderr_truncated)) {
        throw std::invalid_argument("not-run diagnostic contains evidence");
    }
}

}  // namespace

DiagnosticCheck make_runtime_diagnostic(
    const DiagnosticComponent component,
    const DiagnosticOperation operation,
    const BuildEvidence& evidence) {
    if (evidence.elapsed.count() < 0) {
        throw std::invalid_argument("diagnostic runtime duration is invalid");
    }
    const auto passed = evidence.exit_code == 0 && !evidence.timed_out &&
                        !evidence.cancelled;
    DiagnosticCheck check{
        .component = component,
        .operation = operation,
        .result = passed ? DiagnosticResult::passed : DiagnosticResult::failed,
        .exit_code = evidence.exit_code,
        .elapsed_ms = static_cast<std::uint64_t>(evidence.elapsed.count()),
        .stdout_bytes = evidence.stdout_log.size(),
        .stderr_bytes = evidence.stderr_log.size(),
        .timed_out = evidence.timed_out,
        .cancelled = evidence.cancelled,
        .stdout_truncated = evidence.stdout_truncated,
        .stderr_truncated = evidence.stderr_truncated,
    };
    validate_check(check);
    return check;
}

DiagnosticCheck make_boolean_diagnostic(
    const DiagnosticComponent component,
    const DiagnosticOperation operation,
    const bool passed) {
    DiagnosticCheck check{
        .component = component,
        .operation = operation,
        .result = passed ? DiagnosticResult::passed : DiagnosticResult::failed,
        .exit_code = passed ? 0 : 1,
        .elapsed_ms = 0,
        .stdout_bytes = 0,
        .stderr_bytes = 0,
        .timed_out = false,
        .cancelled = false,
        .stdout_truncated = false,
        .stderr_truncated = false,
    };
    validate_check(check);
    return check;
}

DiagnosticCompatibilitySummary summarize_compatibility(
    const ReleaseCompatibilityPolicy& policy) {
    return {
        .available = true,
        .protocol_minimum = policy.protocol_minimum,
        .protocol_maximum = policy.protocol_maximum,
        .state_schema = policy.state_schema_current,
        .package_schema = policy.package_schema,
    };
}

DiagnosticStateSummary summarize_protected_state(
    const ProtectedStateSnapshot& snapshot) {
    if (!is_sha256_hex(snapshot.inventory_sha256)) {
        throw std::invalid_argument("protected state inventory hash is invalid");
    }
    return {
        .available = true,
        .entries = snapshot.entries.size(),
        .total_bytes = snapshot.total_bytes,
        .inventory_sha256 = snapshot.inventory_sha256,
    };
}

DiagnosticUpdateSummary summarize_release_update(
    const ReleaseUpdateRecord& record) {
    if (!is_sha256_hex(record.package_sha256)) {
        throw std::invalid_argument("release update package hash is invalid");
    }
    return {
        .status = record.status,
        .target_version = record.target_version,
        .package_sha256 = record.package_sha256,
        .protected_state_preserved =
            !record.protected_state_before_sha256.empty() &&
            record.protected_state_before_sha256 ==
                record.protected_state_after_sha256,
        .evidence_steps = record.evidence.size(),
    };
}

void validate_release_diagnostic_bundle(
    const ReleaseDiagnosticBundle& bundle) {
    if (bundle.schema_version != 1 || !valid_id(bundle.bundle_id) ||
        !valid_target(bundle.platform) ||
        !valid_target(bundle.architecture) ||
        bundle.generated_at_unix_ms == 0 || bundle.checks.empty() ||
        bundle.checks.size() > maximum_diagnostic_checks) {
        throw std::invalid_argument("release diagnostic bundle is invalid");
    }
    if (bundle.compatibility.available) {
        if (bundle.compatibility.protocol_minimum == 0 ||
            bundle.compatibility.protocol_minimum >
                bundle.compatibility.protocol_maximum ||
            bundle.compatibility.state_schema == 0 ||
            bundle.compatibility.package_schema == 0) {
            throw std::invalid_argument(
                "diagnostic compatibility summary is invalid");
        }
    } else if (bundle.compatibility.protocol_minimum != 0 ||
               bundle.compatibility.protocol_maximum != 0 ||
               bundle.compatibility.state_schema != 0 ||
               bundle.compatibility.package_schema != 0) {
        throw std::invalid_argument(
            "unavailable diagnostic compatibility has data");
    }
    if (bundle.protected_state.available) {
        if (bundle.protected_state.entries < 3 ||
            !is_sha256_hex(bundle.protected_state.inventory_sha256)) {
            throw std::invalid_argument(
                "diagnostic protected state summary is invalid");
        }
    } else if (bundle.protected_state.entries != 0 ||
               bundle.protected_state.total_bytes != 0 ||
               !bundle.protected_state.inventory_sha256.empty()) {
        throw std::invalid_argument(
            "unavailable diagnostic protected state has data");
    }
    if (bundle.update) {
        if (!is_sha256_hex(bundle.update->package_sha256) ||
            bundle.update->evidence_steps == 0) {
            throw std::invalid_argument("diagnostic update summary is invalid");
        }
        static_cast<void>(update_status_name(bundle.update->status));
    }
    std::set<std::tuple<int, int>> unique_checks;
    for (const auto& check : bundle.checks) {
        validate_check(check);
        const auto key = std::tuple{
            static_cast<int>(check.component),
            static_cast<int>(check.operation)};
        if (!unique_checks.insert(key).second) {
            throw std::invalid_argument("diagnostic check is duplicated");
        }
    }
}

std::string render_release_diagnostic_json(
    const ReleaseDiagnosticBundle& bundle) {
    validate_release_diagnostic_bundle(bundle);
    std::string output;
    output.reserve(4096);
    output += "{\n  \"schema_version\": 1,\n";
    output += "  \"bundle_id\": \"" + bundle.bundle_id + "\",\n";
    output += "  \"product_version\": \"" +
              to_string(bundle.product_version) + "\",\n";
    output += "  \"platform\": \"" + bundle.platform + "\",\n";
    output += "  \"architecture\": \"" + bundle.architecture + "\",\n";
    output += "  \"generated_at_unix_ms\": " +
              std::to_string(bundle.generated_at_unix_ms) + ",\n";
    output += "  \"compatibility\": {\"available\": " +
              boolean(bundle.compatibility.available) +
              ", \"protocol_minimum\": " +
              std::to_string(bundle.compatibility.protocol_minimum) +
              ", \"protocol_maximum\": " +
              std::to_string(bundle.compatibility.protocol_maximum) +
              ", \"state_schema\": " +
              std::to_string(bundle.compatibility.state_schema) +
              ", \"package_schema\": " +
              std::to_string(bundle.compatibility.package_schema) + "},\n";
    output += "  \"protected_state\": {\"available\": " +
              boolean(bundle.protected_state.available) +
              ", \"entries\": " +
              std::to_string(bundle.protected_state.entries) +
              ", \"total_bytes\": " +
              std::to_string(bundle.protected_state.total_bytes) +
              ", \"inventory_sha256\": \"" +
              bundle.protected_state.inventory_sha256 + "\"},\n";
    output += "  \"update\": ";
    if (bundle.update) {
        output += "{\"status\": \"" +
                  std::string(update_status_name(bundle.update->status)) +
                  "\", \"target_version\": \"" +
                  to_string(bundle.update->target_version) +
                  "\", \"package_sha256\": \"" +
                  bundle.update->package_sha256 +
                  "\", \"protected_state_preserved\": " +
                  boolean(bundle.update->protected_state_preserved) +
                  ", \"evidence_steps\": " +
                  std::to_string(bundle.update->evidence_steps) + "},\n";
    } else {
        output += "null,\n";
    }
    output += "  \"checks\": [\n";
    for (std::size_t index = 0; index < bundle.checks.size(); ++index) {
        const auto& check = bundle.checks[index];
        output += "    {\"component\": \"" +
                  std::string(component_name(check.component)) +
                  "\", \"operation\": \"" +
                  std::string(operation_name(check.operation)) +
                  "\", \"result\": \"" +
                  std::string(result_name(check.result)) +
                  "\", \"exit_code\": " +
                  std::to_string(check.exit_code) +
                  ", \"elapsed_ms\": " +
                  std::to_string(check.elapsed_ms) +
                  ", \"stdout_bytes\": " +
                  std::to_string(check.stdout_bytes) +
                  ", \"stderr_bytes\": " +
                  std::to_string(check.stderr_bytes) +
                  ", \"timed_out\": " + boolean(check.timed_out) +
                  ", \"cancelled\": " + boolean(check.cancelled) +
                  ", \"stdout_truncated\": " +
                  boolean(check.stdout_truncated) +
                  ", \"stderr_truncated\": " +
                  boolean(check.stderr_truncated) + "}";
        output += index + 1U == bundle.checks.size() ? "\n" : ",\n";
    }
    output += "  ]\n}\n";
    if (output.size() > maximum_diagnostic_json_bytes) {
        throw std::length_error("release diagnostic JSON exceeds limit");
    }
    return output;
}

void write_release_diagnostic_bundle(
    const std::filesystem::path& destination,
    const ReleaseDiagnosticBundle& bundle,
    DurableFileSystem& filesystem) {
    const auto json = render_release_diagnostic_json(bundle);
    if (!destination.is_absolute() || destination.extension() != ".json" ||
        !std::filesystem::is_directory(destination.parent_path()) ||
        std::filesystem::exists(destination)) {
        throw std::invalid_argument(
            "diagnostic destination must be a new absolute JSON file");
    }
    const auto staging = destination.parent_path() /
        ("." + destination.filename().string() + "." + bundle.bundle_id +
         ".part");
    if (std::filesystem::exists(staging)) {
        throw std::logic_error("diagnostic staging path already exists");
    }
    {
        std::ofstream output(staging, std::ios::binary | std::ios::trunc);
        output.write(json.data(), static_cast<std::streamsize>(json.size()));
        if (!output) {
            throw std::runtime_error("diagnostic staging write failed");
        }
    }
    if (std::filesystem::file_size(staging) != json.size() ||
        sha256_file(staging) != sha256_hex(json)) {
        throw std::runtime_error("diagnostic staging verification failed");
    }
    filesystem.flush_file(staging);
    filesystem.atomic_replace(staging, destination);
    if (!std::filesystem::is_regular_file(destination) ||
        std::filesystem::file_size(destination) != json.size() ||
        sha256_file(destination) != sha256_hex(json)) {
        throw std::runtime_error("diagnostic output verification failed");
    }
}

}  // namespace rwn::core
