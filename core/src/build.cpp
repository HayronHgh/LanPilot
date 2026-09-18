#include "rwn/core/build.hpp"

#include "rwn/core/content_hash.hpp"

#include <algorithm>
#include <cctype>
#include <exception>
#include <ranges>
#include <span>
#include <stdexcept>

namespace rwn::core {
namespace {

bool valid_id(const std::string_view value) {
    return !value.empty() && value.size() <= 64 &&
           std::ranges::all_of(value, [](const unsigned char character) {
               return std::isalnum(character) != 0 || character == '-' ||
                      character == '_';
           });
}

bool valid_environment_name(const std::string_view value) {
    if (value.empty() || value.size() > 128 ||
        !(std::isalpha(static_cast<unsigned char>(value.front())) != 0 ||
          value.front() == '_')) {
        return false;
    }
    return std::ranges::all_of(value.substr(1), [](const unsigned char character) {
        return std::isalnum(character) != 0 || character == '_';
    });
}

void append_u64(std::vector<std::byte>& output, const std::uint64_t value) {
    for (const unsigned shift : {56U, 48U, 40U, 32U, 24U, 16U, 8U, 0U}) {
        output.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
    }
}

void append_string(
    std::vector<std::byte>& output, const std::string_view value) {
    append_u64(output, value.size());
    const auto bytes = std::as_bytes(std::span{value.data(), value.size()});
    output.insert(output.end(), bytes.begin(), bytes.end());
}

}  // namespace

void validate_command(const CommandSpec& command, const std::set<std::string, std::less<>>& environment_allowlist) {
    if (command.argv.empty() || command.argv.front().empty() || command.working_directory.empty() || command.working_directory.find('\0') != std::string::npos || command.timeout <= std::chrono::seconds::zero()) { throw std::invalid_argument("invalid command specification"); }
    for (const auto& arg : command.argv) { if (arg.find('\0') != std::string::npos) { throw std::invalid_argument("command argument contains NUL"); } }
    for (const auto& [name, value] : command.environment) { if (!valid_environment_name(name) || value.find('\0') != std::string::npos || !environment_allowlist.contains(name)) { throw std::invalid_argument("environment variable is invalid or not allowlisted"); } }
}
void validate_artifact(const Artifact& artifact) {
    const auto safe_name = !artifact.name.empty() && artifact.name != "." &&
        artifact.name != ".." && artifact.name.size() <= 255 &&
        artifact.name.find_first_of("/\\=\r\n\0") == std::string::npos &&
        std::ranges::none_of(artifact.name, [](const unsigned char character) {
            return character < 0x20U || character == 0x7fU;
        });
    if (!valid_id(artifact.id) || !valid_id(artifact.workspace_id) ||
        !valid_id(artifact.build_id) || artifact.source_revision == 0 ||
        !safe_name || !is_sha256_hex(artifact.sha256) || artifact.size == 0 ||
        !valid_id(artifact.platform) || !valid_id(artifact.architecture) ||
        artifact.created_at == std::chrono::system_clock::time_point{}) {
        throw std::invalid_argument("invalid immutable artifact");
    }
}
void BuildQueue::submit(BuildRequest request, const std::set<std::string, std::less<>>& environment_allowlist) {
    if (!valid_id(request.id) || !valid_id(request.workspace_id) || request.pinned_revision == 0 || !valid_id(request.profile)) { throw std::invalid_argument("invalid build request"); }
    validate_command(request.command, environment_allowlist);
    const auto build_id = request.id;
    if (!jobs_.emplace(build_id, Job{.request = std::move(request), .state = BuildState::queued, .evidence = std::nullopt}).second) {
        throw std::invalid_argument("duplicate build id");
    }
}
void BuildQueue::start(const std::string& build_id) { auto& job = jobs_.at(build_id); if (job.state != BuildState::queued) { throw std::logic_error("build cannot start"); } job.state = BuildState::running; }
void BuildQueue::cancel(const std::string& build_id) { auto& job = jobs_.at(build_id); if (job.state != BuildState::queued && job.state != BuildState::running) { throw std::logic_error("build cannot cancel"); } job.state = BuildState::cancelled; }
void BuildQueue::finish(const std::string& build_id, BuildEvidence evidence) { auto& job = jobs_.at(build_id); if (job.state != BuildState::running || evidence.elapsed < std::chrono::milliseconds::zero()) { throw std::logic_error("build cannot finish"); } job.state = evidence.cancelled ? BuildState::cancelled : (evidence.exit_code == 0 && !evidence.timed_out ? BuildState::succeeded : BuildState::failed); job.evidence = std::move(evidence); }
BuildState BuildQueue::state(const std::string& build_id) const { return jobs_.at(build_id).state; }
const std::optional<BuildEvidence>& BuildQueue::evidence(const std::string& build_id) const { return jobs_.at(build_id).evidence; }
const BuildRequest& BuildQueue::request(const std::string& build_id) const { return jobs_.at(build_id).request; }

BuildEvidence BuildRunner::run(
    const std::string& build_id, const CancellationToken stop_token) {
    queue_.start(build_id);
    BuildEvidence evidence;
    try {
        evidence = executor_.execute(queue_.request(build_id).command, stop_token);
    } catch (const std::exception& error) {
        evidence = {
            .exit_code = -1,
            .stdout_log = {},
            .stderr_log = error.what(),
            .elapsed = std::chrono::milliseconds::zero(),
            .timed_out = false,
            .cancelled = stop_token.stop_requested(),
            .stdout_truncated = false,
            .stderr_truncated = false,
        };
    }
    queue_.finish(build_id, evidence);
    return evidence;
}
std::string build_evidence_sha256(
    const BuildRequest& request, const BuildEvidence& evidence) {
    if (!valid_id(request.id) || !valid_id(request.workspace_id) ||
        request.pinned_revision == 0 || !valid_id(request.profile) ||
        evidence.elapsed < std::chrono::milliseconds::zero()) {
        throw std::invalid_argument("build evidence identity is invalid");
    }
    std::vector<std::byte> canonical;
    append_string(canonical, "rwn-build-evidence-v1");
    append_string(canonical, request.id);
    append_string(canonical, request.workspace_id);
    append_u64(canonical, request.pinned_revision);
    append_string(canonical, request.profile);
    append_u64(canonical, request.command.argv.size());
    for (const auto& argument : request.command.argv) append_string(canonical, argument);
    append_string(canonical, request.command.working_directory);
    append_u64(canonical, static_cast<std::uint64_t>(request.command.timeout.count()));
    append_u64(canonical, request.command.environment.size());
    for (const auto& [name, value] : request.command.environment) {
        append_string(canonical, name); append_string(canonical, value);
    }
    append_u64(canonical, static_cast<std::uint32_t>(evidence.exit_code));
    append_u64(canonical, static_cast<std::uint64_t>(evidence.elapsed.count()));
    canonical.push_back(evidence.timed_out ? std::byte{1} : std::byte{0});
    canonical.push_back(evidence.cancelled ? std::byte{1} : std::byte{0});
    canonical.push_back(evidence.stdout_truncated ? std::byte{1} : std::byte{0});
    canonical.push_back(evidence.stderr_truncated ? std::byte{1} : std::byte{0});
    append_string(canonical, evidence.stdout_log);
    append_string(canonical, evidence.stderr_log);
    return sha256_hex(canonical);
}
}  // namespace rwn::core
