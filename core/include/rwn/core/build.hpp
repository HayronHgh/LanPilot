#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace rwn::core {

class CancellationToken {
public:
  CancellationToken() = default;

  [[nodiscard]] bool stop_requested() const noexcept {
        return state_ != nullptr && state_->load(std::memory_order_acquire);
    }

private:
    friend class CancellationSource;
    explicit CancellationToken(std::shared_ptr<std::atomic_bool> state)
        : state_(std::move(state)) {}
    std::shared_ptr<std::atomic_bool> state_;
};

class CancellationSource {
public:
    CancellationSource() : state_(std::make_shared<std::atomic_bool>(false)) {}
    [[nodiscard]] CancellationToken token() const { return CancellationToken(state_); }
    bool request_stop() noexcept {
        return !state_->exchange(true, std::memory_order_acq_rel);
    }

private:
    std::shared_ptr<std::atomic_bool> state_;
};

struct CommandSpec {
    std::vector<std::string> argv;
    std::string working_directory;
    std::chrono::seconds timeout{};
    std::map<std::string, std::string, std::less<>> environment;
};

struct BuildRequest { std::string id; std::string workspace_id; std::uint64_t pinned_revision{}; std::string profile; CommandSpec command; };
enum class BuildState { queued, running, cancelled, succeeded, failed };
struct BuildEvidence {
    int exit_code{};
    std::string stdout_log{};
    std::string stderr_log{};
    std::chrono::milliseconds elapsed{};
    bool timed_out{};
    bool cancelled{};
    bool stdout_truncated{};
    bool stderr_truncated{};
};
struct BuildExecutionResult {
    BuildEvidence evidence;
    std::vector<std::string> artifact_ids;
};
struct Artifact {
    std::string id;
    std::string workspace_id;
    std::string build_id;
    std::uint64_t source_revision{};
    std::string name;
    std::string sha256;
    std::uint64_t size{};
    std::string platform;
    std::string architecture;
    std::chrono::system_clock::time_point created_at{};
    [[nodiscard]] bool operator==(const Artifact&) const = default;
};

void validate_command(const CommandSpec& command, const std::set<std::string, std::less<>>& environment_allowlist);
void validate_artifact(const Artifact& artifact);
[[nodiscard]] std::string build_evidence_sha256(
    const BuildRequest& request, const BuildEvidence& evidence);

class CommandExecutor {
public:
    virtual ~CommandExecutor() = default;
    [[nodiscard]] virtual BuildEvidence execute(
        const CommandSpec& command, CancellationToken stop_token = {}) = 0;
};

class BuildQueue {
public:
    void submit(BuildRequest request, const std::set<std::string, std::less<>>& environment_allowlist);
    void start(const std::string& build_id);
    void cancel(const std::string& build_id);
    void finish(const std::string& build_id, BuildEvidence evidence);
    [[nodiscard]] BuildState state(const std::string& build_id) const;
    [[nodiscard]] const std::optional<BuildEvidence>& evidence(const std::string& build_id) const;
    [[nodiscard]] const BuildRequest& request(const std::string& build_id) const;
private:
    struct Job { BuildRequest request; BuildState state{BuildState::queued}; std::optional<BuildEvidence> evidence; };
    std::map<std::string, Job, std::less<>> jobs_;
};

class BuildRunner {
public:
    BuildRunner(BuildQueue& queue, CommandExecutor& executor)
        : queue_(queue), executor_(executor) {}
    [[nodiscard]] BuildEvidence run(
        const std::string& build_id, CancellationToken stop_token = {});

private:
    BuildQueue& queue_;
    CommandExecutor& executor_;
};

}  // namespace rwn::core
