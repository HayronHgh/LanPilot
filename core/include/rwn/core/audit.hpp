#pragma once

#include "rwn/core/identity.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace rwn::core {

enum class AuditAction {
    pairing_started,
    pairing_confirmed,
    session_authenticated,
    session_opened,
    session_renewed,
    session_closed,
    device_revoked,
    workspace_sync_started,
    workspace_sync_committed,
    workspace_sync_failed,
    build_submitted,
    build_completed,
    artifact_published,
    artifact_downloaded,
    deployment_started,
    deployment_active,
    deployment_rolled_back,
    deployment_failed,
    scope_access_denied,
    audit_exported,
    agent_job_started,
    agent_review_requested,
    agent_review_granted,
    agent_tool_completed,
    agent_job_completed,
};
enum class AuditResult { allowed, denied, failed };

[[nodiscard]] std::string_view to_string(AuditAction action);
[[nodiscard]] std::string_view to_string(AuditResult result);

struct AuditEvent {
    TimePoint occurred_at{};
    std::string principal_id{};
    std::string device_id{};
    std::string session_id{};
    std::string workspace_id{};
    std::string build_id{};
    std::string artifact_id{};
    std::string artifact_sha256{};
    std::uint64_t source_revision{};
    std::string deployment_id{};
    std::string process_role{};
    std::string reason_code{};
    std::string agent_job_id{};
    std::string tool_name{};
    std::string evidence_id{};
    AuditAction action{AuditAction::session_opened};
    AuditResult result{AuditResult::allowed};
};

struct AuditQuery {
    TimePoint from{};
    TimePoint to{TimePoint::max()};
    std::string principal_id{};
    std::string workspace_id{};
    std::string build_id{};
    std::string artifact_id{};
    std::string deployment_id{};
    std::string agent_job_id{};
    std::size_t limit{1000};
};

struct AuditRetentionPolicy {
    std::chrono::hours maximum_age{std::chrono::hours{24 * 90}};
    std::size_t maximum_events{100000};
};

class AuditSink {
public:
    virtual ~AuditSink() = default;
    virtual void append_line(std::string_view canonical_json_line) = 0;
};

class AuditLog {
public:
    explicit AuditLog(
        AuditRetentionPolicy retention = {}, AuditSink* sink = nullptr);
    void append(AuditEvent event);
    [[nodiscard]] const std::vector<AuditEvent>& events() const { return events_; }
    [[nodiscard]] std::vector<AuditEvent> for_session(std::string_view session_id) const;
    [[nodiscard]] std::vector<AuditEvent> for_artifact(
        std::string_view artifact_id) const;
    [[nodiscard]] std::vector<AuditEvent> query(const AuditQuery& query) const;
    [[nodiscard]] std::string export_json_lines(const AuditQuery& query) const;
    void enforce_retention(TimePoint now);

private:
    AuditRetentionPolicy retention_;
    AuditSink* sink_{};
    std::vector<AuditEvent> events_;
};

}  // namespace rwn::core
