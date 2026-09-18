#include "rwn/core/audit.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace rwn::core {
namespace {

bool identifier_or_empty(const std::string_view value) {
    return value.size() <= 128 &&
           std::ranges::all_of(value, [](const unsigned char character) {
               return std::isalnum(character) != 0 || character == '-' ||
                      character == '_' || character == '.';
           });
}

bool deployment_action(const AuditAction action) {
    return action == AuditAction::deployment_started ||
           action == AuditAction::deployment_active ||
           action == AuditAction::deployment_rolled_back ||
           action == AuditAction::deployment_failed;
}

bool session_action(const AuditAction action) {
    return action == AuditAction::session_authenticated ||
           action == AuditAction::session_opened ||
           action == AuditAction::session_renewed ||
           action == AuditAction::session_closed;
}

bool artifact_action(const AuditAction action) {
    return action == AuditAction::artifact_published ||
           action == AuditAction::artifact_downloaded;
}

bool workspace_action(const AuditAction action) {
    return action == AuditAction::workspace_sync_started ||
           action == AuditAction::workspace_sync_committed ||
           action == AuditAction::workspace_sync_failed;
}

bool build_action(const AuditAction action) {
    return action == AuditAction::build_submitted ||
           action == AuditAction::build_completed;
}

std::string json(const std::string_view value) {
    std::string result{"\""};
    for (const auto character : value) {
        switch (character) {
            case '\\': result += "\\\\"; break;
            case '"': result += "\\\""; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (static_cast<unsigned char>(character) < 0x20U) {
                    throw std::invalid_argument("audit field contains control data");
                }
                result.push_back(character);
        }
    }
    result.push_back('"');
    return result;
}

std::string event_json_line(const AuditEvent& event) {
    std::ostringstream output;
    const auto milliseconds =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            event.occurred_at.time_since_epoch()).count();
    output << "{\"occurred_at_ms\":" << milliseconds
           << ",\"principal_id\":" << json(event.principal_id)
           << ",\"device_id\":" << json(event.device_id)
           << ",\"session_id\":" << json(event.session_id)
           << ",\"workspace_id\":" << json(event.workspace_id)
           << ",\"build_id\":" << json(event.build_id)
           << ",\"artifact_id\":" << json(event.artifact_id)
           << ",\"artifact_sha256\":" << json(event.artifact_sha256)
           << ",\"source_revision\":" << event.source_revision
           << ",\"deployment_id\":" << json(event.deployment_id)
           << ",\"process_role\":" << json(event.process_role)
           << ",\"reason_code\":" << json(event.reason_code)
           << ",\"agent_job_id\":" << json(event.agent_job_id)
           << ",\"tool_name\":" << json(event.tool_name)
           << ",\"evidence_id\":" << json(event.evidence_id)
           << ",\"action\":" << json(to_string(event.action))
           << ",\"result\":" << json(to_string(event.result))
           << "}\n";
    return output.str();
}

}  // namespace

std::string_view to_string(const AuditAction action) {
    switch (action) {
        case AuditAction::pairing_started: return "pairing.started";
        case AuditAction::pairing_confirmed: return "pairing.confirmed";
        case AuditAction::session_authenticated: return "session.authenticated";
        case AuditAction::session_opened: return "session.opened";
        case AuditAction::session_renewed: return "session.renewed";
        case AuditAction::session_closed: return "session.closed";
        case AuditAction::device_revoked: return "device.revoked";
        case AuditAction::workspace_sync_started: return "workspace.sync_started";
        case AuditAction::workspace_sync_committed: return "workspace.sync_committed";
        case AuditAction::workspace_sync_failed: return "workspace.sync_failed";
        case AuditAction::build_submitted: return "build.submitted";
        case AuditAction::build_completed: return "build.completed";
        case AuditAction::artifact_published: return "artifact.published";
        case AuditAction::artifact_downloaded: return "artifact.downloaded";
        case AuditAction::deployment_started: return "deployment.started";
        case AuditAction::deployment_active: return "deployment.active";
        case AuditAction::deployment_rolled_back: return "deployment.rolled_back";
        case AuditAction::deployment_failed: return "deployment.failed";
        case AuditAction::scope_access_denied: return "scope.access_denied";
        case AuditAction::audit_exported: return "audit.exported";
        case AuditAction::agent_job_started: return "agent.job_started";
        case AuditAction::agent_review_requested: return "agent.review_requested";
        case AuditAction::agent_review_granted: return "agent.review_granted";
        case AuditAction::agent_tool_completed: return "agent.tool_completed";
        case AuditAction::agent_job_completed: return "agent.job_completed";
    }
    return "unknown";
}

std::string_view to_string(const AuditResult result) {
    switch (result) {
        case AuditResult::allowed: return "allowed";
        case AuditResult::denied: return "denied";
        case AuditResult::failed: return "failed";
    }
    return "unknown";
}

AuditLog::AuditLog(AuditRetentionPolicy retention, AuditSink* sink)
    : retention_(retention), sink_(sink) {
    if (retention_.maximum_age <= std::chrono::hours::zero() ||
        retention_.maximum_events == 0) {
        throw std::invalid_argument("audit retention policy is invalid");
    }
}

void AuditLog::append(AuditEvent event) {
    if (event.occurred_at == TimePoint{} || event.principal_id.empty() ||
        event.device_id.empty() ||
        !identifier_or_empty(event.principal_id) ||
        !identifier_or_empty(event.device_id) ||
        !identifier_or_empty(event.session_id) ||
        !identifier_or_empty(event.workspace_id) ||
        !identifier_or_empty(event.build_id) ||
        !identifier_or_empty(event.artifact_id) ||
        !identifier_or_empty(event.deployment_id) ||
        !identifier_or_empty(event.process_role) ||
        !identifier_or_empty(event.reason_code) ||
        !identifier_or_empty(event.agent_job_id) ||
        !identifier_or_empty(event.tool_name) ||
        !identifier_or_empty(event.evidence_id) ||
        (session_action(event.action) && event.session_id.empty()) ||
        (artifact_action(event.action) &&
         (event.session_id.empty() || event.workspace_id.empty() ||
          event.build_id.empty() || event.artifact_id.empty() ||
          event.artifact_sha256.empty() || event.source_revision == 0)) ||
        (deployment_action(event.action) &&
         (event.session_id.empty() || event.workspace_id.empty() ||
          event.build_id.empty() || event.artifact_id.empty() ||
          event.artifact_sha256.empty() || event.source_revision == 0 ||
          event.deployment_id.empty())) ||
        (event.action == AuditAction::scope_access_denied &&
         (event.workspace_id.empty() || event.process_role.empty() ||
          event.reason_code.empty())) ||
        (workspace_action(event.action) &&
         (event.session_id.empty() || event.workspace_id.empty() ||
          event.source_revision == 0 || event.reason_code.empty())) ||
        (build_action(event.action) &&
         (event.session_id.empty() || event.workspace_id.empty() ||
          event.build_id.empty() || event.source_revision == 0 ||
          event.process_role != "build_worker" || event.reason_code.empty() ||
          (event.action == AuditAction::build_completed &&
           event.evidence_id.empty()))) ||
        ((event.action == AuditAction::agent_job_started ||
          event.action == AuditAction::agent_review_requested ||
          event.action == AuditAction::agent_review_granted ||
          event.action == AuditAction::agent_tool_completed ||
          event.action == AuditAction::agent_job_completed) &&
         (event.session_id.empty() || event.workspace_id.empty() ||
          event.agent_job_id.empty())) ||
        (event.action == AuditAction::agent_tool_completed &&
         (event.tool_name.empty() || event.evidence_id.empty()))) {
        throw std::invalid_argument("audit event is missing required metadata");
    }
    if (!event.artifact_sha256.empty() &&
        (event.artifact_sha256.size() != 64 ||
         !std::ranges::all_of(event.artifact_sha256,
             [](const unsigned char character) {
                 return (character >= '0' && character <= '9') ||
                        (character >= 'a' && character <= 'f');
             }))) {
        throw std::invalid_argument("audit artifact hash is invalid");
    }
    if (!events_.empty() && event.occurred_at < events_.back().occurred_at) {
        throw std::invalid_argument("audit events must be append-time ordered");
    }
    if (sink_ != nullptr) {
        sink_->append_line(event_json_line(event));
    }
    events_.push_back(std::move(event));
    if (events_.size() > retention_.maximum_events) {
        events_.erase(
            events_.begin(), events_.begin() +
                static_cast<std::ptrdiff_t>(events_.size() -
                                            retention_.maximum_events));
    }
}

std::vector<AuditEvent> AuditLog::for_session(const std::string_view session_id) const {
    std::vector<AuditEvent> result;
    std::ranges::copy_if(events_, std::back_inserter(result), [session_id](const AuditEvent& event) {
        return event.session_id == session_id;
    });
    return result;
}

std::vector<AuditEvent> AuditLog::for_artifact(
    const std::string_view artifact_id) const {
    return query({.artifact_id = std::string(artifact_id)});
}

std::vector<AuditEvent> AuditLog::query(const AuditQuery& filter) const {
    if (filter.from > filter.to || filter.limit == 0 || filter.limit > 10000) {
        throw std::invalid_argument("audit query is invalid or exceeds limit");
    }
    std::vector<AuditEvent> result;
    result.reserve(std::min(filter.limit, events_.size()));
    for (const auto& event : events_) {
        if (event.occurred_at < filter.from || event.occurred_at > filter.to ||
            (!filter.principal_id.empty() &&
             event.principal_id != filter.principal_id) ||
            (!filter.workspace_id.empty() &&
             event.workspace_id != filter.workspace_id) ||
            (!filter.build_id.empty() && event.build_id != filter.build_id) ||
            (!filter.artifact_id.empty() &&
             event.artifact_id != filter.artifact_id) ||
            (!filter.deployment_id.empty() &&
             event.deployment_id != filter.deployment_id) ||
            (!filter.agent_job_id.empty() &&
             event.agent_job_id != filter.agent_job_id)) {
            continue;
        }
        result.push_back(event);
        if (result.size() == filter.limit) break;
    }
    return result;
}

std::string AuditLog::export_json_lines(const AuditQuery& filter) const {
    std::ostringstream output;
    for (const auto& event : query(filter)) {
        output << event_json_line(event);
    }
    return output.str();
}

void AuditLog::enforce_retention(const TimePoint now) {
    const auto cutoff = now - retention_.maximum_age;
    const auto first = std::ranges::find_if(
        events_, [cutoff](const AuditEvent& event) {
            return event.occurred_at >= cutoff;
        });
    events_.erase(events_.begin(), first);
}

}  // namespace rwn::core
