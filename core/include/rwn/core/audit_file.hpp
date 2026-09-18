#pragma once

#include "rwn/core/audit.hpp"
#include "rwn/core/file_transfer.hpp"
#include "rwn/core/workspace_scope.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace rwn::core {

class DurableAuditFileSink final : public AuditSink {
public:
    DurableAuditFileSink(
        std::filesystem::path audit_root,
        std::filesystem::path journal_relative_path,
        DurableFileSystem& filesystem);

    void append_line(std::string_view canonical_json_line) override;
    [[nodiscard]] const std::filesystem::path& journal_path() const {
        return journal_path_;
    }

private:
    WorkspaceScope scope_;
    std::filesystem::path journal_path_;
    DurableFileSystem& filesystem_;
};

struct AuditJournalQuery {
    std::string field;
    std::string identifier;
    std::size_t limit{100};
};

[[nodiscard]] std::vector<std::string> query_audit_journal(
    const std::filesystem::path& journal,
    const AuditJournalQuery& query);

}  // namespace rwn::core
