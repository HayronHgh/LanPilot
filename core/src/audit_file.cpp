#include "rwn/core/audit_file.hpp"

#include <fstream>
#include <algorithm>
#include <cctype>
#include <deque>
#include <ranges>
#include <stdexcept>
#include <utility>

namespace rwn::core {

DurableAuditFileSink::DurableAuditFileSink(
    std::filesystem::path audit_root,
    std::filesystem::path journal_relative_path,
    DurableFileSystem& filesystem)
    : scope_(std::move(audit_root)),
      journal_path_(scope_.resolve(journal_relative_path)),
      filesystem_(filesystem) {
    std::filesystem::create_directories(journal_path_.parent_path());
    if (std::filesystem::exists(journal_path_) &&
        !std::filesystem::is_regular_file(journal_path_)) {
        throw std::invalid_argument("audit journal is not a regular file");
    }
    if (!std::filesystem::exists(journal_path_)) {
        std::ofstream create(journal_path_, std::ios::binary);
        if (!create) {
            throw std::runtime_error("audit journal could not be created");
        }
        create.close();
        filesystem_.flush_file(journal_path_);
    }
}

void DurableAuditFileSink::append_line(
    const std::string_view canonical_json_line) {
    if (canonical_json_line.empty() || canonical_json_line.back() != '\n' ||
        canonical_json_line.find('\r') != std::string_view::npos ||
        canonical_json_line.find('\n') != canonical_json_line.size() - 1) {
        throw std::invalid_argument("audit sink requires one canonical JSON line");
    }
    std::ofstream output(
        journal_path_, std::ios::binary | std::ios::app);
    if (!output) {
        throw std::runtime_error("audit journal could not be opened");
    }
    output.write(
        canonical_json_line.data(),
        static_cast<std::streamsize>(canonical_json_line.size()));
    output.flush();
    if (!output) {
        throw std::runtime_error("audit journal append failed");
    }
    output.close();
    filesystem_.flush_file(journal_path_);
}

std::vector<std::string> query_audit_journal(
    const std::filesystem::path& journal,
    const AuditJournalQuery& query) {
    constexpr std::uintmax_t maximum_journal_bytes = 256U * 1024U * 1024U;
    constexpr std::size_t maximum_line_bytes = 64U * 1024U;
    const auto valid_field = query.field == "session_id" ||
        query.field == "workspace_id" || query.field == "build_id" ||
        query.field == "artifact_id" || query.field == "deployment_id";
    const auto valid_identifier = !query.identifier.empty() &&
        query.identifier.size() <= 64 &&
        std::all_of(query.identifier.begin(), query.identifier.end(),
                    [](const unsigned char value) {
            return std::isalnum(value) != 0 || value == '-' || value == '_' ||
                   value == '.';
        });
    if (!valid_field || !valid_identifier || query.limit == 0 ||
        query.limit > 1000 || !std::filesystem::is_regular_file(journal) ||
        std::filesystem::is_symlink(journal) ||
        std::filesystem::file_size(journal) > maximum_journal_bytes) {
        throw std::invalid_argument("audit journal query is invalid");
    }
    std::ifstream input(journal, std::ios::binary);
    if (!input) throw std::runtime_error("audit journal could not be opened");
    const auto needle = "\"" + query.field + "\":\"" +
        query.identifier + "\"";
    std::deque<std::string> matches;
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line.size() > maximum_line_bytes ||
            line.front() != '{' || line.back() != '}') {
            throw std::invalid_argument("audit journal line is invalid");
        }
        if (line.find(needle) == std::string::npos) continue;
        if (matches.size() == query.limit) matches.pop_front();
        matches.push_back(line);
    }
    if (input.bad()) throw std::runtime_error("audit journal read failed");
    return {matches.begin(), matches.end()};
}

}  // namespace rwn::core
