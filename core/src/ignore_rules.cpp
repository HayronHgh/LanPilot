#include "rwn/core/ignore_rules.hpp"

#include "rwn/core/workspace_sync.hpp"

#include <cctype>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <utility>

namespace rwn::core {
namespace {

std::string_view trim(std::string_view value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
        value.remove_prefix(1);
    }
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
        value.remove_suffix(1);
    }
    return value;
}

bool glob_match(std::string_view pattern, std::string_view value) {
    std::size_t pattern_index{};
    std::size_t value_index{};
    std::size_t star_pattern = std::string_view::npos;
    std::size_t star_value{};
    bool recursive_star{};
    while (value_index < value.size()) {
        if (pattern_index < pattern.size() && pattern[pattern_index] == '?'
            && value[value_index] != '/') {
            ++pattern_index;
            ++value_index;
        } else if (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
            recursive_star = pattern_index + 1 < pattern.size() &&
                             pattern[pattern_index + 1] == '*';
            pattern_index += recursive_star ? 2 : 1;
            star_pattern = pattern_index;
            star_value = value_index;
        } else if (pattern_index < pattern.size() &&
                   pattern[pattern_index] == value[value_index]) {
            ++pattern_index;
            ++value_index;
        } else if (star_pattern != std::string_view::npos &&
                   (recursive_star || value[star_value] != '/')) {
            pattern_index = star_pattern;
            value_index = ++star_value;
        } else {
            return false;
        }
    }
    while (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
        ++pattern_index;
    }
    return pattern_index == pattern.size();
}

bool matches_unanchored(std::string_view pattern, std::string_view path) {
    if (glob_match(pattern, path)) {
        return true;
    }
    auto separator = path.find('/');
    while (separator != std::string_view::npos) {
        path.remove_prefix(separator + 1);
        if (glob_match(pattern, path)) {
            return true;
        }
        separator = path.find('/');
    }
    return false;
}

}  // namespace

IgnoreRules IgnoreRules::parse(const std::string_view contents) {
    IgnoreRules result;
    std::size_t offset{};
    while (offset <= contents.size()) {
        const auto end = contents.find('\n', offset);
        auto line = trim(contents.substr(
            offset, end == std::string_view::npos ? contents.size() - offset : end - offset));
        if (!line.empty() && line.front() != '#') {
            if (line.front() == '!' || line.find('\\') != std::string_view::npos ||
                line.find("..") != std::string_view::npos) {
                throw std::invalid_argument("unsupported or unsafe ignore rule");
            }
            Rule rule;
            if (line.front() == '/') {
                rule.anchored = true;
                line.remove_prefix(1);
            }
            if (!line.empty() && line.back() == '/') {
                rule.directory_only = true;
                line.remove_suffix(1);
            }
            if (line.empty()) {
                throw std::invalid_argument("empty ignore rule");
            }
            rule.pattern = std::string(line);
            result.rules_.push_back(std::move(rule));
        }
        if (end == std::string_view::npos) {
            break;
        }
        offset = end + 1;
    }
    return result;
}

IgnoreRules IgnoreRules::load_optional(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        if (!std::filesystem::exists(path)) {
            return {};
        }
        throw std::runtime_error("ignore file could not be opened");
    }
    const std::string contents{
        std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    return parse(contents);
}

void IgnoreRules::merge(IgnoreRules additional) {
    rules_.insert(
        rules_.end(),
        std::make_move_iterator(additional.rules_.begin()),
        std::make_move_iterator(additional.rules_.end()));
}

bool IgnoreRules::ignores(
    const std::string_view canonical_path, const bool directory) const {
    if (!is_canonical_workspace_path(canonical_path)) {
        throw std::invalid_argument("ignore query path is not canonical");
    }
    for (const auto& rule : rules_) {
        if (rule.directory_only && !directory) {
            const auto prefix = rule.pattern + '/';
            if (rule.anchored ? canonical_path.starts_with(prefix)
                              : matches_unanchored(prefix + "**", canonical_path)) {
                return true;
            }
            continue;
        }
        const auto matched = rule.anchored
            ? glob_match(rule.pattern, canonical_path)
            : matches_unanchored(rule.pattern, canonical_path);
        if (matched) {
            return true;
        }
        if (rule.directory_only && directory) {
            const auto prefix = rule.pattern + '/';
            if (rule.anchored ? canonical_path.starts_with(prefix)
                              : matches_unanchored(prefix + "**", canonical_path)) {
                return true;
            }
        }
    }
    return false;
}

}  // namespace rwn::core
