#include "rwn/core/policy_file.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace rwn::core {
namespace {

std::string_view trim(std::string_view value) {
    const auto space = [](const unsigned char character) {
        return std::isspace(character) != 0;
    };
    while (!value.empty() && space(static_cast<unsigned char>(value.front()))) {
        value.remove_prefix(1);
    }
    while (!value.empty() && space(static_cast<unsigned char>(value.back()))) {
        value.remove_suffix(1);
    }
    return value;
}

std::string parse_quoted(std::string_view value) {
    value = trim(value);
    if (value.size() < 2 || value.front() != '"' || value.back() != '"') {
        throw std::invalid_argument("policy value must be a quoted string");
    }
    value.remove_prefix(1);
    value.remove_suffix(1);
    if (value.empty() || value.find_first_of("\"\\\r\n") != std::string_view::npos ||
        value.find('\0') != std::string_view::npos) {
        throw std::invalid_argument("policy string contains unsupported characters");
    }
    return std::string(value);
}

std::vector<std::string> parse_array(std::string_view value) {
    value = trim(value);
    if (value.size() < 2 || value.front() != '[' || value.back() != ']') {
        throw std::invalid_argument("policy value must be an array");
    }
    value.remove_prefix(1);
    value.remove_suffix(1);
    std::vector<std::string> result;
    while (!trim(value).empty()) {
        value = trim(value);
        const auto comma = value.find(',');
        const auto item = comma == std::string_view::npos ? value : value.substr(0, comma);
        result.push_back(parse_quoted(item));
        if (comma == std::string_view::npos) {
            value = {};
        } else {
            value.remove_prefix(comma + 1);
        }
    }
    if (result.empty()) {
        throw std::invalid_argument("policy array must not be empty");
    }
    return result;
}

}  // namespace

Policy parse_policy(const std::string_view contents) {
    Policy policy;
    std::set<std::string, std::less<>> seen;
    std::size_t offset{};
    while (offset <= contents.size()) {
        const auto end = contents.find('\n', offset);
        auto line = trim(contents.substr(
            offset, end == std::string_view::npos ? contents.size() - offset : end - offset));
        if (!line.empty() && line.front() != '#') {
            const auto equals = line.find('=');
            if (equals == std::string_view::npos) {
                throw std::invalid_argument("policy line is missing '='");
            }
            const auto key = std::string(trim(line.substr(0, equals)));
            const auto value = line.substr(equals + 1);
            if (!seen.insert(key).second) {
                throw std::invalid_argument("duplicate policy field");
            }
            if (key == "principal") {
                policy.principal_id = parse_quoted(value);
            } else if (key == "workspaces") {
                for (auto& workspace : parse_array(value)) {
                    policy.workspaces.insert(std::move(workspace));
                }
            } else if (key == "allow") {
                for (const auto& name : parse_array(value)) {
                    const auto capability = capability_from_string(name);
                    if (!capability.has_value()) {
                        throw std::invalid_argument("unknown policy capability");
                    }
                    policy.allowed.insert(*capability);
                }
            } else {
                throw std::invalid_argument("unknown policy field");
            }
        }
        if (end == std::string_view::npos) {
            break;
        }
        offset = end + 1;
    }
    if (policy.principal_id.empty() || policy.workspaces.empty() || policy.allowed.empty()) {
        throw std::invalid_argument("policy is missing required fields");
    }
    return policy;
}

Policy load_policy_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("policy file could not be opened");
    }
    const std::string contents{
        std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    return parse_policy(contents);
}

}  // namespace rwn::core
