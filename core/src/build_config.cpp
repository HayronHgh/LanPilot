#include "rwn/core/build_config.hpp"
#include "rwn/core/workspace_scope.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <fstream>
#include <limits>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

namespace rwn::core {
namespace {

std::string_view trim(std::string_view value) {
    while (!value.empty() &&
           std::isspace(static_cast<unsigned char>(value.front())) != 0) {
        value.remove_prefix(1);
    }
    while (!value.empty() &&
           std::isspace(static_cast<unsigned char>(value.back())) != 0) {
        value.remove_suffix(1);
    }
    return value;
}

std::string_view without_comment(const std::string_view line) {
    bool quoted{};
    for (std::size_t index = 0; index < line.size(); ++index) {
        if (line[index] == '"' && (index == 0 || line[index - 1] != '\\')) {
            quoted = !quoted;
        } else if (line[index] == '#' && !quoted) {
            return line.substr(0, index);
        }
    }
    if (quoted) {
        throw std::invalid_argument("unterminated config string");
    }
    return line;
}

std::string parse_string(const std::string_view value) {
    const auto input = trim(value);
    if (input.size() < 2 || input.front() != '"' || input.back() != '"') {
        throw std::invalid_argument("config value must be a quoted string");
    }
    const auto body = input.substr(1, input.size() - 2);
    if (body.empty() || body.find_first_of("\\\r\n\0") != std::string_view::npos ||
        body.find('"') != std::string_view::npos) {
        throw std::invalid_argument("config string is empty or unsupported");
    }
    return std::string(body);
}

std::vector<std::string> parse_string_array(const std::string_view value) {
    auto input = trim(value);
    if (input.size() < 2 || input.front() != '[' || input.back() != ']') {
        throw std::invalid_argument("config value must be a string array");
    }
    input = trim(input.substr(1, input.size() - 2));
    std::vector<std::string> result;
    while (!input.empty()) {
        if (input.front() != '"') {
            throw std::invalid_argument("config array item must be a string");
        }
        const auto close = input.find('"', 1);
        if (close == std::string_view::npos) {
            throw std::invalid_argument("unterminated config array string");
        }
        result.push_back(parse_string(input.substr(0, close + 1)));
        input = trim(input.substr(close + 1));
        if (input.empty()) {
            break;
        }
        if (input.front() != ',') {
            throw std::invalid_argument("config array items must be comma separated");
        }
        input = trim(input.substr(1));
        if (input.empty()) {
            throw std::invalid_argument("config array has a trailing comma");
        }
    }
    if (result.empty()) {
        throw std::invalid_argument("config array must not be empty");
    }
    return result;
}

std::uint64_t parse_positive_integer(const std::string_view value) {
    const auto input = trim(value);
    std::uint64_t result{};
    const auto parsed = std::from_chars(
        input.data(), input.data() + input.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != input.data() + input.size() ||
        result == 0) {
        throw std::invalid_argument("config value must be a positive integer");
    }
    return result;
}

bool parse_bool(const std::string_view value) {
    const auto input = trim(value);
    if (input == "true") {
        return true;
    }
    if (input == "false") {
        return false;
    }
    throw std::invalid_argument("config value must be boolean");
}

bool valid_identifier(const std::string_view value) {
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

bool portable_absolute_executable(const std::string_view value) {
    return value.starts_with('/') ||
           (value.size() > 3 && std::isalpha(
                                  static_cast<unsigned char>(value.front())) != 0 &&
            value[1] == ':' && value[2] == '/');
}

void require_safe_relative_pattern(const std::string_view value) {
    if (value.empty() || value.front() == '/' || value.front() == '\\' ||
        value.find('\\') != std::string_view::npos ||
        value.find('\0') != std::string_view::npos) {
        throw std::invalid_argument("artifact pattern is not a canonical relative path");
    }
    std::size_t start{};
    while (start <= value.size()) {
        const auto slash = value.find('/', start);
        const auto component = value.substr(
            start, slash == std::string_view::npos ? value.size() - start
                                                   : slash - start);
        if (component.empty() || component == "." || component == "..") {
            throw std::invalid_argument("artifact pattern escapes workspace");
        }
        if (slash == std::string_view::npos) {
            break;
        }
        start = slash + 1;
    }
}

struct Parser {
    RemoteWorkspaceConfig config;
    std::string section;
    std::set<std::string, std::less<>> seen;

    BuildProfile& target(std::string_view name) {
        if (!valid_identifier(name)) {
            throw std::invalid_argument("invalid target profile name");
        }
        auto& profile = config.profiles[std::string(name)];
        profile.name = name;
        return profile;
    }

    void set_section(const std::string_view value) {
        if (value == "workspace" || value == "sync") {
            section = value;
            return;
        }
        constexpr std::string_view prefix = "target.";
        if (!value.starts_with(prefix)) {
            throw std::invalid_argument("unknown config section");
        }
        auto remainder = value.substr(prefix.size());
        constexpr std::string_view suffix = ".artifacts";
        if (remainder.ends_with(suffix)) {
            remainder.remove_suffix(suffix.size());
        }
        static_cast<void>(target(remainder));
        section = value;
    }

    void assign(const std::string_view key, const std::string_view value) {
        const auto identity = section + "." + std::string(key);
        if (section.empty() || !seen.insert(identity).second) {
            throw std::invalid_argument("config key is outside a section or duplicated");
        }
        if (section == "workspace") {
            if (key == "id") config.workspace_id = parse_string(value);
            else if (key == "name") config.workspace_name = parse_string(value);
            else if (key == "source") config.source = parse_string(value);
            else if (key == "mirror") config.mirror = parse_string(value);
            else throw std::invalid_argument("unknown workspace config key");
            return;
        }
        if (section == "sync") {
            if (key == "direction") config.sync_direction = parse_string(value);
            else if (key == "exclude") config.sync_excludes = parse_string_array(value);
            else throw std::invalid_argument("unknown sync config key");
            return;
        }
        constexpr std::string_view prefix = "target.";
        auto profile_name = std::string_view(section).substr(prefix.size());
        constexpr std::string_view suffix = ".artifacts";
        const auto artifacts = profile_name.ends_with(suffix);
        if (artifacts) profile_name.remove_suffix(suffix.size());
        auto& profile = target(profile_name);
        if (!artifacts) {
            if (key == "node") profile.node = parse_string(value);
            else if (key == "working_dir") profile.command.working_directory = parse_string(value);
            else if (key == "command") profile.command.argv = parse_string_array(value);
            else if (key == "timeout_seconds") {
                const auto seconds = parse_positive_integer(value);
                if (seconds > 86400U) throw std::invalid_argument("build timeout exceeds one day");
                profile.command.timeout = std::chrono::seconds(seconds);
            } else if (key == "environment_allowlist") {
                const auto names = parse_string_array(value);
                if (!std::ranges::all_of(names, valid_environment_name)) {
                    throw std::invalid_argument("invalid environment allowlist entry");
                }
                profile.environment_allowlist.insert(names.begin(), names.end());
                if (profile.environment_allowlist.size() != names.size()) {
                    throw std::invalid_argument("duplicate environment allowlist entry");
                }
            } else throw std::invalid_argument("unknown target config key");
        } else {
            if (key == "paths") profile.artifacts.paths = parse_string_array(value);
            else if (key == "platform") profile.artifacts.platform = parse_string(value);
            else if (key == "architecture") profile.artifacts.architecture = parse_string(value);
            else if (key == "archive_app_bundles") profile.artifacts.archive_app_bundles = parse_bool(value);
            else throw std::invalid_argument("unknown artifact config key");
        }
    }

    RemoteWorkspaceConfig finish() {
        if (!valid_identifier(config.workspace_id) || config.workspace_name.empty() ||
            config.source != "windows" || config.mirror != "macos" ||
            config.sync_direction != "one-way" || config.profiles.empty()) {
            throw std::invalid_argument("remote workspace config is incomplete");
        }
        for (const auto& exclude : config.sync_excludes) {
            require_safe_relative_pattern(exclude);
        }
        for (const auto& [_, profile] : config.profiles) {
            if (profile.node.empty() || profile.command.argv.empty() ||
                profile.command.working_directory.empty() ||
                profile.command.timeout <= std::chrono::seconds::zero() ||
                profile.artifacts.paths.empty() || profile.artifacts.platform.empty() ||
                profile.artifacts.architecture.empty()) {
                throw std::invalid_argument("build target config is incomplete");
            }
            if (!portable_absolute_executable(profile.command.argv.front())) {
                throw std::invalid_argument(
                    "build profile executable must be an absolute path");
            }
            const std::filesystem::path working(profile.command.working_directory);
            if (working.is_absolute()) {
                throw std::invalid_argument("build working directory must be relative");
            }
            for (const auto& component : working) {
                if (component == "..") {
                    throw std::invalid_argument("build working directory escapes workspace");
                }
            }
            for (const auto& pattern : profile.artifacts.paths) {
                require_safe_relative_pattern(pattern);
            }
        }
        return std::move(config);
    }
};

}  // namespace

namespace {

[[nodiscard]] bool glob_matches(
    const std::string_view pattern, const std::string_view value) {
    std::vector<bool> previous(value.size() + 1);
    std::vector<bool> current(value.size() + 1);
    previous[0] = true;
    for (const auto token : pattern) {
        std::ranges::fill(current, false);
        if (token == '*') current[0] = previous[0];
        for (std::size_t index = 1; index <= value.size(); ++index) {
            if (token == '*') {
                current[index] = previous[index] ||
                    (value[index - 1] != '/' && current[index - 1]);
            } else if (token == '?') {
                current[index] = value[index - 1] != '/' && previous[index - 1];
            } else if (token == value[index - 1]) {
                current[index] = previous[index - 1];
            }
        }
        previous.swap(current);
    }
    return previous[value.size()];
}

[[nodiscard]] bool safe_artifact_pattern(const std::string_view pattern) {
    if (pattern.empty() || pattern.size() > 4096 || pattern.front() == '/' ||
        pattern.back() == '/' || pattern.find('\\') != std::string_view::npos ||
        pattern.find('\0') != std::string_view::npos) return false;
    std::size_t start{};
    while (start < pattern.size()) {
        const auto end = pattern.find('/', start);
        const auto part = pattern.substr(
            start, end == std::string_view::npos
                ? pattern.size() - start : end - start);
        if (part.empty() || part == "." || part == "..") return false;
        start = end == std::string_view::npos ? pattern.size() : end + 1;
    }
    return true;
}

}  // namespace

const BuildProfile& RemoteWorkspaceConfig::profile(
    const std::string_view name) const {
    const auto iterator = profiles.find(name);
    if (iterator == profiles.end()) {
        throw std::out_of_range("unknown build profile");
    }
    return iterator->second;
}

BuildRequest RemoteWorkspaceConfig::make_build_request(
    std::string build_id, const std::uint64_t pinned_revision,
    const std::string_view profile_name,
    std::map<std::string, std::string, std::less<>> environment) const {
    const auto& selected = profile(profile_name);
    if (!valid_identifier(build_id) || pinned_revision == 0) {
        throw std::invalid_argument("build request identity is invalid");
    }
    auto command = selected.command;
    command.environment = std::move(environment);
    validate_command(command, selected.environment_allowlist);
    return {
        .id = std::move(build_id),
        .workspace_id = workspace_id,
        .pinned_revision = pinned_revision,
        .profile = selected.name,
        .command = std::move(command),
    };
}

RemoteWorkspaceConfig parse_remote_workspace_config(const std::string_view text) {
    Parser parser;
    std::istringstream input{std::string(text)};
    std::string line;
    while (std::getline(input, line)) {
        auto current = trim(without_comment(line));
        if (current.empty()) {
            continue;
        }
        if (current.front() == '[' && current.back() == ']') {
            parser.set_section(trim(current.substr(1, current.size() - 2)));
            continue;
        }
        const auto equals = current.find('=');
        if (equals == std::string_view::npos) {
            throw std::invalid_argument("invalid config assignment");
        }
        const auto key = trim(current.substr(0, equals));
        if (!valid_identifier(key)) {
            throw std::invalid_argument("invalid config key");
        }
        parser.assign(key, trim(current.substr(equals + 1)));
    }
    return parser.finish();
}

RemoteWorkspaceConfig load_remote_workspace_config(
    const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("remote workspace config could not be opened");
    }
    const std::string text{
        std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    return parse_remote_workspace_config(text);
}

std::vector<std::filesystem::path> discover_build_artifacts(
    const std::filesystem::path& workspace_root,
    const BuildProfile& profile,
    const std::size_t maximum_artifacts) {
    if (profile.artifacts.paths.empty() || maximum_artifacts == 0 ||
        maximum_artifacts > 1024 ||
        !std::ranges::all_of(
            profile.artifacts.paths, safe_artifact_pattern)) {
        throw std::invalid_argument("artifact discovery options are invalid");
    }
    const WorkspaceScope scope(workspace_root);
    if (!std::filesystem::is_directory(scope.root()))
        throw std::invalid_argument("artifact workspace root is not a directory");
    std::vector<std::filesystem::path> result;
    std::size_t scanned{};
    for (auto iterator = std::filesystem::recursive_directory_iterator(
             scope.root(), std::filesystem::directory_options::none);
         iterator != std::filesystem::recursive_directory_iterator{};
         ++iterator) {
        if (++scanned > 1'000'000)
            throw std::length_error("artifact discovery scan exceeds limit");
        const auto status = iterator->symlink_status();
        const auto relative = std::filesystem::relative(
            iterator->path(), scope.root()).generic_string();
        const auto matched = std::ranges::any_of(
            profile.artifacts.paths,
            [&](const auto& pattern) { return glob_matches(pattern, relative); });
        if (std::filesystem::is_symlink(status)) {
            if (iterator->is_directory()) iterator.disable_recursion_pending();
            if (matched)
                throw std::invalid_argument("artifact pattern matched a symlink");
            continue;
        }
        const auto app_bundle = iterator->is_directory() &&
            iterator->path().extension() == ".app";
        if (app_bundle) iterator.disable_recursion_pending();
        if (!matched) continue;
        if (!iterator->is_regular_file() && !app_bundle)
            throw std::invalid_argument(
                "artifact pattern matched an unsupported filesystem entry");
        result.emplace_back(relative);
        if (result.size() > maximum_artifacts)
            throw std::length_error("artifact discovery count exceeds limit");
    }
    std::ranges::sort(result);
    const auto duplicate = std::ranges::adjacent_find(result);
    if (duplicate != result.end())
        throw std::invalid_argument("artifact discovery produced duplicates");
    if (result.empty())
        throw std::runtime_error("successful build produced no configured artifacts");
    return result;
}

}  // namespace rwn::core
