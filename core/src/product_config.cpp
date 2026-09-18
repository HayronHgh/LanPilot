#include "rwn/core/product_config.hpp"

#include "rwn/core/authorization.hpp"
#include "rwn/core/workspace_sync.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <ranges>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>

namespace rwn::core {
namespace {

constexpr std::size_t maximum_config_bytes = 64U * 1024U;

[[nodiscard]] std::string_view trim(std::string_view value) {
    const auto whitespace = [](const unsigned char character) {
        return std::isspace(character) != 0;
    };
    while (!value.empty() && whitespace(
               static_cast<unsigned char>(value.front()))) {
        value.remove_prefix(1);
    }
    while (!value.empty() && whitespace(
               static_cast<unsigned char>(value.back()))) {
        value.remove_suffix(1);
    }
    return value;
}

[[nodiscard]] std::string parse_quoted_value(std::string_view value) {
    value = trim(value);
    if (value.size() < 2 || value.front() != '"' || value.back() != '"') {
        throw std::invalid_argument("runtime config value must be quoted");
    }
    value.remove_prefix(1);
    value.remove_suffix(1);
    if (value.empty() || value.size() > 8192 ||
        value.find_first_of("\"\\\r\n") != std::string_view::npos ||
        value.find('\0') != std::string_view::npos) {
        throw std::invalid_argument("runtime config string is invalid");
    }
    return std::string(value);
}

[[nodiscard]] std::uint64_t unsigned_integer(std::string_view value) {
    value = trim(value);
    std::uint64_t result{};
    const auto parsed = std::from_chars(
        value.data(), value.data() + value.size(), result);
    if (value.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != value.data() + value.size()) {
        throw std::invalid_argument("runtime config integer is invalid");
    }
    return result;
}

[[nodiscard]] bool boolean(std::string_view value) {
    value = trim(value);
    if (value == "true") return true;
    if (value == "false") return false;
    throw std::invalid_argument("runtime config boolean is invalid");
}

[[nodiscard]] std::vector<std::string> string_array(
    std::string_view value) {
    value = trim(value);
    if (value.size() < 2 || value.front() != '[' || value.back() != ']') {
        throw std::invalid_argument("runtime config array is invalid");
    }
    value.remove_prefix(1);
    value.remove_suffix(1);
    std::vector<std::string> result;
    while (!trim(value).empty()) {
        value = trim(value);
        const auto comma = value.find(',');
        result.push_back(parse_quoted_value(
            comma == std::string_view::npos ? value : value.substr(0, comma)));
        if (comma == std::string_view::npos) {
            value = {};
        } else {
            value.remove_prefix(comma + 1);
        }
    }
    if (result.empty() || result.size() > 32) {
        throw std::invalid_argument("runtime config array count is invalid");
    }
    return result;
}

using Fields = std::map<std::string, std::string, std::less<>>;

[[nodiscard]] Fields fields(std::string_view contents) {
    if (contents.empty() || contents.size() > maximum_config_bytes) {
        throw std::invalid_argument("runtime config size is invalid");
    }
    Fields result;
    std::size_t offset{};
    while (offset <= contents.size()) {
        const auto end = contents.find('\n', offset);
        auto line = trim(contents.substr(
            offset, end == std::string_view::npos
                ? contents.size() - offset
                : end - offset));
        if (!line.empty() && line.front() != '#') {
            const auto equals = line.find('=');
            if (equals == std::string_view::npos) {
                throw std::invalid_argument(
                    "runtime config line is missing '='");
            }
            const auto key = std::string(trim(line.substr(0, equals)));
            const auto value = std::string(trim(line.substr(equals + 1)));
            if (key.empty() || value.empty() ||
                !result.emplace(key, value).second) {
                throw std::invalid_argument(
                    "runtime config field is empty or duplicate");
            }
        }
        if (end == std::string_view::npos) break;
        offset = end + 1;
    }
    return result;
}

[[nodiscard]] std::string take(Fields& values, const std::string_view key) {
    const auto found = values.find(key);
    if (found == values.end()) {
        throw std::invalid_argument(
            "runtime config is missing required field " + std::string(key));
    }
    auto value = std::move(found->second);
    values.erase(found);
    return value;
}

[[nodiscard]] std::string take_optional(
    Fields& values, const std::string_view key) {
    const auto found = values.find(key);
    if (found == values.end()) return {};
    auto value = std::move(found->second);
    values.erase(found);
    return value;
}

void require_no_unknown(const Fields& values) {
    if (!values.empty()) {
        throw std::invalid_argument(
            "unknown runtime config field " + values.begin()->first);
    }
}

[[nodiscard]] ProductTransportProvider provider(const std::string_view text) {
    const auto value = parse_quoted_value(text);
    if (value == "msquic") return ProductTransportProvider::msquic;
    if (value == "network-framework") {
        return ProductTransportProvider::network_framework;
    }
    throw std::invalid_argument("runtime transport provider is unsupported");
}

[[nodiscard]] std::filesystem::path absolute_path(
    const std::string_view text, const std::string_view label) {
    auto path = std::filesystem::path(parse_quoted_value(text));
    if (!path.is_absolute()) {
        throw std::invalid_argument(std::string(label) + " must be absolute");
    }
    return path.lexically_normal();
}

[[nodiscard]] bool identifier(const std::string_view value) {
    return !value.empty() && value.size() <= 64 &&
        std::ranges::all_of(value, [](const unsigned char character) {
            return std::isalnum(character) != 0 || character == '-' ||
                character == '_' || character == '.';
        });
}

void require_identifier(
    const std::string_view value, const std::string_view label) {
    if (!identifier(value)) {
        throw std::invalid_argument(std::string(label) + " is invalid");
    }
}

[[nodiscard]] bool hexadecimal(
    const std::string_view value, const std::size_t exact_size = 0) {
    return !value.empty() && (exact_size == 0 || value.size() == exact_size) &&
        value.size() % 2 == 0 &&
        std::ranges::all_of(value, [](const unsigned char character) {
            return std::isdigit(character) != 0 ||
                (character >= 'a' && character <= 'f') ||
                (character >= 'A' && character <= 'F');
        });
}

[[nodiscard]] bool lexically_within(
    const std::filesystem::path& candidate,
    const std::filesystem::path& root) {
    const auto relative = candidate.lexically_normal().lexically_relative(
        root.lexically_normal());
    if (relative.empty() || relative.is_absolute()) return false;
    const auto first = *relative.begin();
    return first != "..";
}

[[nodiscard]] std::uint16_t bounded_u16(
    const std::string_view text, const std::uint16_t minimum,
    const std::uint16_t maximum, const std::string_view label) {
    const auto value = unsigned_integer(text);
    if (value < minimum || value > maximum) {
        throw std::invalid_argument(std::string(label) + " is out of range");
    }
    return static_cast<std::uint16_t>(value);
}

[[nodiscard]] std::string file_contents(
    const std::filesystem::path& path) {
    if (!path.is_absolute()) {
        throw std::invalid_argument("runtime config path must be absolute");
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("runtime config could not be opened");
    std::string result{
        std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    if (result.size() > maximum_config_bytes) {
        throw std::length_error("runtime config exceeds size limit");
    }
    return result;
}

}  // namespace

NodeRuntimeConfig parse_node_runtime_config(const std::string_view contents) {
    auto values = fields(contents);
    NodeRuntimeConfig result;
    result.transport_provider = provider(take(values, "transport_provider"));
    const auto runtime = take_optional(values, "runtime_library");
    if (!runtime.empty()) {
        result.runtime_library = absolute_path(runtime, "runtime_library");
    }
    result.local_identity_hex =
        parse_quoted_value(take(values, "local_identity_hex"));
    result.listen_port = bounded_u16(
        take(values, "listen_port"), 1, 65'535, "listen_port");
    result.transport_settings_file = absolute_path(
        take(values, "transport_settings_file"), "transport_settings_file");
    result.policy_file = absolute_path(
        take(values, "policy_file"), "policy_file");
    result.audit_root = absolute_path(
        take(values, "audit_root"), "audit_root");
    result.audit_journal = std::filesystem::path(
        parse_quoted_value(take(values, "audit_journal"))).lexically_normal();
    const auto pairing_root = take_optional(values, "pairing_root");
    const auto pairing_state = take_optional(values, "pairing_state_file");
    if (pairing_root.empty() != pairing_state.empty()) {
        throw std::invalid_argument(
            "pairing_root and pairing_state_file must be configured together");
    }
    if (!pairing_root.empty()) {
        result.pairing_root = absolute_path(pairing_root, "pairing_root");
        result.pairing_state_file = std::filesystem::path(
            parse_quoted_value(pairing_state)).lexically_normal();
    }
    result.mirror_root = absolute_path(
        take(values, "mirror_root"), "mirror_root");
    result.workspace_state_file = std::filesystem::path(
        parse_quoted_value(take(values, "workspace_state_file")))
        .lexically_normal();
    result.workspace_config_file = absolute_path(
        take(values, "workspace_config_file"), "workspace_config_file");
    result.build_worker_socket = absolute_path(
        take(values, "build_worker_socket"), "build_worker_socket");
    const auto worker_uid = unsigned_integer(take(values, "build_worker_uid"));
    if (worker_uid == 0 ||
        worker_uid > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument("build_worker_uid is out of range");
    }
    result.build_worker_uid = static_cast<std::uint32_t>(worker_uid);
    result.deployment_broker_socket = absolute_path(
        take(values, "deployment_broker_socket"),
        "deployment_broker_socket");
    const auto broker_uid = unsigned_integer(
        take(values, "deployment_broker_uid"));
    if (broker_uid != 0) {
        throw std::invalid_argument("deployment_broker_uid must be root");
    }
    result.deployment_broker_uid = static_cast<std::uint32_t>(broker_uid);
    result.maximum_active_sessions = static_cast<std::size_t>(bounded_u16(
        take(values, "maximum_active_sessions"), 1, 1024,
        "maximum_active_sessions"));
    result.accept_timeout = std::chrono::seconds{bounded_u16(
        take(values, "accept_timeout_seconds"), 1, 300,
        "accept_timeout_seconds")};

    const auto paired_id = take_optional(values, "paired_device_id");
    const auto paired_name = take_optional(values, "paired_device_name");
    const auto paired_fingerprint = take_optional(
        values, "paired_device_certificate_sha256");
    const auto paired_serial = take_optional(
        values, "paired_device_certificate_serial");
    const auto paired_not_before = take_optional(
        values, "paired_device_not_before_unix");
    const auto paired_not_after = take_optional(
        values, "paired_device_not_after_unix");
    const auto paired_revoked = take_optional(
        values, "paired_device_revoked");
    const auto paired_count = static_cast<unsigned int>(!paired_id.empty()) +
        static_cast<unsigned int>(!paired_name.empty()) +
        static_cast<unsigned int>(!paired_fingerprint.empty()) +
        static_cast<unsigned int>(!paired_serial.empty()) +
        static_cast<unsigned int>(!paired_not_before.empty()) +
        static_cast<unsigned int>(!paired_not_after.empty()) +
        static_cast<unsigned int>(!paired_revoked.empty());
    if (paired_count != 0 && paired_count != 7) {
        throw std::invalid_argument(
            "provisioned paired-device fields must be configured together");
    }
    if (paired_count == 7) {
        result.paired_device.id = parse_quoted_value(paired_id);
        result.paired_device.display_name = parse_quoted_value(paired_name);
        result.paired_device.fingerprint = parse_quoted_value(
            paired_fingerprint);
        result.paired_device.certificate = {
            .device_id = result.paired_device.id,
            .fingerprint = result.paired_device.fingerprint,
            .serial = parse_quoted_value(paired_serial),
            .not_before = TimePoint{std::chrono::seconds{
                unsigned_integer(paired_not_before)}},
            .not_after = TimePoint{std::chrono::seconds{
                unsigned_integer(paired_not_after)}},
        };
        result.paired_device.revoked = boolean(paired_revoked);
    }
    require_no_unknown(values);

    if (!hexadecimal(result.local_identity_hex) ||
        result.local_identity_hex.size() > 8192 ||
        (!result.paired_device.id.empty() &&
         (!is_canonical_fingerprint(result.paired_device.fingerprint) ||
          result.paired_device.display_name.size() > 128)) ||
        (result.paired_device.id.empty() && result.pairing_root.empty()) ||
        result.audit_journal.is_absolute() ||
        !is_canonical_workspace_path(result.audit_journal.generic_string()) ||
        (!result.pairing_state_file.empty() &&
         (result.pairing_state_file.is_absolute() ||
          !is_canonical_workspace_path(
              result.pairing_state_file.generic_string()) ||
          lexically_within(result.pairing_root, result.mirror_root))) ||
        result.workspace_state_file.is_absolute() ||
        !is_canonical_workspace_path(
            result.workspace_state_file.generic_string()) ||
        lexically_within(result.workspace_config_file, result.mirror_root) ||
        lexically_within(result.build_worker_socket, result.mirror_root) ||
        lexically_within(result.deployment_broker_socket, result.mirror_root) ||
        (result.transport_provider == ProductTransportProvider::msquic &&
         (result.runtime_library.empty() ||
          result.local_identity_hex.size() != 40)) ||
        (result.transport_provider == ProductTransportProvider::network_framework &&
         !result.runtime_library.empty())) {
        throw std::invalid_argument("node runtime config is inconsistent");
    }
    if (!result.paired_device.id.empty()) {
        require_identifier(result.paired_device.id, "paired_device_id");
        require_identifier(
            result.paired_device.certificate.serial,
            "paired_device_certificate_serial");
        if (result.paired_device.certificate.not_before >=
            result.paired_device.certificate.not_after) {
            throw std::invalid_argument(
                "paired device certificate lifetime is invalid");
        }
    }
    return result;
}

BuildWorkerRuntimeConfig parse_build_worker_runtime_config(
    const std::string_view contents) {
    auto values = fields(contents);
    BuildWorkerRuntimeConfig result;
    result.workspace_root = absolute_path(
        take(values, "workspace_root"), "workspace_root");
    result.workspace_config_file = absolute_path(
        take(values, "workspace_config_file"), "workspace_config_file");
    result.state_root = absolute_path(
        take(values, "state_root"), "state_root");
    result.workspace_state_file = std::filesystem::path(
        parse_quoted_value(take(values, "workspace_state_file")))
        .lexically_normal();
    result.evidence_root = absolute_path(
        take(values, "evidence_root"), "evidence_root");
    result.artifact_root = absolute_path(
        take(values, "artifact_root"), "artifact_root");
    result.socket_path = absolute_path(
        take(values, "socket_path"), "socket_path");
    const auto uid = unsigned_integer(take(values, "allowed_node_uid"));
    if (uid == 0 || uid > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument("allowed_node_uid is out of range");
    }
    result.allowed_node_uid = static_cast<std::uint32_t>(uid);
    result.accept_timeout = std::chrono::seconds{bounded_u16(
        take(values, "accept_timeout_seconds"), 1, 300,
        "accept_timeout_seconds")};
    require_no_unknown(values);
    if (result.workspace_state_file.is_absolute() ||
        !is_canonical_workspace_path(
            result.workspace_state_file.generic_string()) ||
        lexically_within(result.workspace_config_file, result.workspace_root) ||
        lexically_within(result.state_root, result.workspace_root) ||
        lexically_within(result.evidence_root, result.workspace_root) ||
        lexically_within(result.artifact_root, result.workspace_root) ||
        lexically_within(result.socket_path, result.workspace_root)) {
        throw std::invalid_argument(
            "Build Worker runtime boundaries are inconsistent");
    }
    return result;
}

BrokerRuntimeConfig parse_broker_runtime_config(
    const std::string_view contents) {
    auto values = fields(contents);
    BrokerRuntimeConfig result;
    result.artifact_root = absolute_path(
        take(values, "artifact_root"), "artifact_root");
    result.runtime_root = absolute_path(
        take(values, "runtime_root"), "runtime_root");
    result.active_relative_path = std::filesystem::path(
        parse_quoted_value(take(values, "active_relative_path")))
        .lexically_normal();
    result.socket_path = absolute_path(
        take(values, "socket_path"), "socket_path");
    const auto node_uid = unsigned_integer(take(values, "allowed_node_uid"));
    if (node_uid == 0 || node_uid > std::numeric_limits<std::uint32_t>::max())
        throw std::invalid_argument("Broker allowed_node_uid is out of range");
    result.allowed_node_uid = static_cast<std::uint32_t>(node_uid);
    result.stop_command = string_array(take(values, "stop_command"));
    result.start_command = string_array(take(values, "start_command"));
    result.health_command = string_array(take(values, "health_command"));
    result.command_timeout = std::chrono::seconds{bounded_u16(
        take(values, "command_timeout_seconds"), 1, 3600,
        "command_timeout_seconds")};
    result.accept_timeout = std::chrono::seconds{bounded_u16(
        take(values, "accept_timeout_seconds"), 1, 300,
        "accept_timeout_seconds")};
    require_no_unknown(values);
    if (result.active_relative_path.is_absolute() ||
        !is_canonical_workspace_path(
            result.active_relative_path.generic_string()) ||
        lexically_within(result.artifact_root, result.runtime_root) ||
        lexically_within(result.runtime_root, result.artifact_root) ||
        lexically_within(result.socket_path, result.runtime_root) ||
        lexically_within(result.socket_path, result.artifact_root)) {
        throw std::invalid_argument("Broker runtime boundaries are inconsistent");
    }
    for (const auto* command : {
             &result.stop_command, &result.start_command,
             &result.health_command}) {
        if (command->empty() ||
            !std::filesystem::path(command->front()).is_absolute()) {
            throw std::invalid_argument(
                "Broker commands require absolute executables");
        }
    }
    return result;
}

ClientRuntimeConfig parse_client_runtime_config(const std::string_view contents) {
    auto values = fields(contents);
    ClientRuntimeConfig result;
    result.transport_provider = provider(take(values, "transport_provider"));
    result.runtime_library = absolute_path(
        take(values, "runtime_library"), "runtime_library");
    result.local_identity_sha1 =
        parse_quoted_value(take(values, "local_identity_sha1"));
    result.allowed_server_certificate_sha256 =
        parse_quoted_value(take(values, "allowed_server_certificate_sha256"));
    result.host = parse_quoted_value(take(values, "host"));
    result.port = bounded_u16(take(values, "port"), 1, 65'535, "port");
    result.transport_settings_file = absolute_path(
        take(values, "transport_settings_file"), "transport_settings_file");
    result.source_root = absolute_path(
        take(values, "source_root"), "source_root");
    result.workspace_config_file = absolute_path(
        take(values, "workspace_config_file"), "workspace_config_file");
    result.device_id = parse_quoted_value(take(values, "device_id"));
    result.session_id = parse_quoted_value(take(values, "session_id"));
    result.workspace_id = parse_quoted_value(take(values, "workspace_id"));
    result.requested_capabilities = string_array(
        take(values, "requested_capabilities"));
    result.revision = unsigned_integer(take(values, "revision"));
    result.lease_minutes = bounded_u16(
        take(values, "lease_minutes"), 1, 60, "lease_minutes");
    require_no_unknown(values);

    if (result.transport_provider != ProductTransportProvider::msquic ||
        !hexadecimal(result.local_identity_sha1, 40) ||
        !is_canonical_fingerprint(
            result.allowed_server_certificate_sha256) ||
        result.host.size() > 253 ||
        result.revision == 0 ||
        result.host.find_first_of("\r\n\0") != std::string::npos) {
        throw std::invalid_argument("client runtime config is inconsistent");
    }
    require_identifier(result.device_id, "device_id");
    require_identifier(result.session_id, "session_id");
    require_identifier(result.workspace_id, "workspace_id");
    std::set<std::string, std::less<>> unique;
    for (const auto& capability : result.requested_capabilities) {
        if (!capability_from_string(capability).has_value() ||
            !unique.insert(capability).second) {
            throw std::invalid_argument(
                "client capability is unknown or duplicated");
        }
    }
    return result;
}

NodeRuntimeConfig load_node_runtime_config(
    const std::filesystem::path& path) {
    return parse_node_runtime_config(file_contents(path));
}

ClientRuntimeConfig load_client_runtime_config(
    const std::filesystem::path& path) {
    return parse_client_runtime_config(file_contents(path));
}

BuildWorkerRuntimeConfig load_build_worker_runtime_config(
    const std::filesystem::path& path) {
    return parse_build_worker_runtime_config(file_contents(path));
}

BrokerRuntimeConfig load_broker_runtime_config(
    const std::filesystem::path& path) {
    return parse_broker_runtime_config(file_contents(path));
}

}  // namespace rwn::core
