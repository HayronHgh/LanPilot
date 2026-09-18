#pragma once

#include "rwn/core/identity.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace rwn::core {

enum class ProductTransportProvider { msquic, network_framework };

struct NodeRuntimeConfig {
    ProductTransportProvider transport_provider{
        ProductTransportProvider::network_framework};
    std::filesystem::path runtime_library;
    std::string local_identity_hex;
    std::uint16_t listen_port{};
    std::filesystem::path transport_settings_file;
    std::filesystem::path policy_file;
    std::filesystem::path audit_root;
    std::filesystem::path audit_journal;
    std::filesystem::path pairing_root;
    std::filesystem::path pairing_state_file;
    std::filesystem::path mirror_root;
    std::filesystem::path workspace_state_file;
    std::filesystem::path workspace_config_file;
    std::filesystem::path build_worker_socket;
    std::uint32_t build_worker_uid{};
    std::filesystem::path deployment_broker_socket;
    std::uint32_t deployment_broker_uid{};
    PairedDevice paired_device;
    std::size_t maximum_active_sessions{64};
    std::chrono::seconds accept_timeout{120};
};

struct BuildWorkerRuntimeConfig {
    std::filesystem::path workspace_root;
    std::filesystem::path workspace_config_file;
    std::filesystem::path state_root;
    std::filesystem::path workspace_state_file;
    std::filesystem::path evidence_root;
    std::filesystem::path artifact_root;
    std::filesystem::path socket_path;
    std::uint32_t allowed_node_uid{};
    std::chrono::seconds accept_timeout{120};
};

struct ClientRuntimeConfig {
    ProductTransportProvider transport_provider{
        ProductTransportProvider::msquic};
    std::filesystem::path runtime_library;
    std::string local_identity_sha1;
    std::string allowed_server_certificate_sha256;
    std::string host;
    std::uint16_t port{};
    std::filesystem::path transport_settings_file;
    std::filesystem::path source_root;
    std::filesystem::path workspace_config_file;
    std::string device_id;
    std::string session_id;
    std::string workspace_id;
    std::vector<std::string> requested_capabilities;
    std::uint64_t revision{};
    std::uint16_t lease_minutes{15};
};

struct BrokerRuntimeConfig {
    std::filesystem::path artifact_root;
    std::filesystem::path runtime_root;
    std::filesystem::path active_relative_path;
    std::filesystem::path socket_path;
    std::uint32_t allowed_node_uid{};
    std::vector<std::string> stop_command;
    std::vector<std::string> start_command;
    std::vector<std::string> health_command;
    std::chrono::seconds command_timeout{30};
    std::chrono::seconds accept_timeout{120};
};

[[nodiscard]] NodeRuntimeConfig parse_node_runtime_config(
    std::string_view contents);
[[nodiscard]] ClientRuntimeConfig parse_client_runtime_config(
    std::string_view contents);
[[nodiscard]] BuildWorkerRuntimeConfig parse_build_worker_runtime_config(
    std::string_view contents);
[[nodiscard]] BrokerRuntimeConfig parse_broker_runtime_config(
    std::string_view contents);
[[nodiscard]] NodeRuntimeConfig load_node_runtime_config(
    const std::filesystem::path& path);
[[nodiscard]] ClientRuntimeConfig load_client_runtime_config(
    const std::filesystem::path& path);
[[nodiscard]] BuildWorkerRuntimeConfig load_build_worker_runtime_config(
    const std::filesystem::path& path);
[[nodiscard]] BrokerRuntimeConfig load_broker_runtime_config(
    const std::filesystem::path& path);

}  // namespace rwn::core
