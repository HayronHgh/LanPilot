#include "rwn/client/session_client.hpp"
#include "rwn/client/build_client.hpp"
#include "rwn/client/artifact_client.hpp"
#include "rwn/client/deployment_client.hpp"
#include "rwn/client/workspace_client.hpp"
#include "rwn/core/authorization.hpp"
#include "rwn/core/build_config.hpp"
#include "rwn/core/ignore_rules.hpp"
#include "rwn/core/product_config.hpp"
#include "rwn/core/session.hpp"
#include "rwn/core/workspace_manifest.hpp"
#include "rwn/transport/resilient_transport.hpp"

#if defined(RWN_HAS_MSQUIC)
#include "rwn/platform/windows/command_executor.hpp"
#include "rwn/platform/windows/durable_filesystem.hpp"
#include "rwn/transport/msquic_client.hpp"
#include "rwn/transport/msquic_server.hpp"
#endif

#include <charconv>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <ranges>
#include <set>
#include <stdexcept>
#include <string_view>

namespace {

std::uint64_t revision(const std::string_view value) {
    std::uint64_t result{};
    const auto parsed = std::from_chars(
        value.data(), value.data() + value.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
        result == 0) {
        throw std::invalid_argument("revision must be a positive integer");
    }
    return result;
}

int print_build_request(const int argc, char** argv) {
    if (argc != 6) {
        std::cerr << "usage: rwn-client build <config> <profile> <revision> "
                     "<build-id>\n";
        return 64;
    }
    const auto config = rwn::core::load_remote_workspace_config(
        std::filesystem::path(argv[2]));
    const auto request = config.make_build_request(
        argv[5], revision(argv[4]), argv[3]);
    std::cout << "build_id=" << request.id << '\n'
              << "workspace_id=" << request.workspace_id << '\n'
              << "pinned_revision=" << request.pinned_revision << '\n'
              << "profile=" << request.profile << '\n'
              << "node=" << config.profile(request.profile).node << '\n'
              << "working_directory=" << request.command.working_directory << '\n'
              << "timeout_seconds=" << request.command.timeout.count() << '\n'
              << "argv";
    for (const auto& argument : request.command.argv) {
        std::cout << '\t' << argument;
    }
    std::cout << '\n';
    return 0;
}

#if defined(RWN_HAS_MSQUIC)
void print_capabilities(
    const std::string_view label,
    const std::vector<std::string>& capabilities) {
    std::cout << label << '=';
    for (std::size_t index = 0; index < capabilities.size(); ++index) {
        if (index != 0) std::cout << ',';
        std::cout << capabilities[index];
    }
    std::cout << '\n';
}
#endif

int open_session(const std::filesystem::path& config_path) {
    const auto config = rwn::core::load_client_runtime_config(config_path);
#if defined(RWN_HAS_MSQUIC)
    rwn::transport::MsQuicClientConnector connector({
        .runtime_library = config.runtime_library,
        .client_certificate_sha1 =
            rwn::transport::parse_sha1_thumbprint(config.local_identity_sha1),
        .allowed_server_certificate_sha256 = {
            rwn::transport::parse_sha256_fingerprint(
                config.allowed_server_certificate_sha256)},
        .connect_timeout = std::chrono::seconds{30},
        .stream_read_timeout = std::chrono::seconds{30},
    });
    auto connection = connector.connect(
        rwn::transport::TransportMode::quic,
        {
            .host = config.host,
            .port = config.port,
            .path = rwn::transport::NetworkPath::lan,
        },
        rwn::transport::load_transport_settings(
            config.transport_settings_file));
    auto control = connection->open_stream(
        rwn::transport::StreamPurpose::control);
    const auto reply = rwn::client::open_remote_session(*control, {
        .device_id = config.device_id,
        .session_id = config.session_id,
        .workspace_id = config.workspace_id,
        .requested_capabilities = config.requested_capabilities,
        .lease_minutes = config.lease_minutes,
    });
    std::cout << "accepted=" << (reply.accepted ? 1 : 0) << '\n'
              << "reason=" << reply.reason_code << '\n';
    print_capabilities("granted", reply.granted_capabilities);
    print_capabilities("denied", reply.denied_capabilities);
    return reply.accepted ? 0 : 3;
#else
    static_cast<void>(config);
    throw std::runtime_error(
        "this build has no MsQuic provider; use the Windows MsQuic package");
#endif
}

int pair_remote_command(
    const std::filesystem::path& config_path,
    const std::string_view six_digit_code,
    const std::string_view display_name,
    const std::string_view client_certificate_sha256) {
    const auto config = rwn::core::load_client_runtime_config(config_path);
#if defined(RWN_HAS_MSQUIC)
    const auto command = rwn::protocol::PairingConfirmCommand{
        .six_digit_code = std::string(six_digit_code),
        .device_id = config.device_id,
        .display_name = std::string(display_name),
        .certificate_sha256 = std::string(client_certificate_sha256),
    };
    rwn::protocol::validate_pairing_confirm_command(command);
    rwn::transport::MsQuicClientConnector connector({
        .runtime_library = config.runtime_library,
        .client_certificate_sha1 =
            rwn::transport::parse_sha1_thumbprint(config.local_identity_sha1),
        .allowed_server_certificate_sha256 = {
            rwn::transport::parse_sha256_fingerprint(
                config.allowed_server_certificate_sha256)},
        .connect_timeout = std::chrono::seconds{30},
        .stream_read_timeout = std::chrono::seconds{30},
    });
    auto connection = connector.connect(
        rwn::transport::TransportMode::quic,
        {.host = config.host, .port = config.port,
         .path = rwn::transport::NetworkPath::lan},
        rwn::transport::load_transport_settings(
            config.transport_settings_file));
    auto control = connection->open_stream(
        rwn::transport::StreamPurpose::control);
    std::cout << "pairing_code=" << six_digit_code
              << " client_certificate_sha256="
              << client_certificate_sha256
              << " node_certificate_sha256="
              << config.allowed_server_certificate_sha256 << '\n';
    const auto reply = rwn::client::confirm_remote_pairing(*control, command);
    std::cout << "pairing_accepted=" << (reply.accepted ? 1 : 0)
              << " device_id=" << reply.device_id
              << " reason=" << reply.reason_code << '\n';
    return reply.accepted ? 0 : 3;
#else
    static_cast<void>(six_digit_code);
    static_cast<void>(display_name);
    static_cast<void>(client_certificate_sha256);
    static_cast<void>(config);
    throw std::runtime_error(
        "pairing requires the Windows MsQuic package");
#endif
}

#if defined(RWN_HAS_MSQUIC)
[[nodiscard]] std::set<std::string, std::less<>> executable_paths(
    const std::filesystem::path& source_root) {
    if (!std::filesystem::exists(source_root / ".git")) return {};
    rwn::platform::windows::WindowsCommandExecutor executor(source_root);
    const auto evidence = executor.execute({
        .argv = {"git.exe", "ls-files", "--stage", "-z"},
        .working_directory = ".",
        .timeout = std::chrono::seconds{30},
        .environment = {},
    });
    if (evidence.exit_code != 0 || evidence.timed_out || evidence.cancelled ||
        evidence.stdout_truncated || evidence.stderr_truncated) {
        throw std::runtime_error(
            "Git executable-mode inventory failed or exceeded bounds");
    }
    return rwn::core::parse_git_stage_executable_paths(evidence.stdout_log);
}

[[nodiscard]] rwn::core::IgnoreRules sync_ignore_rules(
    const rwn::core::ClientRuntimeConfig& runtime,
    const rwn::core::RemoteWorkspaceConfig& workspace) {
    auto rules = rwn::core::IgnoreRules::load_optional(
        runtime.source_root / ".remoteignore");
    std::string configured;
    for (const auto& exclude : workspace.sync_excludes) {
        configured += exclude;
        configured.push_back('\n');
    }
    rules.merge(rwn::core::IgnoreRules::parse(configured));
    return rules;
}

int sync_workspace_command(const std::filesystem::path& config_path) {
    const auto config = rwn::core::load_client_runtime_config(config_path);
    const auto workspace = rwn::core::load_remote_workspace_config(
        config.workspace_config_file);
    if (workspace.workspace_id != config.workspace_id ||
        workspace.source != "windows" || workspace.mirror != "macos" ||
        workspace.sync_direction != "one-way") {
        throw std::invalid_argument(
            "workspace config is not the authoritative Windows-to-Mac scope");
    }
    rwn::transport::MsQuicClientConnector connector({
        .runtime_library = config.runtime_library,
        .client_certificate_sha1 =
            rwn::transport::parse_sha1_thumbprint(config.local_identity_sha1),
        .allowed_server_certificate_sha256 = {
            rwn::transport::parse_sha256_fingerprint(
                config.allowed_server_certificate_sha256)},
        .connect_timeout = std::chrono::seconds{30},
        .stream_read_timeout = std::chrono::seconds{30},
    });
    auto connection = connector.connect(
        rwn::transport::TransportMode::quic,
        {.host = config.host,
         .port = config.port,
         .path = rwn::transport::NetworkPath::lan},
        rwn::transport::load_transport_settings(
            config.transport_settings_file));
    auto control = connection->open_stream(
        rwn::transport::StreamPurpose::control);
    const auto opened = rwn::client::open_remote_session(*control, {
        .device_id = config.device_id,
        .session_id = config.session_id,
        .workspace_id = config.workspace_id,
        .requested_capabilities = config.requested_capabilities,
        .lease_minutes = config.lease_minutes,
    });
    if (!opened.accepted ||
        std::ranges::find(
            opened.granted_capabilities, "workspace.sync") ==
            opened.granted_capabilities.end()) {
        throw std::runtime_error(
            "Session did not grant workspace.sync for the configured workspace");
    }
    const auto manifest = rwn::core::build_workspace_manifest(
        config.source_root,
        {
            .workspace_id = config.workspace_id,
            .revision = config.revision,
            .ignore_rules = sync_ignore_rules(config, workspace),
            .executable_paths = executable_paths(config.source_root),
        });
    auto file_stream = connection->open_stream(
        rwn::transport::StreamPurpose::file);
    const auto result = rwn::client::sync_workspace(
        *file_stream, config.source_root, manifest, config.session_id);
    std::cout << "diff_accepted=" << (result.diff.accepted ? 1 : 0) << '\n'
              << "previous_revision=" << result.diff.current_revision << '\n';
    if (!result.commit.has_value()) {
        std::cout << "workspace_synced=0 reason="
                  << result.diff.reason_code << '\n';
        return 4;
    }
    std::cout << "workspace_synced="
              << (result.commit->accepted ? 1 : 0) << '\n'
              << "revision=" << result.commit->revision << '\n'
              << "manifest_sha256=" << result.commit->manifest_sha256 << '\n'
              << "reason=" << result.commit->reason_code << '\n';
    return result.commit->accepted ? 0 : 4;
}

int remote_build_command(
    const std::filesystem::path& config_path,
    const std::string_view profile,
    const std::string_view build_id) {
    const auto config = rwn::core::load_client_runtime_config(config_path);
    const auto workspace = rwn::core::load_remote_workspace_config(
        config.workspace_config_file);
    if (workspace.workspace_id != config.workspace_id) {
        throw std::invalid_argument("build workspace config identity mismatches runtime");
    }
    const auto request = workspace.make_build_request(
        std::string(build_id), config.revision, profile);
    rwn::transport::MsQuicClientConnector connector({
        .runtime_library = config.runtime_library,
        .client_certificate_sha1 =
            rwn::transport::parse_sha1_thumbprint(config.local_identity_sha1),
        .allowed_server_certificate_sha256 = {
            rwn::transport::parse_sha256_fingerprint(
                config.allowed_server_certificate_sha256)},
        .connect_timeout = std::chrono::seconds{30},
        .stream_read_timeout = request.command.timeout +
            std::chrono::seconds{60},
    });
    auto connection = connector.connect(
        rwn::transport::TransportMode::quic,
        {.host = config.host, .port = config.port,
         .path = rwn::transport::NetworkPath::lan},
        rwn::transport::load_transport_settings(
            config.transport_settings_file));
    auto control = connection->open_stream(
        rwn::transport::StreamPurpose::control);
    const auto opened = rwn::client::open_remote_session(*control, {
        .device_id = config.device_id,
        .session_id = config.session_id,
        .workspace_id = config.workspace_id,
        .requested_capabilities = config.requested_capabilities,
        .lease_minutes = config.lease_minutes,
    });
    if (!opened.accepted ||
        std::ranges::find(opened.granted_capabilities, "build.submit") ==
            opened.granted_capabilities.end()) {
        throw std::runtime_error("Session did not grant build.submit");
    }
    auto stream = connection->open_stream(rwn::transport::StreamPurpose::build);
    const auto reply = rwn::client::submit_build(*stream, {
        .session_id = config.session_id,
        .workspace_id = config.workspace_id,
        .revision = config.revision,
        .build_id = std::string(build_id),
        .profile = std::string(profile),
    });
    if (!reply.accepted) {
        std::cout << "build_accepted=0 reason=" << reply.reason_code << '\n';
        return 5;
    }
    static_cast<void>(rwn::client::verify_build_evidence(request, reply));
    std::cout << reply.stdout_log;
    std::cerr << reply.stderr_log;
    std::cout << "\nbuild_accepted=1 build_id=" << reply.build_id
              << " exit=" << reply.exit_code
              << " elapsed_ms=" << reply.elapsed_ms
              << " timed_out=" << reply.timed_out
              << " cancelled=" << reply.cancelled
              << " evidence_sha256=" << reply.evidence_sha256
              << " reason=" << reply.reason_code << '\n';
    for (const auto& artifact_id : reply.artifact_ids) {
        std::cout << "artifact_id=" << artifact_id << '\n';
    }
    return reply.state == rwn::protocol::BuildWireState::succeeded ? 0 : 5;
}

int artifact_download_command(
    const std::filesystem::path& config_path,
    const std::string_view artifact_id,
    const std::string_view transfer_id,
    const std::filesystem::path& destination_root,
    const std::filesystem::path& destination_relative_path) {
    const auto config = rwn::core::load_client_runtime_config(config_path);
    if (!destination_root.is_absolute() ||
        !std::filesystem::is_directory(destination_root)) {
        throw std::invalid_argument(
            "artifact destination root must be an existing absolute directory");
    }
    rwn::transport::MsQuicClientConnector connector({
        .runtime_library = config.runtime_library,
        .client_certificate_sha1 =
            rwn::transport::parse_sha1_thumbprint(config.local_identity_sha1),
        .allowed_server_certificate_sha256 = {
            rwn::transport::parse_sha256_fingerprint(
                config.allowed_server_certificate_sha256)},
        .connect_timeout = std::chrono::seconds{30},
        .stream_read_timeout = std::chrono::minutes{30},
    });
    auto connection = connector.connect(
        rwn::transport::TransportMode::quic,
        {.host = config.host, .port = config.port,
         .path = rwn::transport::NetworkPath::lan},
        rwn::transport::load_transport_settings(
            config.transport_settings_file));
    auto control = connection->open_stream(
        rwn::transport::StreamPurpose::control);
    const auto opened = rwn::client::open_remote_session(*control, {
        .device_id = config.device_id,
        .session_id = config.session_id,
        .workspace_id = config.workspace_id,
        .requested_capabilities = config.requested_capabilities,
        .lease_minutes = config.lease_minutes,
    });
    if (!opened.accepted ||
        std::ranges::find(opened.granted_capabilities, "artifact.download") ==
            opened.granted_capabilities.end()) {
        throw std::runtime_error("Session did not grant artifact.download");
    }
    auto stream = connection->open_stream(rwn::transport::StreamPurpose::file);
    rwn::platform::windows::WindowsDurableFileSystem filesystem;
    const auto result = rwn::client::download_artifact(
        *stream,
        {
            .session_id = config.session_id,
            .workspace_id = config.workspace_id,
            .revision = config.revision,
            .artifact_id = std::string(artifact_id),
            .transfer_id = std::string(transfer_id),
        },
        destination_root, destination_relative_path, filesystem);
    if (!result.manifest.accepted) {
        std::cout << "artifact_accepted=0 reason="
                  << result.manifest.reason_code << '\n';
        return 6;
    }
    std::cout << "artifact_accepted=1 artifact_id="
              << result.manifest.artifact_id
              << " destination=" << result.destination.string()
              << " sha256=" << result.manifest.sha256
              << " size=" << result.manifest.size << '\n';
    return 0;
}

int remote_deploy_command(
    const std::filesystem::path& config_path,
    const std::string_view artifact_id,
    const std::string_view deployment_id) {
    const auto config = rwn::core::load_client_runtime_config(config_path);
    rwn::transport::MsQuicClientConnector connector({
        .runtime_library = config.runtime_library,
        .client_certificate_sha1 =
            rwn::transport::parse_sha1_thumbprint(config.local_identity_sha1),
        .allowed_server_certificate_sha256 = {
            rwn::transport::parse_sha256_fingerprint(
                config.allowed_server_certificate_sha256)},
        .connect_timeout = std::chrono::seconds{30},
        .stream_read_timeout = std::chrono::minutes{30},
    });
    auto connection = connector.connect(
        rwn::transport::TransportMode::quic,
        {.host = config.host, .port = config.port,
         .path = rwn::transport::NetworkPath::lan},
        rwn::transport::load_transport_settings(
            config.transport_settings_file));
    auto control = connection->open_stream(
        rwn::transport::StreamPurpose::control);
    const auto opened = rwn::client::open_remote_session(*control, {
        .device_id = config.device_id, .session_id = config.session_id,
        .workspace_id = config.workspace_id,
        .requested_capabilities = config.requested_capabilities,
        .lease_minutes = config.lease_minutes,
    });
    if (!opened.accepted ||
        std::ranges::find(opened.granted_capabilities, "deploy.execute") ==
            opened.granted_capabilities.end()) {
        throw std::runtime_error("Session did not grant deploy.execute");
    }
    auto stream = connection->open_stream(
        rwn::transport::StreamPurpose::command);
    const auto reply = rwn::client::submit_deployment(*stream, {
        .session_id = config.session_id,
        .workspace_id = config.workspace_id,
        .revision = config.revision,
        .artifact_id = std::string(artifact_id),
        .deployment_id = std::string(deployment_id),
    });
    std::cout << "deployment_accepted=" << (reply.accepted ? 1 : 0)
              << " deployment_id=" << reply.deployment_id
              << " artifact_id=" << reply.artifact_id
              << " artifact_sha256=" << reply.artifact_sha256
              << " evidence_sha256=" << reply.evidence_sha256
              << " reason=" << reply.reason_code << '\n';
    for (const auto& step : reply.steps) {
        std::cout << "step=" << static_cast<unsigned int>(step.step)
                  << " succeeded=" << (step.succeeded ? 1 : 0)
                  << " exit=" << step.exit_code
                  << " elapsed_ms=" << step.elapsed_ms
                  << " timed_out=" << (step.timed_out ? 1 : 0)
                  << " cancelled=" << (step.cancelled ? 1 : 0)
                  << " reason=" << step.reason_code << '\n';
    }
    return reply.accepted &&
        reply.status == rwn::protocol::DeploymentWireStatus::active ? 0 : 7;
}
#endif

int self_check() {
    using enum rwn::core::Capability;
    rwn::core::CapabilityRequest request;
    request.principal.id = "coding-agent";
    request.principal.kind = rwn::core::PrincipalKind::agent;
    request.workspace = "example-workspace";
    request.requested = {workspace_read, build_submit, command_exec};
    const auto policy = rwn::core::default_agent_policy(
        "coding-agent", "example-workspace");
    const auto authorization = rwn::core::authorize(request, policy);

    rwn::core::Session session("local-demo-session");
    session.authenticate(true);
    session.open(authorization);
    std::cout << "product=rwn-client version=0.1 self_check=passed granted="
              << authorization.granted.size() << " denied="
              << authorization.denied.size() << '\n';
    return 0;
}

void usage() {
    std::cerr << "usage:\n"
                 "  rwn-client self-check\n"
                 "  rwn-client pair <absolute-client-runtime.toml> "
                     "<six-digit-code> <display-name> "
                     "<client-certificate-sha256>\n"
                 "  rwn-client session-open <absolute-client-runtime.toml>\n"
                 "  rwn-client sync <absolute-client-runtime.toml>\n"
                 "  rwn-client build-remote <absolute-client-runtime.toml> "
                     "<profile> <build-id>\n"
                 "  rwn-client artifact-download <absolute-client-runtime.toml> "
                     "<artifact-id> <transfer-id> <absolute-download-root> "
                     "<relative-destination>\n"
                 "  rwn-client deploy-remote <absolute-client-runtime.toml> "
                     "<artifact-id> <deployment-id>\n"
                 "  rwn-client build <config> <profile> <revision> <build-id>\n";
}

}  // namespace

int main(const int argc, char** argv) {
    try {
        if (argc == 2 && std::string_view(argv[1]) == "self-check") {
            return self_check();
        }
        if (argc == 6 && std::string_view(argv[1]) == "pair") {
            return pair_remote_command(
                std::filesystem::path(argv[2]), argv[3], argv[4], argv[5]);
        }
        if (argc == 3 && std::string_view(argv[1]) == "session-open") {
            return open_session(std::filesystem::path(argv[2]));
        }
        if (argc == 3 && std::string_view(argv[1]) == "sync") {
#if defined(RWN_HAS_MSQUIC)
            return sync_workspace_command(std::filesystem::path(argv[2]));
#else
            throw std::runtime_error(
                "this build has no MsQuic provider; use the Windows MsQuic package");
#endif
        }
        if (argc > 1 && std::string_view(argv[1]) == "build") {
            return print_build_request(argc, argv);
        }
        if (argc == 5 && std::string_view(argv[1]) == "build-remote") {
#if defined(RWN_HAS_MSQUIC)
            return remote_build_command(
                std::filesystem::path(argv[2]), argv[3], argv[4]);
#else
            throw std::runtime_error(
                "this build has no MsQuic provider; use the Windows MsQuic package");
#endif
        }
        if (argc == 7 && std::string_view(argv[1]) == "artifact-download") {
#if defined(RWN_HAS_MSQUIC)
            return artifact_download_command(
                std::filesystem::path(argv[2]), argv[3], argv[4],
                std::filesystem::path(argv[5]), std::filesystem::path(argv[6]));
#else
            throw std::runtime_error(
                "this build has no MsQuic provider; use the Windows MsQuic package");
#endif
        }
        if (argc == 5 && std::string_view(argv[1]) == "deploy-remote") {
#if defined(RWN_HAS_MSQUIC)
            return remote_deploy_command(
                std::filesystem::path(argv[2]), argv[3], argv[4]);
#else
            throw std::runtime_error(
                "this build has no MsQuic provider; use the Windows MsQuic package");
#endif
        }
        usage();
        return 64;
    } catch (const std::exception& error) {
        std::cerr << "rwn-client: " << error.what() << '\n';
        return 1;
    }
}
