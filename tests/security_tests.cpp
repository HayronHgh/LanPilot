#include "rwn/core/authorization.hpp"
#include "rwn/audio/audio.hpp"
#include "rwn/client/session_client.hpp"
#include "rwn/client/build_client.hpp"
#include "rwn/client/workspace_client.hpp"
#include "rwn/core/agent_runtime.hpp"
#include "rwn/core/artifact_store.hpp"
#include "rwn/core/audit_file.hpp"
#include "rwn/core/build.hpp"
#include "rwn/core/build_config.hpp"
#include "rwn/core/content_hash.hpp"
#include "rwn/core/deployment.hpp"
#include "rwn/core/file_transfer.hpp"
#include "rwn/core/ignore_rules.hpp"
#include "rwn/core/identity.hpp"
#include "rwn/core/pairing_store.hpp"
#include "rwn/core/policy_file.hpp"
#include "rwn/core/process_isolation.hpp"
#include "rwn/core/product_config.hpp"
#include "rwn/core/release_security.hpp"
#include "rwn/core/release_compatibility.hpp"
#include "rwn/core/release_diagnostics.hpp"
#include "rwn/core/release_update.hpp"
#include "rwn/core/session.hpp"
#include "rwn/core/session_service.hpp"
#include "rwn/core/terminal.hpp"
#include "rwn/core/workspace_scope.hpp"
#include "rwn/core/workspace_sync.hpp"
#include "rwn/core/workspace_manifest.hpp"
#include "rwn/desktop/desktop.hpp"
#include "rwn/desktop/visual_evidence.hpp"
#include "rwn/desktop/visual_trace.hpp"
#include "rwn/node/control_service.hpp"
#include "rwn/node/build_service.hpp"
#include "rwn/node/artifact_service.hpp"
#include "rwn/node/deployment_service.hpp"
#include "rwn/node/pairing_service.hpp"
#include "rwn/node/workspace_service.hpp"
#include "rwn/protocol/envelope.hpp"
#include "rwn/protocol/build_control.hpp"
#include "rwn/protocol/session_control.hpp"
#include "rwn/protocol/security_gate.hpp"
#include "rwn/protocol/workspace_control.hpp"
#include "rwn/transport/encrypted_fallback.hpp"
#include "rwn/transport/apple_network_contract.hpp"
#include "rwn/transport/resilient_transport.hpp"
#include "rwn/transport/verification.hpp"
#include "test_support.hpp"

#if defined(RWN_TEST_MSQUIC_PROVIDER)
#include "rwn/transport/msquic_client.hpp"
#include "rwn/transport/msquic_server.hpp"
#endif

#include <algorithm>
#include <array>
#include <cstddef>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

#if defined(RWN_TEST_WINDOWS_PLATFORM)
#include "rwn/platform/windows/command_executor.hpp"
#include "rwn/platform/windows/desktop_runtime.hpp"
#include "rwn/platform/windows/dns_sd_discovery.hpp"
#include "rwn/platform/windows/durable_filesystem.hpp"
#include "rwn/platform/windows/pairing_code.hpp"
#include "rwn/platform/windows/schannel_transport.hpp"
#include "rwn/platform/windows/update_signature.hpp"
#endif

namespace {

void build_and_artifact_wire_rejects_forged_evidence() {
    constexpr auto hash =
        "00112233445566778899aabbccddeeff"
        "00112233445566778899aabbccddeeff";
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            rwn::protocol::validate_build_submit_command({
                .session_id = "session",
                .workspace_id = "workspace",
                .revision = 0,
                .build_id = "build",
                .profile = "debug",
            });
        },
        "unpinned build revision");

    auto forged_status = rwn::protocol::BuildStatusReply{
        .accepted = true,
        .build_id = "build",
        .state = rwn::protocol::BuildWireState::succeeded,
        .exit_code = 7,
        .elapsed_ms = 1,
        .timed_out = false,
        .cancelled = false,
        .stdout_truncated = false,
        .stderr_truncated = false,
        .stdout_log = {},
        .stderr_log = {},
        .evidence_sha256 = hash,
        .artifact_ids = {},
        .reason_code = "build_succeeded",
    };
    rwn::test::require_throws<std::invalid_argument>(
        [&] { rwn::protocol::validate_build_status_reply(forged_status); },
        "successful state with failed exit");
    forged_status.exit_code = 0;
    forged_status.evidence_sha256 = std::string(64, 'A');
    rwn::test::require_throws<std::invalid_argument>(
        [&] { rwn::protocol::validate_build_status_reply(forged_status); },
        "noncanonical build evidence hash");

    rwn::test::require_throws<std::invalid_argument>(
        [] { rwn::protocol::validate_deploy_submit_command({
            .session_id = "session", .workspace_id = "workspace",
            .revision = 0, .artifact_id = "artifact",
            .deployment_id = "deployment"}); },
        "deploy without pinned revision");
    rwn::test::require_throws<std::invalid_argument>(
        [&] { rwn::protocol::validate_deploy_status_reply({
            .accepted = true, .deployment_id = "deployment",
            .artifact_id = "artifact", .artifact_sha256 = hash,
            .build_id = "build", .source_revision = 7,
            .status = rwn::protocol::DeploymentWireStatus::active,
            .steps = {{.step = 0, .succeeded = true, .exit_code = 1,
                       .elapsed_ms = 1, .timed_out = false,
                       .cancelled = false, .reason_code = "step_failed"}},
            .evidence_sha256 = hash, .reason_code = "deployment_active"}); },
        "successful deployment step with failed process evidence");

    auto manifest = rwn::protocol::ArtifactManifestReply{
        .accepted = true,
        .artifact_id = "artifact",
        .transfer_id = "transfer",
        .build_id = "build",
        .source_revision = 9,
        .name = "product.zip",
        .sha256 = hash,
        .size = 8,
        .platform = "macos",
        .architecture = "arm64",
        .chunks = {
            {.index = 0, .offset = 0, .size = 4, .sha256 = hash},
            {.index = 1, .offset = 5, .size = 4, .sha256 = hash},
        },
        .reason_code = "artifact_ready",
    };
    rwn::test::require_throws<std::invalid_argument>(
        [&] { rwn::protocol::validate_artifact_manifest_reply(manifest); },
        "artifact plan gap");
    manifest.chunks[1].offset = 4;
    manifest.name = "../product.zip";
    rwn::test::require_throws<std::invalid_argument>(
        [&] { rwn::protocol::validate_artifact_manifest_reply(manifest); },
        "artifact filename traversal");

    auto bytes = rwn::protocol::encode_build_submit_command({
        .session_id = "session",
        .workspace_id = "workspace",
        .revision = 9,
        .build_id = "build",
        .profile = "debug",
    });
    bytes.push_back(std::byte{0});
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::protocol::decode_build_submit_command(bytes));
        },
        "trailing build command bytes");
}

void workspace_control_wire_rejects_unsafe_transactions() {
    constexpr auto hash =
        "00112233445566778899aabbccddeeff"
        "00112233445566778899aabbccddeeff";
    rwn::protocol::WorkspaceManifestCommand manifest{
        .session_id = "session-1",
        .workspace_id = "game",
        .revision = 1,
        .manifest_sha256 = hash,
        .entries = {{.path = "../escape",
                     .kind = rwn::protocol::WorkspaceWireEntryKind::file,
                     .size = 1,
                     .sha256 = hash,
                     .mode = 0644U,
                     .symlink_target = {}}},
    };
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::protocol::encode_workspace_manifest_command(manifest));
        },
        "workspace traversal on wire");
    manifest.entries.front().path = "src/CON.txt";
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::protocol::encode_workspace_manifest_command(manifest));
        },
        "workspace Windows alias on wire");

    rwn::protocol::WorkspaceFilePlanCommand plan{
        .session_id = "session-1",
        .workspace_id = "game",
        .revision = 1,
        .transfer_id = "file-1",
        .path = "src/main.cpp",
        .total_size = 2,
        .sha256 = hash,
        .chunks = {{.index = 0, .offset = 1, .size = 2, .sha256 = hash}},
    };
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::protocol::encode_workspace_file_plan_command(plan));
        },
        "workspace non-contiguous chunk plan");

    rwn::test::require_throws<std::invalid_argument>(
        [] {
            rwn::protocol::validate_workspace_file_plan_reply({
                .accepted = true,
                .missing_chunks = {1, 1},
                .reason_code = "file_plan_ready",
            });
        },
        "workspace duplicate missing chunk");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            rwn::protocol::validate_workspace_file_chunk_command({
                .session_id = "session-1",
                .workspace_id = "game",
                .revision = 1,
                .transfer_id = "file-1",
                .index = 0,
                .bytes = {},
            });
        },
        "workspace empty chunk");

    auto commit = rwn::protocol::encode_workspace_commit_command({
        .session_id = "session-1",
        .workspace_id = "game",
        .revision = 1,
        .manifest_sha256 = hash,
    });
    commit.push_back(std::byte{});
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::protocol::decode_workspace_commit_command(commit));
        },
        "workspace trailing commit bytes");
}

void workspace_mirror_transaction_rejects_forged_scope_and_hash() {
    const auto root = std::filesystem::temp_directory_path() /
        ("rwn-workspace-mirror-security-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(root);
    constexpr auto hash =
        "00112233445566778899aabbccddeeff"
        "00112233445566778899aabbccddeeff";
    rwn::test::TestDurableFileSystem filesystem;
    rwn::node::WorkspaceMirrorService service(root, "game", 0, filesystem);
    const auto wrong_scope = service.begin({
        .session_id = "session-1",
        .workspace_id = "other",
        .revision = 1,
        .manifest_sha256 = hash,
        .entries = {},
    });
    RWN_CHECK(!wrong_scope.accepted);
    RWN_CHECK(wrong_scope.reason_code == "workspace_scope_denied");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(service.begin({
                .session_id = "session-1",
                .workspace_id = "game",
                .revision = 1,
                .manifest_sha256 = hash,
                .entries = {},
            }));
        },
        "workspace forged manifest hash");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::node::WorkspaceMirrorStateFile state(
                root, "../escape.toml", "game", filesystem);
            static_cast<void>(state);
        },
        "workspace state traversal");
    {
        std::ofstream corrupt(root / "state.toml", std::ios::binary);
        corrupt << "workspace_id=game\nrevision=1\nunknown=value\n";
    }
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::node::WorkspaceMirrorStateFile state(
                root, "state.toml", "game", filesystem);
            static_cast<void>(state);
        },
        "workspace state unknown schema");
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}

void product_runtime_configs_reject_unsafe_state() {
    const std::string valid_client =
        "transport_provider = \"msquic\"\n"
        "runtime_library = \"C:/rwn/msquic.dll\"\n"
        "local_identity_sha1 = \"00112233445566778899aabbccddeeff00112233\"\n"
        "allowed_server_certificate_sha256 = \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"\n"
        "host = \"mac-node.example\"\n"
        "port = 4433\n"
        "transport_settings_file = \"C:/rwn/transport.toml\"\n"
        "source_root = \"C:/source/game\"\n"
        "workspace_config_file = \"C:/source/game/remote-workspace.toml\"\n"
        "device_id = \"windows-client\"\n"
        "session_id = \"session-1\"\n"
        "workspace_id = \"game\"\n"
        "requested_capabilities = [\"workspace.sync\"]\n"
        "revision = 1\n"
        "lease_minutes = 15\n";
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::core::parse_client_runtime_config(
                valid_client + "unknown = \"value\"\n"));
        },
        "unknown client runtime field");
    auto relative = valid_client;
    const auto absolute = relative.find("C:/rwn/msquic.dll");
    relative.replace(absolute, std::string("C:/rwn/msquic.dll").size(),
                     "msquic.dll");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::core::parse_client_runtime_config(relative));
        },
        "relative runtime library");
    auto duplicate_capability = valid_client;
    const auto capability = duplicate_capability.find(
        "[\"workspace.sync\"]");
    duplicate_capability.replace(
        capability, std::string("[\"workspace.sync\"]").size(),
        "[\"workspace.sync\", \"workspace.sync\"]");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::core::parse_client_runtime_config(
                duplicate_capability));
        },
        "duplicate requested capability");

    const std::string worker =
        "workspace_root = \"C:/rwn/mirror\"\n"
        "workspace_config_file = \"C:/rwn/mirror/remote-workspace.toml\"\n"
        "state_root = \"C:/rwn/state\"\n"
        "workspace_state_file = \"workspace/game.toml\"\n"
        "evidence_root = \"C:/rwn/evidence\"\n"
        "artifact_root = \"C:/rwn/artifacts\"\n"
        "socket_path = \"C:/rwn/run/build-worker.sock\"\n"
        "allowed_node_uid = 502\n"
        "accept_timeout_seconds = 120\n";
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::core::parse_build_worker_runtime_config(worker));
        },
        "worker-controlled build profile inside workspace");
    auto root_uid = worker;
    const auto config_path = root_uid.find(
        "C:/rwn/mirror/remote-workspace.toml");
    root_uid.replace(
        config_path, std::string("C:/rwn/mirror/remote-workspace.toml").size(),
        "C:/rwn/config/remote-workspace.toml");
    const auto uid = root_uid.find("allowed_node_uid = 502");
    root_uid.replace(uid, std::string("allowed_node_uid = 502").size(),
                     "allowed_node_uid = 0");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::core::parse_build_worker_runtime_config(root_uid));
        },
        "root Node UID at worker boundary");

    const std::string broker =
        "artifact_root = \"C:/rwn/runtime/artifacts\"\n"
        "runtime_root = \"C:/rwn/runtime\"\n"
        "active_relative_path = \"bin/app.zip\"\n"
        "socket_path = \"C:/rwn/run/deployment-broker.sock\"\n"
        "allowed_node_uid = 501\n"
        "stop_command = [\"C:/Windows/System32/sc.exe\", \"stop\", \"app\"]\n"
        "start_command = [\"C:/Windows/System32/sc.exe\", \"start\", \"app\"]\n"
        "health_command = [\"C:/Windows/System32/curl.exe\", \"--fail\", \"http://127.0.0.1/health\"]\n"
        "command_timeout_seconds = 30\n"
        "accept_timeout_seconds = 120\n";
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(
            rwn::core::parse_broker_runtime_config(broker)); },
        "artifact storage nested inside privileged runtime");
    auto relative_command = broker;
    const auto artifact = relative_command.find("C:/rwn/runtime/artifacts");
    relative_command.replace(
        artifact, std::string("C:/rwn/runtime/artifacts").size(),
        "C:/rwn/artifacts");
    const auto executable = relative_command.find(
        "C:/Windows/System32/sc.exe");
    relative_command.replace(
        executable, std::string("C:/Windows/System32/sc.exe").size(),
        "sc.exe");
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(
            rwn::core::parse_broker_runtime_config(relative_command)); },
        "relative privileged command executable");
}

class SecurityControlStream final : public rwn::transport::ReliableStream {
public:
    void write(const std::span<const std::byte> data) override {
        writes.emplace_back(data.begin(), data.end());
    }
    [[nodiscard]] std::vector<std::byte> read() override { return input; }

    std::vector<std::byte> input;
    std::vector<std::vector<std::byte>> writes;
};

class DeniedBuildWorker final : public rwn::node::BuildWorkerBoundary {
public:
    [[nodiscard]] rwn::core::BuildExecutionResult execute(
        const rwn::core::BuildRequest&,
        const rwn::core::BuildProfile&) override {
        ++executions;
        throw std::logic_error("denied worker must not execute");
    }
    std::size_t executions{};
};

class DeniedArtifactSource final : public rwn::node::ArtifactSourceBoundary {
public:
    [[nodiscard]] rwn::protocol::ArtifactManifestReply prepare(
        const rwn::protocol::ArtifactFetchCommand&) override {
        ++calls;
        throw std::logic_error("denied artifact source must not execute");
    }
    void request_chunks(
        const rwn::protocol::ArtifactResumeCommand&) override {
        ++calls;
        throw std::logic_error("denied artifact source must not execute");
    }
    [[nodiscard]] rwn::protocol::ArtifactChunkCommand read_chunk() override {
        ++calls;
        throw std::logic_error("denied artifact source must not execute");
    }
    std::size_t calls{};
};

class DeniedDeploymentWorker final
    : public rwn::node::DeploymentWorkerBoundary {
public:
    [[nodiscard]] rwn::protocol::DeployStatusReply execute(
        const rwn::protocol::DeploySubmitCommand&) override {
        ++calls;
        throw std::logic_error("denied deploy worker must not execute");
    }
    std::size_t calls{};
};

void deployment_service_rejects_missing_capability() {
    using namespace std::chrono_literals;
    constexpr auto fingerprint =
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    const auto now = rwn::core::WallClock::time_point{} + 990h;
    const auto certificate = rwn::core::PeerCertificate{
        .device_id = "client", .fingerprint = fingerprint,
        .serial = "serial-deploy", .not_before = now - 1h,
        .not_after = now + 1h};
    rwn::node::NodeControlService control({
        .principal_id = "client", .workspaces = {"game"},
        .allowed = {rwn::core::Capability::workspace_read}});
    control.pair_device({.id = "client", .display_name = "Client",
        .fingerprint = fingerprint, .certificate = certificate,
        .revoked = false});
    RWN_CHECK(control.open_session({
        .device_id = "client", .session_id = "session",
        .workspace_id = "game", .requested_capabilities = {"workspace.read"},
        .lease_minutes = 1},
        {.tls_1_3_negotiated = true, .client_certificate_present = true,
         .certificate_chain_valid = true, .revocation_checked = true,
         .certificate = certificate}, now).accepted);
    SecurityControlStream stream;
    stream.input = rwn::protocol::encode({
        .version = 1, .type = rwn::protocol::MessageType::deploy_submit,
        .correlation_id = "deploy-denied",
        .payload = rwn::protocol::encode_deploy_submit_command({
            .session_id = "session", .workspace_id = "game", .revision = 7,
            .artifact_id = "artifact", .deployment_id = "deployment"}),
        .unknown_fields = {}});
    DeniedDeploymentWorker worker;
    const auto reply = rwn::node::serve_deployment(
        stream, control, 7, worker, now);
    RWN_CHECK(!reply.accepted);
    RWN_CHECK(reply.reason_code == "capability_denied");
    RWN_CHECK(worker.calls == 0);
}

void artifact_service_rejects_capability_and_stale_revision() {
    using namespace std::chrono_literals;
    constexpr auto fingerprint =
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    const auto now = rwn::core::WallClock::time_point{} + 950h;
    const auto certificate = rwn::core::PeerCertificate{
        .device_id = "client", .fingerprint = fingerprint,
        .serial = "serial-artifact", .not_before = now - 1h,
        .not_after = now + 1h};
    const auto request = [](const std::uint64_t revision) {
        return rwn::protocol::encode({
            .version = 1,
            .type = rwn::protocol::MessageType::artifact_manifest,
            .correlation_id = "artifact-transfer",
            .payload = rwn::protocol::encode_artifact_fetch_command({
                .session_id = "session", .workspace_id = "game",
                .revision = revision, .artifact_id = "artifact",
                .transfer_id = "transfer"}),
            .unknown_fields = {},
        });
    };
    for (const auto allow_capability : {false, true}) {
        rwn::node::NodeControlService control({
            .principal_id = "client", .workspaces = {"game"},
            .allowed = allow_capability
                ? std::set{rwn::core::Capability::artifact_download}
                : std::set{rwn::core::Capability::workspace_read}});
        control.pair_device({
            .id = "client", .display_name = "Client",
            .fingerprint = fingerprint, .certificate = certificate,
            .revoked = false});
        RWN_CHECK(control.open_session({
            .device_id = "client", .session_id = "session",
            .workspace_id = "game",
            .requested_capabilities = allow_capability
                ? std::vector<std::string>{"artifact.download"}
                : std::vector<std::string>{"workspace.read"},
            .lease_minutes = 1},
            {.tls_1_3_negotiated = true, .client_certificate_present = true,
             .certificate_chain_valid = true, .revocation_checked = true,
             .certificate = certificate}, now).accepted);
        SecurityControlStream stream;
        stream.input = request(allow_capability ? 6 : 7);
        DeniedArtifactSource source;
        const auto reply = rwn::node::serve_artifact_download(
            stream, control, 7, source, now);
        RWN_CHECK(!reply.accepted);
        RWN_CHECK(reply.reason_code ==
            (allow_capability ? "revision_mismatch" : "capability_denied"));
        RWN_CHECK(source.calls == 0);
        RWN_CHECK(stream.writes.size() == 1);
    }
}

void build_service_rejects_scope_revision_and_forged_reply() {
    using namespace std::chrono_literals;
    constexpr auto fingerprint =
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    const auto now = rwn::core::WallClock::time_point{} + 900h;
    const auto certificate = rwn::core::PeerCertificate{
        .device_id = "client", .fingerprint = fingerprint,
        .serial = "serial", .not_before = now - 1h, .not_after = now + 1h};
    rwn::node::NodeControlService control({
        .principal_id = "client", .workspaces = {"game"},
        .allowed = {rwn::core::Capability::workspace_read}});
    control.pair_device({.id = "client", .display_name = "Client",
        .fingerprint = fingerprint, .certificate = certificate,
        .revoked = false});
    RWN_CHECK(control.open_session({
        .device_id = "client", .session_id = "session",
        .workspace_id = "game",
        .requested_capabilities = {"workspace.read", "build.submit"},
        .lease_minutes = 1},
        {.tls_1_3_negotiated = true, .client_certificate_present = true,
         .certificate_chain_valid = true, .revocation_checked = true,
         .certificate = certificate}, now).accepted);
    const auto config = rwn::core::parse_remote_workspace_config(
        "[workspace]\nid = \"game\"\nname = \"Game\"\nsource = \"windows\"\nmirror = \"macos\"\n"
        "[sync]\ndirection = \"one-way\"\nexclude = [\"build\"]\n"
        "[target.debug]\nnode = \"mac\"\nworking_dir = \".\"\n"
        "command = [\"/usr/bin/true\"]\ntimeout_seconds = 5\n"
        "environment_allowlist = [\"SDKROOT\"]\n"
        "[target.debug.artifacts]\npaths = [\"dist/a.zip\"]\n"
        "platform = \"macos\"\narchitecture = \"arm64\"\narchive_app_bundles = true\n");
    DeniedBuildWorker worker;
    rwn::node::NodeBuildService service(config, 7, worker);
    SecurityControlStream stream;
    stream.input = rwn::protocol::encode({
        .version = 1, .type = rwn::protocol::MessageType::build_submit,
        .correlation_id = "build-denied",
        .payload = rwn::protocol::encode_build_submit_command({
            .session_id = "session", .workspace_id = "game", .revision = 7,
            .build_id = "denied", .profile = "debug"}),
        .unknown_fields = {}});
    const auto denied = service.serve(stream, control, now);
    RWN_CHECK(!denied.reply.accepted);
    RWN_CHECK(denied.reply.reason_code == "capability_denied");
    RWN_CHECK(worker.executions == 0);

    SecurityControlStream stale;
    stale.input = rwn::protocol::encode({
        .version = 1, .type = rwn::protocol::MessageType::build_submit,
        .correlation_id = "build-stale",
        .payload = rwn::protocol::encode_build_submit_command({
            .session_id = "session", .workspace_id = "game", .revision = 6,
            .build_id = "stale", .profile = "debug"}),
        .unknown_fields = {}});
    RWN_CHECK(service.serve(stale, control, now).reply.reason_code ==
              "revision_mismatch");
    RWN_CHECK(worker.executions == 0);

    SecurityControlStream forged;
    forged.input = rwn::protocol::encode({
        .version = 1, .type = rwn::protocol::MessageType::build_status,
        .correlation_id = "wrong-correlation",
        .payload = rwn::protocol::encode_build_status_reply({
            .accepted = false, .build_id = "denied",
            .state = rwn::protocol::BuildWireState::rejected,
            .exit_code = 0, .elapsed_ms = 0, .timed_out = false,
            .cancelled = false, .stdout_truncated = false,
            .stderr_truncated = false, .stdout_log = {}, .stderr_log = {},
            .evidence_sha256 = {}, .artifact_ids = {},
            .reason_code = "capability_denied"}),
        .unknown_fields = {}});
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(rwn::client::submit_build(forged, {
            .session_id = "session", .workspace_id = "game", .revision = 7,
            .build_id = "denied", .profile = "debug"})); },
        "forged build reply correlation");

    const auto request = config.make_build_request("forged", 7, "debug");
    const rwn::core::BuildEvidence evidence{
        .exit_code = 0, .stdout_log = {}, .stderr_log = {},
        .elapsed = std::chrono::milliseconds{1}, .timed_out = false,
        .cancelled = false, .stdout_truncated = false,
        .stderr_truncated = false};
    auto forged_evidence = rwn::protocol::BuildStatusReply{
        .accepted = true, .build_id = "forged",
        .state = rwn::protocol::BuildWireState::succeeded,
        .exit_code = 0, .elapsed_ms = 1, .timed_out = false,
        .cancelled = false, .stdout_truncated = false,
        .stderr_truncated = false, .stdout_log = {}, .stderr_log = {},
        .evidence_sha256 = rwn::core::build_evidence_sha256(request, evidence),
        .artifact_ids = {},
        .reason_code = "build_succeeded"};
    forged_evidence.evidence_sha256.front() =
        forged_evidence.evidence_sha256.front() == '0' ? '1' : '0';
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::client::verify_build_evidence(request, forged_evidence));
        },
        "build evidence hash forgery");
}

void workspace_client_rejects_forged_reply_correlation() {
    const auto root = std::filesystem::temp_directory_path() /
        ("rwn-workspace-client-security-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(root);
    const rwn::core::WorkspaceManifest manifest{
        .workspace_id = "game",
        .revision = 1,
        .entries = {},
    };
    SecurityControlStream stream;
    stream.input = rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::workspace_diff,
        .correlation_id = "manifest-forged",
        .payload = rwn::protocol::encode_workspace_diff_reply({
            .accepted = true,
            .current_revision = 0,
            .requested_file_paths = {},
            .reason_code = "workspace_diff_ready",
        }),
        .unknown_fields = {},
    });
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::client::sync_workspace(
                stream, root, manifest, "session-1"));
        },
        "workspace client reply correlation binding");
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}

void node_control_rejects_unverified_peer_and_malformed_wire() {
    using namespace std::chrono_literals;
    using enum rwn::core::Capability;
    constexpr auto fingerprint =
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    const auto now = rwn::core::WallClock::time_point{} + 700h;
    const auto certificate = rwn::core::PeerCertificate{
        .device_id = "client-a",
        .fingerprint = fingerprint,
        .serial = "serial-a",
        .not_before = now - 1h,
        .not_after = now + 1h,
    };
    rwn::node::NodeControlService service({
        .principal_id = "client-a",
        .workspaces = {"game"},
        .allowed = {workspace_read},
    }, 1);
    service.pair_device({
        .id = "client-a",
        .display_name = "Client A",
        .fingerprint = fingerprint,
        .certificate = certificate,
        .revoked = false,
    });
    const auto command = rwn::protocol::SessionOpenCommand{
        .device_id = "client-a",
        .session_id = "session-a",
        .workspace_id = "game",
        .requested_capabilities = {"workspace.read"},
        .lease_minutes = 1,
    };
    const auto unverified = service.open_session(
        command,
        {.tls_1_3_negotiated = true,
         .client_certificate_present = true,
         .certificate_chain_valid = true,
         .revocation_checked = false,
         .certificate = certificate},
        now);
    RWN_CHECK(!unverified.accepted);
    RWN_CHECK(unverified.reason_code == "session_denied");
    RWN_CHECK(service.audit().events().back().reason_code ==
              "mtls_authentication_denied");

    auto rebound = command;
    rebound.device_id = "client-b";
    const auto rebound_reply = service.open_session(
        rebound,
        {.tls_1_3_negotiated = true,
         .client_certificate_present = true,
         .certificate_chain_valid = true,
         .revocation_checked = true,
         .certificate = certificate},
        now);
    RWN_CHECK(!rebound_reply.accepted);
    RWN_CHECK(rebound_reply.reason_code == "identity_binding_denied");

    auto invalid_lease = command;
    invalid_lease.lease_minutes = 61;
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(service.open_session(
                invalid_lease,
                {.tls_1_3_negotiated = true,
                 .client_certificate_present = true,
                 .certificate_chain_valid = true,
                 .revocation_checked = true,
                 .certificate = certificate},
                now));
        },
        "direct service lease validation");

    auto duplicate = command;
    duplicate.requested_capabilities.push_back("workspace.read");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::protocol::encode_session_open_command(duplicate));
        },
        "duplicate session capabilities");
    auto trailing = rwn::protocol::encode_session_open_command(command);
    trailing.push_back(std::byte{});
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::protocol::decode_session_open_command(trailing));
        },
        "trailing session command bytes");

    SecurityControlStream client_stream;
    client_stream.input = rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::session_open,
        .correlation_id = "session-forged",
        .payload = rwn::protocol::encode_session_open_reply({
            .accepted = true,
            .granted_capabilities = {"workspace.read"},
            .denied_capabilities = {},
            .reason_code = "session_opened",
        }),
        .unknown_fields = {},
    });
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::client::open_remote_session(client_stream, command));
        },
        "client session correlation binding");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(rwn::protocol::encode_session_open_reply({
                .accepted = true,
                .granted_capabilities = {"workspace.read"},
                .denied_capabilities = {"workspace.read"},
                .reason_code = "session_opened",
            }));
        },
        "overlapping session reply capability sets");

    SecurityControlStream malformed;
    malformed.input = rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::command_exec,
        .correlation_id = "wrong-type",
        .payload = rwn::protocol::encode_session_open_command(command),
        .unknown_fields = {},
    });
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(service.serve_session_open(
                malformed,
                {.certificate_sha256 =
                     rwn::transport::parse_apple_network_sha256_fingerprint(
                         fingerprint),
                 .tls_1_3_negotiated = true,
                 .certificate_chain_valid = true,
                 .revocation_checked = true},
                now));
        },
        "non-authentication control envelope");
    RWN_CHECK(malformed.writes.empty());
    RWN_CHECK(service.audit().events().back().reason_code ==
              "protocol_invalid");

    const auto wrong_fingerprint = service.open_session(
        command,
        {.certificate_sha256 =
             rwn::transport::parse_apple_network_sha256_fingerprint(
                 "00112233445566778899aabbccddeeff"
                 "00112233445566778899aabbccddeeff"),
         .tls_1_3_negotiated = true,
         .certificate_chain_valid = true,
         .revocation_checked = true},
        now);
    RWN_CHECK(!wrong_fingerprint.accepted);
    RWN_CHECK(wrong_fingerprint.reason_code == "session_denied");
    RWN_CHECK(service.audit().events().back().reason_code ==
              "mtls_authentication_denied");

    const auto accepted = service.open_session(
        command,
        {.tls_1_3_negotiated = true,
         .client_certificate_present = true,
         .certificate_chain_valid = true,
         .revocation_checked = true,
         .certificate = certificate},
        now);
    RWN_CHECK(accepted.accepted);
    const auto duplicate_reply = service.open_session(
        command,
        {.tls_1_3_negotiated = true,
         .client_certificate_present = true,
         .certificate_chain_valid = true,
         .revocation_checked = true,
         .certificate = certificate},
        now);
    RWN_CHECK(!duplicate_reply.accepted);
    RWN_CHECK(duplicate_reply.reason_code == "session_duplicate");
    rwn::test::require_throws<std::logic_error>(
        [&] { static_cast<void>(service.health("session-a", now + 2min)); },
        "expired node control session health");
}

void apple_network_contract_rejects_implicit_identity_and_unbounded_queues() {
    const auto peer =
        rwn::transport::parse_apple_network_sha256_fingerprint(
            "00112233445566778899aabbccddeeff"
            "102030405060708090a0b0c0d0e0f001");
    const auto valid = rwn::transport::AppleNetworkClientOptions{
        .identity = {
            .keychain_persistent_reference = {std::byte{0x01}},
            .allowed_peer_certificate_sha256 = {peer},
        },
    };
    rwn::transport::validate_apple_network_client_options(valid);

    rwn::test::require_throws<std::invalid_argument>(
        [] {
            rwn::transport::validate_authenticated_peer_evidence({});
        },
        "empty authenticated peer evidence");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::transport::single_allowed_peer_evidence(
                std::array{peer, peer}));
        },
        "ambiguous authenticated listener peer");

    auto missing_identity = valid;
    missing_identity.identity.keychain_persistent_reference.clear();
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::transport::validate_apple_network_client_options(
                missing_identity);
        },
        "missing Keychain persistent reference");
    auto missing_peers = valid;
    missing_peers.identity.allowed_peer_certificate_sha256.clear();
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::transport::validate_apple_network_client_options(
                missing_peers);
        },
        "missing paired peer allowlist");
    auto duplicate_peers = valid;
    duplicate_peers.identity.allowed_peer_certificate_sha256.push_back(peer);
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::transport::validate_apple_network_client_options(
                duplicate_peers);
        },
        "duplicate paired peer identity");
    auto unbounded_queue = valid;
    unbounded_queue.maximum_pending_streams = 0;
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::transport::validate_apple_network_client_options(
                unbounded_queue);
        },
        "unbounded Apple Network stream queue");
    auto excessive_timeout = valid;
    excessive_timeout.connect_timeout = std::chrono::minutes{3};
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::transport::validate_apple_network_client_options(
                excessive_timeout);
        },
        "excessive Apple Network connect timeout");

    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(
                rwn::transport::parse_apple_network_sha256_fingerprint(
                    "00112233"));
        },
        "short Apple Network fingerprint");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(
                rwn::transport::parse_apple_network_sha256_fingerprint(
                    "00112233445566778899aabbccddeeff"
                    "102030405060708090a0b0c0d0e0f00Z"));
        },
        "non-hex Apple Network fingerprint");
    RWN_CHECK(!rwn::transport::apple_network_peer_allowed({}, peer));

    const auto valid_server = rwn::transport::AppleNetworkServerOptions{
        .identity = valid.identity,
        .listen_port = 4433,
    };
    auto no_port = valid_server;
    no_port.listen_port = 0;
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::transport::validate_apple_network_server_options(no_port);
        },
        "zero Apple Network listen port");
    auto excessive_pending = valid_server;
    excessive_pending.maximum_pending_connections = 1025;
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::transport::validate_apple_network_server_options(
                excessive_pending);
        },
        "excessive Apple Network pending connections");
}

class CountingOpusCodec final : public rwn::audio::OpusCodec {
public:
    std::vector<std::byte> encode(const rwn::audio::PcmFrame&) override {
        ++calls;
        return {std::byte{1}};
    }
    rwn::audio::PcmFrame decode(const rwn::audio::AudioPacket&) override {
        ++calls;
        return {};
    }
    rwn::audio::PcmFrame conceal_loss(std::uint16_t) override {
        ++calls;
        return {};
    }
    int calls{};
};

class DenyingUpdateSignatureVerifier final
    : public rwn::core::UpdateSignatureVerifier {
public:
    bool verify(
        std::span<const std::byte>,
        std::span<const std::byte>) const override {
        ++calls;
        return false;
    }
    mutable int calls{};
};

class UntimestampedAudioCapture final
    : public rwn::audio::AudioCaptureBackend {
public:
    std::optional<rwn::audio::CapturedPcmFrame> capture(
        std::chrono::milliseconds) override {
        return rwn::audio::CapturedPcmFrame{
            .frame = {
                .sample_rate = rwn::audio::opus_sample_rate,
                .channels = rwn::audio::opus_channels,
                .samples_per_channel = rwn::audio::opus_frame_samples,
                .interleaved_samples = std::vector<std::int16_t>(
                    rwn::audio::opus_channels *
                    rwn::audio::opus_frame_samples),
            },
            .captured_at_us = 0,
        };
    }
};

class CountingInputBackend final : public rwn::desktop::InputBackend {
public:
    void raw_key(std::uint32_t, bool) override { ++calls; }
    void text_commit(std::string_view) override { ++calls; }
    void pointer_move(std::uint16_t, std::uint16_t) override { ++calls; }
    void pointer_button(std::uint8_t, bool) override { ++calls; }
    void pointer_wheel(std::int32_t, bool) override { ++calls; }
    int calls{};
};

class DeniedTransport final : public rwn::transport::Transport {
public:
    std::unique_ptr<rwn::transport::ReliableStream> open_stream(
        rwn::transport::StreamPurpose) override {
        ++calls;
        return {};
    }
    void send_datagram(
        rwn::transport::DatagramChannel,
        std::span<const std::byte>) override {
        ++calls;
    }
    int calls{};
};

class SecurityTransportConnector final
    : public rwn::transport::TransportConnector {
public:
    std::unique_ptr<rwn::transport::Transport> connect(
        rwn::transport::TransportMode,
        const rwn::transport::TransportEndpoint&,
        const rwn::transport::QuicTransportSettings&) override {
        auto result = std::make_unique<DeniedTransport>();
        connection = result.get();
        return result;
    }
    bool migrate(
        rwn::transport::Transport&,
        const rwn::transport::TransportEndpoint&) override {
        return false;
    }
    DeniedTransport* connection{};
};

[[nodiscard]] rwn::transport::EncryptedPlaneEvidence
valid_fallback_evidence(
    const rwn::transport::EncryptedPlaneProtocol protocol) {
    rwn::transport::EncryptedPlaneEvidence result{
        .protocol = protocol,
        .chain_validated = true,
        .revocation_checked = true,
    };
    result.peer_certificate_sha256.fill(0x31);
    result.channel_binding.fill(0x42);
    return result;
}

class SecurityFallbackStream final
    : public rwn::transport::ReliableStream {
public:
    void write(std::span<const std::byte>) override {}
    std::vector<std::byte> read() override { return {}; }
};

class SecurityFallbackReliablePlane final
    : public rwn::transport::FallbackReliablePlane {
public:
    explicit SecurityFallbackReliablePlane(
        rwn::transport::EncryptedPlaneEvidence evidence)
        : evidence_(std::move(evidence)) {}

    const rwn::transport::EncryptedPlaneEvidence& evidence() const override {
        return evidence_;
    }
    std::unique_ptr<rwn::transport::ReliableStream> open_stream(
        rwn::transport::StreamPurpose) override {
        if (null_open) return {};
        return std::make_unique<SecurityFallbackStream>();
    }
    rwn::transport::AcceptedStream accept_stream(
        std::chrono::milliseconds) override {
        return {
            .purpose = rwn::transport::StreamPurpose::command,
            .stream = null_accept
                ? std::unique_ptr<rwn::transport::ReliableStream>{}
                : std::make_unique<SecurityFallbackStream>(),
        };
    }

    rwn::transport::EncryptedPlaneEvidence evidence_;
    bool null_open{};
    bool null_accept{};
};

class SecurityFallbackDatagramPlane final
    : public rwn::transport::FallbackDatagramPlane {
public:
    explicit SecurityFallbackDatagramPlane(
        rwn::transport::EncryptedPlaneEvidence evidence)
        : evidence_(std::move(evidence)) {}

    const rwn::transport::EncryptedPlaneEvidence& evidence() const override {
        return evidence_;
    }
    void send_datagram(
        rwn::transport::DatagramChannel,
        std::span<const std::byte>) override {}
    rwn::transport::ReceivedDatagram receive_datagram(
        std::chrono::milliseconds) override {
        return received;
    }

    rwn::transport::EncryptedPlaneEvidence evidence_;
    rwn::transport::ReceivedDatagram received{
        .channel = rwn::transport::DatagramChannel::audio,
        .payload = {std::byte{0x01}},
    };
};

class SecurityFallbackProvider final
    : public rwn::transport::EncryptedFallbackProvider {
public:
    std::unique_ptr<rwn::transport::FallbackReliablePlane> connect_tls13(
        const rwn::transport::TransportEndpoint&,
        const rwn::transport::QuicTransportSettings&) override {
        return std::make_unique<SecurityFallbackReliablePlane>(
            valid_fallback_evidence(
                rwn::transport::EncryptedPlaneProtocol::tls13));
    }
    std::unique_ptr<rwn::transport::FallbackDatagramPlane> connect_dtls12(
        const rwn::transport::TransportEndpoint&,
        const rwn::transport::QuicTransportSettings&) override {
        return std::make_unique<SecurityFallbackDatagramPlane>(
            valid_fallback_evidence(
                rwn::transport::EncryptedPlaneProtocol::dtls12));
    }
};

class RejectingTerminalBackend final : public rwn::core::TerminalBackend {
public:
    void open(
        const rwn::core::CommandSpec&,
        const std::filesystem::path&,
        rwn::core::TerminalSize) override {
        opened = true;
    }
    void resize(rwn::core::TerminalSize) override {}
    std::size_t write(std::span<const std::byte> input) override {
        return input.size();
    }
    std::vector<std::byte> read(std::size_t maximum) override {
        return std::vector<std::byte>(maximum + 1);
    }
    void close() noexcept override {}
    bool opened{};
};

class CountingDeploymentBackend final : public rwn::core::DeploymentBackend {
public:
    rwn::core::BuildEvidence stop() override {
        ++calls;
        return {.exit_code = 0};
    }
    void stage_previous(std::string_view) override { ++calls; }
    void install(
        std::string_view, const std::filesystem::path&,
        const rwn::core::Artifact&) override {
        ++calls;
    }
    rwn::core::BuildEvidence start() override {
        ++calls;
        return {.exit_code = 0};
    }
    rwn::core::BuildEvidence health_check() override {
        ++calls;
        return {.exit_code = 0};
    }
    void restore_previous(std::string_view) override { ++calls; }
    int calls{};
};

void malformed_envelope_is_rejected() {
    const std::vector<std::byte> invalid{std::byte{'B'}, std::byte{'A'}, std::byte{'D'}};
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(rwn::protocol::decode(invalid)); }, "malformed envelope");
}

void declared_oversized_payload_is_rejected() {
    std::vector<std::byte> bytes{
        std::byte{'R'}, std::byte{'W'}, std::byte{'N'}, std::byte{'1'},
        std::byte{0}, std::byte{1}, std::byte{0}, std::byte{1},
        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{2}, std::byte{0}, std::byte{0}, std::byte{0},
        std::byte{0}, std::byte{0},
    };
    rwn::test::require_throws<std::length_error>(
        [&] { static_cast<void>(rwn::protocol::decode(bytes)); }, "oversized declared payload");
}

void workspace_traversal_and_absolute_paths_are_rejected() {
    const auto root = std::filesystem::temp_directory_path() / "rwn-security-workspace";
    std::filesystem::create_directories(root / "src");
    const rwn::core::WorkspaceScope scope(root);

    RWN_CHECK(scope.resolve("src/main.cpp").parent_path() == std::filesystem::weakly_canonical(root / "src"));
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(scope.resolve("../secret.txt")); }, "parent traversal");
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(scope.resolve(std::filesystem::temp_directory_path())); }, "absolute path");

    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}

void sibling_prefix_is_not_treated_as_workspace_child() {
    const auto base = std::filesystem::temp_directory_path() / "rwn-prefix-test";
    const auto root = base / "workspace";
    const auto sibling = base / "workspace-secret";
    std::filesystem::create_directories(root);
    std::filesystem::create_directories(sibling);
    const rwn::core::WorkspaceScope scope(root);
    RWN_CHECK(!scope.contains_resolved(sibling / "key.txt"));
    std::error_code ignored;
    std::filesystem::remove_all(base, ignored);
}

void wrong_principal_and_workspace_are_denied() {
    using enum rwn::core::Capability;
    const rwn::core::Policy policy{
        .principal_id = "agent-a", .workspaces = {"allowed"}, .allowed = {workspace_read}};
    rwn::core::CapabilityRequest wrong_principal;
    wrong_principal.principal.id = "agent-b";
    wrong_principal.principal.kind = rwn::core::PrincipalKind::agent;
    wrong_principal.workspace = "allowed";
    wrong_principal.requested = {workspace_read};
    rwn::core::CapabilityRequest wrong_workspace;
    wrong_workspace.principal.id = "agent-a";
    wrong_workspace.principal.kind = rwn::core::PrincipalKind::agent;
    wrong_workspace.workspace = "private";
    wrong_workspace.requested = {workspace_read};
    RWN_CHECK(!rwn::core::authorize(wrong_principal, policy).permits(workspace_read));
    RWN_CHECK(!rwn::core::authorize(wrong_workspace, policy).permits(workspace_read));
}

void agent_policy_denies_high_risk_capabilities() {
    using enum rwn::core::Capability;
    rwn::core::CapabilityRequest request;
    request.principal.id = "agent-a";
    request.principal.kind = rwn::core::PrincipalKind::agent;
    request.workspace = "game";
    request.requested = {agent_run, command_exec, terminal_open,
                         desktop_control, clipboard_read, system_admin};
    const auto result = rwn::core::authorize(
        request, rwn::core::default_agent_policy("agent-a", "game"));
    RWN_CHECK(result.granted.empty());
    RWN_CHECK(result.denied == request.requested);

    const auto explicit_policy = rwn::core::load_policy_file(
        std::filesystem::path(RWN_SOURCE_DIR) / "config" /
        "agent-policy.example.toml");
    rwn::core::CapabilityRequest explicit_request;
    explicit_request.principal.id = "coding-agent";
    explicit_request.principal.kind = rwn::core::PrincipalKind::agent;
    explicit_request.workspace = "example-workspace";
    explicit_request.requested = {
        agent_run, workspace_read, workspace_write, build_submit, test_run,
        artifact_read, git_status, git_diff, command_exec, terminal_open,
        desktop_control, clipboard_read, system_admin};
    const auto explicit_result = rwn::core::authorize(
        explicit_request, explicit_policy);
    RWN_CHECK(explicit_result.permits(agent_run));
    RWN_CHECK(explicit_result.permits(workspace_read));
    RWN_CHECK(explicit_result.permits(workspace_write));
    RWN_CHECK(explicit_result.permits(build_submit));
    RWN_CHECK(explicit_result.permits(test_run));
    RWN_CHECK(explicit_result.permits(artifact_read));
    RWN_CHECK(explicit_result.permits(git_status));
    RWN_CHECK(explicit_result.permits(git_diff));
    RWN_CHECK(!explicit_result.permits(command_exec));
    RWN_CHECK(!explicit_result.permits(terminal_open));
    RWN_CHECK(!explicit_result.permits(desktop_control));
    RWN_CHECK(!explicit_result.permits(clipboard_read));
    RWN_CHECK(!explicit_result.permits(system_admin));
}

void protocol_and_release_gates_reject_malformed_or_malicious_inputs() {
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(
                rwn::protocol::run_envelope_mutation_gate(0, 4096));
        },
        "zero protocol corpus seed");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(
                rwn::protocol::run_envelope_mutation_gate(42, 8));
        },
        "undersized protocol corpus");
    auto mutation_report =
        rwn::protocol::run_envelope_mutation_gate(42, 256);
    mutation_report.accepted += 1;
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::protocol::render_protocol_mutation_json(
                    mutation_report));
        },
        "forged protocol mutation report");

    for (const std::string_view manifest : {
             "file\t../escape\t1\t1\t0644\t-\n",
             "file\t.git/hooks/pre-commit\t1\t1\t0755\t-\n",
             "file\tCON.txt\t1\t1\t0644\t-\n",
             "file\tpayload\t1000001\t1000\t0644\t-\n",
             "file\tApp\t1\t1\t0644\t-\nfile\tapp\t1\t1\t0644\t-\n",
             "symlink\tlink\t0\t0\t0777\t../outside\n",
             "file\tbad-mode\t1\t1\t0777\t-\n"}) {
        rwn::test::require_throws<std::exception>(
            [&] {
                static_cast<void>(rwn::core::validate_archive_manifest(
                    rwn::core::parse_archive_manifest(manifest)));
            },
            "malicious archive manifest");
    }

    const std::string hash(64, 'a');
    const auto repository = [&](rwn::core::WorkspaceEntry entry) {
        return rwn::core::WorkspaceManifest{
            .workspace_id = "malicious-repository",
            .revision = 1,
            .entries = {std::move(entry)},
        };
    };
    for (auto manifest : {
             repository({.path = ".gitmodules",
                         .kind = rwn::core::WorkspaceEntryKind::file,
                         .size = 10, .content_hash = hash, .mode = 0644,
                         .symlink_target = {}}),
             repository({.path = ".git/hooks/pre-commit",
                         .kind = rwn::core::WorkspaceEntryKind::file,
                         .size = 10, .content_hash = hash, .mode = 0755,
                         .symlink_target = {}}),
             repository({.path = "script.sh",
                         .kind = rwn::core::WorkspaceEntryKind::file,
                         .size = 10, .content_hash = hash, .mode = 04755,
                         .symlink_target = {}}),
             repository({.path = "dangling",
                         .kind = rwn::core::WorkspaceEntryKind::symlink,
                         .size = 0, .content_hash = {}, .mode = 0777,
                         .symlink_target = "missing"})}) {
        rwn::test::require_throws<std::exception>(
            [&] {
                static_cast<void>(
                    rwn::core::validate_repository_release(manifest));
            },
            "malicious repository manifest");
    }
}

void update_policy_rejects_downgrade_tampering_and_unsigned_metadata() {
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(rwn::core::parse_semantic_version("00.1.0"));
        },
        "noncanonical semantic version");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(rwn::core::load_update_manifest(
                std::filesystem::path(RWN_SOURCE_DIR) /
                "config/update-manifest.example.toml"));
        },
        "unsigned example update manifest");

    auto policy = rwn::core::load_release_compatibility(
        std::filesystem::path(RWN_SOURCE_DIR) /
        "config/version-compatibility.toml");
    RWN_CHECK(!rwn::core::peer_is_compatible(
        policy, rwn::core::parse_semantic_version("0.1.0"), 2, 3));
    RWN_CHECK(!rwn::core::state_schema_is_readable(policy, 0));

    const auto root = std::filesystem::temp_directory_path() /
                      "rwn-update-security-unit";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root);
    const auto package = root / "release.zip";
    {
        std::ofstream output(package, std::ios::binary);
        output << "candidate bytes\n";
    }
    rwn::core::UpdateManifest manifest{
        .version = rwn::core::parse_semantic_version("0.1.0"),
        .minimum_installed_version =
            rwn::core::parse_semantic_version("0.0.1"),
        .platform = "windows",
        .architecture = "amd64",
        .package_sha256 = rwn::core::sha256_file(package),
        .package_size = std::filesystem::file_size(package),
        .state_schema = 1,
        .package_schema = 1,
        .signature_algorithm = "ecdsa-p256-sha256",
        .signature_hex = std::string(128, '1'),
    };
    DenyingUpdateSignatureVerifier verifier;
    rwn::test::require_throws<std::runtime_error>(
        [&] {
            static_cast<void>(rwn::core::verify_update_candidate(
                manifest, rwn::core::parse_semantic_version("0.0.1"),
                policy, "windows", "amd64", package, verifier));
        },
        "rejected update signature");
    RWN_CHECK(verifier.calls == 1);

    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::core::verify_update_candidate(
                manifest, rwn::core::parse_semantic_version("0.1.0"),
                policy, "windows", "amd64", package, verifier));
        },
        "update downgrade or reinstall");
    auto tampered = manifest;
    tampered.package_sha256 = std::string(64, 'a');
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::core::verify_update_candidate(
                tampered, rwn::core::parse_semantic_version("0.0.1"),
                policy, "windows", "amd64", package, verifier));
        },
        "tampered update package");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::core::verify_update_candidate(
                manifest, rwn::core::parse_semantic_version("0.0.1"),
                policy, "macos", "arm64", package, verifier));
        },
        "cross-platform update package");
    std::filesystem::remove_all(root, ignored);
}

void protected_release_state_is_bounded_and_complete() {
    const auto root = std::filesystem::temp_directory_path() /
                      "rwn-protected-state-security";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root / "pairing");
    std::filesystem::create_directories(root / "workspaces");
    std::filesystem::create_directories(root / "audit");
    std::ofstream(root / "pairing/device.key", std::ios::binary)
        << "secret-key-material";
    const auto snapshot = rwn::core::capture_protected_state(root);
    RWN_CHECK(snapshot.entries.size() == 4);
    RWN_CHECK(snapshot.total_bytes == 19);
    RWN_CHECK(rwn::core::is_sha256_hex(snapshot.inventory_sha256));

    std::filesystem::create_hard_link(
        root / "pairing/device.key", root / "workspaces/key-alias");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::core::capture_protected_state(root));
        },
        "protected state hard-link alias");
    std::filesystem::remove(root / "workspaces/key-alias");

    rwn::test::require_throws<std::length_error>(
        [&] {
            static_cast<void>(rwn::core::capture_protected_state(
                root, {.maximum_entries = 100,
                       .maximum_file_bytes = 4,
                       .maximum_total_bytes = 1024}));
        },
        "oversized protected state file");
    rwn::test::require_throws<std::length_error>(
        [&] {
            static_cast<void>(rwn::core::capture_protected_state(
                root, {.maximum_entries = 3,
                       .maximum_file_bytes = 1024,
                       .maximum_total_bytes = 1024}));
        },
        "protected state entry limit");
    std::filesystem::remove(root / "audit");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::core::capture_protected_state(root));
        },
        "missing protected state partition");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(rwn::core::capture_protected_state(
                std::filesystem::path("relative-state")));
        },
        "relative protected state root");
    std::filesystem::remove_all(root, ignored);
}

void release_diagnostics_reject_freeform_or_forged_evidence() {
    const auto hash = std::string(64, 'a');
    rwn::core::ReleaseDiagnosticBundle bundle;
    bundle.schema_version = 1;
    bundle.bundle_id = "diagnostic-security";
    bundle.product_version = rwn::core::parse_semantic_version("0.1.0");
    bundle.platform = "windows";
    bundle.architecture = "amd64";
    bundle.generated_at_unix_ms = 1;
    bundle.compatibility.available = true;
    bundle.compatibility.protocol_minimum = 1;
    bundle.compatibility.protocol_maximum = 1;
    bundle.compatibility.state_schema = 1;
    bundle.compatibility.package_schema = 1;
    bundle.protected_state.available = true;
    bundle.protected_state.entries = 3;
    bundle.protected_state.total_bytes = 0;
    bundle.protected_state.inventory_sha256 = hash;
    bundle.update = std::nullopt;
    bundle.checks.push_back(rwn::core::make_boolean_diagnostic(
        rwn::core::DiagnosticComponent::node,
        rwn::core::DiagnosticOperation::self_check, true));
    rwn::core::validate_release_diagnostic_bundle(bundle);
    const auto json = rwn::core::render_release_diagnostic_json(bundle);
    RWN_CHECK(json.find("clipboard") == std::string::npos);
    RWN_CHECK(json.find("authorization") == std::string::npos);
    RWN_CHECK(json.find("environment") == std::string::npos);
    RWN_CHECK(json.find("endpoint") == std::string::npos);

    auto injected = bundle;
    injected.platform = "../windows\nsecret";
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::core::validate_release_diagnostic_bundle(injected);
        },
        "diagnostic target injection");
    auto duplicated = bundle;
    duplicated.checks.push_back(duplicated.checks.front());
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::core::validate_release_diagnostic_bundle(duplicated);
        },
        "duplicate diagnostic check");
    auto forged_failure = bundle;
    forged_failure.checks.front().result =
        rwn::core::DiagnosticResult::failed;
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::core::validate_release_diagnostic_bundle(forged_failure);
        },
        "failed diagnostic with successful evidence");
    auto oversized = bundle;
    oversized.checks.front().stdout_bytes =
        16ULL * 1024ULL * 1024ULL + 1ULL;
    rwn::test::require_throws<std::length_error>(
        [&] {
            rwn::core::validate_release_diagnostic_bundle(oversized);
        },
        "oversized diagnostic telemetry");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(rwn::core::make_runtime_diagnostic(
                rwn::core::DiagnosticComponent::node,
                rwn::core::DiagnosticOperation::self_check,
                {.exit_code = 0,
                 .stdout_log = {},
                 .stderr_log = {},
                 .elapsed = std::chrono::milliseconds(-1),
                 .timed_out = false,
                 .cancelled = false,
                 .stdout_truncated = false,
                 .stderr_truncated = false}));
        },
        "negative diagnostic duration");
}

#if defined(RWN_TEST_WINDOWS_PLATFORM)
void update_signature_public_key_is_bounded() {
    const std::array<std::byte, 63> short_key{};
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::platform::windows::CngEcdsaP256UpdateVerifier(short_key));
        },
        "short update public key");
    const std::array<std::byte, 64> zero_key{};
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::platform::windows::CngEcdsaP256UpdateVerifier(zero_key));
        },
        "zero update public key");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            const std::array<std::byte, 63> short_signature{};
            static_cast<void>(
                rwn::core::ecdsa_p256_signature_der(short_signature));
        },
        "short raw P-256 signature");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            const std::array<std::byte, 64> zero_signature{};
            static_cast<void>(
                rwn::core::ecdsa_p256_signature_der(zero_signature));
        },
        "zero raw P-256 signature");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            std::array<std::byte, 64> zero_r{};
            zero_r.back() = std::byte{1};
            static_cast<void>(rwn::core::ecdsa_p256_signature_der(zero_r));
        },
        "zero P-256 r component");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            std::array<std::byte, 64> zero_s{};
            zero_s.front() = std::byte{1};
            static_cast<void>(rwn::core::ecdsa_p256_signature_der(zero_s));
        },
        "zero P-256 s component");
}
#endif

void pairing_rejects_wrong_code_expired_challenge_and_revoked_device() {
    using namespace std::chrono_literals;
    constexpr auto fingerprint = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const auto now = rwn::core::WallClock::time_point{} + 100h;
    rwn::core::DeviceRegistry registry;
    rwn::core::PairingService pairing(registry);
    const auto challenge = pairing.begin(
        {.node_id = "mac-node", .node_name = "Mac node", .lan_endpoint = "10.0.0.1:4433", .fingerprint = fingerprint},
        "123456", now, 1min);
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(pairing.confirm(challenge, "654321", "client-a", "Client", fingerprint, now, 1h)); },
        "wrong pairing code");
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(pairing.confirm(challenge, "123456", "client-a", "Client", fingerprint, now + 1min, 1h)); },
        "expired pairing challenge");

    const auto certificate = pairing.confirm(challenge, "123456", "client-a", "Client", fingerprint, now, 1h);
    registry.revoke("client-a");
    RWN_CHECK(registry.verify(certificate, now) == rwn::core::PeerVerification::revoked);
}

void mtls_gate_requires_tls13_certificate_and_active_pairing() {
    using namespace std::chrono_literals;
    constexpr auto fingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const auto now = rwn::core::WallClock::time_point{} + 100h;
    rwn::core::DeviceRegistry registry;
    rwn::core::PairingService pairing(registry);
    const auto challenge = pairing.begin(
        {.node_id = "node", .node_name = "Node", .lan_endpoint = "10.0.0.1:4433", .fingerprint = fingerprint},
        "123456", now, 1min);
    const auto certificate = pairing.confirm(challenge, "123456", "client", "Client", fingerprint, now, 1h);
    const rwn::core::MtlsTrustGate gate;
    RWN_CHECK(gate.verify({.tls_1_3_negotiated = false, .client_certificate_present = true, .certificate_chain_valid = true, .revocation_checked = true, .certificate = certificate}, registry, now) ==
              rwn::core::MtlsVerification::tls_version_rejected);
    RWN_CHECK(gate.verify({.tls_1_3_negotiated = true, .client_certificate_present = false, .certificate_chain_valid = true, .revocation_checked = true, .certificate = certificate}, registry, now) ==
              rwn::core::MtlsVerification::certificate_missing);
    RWN_CHECK(gate.verify({.tls_1_3_negotiated = true, .client_certificate_present = true, .certificate_chain_valid = false, .revocation_checked = true, .certificate = certificate}, registry, now) ==
              rwn::core::MtlsVerification::certificate_chain_rejected);
    RWN_CHECK(gate.verify({.tls_1_3_negotiated = true, .client_certificate_present = true, .certificate_chain_valid = true, .revocation_checked = false, .certificate = certificate}, registry, now) ==
              rwn::core::MtlsVerification::revocation_unverified);
    registry.revoke("client");
    RWN_CHECK(gate.verify({.tls_1_3_negotiated = true, .client_certificate_present = true, .certificate_chain_valid = true, .revocation_checked = true, .certificate = certificate}, registry, now) ==
              rwn::core::MtlsVerification::certificate_rejected);
}

void manifest_rejects_traversal_case_unsafe_paths_and_invalid_chunks() {
    RWN_CHECK(!rwn::core::is_canonical_workspace_path("../secret"));
    RWN_CHECK(!rwn::core::is_canonical_workspace_path("src\\main.cpp"));
    rwn::test::require_throws<std::invalid_argument>([] { rwn::core::ChunkResumeLedger ledger(1); ledger.confirm(0, 0, "hash"); }, "empty chunk");
    rwn::test::require_throws<std::invalid_argument>([] { rwn::core::ChunkResumeLedger ledger(1); ledger.confirm(0, rwn::core::ChunkResumeLedger::max_chunk_size + 1, "hash"); }, "oversized chunk");
}

void command_environment_is_deny_by_default() {
    using namespace std::chrono_literals;
    rwn::test::require_throws<std::invalid_argument>([] {
        rwn::core::validate_command({.argv = {"cmake"}, .working_directory = ".", .timeout = 1min, .environment = {{"HOME", "private"}}}, {});
    }, "unallowlisted environment");
    rwn::test::require_throws<std::invalid_argument>([] {
        rwn::core::validate_command(
            {.argv = {"/usr/bin/true"},
             .working_directory = ".",
             .timeout = 1min,
             .environment = {{"SAFE", std::string("ok\0secret", 9)}}},
            {"SAFE"});
    }, "NUL in allowlisted environment value");
}

void pairing_store_rejects_escape_tampering_and_replacement() {
    using namespace std::chrono_literals;
    const auto root = std::filesystem::temp_directory_path() /
        "rwn-security-pairing-store";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root);
    rwn::test::TestDurableFileSystem filesystem;
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::core::PairingStore relative(
                "relative-pairing", "device.state", filesystem);
        },
        "relative pairing root");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::core::PairingStore escape(root, "../device.state", filesystem);
        },
        "pairing state traversal");
    rwn::core::PairingStore store(root, "device.state", filesystem);
    const auto now = rwn::core::TimePoint{100h};
    const rwn::core::PairedDevice device{
        .id = "windows-client",
        .display_name = "Windows Client",
        .fingerprint =
            "0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef",
        .certificate = {
            .device_id = "windows-client",
            .fingerprint =
                "0123456789abcdef0123456789abcdef"
                "0123456789abcdef0123456789abcdef",
            .serial = "client-serial-1",
            .not_before = now,
            .not_after = now + 24h,
        },
        .revoked = false,
    };
    store.create(device);
    rwn::test::require_throws<std::invalid_argument>(
        [&] { store.replace_revoked(device); },
        "active pairing rotation");
    rwn::test::require_throws<std::invalid_argument>(
        [&] { store.create(device); }, "silent pairing replacement");
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(store.revoke("other-device")); },
        "unknown pairing revocation");
    static_cast<void>(store.revoke(device.id));
    auto rebound = device;
    rebound.id = "other-device";
    rebound.certificate.device_id = rebound.id;
    rwn::test::require_throws<std::invalid_argument>(
        [&] { store.replace_revoked(rebound); },
        "revoked pairing identity replacement");
    {
        std::ofstream append(store.state_path(), std::ios::binary | std::ios::app);
        append << "unexpected=value\n";
    }
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(store.load()); },
        "unknown pairing state field");
    std::filesystem::remove_all(root, ignored);
}

void pairing_control_rejects_wrong_code_rebinding_and_forged_reply() {
    using namespace std::chrono_literals;
    constexpr auto fingerprint =
        "1234567890abcdef1234567890abcdef"
        "1234567890abcdef1234567890abcdef";
    constexpr auto other_fingerprint =
        "abcdef1234567890abcdef1234567890"
        "abcdef1234567890abcdef1234567890";
    const auto now = rwn::core::TimePoint{900h};
    const auto root = std::filesystem::temp_directory_path() /
        "rwn-security-pairing-control";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root);
    rwn::test::TestDurableFileSystem filesystem;
    rwn::core::PairingStore store(root, "device.state", filesystem);
    rwn::node::NodePairingService service({
        .id = "challenge-1",
        .node = {
            .node_id = "mac-node",
            .node_name = "Mac Node",
            .lan_endpoint = "mac-node.local:4433",
            .fingerprint = other_fingerprint,
        },
        .six_digit_code = "123456",
        .expires_at = now + 5min,
    }, "windows-client", store, 24h);
    auto command = rwn::protocol::PairingConfirmCommand{
        .six_digit_code = "654321",
        .device_id = "windows-client",
        .display_name = "Windows Client",
        .certificate_sha256 = fingerprint,
    };
    SecurityControlStream wrong_code;
    wrong_code.input = rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::pairing_confirm,
        .correlation_id = "pairing-windows-client",
        .payload = rwn::protocol::encode_pairing_confirm_command(command),
        .unknown_fields = {},
    });
    const auto denied = service.serve_confirmation(
        wrong_code,
        {.certificate_sha256 =
             rwn::transport::parse_apple_network_sha256_fingerprint(
                 fingerprint),
         .tls_1_3_negotiated = true,
         .certificate_chain_valid = true,
         .revocation_checked = true},
        now);
    RWN_CHECK(!denied.reply.accepted);
    RWN_CHECK(!store.exists());
    command.six_digit_code = "123456";
    command.certificate_sha256 = other_fingerprint;
    SecurityControlStream rebound;
    rebound.input = rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::pairing_confirm,
        .correlation_id = "pairing-windows-client",
        .payload = rwn::protocol::encode_pairing_confirm_command(command),
        .unknown_fields = {},
    });
    const auto rebound_reply = service.serve_confirmation(
        rebound,
        {.certificate_sha256 =
             rwn::transport::parse_apple_network_sha256_fingerprint(
                 fingerprint),
         .tls_1_3_negotiated = true,
         .certificate_chain_valid = true,
         .revocation_checked = true},
        now);
    RWN_CHECK(!rebound_reply.reply.accepted);
    RWN_CHECK(rebound_reply.reply.reason_code == "identity_binding_denied");
    RWN_CHECK(!store.exists());
    const rwn::transport::AuthenticatedPeerEvidence retry_peer{
        .certificate_sha256 = rwn::transport::parse_apple_network_sha256_fingerprint(fingerprint),
        .tls_1_3_negotiated = true, .certificate_chain_valid = true,
        .revocation_checked = true};
    for (unsigned attempt = 0; attempt < 3U; ++attempt) {
        SecurityControlStream retry;
        retry.input = wrong_code.input;
        RWN_CHECK(!service.serve_confirmation(retry, retry_peer, now).reply.accepted);
    }
    command.certificate_sha256 = fingerprint;
    SecurityControlStream exhausted;
    exhausted.input = rwn::protocol::encode({
        .version = 1, .type = rwn::protocol::MessageType::pairing_confirm,
        .correlation_id = "pairing-windows-client",
        .payload = rwn::protocol::encode_pairing_confirm_command(command),
        .unknown_fields = {}});
    rwn::test::require_throws<std::invalid_argument>([&] {
        static_cast<void>(service.serve_confirmation(exhausted, retry_peer, now));
    }, "correct code after exhausted window must be denied");
    RWN_CHECK(!store.exists());
    SecurityControlStream forged;
    forged.input = rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::pairing_result,
        .correlation_id = "wrong-correlation",
        .payload = rwn::protocol::encode_pairing_confirm_reply({
            .accepted = true,
            .device_id = "windows-client",
            .reason_code = "pairing_completed",
        }),
        .unknown_fields = {},
    });
    command.certificate_sha256 = fingerprint;
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::client::confirm_remote_pairing(forged, command));
        },
        "forged pairing reply correlation");
    auto trailing = rwn::protocol::encode_pairing_confirm_command(command);
    trailing.push_back(std::byte{});
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::protocol::decode_pairing_confirm_command(trailing));
        },
        "trailing pairing command bytes");
    std::filesystem::remove_all(root, ignored);
}

void workspace_paths_reject_windows_aliases_ads_and_controls() {
    for (const std::string_view path : {
             "CON", "con.txt", "src/NUL.cpp", "COM1.log", "lpt9",
             "src/file:secret", "src/trailing.", "src/trailing ",
             " leading/file", "src/control\x1f.cpp", "src/question?.cpp",
             "src/pipe|name"}) {
        RWN_CHECK(!rwn::core::is_canonical_workspace_path(path));
    }
    RWN_CHECK(rwn::core::is_canonical_workspace_path(".gitignore"));
    RWN_CHECK(rwn::core::is_canonical_workspace_path("src/concept.cpp"));
    RWN_CHECK(rwn::core::is_canonical_workspace_path("src/compile10.cpp"));
}

void desktop_wire_messages_are_strictly_bounded() {
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::fit_preview_frame({
                .frame_id = 1, .captured_at_us = 1,
                .width = 4, .height = 4, .row_stride = 15,
                .bgra = std::vector<std::byte>(60)}, 4, 4));
        },
        "preview frame with undersized stride");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::decode_preview_frame_header(
                std::vector<std::byte>(
                    rwn::desktop::preview_frame_header_size - 1U)));
        },
        "truncated preview header");
    auto forged_preview = rwn::desktop::encode_preview_frame_header({
        .frame_id = 1, .captured_at_us = 1, .width = 320, .height = 180,
        .payload_size = 320U * 180U * 4U});
    forged_preview.back() ^= std::byte{1};
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::desktop::decode_preview_frame_header(forged_preview));
        },
        "forged preview payload size");
    auto forged_encoded =
        rwn::desktop::encode_encoded_preview_frame_header({
            .frame_id = 1, .captured_at_us = 1,
            .width = 1920, .height = 1080,
            .payload_size = 1024, .keyframe = true});
    forged_encoded.at(6) = std::byte{0x80};
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::desktop::decode_encoded_preview_frame_header(
                    forged_encoded));
        },
        "encoded preview with unknown flags");
    forged_encoded =
        rwn::desktop::encode_encoded_preview_frame_header({
            .frame_id = 1, .captured_at_us = 1,
            .width = 1920, .height = 1080,
            .payload_size = 1024, .keyframe = false});
    forged_encoded.at(32) = std::byte{0xff};
    forged_encoded.at(33) = std::byte{0xff};
    forged_encoded.at(34) = std::byte{0xff};
    forged_encoded.at(35) = std::byte{0xff};
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::desktop::decode_encoded_preview_frame_header(
                    forged_encoded));
        },
        "oversized encoded preview payload");
    const auto visual_payload =
        rwn::desktop::encode_visual_h264_access_unit({
            .width = 1280,
            .height = 720,
            .encoded = std::vector<std::byte>(32, std::byte{0x65}),
        });
    auto visual_wire = rwn::desktop::encode_visual_message_header({
        .type = rwn::desktop::VisualMessageType::h264_access_unit,
        .flags = rwn::desktop::visual_flag_frame_final,
        .payload_size = static_cast<std::uint32_t>(visual_payload.size()),
        .session_generation = 1,
        .representation_epoch = 1,
        .visual_sequence = 1,
        .frame_id = 1,
        .captured_at_us = 1,
    });
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::decode_visual_message_header(
                std::span<const std::byte>(visual_wire).first(
                    visual_wire.size() - 1U)));
        },
        "truncated visual message header");
    auto unknown_visual_flags = visual_wire;
    unknown_visual_flags.at(7) = std::byte{0x80};
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::decode_visual_message_header(
                unknown_visual_flags));
        },
        "visual message with unknown flags");
    auto forged_visual_size = visual_wire;
    forged_visual_size.at(12) = std::byte{0xff};
    forged_visual_size.at(13) = std::byte{0xff};
    forged_visual_size.at(14) = std::byte{0xff};
    forged_visual_size.at(15) = std::byte{0xff};
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::decode_visual_message_header(
                forged_visual_size));
        },
        "oversized visual message payload");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::desktop::validate_visual_message_payload(
                rwn::desktop::decode_visual_message_header(visual_wire),
                std::span<const std::byte>(visual_payload).first(
                    visual_payload.size() - 1U));
        },
        "visual payload size mismatch");
    auto cursor_payload =
        rwn::desktop::encode_visual_cursor_position({
            .x = 1, .y = 2, .visible = true, .shape_id = 0});
    cursor_payload.at(9) = std::byte{1};
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::desktop::decode_visual_cursor_position(cursor_payload));
        },
        "cursor position with non-zero reserved bytes");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::encode_visual_cursor_shape({
                .shape_id = 1,
                .width = 2,
                .height = 2,
                .hotspot_x = 2,
                .hotspot_y = 0,
                .bgra = std::vector<std::byte>(16),
            }));
        },
        "cursor hotspot outside image");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::decode_visual_cursor_shape(
                std::vector<std::byte>(19)));
        },
        "truncated cursor shape");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::encode_visual_full_snapshot_chunk({
                .surface_width = 4,
                .surface_height = 4,
                .row_stride = 16,
                .pixel_format = static_cast<
                    rwn::desktop::CanonicalPixelFormat>(2),
                .total_bytes = 64,
                .chunk_offset = 0,
                .chunk = std::vector<std::byte>(64),
            }));
        },
        "snapshot with unknown canonical pixel format");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::encode_visual_raw_rect({
                .base_frame_id = 1,
                .surface_width = 4,
                .surface_height = 4,
                .x = 3,
                .y = 0,
                .width = 2,
                .height = 1,
                .row_stride = 8,
                .bgra = std::vector<std::byte>(8),
            }));
        },
        "raw rectangle outside canonical framebuffer");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::encode_frame_commit_ack({
                .session_generation = 1,
                .representation_epoch = 0,
                .frame_id = 1,
            }));
        },
        "commit ACK without representation epoch");
    const std::array<std::byte, 32> digest{};
    const auto ack_wire = rwn::desktop::encode_frame_commit_ack({
        .session_generation = 1,
        .representation_epoch = 2,
        .frame_id = 3,
        .canonical_sha256 = digest,
    });
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::decode_frame_commit_ack(
                std::span<const std::byte>(ack_wire).first(
                    ack_wire.size() - 1U)));
        },
        "truncated canonical framebuffer ACK hash");
    rwn::desktop::FullSnapshotAssemblyGuard snapshot_guard;
    const rwn::desktop::VisualMessageHeader snapshot_header{
        .type = rwn::desktop::VisualMessageType::full_snapshot,
        .payload_size = 0,
        .session_generation = 1,
        .representation_epoch = 2,
        .visual_sequence = 1,
        .frame_id = 3,
        .captured_at_us = 4,
    };
    const rwn::desktop::VisualFullSnapshotChunk invalid_first{
        .surface_width = 4,
        .surface_height = 4,
        .row_stride = 16,
        .total_bytes = 16,
        .chunk_offset = 0,
        .chunk = std::vector<std::byte>(32),
    };
    RWN_CHECK(!snapshot_guard.begin(snapshot_header, invalid_first));
    RWN_CHECK(!snapshot_guard.active());
    RWN_CHECK(rwn::desktop::maximum_raw_rect_protocol_bytes >
              rwn::desktop::default_raw_rect_selector_bytes);
    rwn::desktop::RawRectTransactionGuard rect_guard;
    auto rect_header = snapshot_header;
    rect_header.type = rwn::desktop::VisualMessageType::raw_rect;
    rect_header.frame_id = 4;
    const rwn::desktop::VisualRawRect first_rect{
        .base_frame_id = 3,
        .surface_width = 4,
        .surface_height = 4,
        .x = 0,
        .y = 0,
        .width = 2,
        .height = 2,
        .row_stride = 8,
        .bgra = std::vector<std::byte>(16),
    };
    RWN_CHECK(rect_guard.accept(rect_header, first_rect));
    auto stale_rect_header = rect_header;
    stale_rect_header.representation_epoch = 1;
    RWN_CHECK(!rect_guard.accept(stale_rect_header, first_rect));
    auto overlap_rect = first_rect;
    overlap_rect.x = 1;
    overlap_rect.y = 1;
    RWN_CHECK(!rect_guard.accept(rect_header, overlap_rect));
    auto wrong_commit = rect_header;
    wrong_commit.type = rwn::desktop::VisualMessageType::frame_commit;
    wrong_commit.session_generation = 2;
    RWN_CHECK(!rect_guard.ready_to_commit(
        wrong_commit, {.base_frame_id = 3}));
    rwn::test::require_throws<std::length_error>(
        [&] {
            static_cast<void>(rwn::desktop::decode_video_fragment(
                std::vector<std::byte>(
                    rwn::desktop::maximum_media_datagram_size + 1U)));
        },
        "oversized media datagram");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::fragment_frame({
                .frame_id = 1, .captured_at_us = 1, .width = 0, .height = 1080,
                .codec = rwn::desktop::VideoCodec::h264, .keyframe = true,
                .encoded = {std::byte{1}}}));
        },
        "zero video width");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::decode_input_event(
                std::vector<std::byte>{std::byte{'B'}}));
        },
        "truncated input event");
    const std::string invalid_utf8{"\xf0\x28\x8c\x28", 4};
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::encode_input_event({
                .kind = rwn::desktop::InputKind::text_commit,
                .sequence = 1,
                .occurred_at_us = 1,
                .text = invalid_utf8}));
        },
        "invalid UTF-8 input");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::encode_keyframe_request({
                .after_frame_id = 1,
                .reason_code = "packet loss: reveal details"}));
        },
        "unbounded keyframe reason");
}

void audio_packets_and_capability_gate_are_bounded() {
    rwn::test::require_throws<std::length_error>(
        [&] {
            static_cast<void>(rwn::audio::decode_packet(
                std::vector<std::byte>(
                    rwn::audio::maximum_audio_datagram_size + 1U)));
        },
        "oversized audio datagram");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::audio::encode_packet({
                .sequence = 1, .captured_at_us = 1,
                .sample_rate = 44100, .channels = 2,
                .samples_per_channel = 960,
                .opus = {std::byte{1}}}));
        },
        "wrong Opus clock rate");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::audio::DynamicOpusCodec codec("relative-opus.dll");
            static_cast<void>(codec);
        },
        "relative Opus library path");

    CountingOpusCodec codec;
    DeniedTransport transport;
    const rwn::core::AuthorizationResult denied{};
    rwn::audio::AudioSender sender(transport, codec, denied);
    rwn::test::require_throws<std::logic_error>(
        [&] {
            sender.send({
                .sample_rate = rwn::audio::opus_sample_rate,
                .channels = rwn::audio::opus_channels,
                .samples_per_channel = rwn::audio::opus_frame_samples,
                .interleaved_samples = std::vector<std::int16_t>(1920)}, 1);
        },
        "audio without desktop view");
    RWN_CHECK(codec.calls == 0);
    RWN_CHECK(transport.calls == 0);

    const rwn::core::AuthorizationResult viewed{
        .principal_matched = true,
        .workspace_allowed = true,
        .granted = {rwn::core::Capability::desktop_view},
        .denied = {},
    };
    rwn::audio::AudioSender viewed_sender(transport, codec, viewed);
    UntimestampedAudioCapture capture;
    rwn::audio::AudioCaptureRelay relay(capture, viewed_sender);
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(relay.pump(std::chrono::milliseconds{20})); },
        "audio capture without timestamp");
    RWN_CHECK(codec.calls == 0);
    RWN_CHECK(transport.calls == 0);
}

void jitter_buffer_bounds_late_and_overflow_packets() {
    auto packet = [](const std::uint64_t sequence) {
        return rwn::audio::AudioPacket{
            .sequence = sequence, .captured_at_us = sequence,
            .sample_rate = rwn::audio::opus_sample_rate,
            .channels = rwn::audio::opus_channels,
            .samples_per_channel = rwn::audio::opus_frame_samples,
            .opus = {std::byte{1}}};
    };
    rwn::audio::AudioJitterBuffer jitter(1, 2);
    RWN_CHECK(jitter.push(packet(10)));
    RWN_CHECK(jitter.pop()->sequence == 10);
    RWN_CHECK(!jitter.push(packet(9)));
    RWN_CHECK(jitter.push(packet(11)));
    RWN_CHECK(jitter.push(packet(12)));
    RWN_CHECK(!jitter.push(packet(13)));
    RWN_CHECK(jitter.telemetry().late == 1);
    RWN_CHECK(jitter.telemetry().overflow == 1);
    RWN_CHECK(jitter.telemetry().depth == 2);
}

void transport_configuration_negotiation_and_recovery_fail_closed() {
    using namespace std::chrono_literals;
    const auto root = std::filesystem::temp_directory_path() /
                      "rwn-transport-settings-security";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root);
    const auto unsafe_settings = root / "unsafe.toml";
    std::ofstream(unsafe_settings, std::ios::binary)
        << "alpn = \"rwn/1\"\n"
           "require_tls13 = false\n"
           "enable_datagrams = true\n"
           "enable_connection_migration = true\n"
           "enable_fallback = true\n"
           "maximum_datagram_bytes = 1400\n"
           "idle_timeout_seconds = 30\n"
           "keep_alive_seconds = 5\n"
           "primary_failures_before_fallback = 2\n";
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::transport::load_transport_settings(unsafe_settings));
        },
        "transport settings TLS downgrade");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            SecurityTransportConnector connector;
            rwn::transport::ResilientTransport transport(
                connector,
                {.host = "mac/node", .port = 4433,
                 .path = rwn::transport::NetworkPath::lan});
            static_cast<void>(transport);
        },
        "transport endpoint injection");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            SecurityTransportConnector connector;
            rwn::transport::ResilientTransport transport(
                connector,
                {.host = "mac-node", .port = 4433,
                 .path = rwn::transport::NetworkPath::lan},
                {.require_tls13 = false});
            static_cast<void>(transport);
        },
        "QUIC TLS downgrade");
    rwn::test::require_throws<std::logic_error>(
        [&] {
            static_cast<void>(rwn::transport::negotiate_features(
                {.minimum_protocol_version = 1,
                 .maximum_protocol_version = 1},
                {.minimum_protocol_version = 2,
                 .maximum_protocol_version = 2}));
        },
        "non-overlapping transport protocol version");
    rwn::test::require_throws<std::logic_error>(
        [&] {
            static_cast<void>(rwn::transport::negotiate_features(
                {.video_features = {rwn::transport::VideoFeature::av1}},
                {.video_features = {rwn::transport::VideoFeature::hevc}}));
        },
        "missing baseline video codec");

    SecurityTransportConnector connector;
    rwn::transport::ResilientTransport transport(
        connector,
        {.host = "mac-node", .port = 4433,
         .path = rwn::transport::NetworkPath::lan});
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            transport.set_recovery_cursor({
                .session_id = "session-1",
                .workspace_id = "game",
                .workspace_revision = 1,
                .active_build_ids = {"duplicate", "duplicate"},
                .audit_sequence = 1,
            });
        },
        "duplicate active build recovery cursor");
    rwn::test::require_throws<std::logic_error>(
        [&] {
            const std::array bytes{std::byte{1}};
            transport.send_datagram(
                rwn::transport::DatagramChannel::video,
                bytes);
        },
        "datagram before transport ready");
    const auto now = std::chrono::steady_clock::time_point{} + 1h;
    transport.connect(now);
    rwn::test::require_throws<std::length_error>(
        [&] {
            transport.send_datagram(
                rwn::transport::DatagramChannel::video, {});
        },
        "empty transport datagram");
    rwn::test::require_throws<std::length_error>(
        [&] {
            transport.send_datagram(
                rwn::transport::DatagramChannel::video,
                std::vector<std::byte>(1401));
        },
        "oversized transport datagram");
    rwn::test::require_throws<std::runtime_error>(
        [&] {
            static_cast<void>(transport.open_stream(
                rwn::transport::StreamPurpose::control));
        },
        "connector returned null stream");
    rwn::test::require_throws<std::runtime_error>(
        [&] {
            static_cast<void>(transport.accept_stream(1s));
        },
        "transport without peer-stream receive support");
    rwn::test::require_throws<std::runtime_error>(
        [&] {
            static_cast<void>(transport.receive_datagram(1s));
        },
        "transport without datagram receive support");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(transport.accept_stream(0ms));
        },
        "zero peer-stream accept timeout");
    RWN_CHECK(connector.connection->calls == 1);
    rwn::test::require_throws<std::invalid_argument>(
        [&] { transport.close(now - 1s); },
        "non-monotonic transport event");
    std::filesystem::remove_all(root, ignored);
}

void encrypted_fallback_rejects_downgrade_splicing_and_unbounded_io() {
    using namespace std::chrono_literals;
    const auto valid_reliable = valid_fallback_evidence(
        rwn::transport::EncryptedPlaneProtocol::tls13);
    const auto valid_datagrams = valid_fallback_evidence(
        rwn::transport::EncryptedPlaneProtocol::dtls12);
    const auto construct = [](
        rwn::transport::EncryptedPlaneEvidence reliable,
        rwn::transport::EncryptedPlaneEvidence datagrams,
        const std::size_t maximum = 1400U) {
        return std::make_unique<
            rwn::transport::EncryptedFallbackTransport>(
            std::make_unique<SecurityFallbackReliablePlane>(
                std::move(reliable)),
            std::make_unique<SecurityFallbackDatagramPlane>(
                std::move(datagrams)),
            maximum);
    };

    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::transport::EncryptedFallbackTransport(
                {}, std::make_unique<SecurityFallbackDatagramPlane>(
                        valid_datagrams),
                1400));
        },
        "missing TLS plane");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            auto downgraded = valid_reliable;
            downgraded.protocol =
                rwn::transport::EncryptedPlaneProtocol::dtls12;
            static_cast<void>(construct(downgraded, valid_datagrams));
        },
        "TLS protocol downgrade");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            auto downgraded = valid_datagrams;
            downgraded.protocol =
                rwn::transport::EncryptedPlaneProtocol::tls13;
            static_cast<void>(construct(valid_reliable, downgraded));
        },
        "DTLS protocol downgrade");
    for (const auto invalid : {0, 1, 2, 3}) {
        auto evidence = valid_reliable;
        switch (invalid) {
        case 0: evidence.chain_validated = false; break;
        case 1: evidence.revocation_checked = false; break;
        case 2: evidence.peer_certificate_sha256.fill(0); break;
        case 3: evidence.channel_binding.fill(0); break;
        default: break;
        }
        rwn::test::require_throws<std::invalid_argument>(
            [&] { static_cast<void>(construct(evidence, valid_datagrams)); },
            "invalid TLS trust evidence");
    }
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            auto spliced = valid_datagrams;
            spliced.peer_certificate_sha256.back() ^= 1U;
            static_cast<void>(construct(valid_reliable, spliced));
        },
        "TLS DTLS peer certificate splice");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            auto spliced = valid_datagrams;
            spliced.channel_binding.front() ^= 1U;
            static_cast<void>(construct(valid_reliable, spliced));
        },
        "TLS DTLS channel binding splice");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                construct(valid_reliable, valid_datagrams, 255));
        },
        "too-small fallback datagram bound");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(construct(
                valid_reliable, valid_datagrams, 64U * 1024U + 1U));
        },
        "too-large fallback datagram bound");

    auto reliable = std::make_unique<SecurityFallbackReliablePlane>(
        valid_reliable);
    auto* reliable_state = reliable.get();
    auto datagrams = std::make_unique<SecurityFallbackDatagramPlane>(
        valid_datagrams);
    auto* datagram_state = datagrams.get();
    rwn::transport::EncryptedFallbackTransport transport(
        std::move(reliable), std::move(datagrams), 256);
    reliable_state->null_open = true;
    rwn::test::require_throws<std::runtime_error>(
        [&] {
            static_cast<void>(transport.open_stream(
                rwn::transport::StreamPurpose::control));
        },
        "null fallback stream");
    reliable_state->null_open = false;
    reliable_state->null_accept = true;
    rwn::test::require_throws<std::runtime_error>(
        [&] { static_cast<void>(transport.accept_stream(1s)); },
        "null accepted fallback stream");
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(transport.accept_stream(0ms)); },
        "zero fallback accept wait");
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(transport.receive_datagram(5min + 1ms)); },
        "unbounded fallback datagram wait");
    rwn::test::require_throws<std::length_error>(
        [&] {
            transport.send_datagram(
                rwn::transport::DatagramChannel::audio, {});
        },
        "empty fallback datagram");
    const std::vector<std::byte> oversized(257, std::byte{0x01});
    rwn::test::require_throws<std::length_error>(
        [&] {
            transport.send_datagram(
                rwn::transport::DatagramChannel::audio, oversized);
        },
        "oversized fallback datagram");
    datagram_state->received.payload.clear();
    rwn::test::require_throws<std::runtime_error>(
        [&] { static_cast<void>(transport.receive_datagram(1s)); },
        "empty received fallback datagram");
    datagram_state->received.payload.assign(257, std::byte{0x01});
    rwn::test::require_throws<std::runtime_error>(
        [&] { static_cast<void>(transport.receive_datagram(1s)); },
        "oversized received fallback datagram");
    datagram_state->received.payload = {std::byte{0x01}};
    datagram_state->received.channel =
        static_cast<rwn::transport::DatagramChannel>(255);
    rwn::test::require_throws<std::runtime_error>(
        [&] { static_cast<void>(transport.receive_datagram(1s)); },
        "invalid received fallback channel");

    SecurityFallbackProvider provider;
    rwn::transport::EncryptedFallbackConnector connector(provider);
    const rwn::transport::TransportEndpoint endpoint{
        .host = "mac-node.local", .port = 4433,
        .path = rwn::transport::NetworkPath::lan};
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(connector.connect(
                rwn::transport::TransportMode::quic, endpoint, {}));
        },
        "QUIC routed through fallback connector");
    auto disabled = rwn::transport::QuicTransportSettings{};
    disabled.enable_fallback = false;
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(connector.connect(
                rwn::transport::TransportMode::tls_tcp_udp_fallback,
                endpoint, disabled));
        },
        "disabled fallback connector");
    auto tls_downgrade = rwn::transport::QuicTransportSettings{};
    tls_downgrade.require_tls13 = false;
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(connector.connect(
                rwn::transport::TransportMode::tls_tcp_udp_fallback,
                endpoint, tls_downgrade));
        },
        "fallback connector TLS downgrade");
}

void transport_verification_rejects_forged_or_malformed_evidence() {
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(
                rwn::transport::standard_impairment_scenario("unknown"));
        },
        "unknown impairment profile");
    auto scenario =
        rwn::transport::standard_impairment_scenario("lan-baseline");
    auto invalid_scenario = scenario;
    invalid_scenario.packet_count = 0;
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::transport::make_deterministic_observations(
                    invalid_scenario));
        },
        "zero-packet impairment profile");

    const std::string hash(64, 'a');
    rwn::transport::CorrectnessEvidence evidence{
        .expected_sync_revision = 42,
        .observed_sync_revision = 42,
        .source_manifest_sha256 = hash,
        .mirror_manifest_sha256 = hash,
        .build_id = "build-42",
        .build_evidence_sha256 = std::string(64, 'b'),
        .build_exit_code = 0,
        .expected_artifact_sha256 = std::string(64, 'c'),
        .observed_artifact_sha256 = std::string(64, 'c'),
    };
    auto invalid_evidence = evidence;
    invalid_evidence.build_evidence_sha256 = std::string(64, 'A');
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::transport::analyze_transport_verification(
                rwn::transport::VerificationMode::deterministic_model,
                scenario, invalid_evidence,
                rwn::transport::make_deterministic_observations(scenario)));
        },
        "noncanonical evidence hash");

    auto observations =
        rwn::transport::make_deterministic_observations(scenario);
    observations[1].sequence = observations[0].sequence;
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::transport::analyze_transport_verification(
                rwn::transport::VerificationMode::deterministic_model,
                scenario, evidence, observations));
        },
        "duplicate packet observation");

    auto failed = evidence;
    failed.observed_sync_revision = 41;
    failed.build_exit_code = 7;
    failed.observed_artifact_sha256 = std::string(64, 'd');
    const auto report = rwn::transport::analyze_transport_verification(
        rwn::transport::VerificationMode::deterministic_model, scenario,
        failed, rwn::transport::make_deterministic_observations(scenario));
    RWN_CHECK(!report.sync_correct);
    RWN_CHECK(!report.build_correct);
    RWN_CHECK(!report.passed);
    auto forged_report = report;
    forged_report.passed = true;
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::transport::render_transport_verification_json(
                    forged_report));
        },
        "forged report verdict");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::transport::write_transport_verification_report(
                "relative-report.json", report);
        },
        "relative report destination");
}

void desktop_control_is_denied_before_platform_or_transport_access() {
    const rwn::core::AuthorizationResult view_only{
        .principal_matched = true,
        .workspace_allowed = true,
        .granted = {rwn::core::Capability::desktop_view},
        .denied = {rwn::core::Capability::desktop_control,
                   rwn::core::Capability::clipboard_read},
    };
    CountingInputBackend backend;
    rwn::desktop::InputReceiver receiver(backend);
    RWN_CHECK(receiver.accept_input_epoch(1, false));
    const rwn::desktop::InputEvent click{
        .kind = rwn::desktop::InputKind::pointer_button,
        .sequence = 1,
        .occurred_at_us = 10,
        .value_a = 1,
        .pressed = true,
        .text = {},
    };
    rwn::test::require_throws<std::logic_error>(
        [&] { static_cast<void>(receiver.receive(click, true, view_only)); },
        "input without control grant");
    RWN_CHECK(backend.calls == 0);

    DeniedTransport transport;
    rwn::desktop::DesktopTransportSession session(transport, view_only);
    rwn::test::require_throws<std::logic_error>(
        [&] { session.send_input(click); }, "transport input without grant");
    rwn::test::require_throws<std::logic_error>(
        [&] {
            session.send_clipboard({
                .origin = "windows", .revision = 1,
                .content_sha256 = rwn::core::sha256_hex("secret"),
                .utf8_text = "secret"});
        },
        "clipboard without grant");
    RWN_CHECK(transport.calls == 0);
}

void input_order_clipboard_hash_and_replay_are_enforced() {
    const rwn::core::AuthorizationResult control{
        .principal_matched = true,
        .workspace_allowed = true,
        .granted = {rwn::core::Capability::desktop_control,
                    rwn::core::Capability::clipboard_write},
        .denied = {},
    };
    CountingInputBackend backend;
    rwn::desktop::InputReceiver receiver(backend);
    RWN_CHECK(receiver.receive(
        {.kind = rwn::desktop::InputKind::raw_key,
         .sequence = 10, .occurred_at_us = 10,
         .value_a = 4, .pressed = true, .text = {}}, true, control));
    RWN_CHECK(!receiver.receive(
        {.kind = rwn::desktop::InputKind::raw_key,
         .sequence = 10, .occurred_at_us = 11,
         .value_a = 4, .pressed = false, .text = {}}, true, control));
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(receiver.receive(
                {.kind = rwn::desktop::InputKind::pointer_button,
                 .sequence = 11, .occurred_at_us = 12,
                 .value_a = 1, .pressed = true, .text = {}}, false, control));
        },
        "button on unreliable transport");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(receiver.receive(
                {.kind = rwn::desktop::InputKind::raw_key,
                 .sequence = 12, .occurred_at_us = 13,
                 .value_a = 4, .pressed = false, .text = {}}, true, control));
        },
        "reliable sequence gap");
    RWN_CHECK(backend.calls == 1);
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(receiver.accept_input_epoch(2, false)); },
        "input epoch advance without release");
    RWN_CHECK(receiver.accept_input_epoch(2, true));
    RWN_CHECK(!receiver.accept_input_epoch(1, false));

    const rwn::desktop::ReverseControlHeader ping{
        .type = rwn::desktop::ReverseControlType::ping,
        .payload_size = 0,
        .input_epoch = 1,
        .sequence = 1,
        .occurred_at_us = 10,
    };
    auto forged_control =
        rwn::desktop::encode_reverse_control_header(ping);
    forged_control.at(6) = std::byte{0xff};
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::desktop::decode_reverse_control_header(forged_control));
        },
        "unknown reverse control type");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::desktop::validate_reverse_control_payload(
                {.type = rwn::desktop::ReverseControlType::ping,
                 .payload_size = 1,
                 .input_epoch = 1,
                 .sequence = 2,
                 .occurred_at_us = 11},
                std::array{std::byte{0x00}});
        },
        "ping payload injection");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::encode_reverse_control_header({
                .type = rwn::desktop::ReverseControlType::input_event,
                .payload_size = static_cast<std::uint32_t>(
                    rwn::desktop::maximum_reverse_control_payload + 1U),
                .input_epoch = 1,
                .sequence = 3,
                .occurred_at_us = 12,
            }));
        },
        "oversized reverse control payload");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::encode_reverse_control_header({
                .type = rwn::desktop::ReverseControlType::ping,
                .payload_size = 0,
                .input_epoch = 0,
                .sequence = 4,
                .occurred_at_us = 13,
            }));
        },
        "reverse control without input epoch");

    rwn::desktop::ClipboardSynchronizer clipboard("mac");
    const rwn::desktop::ClipboardUpdate tampered{
        .origin = "windows",
        .revision = 1,
        .content_sha256 = rwn::core::sha256_hex("expected"),
        .utf8_text = "tampered",
    };
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(clipboard.apply(tampered, control)); },
        "clipboard hash mismatch");
    const rwn::desktop::ClipboardUpdate valid{
        .origin = "windows",
        .revision = 2,
        .content_sha256 = rwn::core::sha256_hex("content"),
        .utf8_text = "content",
    };
    RWN_CHECK(clipboard.apply(valid, control));
    RWN_CHECK(!clipboard.apply(valid, control));
}

void build_profile_parser_rejects_privilege_and_path_injection() {
    constexpr std::string_view prefix =
        "[workspace]\n"
        "id = \"game\"\n"
        "name = \"Game\"\n"
        "source = \"windows\"\n"
        "mirror = \"macos\"\n"
        "[sync]\n"
        "direction = \"one-way\"\n"
        "exclude = [\".git\"]\n"
        "[target.safe]\n"
        "node = \"mac-mini\"\n"
        "working_dir = \".\"\n"
        "command = [\"/usr/bin/true\"]\n"
        "timeout_seconds = 30\n"
        "[target.safe.artifacts]\n"
        "paths = [\"dist/app.zip\"]\n"
        "platform = \"macos\"\n"
        "architecture = \"arm64\"\n";
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::core::parse_remote_workspace_config(
                std::string(prefix) + "shell = true\n"));
        },
        "unknown privilege field");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            auto escaping = std::string(prefix);
            const auto path = escaping.find("dist/app.zip");
            escaping.replace(path, std::string("dist/app.zip").size(),
                             "../private.zip");
            static_cast<void>(
                rwn::core::parse_remote_workspace_config(escaping));
        },
        "artifact path traversal");
    const auto config = rwn::core::parse_remote_workspace_config(prefix);
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(config.make_build_request(
                "build", 1, "safe", {{"PATH", "C:/attacker"}}));
        },
        "environment privilege injection");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            auto relative = std::string(prefix);
            const auto executable = relative.find("/usr/bin/true");
            relative.replace(
                executable, std::string("/usr/bin/true").size(), "true");
            static_cast<void>(
                rwn::core::parse_remote_workspace_config(relative));
        },
        "relative build executable");
    rwn::test::require_throws<std::out_of_range>(
        [&] {
            static_cast<void>(config.make_build_request(
                "build", 1, "attacker-profile"));
        },
        "caller-selected arbitrary command profile");
}

void build_artifact_discovery_rejects_ambiguous_or_excess_outputs() {
    const auto root = std::filesystem::temp_directory_path() /
        "rwn-artifact-discovery-security";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root / "dist/folder");
    std::ofstream(root / "dist/a.zip", std::ios::binary) << "a";
    std::ofstream(root / "dist/b.zip", std::ios::binary) << "b";
    auto profile = rwn::core::BuildProfile{
        .name = "release", .node = "mac",
        .command = {.argv = {"/usr/bin/true"}, .working_directory = ".",
                    .timeout = std::chrono::seconds{1}, .environment = {}},
        .environment_allowlist = {},
        .artifacts = {.paths = {"dist/*.zip"}, .platform = "macos",
                      .architecture = "arm64", .archive_app_bundles = true},
    };
    rwn::test::require_throws<std::length_error>(
        [&] {
            static_cast<void>(
                rwn::core::discover_build_artifacts(root, profile, 1));
        },
        "excess artifact outputs");
    profile.artifacts.paths = {"dist/folder"};
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::core::discover_build_artifacts(root, profile));
        },
        "unpackaged artifact directory");
    profile.artifacts.paths = {"../*.zip"};
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(
                rwn::core::discover_build_artifacts(root, profile));
        },
        "artifact discovery traversal pattern");
    std::filesystem::remove_all(root, ignored);
}

void terminal_api_requires_capability_scope_and_bounded_io() {
    using namespace std::chrono_literals;
    RejectingTerminalBackend denied_backend;
    rwn::core::CapabilityRequest request;
    request.principal.id = "agent";
    request.principal.kind = rwn::core::PrincipalKind::agent;
    request.workspace = "game";
    request.requested = {rwn::core::Capability::terminal_open};
    const auto denied = rwn::core::authorize(
        request, rwn::core::default_agent_policy("agent", "game"));
    rwn::core::TerminalSession denied_terminal(
        "agent-terminal", denied, RWN_SOURCE_DIR, denied_backend);
    rwn::test::require_throws<std::logic_error>(
        [&] {
            denied_terminal.open(
                {.argv = {RWN_PROCESS_FIXTURE},
                 .working_directory = ".",
                 .timeout = 1min,
                 .environment = {}},
                {}, {.columns = 80, .rows = 24});
        },
        "agent default terminal denial");
    RWN_CHECK(!denied_backend.opened);

    RejectingTerminalBackend bounded_backend;
    rwn::core::TerminalSession terminal(
        "human-terminal",
        {.principal_matched = true,
         .workspace_allowed = true,
         .granted = {rwn::core::Capability::terminal_open},
         .denied = {}},
        RWN_SOURCE_DIR, bounded_backend);
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            terminal.open(
                {.argv = {RWN_PROCESS_FIXTURE},
                 .working_directory = "../",
                 .timeout = 1min,
                 .environment = {}},
                {}, {.columns = 80, .rows = 24});
        },
        "terminal workspace escape");
    terminal.open(
        {.argv = {RWN_PROCESS_FIXTURE},
         .working_directory = ".",
         .timeout = 1min,
         .environment = {}},
        {}, {.columns = 80, .rows = 24});
    rwn::test::require_throws<std::invalid_argument>(
        [&] { terminal.resize({.columns = 0, .rows = 24}); },
        "terminal size bound");
    const std::vector<std::byte> oversized(
        rwn::core::TerminalSession::max_input + 1);
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(terminal.write(oversized)); },
        "terminal input bound");
    rwn::test::require_throws<std::runtime_error>(
        [&] { static_cast<void>(terminal.read(1)); },
        "terminal backend output bound");
    terminal.close();
}

void process_roles_enforce_workspace_scope_and_audit_denials() {
    using namespace std::chrono_literals;
    const auto root = std::filesystem::temp_directory_path() /
                      "rwn-process-boundary-security";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root / "src");
    std::ofstream(root / "src/main.cpp") << "int main(){}";
    const auto now = rwn::core::WallClock::now();
    rwn::core::AuditLog audit;
    rwn::core::ProcessBoundary worker(
        rwn::core::default_process_policy(
            rwn::core::ProcessRole::build_worker),
        root, audit);
    const rwn::core::AuthorizationResult workspace_authorization{
        .principal_matched = true,
        .workspace_allowed = true,
        .granted = {rwn::core::Capability::workspace_read,
                    rwn::core::Capability::desktop_control},
        .denied = {},
    };
    RWN_CHECK(worker.resolve_workspace_access(
                  {.principal_id = "agent-1",
                   .device_id = "windows-1",
                   .session_id = "session-1",
                   .workspace_id = "game",
                   .capability = rwn::core::Capability::workspace_read,
                   .relative_path = "src/main.cpp",
                   .authorization = workspace_authorization,
                   .occurred_at = now,
                   .agent_job_id = {}}) ==
              std::filesystem::weakly_canonical(root / "src/main.cpp"));
    rwn::test::require_throws<std::logic_error>(
        [&] {
            static_cast<void>(worker.resolve_workspace_access(
                {.principal_id = "agent-1",
                 .device_id = "windows-1",
                 .session_id = "session-1",
                 .workspace_id = "game",
                 .capability = rwn::core::Capability::workspace_read,
                 .relative_path = "../private/secret.txt",
                 .authorization = workspace_authorization,
                 .occurred_at = now + 1s,
                 .agent_job_id = {}}));
        },
        "build worker workspace escape");

    rwn::core::ProcessBoundary desktop(
        rwn::core::default_process_policy(
            rwn::core::ProcessRole::desktop_agent),
        root, audit);
    RWN_CHECK(!desktop.permits(
        rwn::core::Capability::workspace_read, workspace_authorization));
    RWN_CHECK(!worker.permits(
        rwn::core::Capability::desktop_control, workspace_authorization));
    rwn::test::require_throws<std::logic_error>(
        [&] {
            static_cast<void>(desktop.resolve_workspace_access(
                {.principal_id = "human-1",
                 .device_id = "windows-1",
                 .session_id = "session-1",
                 .workspace_id = "game",
                 .capability = rwn::core::Capability::workspace_read,
                 .relative_path = "src/main.cpp",
                 .authorization = workspace_authorization,
                 .occurred_at = now + 2s,
                 .agent_job_id = {}}));
        },
        "desktop agent workspace access");
    RWN_CHECK(audit.events().size() == 2);
    RWN_CHECK(audit.events().front().action ==
              rwn::core::AuditAction::scope_access_denied);
    RWN_CHECK(audit.events().front().process_role == "build_worker");
    RWN_CHECK(audit.events().front().reason_code == "workspace_scope_escape");
    const auto exported = audit.export_json_lines({});
    RWN_CHECK(exported.find("secret.txt") == std::string::npos);
    RWN_CHECK(exported.find("workspace_scope_escape") != std::string::npos);
    std::filesystem::remove_all(root, ignored);
}

void audit_query_export_and_retention_are_bounded() {
    using namespace std::chrono_literals;
    const auto base = rwn::core::WallClock::now();
    rwn::core::AuditLog audit({.maximum_age = 1h, .maximum_events = 3});
    for (int index = 0; index < 4; ++index) {
        audit.append({
            .occurred_at = base + std::chrono::minutes(index * 30),
            .principal_id = "human-1",
            .device_id = "device-1",
            .session_id = "session-1",
            .workspace_id = "game",
            .action = rwn::core::AuditAction::session_renewed,
            .result = rwn::core::AuditResult::allowed,
        });
    }
    RWN_CHECK(audit.events().size() == 3);
    RWN_CHECK(audit.query({.principal_id = "human-1", .limit = 2}).size() == 2);
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(audit.query({.limit = 10001})); },
        "unbounded audit query");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            audit.append({
                .occurred_at = base + 2h,
                .principal_id = "human-1",
                .device_id = "device-1",
                .session_id = "session-1",
                .workspace_id = "game",
                .process_role = "build_worker",
                .reason_code = "secret=value",
                .action = rwn::core::AuditAction::scope_access_denied,
                .result = rwn::core::AuditResult::denied,
            });
        },
        "arbitrary audit reason content");
    audit.enforce_retention(base + 2h);
    RWN_CHECK(audit.events().size() == 2);

    const auto journal = std::filesystem::temp_directory_path() /
        ("rwn-audit-query-security-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()) +
         ".jsonl");
    std::ofstream(journal, std::ios::binary)
        << "{\"workspace_id\":\"game\"}\nmalformed\n";
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(rwn::core::query_audit_journal(
            journal, {.field = "workspace_id", .identifier = "game",
                      .limit = 10})); },
        "malformed durable audit journal");
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(rwn::core::query_audit_journal(
            journal, {.field = "secret", .identifier = "game",
                      .limit = 10})); },
        "unapproved audit journal field");
    std::error_code ignored;
    std::filesystem::remove(journal, ignored);
}

void manifest_rejects_case_collisions_and_unsafe_symlink_targets() {
    constexpr auto hash =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const rwn::core::WorkspaceManifest collision{
        .workspace_id = "game",
        .revision = 1,
        .entries = {
            {.path = "src/Foo.cpp",
             .kind = rwn::core::WorkspaceEntryKind::file,
             .size = 3,
             .content_hash = hash,
             .mode = 0644U,
             .symlink_target = {}},
            {.path = "src/foo.cpp",
             .kind = rwn::core::WorkspaceEntryKind::file,
             .size = 3,
             .content_hash = hash,
             .mode = 0644U,
             .symlink_target = {}},
        },
    };
    rwn::test::require_throws<std::invalid_argument>(
        [&] { rwn::core::reject_case_collisions(collision); },
        "case-colliding workspace paths");
    const rwn::core::WorkspaceManifest escaping_symlink{
        .workspace_id = "game",
        .revision = 1,
        .entries = {{.path = "src/external",
                     .kind = rwn::core::WorkspaceEntryKind::symlink,
                     .size = 0,
                     .content_hash = {},
                     .mode = 0777U,
                     .symlink_target = "../private"}},
    };
    rwn::test::require_throws<std::invalid_argument>(
        [&] { rwn::core::validate_manifest(escaping_symlink); },
        "escaping symlink target");
}

void manifest_rejects_noncanonical_entry_order() {
    constexpr auto hash =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const rwn::core::WorkspaceManifest unsorted{
        .workspace_id = "game",
        .revision = 1,
        .entries = {
            {.path = "z.cpp",
             .kind = rwn::core::WorkspaceEntryKind::file,
             .size = 3,
             .content_hash = hash,
             .mode = 0644U,
             .symlink_target = {}},
            {.path = "a.cpp",
             .kind = rwn::core::WorkspaceEntryKind::file,
             .size = 3,
             .content_hash = hash,
             .mode = 0644U,
             .symlink_target = {}},
        },
    };
    rwn::test::require_throws<std::invalid_argument>(
        [&] { rwn::core::validate_manifest(unsorted); },
        "noncanonical manifest order");
}

void remoteignore_rejects_negation_and_traversal_rules() {
    rwn::test::require_throws<std::invalid_argument>(
        [] { static_cast<void>(rwn::core::IgnoreRules::parse("!secret.txt\n")); },
        "unsupported ignore negation");
    rwn::test::require_throws<std::invalid_argument>(
        [] { static_cast<void>(rwn::core::IgnoreRules::parse("../private\n")); },
        "unsafe ignore traversal");
    RWN_CHECK(!rwn::core::is_sha256_hex("abc"));
}

void policy_parser_rejects_unknown_fields_and_capabilities() {
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(rwn::core::parse_policy(
                "principal = \"client\"\nworkspaces = [\"game\"]\n"
                "allow = [\"workspace.sync\"]\nadmin = true\n"));
        },
        "unknown policy field");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(rwn::core::parse_policy(
                "principal = \"client\"\nworkspaces = [\"game\"]\n"
                "allow = [\"shell.everything\"]\n"));
        },
        "unknown policy capability");
}

void active_session_loses_access_after_device_revocation() {
    using namespace std::chrono_literals;
    using enum rwn::core::Capability;
    constexpr auto fingerprint =
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const auto now = rwn::core::WallClock::time_point{} + 300h;
    rwn::core::DeviceRegistry registry;
    rwn::core::PairingService pairing(registry);
    const auto challenge = pairing.begin(
        {.node_id = "node",
         .node_name = "Node",
         .lan_endpoint = "10.0.0.1:4433",
         .fingerprint = fingerprint},
        "123456", now, 5min);
    const auto certificate = pairing.confirm(
        challenge, "123456", "client", "Client", fingerprint, now, 1h);
    rwn::core::AuditLog audit;
    rwn::core::SessionService sessions(registry, audit);
    static_cast<void>(sessions.open(
        {.session_id = "revoked-session",
         .peer = {.tls_1_3_negotiated = true,
                  .client_certificate_present = true,
                  .certificate_chain_valid = true,
                  .revocation_checked = true,
                  .certificate = certificate},
         .capabilities = {
             .principal = {.id = "client",
                           .kind = rwn::core::PrincipalKind::device},
             .workspace = "game",
             .requested = {workspace_sync}},
         .lease = 15min},
        {.principal_id = "client",
         .workspaces = {"game"},
         .allowed = {workspace_sync}},
        now));
    registry.revoke("client");
    RWN_CHECK(!sessions.permits(
        "revoked-session", workspace_sync, "game", now + 1min));
    RWN_CHECK(sessions.state("revoked-session") ==
              rwn::core::SessionState::closed);
    rwn::test::require_throws<std::logic_error>(
        [&] { sessions.renew("revoked-session", now + 1min, 5min); },
        "revoked session renewal");
}

void mtls_identity_cannot_be_rebound_to_another_principal() {
    using namespace std::chrono_literals;
    constexpr auto fingerprint =
        "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
    const auto now = rwn::core::WallClock::time_point{} + 400h;
    rwn::core::DeviceRegistry registry;
    rwn::core::PairingService pairing(registry);
    const auto challenge = pairing.begin(
        {.node_id = "node",
         .node_name = "Node",
         .lan_endpoint = "10.0.0.1:4433",
         .fingerprint = fingerprint},
        "123456", now, 5min);
    const auto certificate = pairing.confirm(
        challenge, "123456", "client-a", "Client A", fingerprint, now, 1h);
    rwn::core::AuditLog audit;
    rwn::core::SessionService sessions(registry, audit);
    rwn::test::require_throws<std::logic_error>(
        [&] {
            static_cast<void>(sessions.open(
                {.session_id = "rebound-session",
                 .peer = {.tls_1_3_negotiated = true,
                          .client_certificate_present = true,
                          .certificate_chain_valid = true,
                          .revocation_checked = true,
                          .certificate = certificate},
                 .capabilities = {
                     .principal = {.id = "client-b",
                                   .kind = rwn::core::PrincipalKind::device},
                     .workspace = "game",
                     .requested = {rwn::core::Capability::workspace_sync}},
                 .lease = 15min},
                {.principal_id = "client-b",
                 .workspaces = {"game"},
                 .allowed = {rwn::core::Capability::workspace_sync}},
                now));
        },
        "mTLS identity rebinding");
    RWN_CHECK(audit.events().size() == 1);
    RWN_CHECK(audit.events().front().result == rwn::core::AuditResult::denied);
}

#if defined(RWN_TEST_WINDOWS_PLATFORM)
void windows_pairing_codes_use_native_rng_and_canonical_format() {
    std::set<std::string> generated;
    for (int attempt = 0; attempt < 32; ++attempt) {
        const auto code = rwn::platform::windows::generate_pairing_code();
        RWN_CHECK(code.size() == 6);
        RWN_CHECK(std::ranges::all_of(code, [](const unsigned char value) {
            return value >= '0' && value <= '9';
        }));
        generated.insert(code);
    }
    RWN_CHECK(generated.size() > 1);
}


void windows_dns_sd_adapter_rejects_empty_service_type() {
    rwn::test::require_throws<std::invalid_argument>(
        [] { rwn::platform::windows::DnsSdDiscovery discovery(L""); },
        "empty DNS-SD service type");
}

void windows_dns_sd_adapter_starts_and_stops_native_browse() {
    rwn::platform::windows::DnsSdDiscovery discovery;
    discovery.start();
    RWN_CHECK(discovery.running());
    discovery.stop();
    RWN_CHECK(!discovery.running());
}

void failed_file_hash_never_overwrites_destination() {
    const std::string replacement = "new";
    const auto root = std::filesystem::temp_directory_path() /
                      "rwn-file-transfer-security";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root / "src");
    {
        std::ofstream(root / "src" / "config.txt", std::ios::binary) << "old";
    }
    rwn::platform::windows::WindowsDurableFileSystem filesystem;
    rwn::core::FileTransfer transfer(
        rwn::core::WorkspaceScope(root),
        {.transfer_id = "transfer-security",
         .relative_path = "src/config.txt",
         .total_size = replacement.size(),
         .sha256 = rwn::core::sha256_hex("different"),
         .chunks = {{.index = 0,
                     .offset = 0,
                     .size = replacement.size(),
                     .sha256 = rwn::core::sha256_hex(replacement)}}},
        filesystem);
    transfer.accept_chunk(0, std::as_bytes(std::span{
                                 replacement.data(), replacement.size()}));
    rwn::test::require_throws<std::invalid_argument>(
        [&] { transfer.finalize(); }, "full content hash mismatch");
    std::ifstream input(root / "src" / "config.txt", std::ios::binary);
    const std::string current{
        std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    RWN_CHECK(current == "old");
    std::filesystem::remove_all(root, ignored);
}

void file_transfer_rejects_wrong_chunk_and_unsafe_target() {
    const std::string content = "content";
    const auto root = std::filesystem::temp_directory_path() /
                      "rwn-file-transfer-path-security";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root);
    rwn::platform::windows::WindowsDurableFileSystem filesystem;
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::core::FileTransfer transfer(
                rwn::core::WorkspaceScope(root),
                {.transfer_id = "transfer-path",
                 .relative_path = "../escape.txt",
                 .total_size = content.size(),
                 .sha256 = rwn::core::sha256_hex(content),
                 .chunks = {{.index = 0,
                             .offset = 0,
                             .size = content.size(),
                             .sha256 = rwn::core::sha256_hex(content)}}},
                filesystem);
        },
        "unsafe transfer target");
    rwn::core::FileTransfer transfer(
        rwn::core::WorkspaceScope(root),
        {.transfer_id = "transfer-chunk",
         .relative_path = "safe.txt",
         .total_size = content.size(),
         .sha256 = rwn::core::sha256_hex(content),
         .chunks = {{.index = 0,
                     .offset = 0,
                     .size = content.size(),
                     .sha256 = rwn::core::sha256_hex(content)}}},
        filesystem);
    const std::string corrupt = "corrupt";
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            transfer.accept_chunk(0, std::as_bytes(std::span{
                                         corrupt.data(), corrupt.size()}));
        },
        "wrong chunk hash");
    RWN_CHECK(!std::filesystem::exists(transfer.destination_path()));
    std::filesystem::remove_all(root, ignored);
}

void command_executor_rejects_escape_and_does_not_inherit_environment() {
    using namespace std::chrono_literals;
    RWN_CHECK(std::getenv("PATH") != nullptr);
    rwn::platform::windows::WindowsCommandExecutor executor(RWN_SOURCE_DIR);
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(executor.execute(
                {.argv = {"relative-program.exe"},
                 .working_directory = ".",
                 .timeout = 1min,
                 .environment = {}}));
        },
        "relative executable");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(executor.execute(
                {.argv = {RWN_PROCESS_FIXTURE, "--success"},
                 .working_directory = "../",
                 .timeout = 1min,
                 .environment = {}}));
        },
        "working directory escape");
    const auto evidence = executor.execute(
        {.argv = {RWN_PROCESS_FIXTURE, "--print-env", "PATH"},
         .working_directory = ".",
         .timeout = 1min,
         .environment = {}});
    RWN_CHECK(evidence.exit_code == 0);
    RWN_CHECK(evidence.stdout_log == "<missing>\r\n" ||
              evidence.stdout_log == "<missing>\n");
}

void command_output_is_bounded() {
    using namespace std::chrono_literals;
    constexpr auto cap = 16U * 1024U * 1024U;
    rwn::platform::windows::WindowsCommandExecutor executor(RWN_SOURCE_DIR);
    const auto evidence = executor.execute(
        {.argv = {RWN_PROCESS_FIXTURE, "--spam-stdout",
                  std::to_string(cap + 1024U)},
         .working_directory = ".",
         .timeout = 1min,
         .environment = {}});
    RWN_CHECK(evidence.exit_code == 0);
    RWN_CHECK(evidence.stdout_truncated);
    RWN_CHECK(evidence.stdout_log.size() == cap);
}

void artifact_publication_rejects_failed_builds_bundles_and_tampering() {
    using namespace std::chrono_literals;
    const auto root = std::filesystem::temp_directory_path() /
                      "rwn-artifact-security";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root / "workspace/dist/App.app");
    std::filesystem::create_directories(root / "store");
    std::ofstream(root / "workspace/dist/failed.zip", std::ios::binary)
        << "failed-output";
    rwn::core::BuildQueue builds;
    const auto submit = [&](const std::string& id, const std::uint64_t revision) {
        builds.submit(
            {.id = id,
             .workspace_id = "game",
             .pinned_revision = revision,
             .profile = "macos-release",
             .command = {.argv = {"/usr/bin/false"},
                         .working_directory = ".",
                         .timeout = 1min,
                         .environment = {}}},
            {});
        builds.start(id);
    };
    submit("failed-build", 10);
    builds.finish(
        "failed-build",
        {.exit_code = 1,
         .stdout_log = {},
         .stderr_log = "failed",
         .elapsed = 1ms,
         .timed_out = false,
         .cancelled = false,
         .stdout_truncated = false,
         .stderr_truncated = false});
    rwn::platform::windows::WindowsDurableFileSystem filesystem;
    rwn::core::AuditLog audit;
    rwn::core::ArtifactStore store(
        builds, root / "workspace", root / "store", filesystem, audit);
    const auto publication_time = rwn::core::WallClock::now();
    rwn::test::require_throws<std::logic_error>(
        [&] {
            static_cast<void>(store.publish(
                {.id = "artifact-failed",
                 .build_id = "failed-build",
                 .source_revision = 10,
                 .name = "failed.zip",
                 .platform = "macos",
                 .architecture = "arm64",
                 .source_relative_path = "dist/failed.zip",
                 .principal_id = "human-1",
                 .device_id = "windows-1",
                 .session_id = "session-1",
                 .occurred_at = publication_time}));
        },
        "failed build artifact");

    submit("successful-build", 11);
    builds.finish(
        "successful-build",
        {.exit_code = 0,
         .stdout_log = {},
         .stderr_log = {},
         .elapsed = 1ms,
         .timed_out = false,
         .cancelled = false,
         .stdout_truncated = false,
         .stderr_truncated = false});
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(store.publish(
                {.id = "artifact-bundle",
                 .build_id = "successful-build",
                 .source_revision = 11,
                 .name = "App.app",
                 .platform = "macos",
                 .architecture = "arm64",
                 .source_relative_path = "dist/App.app",
                 .principal_id = "human-1",
                 .device_id = "windows-1",
                 .session_id = "session-1",
                 .occurred_at = publication_time}));
        },
        "unpackaged app bundle");

    const auto published = store.publish(
        {.id = "artifact-good",
         .build_id = "successful-build",
         .source_revision = 11,
         .name = "failed.zip",
         .platform = "macos",
         .architecture = "arm64",
         .source_relative_path = "dist/failed.zip",
         .principal_id = "human-1",
         .device_id = "windows-1",
         .session_id = "session-1",
         .occurred_at = publication_time});
    RWN_CHECK(store.verify(published.id));
    std::ofstream(store.object_path(published.id),
                  std::ios::binary | std::ios::trunc)
        << "tampered";
    RWN_CHECK(!store.verify(published.id));
    rwn::test::require_throws<std::runtime_error>(
        [&] {
            static_cast<void>(store.download_plan(
                published.id, "unsafe-download", "received.zip"));
        },
        "tampered artifact download");
    {
        std::ofstream metadata(
            root / "store/metadata/forged.toml", std::ios::binary);
        metadata << "schema=1\nid=forged\nunknown=field\n";
    }
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::core::ArtifactStore reloaded(
                builds, root / "workspace", root / "store", filesystem,
                audit);
            static_cast<void>(reloaded);
        },
        "unknown durable artifact metadata schema");
    std::filesystem::remove_all(root, ignored);
}

void deployment_requires_capability_and_matching_workspace() {
    using namespace std::chrono_literals;
    const auto root = std::filesystem::temp_directory_path() /
                      "rwn-deployment-security";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root / "workspace/dist");
    std::filesystem::create_directories(root / "store");
    std::ofstream(root / "workspace/dist/app.bin", std::ios::binary)
        << "deployable";
    rwn::core::BuildQueue builds;
    builds.submit(
        {.id = "build-deploy",
         .workspace_id = "game",
         .pinned_revision = 30,
         .profile = "macos-release",
         .command = {.argv = {"/usr/bin/true"},
                     .working_directory = ".",
                     .timeout = 1min,
                     .environment = {}}},
        {});
    builds.start("build-deploy");
    builds.finish(
        "build-deploy",
        {.exit_code = 0,
         .stdout_log = {},
         .stderr_log = {},
         .elapsed = 1ms,
         .timed_out = false,
         .cancelled = false,
         .stdout_truncated = false,
         .stderr_truncated = false});
    rwn::platform::windows::WindowsDurableFileSystem filesystem;
    rwn::core::AuditLog audit;
    const auto publication_time = rwn::core::WallClock::now();
    rwn::core::ArtifactStore artifacts(
        builds, root / "workspace", root / "store", filesystem, audit);
    const auto artifact = artifacts.publish(
        {.id = "artifact-deploy",
         .build_id = "build-deploy",
         .source_revision = 30,
         .name = "app.bin",
         .platform = "macos",
         .architecture = "arm64",
         .source_relative_path = "dist/app.bin",
         .principal_id = "human-1",
         .device_id = "windows-1",
         .session_id = "session-1",
         .occurred_at = publication_time});
    CountingDeploymentBackend backend;
    rwn::core::DeploymentService service(artifacts, backend, audit);
    const auto now = publication_time + 1s;
    rwn::test::require_throws<std::logic_error>(
        [&] {
            static_cast<void>(service.deploy(
                {.deployment_id = "deploy-denied",
                 .artifact_id = artifact.id,
                 .principal_id = "agent-1",
                 .device_id = "windows-1",
                 .session_id = "session-1",
                 .workspace_id = "game",
                 .authorization = {},
                 .occurred_at = now}));
        },
        "deployment without capability");
    RWN_CHECK(backend.calls == 0);
    RWN_CHECK(audit.events().size() == 2);
    RWN_CHECK(audit.events().back().result == rwn::core::AuditResult::denied);
    RWN_CHECK(audit.events().back().build_id == "build-deploy");
    const rwn::core::AuthorizationResult granted{
        .principal_matched = true,
        .workspace_allowed = true,
        .granted = {rwn::core::Capability::deploy_execute},
        .denied = {},
    };
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(service.deploy(
                {.deployment_id = "deploy-wrong-workspace",
                 .artifact_id = artifact.id,
                 .principal_id = "human-1",
                 .device_id = "windows-1",
                 .session_id = "session-1",
                 .workspace_id = "other",
                 .authorization = granted,
                 .occurred_at = now + 1s}));
        },
        "cross-workspace artifact deployment");
    RWN_CHECK(backend.calls == 0);
    std::filesystem::remove_all(root, ignored);
}

void agent_runtime_denies_unreviewed_privilege_and_scope_escape() {
    using namespace std::chrono_literals;
    const auto root = std::filesystem::temp_directory_path() /
                      "rwn-agent-runtime-security";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root / "src");
    std::ofstream(root / "src/main.cpp", std::ios::binary) << "safe\n";

    rwn::platform::windows::WindowsCommandExecutor executor(root);
    rwn::platform::windows::WindowsDurableFileSystem filesystem;
    rwn::core::BuildQueue builds;
    rwn::core::AuditLog audit;
    rwn::core::RemoteWorkspaceConfig config{
        .workspace_id = "game",
        .workspace_name = "Game",
        .source = "windows",
        .mirror = "macos",
        .sync_direction = "windows_to_macos",
        .sync_excludes = {},
        .profiles = {},
    };
    rwn::core::AgentRuntime runtime(
        root, config, builds, executor, filesystem, nullptr, audit,
        RWN_GIT_EXECUTABLE, {}, {},
        {.maximum_parallel_jobs = 2,
         .maximum_jobs_per_minute = 8,
         .maximum_tool_calls_per_job = 8,
         .maximum_read_bytes = 1024,
         .maximum_patch_bytes = 1024,
         .job_timeout = 1min});
    const auto now = rwn::core::WallClock::now();
    const rwn::core::AuthorizationResult no_agent_run{
        .principal_matched = true,
        .workspace_allowed = true,
        .granted = {rwn::core::Capability::workspace_read},
        .denied = {rwn::core::Capability::agent_run},
    };
    rwn::test::require_throws<std::logic_error>(
        [&] {
            runtime.create_job({
                .job_id = "denied-job",
                .principal_id = "coding-agent",
                .device_id = "windows-1",
                .session_id = "session-1",
                .workspace_id = "game",
                .principal_kind = rwn::core::PrincipalKind::agent,
                .source_revision = 7,
                .authorization = no_agent_run,
                .occurred_at = now,
            });
        },
        "Agent job without explicit agent.run");

    const rwn::core::AuthorizationResult run_only{
        .principal_matched = true,
        .workspace_allowed = true,
        .granted = {rwn::core::Capability::agent_run},
        .denied = {rwn::core::Capability::workspace_read},
    };
    runtime.create_job({
        .job_id = "run-only",
        .principal_id = "coding-agent",
        .device_id = "windows-1",
        .session_id = "session-1",
        .workspace_id = "game",
        .principal_kind = rwn::core::PrincipalKind::agent,
        .source_revision = 7,
        .authorization = run_only,
        .occurred_at = now + 1s,
    });
    rwn::test::require_throws<std::logic_error>(
        [&] {
            static_cast<void>(runtime.execute("run-only", {
                .tool = rwn::core::AgentTool::workspace_read,
                .relative_path = "src/main.cpp",
                .expected_sha256 = {},
                .replacement = {},
                .profile = {},
                .operation_id = {},
                .artifact_id = {},
                .maximum_bytes = 128,
                .occurred_at = now + 2s,
            }));
        },
        "workspace read without capability");
    RWN_CHECK(!runtime.evidence("run-only-e1").succeeded);

    const rwn::core::AuthorizationResult scoped{
        .principal_matched = true,
        .workspace_allowed = true,
        .granted = {rwn::core::Capability::agent_run,
                    rwn::core::Capability::workspace_read,
                    rwn::core::Capability::workspace_write},
        .denied = {rwn::core::Capability::command_exec,
                   rwn::core::Capability::terminal_open,
                   rwn::core::Capability::desktop_control,
                   rwn::core::Capability::clipboard_read,
                   rwn::core::Capability::system_admin},
    };
    runtime.create_job({
        .job_id = "scoped-job",
        .principal_id = "coding-agent",
        .device_id = "windows-1",
        .session_id = "session-1",
        .workspace_id = "game",
        .principal_kind = rwn::core::PrincipalKind::agent,
        .source_revision = 7,
        .authorization = scoped,
        .occurred_at = now + 3s,
    });
    const auto escape = runtime.execute("scoped-job", {
        .tool = rwn::core::AgentTool::workspace_read,
        .relative_path = "../private-secret.txt",
        .expected_sha256 = {},
        .replacement = {},
        .profile = {},
        .operation_id = {},
        .artifact_id = {},
        .maximum_bytes = 128,
        .occurred_at = now + 4s,
    });
    RWN_CHECK(!escape.succeeded);
    RWN_CHECK(escape.stderr_log == "process workspace access denied");

    const auto original_hash = rwn::core::sha256_file(root / "src/main.cpp");
    rwn::test::require_throws<std::logic_error>(
        [&] {
            static_cast<void>(runtime.execute("scoped-job", {
                .tool = rwn::core::AgentTool::workspace_patch,
                .relative_path = "src/main.cpp",
                .expected_sha256 = original_hash,
                .replacement = "changed\n",
                .profile = {},
                .operation_id = {},
                .artifact_id = {},
                .maximum_bytes = 0,
                .occurred_at = now + 5s,
            }));
        },
        "patch without human review");
    RWN_CHECK(rwn::core::sha256_file(root / "src/main.cpp") == original_hash);
    runtime.approve_patch("scoped-job", {
        .reviewer_id = "human-1",
        .device_id = "windows-1",
        .session_id = "review-session",
        .reviewer_kind = rwn::core::PrincipalKind::human,
        .authorization = {
            .principal_matched = true,
            .workspace_allowed = true,
            .granted = {rwn::core::Capability::workspace_write},
            .denied = {},
        },
        .occurred_at = now + 6s,
    });
    const auto patch_escape = runtime.execute("scoped-job", {
        .tool = rwn::core::AgentTool::workspace_patch,
        .relative_path = "../private-secret.txt",
        .expected_sha256 = original_hash,
        .replacement = "exfiltrate\n",
        .profile = {},
        .operation_id = {},
        .artifact_id = {},
        .maximum_bytes = 0,
        .occurred_at = now + 7s,
    });
    RWN_CHECK(!patch_escape.succeeded);
    RWN_CHECK(!runtime.job("scoped-job").patch_review_granted);
    rwn::test::require_throws<std::logic_error>(
        [&] {
            static_cast<void>(runtime.execute("scoped-job", {
                .tool = rwn::core::AgentTool::workspace_patch,
                .relative_path = "src/main.cpp",
                .expected_sha256 = original_hash,
                .replacement = "changed\n",
                .profile = {},
                .operation_id = {},
                .artifact_id = {},
                .maximum_bytes = 0,
                .occurred_at = now + 8s,
            }));
        },
        "one-shot patch review consumed after denied attempt");
    runtime.cancel_job("scoped-job", now + 9s);
    runtime.complete_job("run-only", now + 10s);
    RWN_CHECK(runtime.job("run-only").state ==
              rwn::core::AgentJobState::failed);

    runtime.create_job({
        .job_id = "timeout-job",
        .principal_id = "coding-agent",
        .device_id = "windows-1",
        .session_id = "session-1",
        .workspace_id = "game",
        .principal_kind = rwn::core::PrincipalKind::agent,
        .source_revision = 7,
        .authorization = run_only,
        .occurred_at = now + 11s,
    });
    rwn::test::require_throws<std::runtime_error>(
        [&] {
            static_cast<void>(runtime.execute("timeout-job", {
                .tool = rwn::core::AgentTool::git_status,
                .relative_path = {},
                .expected_sha256 = {},
                .replacement = {},
                .profile = {},
                .operation_id = {},
                .artifact_id = {},
                .maximum_bytes = 0,
                .occurred_at = now + 72s,
            }));
        },
        "Agent job timeout");
    RWN_CHECK(runtime.job("timeout-job").state ==
              rwn::core::AgentJobState::timed_out);

    const auto exported = audit.export_json_lines({
        .agent_job_id = "scoped-job"});
    RWN_CHECK(exported.find("private-secret") == std::string::npos);
    RWN_CHECK(exported.find("exfiltrate") == std::string::npos);
    RWN_CHECK(exported.find("scope.access_denied") != std::string::npos);
    std::filesystem::remove_all(root, ignored);
}
#endif

#if defined(RWN_TEST_MSQUIC_PROVIDER)
void msquic_provider_rejects_implicit_runtime_and_invalid_identity() {
    const auto thumbprint = rwn::transport::parse_sha1_thumbprint(
        "00112233445566778899AABBCCDDEEFF10203040");
    RWN_CHECK(thumbprint.front() == 0x00);
    RWN_CHECK(thumbprint.back() == 0x40);
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(rwn::transport::parse_sha1_thumbprint("1234"));
        },
        "short certificate thumbprint");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(rwn::transport::parse_sha1_thumbprint(
                "00112233445566778899AABBCCDDEEFF1020304Z"));
        },
        "non-hexadecimal certificate thumbprint");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(rwn::transport::parse_sha1_thumbprint(
                "0000000000000000000000000000000000000000"));
        },
        "all-zero certificate thumbprint");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(rwn::transport::probe_msquic_runtime(
                "msquic.dll"));
        },
        "implicit runtime search");
    const auto wrong_name =
        std::filesystem::path(RWN_TEST_MSQUIC_DLL).parent_path() /
        "renamed-provider.dll";
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::transport::probe_msquic_runtime(wrong_name));
        },
        "unexpected runtime filename");

    const auto runtime = std::filesystem::path(RWN_TEST_MSQUIC_DLL);
    const auto server_fingerprint =
        rwn::transport::parse_sha256_fingerprint(
            "ffeeddccbbaa99887766554433221100"
            "ffeeddccbbaa99887766554433221100");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::transport::MsQuicClientConnector({
                .runtime_library = runtime,
                .client_certificate_sha1 = {},
                .allowed_server_certificate_sha256 = {server_fingerprint},
                .connect_timeout = std::chrono::milliseconds{100},
                .stream_read_timeout = std::chrono::milliseconds{100},
            }));
        },
        "missing paired client identity");

    rwn::transport::MsQuicClientConnector connector({
        .runtime_library = runtime,
        .client_certificate_sha1 = thumbprint,
        .allowed_server_certificate_sha256 = {server_fingerprint},
        .connect_timeout = std::chrono::milliseconds{100},
        .stream_read_timeout = std::chrono::milliseconds{100},
    });
    auto missing_server_pin = rwn::transport::MsQuicClientOptions{
        .runtime_library = runtime,
        .client_certificate_sha1 = thumbprint,
        .allowed_server_certificate_sha256 = {},
        .connect_timeout = std::chrono::milliseconds{100},
        .stream_read_timeout = std::chrono::milliseconds{100},
    };
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::transport::validate_msquic_client_options(
                missing_server_pin);
        },
        "missing paired server identity");
    auto excessive_build_wait = missing_server_pin;
    excessive_build_wait.allowed_server_certificate_sha256 = {
        server_fingerprint};
    excessive_build_wait.stream_read_timeout = std::chrono::hours{25};
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::transport::validate_msquic_client_options(
                excessive_build_wait);
        },
        "unbounded MsQuic build response wait");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(connector.connect(
                rwn::transport::TransportMode::quic,
                {.host = "node.example\r\nInjected", .port = 4433,
                 .path = rwn::transport::NetworkPath::lan},
                {}));
        },
        "MsQuic endpoint injection");
    auto downgraded = rwn::transport::QuicTransportSettings{};
    downgraded.require_tls13 = false;
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(connector.connect(
                rwn::transport::TransportMode::quic,
                {.host = "node.example", .port = 4433,
                 .path = rwn::transport::NetworkPath::lan},
                downgraded));
        },
        "MsQuic TLS downgrade");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(connector.connect(
                rwn::transport::TransportMode::tls_tcp_udp_fallback,
                {.host = "node.example", .port = 4433,
                 .path = rwn::transport::NetworkPath::lan},
                {}));
        },
        "fallback routed through MsQuic connector");

    const auto client_fingerprint =
        rwn::transport::parse_sha256_fingerprint(
            "00112233445566778899aabbccddeeff"
            "102030405060708090a0b0c0d0e0f001");
    auto unpaired_fingerprint = client_fingerprint;
    unpaired_fingerprint.back() ^= 1U;
    RWN_CHECK(!rwn::transport::client_certificate_allowed(
        std::span{&client_fingerprint, 1}, unpaired_fingerprint));
    RWN_CHECK(!rwn::transport::client_certificate_allowed(
        std::span<const rwn::transport::CertificateSha256>{},
        client_fingerprint));
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(rwn::transport::parse_sha256_fingerprint(
                "00112233"));
        },
        "short client certificate fingerprint");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(rwn::transport::parse_sha256_fingerprint(
                "00112233445566778899aabbccddeeff"
                "102030405060708090a0b0c0d0e0f00Z"));
        },
        "non-hex client certificate fingerprint");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(rwn::transport::parse_sha256_fingerprint(
                "00000000000000000000000000000000"
                "00000000000000000000000000000000"));
        },
        "zero client certificate fingerprint");

    auto valid_server = rwn::transport::MsQuicServerOptions{
        .runtime_library = runtime,
        .server_certificate_sha1 = thumbprint,
        .allowed_client_certificate_sha256 = {client_fingerprint},
        .listen_port = 4433,
        .certificate_in_machine_store = true,
        .stream_read_timeout = std::chrono::milliseconds{30'000},
        .maximum_pending_connections = 64,
    };
    auto missing_server_identity = valid_server;
    missing_server_identity.server_certificate_sha1 = {};
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::transport::validate_msquic_server_options(
                missing_server_identity);
        },
        "missing server certificate identity");
    auto no_clients = valid_server;
    no_clients.allowed_client_certificate_sha256.clear();
    rwn::test::require_throws<std::invalid_argument>(
        [&] { rwn::transport::validate_msquic_server_options(no_clients); },
        "empty paired client allowlist");
    auto zero_client = valid_server;
    zero_client.allowed_client_certificate_sha256 = {{}};
    rwn::test::require_throws<std::invalid_argument>(
        [&] { rwn::transport::validate_msquic_server_options(zero_client); },
        "zero paired client identity");
    auto duplicate_clients = valid_server;
    duplicate_clients.allowed_client_certificate_sha256.push_back(
        client_fingerprint);
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::transport::validate_msquic_server_options(
                duplicate_clients);
        },
        "duplicate paired client identity");
    auto invalid_port = valid_server;
    invalid_port.listen_port = 0;
    rwn::test::require_throws<std::invalid_argument>(
        [&] { rwn::transport::validate_msquic_server_options(invalid_port); },
        "zero MsQuic listen port");
    auto excessive_pending = valid_server;
    excessive_pending.maximum_pending_connections = 257;
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::transport::validate_msquic_server_options(
                excessive_pending);
        },
        "excessive pending MsQuic connections");
}
#endif

#if defined(RWN_TEST_WINDOWS_PLATFORM)
void schannel_fallback_rejects_implicit_or_unbounded_identity() {
    using rwn::platform::windows::SchannelFallbackClientOptions;
    // Configuration must fail before certificate-store lookup or network IO.
    rwn::test::require_throws<std::invalid_argument>([] {
        static_cast<void>(rwn::platform::windows::connect_dedicated_tls_channel(
            {}, {"127.0.0.1", 1, rwn::transport::NetworkPath::lan}));
    }, "dedicated TLS requires explicit paired identities");
    const auto client =
        rwn::platform::windows::parse_schannel_sha1_thumbprint(
            "00112233445566778899AABBCCDDEEFF10203040");
    const auto server =
        rwn::platform::windows::parse_schannel_sha256_fingerprint(
            "00112233445566778899aabbccddeeff"
            "102030405060708090a0b0c0d0e0f001");
    const auto valid = SchannelFallbackClientOptions{
        .client_certificate_sha1 = client,
        .allowed_server_certificate_sha256 = {server},
    };

    for (const auto size : {1U, 65537U}) {
        auto invalid_root = valid;
        invalid_root.exclusive_root_der.assign(size, std::byte{0});
        rwn::test::require_throws<std::invalid_argument>([&] {
            rwn::platform::windows::validate_schannel_fallback_client_options(invalid_root);
        }, "application TLS root rejects malformed and oversized DER");
    }

    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(
                rwn::platform::windows::parse_schannel_sha1_thumbprint(
                    "00112233"));
        },
        "short Schannel client thumbprint");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(
                rwn::platform::windows::parse_schannel_sha256_fingerprint(
                    "00112233445566778899aabbccddeeff"
                    "102030405060708090a0b0c0d0e0f00Z"));
        },
        "non-hex Schannel server fingerprint");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(
                rwn::platform::windows::parse_schannel_sha1_thumbprint(
                    "0000000000000000000000000000000000000000"));
        },
        "zero Schannel client thumbprint");

    auto missing_client = valid;
    missing_client.client_certificate_sha1 = {};
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::platform::windows::validate_schannel_fallback_client_options(
                missing_client);
        },
        "missing Schannel client identity");
    auto missing_servers = valid;
    missing_servers.allowed_server_certificate_sha256.clear();
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::platform::windows::validate_schannel_fallback_client_options(
                missing_servers);
        },
        "missing Schannel server allowlist");
    auto duplicate_servers = valid;
    duplicate_servers.allowed_server_certificate_sha256.push_back(server);
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::platform::windows::validate_schannel_fallback_client_options(
                duplicate_servers);
        },
        "duplicate Schannel server identity");
    auto implicit_store = valid;
    implicit_store.certificate_store_name = L"ROOT";
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::platform::windows::validate_schannel_fallback_client_options(
                implicit_store);
        },
        "non-MY Schannel certificate store");
    auto short_timeout = valid;
    short_timeout.connect_timeout = std::chrono::milliseconds{99};
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::platform::windows::validate_schannel_fallback_client_options(
                short_timeout);
        },
        "unbounded Schannel connect timeout");
    auto excessive_streams = valid;
    excessive_streams.maximum_streams = 257;
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::platform::windows::validate_schannel_fallback_client_options(
                excessive_streams);
        },
        "excessive Schannel stream count");
    auto undersized_queue = valid;
    undersized_queue.maximum_queued_stream_bytes = 1024;
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::platform::windows::validate_schannel_fallback_client_options(
                undersized_queue);
        },
        "undersized Schannel stream queue");

    rwn::platform::windows::SchannelFallbackClientProvider provider(valid);
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(provider.connect_tls13(
                {.host = "node.example\r\nInjected", .port = 4433,
                 .path = rwn::transport::NetworkPath::lan},
                {}));
        },
        "Schannel endpoint injection");
    auto downgraded = rwn::transport::QuicTransportSettings{};
    downgraded.require_tls13 = false;
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(provider.connect_tls13(
                {.host = "node.example", .port = 4433,
                 .path = rwn::transport::NetworkPath::lan},
                downgraded));
        },
        "Schannel TLS downgrade");
    rwn::test::require_throws<std::logic_error>(
        [&] {
            static_cast<void>(provider.connect_dtls12(
                {.host = "node.example", .port = 4433,
                 .path = rwn::transport::NetworkPath::lan},
                {}));
        },
        "Schannel DTLS without TLS binding");
}
#endif

void visual_trace_rejects_untrusted_data_and_unsafe_destinations() {
#if defined(RWN_TEST_WINDOWS_PLATFORM)
    const std::array<std::byte, 24> malformed_nv12{};
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::platform::windows::repack_padded_nv12(
                malformed_nv12, 4, 4, 3, 4));
        },
        "NV12 stride smaller than visible width");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::platform::windows::repack_padded_nv12(
                malformed_nv12, 4, 4, 4, 68));
        },
        "excessive NV12 padded luma rows");
#endif
    rwn::test::require_throws<std::invalid_argument>(
        [] { rwn::desktop::VisualTailRefreshBudget invalid(0, 20'000); },
        "zero visual tail refresh budget");
    rwn::desktop::VisualTailRefreshBudget refresh;
    refresh.publish_visual(100, 1'000);
    rwn::test::require_throws<std::invalid_argument>(
        [&] { refresh.repeat_completed(99); },
        "stale visual tail refresh generation");
    const rwn::desktop::VisualTraceEvent event{
        .schema_version = rwn::desktop::visual_trace_schema_version,
        .host = rwn::desktop::VisualTraceHost::mac,
        .session_generation = 9,
        .representation_epoch = 7,
        .event_sequence = 1,
        .frame_id = 42,
        .stage = rwn::desktop::VisualLifecycleStage::vt_output,
        .local_monotonic_us = 100,
    };
    const auto valid = rwn::desktop::render_visual_trace_json(event);
    for (const auto field : {"latest_source_frame_id", "latest_content_frame_id",
                             "exact_base_frame_id", "exact_base_content_frame_id"}) {
        for (const auto number : {"00", "-1", "18446744073709551616"}) {
            auto invalid = valid;
            const auto needle = std::string("\"") + field + "\":0";
            const auto offset = invalid.find(needle);
            RWN_CHECK(offset != std::string::npos);
            invalid.replace(offset, needle.size(),
                            std::string("\"") + field + "\":" + number);
            rwn::test::require_throws<std::invalid_argument>([&] {
                static_cast<void>(rwn::desktop::decode_visual_trace_json(invalid));
            }, "invalid source/content trace identity");
        }
    }
    const auto replace_once = [](std::string value, const std::string_view from,
                                 const std::string_view to) {
        const auto offset = value.find(from);
        RWN_CHECK(offset != std::string::npos);
        value.replace(offset, from.size(), to);
        return value;
    };
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::decode_visual_trace_json(
                replace_once(valid, "\"stage\":\"vt_output\"",
                             "\"stage\":\"unknown\"")));
        },
        "unknown visual trace stage");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::decode_visual_trace_json(
                replace_once(valid, "\"fallback_reason\":\"none\"",
                             "\"fallback_reason\":\"untrusted\"")));
        },
        "unknown visual fallback reason");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::decode_visual_trace_json(
                replace_once(valid,
                    "\"exact_residency_ratio_ppm\":0",
                    "\"exact_residency_ratio_ppm\":1000001")));
        },
        "visual exact residency overflow");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::decode_visual_trace_json(
                replace_once(valid, "\"frame_id\":42",
                             "\"frame_id\":042")));
        },
        "noncanonical visual trace number");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::decode_visual_trace_json(
                replace_once(valid, "\"frame_id\":42",
                    "\"frame_id\":18446744073709551616")));
        },
        "visual trace generation overflow");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::decode_visual_trace_json(
                replace_once(valid, "\"representation_epoch\":7",
                    "\"representation_epoch\":18446744073709551616")));
        },
        "visual trace representation epoch overflow");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::decode_visual_trace_json(
                valid + "\n"));
        },
        "multiline visual trace");
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            static_cast<void>(rwn::desktop::decode_visual_trace_json(
                std::string(
                    rwn::desktop::maximum_visual_trace_line_bytes + 1U,
                    'x')));
        },
        "oversized visual trace");

    const auto root = std::filesystem::temp_directory_path() /
        ("rwn-visual-trace-security-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(root);
    const auto fresh = root / "fresh.jsonl";
    rwn::desktop::validate_visual_trace_destination(fresh);
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            rwn::desktop::validate_visual_trace_destination("relative.jsonl");
        },
        "relative visual trace destination");
    const auto existing = root / "existing.jsonl";
    std::ofstream(existing) << "already exists";
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::desktop::validate_visual_trace_destination(existing);
        },
        "existing visual trace destination");
    std::filesystem::remove(existing);
    std::filesystem::remove(root);
}

void visual_evidence_fails_closed_on_invalid_or_corrupt_runs() {
    using namespace rwn::desktop;
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(compare_visual_evidence(
                {}, {}, "../unsafe", 30, 200'000));
        },
        "unsafe evidence workload");
    rwn::test::require_throws<std::invalid_argument>(
        [] {
            static_cast<void>(compare_visual_evidence(
                {}, {}, "typing", 30, 1'000'001));
        },
        "noncanonical evidence improvement ratio");

    const std::array hybrid{
        VisualTraceEvent{
            .host = VisualTraceHost::windows,
            .session_generation = 1,
            .representation_epoch = 2,
            .event_sequence = 1,
            .frame_id = 10,
            .stage = VisualLifecycleStage::gpu_exact_verify,
            .local_monotonic_us = 100,
            .payload_bytes = 64,
            .verification_mismatches = 1,
        },
        VisualTraceEvent{
            .host = VisualTraceHost::windows,
            .session_generation = 1,
            .representation_epoch = 2,
            .event_sequence = 2,
            .frame_id = 10,
            .stage = VisualLifecycleStage::trace_dropped,
            .local_monotonic_us = 101,
            .trace_dropped = 3,
        },
        VisualTraceEvent{
            .host = VisualTraceHost::windows,
            .session_generation = 1,
            .representation_epoch = 2,
            .event_sequence = 3,
            .frame_id = 10,
            .stage = VisualLifecycleStage::visual_stall,
            .local_monotonic_us = 102,
        },
    };
    const auto comparison = compare_visual_evidence(
        {}, hybrid, "typing", 1, 0);
    RWN_CHECK(!comparison.correctness_gate_passed);
    RWN_CHECK(!comparison.latency_gate_passed);
    RWN_CHECK(comparison.hybrid.trace_dropped == 3U);
    RWN_CHECK(comparison.hybrid.unrecovered_stalls == 1U);
    RWN_CHECK(comparison.hybrid.exact_mismatched_bytes == 1U);
    const std::array wrong_host{
        VisualTraceEvent{
            .host = VisualTraceHost::windows,
            .session_generation = 1,
            .event_sequence = 1,
            .frame_id = 1,
            .stage = VisualLifecycleStage::wire_write_complete,
            .local_monotonic_us = 1,
        },
    };
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(analyze_visual_evidence(wrong_host)); },
        "wrong-host visual evidence stage");
    const std::array overflowing{
        VisualTraceEvent{
            .host = VisualTraceHost::mac,
            .session_generation = 1,
            .event_sequence = 1,
            .frame_id = 1,
            .stage = VisualLifecycleStage::wire_write_complete,
            .local_monotonic_us = 1,
            .payload_bytes = std::numeric_limits<std::uint64_t>::max(),
        },
        VisualTraceEvent{
            .host = VisualTraceHost::mac,
            .session_generation = 1,
            .event_sequence = 2,
            .frame_id = 2,
            .stage = VisualLifecycleStage::wire_write_complete,
            .local_monotonic_us = 2,
            .payload_bytes = 1,
        },
    };
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(analyze_visual_evidence(overflowing)); },
        "visual evidence byte overflow");

    const auto root = std::filesystem::temp_directory_path() /
        ("rwn-visual-evidence-security-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(root);
    const auto input = root / "input.jsonl";
    std::ofstream(input) << "{}\n";
    validate_visual_evidence_input(input);
    const auto output = root / "report.json";
    write_visual_evidence_report_new(output, "{}\n");
    RWN_CHECK(std::filesystem::file_size(output) == 3U);
    rwn::test::require_throws<std::invalid_argument>(
        [&] { write_visual_evidence_report_new(output, "replacement\n"); },
        "existing visual evidence report");
    rwn::test::require_throws<std::invalid_argument>(
        [] { validate_visual_evidence_input("relative.jsonl"); },
        "relative visual evidence input");
    rwn::test::require_throws<std::invalid_argument>(
        [] { validate_visual_evidence_output("relative.json"); },
        "relative visual evidence output");
    rwn::test::require_throws<std::length_error>(
        [&] {
            write_visual_evidence_report_new(
                root / "oversized.json",
                std::string(maximum_visual_evidence_report_bytes + 1U, 'x'));
        },
        "oversized visual evidence output");
    std::filesystem::remove(output);
    std::filesystem::remove(input);
    std::filesystem::remove(root);
}

void exact_only_mode_rejects_lossy_and_unimplemented_representations() {
    using rwn::desktop::VisualMessageType;
    using rwn::desktop::VisualRuntimeMode;

    RWN_CHECK(!rwn::desktop::visual_message_allowed(
        VisualRuntimeMode::exact_only,
        VisualMessageType::h264_access_unit));
    RWN_CHECK(!rwn::desktop::visual_message_allowed(
        VisualRuntimeMode::exact_only, VisualMessageType::lz4_rect));
    RWN_CHECK(!rwn::desktop::visual_message_allowed(
        VisualRuntimeMode::exact_only, VisualMessageType::copy_rect));
    RWN_CHECK(rwn::desktop::visual_message_allowed(
        VisualRuntimeMode::exact_only, VisualMessageType::state_reset));
    RWN_CHECK(rwn::desktop::visual_message_allowed(
        VisualRuntimeMode::exact_only, VisualMessageType::full_snapshot));
    RWN_CHECK(rwn::desktop::visual_message_allowed(
        VisualRuntimeMode::exact_only, VisualMessageType::raw_rect));
}

}  // namespace

#include "channel_session_tests.hpp"

int main() {
    rwn::test::Runner runner;
    runner.run("TCP channels reject untrusted cross-session and duplicate bindings", channel_tests::security);
    runner.run("build and artifact wire rejects forged evidence", build_and_artifact_wire_rejects_forged_evidence);
    runner.run("workspace control wire rejects unsafe transactions", workspace_control_wire_rejects_unsafe_transactions);
    runner.run("build service rejects scope revision and forged reply", build_service_rejects_scope_revision_and_forged_reply);
    runner.run("artifact service rejects capability and stale revision", artifact_service_rejects_capability_and_stale_revision);
    runner.run("deployment service rejects missing capability", deployment_service_rejects_missing_capability);
    runner.run("workspace mirror transaction rejects forged scope and hash", workspace_mirror_transaction_rejects_forged_scope_and_hash);
    runner.run("workspace client rejects forged reply correlation", workspace_client_rejects_forged_reply_correlation);
    runner.run("product runtime configs reject unsafe state", product_runtime_configs_reject_unsafe_state);
    runner.run("Node control rejects unverified peer and malformed wire", node_control_rejects_unverified_peer_and_malformed_wire);
    runner.run("Apple Network contract rejects implicit identity and queues", apple_network_contract_rejects_implicit_identity_and_unbounded_queues);
    runner.run("malformed envelope rejected", malformed_envelope_is_rejected);
    runner.run("protocol and release gates reject malicious inputs", protocol_and_release_gates_reject_malformed_or_malicious_inputs);
    runner.run("update policy rejects downgrade and unsigned metadata", update_policy_rejects_downgrade_tampering_and_unsigned_metadata);
    runner.run("protected release state is bounded and complete", protected_release_state_is_bounded_and_complete);
    runner.run("release diagnostics reject freeform and forged evidence", release_diagnostics_reject_freeform_or_forged_evidence);
#if defined(RWN_TEST_WINDOWS_PLATFORM)
    runner.run("update signature public key is bounded", update_signature_public_key_is_bounded);
#endif
    runner.run("oversized payload rejected", declared_oversized_payload_is_rejected);
    runner.run("desktop wire messages are bounded", desktop_wire_messages_are_strictly_bounded);
    runner.run("visual trace rejects untrusted data and unsafe destinations", visual_trace_rejects_untrusted_data_and_unsafe_destinations);
    runner.run("visual evidence fails closed on corrupt runs", visual_evidence_fails_closed_on_invalid_or_corrupt_runs);
    runner.run("exact-only mode rejects codec downgrade", exact_only_mode_rejects_lossy_and_unimplemented_representations);
    runner.run("audio packets and capability gate are bounded", audio_packets_and_capability_gate_are_bounded);
    runner.run("audio jitter bounds late and overflow packets", jitter_buffer_bounds_late_and_overflow_packets);
    runner.run("transport configuration and recovery fail closed", transport_configuration_negotiation_and_recovery_fail_closed);
    runner.run("encrypted fallback rejects downgrade and plane splicing", encrypted_fallback_rejects_downgrade_splicing_and_unbounded_io);
    runner.run("transport verification rejects forged evidence", transport_verification_rejects_forged_or_malformed_evidence);
    runner.run("view-only session blocks input and clipboard", desktop_control_is_denied_before_platform_or_transport_access);
    runner.run("input order and clipboard integrity enforced", input_order_clipboard_hash_and_replay_are_enforced);
    runner.run("workspace traversal rejected", workspace_traversal_and_absolute_paths_are_rejected);
    runner.run("workspace sibling prefix rejected", sibling_prefix_is_not_treated_as_workspace_child);
    runner.run("principal and workspace scope enforced", wrong_principal_and_workspace_are_denied);
    runner.run("agent high-risk capabilities denied", agent_policy_denies_high_risk_capabilities);
    runner.run("pairing code, expiry, and revocation enforced", pairing_rejects_wrong_code_expired_challenge_and_revoked_device);
    runner.run("pairing store rejects escape tampering and replacement", pairing_store_rejects_escape_tampering_and_replacement);
    runner.run("pairing control rejects wrong code rebinding and forged reply", pairing_control_rejects_wrong_code_rebinding_and_forged_reply);
    runner.run("mTLS trust gate rejects downgraded or revoked peers", mtls_gate_requires_tls13_certificate_and_active_pairing);
    runner.run("manifest paths and chunks are bounded", manifest_rejects_traversal_case_unsafe_paths_and_invalid_chunks);
    runner.run("workspace paths reject Windows aliases and ADS", workspace_paths_reject_windows_aliases_ads_and_controls);
    runner.run("manifest rejects case collision and symlink escape", manifest_rejects_case_collisions_and_unsafe_symlink_targets);
    runner.run("manifest rejects noncanonical order", manifest_rejects_noncanonical_entry_order);
    runner.run("remoteignore rejects unsafe rules", remoteignore_rejects_negation_and_traversal_rules);
    runner.run("command environment is deny-by-default", command_environment_is_deny_by_default);
    runner.run("build profile parser fails closed", build_profile_parser_rejects_privilege_and_path_injection);
    runner.run("build artifact discovery rejects ambiguous outputs", build_artifact_discovery_rejects_ambiguous_or_excess_outputs);
    runner.run("terminal API enforces capability scope and bounds", terminal_api_requires_capability_scope_and_bounded_io);
    runner.run("process roles enforce workspace scope and audit denials", process_roles_enforce_workspace_scope_and_audit_denials);
    runner.run("audit query export and retention are bounded", audit_query_export_and_retention_are_bounded);
    runner.run("policy parser rejects unknown privilege fields", policy_parser_rejects_unknown_fields_and_capabilities);
    runner.run("revocation closes an active session", active_session_loses_access_after_device_revocation);
    runner.run("mTLS identity rebinding is rejected", mtls_identity_cannot_be_rebound_to_another_principal);
#if defined(RWN_TEST_MSQUIC_PROVIDER)
    runner.run("MsQuic provider requires explicit runtime and identity", msquic_provider_rejects_implicit_runtime_and_invalid_identity);
#endif
#if defined(RWN_TEST_WINDOWS_PLATFORM)
    runner.run("Schannel fallback rejects implicit or unbounded identity", schannel_fallback_rejects_implicit_or_unbounded_identity);
    runner.run("Windows pairing codes use native CNG", windows_pairing_codes_use_native_rng_and_canonical_format);
    runner.run("Windows DNS-SD service type is validated", windows_dns_sd_adapter_rejects_empty_service_type);
    runner.run("Windows DNS-SD browse starts and stops", windows_dns_sd_adapter_starts_and_stops_native_browse);
    runner.run("failed file hash preserves destination", failed_file_hash_never_overwrites_destination);
    runner.run("file transfer rejects corrupt or escaping content", file_transfer_rejects_wrong_chunk_and_unsafe_target);
    runner.run("command execution is scoped and environment-isolated", command_executor_rejects_escape_and_does_not_inherit_environment);
    runner.run("command output capture is bounded", command_output_is_bounded);
    runner.run("artifact publication rejects untrusted evidence", artifact_publication_rejects_failed_builds_bundles_and_tampering);
    runner.run("deployment requires capability and workspace binding", deployment_requires_capability_and_matching_workspace);
    runner.run("Agent runtime denies privilege review bypass and scope escape", agent_runtime_denies_unreviewed_privilege_and_scope_escape);
#endif
    return runner.exit_code();
}
