#include "channel_session_tests.hpp"
#include "rwn/core/audit.hpp"
#include "rwn/audio/audio.hpp"
#include "rwn/client/session_client.hpp"
#include "rwn/client/build_client.hpp"
#include "rwn/client/artifact_client.hpp"
#include "rwn/client/deployment_client.hpp"
#include "rwn/client/workspace_client.hpp"
#include "rwn/core/agent_runtime.hpp"
#include "rwn/core/artifact_store.hpp"
#include "rwn/core/audit_file.hpp"
#include "rwn/core/build.hpp"
#include "rwn/core/build_config.hpp"
#include "rwn/core/authorization.hpp"
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
#include "rwn/core/workspace_sync.hpp"
#include "rwn/core/workspace_manifest.hpp"
#include "rwn/core/workspace_watcher.hpp"
#include "rwn/desktop/desktop.hpp"
#include "rwn/desktop/pointer_click_tracker.hpp"
#include "rwn/desktop/snapshot_upload.hpp"
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

#if defined(RWN_TEST_WINDOWS_PLATFORM)
#include "rwn/platform/windows/command_executor.hpp"
#include "rwn/platform/windows/desktop_runtime.hpp"
#include "rwn/platform/windows/directory_watcher.hpp"
#include "rwn/platform/windows/durable_filesystem.hpp"
#include "rwn/platform/windows/schannel_transport.hpp"
#include "rwn/platform/windows/update_signature.hpp"
#endif

#include <algorithm>
#include <array>
#include <cstddef>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <future>
#include <iomanip>
#include <iterator>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {

void build_and_artifact_control_wire_round_trips_evidence() {
    constexpr auto hash =
        "00112233445566778899aabbccddeeff"
        "00112233445566778899aabbccddeeff";
    const rwn::protocol::BuildSubmitCommand submit{
        .session_id = "session-42",
        .workspace_id = "workspace-42",
        .revision = 42,
        .build_id = "build-42",
        .profile = "macos-debug",
    };
    RWN_CHECK(rwn::protocol::decode_build_submit_command(
        rwn::protocol::encode_build_submit_command(submit)) == submit);

    const rwn::protocol::BuildStatusReply status{
        .accepted = true,
        .build_id = "build-42",
        .state = rwn::protocol::BuildWireState::succeeded,
        .exit_code = 0,
        .elapsed_ms = 1532,
        .timed_out = false,
        .cancelled = false,
        .stdout_truncated = false,
        .stderr_truncated = false,
        .stdout_log = "configured\nbuilt\n",
        .stderr_log = {},
        .evidence_sha256 = hash,
        .artifact_ids = {"artifact-42"},
        .reason_code = "build_succeeded",
    };
    RWN_CHECK(rwn::protocol::decode_build_status_reply(
        rwn::protocol::encode_build_status_reply(status)) == status);

    const rwn::protocol::ArtifactFetchCommand fetch{
        .session_id = "session-42",
        .workspace_id = "workspace-42",
        .revision = 42,
        .artifact_id = "artifact-42",
        .transfer_id = "artifact-transfer-42",
    };
    RWN_CHECK(rwn::protocol::decode_artifact_fetch_command(
        rwn::protocol::encode_artifact_fetch_command(fetch)) == fetch);

    const rwn::protocol::DeploySubmitCommand deploy{
        .session_id = "session-42", .workspace_id = "workspace-42",
        .revision = 42, .artifact_id = "artifact-42",
        .deployment_id = "deployment-42"};
    RWN_CHECK(rwn::protocol::decode_deploy_submit_command(
        rwn::protocol::encode_deploy_submit_command(deploy)) == deploy);
    const rwn::protocol::DeployStatusReply deployment{
        .accepted = true, .deployment_id = "deployment-42",
        .artifact_id = "artifact-42", .artifact_sha256 = hash,
        .build_id = "build-42", .source_revision = 42,
        .status = rwn::protocol::DeploymentWireStatus::active,
        .steps = {{.step = 0, .succeeded = true, .exit_code = 0,
                   .elapsed_ms = 7, .timed_out = false, .cancelled = false,
                   .reason_code = "step_succeeded"}},
        .evidence_sha256 = hash, .reason_code = "deployment_active"};
    RWN_CHECK(rwn::protocol::decode_deploy_status_reply(
        rwn::protocol::encode_deploy_status_reply(deployment)) == deployment);

    const rwn::protocol::ArtifactManifestReply manifest{
        .accepted = true,
        .artifact_id = "artifact-42",
        .transfer_id = "artifact-transfer-42",
        .build_id = "build-42",
        .source_revision = 42,
        .name = "product.zip",
        .sha256 = hash,
        .size = 5,
        .platform = "macos",
        .architecture = "arm64",
        .chunks = {{.index = 0, .offset = 0, .size = 5, .sha256 = hash}},
        .reason_code = "artifact_ready",
    };
    RWN_CHECK(rwn::protocol::decode_artifact_manifest_reply(
        rwn::protocol::encode_artifact_manifest_reply(manifest)) == manifest);

    const rwn::protocol::ArtifactChunkCommand chunk{
        .session_id = "session-42",
        .workspace_id = "workspace-42",
        .revision = 42,
        .artifact_id = "artifact-42",
        .transfer_id = "artifact-transfer-42",
        .index = 0,
        .bytes = {std::byte{'h'}, std::byte{'e'}, std::byte{'l'},
                  std::byte{'l'}, std::byte{'o'}},
    };
    RWN_CHECK(rwn::protocol::decode_artifact_chunk_command(
        rwn::protocol::encode_artifact_chunk_command(chunk)) == chunk);
}

void workspace_control_wire_round_trips_sync_transaction() {
    constexpr auto first_hash =
        "00112233445566778899aabbccddeeff"
        "00112233445566778899aabbccddeeff";
    constexpr auto second_hash =
        "abcdefabcdefabcdefabcdefabcdefab"
        "cdefabcdefabcdefabcdefabcdefabcd";
    const rwn::protocol::WorkspaceManifestCommand manifest{
        .session_id = "session-42",
        .workspace_id = "game",
        .revision = 42,
        .manifest_sha256 = first_hash,
        .entries = {
            {.path = "CMakeLists.txt",
             .kind = rwn::protocol::WorkspaceWireEntryKind::file,
             .size = 3,
             .sha256 = second_hash,
             .mode = 0644U,
             .symlink_target = {}},
            {.path = "src",
             .kind = rwn::protocol::WorkspaceWireEntryKind::directory,
             .size = 0,
             .sha256 = {},
             .mode = 0755U,
             .symlink_target = {}},
        },
    };
    RWN_CHECK(rwn::protocol::decode_workspace_manifest_command(
        rwn::protocol::encode_workspace_manifest_command(manifest)) == manifest);

    const rwn::protocol::WorkspaceDiffReply diff{
        .accepted = true,
        .current_revision = 41,
        .requested_file_paths = {"CMakeLists.txt"},
        .reason_code = "workspace_diff_ready",
    };
    RWN_CHECK(rwn::protocol::decode_workspace_diff_reply(
        rwn::protocol::encode_workspace_diff_reply(diff)) == diff);

    const rwn::protocol::WorkspaceFilePlanCommand plan{
        .session_id = "session-42",
        .workspace_id = "game",
        .revision = 42,
        .transfer_id = "file-42",
        .path = "CMakeLists.txt",
        .total_size = 3,
        .sha256 = second_hash,
        .chunks = {{.index = 0,
                    .offset = 0,
                    .size = 3,
                    .sha256 = second_hash}},
    };
    RWN_CHECK(rwn::protocol::decode_workspace_file_plan_command(
        rwn::protocol::encode_workspace_file_plan_command(plan)) == plan);
    const rwn::protocol::WorkspaceFilePlanReply plan_reply{
        .accepted = true,
        .missing_chunks = {0},
        .reason_code = "file_plan_ready",
    };
    RWN_CHECK(rwn::protocol::decode_workspace_file_plan_reply(
        rwn::protocol::encode_workspace_file_plan_reply(plan_reply)) ==
        plan_reply);

    const rwn::protocol::WorkspaceFileChunkCommand chunk{
        .session_id = "session-42",
        .workspace_id = "game",
        .revision = 42,
        .transfer_id = "file-42",
        .index = 0,
        .bytes = {std::byte{'a'}, std::byte{'b'}, std::byte{'c'}},
    };
    RWN_CHECK(rwn::protocol::decode_workspace_file_chunk_command(
        rwn::protocol::encode_workspace_file_chunk_command(chunk)) == chunk);

    const rwn::protocol::WorkspaceCommitCommand commit{
        .session_id = "session-42",
        .workspace_id = "game",
        .revision = 42,
        .manifest_sha256 = first_hash,
    };
    RWN_CHECK(rwn::protocol::decode_workspace_commit_command(
        rwn::protocol::encode_workspace_commit_command(commit)) == commit);
    const rwn::protocol::WorkspaceCommitReply committed{
        .accepted = true,
        .revision = 42,
        .manifest_sha256 = first_hash,
        .reason_code = "workspace_committed",
    };
    RWN_CHECK(rwn::protocol::decode_workspace_commit_reply(
        rwn::protocol::encode_workspace_commit_reply(committed)) == committed);
}

void workspace_mirror_transaction_applies_verified_revision() {
    const auto root = std::filesystem::temp_directory_path() /
        ("rwn-workspace-mirror-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(root);
    {
        std::ofstream extra(root / "obsolete.txt", std::ios::binary);
        extra << "remove me";
    }
    const std::vector bytes{
        std::byte{'a'}, std::byte{'b'}, std::byte{'c'}};
    const auto file_hash = rwn::core::sha256_hex(bytes);
    const rwn::core::WorkspaceManifest core_manifest{
        .workspace_id = "game",
        .revision = 1,
        .entries = {
            {.path = "src",
             .kind = rwn::core::WorkspaceEntryKind::directory,
             .size = 0,
             .content_hash = {},
             .mode = 0755U,
             .symlink_target = {}},
            {.path = "src/main.cpp",
             .kind = rwn::core::WorkspaceEntryKind::file,
             .size = bytes.size(),
             .content_hash = file_hash,
             .mode = 0644U,
             .symlink_target = {}},
        },
    };
    const auto manifest_hash = rwn::core::manifest_content_hash(core_manifest);
    rwn::test::TestDurableFileSystem filesystem;
    rwn::node::WorkspaceMirrorService service(root, "game", 0, filesystem);
    const auto diff = service.begin({
        .session_id = "session-1",
        .workspace_id = "game",
        .revision = 1,
        .manifest_sha256 = manifest_hash,
        .entries = {
            {.path = "src",
             .kind = rwn::protocol::WorkspaceWireEntryKind::directory,
             .size = 0,
             .sha256 = {},
             .mode = 0755U,
             .symlink_target = {}},
            {.path = "src/main.cpp",
             .kind = rwn::protocol::WorkspaceWireEntryKind::file,
             .size = bytes.size(),
             .sha256 = file_hash,
             .mode = 0644U,
             .symlink_target = {}},
        },
    });
    RWN_CHECK(diff.accepted);
    RWN_CHECK(diff.current_revision == 0);
    RWN_CHECK(diff.requested_file_paths ==
              std::vector<std::string>{"src/main.cpp"});
    const auto plan = service.accept_plan({
        .session_id = "session-1",
        .workspace_id = "game",
        .revision = 1,
        .transfer_id = "main-1",
        .path = "src/main.cpp",
        .total_size = bytes.size(),
        .sha256 = file_hash,
        .chunks = {{.index = 0,
                    .offset = 0,
                    .size = static_cast<std::uint32_t>(bytes.size()),
                    .sha256 = file_hash}},
    });
    RWN_CHECK(plan.accepted);
    RWN_CHECK(plan.missing_chunks == std::vector<std::uint32_t>{0});
    service.accept_chunk({
        .session_id = "session-1",
        .workspace_id = "game",
        .revision = 1,
        .transfer_id = "main-1",
        .index = 0,
        .bytes = bytes,
    });
    const auto committed = service.commit({
        .session_id = "session-1",
        .workspace_id = "game",
        .revision = 1,
        .manifest_sha256 = manifest_hash,
    });
    RWN_CHECK(committed.accepted);
    RWN_CHECK(committed.revision == 1);
    RWN_CHECK(rwn::core::sha256_file(root / "src/main.cpp") == file_hash);
    RWN_CHECK(!std::filesystem::exists(root / "obsolete.txt"));
    const auto state_root = root.parent_path() /
        (root.filename().string() + "-state");
    rwn::node::WorkspaceMirrorStateFile state(
        state_root, "workspace/game.toml", "game", filesystem);
    RWN_CHECK(state.state().revision == 0);
    state.persist(1, manifest_hash);
    rwn::node::WorkspaceMirrorStateFile reloaded(
        state_root, "workspace/game.toml", "game", filesystem);
    RWN_CHECK(reloaded.state().revision == 1);
    RWN_CHECK(reloaded.state().manifest_sha256 == manifest_hash);
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::remove_all(state_root, ignored);
}

void product_runtime_configs_are_strict_and_complete() {
    const auto native_absolute_config = [](std::string config) {
#if !defined(_WIN32)
        std::size_t offset{};
        while ((offset = config.find("C:/", offset)) != std::string::npos) {
            config.replace(offset, 3, "/");
            ++offset;
        }
#endif
        return config;
    };
    const std::string node_config = native_absolute_config(
        "transport_provider = \"msquic\"\n"
        "runtime_library = \"C:/rwn/msquic.dll\"\n"
        "local_identity_hex = \"00112233445566778899aabbccddeeff00112233\"\n"
        "listen_port = 4433\n"
        "transport_settings_file = \"C:/rwn/transport.toml\"\n"
        "policy_file = \"C:/rwn/policy.toml\"\n"
        "audit_root = \"C:/rwn/state\"\n"
        "audit_journal = \"audit/events.jsonl\"\n"
        "pairing_root = \"C:/rwn/state/pairing\"\n"
        "pairing_state_file = \"device.state\"\n"
        "mirror_root = \"C:/rwn/mirror\"\n"
        "workspace_state_file = \"workspace/game.toml\"\n"
        "workspace_config_file = \"C:/rwn/remote-workspace.toml\"\n"
        "build_worker_socket = \"C:/rwn/run/build-worker.sock\"\n"
        "build_worker_uid = 501\n"
        "deployment_broker_socket = \"C:/rwn/run/deployment-broker.sock\"\n"
        "deployment_broker_uid = 0\n"
        "maximum_active_sessions = 1\n"
        "accept_timeout_seconds = 120\n"
        "paired_device_id = \"windows-client\"\n"
        "paired_device_name = \"Windows Client\"\n"
        "paired_device_certificate_sha256 = \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"\n"
        "paired_device_certificate_serial = \"client-1\"\n"
        "paired_device_not_before_unix = 100\n"
        "paired_device_not_after_unix = 200\n"
        "paired_device_revoked = false\n");
    const auto node = rwn::core::parse_node_runtime_config(node_config);
    RWN_CHECK(node.transport_provider ==
              rwn::core::ProductTransportProvider::msquic);
    RWN_CHECK(node.listen_port == 4433);
    RWN_CHECK(node.maximum_active_sessions == 1);
    RWN_CHECK(node.deployment_broker_uid == 0);
    RWN_CHECK(node.paired_device.id == "windows-client");
    RWN_CHECK(node.pairing_root.is_absolute());
    RWN_CHECK(node.pairing_root.filename() == "pairing");
    RWN_CHECK(node.pairing_state_file == "device.state");
    auto store_only = node_config;
    for (const std::string_view key : {
             "paired_device_id", "paired_device_name",
             "paired_device_certificate_sha256",
             "paired_device_certificate_serial",
             "paired_device_not_before_unix",
             "paired_device_not_after_unix", "paired_device_revoked"}) {
        const auto begin = store_only.find(std::string(key) + " = ");
        RWN_CHECK(begin != std::string::npos);
        const auto end = store_only.find('\n', begin);
        store_only.erase(begin, end - begin + 1);
    }
    const auto unpaired = rwn::core::parse_node_runtime_config(store_only);
    RWN_CHECK(unpaired.paired_device.id.empty());
    RWN_CHECK(!unpaired.pairing_root.empty());

    const auto client = rwn::core::parse_client_runtime_config(
        native_absolute_config(
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
        "requested_capabilities = [\"workspace.sync\", \"build.submit\"]\n"
        "revision = 42\n"
        "lease_minutes = 15\n"));
    RWN_CHECK(client.host == "mac-node.example");
    RWN_CHECK(client.requested_capabilities.size() == 2);
    RWN_CHECK(client.revision == 42);

    const auto worker = rwn::core::parse_build_worker_runtime_config(
        native_absolute_config(
        "workspace_root = \"C:/rwn/mirror\"\n"
        "workspace_config_file = \"C:/rwn/config/remote-workspace.toml\"\n"
        "state_root = \"C:/rwn/state\"\n"
        "workspace_state_file = \"workspace/game.toml\"\n"
        "evidence_root = \"C:/rwn/evidence\"\n"
        "artifact_root = \"C:/rwn/artifacts\"\n"
        "socket_path = \"C:/rwn/run/build-worker.sock\"\n"
        "allowed_node_uid = 502\n"
        "accept_timeout_seconds = 120\n"));
    RWN_CHECK(worker.allowed_node_uid == 502);
    RWN_CHECK(worker.workspace_state_file == "workspace/game.toml");

    const auto broker = rwn::core::parse_broker_runtime_config(
        native_absolute_config(
        "artifact_root = \"C:/rwn/artifacts\"\n"
        "runtime_root = \"C:/rwn/runtime\"\n"
        "active_relative_path = \"bin/application.zip\"\n"
        "socket_path = \"C:/rwn/run/deployment-broker.sock\"\n"
        "allowed_node_uid = 501\n"
        "stop_command = [\"C:/Windows/System32/sc.exe\", \"stop\", \"app\"]\n"
        "start_command = [\"C:/Windows/System32/sc.exe\", \"start\", \"app\"]\n"
        "health_command = [\"C:/Windows/System32/curl.exe\", \"--fail\", \"http://127.0.0.1/health\"]\n"
        "command_timeout_seconds = 30\n"
        "accept_timeout_seconds = 120\n"));
    RWN_CHECK(broker.allowed_node_uid == 501);
    RWN_CHECK(broker.active_relative_path == "bin/application.zip");
}

class ControlTestStream final : public rwn::transport::ReliableStream {
public:
    void write(const std::span<const std::byte> data) override {
        writes.emplace_back(data.begin(), data.end());
    }

    [[nodiscard]] std::vector<std::byte> read() override {
        if (read_index >= reads.size()) {
            throw std::runtime_error("control test stream has no queued read");
        }
        return reads[read_index++];
    }

    std::vector<std::vector<std::byte>> reads;
    std::vector<std::vector<std::byte>> writes;
    std::size_t read_index{};
};

class CollectingAuditSink final : public rwn::core::AuditSink {
public:
    void append_line(const std::string_view line) override {
        lines.emplace_back(line);
    }

    std::vector<std::string> lines;
};

class RecordingBuildWorker final : public rwn::node::BuildWorkerBoundary {
public:
    [[nodiscard]] rwn::core::BuildExecutionResult execute(
        const rwn::core::BuildRequest& request,
        const rwn::core::BuildProfile& profile) override {
        observed_request = request;
        observed_profile = profile.name;
        ++executions;
        return {
            .evidence = {
                .exit_code = 0,
                .stdout_log = "real worker output\n",
                .stderr_log = {},
                .elapsed = std::chrono::milliseconds{27},
                .timed_out = false,
                .cancelled = false,
                .stdout_truncated = false,
                .stderr_truncated = false,
            },
            .artifact_ids = {},
        };
    }

    rwn::core::BuildRequest observed_request;
    std::string observed_profile;
    std::size_t executions{};
};

class RecordingArtifactSource final : public rwn::node::ArtifactSourceBoundary {
public:
    explicit RecordingArtifactSource(std::vector<std::byte> bytes)
        : bytes_(std::move(bytes)) {}

    [[nodiscard]] rwn::protocol::ArtifactManifestReply prepare(
        const rwn::protocol::ArtifactFetchCommand& command) override {
        observed_fetch = command;
        return {
            .accepted = true,
            .artifact_id = command.artifact_id,
            .transfer_id = command.transfer_id,
            .build_id = "build-artifact-42",
            .source_revision = command.revision,
            .name = "product.zip",
            .sha256 = rwn::core::sha256_hex(bytes_),
            .size = bytes_.size(),
            .platform = "macos",
            .architecture = "arm64",
            .chunks = {{
                .index = 0, .offset = 0,
                .size = static_cast<std::uint32_t>(bytes_.size()),
                .sha256 = rwn::core::sha256_hex(bytes_)}},
            .reason_code = "artifact_ready",
        };
    }

    void request_chunks(
        const rwn::protocol::ArtifactResumeCommand& command) override {
        observed_resume = command;
        requested = command.missing_chunks;
    }

    [[nodiscard]] rwn::protocol::ArtifactChunkCommand read_chunk() override {
        if (requested.empty())
            throw std::runtime_error("artifact source has no requested chunk");
        const auto index = requested.front();
        requested.erase(requested.begin());
        return {
            .session_id = observed_fetch.session_id,
            .workspace_id = observed_fetch.workspace_id,
            .revision = observed_fetch.revision,
            .artifact_id = observed_fetch.artifact_id,
            .transfer_id = observed_fetch.transfer_id,
            .index = index,
            .bytes = bytes_,
        };
    }

    rwn::protocol::ArtifactFetchCommand observed_fetch;
    rwn::protocol::ArtifactResumeCommand observed_resume;
    std::vector<std::uint32_t> requested;
private:
    std::vector<std::byte> bytes_;
};

class RecordingDeploymentWorker final
    : public rwn::node::DeploymentWorkerBoundary {
public:
    [[nodiscard]] rwn::protocol::DeployStatusReply execute(
        const rwn::protocol::DeploySubmitCommand& command) override {
        ++executions;
        observed = command;
        rwn::protocol::DeployStatusReply reply{
            .accepted = true, .deployment_id = command.deployment_id,
            .artifact_id = command.artifact_id,
            .artifact_sha256 = std::string(64, 'a'),
            .build_id = "build-deploy", .source_revision = command.revision,
            .status = rwn::protocol::DeploymentWireStatus::active,
            .steps = {{.step = 0, .succeeded = true, .exit_code = 0,
                       .elapsed_ms = 2, .timed_out = false,
                       .cancelled = false, .reason_code = "step_succeeded"}},
            .evidence_sha256 = {}, .reason_code = "deployment_active"};
        reply.evidence_sha256 = rwn::core::sha256_hex(
            rwn::protocol::encode_deploy_evidence_binding(reply));
        return reply;
    }
    rwn::protocol::DeploySubmitCommand observed;
    std::size_t executions{};
};

void deployment_stream_binds_capability_revision_and_evidence() {
    using namespace std::chrono_literals;
    constexpr auto fingerprint =
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const auto now = rwn::core::WallClock::time_point{} + 980h;
    const auto certificate = rwn::core::PeerCertificate{
        .device_id = "windows-client", .fingerprint = fingerprint,
        .serial = "serial-deploy", .not_before = now - 1h,
        .not_after = now + 24h};
    rwn::node::NodeControlService control({
        .principal_id = "windows-client", .workspaces = {"game"},
        .allowed = {rwn::core::Capability::deploy_execute}});
    control.pair_device({
        .id = "windows-client", .display_name = "Windows client",
        .fingerprint = fingerprint, .certificate = certificate,
        .revoked = false});
    RWN_CHECK(control.open_session({
        .device_id = "windows-client", .session_id = "session-deploy",
        .workspace_id = "game",
        .requested_capabilities = {"deploy.execute"}, .lease_minutes = 15},
        {.tls_1_3_negotiated = true, .client_certificate_present = true,
         .certificate_chain_valid = true, .revocation_checked = true,
         .certificate = certificate}, now).accepted);
    const rwn::protocol::DeploySubmitCommand command{
        .session_id = "session-deploy", .workspace_id = "game",
        .revision = 42, .artifact_id = "artifact-deploy",
        .deployment_id = "deployment-42"};
    ControlTestStream node_stream;
    node_stream.reads = {rwn::protocol::encode({
        .version = 1, .type = rwn::protocol::MessageType::deploy_submit,
        .correlation_id = "deploy-deployment-42",
        .payload = rwn::protocol::encode_deploy_submit_command(command),
        .unknown_fields = {}})};
    RecordingDeploymentWorker worker;
    const auto served = rwn::node::serve_deployment(
        node_stream, control, 42, worker, now);
    RWN_CHECK(served.status == rwn::protocol::DeploymentWireStatus::active);
    RWN_CHECK(worker.executions == 1);
    RWN_CHECK(control.audit().events().back().action ==
              rwn::core::AuditAction::deployment_active);
    RWN_CHECK(control.audit().events().back().evidence_id ==
              served.evidence_sha256);
    ControlTestStream client_stream;
    client_stream.reads = node_stream.writes;
    const auto received = rwn::client::submit_deployment(client_stream, command);
    RWN_CHECK(received == served);
    RWN_CHECK(client_stream.writes.size() == 1);
}

void artifact_stream_resumes_and_verifies_immutable_download() {
    using namespace std::chrono_literals;
    using enum rwn::core::Capability;
    constexpr auto fingerprint =
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const auto now = rwn::core::WallClock::time_point{} + 900h;
    const auto certificate = rwn::core::PeerCertificate{
        .device_id = "windows-client", .fingerprint = fingerprint,
        .serial = "serial-artifact", .not_before = now - 1h,
        .not_after = now + 24h};
    rwn::node::NodeControlService control({
        .principal_id = "windows-client", .workspaces = {"game"},
        .allowed = {artifact_download}});
    control.pair_device({
        .id = "windows-client", .display_name = "Windows client",
        .fingerprint = fingerprint, .certificate = certificate,
        .revoked = false});
    RWN_CHECK(control.open_session({
        .device_id = "windows-client", .session_id = "session-artifact",
        .workspace_id = "game",
        .requested_capabilities = {"artifact.download"},
        .lease_minutes = 15},
        {.tls_1_3_negotiated = true, .client_certificate_present = true,
         .certificate_chain_valid = true, .revocation_checked = true,
         .certificate = certificate}, now).accepted);

    const std::vector<std::byte> bytes{
        std::byte{'R'}, std::byte{'W'}, std::byte{'N'}, std::byte{'!'}};
    const rwn::protocol::ArtifactFetchCommand fetch{
        .session_id = "session-artifact", .workspace_id = "game",
        .revision = 42, .artifact_id = "artifact-42",
        .transfer_id = "transfer-42"};
    const rwn::protocol::ArtifactResumeCommand resume{
        .session_id = fetch.session_id, .workspace_id = fetch.workspace_id,
        .revision = fetch.revision, .artifact_id = fetch.artifact_id,
        .transfer_id = fetch.transfer_id, .missing_chunks = {0}};
    ControlTestStream node_stream;
    node_stream.reads = {
        rwn::protocol::encode({
            .version = 1, .type = rwn::protocol::MessageType::artifact_manifest,
            .correlation_id = "artifact-transfer-42",
            .payload = rwn::protocol::encode_artifact_fetch_command(fetch),
            .unknown_fields = {}}),
        rwn::protocol::encode({
            .version = 1, .type = rwn::protocol::MessageType::artifact_resume,
            .correlation_id = "resume-transfer-42",
            .payload = rwn::protocol::encode_artifact_resume_command(resume),
            .unknown_fields = {}}),
    };
    RecordingArtifactSource source(bytes);
    const auto served = rwn::node::serve_artifact_download(
        node_stream, control, 42, source, now);
    RWN_CHECK(served.accepted);
    RWN_CHECK(node_stream.writes.size() == 2);
    RWN_CHECK(source.observed_resume.missing_chunks ==
              std::vector<std::uint32_t>{0});

    const auto root = std::filesystem::temp_directory_path() /
        ("rwn-artifact-product-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(root);
    try {
        ControlTestStream client_stream;
        client_stream.reads = node_stream.writes;
        rwn::test::TestDurableFileSystem filesystem;
        const auto downloaded = rwn::client::download_artifact(
            client_stream, fetch, root, "downloads/product.zip", filesystem);
        RWN_CHECK(downloaded.manifest.sha256 == rwn::core::sha256_hex(bytes));
        RWN_CHECK(rwn::core::sha256_file(downloaded.destination) ==
                  downloaded.manifest.sha256);
        RWN_CHECK(client_stream.writes.size() == 2);
    } catch (...) {
        std::filesystem::remove_all(root);
        throw;
    }
    std::filesystem::remove_all(root);
}

void build_stream_binds_session_revision_and_runtime_evidence() {
    using namespace std::chrono_literals;
    using enum rwn::core::Capability;
    constexpr auto fingerprint =
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const auto now = rwn::core::WallClock::time_point{} + 800h;
    const auto certificate = rwn::core::PeerCertificate{
        .device_id = "windows-client", .fingerprint = fingerprint,
        .serial = "serial-build", .not_before = now - 1h,
        .not_after = now + 24h};
    rwn::node::NodeControlService control({
        .principal_id = "windows-client",
        .workspaces = {"game"},
        .allowed = {build_submit},
    });
    control.pair_device({
        .id = "windows-client", .display_name = "Windows client",
        .fingerprint = fingerprint, .certificate = certificate,
        .revoked = false});
    const auto opened = control.open_session({
        .device_id = "windows-client", .session_id = "session-build",
        .workspace_id = "game", .requested_capabilities = {"build.submit"},
        .lease_minutes = 15},
        {.tls_1_3_negotiated = true, .client_certificate_present = true,
         .certificate_chain_valid = true, .revocation_checked = true,
         .certificate = certificate}, now);
    RWN_CHECK(opened.accepted);

    const auto config = rwn::core::parse_remote_workspace_config(
        "[workspace]\n"
        "id = \"game\"\nname = \"Game\"\nsource = \"windows\"\nmirror = \"macos\"\n"
        "[sync]\ndirection = \"one-way\"\nexclude = [\"build\"]\n"
        "[target.debug]\nnode = \"mac-mini\"\nworking_dir = \".\"\n"
        "command = [\"/usr/bin/cmake\", \"--build\", \"build\"]\n"
        "timeout_seconds = 60\nenvironment_allowlist = [\"SDKROOT\"]\n"
        "[target.debug.artifacts]\npaths = [\"dist/product.zip\"]\n"
        "platform = \"macos\"\narchitecture = \"arm64\"\n"
        "archive_app_bundles = true\n");
    RecordingBuildWorker worker;
    rwn::node::NodeBuildService service(config, 42, worker);
    const rwn::protocol::BuildSubmitCommand command{
        .session_id = "session-build", .workspace_id = "game",
        .revision = 42, .build_id = "build-42", .profile = "debug"};
    ControlTestStream node_stream;
    node_stream.reads.push_back(rwn::protocol::encode({
        .version = 1, .type = rwn::protocol::MessageType::build_submit,
        .correlation_id = "build-build-42",
        .payload = rwn::protocol::encode_build_submit_command(command),
        .unknown_fields = {}}));
    const auto served = service.serve(node_stream, control, now);
    RWN_CHECK(served.reply.accepted);
    RWN_CHECK(served.reply.state == rwn::protocol::BuildWireState::succeeded);
    RWN_CHECK(worker.executions == 1);
    RWN_CHECK(worker.observed_request.pinned_revision == 42);
    RWN_CHECK(served.reply.evidence_sha256 == rwn::core::build_evidence_sha256(
        worker.observed_request,
        {.exit_code = 0, .stdout_log = "real worker output\n",
         .stderr_log = {}, .elapsed = std::chrono::milliseconds{27},
         .timed_out = false, .cancelled = false,
         .stdout_truncated = false, .stderr_truncated = false}));
    RWN_CHECK(control.audit().events().size() == 4);
    RWN_CHECK(control.audit().events()[2].action ==
              rwn::core::AuditAction::build_submitted);
    RWN_CHECK(control.audit().events()[3].evidence_id ==
              served.reply.evidence_sha256);

    ControlTestStream client_stream;
    client_stream.reads = node_stream.writes;
    const auto client_reply = rwn::client::submit_build(client_stream, command);
    RWN_CHECK(client_reply == served.reply);
    RWN_CHECK(rwn::client::verify_build_evidence(
        worker.observed_request, client_reply).exit_code == 0);
    RWN_CHECK(rwn::protocol::decode(client_stream.writes.front()).type ==
              rwn::protocol::MessageType::build_submit);
}

void workspace_stream_services_bind_session_and_commit() {
    const auto root = std::filesystem::temp_directory_path() /
        ("rwn-workspace-stream-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(root);
    const rwn::core::WorkspaceManifest manifest{
        .workspace_id = "game",
        .revision = 1,
        .entries = {},
    };
    const auto manifest_hash = rwn::core::manifest_content_hash(manifest);

    ControlTestStream client_stream;
    client_stream.reads.push_back(rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::workspace_diff,
        .correlation_id = "manifest-session-1",
        .payload = rwn::protocol::encode_workspace_diff_reply({
            .accepted = true,
            .current_revision = 0,
            .requested_file_paths = {},
            .reason_code = "workspace_diff_ready",
        }),
        .unknown_fields = {},
    }));
    client_stream.reads.push_back(rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::workspace_commit,
        .correlation_id = "commit-session-1",
        .payload = rwn::protocol::encode_workspace_commit_reply({
            .accepted = true,
            .revision = 1,
            .manifest_sha256 = manifest_hash,
            .reason_code = "workspace_committed",
        }),
        .unknown_fields = {},
    }));
    const auto client_result = rwn::client::sync_workspace(
        client_stream, root, manifest, "session-1");
    RWN_CHECK(client_result.diff.accepted);
    RWN_CHECK(client_result.commit.has_value());
    RWN_CHECK(client_result.commit->accepted);
    RWN_CHECK(client_stream.writes.size() == 2);
    RWN_CHECK(rwn::protocol::decode(client_stream.writes[0]).type ==
              rwn::protocol::MessageType::workspace_manifest);
    RWN_CHECK(rwn::protocol::decode(client_stream.writes[1]).type ==
              rwn::protocol::MessageType::workspace_commit);

    ControlTestStream node_stream;
    node_stream.reads.push_back(client_stream.writes[0]);
    node_stream.reads.push_back(client_stream.writes[1]);
    rwn::test::TestDurableFileSystem filesystem;
    rwn::node::WorkspaceMirrorService service(root, "game", 0, filesystem);
    rwn::node::serve_workspace_sync(service, node_stream);
    RWN_CHECK(node_stream.writes.size() == 2);
    RWN_CHECK(rwn::protocol::decode(node_stream.writes[0]).type ==
              rwn::protocol::MessageType::workspace_diff);
    const auto committed = rwn::protocol::decode_workspace_commit_reply(
        rwn::protocol::decode(node_stream.writes[1]).payload);
    RWN_CHECK(committed.accepted);
    RWN_CHECK(service.current_revision() == 1);
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
}

void node_control_stream_opens_policy_scoped_session() {
    using namespace std::chrono_literals;
    using enum rwn::core::Capability;
    constexpr auto fingerprint =
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const auto now = rwn::core::WallClock::time_point{} + 600h;
    const auto certificate = rwn::core::PeerCertificate{
        .device_id = "windows-client",
        .fingerprint = fingerprint,
        .serial = "serial-1",
        .not_before = now - 1h,
        .not_after = now + 24h,
    };
    CollectingAuditSink audit_sink;
    rwn::node::NodeControlService service(
        {
            .principal_id = "windows-client",
            .workspaces = {"game"},
            .allowed = {workspace_read, workspace_sync},
        },
        64, &audit_sink);
    service.pair_device({
        .id = "windows-client",
        .display_name = "Windows client",
        .fingerprint = fingerprint,
        .certificate = certificate,
        .revoked = false,
    });
    const auto command = rwn::protocol::SessionOpenCommand{
        .device_id = "windows-client",
        .session_id = "session-600",
        .workspace_id = "game",
        .requested_capabilities = {
            "workspace.read", "workspace.sync", "command.exec"},
        .lease_minutes = 15,
    };
    RWN_CHECK(rwn::protocol::decode_session_open_command(
        rwn::protocol::encode_session_open_command(command)) == command);

    ControlTestStream server_stream;
    server_stream.reads.push_back(rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::authenticate,
        .correlation_id = "open-600",
        .payload = rwn::protocol::encode_session_open_command(command),
        .unknown_fields = {},
    }));
    const auto opened = service.serve_session_open(
        server_stream,
        {.certificate_sha256 =
             rwn::transport::parse_apple_network_sha256_fingerprint(
                 fingerprint),
         .tls_1_3_negotiated = true,
         .certificate_chain_valid = true,
         .revocation_checked = true},
        now);
    RWN_CHECK(opened.command == command);
    RWN_CHECK(opened.reply.accepted);
    RWN_CHECK(server_stream.writes.size() == 1);
    const auto response = rwn::protocol::decode(server_stream.writes.front());
    RWN_CHECK(response.type == rwn::protocol::MessageType::session_open);
    RWN_CHECK(response.correlation_id == "open-600");
    const auto reply =
        rwn::protocol::decode_session_open_reply(response.payload);
    RWN_CHECK(reply.accepted);
    RWN_CHECK(reply.granted_capabilities ==
              std::vector<std::string>({"workspace.read", "workspace.sync"}));
    RWN_CHECK(reply.denied_capabilities ==
              std::vector<std::string>({"command.exec"}));
    const auto health = service.health("session-600", now + 1min);
    RWN_CHECK(health.ready);
    RWN_CHECK(health.active_sessions == 1);
    RWN_CHECK(health.audit_events == 2);
    RWN_CHECK(service.permits_session(
        "session-600", rwn::core::Capability::workspace_sync,
        "game", now + 1min));
    service.record_workspace_sync(
        "session-600", "game", 1,
        rwn::core::AuditAction::workspace_sync_started,
        rwn::core::AuditResult::allowed,
        "workspace_sync_started", now + 1min);
    service.record_workspace_sync(
        "session-600", "game", 1,
        rwn::core::AuditAction::workspace_sync_committed,
        rwn::core::AuditResult::allowed,
        "workspace_committed", now + 1min);
    service.close_session("session-600", now + 2min);
    RWN_CHECK(service.audit().events().size() == 5);
    RWN_CHECK(audit_sink.lines.size() == 5);

    ControlTestStream client_stream;
    client_stream.reads.push_back(response.payload.empty()
        ? std::vector<std::byte>{}
        : rwn::protocol::encode({
            .version = 1,
            .type = rwn::protocol::MessageType::session_open,
            .correlation_id = "session-" + command.session_id,
            .payload = rwn::protocol::encode_session_open_reply(reply),
            .unknown_fields = {},
        }));
    RWN_CHECK(rwn::client::open_remote_session(client_stream, command) == reply);
    RWN_CHECK(client_stream.writes.size() == 1);
    RWN_CHECK(rwn::protocol::decode(client_stream.writes.front()).type ==
              rwn::protocol::MessageType::authenticate);
}

void apple_network_contract_accepts_explicit_paired_identities() {
    const auto peer =
        rwn::transport::parse_apple_network_sha256_fingerprint(
            "00112233445566778899aabbccddeeff"
            "102030405060708090a0b0c0d0e0f001");
    const std::vector persistent_reference{
        std::byte{0x01}, std::byte{0x23}, std::byte{0x45}};
    const auto client = rwn::transport::AppleNetworkClientOptions{
        .identity = {
            .keychain_persistent_reference = persistent_reference,
            .allowed_peer_certificate_sha256 = {peer},
        },
    };
    rwn::transport::validate_apple_network_client_options(client);
    RWN_CHECK(rwn::transport::apple_network_peer_allowed(
        client.identity.allowed_peer_certificate_sha256, peer));

    const auto server = rwn::transport::AppleNetworkServerOptions{
        .identity = client.identity,
        .listen_port = 4433,
    };
    rwn::transport::validate_apple_network_server_options(server);
    const auto evidence = rwn::transport::single_allowed_peer_evidence(
        server.identity.allowed_peer_certificate_sha256);
    rwn::transport::validate_authenticated_peer_evidence(evidence);
    RWN_CHECK(rwn::transport::certificate_sha256_hex(peer) ==
              "00112233445566778899aabbccddeeff"
              "102030405060708090a0b0c0d0e0f001");
}

[[nodiscard]] std::vector<std::byte> bytes_from_hex(
    const std::string_view value) {
    RWN_CHECK(value.size() % 2U == 0U);
    const auto nibble = [](const char character) -> std::uint8_t {
        if (character >= '0' && character <= '9') {
            return static_cast<std::uint8_t>(character - '0');
        }
        if (character >= 'a' && character <= 'f') {
            return static_cast<std::uint8_t>(character - 'a' + 10);
        }
        if (character >= 'A' && character <= 'F') {
            return static_cast<std::uint8_t>(character - 'A' + 10);
        }
        throw std::invalid_argument("test hex character is invalid");
    };
    std::vector<std::byte> result(value.size() / 2U);
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = static_cast<std::byte>(
            (nibble(value[index * 2U]) << 4U) |
            nibble(value[index * 2U + 1U]));
    }
    return result;
}

class DeterministicOpusCodec final : public rwn::audio::OpusCodec {
public:
    std::vector<std::byte> encode(const rwn::audio::PcmFrame& frame) override {
        rwn::audio::validate_pcm_frame(frame);
        return {std::byte{0x4f}, std::byte{0x50}, std::byte{0x55}, std::byte{0x53}};
    }
    rwn::audio::PcmFrame decode(const rwn::audio::AudioPacket& packet) override {
        ++decoded;
        return frame(packet.samples_per_channel, 1);
    }
    rwn::audio::PcmFrame conceal_loss(
        const std::uint16_t samples_per_channel) override {
        ++concealed;
        return frame(samples_per_channel, 0);
    }
    static rwn::audio::PcmFrame frame(
        const std::uint16_t samples, const std::int16_t value) {
        return {
            .sample_rate = rwn::audio::opus_sample_rate,
            .channels = rwn::audio::opus_channels,
            .samples_per_channel = samples,
            .interleaved_samples = std::vector<std::int16_t>(
                static_cast<std::size_t>(rwn::audio::opus_channels) * samples,
                value),
        };
    }
    int decoded{};
    int concealed{};
};

class SingleFrameAudioCapture final : public rwn::audio::AudioCaptureBackend {
public:
    std::optional<rwn::audio::CapturedPcmFrame> next;
    std::optional<rwn::audio::CapturedPcmFrame> capture(
        const std::chrono::milliseconds timeout) override {
        last_timeout = timeout;
        auto result = std::move(next);
        next.reset();
        return result;
    }
    std::chrono::milliseconds last_timeout{};
};

class RecordingAudioPlayback final : public rwn::audio::AudioPlaybackBackend {
public:
    void play(
        const rwn::audio::PcmFrame& frame,
        const std::chrono::milliseconds timeout) override {
        frames.push_back(frame);
        last_timeout = timeout;
    }
    std::vector<rwn::audio::PcmFrame> frames;
    std::chrono::milliseconds last_timeout{};
};

class BoundUpdateSignatureVerifier final
    : public rwn::core::UpdateSignatureVerifier {
public:
    bool verify(
        const std::span<const std::byte> payload,
        const std::span<const std::byte> signature) const override {
        called = true;
        const std::string text(
            reinterpret_cast<const char*>(payload.data()), payload.size());
        return text.find("version=0.1.0\n") != std::string::npos &&
               signature.size() == 64 &&
               std::ranges::all_of(signature, [](const std::byte value) {
                   return value == std::byte{0x11};
               });
    }
    mutable bool called{};
};

class RecordingInputBackend final : public rwn::desktop::InputBackend {
public:
    void raw_key(const std::uint32_t hid_usage, const bool pressed) override {
        keys.emplace_back(hid_usage, pressed);
    }
    void text_commit(const std::string_view utf8) override {
        texts.emplace_back(utf8);
    }
    void pointer_move(
        const std::uint16_t normalized_x,
        const std::uint16_t normalized_y) override {
        moves.emplace_back(normalized_x, normalized_y);
    }
    void pointer_button(const std::uint8_t button, const bool pressed) override {
        buttons.emplace_back(button, pressed);
    }
    void pointer_wheel(const std::int32_t delta, const bool horizontal) override {
        wheels.emplace_back(delta, horizontal);
    }

    std::vector<std::pair<std::uint32_t, bool>> keys;
    std::vector<std::string> texts;
    std::vector<std::pair<std::uint16_t, std::uint16_t>> moves;
    std::vector<std::pair<std::uint8_t, bool>> buttons;
    std::vector<std::pair<std::int32_t, bool>> wheels;
};

struct RecordedStream {
    rwn::transport::StreamPurpose purpose{};
    std::vector<std::vector<std::byte>> writes;
};

class RecordingStream final : public rwn::transport::ReliableStream {
public:
    explicit RecordingStream(std::shared_ptr<RecordedStream> state)
        : state_(std::move(state)) {}
    void write(const std::span<const std::byte> data) override {
        state_->writes.emplace_back(data.begin(), data.end());
    }
    std::vector<std::byte> read() override { return {}; }

private:
    std::shared_ptr<RecordedStream> state_;
};

class RecordingTransport final : public rwn::transport::DuplexTransport {
public:
    std::unique_ptr<rwn::transport::ReliableStream> open_stream(
        const rwn::transport::StreamPurpose purpose) override {
        auto state = std::make_shared<RecordedStream>();
        state->purpose = purpose;
        streams.push_back(state);
        return std::make_unique<RecordingStream>(std::move(state));
    }
    void send_datagram(
        const rwn::transport::DatagramChannel channel,
        const std::span<const std::byte> data) override {
        datagrams.emplace_back(channel, std::vector<std::byte>(data.begin(), data.end()));
    }
    rwn::transport::AcceptedStream accept_stream(
        std::chrono::milliseconds) override {
        auto state = std::make_shared<RecordedStream>();
        state->purpose = rwn::transport::StreamPurpose::command;
        accepted_streams.push_back(state);
        return {
            .purpose = state->purpose,
            .stream = std::make_unique<RecordingStream>(std::move(state)),
        };
    }
    rwn::transport::ReceivedDatagram receive_datagram(
        std::chrono::milliseconds) override {
        return {
            .channel = rwn::transport::DatagramChannel::video,
            .payload = {std::byte{5}, std::byte{6}},
        };
    }

    std::vector<std::shared_ptr<RecordedStream>> streams;
    std::vector<std::shared_ptr<RecordedStream>> accepted_streams;
    std::vector<std::pair<rwn::transport::DatagramChannel,
                          std::vector<std::byte>>> datagrams;
};

class ScriptedTransportConnector final
    : public rwn::transport::TransportConnector {
public:
    std::unique_ptr<rwn::transport::Transport> connect(
        const rwn::transport::TransportMode mode,
        const rwn::transport::TransportEndpoint& endpoint,
        const rwn::transport::QuicTransportSettings&) override {
        attempts.push_back(mode);
        endpoints.push_back(endpoint);
        if (mode == rwn::transport::TransportMode::quic &&
            primary_failures_remaining != 0) {
            --primary_failures_remaining;
            throw std::runtime_error("scripted primary failure");
        }
        auto result = std::make_unique<RecordingTransport>();
        last_connection = result.get();
        return result;
    }
    bool migrate(
        rwn::transport::Transport&,
        const rwn::transport::TransportEndpoint& endpoint) override {
        migrations.push_back(endpoint);
        return migration_succeeds;
    }

    std::size_t primary_failures_remaining{};
    bool migration_succeeds{true};
    RecordingTransport* last_connection{};
    std::vector<rwn::transport::TransportMode> attempts;
    std::vector<rwn::transport::TransportEndpoint> endpoints;
    std::vector<rwn::transport::TransportEndpoint> migrations;
};

[[nodiscard]] rwn::transport::EncryptedPlaneEvidence fallback_evidence(
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

class RecordingFallbackReliablePlane final
    : public rwn::transport::FallbackReliablePlane {
public:
    RecordingFallbackReliablePlane()
        : evidence_(fallback_evidence(
              rwn::transport::EncryptedPlaneProtocol::tls13)) {}

    const rwn::transport::EncryptedPlaneEvidence& evidence() const override {
        return evidence_;
    }
    std::unique_ptr<rwn::transport::ReliableStream> open_stream(
        const rwn::transport::StreamPurpose purpose) override {
        auto state = std::make_shared<RecordedStream>();
        state->purpose = purpose;
        opened.push_back(state);
        return std::make_unique<RecordingStream>(std::move(state));
    }
    rwn::transport::AcceptedStream accept_stream(
        const std::chrono::milliseconds timeout) override {
        last_accept_timeout = timeout;
        auto state = std::make_shared<RecordedStream>();
        state->purpose = rwn::transport::StreamPurpose::command;
        accepted.push_back(state);
        return {
            .purpose = state->purpose,
            .stream = std::make_unique<RecordingStream>(std::move(state)),
        };
    }

    rwn::transport::EncryptedPlaneEvidence evidence_;
    std::vector<std::shared_ptr<RecordedStream>> opened;
    std::vector<std::shared_ptr<RecordedStream>> accepted;
    std::chrono::milliseconds last_accept_timeout{};
};

class RecordingFallbackDatagramPlane final
    : public rwn::transport::FallbackDatagramPlane {
public:
    RecordingFallbackDatagramPlane()
        : evidence_(fallback_evidence(
              rwn::transport::EncryptedPlaneProtocol::dtls12)) {}

    const rwn::transport::EncryptedPlaneEvidence& evidence() const override {
        return evidence_;
    }
    void send_datagram(
        const rwn::transport::DatagramChannel channel,
        const std::span<const std::byte> data) override {
        sent.emplace_back(
            channel, std::vector<std::byte>(data.begin(), data.end()));
    }
    rwn::transport::ReceivedDatagram receive_datagram(
        const std::chrono::milliseconds timeout) override {
        last_receive_timeout = timeout;
        return {
            .channel = rwn::transport::DatagramChannel::video,
            .payload = {std::byte{0x51}, std::byte{0x52}},
        };
    }

    rwn::transport::EncryptedPlaneEvidence evidence_;
    std::vector<std::pair<rwn::transport::DatagramChannel,
                          std::vector<std::byte>>> sent;
    std::chrono::milliseconds last_receive_timeout{};
};

class RecordingFallbackProvider final
    : public rwn::transport::EncryptedFallbackProvider {
public:
    std::unique_ptr<rwn::transport::FallbackReliablePlane> connect_tls13(
        const rwn::transport::TransportEndpoint& endpoint,
        const rwn::transport::QuicTransportSettings&) override {
        ++tls_connections;
        last_tls_endpoint = endpoint;
        auto result = std::make_unique<RecordingFallbackReliablePlane>();
        reliable = result.get();
        return result;
    }
    std::unique_ptr<rwn::transport::FallbackDatagramPlane> connect_dtls12(
        const rwn::transport::TransportEndpoint& endpoint,
        const rwn::transport::QuicTransportSettings&) override {
        ++dtls_connections;
        last_dtls_endpoint = endpoint;
        auto result = std::make_unique<RecordingFallbackDatagramPlane>();
        datagrams = result.get();
        return result;
    }

    std::size_t tls_connections{};
    std::size_t dtls_connections{};
    rwn::transport::TransportEndpoint last_tls_endpoint;
    rwn::transport::TransportEndpoint last_dtls_endpoint;
    RecordingFallbackReliablePlane* reliable{};
    RecordingFallbackDatagramPlane* datagrams{};
};

[[nodiscard]] rwn::core::AuthorizationResult desktop_authorization() {
    return {
        .principal_matched = true,
        .workspace_allowed = true,
        .granted = {
            rwn::core::Capability::desktop_view,
            rwn::core::Capability::desktop_control,
            rwn::core::Capability::clipboard_read,
            rwn::core::Capability::clipboard_write},
        .denied = {},
    };
}

class RecordingTerminalBackend final : public rwn::core::TerminalBackend {
public:
    void open(
        const rwn::core::CommandSpec& command,
        const std::filesystem::path& resolved_working_directory,
        const rwn::core::TerminalSize size) override {
        opened = true;
        argv = command.argv;
        working_directory = resolved_working_directory;
        current_size = size;
    }
    void resize(const rwn::core::TerminalSize size) override {
        current_size = size;
    }
    std::size_t write(const std::span<const std::byte> bytes) override {
        input.insert(input.end(), bytes.begin(), bytes.end());
        return bytes.size();
    }
    std::vector<std::byte> read(const std::size_t maximum) override {
        const auto count = std::min(maximum, output.size());
        std::vector<std::byte> result(output.begin(), output.begin() +
            static_cast<std::ptrdiff_t>(count));
        output.erase(output.begin(), output.begin() +
            static_cast<std::ptrdiff_t>(count));
        return result;
    }
    void close() noexcept override { closed = true; }

    bool opened{};
    bool closed{};
    std::vector<std::string> argv;
    std::filesystem::path working_directory;
    rwn::core::TerminalSize current_size{};
    std::vector<std::byte> input;
    std::vector<std::byte> output;
};

std::span<const std::byte> bytes_of(const std::string_view value) {
    return std::as_bytes(std::span{value.data(), value.size()});
}

void envelope_round_trip_preserves_unknown_fields() {
    const rwn::protocol::Envelope original{
        .version = 1,
        .type = rwn::protocol::MessageType::capability_request,
        .correlation_id = "flow-001",
        .payload = {std::byte{0x10}, std::byte{0x20}},
        .unknown_fields = {{.tag = 900, .value = {std::byte{0xab}, std::byte{0xcd}}}},
    };
    RWN_CHECK(rwn::protocol::decode(rwn::protocol::encode(original)) == original);
}

void capability_request_is_policy_intersection() {
    using enum rwn::core::Capability;
    rwn::core::CapabilityRequest request;
    request.principal.id = "agent-a";
    request.principal.kind = rwn::core::PrincipalKind::agent;
    request.workspace = "game";
    request.requested = {workspace_read, build_submit, command_exec};
    const auto result = rwn::core::authorize(
        request, rwn::core::default_agent_policy("agent-a", "game"));
    RWN_CHECK(result.permits(workspace_read));
    RWN_CHECK(result.permits(build_submit));
    RWN_CHECK(!result.permits(command_exec));
    RWN_CHECK(result.denied.contains(command_exec));
}

void authenticated_authorized_session_opens_and_closes() {
    using enum rwn::core::Capability;
    rwn::core::CapabilityRequest request;
    request.principal.id = "device-a";
    request.principal.kind = rwn::core::PrincipalKind::device;
    request.workspace = "game";
    request.requested = {workspace_sync};
    const rwn::core::Policy policy{
        .principal_id = "device-a", .workspaces = {"game"}, .allowed = {workspace_sync}};

    rwn::core::Session session("session-1");
    RWN_CHECK(session.state() == rwn::core::SessionState::created);
    session.authenticate(true);
    RWN_CHECK(session.state() == rwn::core::SessionState::authenticated);
    session.open(rwn::core::authorize(request, policy));
    RWN_CHECK(session.state() == rwn::core::SessionState::open);
    session.close();
    RWN_CHECK(session.state() == rwn::core::SessionState::closed);
}

void unauthenticated_session_cannot_open() {
    rwn::core::Session session("session-2");
    const rwn::core::AuthorizationResult authorization{
        .principal_matched = true,
        .workspace_allowed = true,
        .granted = {rwn::core::Capability::workspace_read},
        .denied = {},
    };
    rwn::test::require_throws<std::logic_error>(
        [&] { session.open(authorization); }, "unauthenticated session open");
}

void paired_certificate_opens_and_renews_a_session() {
    using namespace std::chrono_literals;
    constexpr auto fingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const auto now = rwn::core::WallClock::time_point{} + 100h;
    rwn::core::DeviceRegistry registry;
    rwn::core::PairingService pairing(registry);
    const auto challenge = pairing.begin(
        {.node_id = "mac-node", .node_name = "Mac node", .lan_endpoint = "192.168.1.8:4433", .fingerprint = fingerprint},
        "123456", now, 5min);
    const auto certificate = pairing.confirm(
        challenge, "123456", "windows-client", "Windows client", fingerprint, now, 24h);

    using enum rwn::core::Capability;
    rwn::core::CapabilityRequest request;
    request.principal.id = "windows-client";
    request.principal.kind = rwn::core::PrincipalKind::device;
    request.workspace = "game";
    request.requested = {workspace_sync};
    const rwn::core::Policy policy{.principal_id = "windows-client", .workspaces = {"game"}, .allowed = {workspace_sync}};
    rwn::core::Session session("paired-session");
    session.authenticate(certificate, registry, now);
    session.open(rwn::core::authorize(request, policy));
    session.renew(now + 1min, 15min);
    RWN_CHECK(session.active_at(now + 10min));

    rwn::core::AuditLog audit;
    audit.append({.occurred_at = now, .principal_id = "windows-client", .device_id = "windows-client",
                  .session_id = session.id(), .workspace_id = "game", .action = rwn::core::AuditAction::session_opened});
    RWN_CHECK(audit.for_session(session.id()).size() == 1);
}

void pairing_state_persists_and_revokes_atomically() {
    using namespace std::chrono_literals;
    const auto root = std::filesystem::temp_directory_path() /
        "rwn-flow-pairing-store";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root);
    rwn::test::TestDurableFileSystem filesystem;
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
    RWN_CHECK(!store.exists());
    store.create(device);
    RWN_CHECK(store.exists());
    RWN_CHECK(store.load().id == device.id);
    RWN_CHECK(store.load().display_name == device.display_name);
    RWN_CHECK(!store.load().revoked);
    const auto revoked = store.revoke(device.id);
    RWN_CHECK(revoked.revoked);
    RWN_CHECK(store.load().revoked);
    RWN_CHECK(store.revoke(device.id).revoked);
    auto rotated = device;
    rotated.fingerprint =
        "abcdef0123456789abcdef0123456789"
        "abcdef0123456789abcdef0123456789";
    rotated.certificate.fingerprint = rotated.fingerprint;
    rotated.certificate.serial = "client-serial-2";
    store.replace_revoked(rotated);
    RWN_CHECK(!store.load().revoked);
    RWN_CHECK(store.load().fingerprint == rotated.fingerprint);
    std::filesystem::remove_all(root, ignored);
}

void pairing_control_binds_transport_identity_and_persists_device() {
    using namespace std::chrono_literals;
    constexpr auto client_fingerprint =
        "1234567890abcdef1234567890abcdef"
        "1234567890abcdef1234567890abcdef";
    constexpr auto node_fingerprint =
        "abcdef1234567890abcdef1234567890"
        "abcdef1234567890abcdef1234567890";
    const auto now = rwn::core::TimePoint{800h};
    const auto root = std::filesystem::temp_directory_path() /
        "rwn-flow-pairing-control";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root);
    rwn::test::TestDurableFileSystem filesystem;
    rwn::core::PairingStore store(root, "device.state", filesystem);
    const auto command = rwn::protocol::PairingConfirmCommand{
        .six_digit_code = "123456",
        .device_id = "windows-client",
        .display_name = "Windows Client",
        .certificate_sha256 = client_fingerprint,
    };
    RWN_CHECK(rwn::protocol::decode_pairing_confirm_command(
        rwn::protocol::encode_pairing_confirm_command(command)) == command);
    ControlTestStream server_stream;
    server_stream.reads.push_back(rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::pairing_confirm,
        .correlation_id = "pairing-windows-client",
        .payload = rwn::protocol::encode_pairing_confirm_command(command),
        .unknown_fields = {},
    }));
    rwn::node::NodePairingService service({
        .id = "challenge-1",
        .node = {
            .node_id = "mac-node",
            .node_name = "Mac Node",
            .lan_endpoint = "mac-node.local:4433",
            .fingerprint = node_fingerprint,
        },
        .six_digit_code = "123456",
        .expires_at = now + 5min,
    }, "windows-client", store, 24h);
    const auto served = service.serve_confirmation(
        server_stream,
        {.certificate_sha256 =
             rwn::transport::parse_apple_network_sha256_fingerprint(
                 client_fingerprint),
         .tls_1_3_negotiated = true,
         .certificate_chain_valid = true,
         .revocation_checked = true},
        now);
    RWN_CHECK(served.command == command);
    RWN_CHECK(served.reply.accepted);
    RWN_CHECK(store.load().fingerprint == client_fingerprint);
    ControlTestStream client_stream;
    client_stream.reads = server_stream.writes;
    RWN_CHECK(rwn::client::confirm_remote_pairing(client_stream, command) ==
              served.reply);
    RWN_CHECK(rwn::protocol::decode(client_stream.writes.front()).type ==
              rwn::protocol::MessageType::pairing_confirm);
    ControlTestStream replay;
    replay.reads = client_stream.writes;
    rwn::test::require_throws<std::invalid_argument>([&] {
        static_cast<void>(service.serve_confirmation(replay,
            {.certificate_sha256 = rwn::transport::parse_apple_network_sha256_fingerprint(client_fingerprint),
             .tls_1_3_negotiated = true, .certificate_chain_valid = true,
             .revocation_checked = true}, now));
    }, "successful pairing window must not be reusable");
    std::filesystem::remove_all(root, ignored);
}

void protocol_mutation_and_release_security_gates_pass_valid_corpora() {
    const auto first = rwn::protocol::run_envelope_mutation_gate(
        0x52574e2d763031ULL, 4096);
    const auto second = rwn::protocol::run_envelope_mutation_gate(
        0x52574e2d763031ULL, 4096);
    RWN_CHECK(first.passed);
    RWN_CHECK(first.accepted != 0);
    RWN_CHECK(first.rejected != 0);
    RWN_CHECK(first.corpus_fingerprint == second.corpus_fingerprint);
    RWN_CHECK(rwn::protocol::render_protocol_mutation_json(first).find(
                  "\"passed\": true") != std::string::npos);

    const auto archive = rwn::core::parse_archive_manifest(
        "directory\tApp\t0\t0\t0755\t-\n"
        "directory\tApp/bin\t0\t0\t0755\t-\n"
        "file\tApp/bin/node\t4096\t2048\t0755\t-\n"
        "file\tApp/README.md\t256\t128\t0644\t-\n"
        "symlink\tApp/current\t0\t0\t0777\tApp/bin/node\n");
    const auto archive_report =
        rwn::core::validate_archive_manifest(archive);
    RWN_CHECK(archive_report.passed);
    RWN_CHECK(archive_report.entries == 5);
    RWN_CHECK(archive_report.total_uncompressed_bytes == 4352);

    const std::string hash(64, 'a');
    const rwn::core::WorkspaceManifest repository{
        .workspace_id = "release-repository",
        .revision = 42,
        .entries = {
            {.path = "README.md", .kind = rwn::core::WorkspaceEntryKind::file,
             .size = 256, .content_hash = hash, .mode = 0644,
             .symlink_target = {}},
            {.path = "src", .kind = rwn::core::WorkspaceEntryKind::directory,
             .size = 0, .content_hash = {}, .mode = 0755,
             .symlink_target = {}},
            {.path = "src/main-link", .kind = rwn::core::WorkspaceEntryKind::symlink,
             .size = 0, .content_hash = {}, .mode = 0777,
             .symlink_target = "src/main.cpp"},
            {.path = "src/main.cpp", .kind = rwn::core::WorkspaceEntryKind::file,
             .size = 4096, .content_hash = hash, .mode = 0644,
             .symlink_target = {}},
        },
    };
    const auto repository_report =
        rwn::core::validate_repository_release(repository);
    RWN_CHECK(repository_report.passed);
    RWN_CHECK(repository_report.total_uncompressed_bytes == 4352);
    RWN_CHECK(rwn::core::render_release_security_json(repository_report).find(
                  "\"gate\": \"repository_manifest\"") !=
              std::string::npos);
}

void release_compatibility_and_signed_update_bind_real_package() {
    const auto policy = rwn::core::load_release_compatibility(
        std::filesystem::path(RWN_SOURCE_DIR) /
        "config/version-compatibility.toml");
    RWN_CHECK(policy.product_version ==
              rwn::core::parse_semantic_version("0.1.0"));
    RWN_CHECK(rwn::core::peer_is_compatible(
        policy, rwn::core::parse_semantic_version("0.1.42"), 1, 1));
    RWN_CHECK(!rwn::core::peer_is_compatible(
        policy, rwn::core::parse_semantic_version("0.2.0"), 1, 1));
    RWN_CHECK(rwn::core::state_schema_is_readable(policy, 1));

    const auto root = std::filesystem::temp_directory_path() /
                      "rwn-update-verification-unit";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root);
    const auto package = root / "release.zip";
    {
        std::ofstream output(package, std::ios::binary);
        output << "verified release package bytes\n";
    }
    const rwn::core::UpdateManifest manifest{
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
    BoundUpdateSignatureVerifier verifier;
    const auto verified = rwn::core::verify_update_candidate(
        manifest, rwn::core::parse_semantic_version("0.0.1"), policy,
        "windows", "amd64", package, verifier);
    RWN_CHECK(verifier.called);
    RWN_CHECK(verified.package_path() ==
              std::filesystem::weakly_canonical(package));
    RWN_CHECK(rwn::core::canonical_update_payload(manifest).find(
                  "package_sha256=" + manifest.package_sha256) !=
              std::string::npos);
    std::filesystem::remove_all(root, ignored);
}

#if defined(RWN_TEST_WINDOWS_PLATFORM)
void windows_raw_keyboard_maps_full_standard_layout() {
    const auto map = [](const std::uint16_t make_code,
                        const std::uint16_t flags,
                        const std::uint16_t virtual_key) {
        return rwn::platform::windows::
            map_windows_raw_keyboard_to_hid_usage(
                make_code, flags, virtual_key);
    };
    RWN_CHECK(map(0x1e, 0, 'A') == 0x04U);
    RWN_CHECK(map(0x0c, 0, VK_OEM_MINUS) == 0x2dU);
    RWN_CHECK(map(0x1c, 0, VK_RETURN) == 0x28U);
    RWN_CHECK(map(0x1c, RI_KEY_E0, VK_RETURN) == 0x58U);
    RWN_CHECK(map(0x1d, 0, VK_CONTROL) == 0xe0U);
    RWN_CHECK(map(0x1d, RI_KEY_E0, VK_CONTROL) == 0xe4U);
    RWN_CHECK(map(0x36, 0, VK_SHIFT) == 0xe5U);
    RWN_CHECK(map(0x48, 0, VK_UP) == 0x60U);
    RWN_CHECK(map(0x48, RI_KEY_E0, VK_UP) == 0x52U);
    RWN_CHECK(map(0x3b, 0, VK_F1) == 0x3aU);
    RWN_CHECK(map(0, 0, VK_F20) == 0x6fU);
    RWN_CHECK(!map(0, 0, VK_F21));
    RWN_CHECK(map(0, 0, VK_VOLUME_UP) == 0x80U);
    RWN_CHECK(!map(0, 0, 0xffU));
}

void windows_cng_verifies_rfc6979_p256_signature() {
    const auto public_key = bytes_from_hex(
        "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
        "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299");
    const auto signature = bytes_from_hex(
        "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
        "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
    const std::string payload = "sample";
    rwn::platform::windows::CngEcdsaP256UpdateVerifier verifier(public_key);
    RWN_CHECK(verifier.verify(std::as_bytes(std::span{payload}), signature));
    const auto der = rwn::core::ecdsa_p256_signature_der(signature);
    RWN_CHECK(der.size() == 72);
    RWN_CHECK(der.at(0) == std::byte{0x30});
    RWN_CHECK(der.at(1) == std::byte{0x46});
    RWN_CHECK(der.at(2) == std::byte{0x02});
    RWN_CHECK(der.at(3) == std::byte{0x21});
    RWN_CHECK(der.at(4) == std::byte{0x00});
    RWN_CHECK(der.at(5) == std::byte{0xef});

    auto tampered = signature;
    tampered.front() ^= std::byte{1};
    RWN_CHECK(!verifier.verify(
        std::as_bytes(std::span{payload}), tampered));
}
#endif

void preview_frames_scale_and_header_round_trip() {
    rwn::desktop::RawFrame source{
        .frame_id = 7,
        .captured_at_us = 9000,
        .width = 4,
        .height = 2,
        .row_stride = 16,
        .bgra = std::vector<std::byte>(32),
    };
    for (std::size_t index = 0; index < source.bgra.size(); ++index) {
        source.bgra.at(index) = static_cast<std::byte>(index);
    }
    const auto scaled = rwn::desktop::fit_preview_frame(source, 2, 2);
    RWN_CHECK(scaled.width == 2);
    RWN_CHECK(scaled.height == 1);
    RWN_CHECK(scaled.row_stride == 8);
    RWN_CHECK(scaled.bgra.size() == 8);
    RWN_CHECK(scaled.bgra.at(0) == source.bgra.at(0));
    RWN_CHECK(scaled.bgra.at(4) == source.bgra.at(8));

    const rwn::desktop::PreviewFrameHeader header{
        .frame_id = scaled.frame_id,
        .captured_at_us = scaled.captured_at_us,
        .width = scaled.width,
        .height = scaled.height,
        .payload_size = static_cast<std::uint32_t>(scaled.bgra.size()),
    };
    const auto wire = rwn::desktop::encode_preview_frame_header(header);
    RWN_CHECK(wire.size() == rwn::desktop::preview_frame_header_size);
    RWN_CHECK(rwn::desktop::decode_preview_frame_header(wire) == header);

    const rwn::desktop::EncodedPreviewFrameHeader encoded_header{
        .frame_id = 8,
        .captured_at_us = 9100,
        .width = 1920,
        .height = 1080,
        .payload_size = 48'000,
        .keyframe = true,
    };
    const auto encoded_wire =
        rwn::desktop::encode_encoded_preview_frame_header(encoded_header);
    RWN_CHECK(
        encoded_wire.size() ==
        rwn::desktop::encoded_preview_frame_header_size);
    RWN_CHECK(
        rwn::desktop::decode_encoded_preview_frame_header(encoded_wire) ==
        encoded_header);

    const rwn::desktop::VisualH264AccessUnit access_unit{
        .width = 1280,
        .height = 720,
        .encoded = std::vector<std::byte>(128, std::byte{0x65}),
    };
    const auto access_payload =
        rwn::desktop::encode_visual_h264_access_unit(access_unit);
    const rwn::desktop::VisualMessageHeader visual_header{
        .type = rwn::desktop::VisualMessageType::h264_access_unit,
        .flags = rwn::desktop::visual_flag_frame_final |
                 rwn::desktop::visual_flag_keyframe,
        .payload_size = static_cast<std::uint32_t>(access_payload.size()),
        .session_generation = 44,
        .representation_epoch = 1,
        .visual_sequence = 1,
        .frame_id = 9,
        .captured_at_us = 9200,
    };
    const auto visual_wire =
        rwn::desktop::encode_visual_message_header(visual_header);
    RWN_CHECK(
        visual_wire.size() == rwn::desktop::visual_message_header_size);
    RWN_CHECK(
        rwn::desktop::decode_visual_message_header(visual_wire) ==
        visual_header);
    rwn::desktop::validate_visual_message_payload(
        visual_header, access_payload);
    RWN_CHECK(
        rwn::desktop::decode_visual_h264_access_unit(access_payload) ==
        access_unit);

    const rwn::desktop::VisualCursorPosition cursor{
        .x = 640,
        .y = 360,
        .visible = true,
        .shape_id = 7,
    };
    const auto cursor_payload =
        rwn::desktop::encode_visual_cursor_position(cursor);
    const rwn::desktop::VisualMessageHeader cursor_header{
        .type = rwn::desktop::VisualMessageType::cursor_position,
        .payload_size = static_cast<std::uint32_t>(cursor_payload.size()),
        .session_generation = 44,
        .representation_epoch = 1,
        .visual_sequence = 2,
        .captured_at_us = 9250,
    };
    rwn::desktop::validate_visual_message_payload(
        cursor_header, cursor_payload);
    RWN_CHECK(
        rwn::desktop::decode_visual_cursor_position(cursor_payload) == cursor);

    const rwn::desktop::VisualCursorShape cursor_shape{
        .shape_id = 9,
        .width = 2,
        .height = 2,
        .hotspot_x = 1,
        .hotspot_y = 1,
        .bgra = std::vector<std::byte>(16, std::byte{0x7f}),
    };
    const auto cursor_shape_payload =
        rwn::desktop::encode_visual_cursor_shape(cursor_shape);
    const rwn::desktop::VisualMessageHeader cursor_shape_header{
        .type = rwn::desktop::VisualMessageType::cursor_shape,
        .payload_size = static_cast<std::uint32_t>(
            cursor_shape_payload.size()),
        .session_generation = 44,
        .representation_epoch = 1,
        .visual_sequence = 3,
        .captured_at_us = 9260,
    };
    rwn::desktop::validate_visual_message_payload(
        cursor_shape_header, cursor_shape_payload);
    RWN_CHECK(rwn::desktop::decode_visual_cursor_shape(
                  cursor_shape_payload) == cursor_shape);

    rwn::desktop::VisualSequenceTracker sequence;
    RWN_CHECK(
        sequence.receive(visual_header) ==
        rwn::desktop::VisualSequenceResult::new_generation);
    RWN_CHECK(
        sequence.receive(cursor_header) ==
        rwn::desktop::VisualSequenceResult::accepted);
    auto skipped = cursor_header;
    skipped.visual_sequence = 4;
    RWN_CHECK(
        sequence.receive(skipped) ==
        rwn::desktop::VisualSequenceResult::gap);
}

void media_frames_fragment_reassemble_and_drop_stale_frames() {
    rwn::desktop::VideoFrame source{
        .frame_id = 1,
        .captured_at_us = 1000,
        .width = 1920,
        .height = 1080,
        .codec = rwn::desktop::VideoCodec::h264,
        .keyframe = true,
        .encoded = std::vector<std::byte>(3000, std::byte{0x5a}),
    };
    const auto fragments = rwn::desktop::fragment_frame(source);
    RWN_CHECK(fragments.size() == 3);
    for (const auto& fragment : fragments) {
        const auto wire = rwn::desktop::encode_video_fragment(fragment);
        RWN_CHECK(wire.size() <= rwn::desktop::maximum_media_datagram_size);
        RWN_CHECK(rwn::desktop::decode_video_fragment(wire).payload == fragment.payload);
    }

    rwn::desktop::FrameReassembler reassembler;
    RWN_CHECK(!reassembler.receive(fragments.at(2)));
    RWN_CHECK(!reassembler.receive(fragments.at(0)));
    const auto complete = reassembler.receive(fragments.at(1));
    RWN_CHECK(complete.has_value());
    RWN_CHECK(complete->encoded == source.encoded);
    RWN_CHECK(!reassembler.keyframe_required());
    RWN_CHECK(!reassembler.receive(fragments.front()));

    reassembler.notify_loss();
    auto delta = source;
    delta.frame_id = 2;
    delta.keyframe = false;
    RWN_CHECK(!reassembler.receive(rwn::desktop::fragment_frame(delta).front()));
    RWN_CHECK(reassembler.keyframe_required());
    source.frame_id = 3;
    const auto recovery = rwn::desktop::fragment_frame(source);
    std::optional<rwn::desktop::VideoFrame> recovered;
    for (const auto& fragment : recovery) {
        recovered = reassembler.receive(fragment);
    }
    RWN_CHECK(recovered.has_value());

    rwn::desktop::LatestFrameQueue queue;
    source.frame_id = 10;
    queue.push(source);
    source.frame_id = 11;
    queue.push(source);
    RWN_CHECK(queue.dropped_frames() == 1);
    RWN_CHECK(queue.take()->frame_id == 11);
}

void audio_relay_reorders_packets_and_exposes_plc_telemetry() {
    using namespace std::chrono_literals;
    DeterministicOpusCodec codec;
    RecordingTransport transport;
    rwn::audio::AudioSender sender(transport, codec, desktop_authorization());
    const auto pcm = DeterministicOpusCodec::frame(
        rwn::audio::opus_frame_samples, 7);
    SingleFrameAudioCapture capture;
    capture.next = rwn::audio::CapturedPcmFrame{
        .frame = pcm, .captured_at_us = 1000};
    rwn::audio::AudioCaptureRelay capture_relay(capture, sender);
    RWN_CHECK(capture_relay.pump(250ms));
    RWN_CHECK(capture.last_timeout == 250ms);
    RWN_CHECK(!capture_relay.pump(250ms));
    sender.send(pcm, 21000);
    sender.send(pcm, 41000);
    RWN_CHECK(transport.datagrams.size() == 3);
    for (const auto& [channel, datagram] : transport.datagrams) {
        RWN_CHECK(channel == rwn::transport::DatagramChannel::audio);
        RWN_CHECK(datagram.size() <= rwn::audio::maximum_audio_datagram_size);
    }

    rwn::audio::AudioReceiver receiver(
        codec, desktop_authorization(), 2, 5);
    RecordingAudioPlayback playback;
    rwn::audio::AudioPlaybackRelay playback_relay(receiver, playback);
    RWN_CHECK(receiver.receive(transport.datagrams.at(1).second));
    RWN_CHECK(receiver.receive(transport.datagrams.at(0).second));
    RWN_CHECK(playback_relay.pump(false, 250ms));
    RWN_CHECK(playback_relay.pump(false, 250ms));
    RWN_CHECK(receiver.receive(transport.datagrams.at(2).second));
    RWN_CHECK(playback_relay.pump(false, 250ms));
    RWN_CHECK(playback.frames.size() == 3);
    RWN_CHECK(playback.frames.front().interleaved_samples.front() == 1);
    RWN_CHECK(playback.last_timeout == 250ms);

    const rwn::audio::AudioPacket packet4{
        .sequence = 4, .captured_at_us = 61000,
        .sample_rate = rwn::audio::opus_sample_rate,
        .channels = rwn::audio::opus_channels,
        .samples_per_channel = rwn::audio::opus_frame_samples,
        .opus = {std::byte{1}}};
    auto packet6 = packet4;
    packet6.sequence = 6;
    packet6.captured_at_us = 101000;
    RWN_CHECK(receiver.receive(rwn::audio::encode_packet(packet6)));
    RWN_CHECK(playback_relay.pump(true, 250ms));
    RWN_CHECK(playback.frames.back().interleaved_samples.front() == 0);
    RWN_CHECK(receiver.telemetry().plc_frames == 1);
    RWN_CHECK(codec.concealed == 1);
}

void audio_jitter_buffer_starts_at_target_and_rejects_duplicates() {
    auto packet = [](const std::uint64_t sequence) {
        return rwn::audio::AudioPacket{
            .sequence = sequence,
            .captured_at_us = sequence * 20000,
            .sample_rate = rwn::audio::opus_sample_rate,
            .channels = rwn::audio::opus_channels,
            .samples_per_channel = rwn::audio::opus_frame_samples,
            .opus = {std::byte{0x01}},
        };
    };
    rwn::audio::AudioJitterBuffer jitter(3, 5);
    RWN_CHECK(jitter.push(packet(11)));
    RWN_CHECK(jitter.push(packet(10)));
    RWN_CHECK(!jitter.pop());
    RWN_CHECK(!jitter.push(packet(10)));
    RWN_CHECK(jitter.push(packet(12)));
    RWN_CHECK(jitter.pop()->sequence == 10);
    RWN_CHECK(jitter.pop()->sequence == 11);
    RWN_CHECK(jitter.telemetry().duplicates == 1);
}

void resilient_transport_negotiates_migrates_and_falls_back() {
    using namespace std::chrono_literals;
    using enum rwn::transport::VideoFeature;
    const auto settings = rwn::transport::load_transport_settings(
        std::filesystem::path(RWN_SOURCE_DIR) / "config" /
        "transport.example.toml");
    RWN_CHECK(settings.alpn == "rwn/1");
    RWN_CHECK(settings.require_tls13);
    RWN_CHECK(settings.enable_datagrams);
    RWN_CHECK(settings.enable_connection_migration);
    RWN_CHECK(settings.enable_fallback);
    RWN_CHECK(settings.maximum_datagram_bytes == 1400);
    RWN_CHECK(settings.idle_timeout == 30s);
    RWN_CHECK(settings.keep_alive == 5s);
    RWN_CHECK(settings.primary_failures_before_fallback == 2);
    const auto negotiated = rwn::transport::negotiate_features(
        {.minimum_protocol_version = 1,
         .maximum_protocol_version = 3,
         .video_features = {h264, av1, resolution_4k, fps_120,
                            adaptive_bitrate},
         .maximum_width = 3840,
         .maximum_height = 2160,
         .maximum_frames_per_second = 120,
         .datagrams = true},
        {.minimum_protocol_version = 2,
         .maximum_protocol_version = 4,
         .video_features = {h264, hevc, adaptive_bitrate},
         .maximum_width = 2560,
         .maximum_height = 1440,
         .maximum_frames_per_second = 90,
         .datagrams = true});
    RWN_CHECK(negotiated.protocol_version == 3);
    const std::set expected_features{h264, adaptive_bitrate};
    RWN_CHECK(negotiated.video_features == expected_features);
    RWN_CHECK(negotiated.maximum_width == 1920);
    RWN_CHECK(negotiated.maximum_height == 1080);
    RWN_CHECK(negotiated.maximum_frames_per_second == 60);
    RWN_CHECK(negotiated.datagrams);

    const auto now = std::chrono::steady_clock::time_point{} + 1h;
    ScriptedTransportConnector connector;
    rwn::transport::ResilientTransport transport(
        connector, {.host = "mac-node.local", .port = 4433,
                    .path = rwn::transport::NetworkPath::lan},
        settings);
    transport.set_recovery_cursor({
        .session_id = "session-1",
        .workspace_id = "game",
        .workspace_revision = 42,
        .active_build_ids = {"build-42"},
        .audit_sequence = 9,
    });
    transport.connect(now);
    RWN_CHECK(transport.mode() == rwn::transport::TransportMode::quic);
    auto stream = transport.open_stream(
        rwn::transport::StreamPurpose::control);
    const std::array stream_bytes{std::byte{1}, std::byte{2}};
    stream->write(stream_bytes);
    const std::array datagram_bytes{std::byte{3}, std::byte{4}};
    transport.send_datagram(
        rwn::transport::DatagramChannel::audio,
        datagram_bytes);
    RWN_CHECK(connector.last_connection->streams.size() == 1);
    RWN_CHECK(connector.last_connection->datagrams.size() == 1);
    auto accepted = transport.accept_stream(1s);
    RWN_CHECK(accepted.purpose == rwn::transport::StreamPurpose::command);
    RWN_CHECK(accepted.stream != nullptr);
    const auto received = transport.receive_datagram(1s);
    RWN_CHECK(received.channel == rwn::transport::DatagramChannel::video);
    RWN_CHECK(received.payload ==
              std::vector<std::byte>({std::byte{5}, std::byte{6}}));
    RWN_CHECK(transport.telemetry().streams_accepted == 1);
    RWN_CHECK(transport.telemetry().datagrams_received == 1);
    RWN_CHECK(transport.telemetry().datagram_bytes_received == 2);
    transport.network_changed(
        {.host = "mac-node.vpn", .port = 4433,
         .path = rwn::transport::NetworkPath::vpn},
        now + 1s);
    RWN_CHECK(transport.state() ==
              rwn::transport::ConnectionState::ready);
    RWN_CHECK(transport.mode() == rwn::transport::TransportMode::quic);
    RWN_CHECK(transport.telemetry().migration_attempts == 1);
    RWN_CHECK(transport.telemetry().migration_failures == 0);
    RWN_CHECK(transport.recovery_cursor().workspace_revision == 42);
    RWN_CHECK(transport.recovery_cursor().active_build_ids ==
              std::vector<std::string>{"build-42"});

    ScriptedTransportConnector fallback_connector;
    fallback_connector.primary_failures_remaining = 2;
    rwn::transport::ResilientTransport fallback(
        fallback_connector,
        {.host = "mac-node.local", .port = 4433,
         .path = rwn::transport::NetworkPath::wifi},
        {.primary_failures_before_fallback = 2});
    fallback.set_recovery_cursor({
        .session_id = "session-2",
        .workspace_id = "game",
        .workspace_revision = 43,
        .active_build_ids = {"build-43"},
        .audit_sequence = 10,
    });
    rwn::test::require_throws<std::runtime_error>(
        [&] { fallback.connect(now + 2s); },
        "first QUIC failure before fallback threshold");
    fallback.connect(now + 3s);
    RWN_CHECK(fallback.mode() ==
              rwn::transport::TransportMode::tls_tcp_udp_fallback);
    RWN_CHECK(fallback.telemetry().primary_connection_failures == 2);
    RWN_CHECK(fallback.telemetry().fallback_connections == 1);
    RWN_CHECK(fallback.recovery_cursor().session_id == "session-2");
    fallback.network_changed(
        {.host = "mac-node.lan", .port = 4433,
         .path = rwn::transport::NetworkPath::lan},
        now + 4s);
    RWN_CHECK(fallback.mode() == rwn::transport::TransportMode::quic);
    RWN_CHECK(fallback.telemetry().reconnects == 1);
    RWN_CHECK(fallback.recovery_cursor().workspace_revision == 43);
    fallback.close(now + 5s);
    RWN_CHECK(fallback.state() ==
              rwn::transport::ConnectionState::closed);
}

void encrypted_fallback_binds_tls_and_dtls_to_one_peer() {
    using namespace std::chrono_literals;
    const rwn::transport::TransportEndpoint endpoint{
        .host = "mac-node.local",
        .port = 4433,
        .path = rwn::transport::NetworkPath::lan,
    };
    const rwn::transport::QuicTransportSettings settings{};
    RecordingFallbackProvider provider;
    rwn::transport::EncryptedFallbackConnector connector(provider);
    auto transport = connector.connect(
        rwn::transport::TransportMode::tls_tcp_udp_fallback,
        endpoint, settings);
    auto* duplex = dynamic_cast<rwn::transport::DuplexTransport*>(
        transport.get());
    RWN_CHECK(duplex != nullptr);
    RWN_CHECK(provider.tls_connections == 1);
    RWN_CHECK(provider.dtls_connections == 1);
    RWN_CHECK(provider.last_tls_endpoint.host == endpoint.host);
    RWN_CHECK(provider.last_dtls_endpoint.port == endpoint.port);

    auto stream = duplex->open_stream(
        rwn::transport::StreamPurpose::control);
    const std::array stream_payload{std::byte{0x21}, std::byte{0x22}};
    stream->write(stream_payload);
    RWN_CHECK(provider.reliable->opened.size() == 1);
    RWN_CHECK(provider.reliable->opened.front()->purpose ==
              rwn::transport::StreamPurpose::control);
    RWN_CHECK(provider.reliable->opened.front()->writes.front() ==
              std::vector<std::byte>(stream_payload.begin(),
                                     stream_payload.end()));

    const auto accepted = duplex->accept_stream(2s);
    RWN_CHECK(accepted.purpose ==
              rwn::transport::StreamPurpose::command);
    RWN_CHECK(accepted.stream != nullptr);
    RWN_CHECK(provider.reliable->last_accept_timeout == 2s);

    const std::array datagram_payload{
        std::byte{0x31}, std::byte{0x32}, std::byte{0x33}};
    duplex->send_datagram(
        rwn::transport::DatagramChannel::audio, datagram_payload);
    RWN_CHECK(provider.datagrams->sent.size() == 1);
    RWN_CHECK(provider.datagrams->sent.front().first ==
              rwn::transport::DatagramChannel::audio);
    const auto received = duplex->receive_datagram(3s);
    RWN_CHECK(received.channel ==
              rwn::transport::DatagramChannel::video);
    RWN_CHECK(received.payload == std::vector<std::byte>(
              {std::byte{0x51}, std::byte{0x52}}));
    RWN_CHECK(provider.datagrams->last_receive_timeout == 3s);

    ScriptedTransportConnector primary;
    RecordingFallbackProvider routed_provider;
    rwn::transport::EncryptedFallbackConnector routed_fallback(
        routed_provider);
    rwn::transport::RoutedTransportConnector routed(
        primary, routed_fallback);
    auto primary_transport = routed.connect(
        rwn::transport::TransportMode::quic, endpoint, settings);
    auto fallback_transport = routed.connect(
        rwn::transport::TransportMode::tls_tcp_udp_fallback,
        endpoint, settings);
    RWN_CHECK(primary.attempts ==
              std::vector<rwn::transport::TransportMode>{
                  rwn::transport::TransportMode::quic});
    RWN_CHECK(!routed.migrate(*fallback_transport, endpoint));
    RWN_CHECK(primary.migrations.empty());
    RWN_CHECK(routed.migrate(*primary_transport, endpoint));
    RWN_CHECK(primary.migrations.size() == 1);
}

void transport_verification_reports_impairment_and_correctness() {
    const std::string hash(64, 'a');
    const rwn::transport::CorrectnessEvidence evidence{
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
    for (const std::string_view id : {
             "lan-baseline", "wifi-loss-reorder", "vpn-network-switch"}) {
        const auto scenario =
            rwn::transport::standard_impairment_scenario(id);
        const auto observations =
            rwn::transport::make_deterministic_observations(scenario);
        const auto report = rwn::transport::analyze_transport_verification(
            rwn::transport::VerificationMode::deterministic_model, scenario,
            evidence, observations);
        RWN_CHECK(report.scenario.id == id);
        RWN_CHECK(report.packets_sent == 10'000);
        RWN_CHECK(report.packets_delivered + report.packets_lost ==
                  report.packets_sent);
        RWN_CHECK(report.sync_correct);
        RWN_CHECK(report.build_correct);
        RWN_CHECK(report.migration_recovered);
        RWN_CHECK(report.passed);
        const auto json =
            rwn::transport::render_transport_verification_json(report);
        RWN_CHECK(json.find("\"mode\": \"deterministic_model\"") !=
                  std::string::npos);
        RWN_CHECK(json.find("\"build_evidence_sha256\"") !=
                  std::string::npos);
        RWN_CHECK(json.find("\"p95_latency_budget_us\"") !=
                  std::string::npos);
    }

    const auto root = std::filesystem::temp_directory_path() /
                      "rwn-transport-report-unit";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root);
    const auto scenario =
        rwn::transport::standard_impairment_scenario("lan-baseline");
    const auto report = rwn::transport::analyze_transport_verification(
        rwn::transport::VerificationMode::deterministic_model, scenario,
        evidence, rwn::transport::make_deterministic_observations(scenario));
    const auto destination = root / "report.json";
    rwn::transport::write_transport_verification_report(destination, report);
    RWN_CHECK(std::filesystem::is_regular_file(destination));
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::transport::write_transport_verification_report(
                destination, report);
        },
        "immutable transport report");
    std::filesystem::remove_all(root, ignored);
}

void desktop_transport_routes_media_pointer_input_and_clipboard() {
    RecordingTransport transport;
    rwn::desktop::DesktopTransportSession session(
        transport, desktop_authorization());
    session.send_frame({
        .frame_id = 1,
        .captured_at_us = 100,
        .width = 1920,
        .height = 1080,
        .codec = rwn::desktop::VideoCodec::h264,
        .keyframe = true,
        .encoded = std::vector<std::byte>(2000, std::byte{0x01}),
    });
    session.request_keyframe({.after_frame_id = 1, .reason_code = "packet_loss"});
    session.send_input({
        .kind = rwn::desktop::InputKind::pointer_move,
        .sequence = 1,
        .occurred_at_us = 110,
        .value_a = 32767,
        .value_b = 32767,
        .text = {},
    });
    session.send_input({
        .kind = rwn::desktop::InputKind::pointer_button,
        .sequence = 2,
        .occurred_at_us = 120,
        .value_a = 1,
        .pressed = true,
        .text = {},
    });
    rwn::desktop::ClipboardSynchronizer clipboard("windows-client");
    const auto update = clipboard.make_update(
        "繁中 clipboard", 1, desktop_authorization());
    session.send_clipboard(update);

    RWN_CHECK(transport.datagrams.size() == 3);
    RWN_CHECK(transport.datagrams.at(0).first ==
              rwn::transport::DatagramChannel::video);
    RWN_CHECK(transport.datagrams.at(1).first ==
              rwn::transport::DatagramChannel::video);
    RWN_CHECK(transport.datagrams.at(2).first ==
              rwn::transport::DatagramChannel::pointer);
    RWN_CHECK(transport.streams.size() == 3);
    RWN_CHECK(transport.streams.at(0)->purpose ==
              rwn::transport::StreamPurpose::control);
    RWN_CHECK(rwn::desktop::decode_keyframe_request(
                  transport.streams.at(0)->writes.front()).reason_code ==
              "packet_loss");
    RWN_CHECK(transport.streams.at(1)->purpose ==
              rwn::transport::StreamPurpose::input);
    RWN_CHECK(rwn::desktop::decode_input_event(
                  transport.streams.at(1)->writes.front()).kind ==
              rwn::desktop::InputKind::pointer_button);
    RWN_CHECK(transport.streams.at(2)->purpose ==
              rwn::transport::StreamPurpose::clipboard);
    RWN_CHECK(rwn::desktop::decode_clipboard_update(
                  transport.streams.at(2)->writes.front()).utf8_text ==
              "繁中 clipboard");
}

void input_conformance_handles_unicode_coordinates_and_stuck_keys() {
    using enum rwn::desktop::InputKind;
    RecordingInputBackend backend;
    rwn::desktop::InputReceiver receiver(backend);
    const auto authorization = desktop_authorization();
    RWN_CHECK(receiver.receive(
        {.kind = raw_key, .sequence = 10, .occurred_at_us = 1000000,
         .value_a = 0x04, .pressed = true, .text = {}}, true, authorization));
    const rwn::desktop::InputEvent text{
        .kind = text_commit,
        .sequence = 11,
        .occurred_at_us = 1100000,
        .text = "繁中🙂",
    };
    RWN_CHECK(rwn::desktop::decode_input_event(
                  rwn::desktop::encode_input_event(text)) == text);
    RWN_CHECK(receiver.receive(text, true, authorization));
    RWN_CHECK(receiver.receive(
        {.kind = pointer_button, .sequence = 12, .occurred_at_us = 1200000,
         .value_a = 1, .pressed = true, .text = {}}, true, authorization));
    RWN_CHECK(receiver.receive(
        {.kind = vertical_wheel, .sequence = 13,
         .occurred_at_us = 1220000, .value_a = 120, .text = {}},
        true, authorization));
    RWN_CHECK(receiver.receive(
        {.kind = pointer_move, .sequence = 50, .occurred_at_us = 1250000,
         .value_a = 32768, .value_b = 32768, .text = {}}, false, authorization));
    RWN_CHECK(receiver.release_stuck_keys(3000000, std::chrono::seconds{1}) == 1);
    RWN_CHECK(backend.keys.size() == 2);
    RWN_CHECK(!backend.keys.back().second);
    RWN_CHECK(backend.texts.front() == "繁中🙂");
    RWN_CHECK(backend.wheels.size() == 1);
    RWN_CHECK((backend.wheels.front() ==
               std::pair{std::int32_t{120}, false}));
    RWN_CHECK(receiver.release_all_input() == 1);
    RWN_CHECK(backend.buttons.size() == 2);
    RWN_CHECK(!backend.buttons.back().second);

    rwn::desktop::InputFocusReleaseGate focus_gate;
    RWN_CHECK(focus_gate.focus_lost());
    RWN_CHECK(!focus_gate.focus_lost());
    focus_gate.focus_acquired();
    RWN_CHECK(focus_gate.focus_lost());

    const auto control_payload = rwn::desktop::encode_input_event(text);
    const rwn::desktop::ReverseControlHeader control_header{
        .type = rwn::desktop::ReverseControlType::input_event,
        .payload_size = static_cast<std::uint32_t>(control_payload.size()),
        .input_epoch = 1,
        .sequence = 1,
        .occurred_at_us = 1100000,
    };
    const auto control_wire =
        rwn::desktop::encode_reverse_control_header(control_header);
    RWN_CHECK(rwn::desktop::decode_reverse_control_header(control_wire) ==
              control_header);
    rwn::desktop::validate_reverse_control_payload(
        control_header, control_payload);

    const auto center = rwn::desktop::map_pointer_to_surface(
        32768, 32768, {.width = 1000, .height = 1000},
        {.width = 1920, .height = 1080});
    RWN_CHECK(center.has_value());
    RWN_CHECK(center->x >= 959 && center->x <= 961);
    RWN_CHECK(center->y >= 539 && center->y <= 541);
    RWN_CHECK(!rwn::desktop::map_pointer_to_surface(
        32768, 0, {.width = 1000, .height = 1000},
        {.width = 1920, .height = 1080}));
}

void clipboard_loop_prevention_and_latency_adaptation_are_deterministic() {
    const auto authorization = desktop_authorization();
    rwn::desktop::ClipboardSynchronizer windows("windows");
    rwn::desktop::ClipboardSynchronizer mac("mac");
    const auto outbound = windows.make_update("文字🙂", 1, authorization);
    const auto wire = rwn::desktop::encode_clipboard_update(outbound);
    const auto decoded = rwn::desktop::decode_clipboard_update(wire);
    RWN_CHECK(mac.apply(decoded, authorization));
    RWN_CHECK(*mac.latest_text() == "文字🙂");
    RWN_CHECK(!mac.apply(decoded, authorization));
    RWN_CHECK(!windows.apply(decoded, authorization));

    const auto degraded = rwn::desktop::adapt_video_settings(
        {}, {.round_trip_ms = 90, .loss_basis_points = 600, .send_queue_ms = 70});
    RWN_CHECK(degraded.width == 1280);
    RWN_CHECK(degraded.height == 720);
    RWN_CHECK(degraded.frames_per_second == 45);
    RWN_CHECK(degraded.bitrate_kbps == 9000);
    const auto recovered = rwn::desktop::adapt_video_settings(
        degraded, {.round_trip_ms = 10, .loss_basis_points = 0, .send_queue_ms = 0});
    RWN_CHECK(recovered.width == 1920);
    RWN_CHECK(recovered.height == 1080);

    rwn::desktop::LatencyTelemetry latency;
    latency.record({.captured_at_us = 100, .encoded_at_us = 110,
                    .received_at_us = 120, .decoded_at_us = 130,
                    .displayed_at_us = 140});
    latency.record({.captured_at_us = 200, .encoded_at_us = 220,
                    .received_at_us = 240, .decoded_at_us = 260,
                    .displayed_at_us = 300});
    RWN_CHECK(latency.percentile_end_to_end(0.5) == 40);
    RWN_CHECK(latency.percentile_end_to_end(0.95) == 100);
}

void session_service_binds_mtls_policy_lease_and_audit() {
    using namespace std::chrono_literals;
    using enum rwn::core::Capability;
    constexpr auto fingerprint =
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    const auto now = rwn::core::WallClock::time_point{} + 200h;
    rwn::core::DeviceRegistry registry;
    rwn::core::PairingService pairing(registry);
    const auto challenge = pairing.begin(
        {.node_id = "mac-node",
         .node_name = "Mac node",
         .lan_endpoint = "192.168.1.8:4433",
         .fingerprint = fingerprint},
        "123456", now, 5min);
    const auto certificate = pairing.confirm(
        challenge, "123456", "windows-client", "Windows client", fingerprint,
        now, 24h);
    rwn::core::AuditLog audit;
    rwn::core::SessionService sessions(registry, audit);
    const rwn::core::Policy policy{
        .principal_id = "windows-client",
        .workspaces = {"game"},
        .allowed = {workspace_sync, artifact_download},
    };
    const auto authorization = sessions.open(
        {.session_id = "integrated-session",
         .peer = {.tls_1_3_negotiated = true,
                  .client_certificate_present = true,
                  .certificate_chain_valid = true,
                  .revocation_checked = true,
                  .certificate = certificate},
         .capabilities = {
             .principal = {.id = "windows-client",
                           .kind = rwn::core::PrincipalKind::device},
             .workspace = "game",
             .requested = {workspace_sync, artifact_download, command_exec}},
         .lease = 15min},
        policy, now);
    RWN_CHECK(authorization.permits(workspace_sync));
    RWN_CHECK(!authorization.permits(command_exec));
    RWN_CHECK(sessions.permits(
        "integrated-session", artifact_download, "game", now + 1min));
    RWN_CHECK(!sessions.permits(
        "integrated-session", artifact_download, "other", now + 1min));
    sessions.renew("integrated-session", now + 5min, 15min);
    sessions.close("integrated-session", now + 6min);
    RWN_CHECK(sessions.state("integrated-session") ==
              rwn::core::SessionState::closed);
    RWN_CHECK(audit.for_session("integrated-session").size() == 4);
}

void discovery_cache_expires_stale_mdns_observations() {
    using namespace std::chrono_literals;
    constexpr auto fingerprint =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const auto now = rwn::core::WallClock::time_point{} + 500h;
    rwn::core::DiscoveryCache discovery(30s);
    discovery.observe(
        {.node_id = "mac-node",
         .node_name = "Mac Node",
         .lan_endpoint = "192.168.1.8:4433",
         .fingerprint = fingerprint},
        now);
    RWN_CHECK(discovery.find("mac-node", now + 29s) != nullptr);
    RWN_CHECK(discovery.find("mac-node", now + 31s) == nullptr);
}

void strict_policy_file_is_readable_and_authorizes_by_intersection() {
    using enum rwn::core::Capability;
    const auto policy = rwn::core::load_policy_file(
        std::filesystem::path(RWN_SOURCE_DIR) / "config" /
        "access-policy.example.toml");
    const auto result = rwn::core::authorize(
        {.principal = {.id = "windows-client",
                       .kind = rwn::core::PrincipalKind::device},
         .workspace = "example-workspace",
         .requested = {workspace_sync, artifact_download, system_admin}},
        policy);
    RWN_CHECK(result.permits(workspace_sync));
    RWN_CHECK(result.permits(artifact_download));
    RWN_CHECK(!result.permits(system_admin));
}

void one_way_manifest_diff_handles_rename_and_resume() {
    constexpr auto content_hash =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const rwn::core::WorkspaceManifest mirror{.workspace_id = "game", .revision = 1,
        .entries = {{.path = "src/old.cpp", .kind = rwn::core::WorkspaceEntryKind::file, .size = 3, .content_hash = content_hash, .mode = 0, .symlink_target = {}}}};
    const rwn::core::WorkspaceManifest source{.workspace_id = "game", .revision = 2,
        .entries = {{.path = "src/new.cpp", .kind = rwn::core::WorkspaceEntryKind::file, .size = 3, .content_hash = content_hash, .mode = 0, .symlink_target = {}}}};
    const auto changes = rwn::core::diff_manifests(source, mirror);
    RWN_CHECK(changes.size() == 1 && changes.front().kind == rwn::core::WorkspaceChangeKind::rename);
    rwn::core::ChunkResumeLedger transfer(3);
    transfer.confirm(0, 16, "chunk-a"); transfer.confirm(2, 16, "chunk-c");
    RWN_CHECK(transfer.missing() == std::vector<std::size_t>{1});
}

void sha256_and_filesystem_manifest_are_content_authoritative() {
    constexpr auto abc_hash =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    RWN_CHECK(rwn::core::sha256_hex("abc") == abc_hash);
    const auto root = std::filesystem::temp_directory_path() /
                      "rwn-workspace-manifest-unit";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root / "src");
    std::filesystem::create_directories(root / "build");
    {
        std::ofstream(root / "src" / "main.cpp", std::ios::binary) << "abc";
        std::ofstream(root / "src" / "run.sh", std::ios::binary) << "#!/bin/sh\n";
        std::ofstream(root / "build" / "ignored.obj", std::ios::binary) << "ignored";
    }
    const auto manifest = rwn::core::build_workspace_manifest(
        root,
        {.workspace_id = "game",
         .revision = 7,
         .ignore_rules = rwn::core::IgnoreRules::parse("build/\n"),
         .executable_paths = {"src/run.sh"}});
    RWN_CHECK(manifest.entries.size() == 3);
    const auto main_entry = std::ranges::find_if(
        manifest.entries, [](const rwn::core::WorkspaceEntry& entry) {
            return entry.path == "src/main.cpp";
        });
    RWN_CHECK(main_entry != manifest.entries.end());
    RWN_CHECK(main_entry->content_hash == abc_hash);
    const auto run_entry = std::ranges::find_if(
        manifest.entries, [](const rwn::core::WorkspaceEntry& entry) {
            return entry.path == "src/run.sh";
        });
    RWN_CHECK(run_entry != manifest.entries.end());
    RWN_CHECK(run_entry->mode == 0755U);
    RWN_CHECK(std::ranges::none_of(
        manifest.entries, [](const rwn::core::WorkspaceEntry& entry) {
            return entry.path.starts_with("build");
        }));
    std::filesystem::remove_all(root, ignored);
}

void git_index_stage_modes_supply_executable_metadata() {
    std::string stage_output;
    stage_output.append("100755 abcdef 0\tscripts/build.sh");
    stage_output.push_back('\0');
    stage_output.append("100644 123456 0\tsrc/main.cpp");
    stage_output.push_back('\0');
    const auto executable =
        rwn::core::parse_git_stage_executable_paths(stage_output);
    RWN_CHECK((executable ==
               std::set<std::string, std::less<>>{"scripts/build.sh"}));
}

void transfer_encoding_skips_already_compressed_content() {
    RWN_CHECK(rwn::core::choose_transfer_encoding("src/main.cpp", true) ==
              rwn::core::TransferEncoding::zstd);
    RWN_CHECK(rwn::core::choose_transfer_encoding("assets/image.PNG", true) ==
              rwn::core::TransferEncoding::identity);
    RWN_CHECK(rwn::core::choose_transfer_encoding("src/main.cpp", false) ==
              rwn::core::TransferEncoding::identity);
}

void watcher_events_are_debounced_as_triggers_only() {
    using namespace std::chrono_literals;
    const auto now = rwn::core::WallClock::time_point{} + 600h;
    rwn::core::ChangeDebouncer debounce(100ms);
    debounce.notify(
        {.kind = rwn::core::WorkspaceTriggerKind::added,
         .path = "src/main.cpp"},
        now);
    debounce.notify(
        {.kind = rwn::core::WorkspaceTriggerKind::modified,
         .path = "src/main.cpp"},
        now + 50ms);
    RWN_CHECK(debounce.take_ready(now + 149ms).empty());
    const auto ready = debounce.take_ready(now + 150ms);
    RWN_CHECK(ready.size() == 1);
    RWN_CHECK(ready.front().kind ==
              rwn::core::WorkspaceTriggerKind::modified);
}

std::string numbered_workspace_path(const std::size_t index) {
    std::ostringstream output;
    output << "src/file-" << std::setw(6) << std::setfill('0') << index << ".cpp";
    return output.str();
}

void hundred_thousand_entry_diff_reconciles_exactly() {
    constexpr std::size_t file_count = 100'000;
    rwn::core::WorkspaceManifest destination{
        .workspace_id = "large-workspace", .revision = 1, .entries = {}};
    destination.entries.reserve(file_count + 1);
    for (std::size_t index = 0; index < file_count; ++index) {
        const auto path = numbered_workspace_path(index);
        destination.entries.push_back({
            .path = path,
            .kind = rwn::core::WorkspaceEntryKind::file,
            .size = 1,
            .content_hash = rwn::core::sha256_hex(path),
            .mode = 0644U,
            .symlink_target = {},
        });
    }
    destination.entries.push_back({
        .path = "zz/link",
        .kind = rwn::core::WorkspaceEntryKind::symlink,
        .size = 0,
        .content_hash = {},
        .mode = 0777U,
        .symlink_target = "src/file-000000.cpp",
    });
    auto source = destination;
    source.revision = 2;
    source.entries.front().path = "src/renamed.cpp";
    source.entries.erase(source.entries.begin() + 1);
    source.entries[file_count - 2].content_hash =
        rwn::core::sha256_hex("one-byte-change");
    std::ranges::sort(source.entries, {}, &rwn::core::WorkspaceEntry::path);

    const auto changes = rwn::core::diff_manifests(source, destination);
    RWN_CHECK(changes.size() == 3);
    const auto applied =
        rwn::core::apply_manifest_diff(source, destination, changes);
    RWN_CHECK(applied.entries == source.entries);
    RWN_CHECK(rwn::core::manifest_content_hash(applied) ==
              rwn::core::manifest_content_hash(source));
}

void revision_history_requires_contiguous_verified_manifests() {
    constexpr auto hash =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    rwn::core::WorkspaceRevisionHistory history("game", 2);
    history.begin(1);
    history.commit({
        .workspace_id = "game",
        .revision = 1,
        .entries = {{.path = "src/main.cpp",
                     .kind = rwn::core::WorkspaceEntryKind::file,
                     .size = 3,
                     .content_hash = hash,
                     .mode = 0644U,
                     .symlink_target = {}}},
    });
    RWN_CHECK(history.current_revision() == 1);
    RWN_CHECK(history.state() == rwn::core::WorkspaceSyncState::synced);
    history.begin(2);
    history.fail("connection interrupted");
    RWN_CHECK(history.current_revision() == 1);
    RWN_CHECK(history.state() == rwn::core::WorkspaceSyncState::failed);
    RWN_CHECK(!history.failure_reason().empty());
    rwn::test::require_throws<std::logic_error>(
        [&] { history.begin(3); }, "non-contiguous revision");
}

#if defined(RWN_TEST_WINDOWS_PLATFORM)
void file_transfer_resumes_from_verified_staging_chunks_and_replaces_atomically() {
    const std::string first = "hello ";
    const std::string second = "world";
    const std::string complete = first + second;
    const auto root = std::filesystem::temp_directory_path() /
                      "rwn-file-transfer-unit";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root);
    rwn::platform::windows::WindowsDurableFileSystem filesystem;
    const rwn::core::FileTransferPlan plan{
        .transfer_id = "transfer-1",
        .relative_path = "src/message.txt",
        .total_size = complete.size(),
        .sha256 = rwn::core::sha256_hex(complete),
        .chunks = {
            {.index = 0,
             .offset = 0,
             .size = first.size(),
             .sha256 = rwn::core::sha256_hex(first)},
            {.index = 1,
             .offset = first.size(),
             .size = second.size(),
             .sha256 = rwn::core::sha256_hex(second)},
        },
    };
    {
        rwn::core::FileTransfer transfer(
            rwn::core::WorkspaceScope(root), plan, filesystem);
        transfer.accept_chunk(0, bytes_of(first));
        RWN_CHECK(transfer.missing_chunks() == std::vector<std::size_t>{1});
        RWN_CHECK(!std::filesystem::exists(transfer.destination_path()));
    }
    {
        rwn::core::FileTransfer resumed(
            rwn::core::WorkspaceScope(root), plan, filesystem);
        RWN_CHECK(resumed.missing_chunks() == std::vector<std::size_t>{1});
        resumed.accept_chunk(1, bytes_of(second));
        resumed.finalize();
        RWN_CHECK(std::filesystem::exists(resumed.destination_path()));
        RWN_CHECK(!std::filesystem::exists(resumed.staging_path()));
    }
    std::ifstream input(root / "src" / "message.txt", std::ios::binary);
    const std::string written{
        std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    RWN_CHECK(written == complete);
    std::filesystem::remove_all(root, ignored);
}


void windows_directory_watcher_emits_trigger_for_real_change() {
    using namespace std::chrono_literals;
    const auto root = std::filesystem::temp_directory_path() /
                      "rwn-directory-watcher-unit";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root);
    rwn::platform::windows::DirectoryWatcher watcher(root);
    std::jthread writer([root] {
        std::this_thread::sleep_for(50ms);
        std::ofstream(root / "created.txt", std::ios::binary) << "content";
    });
    const auto triggers = watcher.poll(2s);
    RWN_CHECK(std::ranges::any_of(
        triggers, [](const rwn::core::WorkspaceTrigger& trigger) {
            return trigger.path == "created.txt";
        }));
    writer.join();
    std::filesystem::remove_all(root, ignored);
}
#endif

#if defined(RWN_TEST_WINDOWS_PLATFORM)
void pinned_build_runs_process_and_reports_actual_exit_evidence() {
    using namespace std::chrono_literals;
    rwn::core::BuildQueue builds;
    builds.submit(
        {.id = "build-1",
         .workspace_id = "game",
         .pinned_revision = 2,
         .profile = "windows-fixture",
         .command = {.argv = {RWN_PROCESS_FIXTURE, "--fail"},
                     .working_directory = ".",
                     .timeout = 1min,
                     .environment = {}}},
        {});
    rwn::platform::windows::WindowsCommandExecutor executor(RWN_SOURCE_DIR);
    rwn::core::BuildRunner runner(builds, executor);
    const auto evidence = runner.run("build-1");
    RWN_CHECK(builds.state("build-1") == rwn::core::BuildState::failed);
    RWN_CHECK(evidence.exit_code == 7);
    RWN_CHECK(evidence.stdout_log == "failed-out\r\n" ||
              evidence.stdout_log == "failed-out\n");
    RWN_CHECK(evidence.stderr_log == "failed-err\r\n" ||
              evidence.stderr_log == "failed-err\n");
    RWN_CHECK(evidence.elapsed >= 0ms);
    RWN_CHECK(!evidence.timed_out);
    RWN_CHECK(!evidence.cancelled);
    RWN_CHECK(builds.evidence("build-1")->exit_code == evidence.exit_code);
}

void command_executor_captures_success_and_timeout() {
    using namespace std::chrono_literals;
    rwn::platform::windows::WindowsCommandExecutor executor(RWN_SOURCE_DIR);
    const auto success = executor.execute(
        {.argv = {RWN_PROCESS_FIXTURE, "--success"},
         .working_directory = ".",
         .timeout = 1min,
         .environment = {}});
    RWN_CHECK(success.exit_code == 0);
    RWN_CHECK(success.stdout_log == "fixture-out\r\n" ||
              success.stdout_log == "fixture-out\n");
    RWN_CHECK(success.stderr_log == "fixture-err\r\n" ||
              success.stderr_log == "fixture-err\n");

    const auto timed_out = executor.execute(
        {.argv = {RWN_PROCESS_FIXTURE, "--sleep", "2500"},
         .working_directory = ".",
         .timeout = 1s,
         .environment = {}});
    RWN_CHECK(timed_out.timed_out);
    RWN_CHECK(!timed_out.cancelled);
    RWN_CHECK(timed_out.exit_code != 0);
}

void command_cancel_kills_the_process_tree() {
    using namespace std::chrono_literals;
    const auto marker = std::filesystem::temp_directory_path() /
                        "rwn-command-child-survived.txt";
    std::error_code ignored;
    std::filesystem::remove(marker, ignored);
    rwn::platform::windows::WindowsCommandExecutor executor(RWN_SOURCE_DIR);
    rwn::core::CancellationSource cancellation;
    auto future = std::async(std::launch::async, [&] {
        return executor.execute(
            {.argv = {RWN_PROCESS_FIXTURE, "--spawn-child", marker.string()},
             .working_directory = ".",
             .timeout = 1min,
             .environment = {}},
            cancellation.token());
    });
    std::this_thread::sleep_for(100ms);
    cancellation.request_stop();
    const auto evidence = future.get();
    RWN_CHECK(evidence.cancelled);
    RWN_CHECK(!evidence.timed_out);
    std::this_thread::sleep_for(900ms);
    RWN_CHECK(!std::filesystem::exists(marker));
}

void successful_build_publishes_verified_resumable_immutable_artifact() {
    using namespace std::chrono_literals;
    const auto root = std::filesystem::temp_directory_path() /
                      "rwn-artifact-flow";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root / "workspace/dist");
    std::filesystem::create_directories(root / "store");
    std::filesystem::create_directories(root / "download");
    const std::string content = "immutable-artifact-content";
    {
        std::ofstream(root / "workspace/dist/app.zip", std::ios::binary)
            << content;
    }
    rwn::core::BuildQueue builds;
    builds.submit(
        {.id = "build-artifact",
         .workspace_id = "game",
         .pinned_revision = 9,
         .profile = "macos-release",
         .command = {.argv = {"/usr/bin/true"},
                     .working_directory = ".",
                     .timeout = 1min,
                     .environment = {}}},
        {});
    builds.start("build-artifact");
    builds.finish(
        "build-artifact",
        {.exit_code = 0,
         .stdout_log = "built",
         .stderr_log = {},
         .elapsed = 1ms,
         .timed_out = false,
         .cancelled = false,
         .stdout_truncated = false,
         .stderr_truncated = false});
    rwn::platform::windows::WindowsDurableFileSystem filesystem;
    rwn::core::DurableAuditFileSink audit_sink(
        root / "audit", "events.jsonl", filesystem);
    rwn::core::AuditLog audit({}, &audit_sink);
    rwn::core::ArtifactStore store(
        builds, root / "workspace", root / "store", filesystem, audit);
    const auto artifact = store.publish(
        {.id = "artifact-1",
         .build_id = "build-artifact",
         .source_revision = 9,
         .name = "app.zip",
         .platform = "macos",
         .architecture = "arm64",
         .source_relative_path = "dist/app.zip",
         .principal_id = "human-1",
         .device_id = "windows-1",
         .session_id = "session-1",
         .occurred_at = rwn::core::WallClock::now()});
    RWN_CHECK(artifact.sha256 == rwn::core::sha256_hex(content));
    RWN_CHECK(artifact.size == content.size());
    RWN_CHECK(store.verify("artifact-1"));
    RWN_CHECK(std::filesystem::is_regular_file(
        root / "store/metadata/artifact-1.toml"));

    rwn::core::ArtifactStore reloaded(
        builds, root / "workspace", root / "store", filesystem, audit);
    RWN_CHECK(reloaded.metadata("artifact-1") == artifact);
    RWN_CHECK(reloaded.verify("artifact-1"));

    const auto plan = reloaded.download_plan(
        "artifact-1", "download-1", "received/app.zip", 8);
    RWN_CHECK(plan.chunks.size() > 1);
    std::ifstream object(reloaded.object_path("artifact-1"), std::ios::binary);
    const std::string stored{
        std::istreambuf_iterator<char>(object),
        std::istreambuf_iterator<char>()};
    rwn::core::FileTransfer first(
        rwn::core::WorkspaceScope(root / "download"), plan, filesystem);
    const auto& second_chunk = plan.chunks.at(1);
    first.accept_chunk(
        1, std::as_bytes(std::span{
               stored.data() + static_cast<std::ptrdiff_t>(second_chunk.offset),
               second_chunk.size}));
    rwn::core::FileTransfer resumed(
        rwn::core::WorkspaceScope(root / "download"), plan, filesystem);
    const auto missing = resumed.missing_chunks();
    RWN_CHECK(std::ranges::find(missing, 1U) == missing.end());
    for (const auto index : missing) {
        const auto& chunk = plan.chunks.at(index);
        resumed.accept_chunk(
            index, std::as_bytes(std::span{
                       stored.data() + static_cast<std::ptrdiff_t>(chunk.offset),
                       chunk.size}));
    }
    resumed.finalize();
    std::ifstream downloaded(
        root / "download/received/app.zip", std::ios::binary);
    const std::string received{
        std::istreambuf_iterator<char>(downloaded),
        std::istreambuf_iterator<char>()};
    RWN_CHECK(received == content);
    std::filesystem::remove_all(root, ignored);
}

void deployment_activates_healthy_artifact_and_rolls_back_failed_health() {
    using namespace std::chrono_literals;
    const auto root = std::filesystem::temp_directory_path() /
                      "rwn-deployment-flow";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root / "workspace/dist");
    std::filesystem::create_directories(root / "store");
    std::filesystem::create_directories(root / "runtime/bin");
    std::ofstream(root / "workspace/dist/v1.bin", std::ios::binary)
        << "release-v1";
    std::ofstream(root / "workspace/dist/v2.bin", std::ios::binary)
        << "release-v2-bad";
    std::ofstream(root / "runtime/bin/current.bin", std::ios::binary)
        << "release-v0";

    rwn::core::BuildQueue builds;
    const auto successful_build = [&](const std::string& id,
                                      const std::uint64_t revision) {
        builds.submit(
            {.id = id,
             .workspace_id = "game",
             .pinned_revision = revision,
             .profile = "macos-release",
             .command = {.argv = {"/usr/bin/true"},
                         .working_directory = ".",
                         .timeout = 1min,
                         .environment = {}}},
            {});
        builds.start(id);
        builds.finish(
            id,
            {.exit_code = 0,
             .stdout_log = "built",
             .stderr_log = {},
             .elapsed = 1ms,
             .timed_out = false,
             .cancelled = false,
             .stdout_truncated = false,
             .stderr_truncated = false});
    };
    successful_build("build-v1", 21);
    successful_build("build-v2", 22);
    rwn::platform::windows::WindowsDurableFileSystem filesystem;
    rwn::core::DurableAuditFileSink audit_sink(
        root / "audit", "events.jsonl", filesystem);
    rwn::core::AuditLog audit({}, &audit_sink);
    const auto publication_time = rwn::core::WallClock::now();
    rwn::core::ArtifactStore artifacts(
        builds, root / "workspace", root / "store", filesystem, audit);
    const auto v1 = artifacts.publish(
        {.id = "artifact-v1",
         .build_id = "build-v1",
         .source_revision = 21,
         .name = "v1.bin",
         .platform = "macos",
         .architecture = "arm64",
         .source_relative_path = "dist/v1.bin",
         .principal_id = "human-1",
         .device_id = "windows-1",
         .session_id = "session-1",
         .occurred_at = publication_time});
    const auto v2 = artifacts.publish(
        {.id = "artifact-v2",
         .build_id = "build-v2",
         .source_revision = 22,
         .name = "v2.bin",
         .platform = "macos",
         .architecture = "arm64",
         .source_relative_path = "dist/v2.bin",
         .principal_id = "human-1",
         .device_id = "windows-1",
         .session_id = "session-1",
         .occurred_at = publication_time + 1ms});
    rwn::platform::windows::WindowsCommandExecutor executor(root / "runtime");
    const auto command = [](std::vector<std::string> argv) {
        return rwn::core::CommandSpec{
            .argv = std::move(argv),
            .working_directory = ".",
            .timeout = std::chrono::minutes(1),
            .environment = {},
        };
    };
    const rwn::core::AuthorizationResult deploy_authorization{
        .principal_matched = true,
        .workspace_allowed = true,
        .granted = {rwn::core::Capability::deploy_execute},
        .denied = {},
    };
    const auto now = publication_time + 1s;
    rwn::core::FileDeploymentBackend healthy_backend(
        root / "runtime", "bin/current.bin", executor, filesystem,
        command({RWN_PROCESS_FIXTURE, "--success"}),
        command({RWN_PROCESS_FIXTURE, "--success"}),
        command({RWN_PROCESS_FIXTURE, "--success"}));
    rwn::core::DeploymentService healthy_service(
        artifacts, healthy_backend, audit);
    const auto active = healthy_service.deploy(
        {.deployment_id = "deploy-v1",
         .artifact_id = v1.id,
         .principal_id = "human-1",
         .device_id = "windows-1",
         .session_id = "session-1",
         .workspace_id = "game",
         .authorization = deploy_authorization,
         .occurred_at = now});
    RWN_CHECK(active.status == rwn::core::DeploymentStatus::active);
    RWN_CHECK(active.workspace_revision == 21);
    RWN_CHECK(active.evidence.size() == 5);
    RWN_CHECK(active.evidence.front().process.stdout_log.find("fixture-out") !=
              std::string::npos);
    RWN_CHECK(rwn::core::sha256_file(healthy_backend.active_path()) == v1.sha256);

    const auto health_marker = root / "runtime/health-failed-once";
    rwn::core::FileDeploymentBackend failing_backend(
        root / "runtime", "bin/current.bin", executor, filesystem,
        command({RWN_PROCESS_FIXTURE, "--success"}),
        command({RWN_PROCESS_FIXTURE, "--success"}),
        command({RWN_PROCESS_FIXTURE, "--fail-once", health_marker.string()}));
    rwn::core::DeploymentService failing_service(
        artifacts, failing_backend, audit);
    const auto rolled_back = failing_service.deploy(
        {.deployment_id = "deploy-v2",
         .artifact_id = v2.id,
         .principal_id = "human-1",
         .device_id = "windows-1",
         .session_id = "session-1",
         .workspace_id = "game",
         .authorization = deploy_authorization,
         .occurred_at = now + 1s});
    RWN_CHECK(rolled_back.status ==
              rwn::core::DeploymentStatus::rolled_back);
    RWN_CHECK(rolled_back.workspace_revision == 22);
    RWN_CHECK(rolled_back.evidence.size() == 9);
    RWN_CHECK(!rolled_back.evidence.at(4).succeeded);
    RWN_CHECK(rolled_back.evidence.back().succeeded);
    RWN_CHECK(rwn::core::sha256_file(failing_backend.active_path()) == v1.sha256);
    RWN_CHECK(std::filesystem::is_regular_file(
        root / "runtime/failed/deploy-v2.failed"));

    const auto lineage = audit.for_artifact(v2.id);
    RWN_CHECK(lineage.size() == 3);
    RWN_CHECK(lineage.front().action ==
              rwn::core::AuditAction::artifact_published);
    RWN_CHECK(lineage.front().build_id == "build-v2");
    RWN_CHECK(lineage.front().source_revision == 22);
    RWN_CHECK(lineage.front().artifact_sha256 == v2.sha256);
    RWN_CHECK(lineage.back().action ==
              rwn::core::AuditAction::deployment_rolled_back);
    const auto exported = audit.export_json_lines(
        {.deployment_id = "deploy-v2"});
    RWN_CHECK(exported.find("\"build_id\":\"build-v2\"") !=
              std::string::npos);
    RWN_CHECK(exported.find(v2.sha256) != std::string::npos);
    const auto manual = healthy_service.rollback(
        {.deployment_id = "deploy-v1",
         .principal_id = "human-1",
         .device_id = "windows-1",
         .session_id = "session-1",
         .authorization = deploy_authorization,
         .occurred_at = now + 2s});
    RWN_CHECK(manual.status == rwn::core::DeploymentStatus::rolled_back);
    RWN_CHECK(manual.failure_reason == "manual_rollback");
    RWN_CHECK(manual.evidence.size() == 9);
    RWN_CHECK(rwn::core::sha256_file(healthy_backend.active_path()) ==
              rwn::core::sha256_hex("release-v0"));
    const auto v1_lineage = audit.for_artifact(v1.id);
    RWN_CHECK(v1_lineage.size() == 4);
    RWN_CHECK(v1_lineage.back().action ==
              rwn::core::AuditAction::deployment_rolled_back);
    std::ifstream journal(audit_sink.journal_path(), std::ios::binary);
    const std::string journal_text{
        std::istreambuf_iterator<char>(journal),
        std::istreambuf_iterator<char>()};
    RWN_CHECK(std::ranges::count(journal_text, '\n') == 7);
    RWN_CHECK(journal_text.find("deployment.rolled_back") !=
              std::string::npos);
    RWN_CHECK(journal_text.find(v2.sha256) != std::string::npos);
    const auto journal_rows = rwn::core::query_audit_journal(
        audit_sink.journal_path(), {
            .field = "deployment_id", .identifier = "deploy-v2", .limit = 10});
    RWN_CHECK(journal_rows.size() == 2);
    RWN_CHECK(journal_rows.back().find("deployment.rolled_back") !=
              std::string::npos);
    std::filesystem::remove_all(root, ignored);
}

#if defined(RWN_TEST_WINDOWS_PLATFORM)
void release_update_preserves_state_and_records_real_rollback_evidence() {
    using namespace std::chrono_literals;
    const auto make_tree = [](const std::filesystem::path& root) {
        std::filesystem::create_directories(root / "install/bin");
        std::filesystem::create_directories(root / "state/pairing");
        std::filesystem::create_directories(root / "state/workspaces");
        std::filesystem::create_directories(root / "state/audit");
        std::filesystem::create_directories(root / "transactions");
        std::ofstream(root / "install/bin/current.package", std::ios::binary)
            << "installed-v0";
        std::ofstream(root / "state/pairing/device.key", std::ios::binary)
            << "pairing-key-material";
        std::ofstream(root / "state/workspaces/catalog.json", std::ios::binary)
            << "workspace-metadata";
        std::ofstream(root / "state/audit/events.jsonl", std::ios::binary)
            << "audit-chain-entry";
        std::ofstream(root / "candidate.package", std::ios::binary)
            << "installed-v1";
    };
    const auto command = [](std::vector<std::string> argv) {
        return rwn::core::CommandSpec{
            .argv = std::move(argv),
            .working_directory = ".",
            .timeout = 1min,
            .environment = {},
        };
    };
    const auto verified_candidate = [](const std::filesystem::path& package) {
        const auto policy = rwn::core::load_release_compatibility(
            std::filesystem::path(RWN_SOURCE_DIR) /
            "config/version-compatibility.toml");
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
        BoundUpdateSignatureVerifier verifier;
        return rwn::core::verify_update_candidate(
            manifest, rwn::core::parse_semantic_version("0.0.1"), policy,
            "windows", "amd64", package, verifier);
    };

    const auto root = std::filesystem::temp_directory_path() /
                      "rwn-release-update-flow";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    make_tree(root);
    const auto state_before =
        rwn::core::capture_protected_state(root / "state");
    const auto old_package_hash =
        rwn::core::sha256_file(root / "install/bin/current.package");
    const auto candidate = verified_candidate(root / "candidate.package");
    rwn::platform::windows::WindowsDurableFileSystem filesystem;
    rwn::platform::windows::WindowsCommandExecutor executor(root / "install");
    rwn::core::FileReleaseUpdateBackend backend(
        root / "install", "bin/current.package", root / "state",
        root / "transactions", executor, filesystem,
        command({RWN_PROCESS_FIXTURE, "--success"}),
        command({RWN_PROCESS_FIXTURE, "--success"}),
        command({RWN_PROCESS_FIXTURE, "--success"}));
    rwn::core::ReleaseUpdateService service(backend);
    const auto active = service.apply(
        "update-v1", rwn::core::parse_semantic_version("0.0.1"), candidate);
    RWN_CHECK(active.status == rwn::core::ReleaseUpdateStatus::active);
    RWN_CHECK(active.evidence.size() == 8);
    RWN_CHECK(active.evidence.at(2).runtime.stdout_log.find("fixture-out") !=
              std::string::npos);
    RWN_CHECK(active.protected_state_before_sha256 ==
              state_before.inventory_sha256);
    RWN_CHECK(active.protected_state_after_sha256 ==
              state_before.inventory_sha256);
    RWN_CHECK(rwn::core::capture_protected_state(root / "state") ==
              state_before);
    RWN_CHECK(rwn::core::sha256_file(backend.active_path()) ==
              candidate.manifest().package_sha256);

    const auto manual = service.rollback("update-v1");
    RWN_CHECK(manual.status == rwn::core::ReleaseUpdateStatus::rolled_back);
    RWN_CHECK(manual.failure_reason == "manual_rollback");
    RWN_CHECK(manual.evidence.size() == 16);
    RWN_CHECK(rwn::core::sha256_file(backend.active_path()) ==
              old_package_hash);
    RWN_CHECK(rwn::core::capture_protected_state(root / "state") ==
              state_before);

    const auto failing_root = std::filesystem::temp_directory_path() /
                              "rwn-release-update-rollback-flow";
    std::filesystem::remove_all(failing_root, ignored);
    make_tree(failing_root);
    const auto failing_state_before =
        rwn::core::capture_protected_state(failing_root / "state");
    const auto failing_old_hash = rwn::core::sha256_file(
        failing_root / "install/bin/current.package");
    const auto failing_candidate =
        verified_candidate(failing_root / "candidate.package");
    rwn::platform::windows::WindowsCommandExecutor failing_executor(
        failing_root / "install");
    rwn::core::FileReleaseUpdateBackend failing_backend(
        failing_root / "install", "bin/current.package",
        failing_root / "state", failing_root / "transactions",
        failing_executor, filesystem,
        command({RWN_PROCESS_FIXTURE, "--success"}),
        command({RWN_PROCESS_FIXTURE, "--success"}),
        command({RWN_PROCESS_FIXTURE, "--mutate-fail-once",
                 (failing_root / "health-failed-once").string(),
                 (failing_root / "state/pairing/device.key").string()}));
    rwn::core::ReleaseUpdateService failing_service(failing_backend);
    const auto rolled_back = failing_service.apply(
        "update-bad", rwn::core::parse_semantic_version("0.0.1"),
        failing_candidate);
    RWN_CHECK(rolled_back.status ==
              rwn::core::ReleaseUpdateStatus::rolled_back);
    RWN_CHECK(rolled_back.failure_reason == "update_health_check_failed");
    RWN_CHECK(rolled_back.protected_state_before_sha256 ==
              failing_state_before.inventory_sha256);
    RWN_CHECK(rolled_back.protected_state_after_sha256 ==
              failing_state_before.inventory_sha256);
    RWN_CHECK(rwn::core::sha256_file(failing_backend.active_path()) ==
              failing_old_hash);
    RWN_CHECK(rwn::core::capture_protected_state(failing_root / "state") ==
              failing_state_before);
    RWN_CHECK(std::filesystem::is_regular_file(
        failing_root / "install/failed/update-bad.failed"));
    RWN_CHECK(rolled_back.evidence.back().step ==
              rwn::core::ReleaseUpdateStep::rollback_state_verify);
    RWN_CHECK(rolled_back.evidence.back().succeeded);

    std::filesystem::remove_all(root, ignored);
    std::filesystem::remove_all(failing_root, ignored);
}

void release_diagnostics_emit_typed_redacted_immutable_bundle() {
    using namespace std::chrono_literals;
    const auto root = std::filesystem::temp_directory_path() /
                      "rwn-release-diagnostics-flow";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root / "state/pairing");
    std::filesystem::create_directories(root / "state/workspaces");
    std::filesystem::create_directories(root / "state/audit");
    std::filesystem::create_directories(root / "output");
    std::ofstream(root / "state/pairing/device.key", std::ios::binary)
        << "pairing-secret-not-for-diagnostics";

    const auto policy = rwn::core::load_release_compatibility(
        std::filesystem::path(RWN_SOURCE_DIR) /
        "config/version-compatibility.toml");
    const auto state = rwn::core::capture_protected_state(root / "state");
    const rwn::core::BuildEvidence runtime{
        .exit_code = 0,
        .stdout_log = "Authorization: Bearer secret-token clipboard-private",
        .stderr_log = "C:\\Users\\private-user\\secret.txt",
        .elapsed = 17ms,
        .timed_out = false,
        .cancelled = false,
        .stdout_truncated = false,
        .stderr_truncated = false,
    };
    const std::string package_hash(64, 'a');
    const rwn::core::ReleaseUpdateRecord update{
        .id = "update-diagnostic",
        .installed_before = rwn::core::parse_semantic_version("0.0.1"),
        .target_version = rwn::core::parse_semantic_version("0.1.0"),
        .package_sha256 = package_hash,
        .status = rwn::core::ReleaseUpdateStatus::active,
        .protected_state_before_sha256 = state.inventory_sha256,
        .protected_state_after_sha256 = state.inventory_sha256,
        .failure_reason = {},
        .evidence = {{
            .step = rwn::core::ReleaseUpdateStep::health_check,
            .succeeded = true,
            .runtime = runtime,
            .state_inventory_sha256 = {},
            .reason_code = {},
        }},
    };
    const rwn::core::ReleaseDiagnosticBundle bundle{
        .schema_version = 1,
        .bundle_id = "diagnostic-flow-1",
        .product_version = rwn::core::parse_semantic_version("0.1.0"),
        .platform = "windows",
        .architecture = "amd64",
        .generated_at_unix_ms = 1'700'000'000'000ULL,
        .compatibility = rwn::core::summarize_compatibility(policy),
        .protected_state = rwn::core::summarize_protected_state(state),
        .update = rwn::core::summarize_release_update(update),
        .checks = {
            rwn::core::make_runtime_diagnostic(
                rwn::core::DiagnosticComponent::node,
                rwn::core::DiagnosticOperation::self_check, runtime),
            rwn::core::make_boolean_diagnostic(
                rwn::core::DiagnosticComponent::compatibility,
                rwn::core::DiagnosticOperation::compatibility_load, true),
            rwn::core::make_boolean_diagnostic(
                rwn::core::DiagnosticComponent::protected_state,
                rwn::core::DiagnosticOperation::state_inventory, true),
        },
    };
    const auto json = rwn::core::render_release_diagnostic_json(bundle);
    RWN_CHECK(json.find(
                  "\"stdout_bytes\": " +
                  std::to_string(runtime.stdout_log.size())) !=
              std::string::npos);
    RWN_CHECK(json.find("secret-token") == std::string::npos);
    RWN_CHECK(json.find("clipboard-private") == std::string::npos);
    RWN_CHECK(json.find("private-user") == std::string::npos);
    RWN_CHECK(json.find("pairing-secret") == std::string::npos);
    RWN_CHECK(json.find(state.inventory_sha256) != std::string::npos);
    RWN_CHECK(json.find("\"protected_state_preserved\": true") !=
              std::string::npos);

    rwn::platform::windows::WindowsDurableFileSystem filesystem;
    const auto destination = root / "output/diagnostic.json";
    rwn::core::write_release_diagnostic_bundle(
        destination, bundle, filesystem);
    std::ifstream input(destination, std::ios::binary);
    const std::string stored{
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()};
    RWN_CHECK(stored == json);
    rwn::test::require_throws<std::invalid_argument>(
        [&] {
            rwn::core::write_release_diagnostic_bundle(
                destination, bundle, filesystem);
        },
        "immutable diagnostic destination");
    std::filesystem::remove_all(root, ignored);
}
#endif

void agent_runtime_repairs_build_and_binds_every_claim_to_evidence() {
    using namespace std::chrono_literals;
    const auto root = std::filesystem::temp_directory_path() /
                      "rwn-agent-runtime-flow";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root / "src");
    std::filesystem::create_directories(root / "dist");
    std::filesystem::create_directories(root / "artifacts");
    std::ofstream(root / "src/fix.cpp", std::ios::binary) << "broken\n";

    rwn::platform::windows::WindowsCommandExecutor executor(root);
    const auto git_init = executor.execute({
        .argv = {RWN_GIT_EXECUTABLE, "init", "--quiet"},
        .working_directory = ".",
        .timeout = 30s,
        .environment = {},
    });
    RWN_CHECK(git_init.exit_code == 0);
    rwn::platform::windows::WindowsDurableFileSystem filesystem;
    rwn::core::BuildQueue builds;
    rwn::core::AuditLog audit;
    rwn::core::ArtifactStore artifacts(
        builds, root, root / "artifacts", filesystem, audit);
    const rwn::core::CommandSpec success_command{
        .argv = {RWN_PROCESS_FIXTURE, "--success"},
        .working_directory = ".",
        .timeout = 30s,
        .environment = {},
    };
    const rwn::core::CommandSpec failing_command{
        .argv = {RWN_PROCESS_FIXTURE, "--fail"},
        .working_directory = ".",
        .timeout = 30s,
        .environment = {},
    };
    rwn::core::RemoteWorkspaceConfig config{
        .workspace_id = "game",
        .workspace_name = "Game",
        .source = "windows",
        .mirror = "macos",
        .sync_direction = "windows_to_macos",
        .sync_excludes = {},
        .profiles = {
            {"agent-build",
             {.name = "agent-build", .node = "mac-node",
              .command = success_command, .environment_allowlist = {},
              .artifacts = {.paths = {"dist/repair.bin"},
                            .platform = "macos", .architecture = "arm64",
                            .archive_app_bundles = true}}},
            {"agent-test",
             {.name = "agent-test", .node = "mac-node",
              .command = success_command, .environment_allowlist = {},
              .artifacts = {.paths = {}, .platform = "macos",
                            .architecture = "arm64",
                            .archive_app_bundles = true}}},
            {"agent-test-fail",
             {.name = "agent-test-fail", .node = "mac-node",
              .command = failing_command, .environment_allowlist = {},
              .artifacts = {.paths = {}, .platform = "macos",
                            .architecture = "arm64",
                            .archive_app_bundles = true}}},
        },
    };
    rwn::core::AgentRuntime runtime(
        root, config, builds, executor, filesystem, &artifacts, audit,
        RWN_GIT_EXECUTABLE, {"agent-build"},
        {"agent-test", "agent-test-fail"});
    const rwn::core::AuthorizationResult authorization{
        .principal_matched = true,
        .workspace_allowed = true,
        .granted = {
            rwn::core::Capability::agent_run,
            rwn::core::Capability::workspace_read,
            rwn::core::Capability::workspace_write,
            rwn::core::Capability::build_submit,
            rwn::core::Capability::test_run,
            rwn::core::Capability::artifact_read,
            rwn::core::Capability::git_status,
            rwn::core::Capability::git_diff},
        .denied = {},
    };
    const auto now = rwn::core::WallClock::now();
    runtime.create_job({
        .job_id = "repair-macos",
        .principal_id = "coding-agent",
        .device_id = "windows-1",
        .session_id = "session-1",
        .workspace_id = "game",
        .principal_kind = rwn::core::PrincipalKind::agent,
        .source_revision = 42,
        .authorization = authorization,
        .occurred_at = now,
    });
    const auto read = runtime.execute("repair-macos", {
        .tool = rwn::core::AgentTool::workspace_read,
        .relative_path = "src/fix.cpp",
        .expected_sha256 = {},
        .replacement = {},
        .profile = {},
        .operation_id = {},
        .artifact_id = {},
        .maximum_bytes = 1024,
        .occurred_at = now + 1s,
    });
    RWN_CHECK(read.succeeded);
    RWN_CHECK(read.stdout_log == "broken\n");
    RWN_CHECK(runtime.verify_claim(
        read.id, rwn::core::AgentClaim::tool_succeeded));

    rwn::test::require_throws<std::logic_error>(
        [&] {
            static_cast<void>(runtime.execute("repair-macos", {
                .tool = rwn::core::AgentTool::workspace_patch,
                .relative_path = "src/fix.cpp",
                .expected_sha256 = read.after_sha256,
                .replacement = "fixed\n",
                .profile = {},
                .operation_id = {},
                .artifact_id = {},
                .maximum_bytes = 0,
                .occurred_at = now + 2s,
            }));
        },
        "patch review required");
    RWN_CHECK(runtime.job("repair-macos").state ==
              rwn::core::AgentJobState::waiting_review);
    RWN_CHECK(rwn::core::sha256_file(root / "src/fix.cpp") ==
              read.after_sha256);
    runtime.approve_patch("repair-macos", {
        .reviewer_id = "human-1",
        .device_id = "windows-1",
        .session_id = "session-1",
        .reviewer_kind = rwn::core::PrincipalKind::human,
        .authorization = {
            .principal_matched = true,
            .workspace_allowed = true,
            .granted = {rwn::core::Capability::workspace_write},
            .denied = {},
        },
        .occurred_at = now + 3s,
    });
    const auto patch_evidence = runtime.execute("repair-macos", {
        .tool = rwn::core::AgentTool::workspace_patch,
        .relative_path = "src/fix.cpp",
        .expected_sha256 = read.after_sha256,
        .replacement = "fixed\n",
        .profile = {},
        .operation_id = {},
        .artifact_id = {},
        .maximum_bytes = 0,
        .occurred_at = now + 4s,
    });
    RWN_CHECK(runtime.verify_claim(
        patch_evidence.id, rwn::core::AgentClaim::patch_applied));
    RWN_CHECK(rwn::core::sha256_file(root / "src/fix.cpp") ==
              patch_evidence.after_sha256);

    const auto build = runtime.execute("repair-macos", {
        .tool = rwn::core::AgentTool::build_submit,
        .relative_path = {},
        .expected_sha256 = {},
        .replacement = {},
        .profile = "agent-build",
        .operation_id = "agent-build-42",
        .artifact_id = {},
        .maximum_bytes = 0,
        .occurred_at = now + 5s,
    });
    RWN_CHECK(build.succeeded);
    RWN_CHECK(build.exit_code == 0);
    RWN_CHECK(build.stdout_log.find("fixture-out") != std::string::npos);
    RWN_CHECK(runtime.verify_claim(
        build.id, rwn::core::AgentClaim::build_succeeded));

    std::ofstream(root / "dist/repair.bin", std::ios::binary) << "fixed-app";
    const auto artifact = artifacts.publish({
        .id = "agent-artifact-42",
        .build_id = "agent-build-42",
        .source_revision = 42,
        .name = "repair.bin",
        .platform = "macos",
        .architecture = "arm64",
        .source_relative_path = "dist/repair.bin",
        .principal_id = "human-1",
        .device_id = "windows-1",
        .session_id = "session-1",
        .occurred_at = now + 6s,
    });
    const auto inspected = runtime.execute("repair-macos", {
        .tool = rwn::core::AgentTool::artifact_inspect,
        .relative_path = {},
        .expected_sha256 = {},
        .replacement = {},
        .profile = {},
        .operation_id = {},
        .artifact_id = artifact.id,
        .maximum_bytes = 0,
        .occurred_at = now + 7s,
    });
    RWN_CHECK(inspected.artifact_sha256 == artifact.sha256);
    RWN_CHECK(runtime.verify_claim(
        inspected.id, rwn::core::AgentClaim::artifact_verified));
    RWN_CHECK(rwn::core::render_agent_evidence(inspected).find(
                  "artifact_sha256=" + artifact.sha256) != std::string::npos);

    const auto test = runtime.execute("repair-macos", {
        .tool = rwn::core::AgentTool::test_run,
        .relative_path = {},
        .expected_sha256 = {},
        .replacement = {},
        .profile = "agent-test",
        .operation_id = "agent-test-42",
        .artifact_id = {},
        .maximum_bytes = 0,
        .occurred_at = now + 8s,
    });
    RWN_CHECK(runtime.verify_claim(
        test.id, rwn::core::AgentClaim::test_succeeded));
    const auto status = runtime.execute("repair-macos", {
        .tool = rwn::core::AgentTool::git_status,
        .relative_path = {},
        .expected_sha256 = {},
        .replacement = {},
        .profile = {},
        .operation_id = {},
        .artifact_id = {},
        .maximum_bytes = 0,
        .occurred_at = now + 9s,
    });
    RWN_CHECK(status.succeeded);
    runtime.complete_job("repair-macos", now + 10s);
    RWN_CHECK(runtime.job("repair-macos").state ==
              rwn::core::AgentJobState::succeeded);
    RWN_CHECK(runtime.job("repair-macos").evidence_ids.size() == 6);

    const auto exported = audit.export_json_lines({
        .agent_job_id = "repair-macos"});
    RWN_CHECK(exported.find("agent.tool_completed") != std::string::npos);
    RWN_CHECK(exported.find("workspace.patch") != std::string::npos);
    RWN_CHECK(exported.find("fixed-app") == std::string::npos);
    RWN_CHECK(exported.find("fixed\\n") == std::string::npos);

    runtime.create_job({
        .job_id = "failed-tests",
        .principal_id = "coding-agent",
        .device_id = "windows-1",
        .session_id = "session-1",
        .workspace_id = "game",
        .principal_kind = rwn::core::PrincipalKind::agent,
        .source_revision = 42,
        .authorization = authorization,
        .occurred_at = now + 11s,
    });
    const auto failed_test = runtime.execute("failed-tests", {
        .tool = rwn::core::AgentTool::test_run,
        .relative_path = {},
        .expected_sha256 = {},
        .replacement = {},
        .profile = "agent-test-fail",
        .operation_id = "agent-test-failed-42",
        .artifact_id = {},
        .maximum_bytes = 0,
        .occurred_at = now + 12s,
    });
    RWN_CHECK(!failed_test.succeeded);
    RWN_CHECK(failed_test.exit_code == 7);
    RWN_CHECK(failed_test.stdout_log.find("failed-out") != std::string::npos);
    RWN_CHECK(failed_test.stderr_log.find("failed-err") != std::string::npos);
    RWN_CHECK(!runtime.verify_claim(
        failed_test.id, rwn::core::AgentClaim::test_succeeded));
    RWN_CHECK(rwn::core::render_agent_evidence(failed_test).find(
                  "exit_code=7") != std::string::npos);
    runtime.complete_job("failed-tests", now + 13s);
    RWN_CHECK(runtime.job("failed-tests").state ==
              rwn::core::AgentJobState::failed);
    std::filesystem::remove_all(root, ignored);
}
#endif

void build_profiles_create_fixed_revision_pinned_requests() {
    const auto config = rwn::core::load_remote_workspace_config(
        std::filesystem::path(RWN_SOURCE_DIR) / "remote-workspace.toml");
    const auto request = config.make_build_request(
        "build-profile-1", 42, "macos-debug", {{"SDKROOT", "macosx"}});
    RWN_CHECK(request.workspace_id == "example-workspace");
    RWN_CHECK(request.pinned_revision == 42);
    RWN_CHECK(request.profile == "macos-debug");
    RWN_CHECK(request.command.argv.front() == "/opt/homebrew/bin/cmake");
    RWN_CHECK(request.command.environment.at("SDKROOT") == "macosx");

    const auto examples = rwn::core::load_remote_workspace_config(
        std::filesystem::path(RWN_SOURCE_DIR) /
        "config/remote-workspace.example.toml");
    RWN_CHECK(examples.profiles.size() == 5);
    RWN_CHECK(examples.profile("cmake-debug").artifacts.platform == "macos");
    RWN_CHECK(examples.profile("cargo-release").command.argv.at(1) == "build");
    RWN_CHECK(examples.profile("npm-test").command.argv.front().ends_with("npm"));
    RWN_CHECK(examples.profile("xcode-release").command.argv.front() ==
              "/usr/bin/xcodebuild");
    RWN_CHECK(examples.profile("godot-export").artifacts.archive_app_bundles);
}

void build_artifact_discovery_matches_only_bounded_outputs() {
    const auto root = std::filesystem::temp_directory_path() /
        "rwn-artifact-discovery";
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    std::filesystem::create_directories(root / "dist/Product.app/Contents");
    std::ofstream(root / "dist/product.zip", std::ios::binary) << "zip";
    std::ofstream(root / "dist/notes.txt", std::ios::binary) << "notes";
    std::ofstream(root / "dist/Product.app/Contents/info", std::ios::binary)
        << "bundle";
    const rwn::core::BuildProfile profile{
        .name = "release",
        .node = "mac",
        .command = {.argv = {"/usr/bin/true"}, .working_directory = ".",
                    .timeout = std::chrono::seconds{1}, .environment = {}},
        .environment_allowlist = {},
        .artifacts = {.paths = {"dist/*.zip", "dist/Product.app"},
                      .platform = "macos", .architecture = "arm64",
                      .archive_app_bundles = true},
    };
    const auto artifacts = rwn::core::discover_build_artifacts(root, profile);
    RWN_CHECK((artifacts == std::vector<std::filesystem::path>{
        "dist/Product.app", "dist/product.zip"}));
    std::filesystem::remove_all(root, ignored);
}

void terminal_api_opens_resizes_streams_and_closes() {
    using namespace std::chrono_literals;
    RecordingTerminalBackend backend;
    backend.output = {std::byte{'o'}, std::byte{'k'}};
    rwn::core::TerminalSession terminal(
        "terminal-1",
        {.principal_matched = true,
         .workspace_allowed = true,
         .granted = {rwn::core::Capability::terminal_open},
         .denied = {}},
        RWN_SOURCE_DIR, backend);
    terminal.open(
        {.argv = {RWN_PROCESS_FIXTURE, "--success"},
         .working_directory = ".",
         .timeout = 1min,
         .environment = {}},
        {}, {.columns = 120, .rows = 40});
    RWN_CHECK(terminal.state() == rwn::core::TerminalState::open);
    RWN_CHECK(backend.opened);
    terminal.resize({.columns = 132, .rows = 50});
    RWN_CHECK(terminal.size().columns == 132);
    const std::array input{std::byte{'p'}, std::byte{'w'}, std::byte{'d'}};
    RWN_CHECK(terminal.write(input) == input.size());
    const std::vector expected_output{std::byte{'o'}, std::byte{'k'}};
    RWN_CHECK(terminal.read(2) == expected_output);
    terminal.close();
    RWN_CHECK(backend.closed);
    RWN_CHECK(terminal.state() == rwn::core::TerminalState::closed);
}

#if defined(RWN_TEST_WINDOWS_PLATFORM)
void windows_nv12_repack_preserves_padded_chroma_origin() {
    constexpr std::uint32_t width = 4;
    constexpr std::uint32_t height = 4;
    constexpr std::uint32_t stride = 8;
    constexpr std::uint32_t padded_luma_rows = 8;
    std::vector<std::byte> source(
        static_cast<std::size_t>(stride) *
        (padded_luma_rows + height / 2U), std::byte{0xee});
    for (std::uint32_t row = 0; row < height; ++row) {
        for (std::uint32_t column = 0; column < width; ++column) {
            source[static_cast<std::size_t>(row) * stride + column] =
                static_cast<std::byte>(row * 16U + column);
        }
    }
    const auto uv_offset =
        static_cast<std::size_t>(stride) * padded_luma_rows;
    for (std::uint32_t row = 0; row < height / 2U; ++row) {
        for (std::uint32_t column = 0; column < width; ++column) {
            source[uv_offset + static_cast<std::size_t>(row) * stride + column] =
                static_cast<std::byte>(0x80U + row * 16U + column);
        }
    }
    const auto packed = rwn::platform::windows::repack_padded_nv12(
        source, width, height, stride, padded_luma_rows);
    RWN_CHECK(packed.size() == width * height * 3U / 2U);
    RWN_CHECK(packed[0] == std::byte{0});
    RWN_CHECK(packed[15] == std::byte{0x33});
    RWN_CHECK(packed[16] == std::byte{0x80});
    RWN_CHECK(packed[23] == std::byte{0x93});
}

void schannel_fallback_accepts_explicit_paired_identities() {
    const auto client =
        rwn::platform::windows::parse_schannel_sha1_thumbprint(
            "00112233445566778899AABBCCDDEEFF10203040");
    const auto server =
        rwn::platform::windows::parse_schannel_sha256_fingerprint(
            "00112233445566778899aabbccddeeff"
            "102030405060708090a0b0c0d0e0f001");
    RWN_CHECK(client.front() == 0x00U);
    RWN_CHECK(client.back() == 0x40U);
    RWN_CHECK(server.front() == 0x00U);
    RWN_CHECK(server.back() == 0x01U);

    const auto options =
        rwn::platform::windows::SchannelFallbackClientOptions{
            .client_certificate_sha1 = client,
            .allowed_server_certificate_sha256 = {server},
        };
    rwn::platform::windows::validate_schannel_fallback_client_options(
        options);
    auto provider =
        rwn::platform::windows::SchannelFallbackClientProvider(options);
    static_cast<void>(provider);
}
#endif

#if defined(RWN_TEST_MSQUIC_PROVIDER)
void msquic_runtime_loads_versioned_api_from_explicit_package() {
    const auto info = rwn::transport::probe_msquic_runtime(
        std::filesystem::path(RWN_TEST_MSQUIC_DLL));
    RWN_CHECK(info.loaded_library.is_absolute());
    RWN_CHECK(info.loaded_library.filename() == "msquic.dll");
    RWN_CHECK(info.library_version[0] == 2);
    RWN_CHECK(info.library_version[1] == 5);
    RWN_CHECK(info.library_version[2] == 7);

    const auto server_certificate = rwn::transport::parse_sha1_thumbprint(
        "00112233445566778899AABBCCDDEEFF10203040");
    const auto client_fingerprint =
        rwn::transport::parse_sha256_fingerprint(
            "00112233445566778899aabbccddeeff"
            "102030405060708090a0b0c0d0e0f001");
    RWN_CHECK(rwn::transport::client_certificate_allowed(
        std::span{&client_fingerprint, 1}, client_fingerprint));
    rwn::transport::validate_msquic_client_options({
        .runtime_library = std::filesystem::path(RWN_TEST_MSQUIC_DLL),
        .client_certificate_sha1 = server_certificate,
        .allowed_server_certificate_sha256 = {client_fingerprint},
        .connect_timeout = std::chrono::milliseconds{30'000},
        .stream_read_timeout = std::chrono::milliseconds{30'000},
    });
    rwn::transport::validate_msquic_server_options({
        .runtime_library = std::filesystem::path(RWN_TEST_MSQUIC_DLL),
        .server_certificate_sha1 = server_certificate,
        .allowed_client_certificate_sha256 = {client_fingerprint},
        .listen_port = 4433,
        .certificate_in_machine_store = true,
        .stream_read_timeout = std::chrono::milliseconds{30'000},
        .maximum_pending_connections = 64,
    });
}
#endif

void visual_lifecycle_trace_observes_tail_progress_without_scheduling() {
    using rwn::desktop::VisualLifecycleDomain;
    using rwn::desktop::VisualLifecycleStage;
    using rwn::desktop::VisualSckStatus;
    using rwn::desktop::VisualTraceEvent;
    using rwn::desktop::VisualTraceHost;

    rwn::desktop::VisualTraceQueue queue(8);
    rwn::desktop::VisualLifecycleTracker tracker(
        VisualTraceHost::mac, 77, &queue);
    tracker.record(
        VisualLifecycleStage::sck_callback, 100, 1'000,
        VisualTraceEvent{
            .callback_sequence = 1,
            .sck_status = VisualSckStatus::complete,
            .valid_image = true,
            .content_width = 1280,
            .content_height = 720,
            .sck_dirty_rect_count = 2,
            .sck_dirty_union_area = 10'000,
            .sck_dirty_ratio_ppm = 10'850,
        });
    tracker.record(VisualLifecycleStage::latest_publish, 100, 1'010);
    tracker.record(VisualLifecycleStage::vt_submit, 100, 1'020);
    tracker.record(VisualLifecycleStage::vt_output, 100, 1'030);
    tracker.record(
        VisualLifecycleStage::wire_write_complete, 100, 1'040);
    const auto snapshot = tracker.snapshot();
    RWN_CHECK(snapshot.source_generation == 100);
    RWN_CHECK(snapshot.published_generation == 100);
    RWN_CHECK(snapshot.submitted_generation == 100);
    RWN_CHECK(snapshot.encoded_generation == 100);
    RWN_CHECK(snapshot.written_generation == 100);

    const auto first = queue.wait_pop(std::chrono::milliseconds{0});
    RWN_CHECK(first.has_value());
    const auto json = rwn::desktop::render_visual_trace_json(*first);
    RWN_CHECK(rwn::desktop::decode_visual_trace_json(json) == *first);

    auto identity_event = *first;
    identity_event.stage = VisualLifecycleStage::representation_state;
    identity_event.latest_source_frame_id = 445;
    identity_event.latest_content_frame_id = 432;
    identity_event.exact_base_frame_id = 432;
    identity_event.exact_base_content_frame_id = 432;
    const auto identity_json = rwn::desktop::render_visual_trace_json(identity_event);
    RWN_CHECK(rwn::desktop::decode_visual_trace_json(identity_json) == identity_event);
    // Diagnostic metadata must not manufacture forward progress.
    RWN_CHECK(tracker.snapshot() == snapshot);
    for (const auto version : {4U, 5U}) {
        auto legacy = identity_json;
        const auto suffix = legacy.find(version == 5U
            ? ",\"latest_source_frame_id\":" : ",\"input_correlation_id\":");
        RWN_CHECK(suffix != std::string::npos);
        legacy.erase(suffix);
        legacy += '}';
        const auto version_offset = legacy.find("\"schema_version\":6");
        RWN_CHECK(version_offset != std::string::npos);
        legacy.replace(version_offset, std::string("\"schema_version\":6").size(),
                       "\"schema_version\":" + std::to_string(version));
        const auto parsed = rwn::desktop::decode_visual_trace_json(legacy);
        RWN_CHECK(parsed.schema_version == version);
        RWN_CHECK(parsed.latest_source_frame_id == 0);
        RWN_CHECK(parsed.latest_content_frame_id == 0);
        RWN_CHECK(parsed.exact_base_frame_id == 0);
        RWN_CHECK(parsed.exact_base_content_frame_id == 0);
        RWN_CHECK(rwn::desktop::render_visual_trace_json(parsed) == legacy);
        RWN_CHECK(rwn::desktop::decode_visual_trace_json(
                      rwn::desktop::render_visual_trace_json(parsed)) == parsed);
    }

    rwn::desktop::VisualTraceQueue ack_queue(16);
    rwn::desktop::VisualLifecycleTracker ack_tracker(
        VisualTraceHost::windows, 77, &ack_queue);
    const VisualTraceEvent ack_metadata{
        .representation_epoch = 9,
    };
    ack_tracker.record(
        VisualLifecycleStage::framebuffer_commit, 105, 2'000,
        ack_metadata);
    ack_tracker.record(
        VisualLifecycleStage::ack_created, 105, 2'003, ack_metadata);
    ack_tracker.record(
        VisualLifecycleStage::ack_enqueued, 105, 2'005, ack_metadata);
    ack_tracker.record(
        VisualLifecycleStage::ack_write_complete, 105, 2'009,
        ack_metadata);
    for (const auto expected_stage : {
             VisualLifecycleStage::framebuffer_commit,
             VisualLifecycleStage::ack_created,
             VisualLifecycleStage::ack_enqueued,
             VisualLifecycleStage::ack_write_complete}) {
        const auto event = ack_queue.wait_pop(std::chrono::milliseconds{0});
        RWN_CHECK(event.has_value());
        RWN_CHECK(event->stage == expected_stage);
        RWN_CHECK(event->frame_id == 105);
        RWN_CHECK(event->representation_epoch == 9);
        RWN_CHECK(rwn::desktop::decode_visual_trace_json(
                      rwn::desktop::render_visual_trace_json(*event)) ==
                  *event);
    }

    rwn::desktop::VisualTraceQueue ack_receive_queue(16);
    rwn::desktop::VisualLifecycleTracker ack_receive_tracker(
        VisualTraceHost::mac, 77, &ack_receive_queue);
    ack_receive_tracker.record(
        VisualLifecycleStage::frame_commit_write_complete, 105, 3'000,
        ack_metadata);
    ack_receive_tracker.record(
        VisualLifecycleStage::ack_bytes_received, 105, 3'020,
        ack_metadata);
    ack_receive_tracker.record(
        VisualLifecycleStage::ack_parsed, 105, 3'022, ack_metadata);
    ack_receive_tracker.record(
        VisualLifecycleStage::ack_accepted, 105, 3'025, ack_metadata);
    for (const auto expected_stage : {
             VisualLifecycleStage::frame_commit_write_complete,
             VisualLifecycleStage::ack_bytes_received,
             VisualLifecycleStage::ack_parsed,
             VisualLifecycleStage::ack_accepted}) {
        const auto event = ack_receive_queue.wait_pop(
            std::chrono::milliseconds{0});
        RWN_CHECK(event.has_value());
        RWN_CHECK(event->stage == expected_stage);
        RWN_CHECK(event->representation_epoch == 9);
    }

    rwn::desktop::VisualTraceQueue bounded(1);
    RWN_CHECK(bounded.try_push(*first));
    RWN_CHECK(!bounded.try_push(*first));
    RWN_CHECK(bounded.dropped_events() == 1);

    rwn::desktop::VisualLivenessWatchdog watchdog(
        VisualLifecycleDomain::windows);
    rwn::desktop::VisualLifecycleSnapshot windows{
        .received_generation = 105,
    };
    RWN_CHECK(!watchdog.poll(windows, 10'000).has_value());
    const auto stalled = watchdog.poll(windows, 60'000);
    RWN_CHECK(stalled.has_value());
    RWN_CHECK(stalled->stalled);
    RWN_CHECK(stalled->related_stage == VisualLifecycleStage::mf_output);
    RWN_CHECK(stalled->frame_id == 105);
    RWN_CHECK(!watchdog.poll(windows, 110'000).has_value());
    RWN_CHECK(watchdog.hard_timeout_active());
    windows.decoded_generation = 105;
    windows.committed_generation = 105;
    windows.present_submitted_generation = 105;
    const auto recovered = watchdog.poll(windows, 120'000);
    RWN_CHECK(recovered.has_value());
    RWN_CHECK(recovered->recovered);
    RWN_CHECK(recovered->related_stage == VisualLifecycleStage::mf_output);
    RWN_CHECK(recovered->frame_id == 105);
    RWN_CHECK(!watchdog.poll(windows, 130'000).has_value());

    rwn::desktop::VisualTailRefreshBudget refresh(5, 20'000);
    refresh.publish_visual(100, 1'000);
    RWN_CHECK(!refresh.repeat_due(20'999));
    RWN_CHECK(refresh.repeat_due(21'000));
    for (int count = 0; count < 5; ++count) {
        RWN_CHECK(refresh.repeat_due(21'000));
        refresh.repeat_completed(100);
    }
    RWN_CHECK(!refresh.repeat_due(21'000));
    RWN_CHECK(refresh.remaining() == 0);
    refresh.publish_visual(101, 30'000);
    RWN_CHECK(!refresh.repeat_due(49'999));
    RWN_CHECK(refresh.repeat_due(50'000));

    // A failed encoder submission must not consume the tail budget.  This is
    // the deterministic model for VT capacity being temporarily unavailable.
    RWN_CHECK(refresh.remaining() == 5);
    RWN_CHECK(refresh.repeat_due(50'001));
    RWN_CHECK(refresh.remaining() == 5);
    refresh.repeat_completed(101);
    RWN_CHECK(refresh.remaining() == 4);

    // Motion may supersede intermediate visual states, but silence must arm a
    // complete drain budget for the final published generation.
    for (std::uint64_t frame_id = 102; frame_id <= 105; ++frame_id) {
        refresh.publish_visual(frame_id, frame_id * 1'000);
    }
    RWN_CHECK(!refresh.repeat_due(124'999));
    RWN_CHECK(refresh.repeat_due(125'000));
    for (int count = 0; count < 5; ++count) {
        refresh.repeat_completed(105);
    }
    RWN_CHECK(refresh.remaining() == 0);
    RWN_CHECK(!refresh.repeat_due(200'000));

}

void hybrid_visual_protocol_tracks_exact_state_and_epochs() {
    using namespace rwn::desktop;

    const VisualFullSnapshotChunk snapshot{
        .surface_width = 4,
        .surface_height = 2,
        .row_stride = 16,
        .pixel_format = CanonicalPixelFormat::bgra8_premultiplied_srgb,
        .total_bytes = 32,
        .chunk_offset = 3,
        .chunk = std::vector<std::byte>(5, std::byte{0x31}),
    };
    const auto snapshot_wire = encode_visual_full_snapshot_chunk(snapshot);
    RWN_CHECK(decode_visual_full_snapshot_chunk(snapshot_wire) == snapshot);
    RWN_CHECK(snapshot.chunk_offset == 3);
    RWN_CHECK(snapshot.chunk.size() == 5);

    const VisualRawRect rect{
        .base_frame_id = 10,
        .surface_width = 4,
        .surface_height = 2,
        .x = 1,
        .y = 0,
        .width = 2,
        .height = 1,
        .row_stride = 8,
        .pixel_format = CanonicalPixelFormat::bgra8_premultiplied_srgb,
        .bgra = std::vector<std::byte>(8, std::byte{0xa5}),
    };
    RWN_CHECK(decode_visual_raw_rect(encode_visual_raw_rect(rect)) == rect);
    RWN_CHECK(decode_visual_frame_commit(
                  encode_visual_frame_commit({.base_frame_id = 10})) ==
              VisualFrameCommit{.base_frame_id = 10});
    RWN_CHECK(decode_visual_state_reset(encode_visual_state_reset({
                  .reason = VisualStateResetReason::base_mismatch})) ==
              VisualStateReset{.reason = VisualStateResetReason::base_mismatch});

    RWN_CHECK(maximum_raw_rect_protocol_bytes >
              default_raw_rect_selector_bytes);
    RWN_CHECK(default_raw_rect_selector_bytes == 128U * 1024U);
    RWN_CHECK(maximum_snapshot_wire_chunk_bytes <
              maximum_snapshot_total_bytes);

    CanonicalFramebufferState state;
    std::array<std::byte, 32> canonical_digest{};
    canonical_digest.fill(std::byte{0x5a});
    RWN_CHECK(state.enter_representation(VisualRepresentation::video, 1));
    RWN_CHECK(state.commit_video(1, 10));
    RWN_CHECK(state.quality() == FramebufferQuality::lossy);
    RWN_CHECK(!state.take_commit_ack(99, canonical_digest).has_value());

    RWN_CHECK(state.enter_representation(VisualRepresentation::snapshot, 2));
    RWN_CHECK(state.commit_snapshot(2, 10));
    RWN_CHECK(state.quality() == FramebufferQuality::exact);
    const auto snapshot_ack = state.take_commit_ack(99, canonical_digest);
    RWN_CHECK(snapshot_ack.has_value());
    RWN_CHECK(snapshot_ack->representation_epoch == 2);
    RWN_CHECK(snapshot_ack->frame_id == 10);
    RWN_CHECK(snapshot_ack->canonical_sha256 == canonical_digest);
    RWN_CHECK(state.present_submitted_frame_id() == 0);
    RWN_CHECK(decode_frame_commit_ack(
                  encode_frame_commit_ack(*snapshot_ack)) == *snapshot_ack);

    const std::array rectangles{rect};
    const auto rect_digest = advance_canonical_rect_digest(
        canonical_digest, 11, rectangles);
    RWN_CHECK(rect_digest != canonical_digest);
    auto changed_rect = rect;
    changed_rect.bgra.back() ^= std::byte{0x01};
    const std::array changed_rectangles{changed_rect};
    RWN_CHECK(advance_canonical_rect_digest(
        canonical_digest, 11, changed_rectangles) != rect_digest);

    RawRectTransactionGuard rect_guard;
    const VisualMessageHeader rect_header{
        .type = VisualMessageType::raw_rect,
        .session_generation = 99,
        .representation_epoch = 3,
        .visual_sequence = 1,
        .frame_id = 11,
        .captured_at_us = 2'000,
    };
    RWN_CHECK(rect_guard.accept(rect_header, rect));
    auto overlapping = rect;
    overlapping.x = 2;
    overlapping.width = 1;
    overlapping.row_stride = 4;
    overlapping.bgra.resize(4);
    RWN_CHECK(!rect_guard.accept(rect_header, overlapping));
    auto commit_header = rect_header;
    commit_header.type = VisualMessageType::frame_commit;
    RWN_CHECK(rect_guard.ready_to_commit(
        commit_header, {.base_frame_id = 10}));
    RWN_CHECK(rect_guard.rectangle_count() == 1);
    RWN_CHECK(rect_guard.packed_bytes() == rect.bgra.size());

    RWN_CHECK(state.enter_representation(VisualRepresentation::rect, 3));
    RWN_CHECK(!state.begin_rect(2, 10, 11));
    RWN_CHECK(state.begin_rect(3, 10, 11));
    RWN_CHECK(state.commit_rect(3, 10, 11));
    RWN_CHECK(state.committed_frame_id() == 11);
    RWN_CHECK(state.quality() == FramebufferQuality::exact);
    const auto rect_ack = state.take_commit_ack(99, rect_digest);
    RWN_CHECK(rect_ack.has_value());
    RWN_CHECK(rect_ack->frame_id == 11);
    RWN_CHECK(rect_ack->canonical_sha256 == rect_digest);
    state.present_submitted(11);
    RWN_CHECK(state.present_submitted_frame_id() == 11);

    RWN_CHECK(state.enter_representation(VisualRepresentation::video, 4));
    RWN_CHECK(!state.enter_representation(VisualRepresentation::rect, 3));
    RWN_CHECK(!state.commit_rect(3, 11, 12));
    RWN_CHECK(state.commit_video(4, 12));
    RWN_CHECK(state.quality() == FramebufferQuality::lossy);
    rect_guard.cancel();
    RWN_CHECK(!rect_guard.active());
}

void exact_only_visual_mode_has_no_codec_messages() {
    using rwn::desktop::VisualMessageType;
    using rwn::desktop::VisualRuntimeMode;

    for (const auto type : {
             VisualMessageType::full_snapshot,
             VisualMessageType::raw_rect,
             VisualMessageType::frame_commit,
             VisualMessageType::state_reset,
             VisualMessageType::cursor_position,
             VisualMessageType::cursor_shape}) {
        RWN_CHECK(rwn::desktop::visual_message_allowed(
            VisualRuntimeMode::exact_only, type));
    }
    RWN_CHECK(!rwn::desktop::visual_message_allowed(
        VisualRuntimeMode::exact_only,
        VisualMessageType::h264_access_unit));
    RWN_CHECK(!rwn::desktop::visual_message_allowed(
        VisualRuntimeMode::exact_only, VisualMessageType::lz4_rect));
    RWN_CHECK(!rwn::desktop::visual_message_allowed(
        VisualRuntimeMode::exact_only, VisualMessageType::copy_rect));
}

void input_epoch_release_invalidates_only_when_explicit() {
    RecordingInputBackend backend;
    rwn::desktop::InputReceiver receiver(backend);
    const auto authorization = desktop_authorization();
    RWN_CHECK(receiver.accept_input_epoch(1, false));
    RWN_CHECK(receiver.receive(
        {.kind = rwn::desktop::InputKind::raw_key,
         .sequence = 1,
         .occurred_at_us = 100,
         .value_a = 0x04,
         .pressed = true,
         .text = {}},
        true, authorization));
    rwn::test::require_throws<std::invalid_argument>(
        [&] { static_cast<void>(receiver.accept_input_epoch(2, false)); },
        "new input epoch without release");
    RWN_CHECK(receiver.accept_input_epoch(2, true));
    RWN_CHECK(receiver.input_epoch() == 2);
    RWN_CHECK(backend.keys.size() == 2);
    RWN_CHECK(!backend.keys.back().second);
    RWN_CHECK(!receiver.accept_input_epoch(1, false));
}

void full_snapshot_transactions_are_exact_atomic_and_recoverable() {
    using namespace rwn::desktop;
    constexpr std::uint32_t width = 64;
    constexpr std::uint32_t height = 32;
    constexpr std::uint32_t stride = width * 4U;
    std::vector<std::byte> source(
        static_cast<std::size_t>(stride) * height);
    for (std::size_t index = 0; index < source.size(); ++index) {
        source[index] = static_cast<std::byte>(
            (index * 131U + index / stride * 17U) & 0xffU);
    }
    const auto expected_digest = rwn::core::sha256(source);
    const VisualMessageHeader first_header{
        .type = VisualMessageType::full_snapshot,
        .payload_size = 0,
        .session_generation = 77,
        .representation_epoch = 2,
        .visual_sequence = 2,
        .frame_id = 101,
        .captured_at_us = 1'000,
    };
    FullSnapshotAssemblyGuard guard;
    rwn::core::Sha256Accumulator streaming_digest;
    std::vector<std::byte> assembled;
    for (std::size_t offset = 0; offset < source.size(); offset += stride * 5U) {
        const auto size = std::min<std::size_t>(
            stride * 5U, source.size() - offset);
        VisualFullSnapshotChunk chunk{
            .surface_width = width,
            .surface_height = height,
            .row_stride = stride,
            .pixel_format = CanonicalPixelFormat::bgra8_premultiplied_srgb,
            .total_bytes = static_cast<std::uint32_t>(source.size()),
            .chunk_offset = static_cast<std::uint32_t>(offset),
            .chunk = std::vector<std::byte>(
                source.begin() + static_cast<std::ptrdiff_t>(offset),
                source.begin() + static_cast<std::ptrdiff_t>(offset + size)),
        };
        const auto decoded = decode_visual_full_snapshot_chunk(
            encode_visual_full_snapshot_chunk(chunk));
        if (offset == 0) {
            RWN_CHECK(guard.begin(first_header, decoded));
        } else {
            RWN_CHECK(guard.accept(first_header, decoded));
        }
        assembled.insert(
            assembled.end(), decoded.chunk.begin(), decoded.chunk.end());
        streaming_digest.update(decoded.chunk);
    }
    const auto commit_payload = VisualFrameCommit{.base_frame_id = 0};
    auto commit_header = first_header;
    commit_header.type = VisualMessageType::frame_commit;
    commit_header.visual_sequence = 20;
    RWN_CHECK(guard.ready_to_commit(commit_header, commit_payload));
    RWN_CHECK(assembled == source);
    RWN_CHECK(rwn::core::sha256(assembled) == expected_digest);
    RWN_CHECK(streaming_digest.bytes_received() == source.size());
    RWN_CHECK(streaming_digest.finish() == expected_digest);
    rwn::test::require_throws<std::logic_error>(
        [&] { streaming_digest.update(source); },
        "snapshot digest update after finish");
    rwn::test::require_throws<std::logic_error>(
        [&] { static_cast<void>(streaming_digest.finish()); },
        "snapshot digest finish twice");

    auto altered_source = source;
    altered_source.back() ^= std::byte{0x01};
    rwn::core::Sha256Accumulator altered_digest;
    const auto altered_bytes = std::span{altered_source};
    altered_digest.update(altered_bytes.first(altered_source.size() / 2U));
    altered_digest.update(altered_bytes.last(
        altered_source.size() - altered_source.size() / 2U));
    RWN_CHECK(altered_digest.finish() != expected_digest);

    FullSnapshotAssemblyGuard incomplete;
    const auto first = decode_visual_full_snapshot_chunk(
        encode_visual_full_snapshot_chunk({
            .surface_width = width,
            .surface_height = height,
            .row_stride = stride,
            .total_bytes = static_cast<std::uint32_t>(source.size()),
            .chunk_offset = 0,
            .chunk = std::vector<std::byte>(
                source.begin(), source.begin() + stride),
        }));
    RWN_CHECK(incomplete.begin(first_header, first));
    RWN_CHECK(!incomplete.ready_to_commit(commit_header, commit_payload));
    auto wrong_session = first_header;
    wrong_session.session_generation = 78;
    auto second = first;
    second.chunk_offset = stride;
    RWN_CHECK(!incomplete.accept(wrong_session, second));
    second.chunk_offset = 0;
    RWN_CHECK(!incomplete.accept(first_header, second));
    incomplete.cancel();
    RWN_CHECK(!incomplete.active());

    CanonicalFramebufferState state;
    RWN_CHECK(state.enter_representation(VisualRepresentation::video, 1));
    RWN_CHECK(state.commit_video(1, 100));
    RWN_CHECK(state.enter_representation(VisualRepresentation::snapshot, 2));
    RWN_CHECK(state.commit_snapshot(2, 101));
    const auto ack = state.take_commit_ack(77, expected_digest);
    RWN_CHECK(ack.has_value());
    RWN_CHECK(ack->canonical_sha256 == expected_digest);
    RWN_CHECK(frame_commit_ack_matches(
        *ack, 77, 2, 101, expected_digest));
    RWN_CHECK(!frame_commit_ack_matches(
        *ack, 78, 2, 101, expected_digest));
    RWN_CHECK(!frame_commit_ack_matches(
        *ack, 77, 3, 101, expected_digest));
    auto wrong_digest = expected_digest;
    wrong_digest.front() ^= std::byte{0xff};
    RWN_CHECK(!frame_commit_ack_matches(
        *ack, 77, 2, 101, wrong_digest));
    RWN_CHECK(state.enter_representation(VisualRepresentation::video, 3));
    RWN_CHECK(!state.commit_snapshot(2, 102));
    RWN_CHECK(state.commit_video(3, 102));
    RWN_CHECK(state.quality() == FramebufferQuality::lossy);
    RWN_CHECK(state.enter_representation(VisualRepresentation::snapshot, 4));
    RWN_CHECK(state.enter_representation(VisualRepresentation::video, 5));
    RWN_CHECK(state.commit_video(5, 103));
    RWN_CHECK(state.quality() == FramebufferQuality::lossy);
    RWN_CHECK(state.enter_representation(VisualRepresentation::snapshot, 6));
    RWN_CHECK(state.commit_snapshot(6, 104));
    RWN_CHECK(state.quality() == FramebufferQuality::exact);
    RWN_CHECK(!state.enter_representation(VisualRepresentation::video, 5));

    for (std::uint64_t cycle = 0; cycle < 32; ++cycle) {
        const auto video_epoch = 7U + cycle * 2U;
        const auto snapshot_cycle_epoch = video_epoch + 1U;
        const auto video_frame = 200U + cycle * 2U;
        const auto snapshot_frame = video_frame + 1U;
        RWN_CHECK(state.enter_representation(
            VisualRepresentation::video, video_epoch));
        RWN_CHECK(state.commit_video(video_epoch, video_frame));
        RWN_CHECK(state.quality() == FramebufferQuality::lossy);
        RWN_CHECK(!state.commit_snapshot(
            snapshot_cycle_epoch - 1U, snapshot_frame));
        RWN_CHECK(state.enter_representation(
            VisualRepresentation::snapshot, snapshot_cycle_epoch));

        FullSnapshotAssemblyGuard transaction;
        auto cycle_header = first_header;
        cycle_header.representation_epoch = snapshot_cycle_epoch;
        cycle_header.frame_id = snapshot_frame;
        const VisualFullSnapshotChunk whole{
            .surface_width = width,
            .surface_height = height,
            .row_stride = stride,
            .pixel_format =
                CanonicalPixelFormat::bgra8_premultiplied_srgb,
            .total_bytes = static_cast<std::uint32_t>(source.size()),
            .chunk_offset = 0,
            .chunk = source,
        };
        RWN_CHECK(transaction.begin(cycle_header, whole));
        auto cycle_commit_header = cycle_header;
        cycle_commit_header.type = VisualMessageType::frame_commit;
        RWN_CHECK(transaction.ready_to_commit(
            cycle_commit_header, {.base_frame_id = 0}));
        RWN_CHECK(state.commit_snapshot(
            snapshot_cycle_epoch, snapshot_frame));
        const auto cycle_ack = state.take_commit_ack(77, expected_digest);
        RWN_CHECK(cycle_ack.has_value());
        RWN_CHECK(frame_commit_ack_matches(
            *cycle_ack, 77, snapshot_cycle_epoch,
            snapshot_frame, expected_digest));

        transaction.cancel();
        RWN_CHECK(!transaction.ready_to_commit(
            cycle_commit_header, {.base_frame_id = 0}));
        RWN_CHECK(state.quality() == FramebufferQuality::exact);
        RWN_CHECK(!state.commit_snapshot(
            snapshot_cycle_epoch - 1U, snapshot_frame + 1U));
    }
}

void snapshot_wire_drain_is_bounded_and_converges_to_latest() {
    using namespace rwn::desktop;
    constexpr std::uint32_t stride = 1920U * 4U;
    constexpr std::uint32_t total = stride * 1080U;
    SnapshotWireDrainPlan drain;
    RWN_CHECK(drain.begin(100, total, stride));
    std::uint32_t emitted{};
    std::size_t bursts{};
    while (!drain.complete()) {
        const auto ranges = drain.take_burst();
        RWN_CHECK(!ranges.empty());
        std::uint32_t burst_bytes{};
        for (const auto& range : ranges) {
            RWN_CHECK(range.offset == emitted);
            RWN_CHECK(range.size <= maximum_snapshot_wire_chunk_bytes);
            RWN_CHECK(range.size % stride == 0);
            emitted += range.size;
            burst_bytes += range.size;
            RWN_CHECK(range.final == (emitted == total));
        }
        RWN_CHECK(burst_bytes <= 512U * 1024U);
        ++bursts;
        if (bursts == 2) {
            drain.observe_latest_source(101);
            drain.observe_latest_source(103);
            drain.observe_latest_source(103);
            RWN_CHECK(drain.superseded());
        }
    }
    RWN_CHECK(emitted == total);
    RWN_CHECK(bursts > 1);
    RWN_CHECK(drain.source_frame_id() == 100);
    RWN_CHECK(drain.latest_source_frame_id() == 103);
    RWN_CHECK(drain.superseded_sources() == 2);
    RWN_CHECK(drain.take_burst().empty());
    drain.cancel();
    RWN_CHECK(!drain.active());

    RWN_CHECK(!drain.begin(0, total, stride));
    RWN_CHECK(!drain.begin(100, total - 1U, stride));
    RWN_CHECK(!drain.begin(100, total, stride, stride - 1U));
    RWN_CHECK(!drain.begin(
        100, total, stride,
        static_cast<std::uint32_t>(maximum_snapshot_wire_chunk_bytes + 1U)));
}

void visual_evidence_compares_latency_quality_and_exact_residency() {
    using namespace rwn::desktop;
    std::vector<VisualTraceEvent> baseline;
    std::vector<VisualTraceEvent> hybrid;
    for (std::uint64_t frame = 1; frame <= 40; ++frame) {
        const auto mac_time = 1'000U + frame * 20'000U;
        const auto windows_time = 2'000U + frame * 20'000U;
        baseline.push_back({
            .host = VisualTraceHost::mac,
            .session_generation = 1,
            .representation_epoch = 1,
            .event_sequence = frame * 2U,
            .frame_id = frame,
            .stage = VisualLifecycleStage::sck_callback,
            .local_monotonic_us = mac_time,
            .sck_status = VisualSckStatus::complete,
            .valid_image = true,
        });
        baseline.push_back({
            .host = VisualTraceHost::mac,
            .session_generation = 1,
            .representation_epoch = 1,
            .event_sequence = frame * 2U + 1U,
            .frame_id = frame,
            .stage = VisualLifecycleStage::wire_write_complete,
            .local_monotonic_us = mac_time + 8'000U,
        });
        baseline.push_back({
            .host = VisualTraceHost::windows,
            .session_generation = 1,
            .representation_epoch = 1,
            .event_sequence = frame * 2U,
            .frame_id = frame,
            .stage = VisualLifecycleStage::wire_receive,
            .local_monotonic_us = windows_time,
        });
        baseline.push_back({
            .host = VisualTraceHost::windows,
            .session_generation = 1,
            .representation_epoch = 1,
            .event_sequence = frame * 2U + 1U,
            .frame_id = frame,
            .stage = VisualLifecycleStage::present_submitted,
            .local_monotonic_us = windows_time + 1'000U,
        });

        hybrid.push_back({
            .host = VisualTraceHost::mac,
            .session_generation = 2,
            .representation_epoch = 7,
            .event_sequence = frame * 3U,
            .frame_id = frame,
            .stage = VisualLifecycleStage::sck_callback,
            .local_monotonic_us = mac_time,
            .sck_status = VisualSckStatus::complete,
            .valid_image = true,
        });
        hybrid.push_back({
            .host = VisualTraceHost::mac,
            .session_generation = 2,
            .representation_epoch = 7,
            .event_sequence = frame * 3U + 1U,
            .frame_id = frame,
            .stage = VisualLifecycleStage::raw_rect_write_complete,
            .local_monotonic_us = mac_time + 2'000U,
        });
        hybrid.push_back({
            .host = VisualTraceHost::mac,
            .session_generation = 2,
            .representation_epoch = 7,
            .event_sequence = frame * 3U + 2U,
            .frame_id = frame,
            .stage = VisualLifecycleStage::ack_accepted,
            .local_monotonic_us = mac_time + 3'000U,
        });
        hybrid.push_back({
            .host = VisualTraceHost::windows,
            .session_generation = 2,
            .representation_epoch = 7,
            .event_sequence = frame * 3U,
            .frame_id = frame,
            .stage = VisualLifecycleStage::raw_rect_receive,
            .local_monotonic_us = windows_time,
        });
        hybrid.push_back({
            .host = VisualTraceHost::windows,
            .session_generation = 2,
            .representation_epoch = 7,
            .event_sequence = frame * 3U + 1U,
            .frame_id = frame,
            .stage = VisualLifecycleStage::present_submitted,
            .local_monotonic_us = windows_time + 500U,
        });
    }
    hybrid.push_back({
        .host = VisualTraceHost::windows,
        .session_generation = 2,
        .representation_epoch = 7,
        .event_sequence = 500,
        .frame_id = 40,
        .stage = VisualLifecycleStage::gpu_exact_verify,
        .local_monotonic_us = 999'000,
        .stage_duration_us = 900,
        .payload_bytes = 16'384,
    });
    hybrid.push_back({
        .host = VisualTraceHost::windows,
        .session_generation = 2,
        .representation_epoch = 7,
        .event_sequence = 501,
        .frame_id = 40,
        .stage = VisualLifecycleStage::h264_quality_compare,
        .local_monotonic_us = 999'100,
        .payload_bytes = 8'294'400,
        .verification_mismatches = 300,
        .absolute_error_sum = 900,
        .squared_error_sum = 3'300,
    });
    hybrid.push_back({
        .host = VisualTraceHost::mac,
        .session_generation = 2,
        .representation_epoch = 7,
        .event_sequence = 502,
        .frame_id = 40,
        .stage = VisualLifecycleStage::representation_state,
        .local_monotonic_us = 999'200,
        .representation_mode = VisualRepresentationMode::rect_exact,
        .fallback_reason = VisualFallbackReason::dirty_ratio,
        .exact_residency_ratio_ppm = 875'000,
        .representation_switches = 4,
        .rect_superseded_sources = 12,
    });

    const auto comparison = compare_visual_evidence(
        baseline, hybrid, "typing", 30, 200'000);
    RWN_CHECK(comparison.latency_gate_has_enough_samples);
    RWN_CHECK(comparison.latency_gate_passed);
    RWN_CHECK(comparison.correctness_gate_passed);
    RWN_CHECK(comparison.quality_gate_has_evidence);
    RWN_CHECK(comparison.quality_gate_passed);
    RWN_CHECK(comparison.baseline.h264_local_pipeline.p95_us == 9'000U);
    RWN_CHECK(comparison.hybrid.raw_local_pipeline.p95_us == 2'500U);
    RWN_CHECK(comparison.hybrid.raw_ack_round_trip.p95_us == 1'000U);
    RWN_CHECK(comparison.hybrid.exact_residency_ratio_ppm == 875'000U);
    RWN_CHECK(comparison.hybrid.quality_mismatched_bytes == 300U);
    RWN_CHECK(comparison.hybrid.exact_mismatched_bytes == 0U);
    RWN_CHECK(comparison.hybrid.fallbacks.size() == 1U);
    const auto json = render_visual_evidence_json(comparison);
    RWN_CHECK(json.find("\"latency_passed\":true") != std::string::npos);
    RWN_CHECK(json.find("\"dirty_ratio\"") != std::string::npos);
    // Anti-correlated host costs: p95(A)+p95(B)=1800, but p95(A+B)=1000.
    auto anti = baseline;
    for (auto& event : anti) {
        const auto mac_duration = event.frame_id <= 20 ? 100U : 900U;
        const auto win_duration = 1000U - mac_duration;
        const auto time = event.frame_id * 20'000U;
        if (event.host == VisualTraceHost::mac)
            event.local_monotonic_us = time + 1'000U +
                (event.stage == VisualLifecycleStage::wire_write_complete ? mac_duration : 0U);
        else
            event.local_monotonic_us = time + 100'000'000U +
                (event.stage == VisualLifecycleStage::present_submitted ? win_duration : 0U);
    }
    const auto paired = analyze_visual_evidence(anti);
    RWN_CHECK(paired.h264_local_pipeline.count == 40);
    RWN_CHECK(paired.h264_local_pipeline.p95_us == 1000);
    for (auto& event : anti)
        if (event.host == VisualTraceHost::windows) event.session_generation = 999;
    RWN_CHECK(analyze_visual_evidence(anti).h264_local_pipeline.count == 0);
    const auto missing_raw = compare_visual_evidence(baseline, {}, "missing-raw");
    RWN_CHECK(missing_raw.raw_p95_improvement_ppm == 0);
    RWN_CHECK(!missing_raw.latency_gate_has_enough_samples);
    RWN_CHECK(!missing_raw.promotion_gate_passed);
}

}  // namespace

int main() {
    rwn::test::Runner runner;
    runner.run("independent TCP channels bind and revoke together", channel_tests::workflow);
    runner.run("snapshot GPU batch remains row aligned independent of wire chunks", [] {
        constexpr std::size_t budget = 1024U * 1024U;
        for (const std::size_t width : {1920U, 1919U, 1280U, 1U}) {
            const auto stride = width * 4;
            const auto limit = rwn::desktop::snapshot_upload_batch_size(stride, budget);
            rwn::test::require(limit <= budget && limit % stride == 0 && limit > 0,
                               "bounded whole-row batches");
            for (const std::size_t wire : {65536U, 32771U, 7001U}) {
                const auto total = stride * 1080;
                std::size_t pending{}, uploaded{};
                for (std::size_t offset = 0; offset < total;) {
                    const auto chunk = std::min(wire, total - offset);
                    std::size_t consumed{};
                    while (consumed < chunk) {
                        const auto count = std::min(chunk - consumed, limit - pending);
                        consumed += count;
                        pending += count;
                        if (pending == limit || offset + consumed == total) {
                            rwn::test::require(uploaded % stride == 0 && pending % stride == 0,
                                               "every GPU offset and length row aligned");
                            uploaded += pending;
                            pending = 0;
                        }
                    }
                    offset += chunk;
                }
                rwn::test::require(uploaded == total && pending == 0, "all bytes drain exactly");
            }
        }
        rwn::test::require_throws<std::invalid_argument>([] {
            rwn::desktop::snapshot_upload_batch_size(0, budget);
        }, "zero stride rejected");
        rwn::test::require_throws<std::invalid_argument>([] {
            rwn::desktop::snapshot_upload_batch_size(budget + 1, budget);
        }, "oversized row rejected");
    });
    runner.run("pointer click pairs preserve multi-click and reset after drag", [] {
        rwn::desktop::PointerClickTracker clicks;
        const auto edge = [&](bool down, std::uint64_t time) {
            return clicks.button(1, down, 100, 100, time, 500'000);
        };
        rwn::test::require(edge(true, 1000) == 1, "first down");
        rwn::test::require(edge(false, 2000) == 1, "first up");
        rwn::test::require(edge(true, 100000) == 2, "double down");
        rwn::test::require(edge(false, 110000) == 2, "double up");
        rwn::test::require(edge(true, 200000) == 3, "triple down");
        rwn::test::require(edge(false, 210000) == 3, "triple up");
        rwn::test::require(edge(true, 900000) == 1, "timeout resets");
        clicks.move(120, 100);
        clicks.move(100, 100);
        rwn::test::require(edge(false, 910000) == 1, "drag up retains count");
        rwn::test::require(edge(true, 920000) == 1, "drag breaks next click chain");
        rwn::test::require(edge(false, 930000) == 1, "new click up");
        rwn::test::require(clicks.button(2, true, 100, 100, 940000, 500000) == 1, "other button starts single");
        rwn::test::require(clicks.button(2, false, 100, 100, 950000, 500000) == 1, "right up");
        rwn::test::require(edge(true, 960000) == 1, "button switch resets");
        rwn::test::require(edge(false, 970000) == 1, "left up");
        rwn::test::require(edge(true, 500) == 1, "clock regression resets");
        rwn::test::require_throws<std::invalid_argument>([&] {
            clicks.button(0, true, 0, 0, 1, 500000);
        }, "invalid button rejected");
    });
    runner.run("build and artifact wire round-trips evidence", build_and_artifact_control_wire_round_trips_evidence);
    runner.run("workspace control wire round-trips sync transaction", workspace_control_wire_round_trips_sync_transaction);
    runner.run("build stream binds Session revision and evidence", build_stream_binds_session_revision_and_runtime_evidence);
    runner.run("artifact stream resumes and verifies immutable download", artifact_stream_resumes_and_verifies_immutable_download);
    runner.run("deployment stream binds capability revision and evidence", deployment_stream_binds_capability_revision_and_evidence);
    runner.run("workspace mirror transaction applies verified revision", workspace_mirror_transaction_applies_verified_revision);
    runner.run("workspace stream services bind session and commit", workspace_stream_services_bind_session_and_commit);
    runner.run("product runtime configs are strict and complete", product_runtime_configs_are_strict_and_complete);
    runner.run("Node control stream opens policy-scoped session", node_control_stream_opens_policy_scoped_session);
    runner.run("Apple Network contract accepts explicit paired identities", apple_network_contract_accepts_explicit_paired_identities);
    runner.run("envelope preserves unknown fields", envelope_round_trip_preserves_unknown_fields);
    runner.run("protocol and release security gates accept valid corpora", protocol_mutation_and_release_security_gates_pass_valid_corpora);
    runner.run("release compatibility verifies signed package binding", release_compatibility_and_signed_update_bind_real_package);
#if defined(RWN_TEST_WINDOWS_PLATFORM)
    runner.run("Windows NV12 repack preserves padded chroma origin", windows_nv12_repack_preserves_padded_chroma_origin);
    runner.run("Windows Raw Input maps full standard keyboard", windows_raw_keyboard_maps_full_standard_layout);
    runner.run("Windows CNG verifies P-256 update signatures", windows_cng_verifies_rfc6979_p256_signature);
#endif
    runner.run("preview frames scale and header round-trip", preview_frames_scale_and_header_round_trip);
    runner.run("visual lifecycle trace observes tail progress", visual_lifecycle_trace_observes_tail_progress_without_scheduling);
    runner.run("hybrid visual protocol tracks exact state and epochs", hybrid_visual_protocol_tracks_exact_state_and_epochs);
    runner.run("exact-only visual mode excludes codec messages", exact_only_visual_mode_has_no_codec_messages);
    runner.run("media fragments reassemble and stale frames drop", media_frames_fragment_reassemble_and_drop_stale_frames);
    runner.run("audio relay reorders and exposes PLC telemetry", audio_relay_reorders_packets_and_exposes_plc_telemetry);
    runner.run("audio jitter starts at target and rejects duplicates", audio_jitter_buffer_starts_at_target_and_rejects_duplicates);
    runner.run("resilient transport negotiates migration and fallback", resilient_transport_negotiates_migrates_and_falls_back);
    runner.run("encrypted fallback peer-binds TLS and DTLS", encrypted_fallback_binds_tls_and_dtls_to_one_peer);
    runner.run("transport verification reports impairment and correctness", transport_verification_reports_impairment_and_correctness);
    runner.run("desktop transport routes media and ordered control", desktop_transport_routes_media_pointer_input_and_clipboard);
    runner.run("input conformance handles Unicode and stuck keys", input_conformance_handles_unicode_coordinates_and_stuck_keys);
    runner.run("input epoch release invalidates only explicitly", input_epoch_release_invalidates_only_when_explicit);
    runner.run("full snapshot transactions are exact and recoverable", full_snapshot_transactions_are_exact_atomic_and_recoverable);
    runner.run("snapshot wire drain is bounded and converges to latest", snapshot_wire_drain_is_bounded_and_converges_to_latest);
    runner.run("visual evidence compares latency quality and exact residency", visual_evidence_compares_latency_quality_and_exact_residency);
    runner.run("clipboard loops and latency adaptation are deterministic", clipboard_loop_prevention_and_latency_adaptation_are_deterministic);
    runner.run("capabilities are policy intersection", capability_request_is_policy_intersection);
    runner.run("session lifecycle", authenticated_authorized_session_opens_and_closes);
    runner.run("unauthenticated open rejected", unauthenticated_session_cannot_open);
    runner.run("paired certificate opens renewable session", paired_certificate_opens_and_renews_a_session);
    runner.run("pairing state persists and revokes atomically", pairing_state_persists_and_revokes_atomically);
    runner.run("pairing control binds transport identity and persists device", pairing_control_binds_transport_identity_and_persists_device);
    runner.run("session service binds mTLS policy lease and audit", session_service_binds_mtls_policy_lease_and_audit);
    runner.run("mDNS discovery observations expire", discovery_cache_expires_stale_mdns_observations);
    runner.run("strict policy file is loaded", strict_policy_file_is_readable_and_authorizes_by_intersection);
    runner.run("one-way manifest rename and chunk resume", one_way_manifest_diff_handles_rename_and_resume);
    runner.run("SHA-256 manifest is content authoritative", sha256_and_filesystem_manifest_are_content_authoritative);
    runner.run("Git stage supplies executable metadata", git_index_stage_modes_supply_executable_metadata);
    runner.run("transfer encoding skips compressed files", transfer_encoding_skips_already_compressed_content);
    runner.run("watcher events debounce before manifest scan", watcher_events_are_debounced_as_triggers_only);
    runner.run("100k-entry diff reconciles exactly", hundred_thousand_entry_diff_reconciles_exactly);
    runner.run("revision history is contiguous", revision_history_requires_contiguous_verified_manifests);
    runner.run("build profiles pin fixed commands to revisions", build_profiles_create_fixed_revision_pinned_requests);
    runner.run("build artifact discovery matches bounded outputs", build_artifact_discovery_matches_only_bounded_outputs);
    runner.run("terminal API controls open resize stream and close", terminal_api_opens_resizes_streams_and_closes);
#if defined(RWN_TEST_MSQUIC_PROVIDER)
    runner.run("MsQuic runtime loads pinned API", msquic_runtime_loads_versioned_api_from_explicit_package);
#endif
#if defined(RWN_TEST_WINDOWS_PLATFORM)
    runner.run("Schannel fallback accepts explicit paired identities", schannel_fallback_accepts_explicit_paired_identities);
    runner.run("file transfer resumes and atomically replaces", file_transfer_resumes_from_verified_staging_chunks_and_replaces_atomically);
    runner.run("Windows watcher emits real filesystem trigger", windows_directory_watcher_emits_trigger_for_real_change);
    runner.run("pinned build runs and preserves real exit evidence", pinned_build_runs_process_and_reports_actual_exit_evidence);
    runner.run("command executor captures success and timeout", command_executor_captures_success_and_timeout);
    runner.run("command cancellation kills process tree", command_cancel_kills_the_process_tree);
    runner.run("successful build publishes resumable immutable artifact", successful_build_publishes_verified_resumable_immutable_artifact);
    runner.run("deployment activates healthy artifact and rolls back failed health", deployment_activates_healthy_artifact_and_rolls_back_failed_health);
#if defined(RWN_TEST_WINDOWS_PLATFORM)
    runner.run("release update preserves state with runtime-backed rollback", release_update_preserves_state_and_records_real_rollback_evidence);
    runner.run("release diagnostics are typed redacted and immutable", release_diagnostics_emit_typed_redacted_immutable_bundle);
#endif
    runner.run("Agent repairs build with review and runtime evidence", agent_runtime_repairs_build_and_binds_every_claim_to_evidence);
#endif
    return runner.exit_code();
}
