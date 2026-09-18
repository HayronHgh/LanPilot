#include "rwn/core/audit_file.hpp"
#include "rwn/core/policy_file.hpp"
#include "rwn/core/pairing_store.hpp"
#include "rwn/core/product_config.hpp"
#include "rwn/core/build_config.hpp"
#include "rwn/core/workspace_scope.hpp"
#include "rwn/node/build_service.hpp"
#include "rwn/node/artifact_service.hpp"
#include "rwn/node/deployment_service.hpp"
#include "rwn/node/control_service.hpp"
#include "rwn/node/pairing_service.hpp"
#include "rwn/node/workspace_service.hpp"
#include "rwn/protocol/envelope.hpp"
#include "rwn/transport/resilient_transport.hpp"

#if defined(RWN_HAS_NETWORK_FRAMEWORK)
#include "rwn/platform/macos/durable_filesystem.hpp"
#include "rwn/platform/macos/build_worker_ipc.hpp"
#include "rwn/platform/macos/deployment_broker_ipc.hpp"
#include "rwn/platform/macos/network_transport.hpp"
#include "rwn/platform/macos/pairing_code.hpp"
#endif

#if defined(RWN_HAS_WINDOWS_PLATFORM)
#include "rwn/platform/windows/durable_filesystem.hpp"
#include "rwn/platform/windows/pairing_code.hpp"
#endif

#if defined(RWN_HAS_MSQUIC)
#include "rwn/transport/msquic_client.hpp"
#include "rwn/transport/msquic_server.hpp"
#endif

#include <cstddef>
#include <charconv>
#include <filesystem>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {

enum class ServeOperation { session, synchronize, build, artifact, deploy };

#if defined(RWN_HAS_NETWORK_FRAMEWORK)
[[nodiscard]] std::vector<std::byte> parse_hex_bytes(
    const std::string_view value) {
    const auto nibble = [](const char character) -> unsigned int {
        if (character >= '0' && character <= '9') {
            return static_cast<unsigned int>(character - '0');
        }
        if (character >= 'a' && character <= 'f') {
            return static_cast<unsigned int>(character - 'a' + 10);
        }
        if (character >= 'A' && character <= 'F') {
            return static_cast<unsigned int>(character - 'A' + 10);
        }
        throw std::invalid_argument("local identity reference is not hex");
    };
    if (value.empty() || value.size() % 2 != 0 || value.size() > 8192) {
        throw std::invalid_argument("local identity reference is invalid");
    }
    std::vector<std::byte> result(value.size() / 2);
    for (std::size_t index = 0; index < result.size(); ++index) {
        result[index] = static_cast<std::byte>(
            (nibble(value[index * 2]) << 4U) |
            nibble(value[index * 2 + 1]));
    }
    return result;
}
#endif

int self_check() {
    const rwn::protocol::Envelope hello{
        .version = 1,
        .type = rwn::protocol::MessageType::hello,
        .correlation_id = "node-self-check",
        .payload = {std::byte{0x01}},
        .unknown_fields = {},
    };
    const auto decoded = rwn::protocol::decode(rwn::protocol::encode(hello));
    std::cout << "product=rwn-node version=0.1 protocol=" << decoded.version
              << " self_check=passed\n";
    return 0;
}

#if defined(RWN_HAS_NETWORK_FRAMEWORK) || defined(RWN_HAS_MSQUIC)
[[nodiscard]] rwn::core::PairedDevice active_paired_device(
    const rwn::core::NodeRuntimeConfig& config,
    rwn::core::DurableFileSystem& filesystem) {
    auto device = config.paired_device;
    if (!config.pairing_root.empty()) {
        rwn::core::PairingStore store(
            config.pairing_root, config.pairing_state_file, filesystem);
        if (store.exists()) device = store.load();
    }
    if (device.id.empty())
        throw std::runtime_error(
            "no paired device exists; run pair-once first");
    if (device.revoked)
        throw std::runtime_error("paired device is revoked");
    return device;
}
#endif

int audit_query(
    const std::filesystem::path& config_path,
    const std::string_view field,
    const std::string_view identifier,
    const std::string_view limit_text) {
    std::size_t limit{};
    const auto parsed = std::from_chars(
        limit_text.data(), limit_text.data() + limit_text.size(), limit);
    if (parsed.ec != std::errc{} ||
        parsed.ptr != limit_text.data() + limit_text.size()) {
        throw std::invalid_argument("audit query limit is invalid");
    }
    const auto config = rwn::core::load_node_runtime_config(config_path);
    const rwn::core::WorkspaceScope audit_scope(config.audit_root);
    const auto journal = audit_scope.resolve(config.audit_journal);
    const auto rows = rwn::core::query_audit_journal(journal, {
        .field = std::string(field),
        .identifier = std::string(identifier),
        .limit = limit,
    });
    for (const auto& row : rows) std::cout << row << '\n';
    std::cerr << "audit_rows=" << rows.size() << '\n';
    return 0;
}

#if defined(RWN_HAS_NETWORK_FRAMEWORK) || defined(RWN_HAS_MSQUIC)
#if defined(RWN_HAS_NETWORK_FRAMEWORK)
class IpcBuildWorker final : public rwn::node::BuildWorkerBoundary {
public:
    explicit IpcBuildWorker(const rwn::core::NodeRuntimeConfig& config)
        : config_(config) {}
    [[nodiscard]] rwn::core::BuildExecutionResult execute(
        const rwn::core::BuildRequest& request,
        const rwn::core::BuildProfile& profile) override {
        return rwn::platform::macos::execute_build_worker_ipc(
            config_.build_worker_socket, config_.build_worker_uid, request,
            profile.command.timeout + std::chrono::seconds{30});
    }
private:
    const rwn::core::NodeRuntimeConfig& config_;
};

class IpcArtifactSource final : public rwn::node::ArtifactSourceBoundary {
public:
    explicit IpcArtifactSource(const rwn::core::NodeRuntimeConfig& config)
        : config_(config) {}
    [[nodiscard]] rwn::protocol::ArtifactManifestReply prepare(
        const rwn::protocol::ArtifactFetchCommand& command) override {
        if (session_) throw std::logic_error("artifact IPC session is already open");
        session_ = std::make_unique<
            rwn::platform::macos::ArtifactWorkerIpcSession>(
                config_.build_worker_socket, config_.build_worker_uid,
                std::chrono::minutes{30});
        return session_->prepare(command);
    }
    void request_chunks(
        const rwn::protocol::ArtifactResumeCommand& command) override {
        if (!session_) throw std::logic_error("artifact IPC session is not open");
        session_->request_chunks(command);
    }
    [[nodiscard]] rwn::protocol::ArtifactChunkCommand read_chunk() override {
        if (!session_) throw std::logic_error("artifact IPC session is not open");
        return session_->read_chunk();
    }
private:
    const rwn::core::NodeRuntimeConfig& config_;
    std::unique_ptr<rwn::platform::macos::ArtifactWorkerIpcSession> session_;
};

class IpcDeploymentWorker final
    : public rwn::node::DeploymentWorkerBoundary {
public:
    explicit IpcDeploymentWorker(const rwn::core::NodeRuntimeConfig& config)
        : config_(config) {}
    [[nodiscard]] rwn::protocol::DeployStatusReply execute(
        const rwn::protocol::DeploySubmitCommand& command) override {
        return rwn::platform::macos::execute_deployment_broker_ipc(
            config_.deployment_broker_socket,
            config_.deployment_broker_uid, command,
            std::chrono::minutes{30});
    }
private:
    const rwn::core::NodeRuntimeConfig& config_;
};
#endif

void process_connection(
    const rwn::core::NodeRuntimeConfig& config,
    rwn::core::PairedDevice paired_device,
    rwn::core::AuditSink& audit_sink,
    rwn::core::DurableFileSystem& filesystem,
    rwn::transport::AuthenticatedConnection accepted,
    const ServeOperation operation) {
    if (!accepted.transport) {
        throw std::runtime_error("transport accepted an empty connection");
    }
    rwn::node::NodeControlService service(
        rwn::core::load_policy_file(config.policy_file),
        config.maximum_active_sessions, &audit_sink);
    service.pair_device(std::move(paired_device));
    auto control = accepted.transport->accept_stream(config.accept_timeout);
    if (control.purpose != rwn::transport::StreamPurpose::control ||
        !control.stream) {
        throw std::runtime_error("first peer stream must be control");
    }
    const auto opened = service.serve_session_open(
        *control.stream, accepted.peer, rwn::core::WallClock::now());
    if (!opened.reply.accepted) {
        std::cout << "session_processed=1 accepted=0 audit_events="
                  << service.audit().events().size() << '\n';
        return;
    }
    if (operation == ServeOperation::synchronize) {
        const auto now = rwn::core::WallClock::now();
        if (!service.permits_session(
                opened.command.session_id,
                rwn::core::Capability::workspace_sync,
                opened.command.workspace_id, now)) {
            throw std::runtime_error(
                "Session does not grant workspace.sync for this workspace");
        }
        rwn::node::WorkspaceMirrorStateFile state(
            config.audit_root, config.workspace_state_file,
            opened.command.workspace_id, filesystem);
        if (state.state().revision ==
            std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error("workspace revision is exhausted");
        }
        const auto expected_revision = state.state().revision + 1;
        rwn::node::WorkspaceMirrorService mirror(
            config.mirror_root, opened.command.workspace_id,
            state.state().revision, filesystem);
        service.record_workspace_sync(
            opened.command.session_id, opened.command.workspace_id,
            expected_revision,
            rwn::core::AuditAction::workspace_sync_started,
            rwn::core::AuditResult::allowed,
            "workspace_sync_started", now);
        try {
            auto workspace =
                accepted.transport->accept_stream(config.accept_timeout);
            if (workspace.purpose != rwn::transport::StreamPurpose::file ||
                !workspace.stream) {
                throw std::runtime_error(
                    "second peer stream must be workspace file stream");
            }
            rwn::node::serve_workspace_sync(mirror, *workspace.stream);
            if (mirror.current_revision() != expected_revision) {
                service.record_workspace_sync(
                    opened.command.session_id, opened.command.workspace_id,
                    expected_revision,
                    rwn::core::AuditAction::workspace_sync_failed,
                    rwn::core::AuditResult::denied,
                    "workspace_not_committed",
                    rwn::core::WallClock::now());
                std::cout << "workspace_synced=0 current_revision="
                          << mirror.current_revision() << '\n';
                service.close_session(
                    opened.command.session_id,
                    rwn::core::WallClock::now());
                return;
            }
            state.persist(
                mirror.current_revision(),
                mirror.current_manifest_sha256());
            service.record_workspace_sync(
                opened.command.session_id, opened.command.workspace_id,
                mirror.current_revision(),
                rwn::core::AuditAction::workspace_sync_committed,
                rwn::core::AuditResult::allowed,
                "workspace_committed",
                rwn::core::WallClock::now());
            std::cout << "workspace_synced=1 revision="
                      << mirror.current_revision() << " manifest_sha256="
                      << mirror.current_manifest_sha256() << '\n';
        } catch (...) {
            service.record_workspace_sync(
                opened.command.session_id, opened.command.workspace_id,
                expected_revision,
                rwn::core::AuditAction::workspace_sync_failed,
                rwn::core::AuditResult::failed,
                "workspace_sync_failed",
                rwn::core::WallClock::now());
            throw;
        }
    } else if (operation == ServeOperation::build) {
#if defined(RWN_HAS_NETWORK_FRAMEWORK)
        const rwn::core::WorkspaceScope mirror_scope(config.mirror_root);
        if (mirror_scope.contains_resolved(
                std::filesystem::weakly_canonical(
                    config.workspace_config_file)) ||
            mirror_scope.contains_resolved(
                std::filesystem::weakly_canonical(
                    config.build_worker_socket.parent_path()))) {
            throw std::invalid_argument(
                "Node build control paths resolve inside synchronized mirror");
        }
        rwn::node::WorkspaceMirrorStateFile state(
            config.audit_root, config.workspace_state_file,
            opened.command.workspace_id, filesystem);
        if (state.state().revision == 0) {
            throw std::runtime_error(
                "Build requires a committed workspace revision");
        }
        auto build_stream =
            accepted.transport->accept_stream(config.accept_timeout);
        if (build_stream.purpose != rwn::transport::StreamPurpose::build ||
            !build_stream.stream) {
            throw std::runtime_error("second peer stream must be build stream");
        }
        IpcBuildWorker worker(config);
        rwn::node::NodeBuildService builds(
            rwn::core::load_remote_workspace_config(
                config.workspace_config_file),
            state.state().revision, worker);
        const auto result = builds.serve(
            *build_stream.stream, service, rwn::core::WallClock::now());
        std::cout << "build_accepted=" << (result.reply.accepted ? 1 : 0)
                  << " build_id=" << result.reply.build_id
                  << " exit=" << result.reply.exit_code
                  << " evidence_sha256=" << result.reply.evidence_sha256
                  << " reason=" << result.reply.reason_code << '\n';
#else
        throw std::runtime_error(
            "Build service is available only on the macOS Node package");
#endif
    } else if (operation == ServeOperation::artifact) {
#if defined(RWN_HAS_NETWORK_FRAMEWORK)
        rwn::node::WorkspaceMirrorStateFile state(
            config.audit_root, config.workspace_state_file,
            opened.command.workspace_id, filesystem);
        if (state.state().revision == 0) {
            throw std::runtime_error(
                "Artifact download requires a committed workspace revision");
        }
        auto artifact_stream =
            accepted.transport->accept_stream(config.accept_timeout);
        if (artifact_stream.purpose != rwn::transport::StreamPurpose::file ||
            !artifact_stream.stream) {
            throw std::runtime_error("second peer stream must be artifact file stream");
        }
        IpcArtifactSource source(config);
        const auto manifest = rwn::node::serve_artifact_download(
            *artifact_stream.stream, service, state.state().revision,
            source, rwn::core::WallClock::now());
        std::cout << "artifact_accepted=" << (manifest.accepted ? 1 : 0)
                  << " artifact_id=" << manifest.artifact_id
                  << " sha256=" << manifest.sha256
                  << " reason=" << manifest.reason_code << '\n';
#else
        throw std::runtime_error(
            "Artifact service is available only on the macOS Node package");
#endif
    } else if (operation == ServeOperation::deploy) {
#if defined(RWN_HAS_NETWORK_FRAMEWORK)
        rwn::node::WorkspaceMirrorStateFile state(
            config.audit_root, config.workspace_state_file,
            opened.command.workspace_id, filesystem);
        if (state.state().revision == 0)
            throw std::runtime_error(
                "Deployment requires a committed workspace revision");
        auto deploy_stream =
            accepted.transport->accept_stream(config.accept_timeout);
        if (deploy_stream.purpose != rwn::transport::StreamPurpose::command ||
            !deploy_stream.stream) {
            throw std::runtime_error("second peer stream must be deploy command stream");
        }
        IpcDeploymentWorker worker(config);
        const auto reply = rwn::node::serve_deployment(
            *deploy_stream.stream, service, state.state().revision,
            worker, rwn::core::WallClock::now());
        std::cout << "deployment_accepted=" << (reply.accepted ? 1 : 0)
                  << " deployment_id=" << reply.deployment_id
                  << " evidence_sha256=" << reply.evidence_sha256
                  << " reason=" << reply.reason_code << '\n';
#else
        throw std::runtime_error(
            "Deployment is available only on the macOS Node package");
#endif
    }
    service.close_session(
        opened.command.session_id, rwn::core::WallClock::now());
    std::cout << "session_processed=1 audit_events="
              << service.audit().events().size()
              << " accepted=" << (opened.reply.accepted ? 1 : 0) << '\n';
}
#endif

int serve_once(
    const std::filesystem::path& config_path,
    const ServeOperation operation) {
    const auto config = rwn::core::load_node_runtime_config(config_path);
#if !defined(RWN_HAS_NETWORK_FRAMEWORK) && !defined(RWN_HAS_MSQUIC)
    static_cast<void>(operation);
    throw std::runtime_error(
        "this build has no product transport provider; use a platform package");
#endif
    const auto transport_settings =
        rwn::transport::load_transport_settings(config.transport_settings_file);

#if defined(RWN_HAS_NETWORK_FRAMEWORK)
    if (config.transport_provider !=
        rwn::core::ProductTransportProvider::network_framework) {
        throw std::invalid_argument(
            "this macOS binary requires transport_provider=network-framework");
    }
    rwn::platform::macos::MacDurableFileSystem filesystem;
    const auto paired_device = active_paired_device(config, filesystem);
    rwn::core::DurableAuditFileSink audit_sink(
        config.audit_root, config.audit_journal, filesystem);
    rwn::platform::macos::NetworkFrameworkServerListener listener({
        .identity = {
            .keychain_persistent_reference =
                parse_hex_bytes(config.local_identity_hex),
            .allowed_peer_certificate_sha256 = {
                rwn::transport::parse_apple_network_sha256_fingerprint(
                    paired_device.fingerprint)},
        },
        .listen_port = config.listen_port,
        .maximum_pending_connections = config.maximum_active_sessions,
    }, transport_settings);
    std::cout << "product=rwn-node provider=network-framework state=listening "
              << "port=" << listener.listen_port() << '\n' << std::flush;
    process_connection(
        config, paired_device, audit_sink, filesystem,
        listener.accept(config.accept_timeout), operation);
#elif defined(RWN_HAS_MSQUIC)
    if (config.transport_provider !=
        rwn::core::ProductTransportProvider::msquic) {
        throw std::invalid_argument(
            "this Windows binary requires transport_provider=msquic");
    }
    rwn::platform::windows::WindowsDurableFileSystem filesystem;
    const auto paired_device = active_paired_device(config, filesystem);
    rwn::core::DurableAuditFileSink audit_sink(
        config.audit_root, config.audit_journal, filesystem);
    rwn::transport::MsQuicServerListener listener({
        .runtime_library = config.runtime_library,
        .server_certificate_sha1 =
            rwn::transport::parse_sha1_thumbprint(config.local_identity_hex),
        .allowed_client_certificate_sha256 = {
            rwn::transport::parse_sha256_fingerprint(
                paired_device.fingerprint)},
        .listen_port = config.listen_port,
        .maximum_pending_connections = config.maximum_active_sessions,
    }, transport_settings);
    std::cout << "product=rwn-node provider=msquic state=listening port="
              << listener.listen_port() << '\n' << std::flush;
    process_connection(
        config, paired_device, audit_sink, filesystem,
        listener.accept(config.accept_timeout), operation);
#else
    static_cast<void>(transport_settings);
#endif
    return 0;
}

#if defined(RWN_HAS_NETWORK_FRAMEWORK) || defined(RWN_HAS_MSQUIC)
[[nodiscard]] std::string secure_pairing_code() {
#if defined(RWN_HAS_NETWORK_FRAMEWORK)
    return rwn::platform::macos::generate_pairing_code();
#elif defined(RWN_HAS_WINDOWS_PLATFORM)
    return rwn::platform::windows::generate_pairing_code();
#endif
}

int pair_once(
    const std::filesystem::path& config_path,
    const std::string_view expected_device_id,
    const std::string_view client_certificate_sha256,
    const std::string_view node_certificate_sha256) {
    using namespace std::chrono_literals;
    const auto config = rwn::core::load_node_runtime_config(config_path);
    if (config.pairing_root.empty() ||
        !rwn::core::is_canonical_fingerprint(client_certificate_sha256) ||
        !rwn::core::is_canonical_fingerprint(node_certificate_sha256)) {
        throw std::invalid_argument("pairing Runtime or fingerprints are invalid");
    }
    if (rwn::core::load_policy_file(config.policy_file).principal_id !=
        expected_device_id) {
        throw std::invalid_argument(
            "pairing device ID does not match the access policy principal");
    }
    const auto code = secure_pairing_code();
    rwn::protocol::validate_pairing_confirm_command({
        .six_digit_code = code,
        .device_id = std::string(expected_device_id),
        .display_name = "Pairing Candidate",
        .certificate_sha256 = std::string(client_certificate_sha256),
    });
    const auto settings = rwn::transport::load_transport_settings(
        config.transport_settings_file);
    const auto started_at = rwn::core::WallClock::now();
#if defined(RWN_HAS_NETWORK_FRAMEWORK)
    if (config.transport_provider !=
        rwn::core::ProductTransportProvider::network_framework) {
        throw std::invalid_argument(
            "this macOS binary requires transport_provider=network-framework");
    }
    rwn::platform::macos::MacDurableFileSystem filesystem;
#elif defined(RWN_HAS_MSQUIC)
    if (config.transport_provider !=
        rwn::core::ProductTransportProvider::msquic) {
        throw std::invalid_argument(
            "this Windows binary requires transport_provider=msquic");
    }
    rwn::platform::windows::WindowsDurableFileSystem filesystem;
#endif
    rwn::core::PairingStore store(
        config.pairing_root, config.pairing_state_file, filesystem);
    if (store.exists()) {
        const auto current = store.load();
        if (!current.revoked || current.id != expected_device_id) {
            throw std::invalid_argument(
                "an active or different paired device already exists");
        }
    }
    rwn::core::DurableAuditFileSink audit_sink(
        config.audit_root, config.audit_journal, filesystem);
    rwn::core::AuditLog audit({}, &audit_sink);
    audit.append({
        .occurred_at = started_at,
        .principal_id = std::string(expected_device_id),
        .device_id = std::string(expected_device_id),
        .reason_code = "pairing_started",
        .action = rwn::core::AuditAction::pairing_started,
        .result = rwn::core::AuditResult::allowed,
    });
    rwn::node::NodePairingService pairing({
        .id = "interactive-1",
        .node = {
            .node_id = "mac-node",
            .node_name = "Remote Workspace Node",
            .lan_endpoint = "configured-listener",
            .fingerprint = std::string(node_certificate_sha256),
        },
        .six_digit_code = code,
        .expires_at = started_at + 5min,
    }, std::string(expected_device_id), store, 24h * 365);
    std::cout << "product=rwn-node state=pairing code=" << code
              << " client_certificate_sha256=" << client_certificate_sha256
              << " node_certificate_sha256=" << node_certificate_sha256
              << " port=" << config.listen_port << '\n' << std::flush;
#if defined(RWN_HAS_NETWORK_FRAMEWORK)
    rwn::platform::macos::NetworkFrameworkServerListener listener({
        .identity = {
            .keychain_persistent_reference =
                parse_hex_bytes(config.local_identity_hex),
            .allowed_peer_certificate_sha256 = {
                rwn::transport::parse_apple_network_sha256_fingerprint(
                    client_certificate_sha256)},
        },
        .listen_port = config.listen_port,
        .maximum_pending_connections = 1,
    }, settings);
    auto accepted = listener.accept(config.accept_timeout);
#elif defined(RWN_HAS_MSQUIC)
    rwn::transport::MsQuicServerListener listener({
        .runtime_library = config.runtime_library,
        .server_certificate_sha1 =
            rwn::transport::parse_sha1_thumbprint(config.local_identity_hex),
        .allowed_client_certificate_sha256 = {
            rwn::transport::parse_sha256_fingerprint(
                client_certificate_sha256)},
        .listen_port = config.listen_port,
        .maximum_pending_connections = 1,
    }, settings);
    auto accepted = listener.accept(config.accept_timeout);
#endif
    if (!accepted.transport)
        throw std::runtime_error("pairing accepted an empty connection");
    auto control = accepted.transport->accept_stream(config.accept_timeout);
    if (control.purpose != rwn::transport::StreamPurpose::control ||
        !control.stream) {
        throw std::runtime_error("pairing requires a control stream");
    }
    const auto served = pairing.serve_confirmation(
        *control.stream, accepted.peer, rwn::core::WallClock::now());
    audit.append({
        .occurred_at = rwn::core::WallClock::now(),
        .principal_id = std::string(expected_device_id),
        .device_id = std::string(expected_device_id),
        .reason_code = served.reply.reason_code,
        .action = rwn::core::AuditAction::pairing_confirmed,
        .result = served.reply.accepted
            ? rwn::core::AuditResult::allowed
            : rwn::core::AuditResult::denied,
    });
    std::cout << "pairing_accepted=" << (served.reply.accepted ? 1 : 0)
              << " device_id=" << served.reply.device_id
              << " reason=" << served.reply.reason_code << '\n';
    return served.reply.accepted ? 0 : 3;
}
#endif

int revoke_pairing(
    const std::filesystem::path& config_path,
    const std::string_view device_id) {
    const auto config = rwn::core::load_node_runtime_config(config_path);
    if (config.pairing_root.empty())
        throw std::invalid_argument("pairing state is not configured");
#if defined(RWN_HAS_NETWORK_FRAMEWORK)
    rwn::platform::macos::MacDurableFileSystem filesystem;
#elif defined(RWN_HAS_WINDOWS_PLATFORM)
    rwn::platform::windows::WindowsDurableFileSystem filesystem;
#else
    static_cast<void>(device_id);
    throw std::runtime_error("pairing revoke requires a platform package");
#endif
#if defined(RWN_HAS_NETWORK_FRAMEWORK) || defined(RWN_HAS_WINDOWS_PLATFORM)
    rwn::core::PairingStore store(
        config.pairing_root, config.pairing_state_file, filesystem);
    if (!store.exists()) {
        if (config.paired_device.id.empty())
            throw std::invalid_argument("no paired device exists to revoke");
        store.create(config.paired_device);
    }
    const auto revoked = store.revoke(device_id);
    rwn::core::DurableAuditFileSink audit_sink(
        config.audit_root, config.audit_journal, filesystem);
    rwn::core::AuditLog audit({}, &audit_sink);
    audit.append({
        .occurred_at = rwn::core::WallClock::now(),
        .principal_id = revoked.id,
        .device_id = revoked.id,
        .reason_code = "device_revoked",
        .action = rwn::core::AuditAction::device_revoked,
        .result = rwn::core::AuditResult::allowed,
    });
    std::cout << "device_revoked=1 device_id=" << revoked.id << '\n';
    return 0;
#endif
}

void usage() {
    std::cerr << "usage:\n"
                 "  rwn-node self-check\n"
                 "  rwn-node pair-once <absolute-node-runtime.toml> "
                     "<device-id> <client-certificate-sha256> "
                     "<node-certificate-sha256>\n"
                 "  rwn-node pairing-revoke <absolute-node-runtime.toml> "
                     "<device-id>\n"
                 "  rwn-node audit-query <absolute-node-runtime.toml> "
                     "<session_id|workspace_id|build_id|artifact_id|deployment_id> "
                     "<identifier> <limit>\n"
                 "  rwn-node serve-once <absolute-node-runtime.toml>\n"
                 "  rwn-node serve-sync-once <absolute-node-runtime.toml>\n"
                 "  rwn-node serve-build-once <absolute-node-runtime.toml>\n"
                 "  rwn-node serve-artifact-once <absolute-node-runtime.toml>\n"
                 "  rwn-node serve-deploy-once <absolute-node-runtime.toml>\n";
}

}  // namespace

int main(const int argc, char** argv) {
    try {
        if (argc == 2 && std::string_view(argv[1]) == "self-check") {
            return self_check();
        }
        if (argc == 6 && std::string_view(argv[1]) == "pair-once") {
#if defined(RWN_HAS_NETWORK_FRAMEWORK) || defined(RWN_HAS_MSQUIC)
            return pair_once(
                std::filesystem::path(argv[2]), argv[3], argv[4], argv[5]);
#else
            throw std::runtime_error(
                "pairing requires a product transport provider");
#endif
        }
        if (argc == 4 && std::string_view(argv[1]) == "pairing-revoke") {
            return revoke_pairing(std::filesystem::path(argv[2]), argv[3]);
        }
        if (argc == 6 && std::string_view(argv[1]) == "audit-query") {
            return audit_query(
                std::filesystem::path(argv[2]), argv[3], argv[4], argv[5]);
        }
        if (argc == 3 && std::string_view(argv[1]) == "serve-once") {
            return serve_once(
                std::filesystem::path(argv[2]), ServeOperation::session);
        }
        if (argc == 3 && std::string_view(argv[1]) == "serve-sync-once") {
            return serve_once(
                std::filesystem::path(argv[2]), ServeOperation::synchronize);
        }
        if (argc == 3 && std::string_view(argv[1]) == "serve-build-once") {
            return serve_once(
                std::filesystem::path(argv[2]), ServeOperation::build);
        }
        if (argc == 3 && std::string_view(argv[1]) == "serve-artifact-once") {
            return serve_once(
                std::filesystem::path(argv[2]), ServeOperation::artifact);
        }
        if (argc == 3 && std::string_view(argv[1]) == "serve-deploy-once") {
            return serve_once(
                std::filesystem::path(argv[2]), ServeOperation::deploy);
        }
        usage();
        return 64;
    } catch (const std::exception& error) {
        std::cerr << "rwn-node: " << error.what() << '\n';
        return 1;
    }
}
