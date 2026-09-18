#include "rwn/core/artifact_store.hpp"
#include "rwn/core/content_hash.hpp"
#include "rwn/core/deployment.hpp"
#include "rwn/core/process_isolation.hpp"
#include "rwn/core/product_config.hpp"
#include "rwn/protocol/build_control.hpp"
#include "rwn/protocol/envelope.hpp"

#if defined(__APPLE__)
#include "rwn/platform/macos/command_executor.hpp"
#include "rwn/platform/macos/durable_filesystem.hpp"
#include "rwn/platform/macos/process_identity.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace {

#if defined(__APPLE__)
class Socket final {
public:
    explicit Socket(const int value = -1) : value_(value) {}
    ~Socket() { if (value_ >= 0) static_cast<void>(::close(value_)); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    [[nodiscard]] int get() const noexcept { return value_; }
private:
    int value_{};
};

class SocketPath final {
public:
    explicit SocketPath(std::filesystem::path path) : path_(std::move(path)) {}
    ~SocketPath() { if (bound_) static_cast<void>(::unlink(path_.c_str())); }
    void bound() noexcept { bound_ = true; }
private:
    std::filesystem::path path_;
    bool bound_{};
};

void transfer_all(const int socket, std::byte* data, const std::size_t size,
                  const bool sending) {
    std::size_t offset{};
    while (offset < size) {
        const auto count = sending
            ? ::send(socket, data + offset, size - offset, 0)
            : ::recv(socket, data + offset, size - offset, 0);
        if (count <= 0) throw std::runtime_error(
            sending ? "Deployment Broker IPC send failed"
                    : "Deployment Broker IPC receive failed");
        offset += static_cast<std::size_t>(count);
    }
}

[[nodiscard]] std::vector<std::byte> receive_frame(const int socket) {
    std::uint32_t wire_size{};
    transfer_all(socket, reinterpret_cast<std::byte*>(&wire_size),
                 sizeof(wire_size), false);
    const auto size = ntohl(wire_size);
    if (size == 0 || size > rwn::protocol::max_payload_size + 4096U)
        throw std::length_error("Deployment Broker IPC frame exceeds limit");
    std::vector<std::byte> result(size);
    transfer_all(socket, result.data(), result.size(), false);
    return result;
}

void send_frame(const int socket, const std::span<const std::byte> payload) {
    if (payload.empty() || payload.size() > rwn::protocol::max_payload_size + 4096U)
        throw std::length_error("Deployment Broker IPC frame exceeds limit");
    auto size = htonl(static_cast<std::uint32_t>(payload.size()));
    transfer_all(socket, reinterpret_cast<std::byte*>(&size), sizeof(size), true);
    transfer_all(socket, const_cast<std::byte*>(payload.data()), payload.size(), true);
}

[[nodiscard]] rwn::core::CommandSpec fixed_command(
    const std::vector<std::string>& argv,
    const std::chrono::seconds timeout) {
    return {.argv = argv, .working_directory = ".", .timeout = timeout,
            .environment = {}};
}

[[nodiscard]] rwn::protocol::DeploymentWireStatus wire_status(
    const rwn::core::DeploymentStatus status) {
    switch (status) {
        case rwn::core::DeploymentStatus::active:
            return rwn::protocol::DeploymentWireStatus::active;
        case rwn::core::DeploymentStatus::rolled_back:
            return rwn::protocol::DeploymentWireStatus::rolled_back;
        case rwn::core::DeploymentStatus::failed:
        case rwn::core::DeploymentStatus::deploying:
            return rwn::protocol::DeploymentWireStatus::failed;
    }
    throw std::logic_error("unknown deployment status");
}

[[nodiscard]] rwn::protocol::DeployStatusReply execute_deployment(
    const rwn::core::BrokerRuntimeConfig& runtime,
    const rwn::protocol::DeploySubmitCommand& command) {
    rwn::platform::macos::MacDurableFileSystem filesystem;
    rwn::core::BuildQueue builds;
    rwn::core::AuditLog artifact_audit;
    rwn::core::ArtifactStore artifacts(
        builds, runtime.artifact_root, runtime.artifact_root,
        filesystem, artifact_audit);
    const auto& artifact = artifacts.metadata(command.artifact_id);
    if (artifact.workspace_id != command.workspace_id ||
        artifact.source_revision != command.revision ||
        !artifacts.verify(command.artifact_id)) {
        throw std::invalid_argument("Deployment Broker artifact binding is invalid");
    }
    rwn::platform::macos::CommandExecutor executor(runtime.runtime_root);
    rwn::core::FileDeploymentBackend backend(
        runtime.runtime_root, runtime.active_relative_path, executor, filesystem,
        fixed_command(runtime.stop_command, runtime.command_timeout),
        fixed_command(runtime.start_command, runtime.command_timeout),
        fixed_command(runtime.health_command, runtime.command_timeout));
    rwn::core::AuditLog deployment_audit;
    rwn::core::DeploymentService service(artifacts, backend, deployment_audit);
    const auto record = service.deploy({
        .deployment_id = command.deployment_id,
        .artifact_id = command.artifact_id,
        .principal_id = "node-local", .device_id = "node-local",
        .session_id = command.session_id,
        .workspace_id = command.workspace_id,
        .authorization = {
            .granted = {rwn::core::Capability::deploy_execute}, .denied = {}},
        .occurred_at = rwn::core::WallClock::now(),
    });
    rwn::protocol::DeployStatusReply reply{
        .accepted = true, .deployment_id = record.id,
        .artifact_id = record.artifact_id,
        .artifact_sha256 = record.artifact_sha256,
        .build_id = record.build_id,
        .source_revision = record.workspace_revision,
        .status = wire_status(record.status), .steps = {},
        .evidence_sha256 = {},
        .reason_code = record.status == rwn::core::DeploymentStatus::active
            ? "deployment_active"
            : (record.status == rwn::core::DeploymentStatus::rolled_back
                ? "deployment_rolled_back" : "deployment_failed"),
    };
    reply.steps.reserve(record.evidence.size());
    for (const auto& evidence : record.evidence) {
        reply.steps.push_back({
            .step = static_cast<std::uint8_t>(evidence.step),
            .succeeded = evidence.succeeded,
            .exit_code = evidence.process.exit_code,
            .elapsed_ms = static_cast<std::uint64_t>(evidence.process.elapsed.count()),
            .timed_out = evidence.process.timed_out,
            .cancelled = evidence.process.cancelled,
            .reason_code = evidence.reason_code.empty()
                ? "step_succeeded" : evidence.reason_code,
        });
    }
    reply.evidence_sha256 = rwn::core::sha256_hex(
        rwn::protocol::encode_deploy_evidence_binding(reply));
    rwn::protocol::validate_deploy_status_reply(reply);
    return reply;
}

int serve_once(const std::filesystem::path& config_path) {
    rwn::platform::macos::require_process_identity(
        rwn::core::ProcessRole::privileged_broker);
    const auto runtime = rwn::core::load_broker_runtime_config(config_path);
    if (!std::filesystem::is_directory(runtime.artifact_root) ||
        !std::filesystem::is_directory(runtime.runtime_root) ||
        !std::filesystem::is_directory(runtime.socket_path.parent_path()) ||
        std::filesystem::exists(runtime.socket_path)) {
        throw std::invalid_argument("Deployment Broker runtime paths are invalid");
    }
    const auto native = runtime.socket_path.string();
    sockaddr_un address{};
    if (native.size() >= sizeof(address.sun_path))
        throw std::length_error("Deployment Broker socket path is too long");
    Socket listener(::socket(AF_UNIX, SOCK_STREAM, 0));
    if (listener.get() < 0) throw std::runtime_error("Broker socket failed");
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, native.c_str(), native.size() + 1);
    SocketPath cleanup(runtime.socket_path);
    if (::bind(listener.get(), reinterpret_cast<sockaddr*>(&address),
               sizeof(address)) != 0) {
        throw std::runtime_error("Deployment Broker socket bind failed");
    }
    cleanup.bound();
    if (::chmod(runtime.socket_path.c_str(), 0660) != 0 ||
        ::listen(listener.get(), 1) != 0) {
        throw std::runtime_error("Deployment Broker socket listen failed");
    }
    std::cout << "product=rwn-broker state=listening socket="
              << runtime.socket_path.string() << '\n' << std::flush;
    pollfd ready{.fd = listener.get(), .events = POLLIN, .revents = 0};
    if (::poll(&ready, 1,
               static_cast<int>(runtime.accept_timeout.count() * 1000)) <= 0 ||
        (ready.revents & POLLIN) == 0) {
        throw std::runtime_error("Deployment Broker accept timed out");
    }
    Socket client(::accept(listener.get(), nullptr, nullptr));
    if (client.get() < 0) throw std::runtime_error("Broker accept failed");
    int no_sigpipe = 1;
    if (::setsockopt(client.get(), SOL_SOCKET, SO_NOSIGPIPE,
                     &no_sigpipe, sizeof(no_sigpipe)) != 0) {
        throw std::runtime_error("Broker socket signal guard failed");
    }
    uid_t peer_uid{};
    gid_t peer_gid{};
    if (::getpeereid(client.get(), &peer_uid, &peer_gid) != 0 ||
        peer_uid != runtime.allowed_node_uid) {
        throw std::runtime_error("Deployment Broker caller identity is denied");
    }
    const auto envelope = rwn::protocol::decode(receive_frame(client.get()));
    if (envelope.version != 1 ||
        envelope.type != rwn::protocol::MessageType::deploy_submit ||
        envelope.correlation_id.empty() || !envelope.unknown_fields.empty()) {
        throw std::invalid_argument("Deployment Broker request is invalid");
    }
    const auto reply = execute_deployment(
        runtime, rwn::protocol::decode_deploy_submit_command(envelope.payload));
    send_frame(client.get(), rwn::protocol::encode({
        .version = 1, .type = rwn::protocol::MessageType::deploy_status,
        .correlation_id = envelope.correlation_id,
        .payload = rwn::protocol::encode_deploy_status_reply(reply),
        .unknown_fields = {},
    }));
    return reply.status == rwn::protocol::DeploymentWireStatus::active ? 0 : 5;
}
#endif

void usage() {
    std::cerr << "usage:\n"
                 "  rwn-broker self-check\n"
                 "  rwn-broker serve-once <absolute-broker-runtime.toml>\n";
}
}  // namespace

int main(const int argc, char** argv) {
    try {
        if (argc == 2 && std::string_view(argv[1]) == "self-check") {
#if defined(__APPLE__)
            rwn::platform::macos::require_process_identity(
                rwn::core::ProcessRole::privileged_broker);
#endif
            const auto policy = rwn::core::default_process_policy(
                rwn::core::ProcessRole::privileged_broker);
            std::cout << "product=rwn-broker self_check=passed capabilities="
                      << policy.allowed_capabilities.size() << '\n';
            return 0;
        }
        if (argc == 3 && std::string_view(argv[1]) == "serve-once") {
#if defined(__APPLE__)
            return serve_once(std::filesystem::path(argv[2]));
#else
            throw std::runtime_error(
                "Deployment Broker is available only in the macOS package");
#endif
        }
        usage();
        return 64;
    } catch (const std::exception& error) {
        std::cerr << "rwn-broker: " << error.what() << '\n';
        return 1;
    }
}
