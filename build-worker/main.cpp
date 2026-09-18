#include "rwn/core/build.hpp"
#include "rwn/core/build_config.hpp"
#include "rwn/core/artifact_store.hpp"
#include "rwn/core/content_hash.hpp"
#include "rwn/core/process_isolation.hpp"
#include "rwn/core/product_config.hpp"
#include "rwn/protocol/build_control.hpp"
#include "rwn/protocol/envelope.hpp"
#include "rwn/core/workspace_scope.hpp"
#include "rwn/node/workspace_service.hpp"

#if defined(__APPLE__)
#include "rwn/platform/macos/command_executor.hpp"
#include "rwn/platform/macos/app_packager.hpp"
#include "rwn/platform/macos/process_identity.hpp"
#include "rwn/platform/macos/durable_filesystem.hpp"
#endif

#include <charconv>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <vector>
#include <stdexcept>
#include <string_view>
#include <utility>

#if defined(__APPLE__)
#include <arpa/inet.h>
#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace {

#if defined(__APPLE__)
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

int run_build(const int argc, char** argv) {
    if (argc != 7 || std::string_view(argv[1]) != "build") {
        std::cerr << "usage: rwn-build-worker build <workspace-root> <config> "
                     "<profile> <revision> <build-id>\n";
        return 64;
    }
    rwn::platform::macos::require_process_identity(
        rwn::core::ProcessRole::build_worker);
    const auto config = rwn::core::load_remote_workspace_config(argv[3]);
    auto request = config.make_build_request(
        argv[6], revision(argv[5]), argv[4]);
    rwn::core::BuildQueue queue;
    queue.submit(
        std::move(request), config.profile(argv[4]).environment_allowlist);
    rwn::platform::macos::CommandExecutor executor{
        std::filesystem::path(argv[2])};
    rwn::core::BuildRunner runner(queue, executor);
    const auto evidence = runner.run(argv[6]);
    std::cout << evidence.stdout_log;
    std::cerr << evidence.stderr_log;
    std::cerr << "\n[rwn] exit=" << evidence.exit_code
              << " elapsed_ms=" << evidence.elapsed.count()
              << " timeout=" << evidence.timed_out
              << " cancelled=" << evidence.cancelled << '\n';
    return queue.state(argv[6]) == rwn::core::BuildState::succeeded ? 0 : 1;
}

void bound_logs(rwn::core::BuildEvidence& evidence) {
    if (evidence.stdout_log.size() > rwn::protocol::max_build_log_bytes) {
        evidence.stdout_log.resize(rwn::protocol::max_build_log_bytes);
        evidence.stdout_truncated = true;
    }
    if (evidence.stderr_log.size() > rwn::protocol::max_build_log_bytes) {
        evidence.stderr_log.resize(rwn::protocol::max_build_log_bytes);
        evidence.stderr_truncated = true;
    }
}

int execute_build(const int argc, char** argv) {
    if (argc != 8 || std::string_view(argv[1]) != "execute") {
        std::cerr << "usage: rwn-build-worker execute <workspace-root> <config> "
                     "<profile> <revision> <build-id> <evidence-root>\n";
        return 64;
    }
    rwn::platform::macos::require_process_identity(
        rwn::core::ProcessRole::build_worker);
    const auto config = rwn::core::load_remote_workspace_config(argv[3]);
    auto request = config.make_build_request(
        argv[6], revision(argv[5]), argv[4]);
    rwn::core::BuildQueue queue;
    queue.submit(request, config.profile(argv[4]).environment_allowlist);
    rwn::platform::macos::CommandExecutor executor{
        std::filesystem::path(argv[2])};
    rwn::core::BuildRunner runner(queue, executor);
    auto evidence = runner.run(argv[6]);
    bound_logs(evidence);
    const auto succeeded = queue.state(argv[6]) ==
        rwn::core::BuildState::succeeded;
    const auto cancelled = queue.state(argv[6]) ==
        rwn::core::BuildState::cancelled;
    const auto payload = rwn::protocol::encode_build_status_reply({
        .accepted = true,
        .build_id = request.id,
        .state = succeeded ? rwn::protocol::BuildWireState::succeeded
                           : (cancelled
                               ? rwn::protocol::BuildWireState::cancelled
                               : rwn::protocol::BuildWireState::failed),
        .exit_code = evidence.exit_code,
        .elapsed_ms = static_cast<std::uint64_t>(evidence.elapsed.count()),
        .timed_out = evidence.timed_out,
        .cancelled = evidence.cancelled,
        .stdout_truncated = evidence.stdout_truncated,
        .stderr_truncated = evidence.stderr_truncated,
        .stdout_log = evidence.stdout_log,
        .stderr_log = evidence.stderr_log,
        .evidence_sha256 = rwn::core::build_evidence_sha256(request, evidence),
        .artifact_ids = {},
        .reason_code = succeeded ? "build_succeeded"
            : (cancelled ? "build_cancelled"
                         : (evidence.timed_out ? "build_timed_out"
                                               : "build_failed")),
    });
    const auto evidence_root = std::filesystem::path(argv[7]);
    if (!evidence_root.is_absolute() ||
        !std::filesystem::is_directory(evidence_root)) {
        throw std::invalid_argument(
            "Build Worker evidence root must be an existing absolute directory");
    }
    const rwn::core::WorkspaceScope evidence_scope(evidence_root);
    const auto destination = evidence_scope.resolve(request.id + ".evidence");
    const auto staging = evidence_scope.resolve(request.id + ".evidence.partial");
    if (std::filesystem::exists(destination) ||
        std::filesystem::exists(staging)) {
        throw std::invalid_argument("Build Worker evidence id already exists");
    }
    {
        std::ofstream output(staging, std::ios::binary | std::ios::trunc);
        if (!output) throw std::runtime_error("Build evidence staging failed");
        output.write(
            reinterpret_cast<const char*>(payload.data()),
            static_cast<std::streamsize>(payload.size()));
        output.flush();
        if (!output) throw std::runtime_error("Build evidence write failed");
    }
    rwn::platform::macos::MacDurableFileSystem filesystem;
    filesystem.flush_file(staging);
    filesystem.atomic_replace(staging, destination);
    std::cout << "build_id=" << request.id
              << " evidence_file=" << destination.string() << '\n';
    return 0;
}

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
    ~SocketPath() {
        if (bound_) static_cast<void>(::unlink(path_.c_str()));
    }
    void bound() noexcept { bound_ = true; }
private:
    std::filesystem::path path_;
    bool bound_{};
};

void transfer_all(
    const int socket, std::byte* data, const std::size_t size,
    const bool sending) {
    std::size_t offset{};
    while (offset < size) {
        const auto count = sending
            ? ::send(socket, data + offset, size - offset, 0)
            : ::recv(socket, data + offset, size - offset, 0);
        if (count <= 0) throw std::runtime_error(
            sending ? "Build Worker IPC send failed"
                    : "Build Worker IPC receive failed");
        offset += static_cast<std::size_t>(count);
    }
}

[[nodiscard]] std::vector<std::byte> receive_frame(const int socket) {
    std::uint32_t wire_size{};
    transfer_all(socket, reinterpret_cast<std::byte*>(&wire_size),
                 sizeof(wire_size), false);
    const auto size = ntohl(wire_size);
    if (size == 0 || size > rwn::protocol::max_payload_size + 4096U)
        throw std::length_error("Build Worker IPC request exceeds limit");
    std::vector<std::byte> result(size);
    transfer_all(socket, result.data(), result.size(), false);
    return result;
}

void send_frame(const int socket, const std::span<const std::byte> payload) {
    if (payload.empty() || payload.size() > rwn::protocol::max_payload_size + 4096U)
        throw std::length_error("Build Worker IPC response exceeds limit");
    auto size = htonl(static_cast<std::uint32_t>(payload.size()));
    transfer_all(socket, reinterpret_cast<std::byte*>(&size), sizeof(size), true);
    transfer_all(socket, const_cast<std::byte*>(payload.data()), payload.size(), true);
}

[[nodiscard]] rwn::protocol::BuildStatusReply execute_request(
    const rwn::core::BuildWorkerRuntimeConfig& runtime,
    const rwn::protocol::BuildSubmitCommand& command) {
    const auto config = rwn::core::load_remote_workspace_config(
        runtime.workspace_config_file);
    if (command.workspace_id != config.workspace_id)
        throw std::invalid_argument("Build Worker workspace is denied");
    rwn::platform::macos::MacDurableFileSystem filesystem;
    const rwn::node::WorkspaceMirrorStateFile state(
        runtime.state_root, runtime.workspace_state_file,
        config.workspace_id, filesystem);
    if (command.revision != state.state().revision)
        throw std::invalid_argument("Build Worker revision is not current");
    auto request = config.make_build_request(
        command.build_id, command.revision, command.profile);
    rwn::core::BuildQueue queue;
    queue.submit(request, config.profile(command.profile).environment_allowlist);
    rwn::platform::macos::CommandExecutor executor(runtime.workspace_root);
    rwn::core::BuildRunner runner(queue, executor);
    auto evidence = runner.run(command.build_id);
    bound_logs(evidence);
    const auto succeeded = queue.state(command.build_id) ==
        rwn::core::BuildState::succeeded;
    const auto cancelled = queue.state(command.build_id) ==
        rwn::core::BuildState::cancelled;
    std::vector<std::string> artifact_ids;
    if (succeeded) {
        rwn::core::AuditLog publication_audit;
        rwn::core::ArtifactStore artifacts(
            queue, runtime.workspace_root, runtime.artifact_root,
            filesystem, publication_audit);
        const auto& profile = config.profile(command.profile);
        const auto discovered = rwn::core::discover_build_artifacts(
            runtime.workspace_root, profile,
            rwn::protocol::max_build_artifact_ids);
        rwn::platform::macos::AppPackager packager(
            runtime.workspace_root, executor);
        for (std::size_t index = 0; index < discovered.size(); ++index) {
            auto source = discovered[index];
            auto name = source.filename().string();
            if (std::filesystem::is_directory(
                    rwn::core::WorkspaceScope(runtime.workspace_root)
                        .resolve(source))) {
                if (!profile.artifacts.archive_app_bundles ||
                    source.extension() != ".app") {
                    throw std::invalid_argument(
                        "Build artifact directory is not packageable");
                }
                const auto archive = std::filesystem::path(".rwn-artifacts") /
                    (command.build_id + "-" + std::to_string(index + 1) + ".zip");
                const auto package_evidence = packager.package(source, archive);
                if (package_evidence.exit_code != 0 ||
                    package_evidence.timed_out || package_evidence.cancelled) {
                    throw std::runtime_error("macOS app artifact packaging failed");
                }
                source = archive;
                name += ".zip";
            }
            const auto artifact_id = "artifact-" + rwn::core::sha256_hex(
                command.build_id + ":" + std::to_string(index)).substr(0, 32);
            const auto metadata = artifacts.publish({
                .id = artifact_id,
                .build_id = command.build_id,
                .source_revision = command.revision,
                .name = name,
                .platform = profile.artifacts.platform,
                .architecture = profile.artifacts.architecture,
                .source_relative_path = source,
                .principal_id = "node-local",
                .device_id = "node-local",
                .session_id = command.session_id,
                .occurred_at = rwn::core::WallClock::now(),
            });
            artifact_ids.push_back(metadata.id);
        }
    }
    rwn::protocol::BuildStatusReply reply{
        .accepted = true,
        .build_id = request.id,
        .state = succeeded ? rwn::protocol::BuildWireState::succeeded
                           : (cancelled
                               ? rwn::protocol::BuildWireState::cancelled
                               : rwn::protocol::BuildWireState::failed),
        .exit_code = evidence.exit_code,
        .elapsed_ms = static_cast<std::uint64_t>(evidence.elapsed.count()),
        .timed_out = evidence.timed_out,
        .cancelled = evidence.cancelled,
        .stdout_truncated = evidence.stdout_truncated,
        .stderr_truncated = evidence.stderr_truncated,
        .stdout_log = evidence.stdout_log,
        .stderr_log = evidence.stderr_log,
        .evidence_sha256 = rwn::core::build_evidence_sha256(request, evidence),
        .artifact_ids = std::move(artifact_ids),
        .reason_code = succeeded ? "build_succeeded"
            : (cancelled ? "build_cancelled"
                         : (evidence.timed_out ? "build_timed_out"
                                               : "build_failed")),
    };
    const rwn::core::WorkspaceScope evidence_scope(runtime.evidence_root);
    const auto destination = evidence_scope.resolve(request.id + ".evidence");
    const auto staging = evidence_scope.resolve(request.id + ".evidence.partial");
    if (std::filesystem::exists(destination) || std::filesystem::exists(staging))
        throw std::invalid_argument("Build Worker evidence id already exists");
    const auto payload = rwn::protocol::encode_build_status_reply(reply);
    {
        std::ofstream output(staging, std::ios::binary | std::ios::trunc);
        if (!output) throw std::runtime_error("Build evidence staging failed");
        output.write(reinterpret_cast<const char*>(payload.data()),
                     static_cast<std::streamsize>(payload.size()));
        output.flush();
        if (!output) throw std::runtime_error("Build evidence write failed");
    }
    filesystem.flush_file(staging);
    filesystem.atomic_replace(staging, destination);
    return reply;
}

void serve_artifact_request(
    const int socket,
    const rwn::core::BuildWorkerRuntimeConfig& runtime,
    const rwn::protocol::Envelope& envelope) {
    const auto command = rwn::protocol::decode_artifact_fetch_command(
        envelope.payload);
    const auto config = rwn::core::load_remote_workspace_config(
        runtime.workspace_config_file);
    if (command.workspace_id != config.workspace_id)
        throw std::invalid_argument("Build Worker artifact workspace is denied");
    rwn::platform::macos::MacDurableFileSystem filesystem;
    const rwn::node::WorkspaceMirrorStateFile state(
        runtime.state_root, runtime.workspace_state_file,
        config.workspace_id, filesystem);
    if (command.revision != state.state().revision)
        throw std::invalid_argument("Build Worker artifact revision is not current");
    rwn::core::BuildQueue builds;
    rwn::core::AuditLog audit;
    rwn::core::ArtifactStore artifacts(
        builds, runtime.workspace_root, runtime.artifact_root,
        filesystem, audit);
    const auto& metadata = artifacts.metadata(command.artifact_id);
    if (metadata.workspace_id != command.workspace_id ||
        metadata.source_revision != command.revision ||
        !artifacts.verify(command.artifact_id)) {
        throw std::invalid_argument("Build Worker artifact binding is invalid");
    }
    const auto plan = artifacts.download_plan(
        command.artifact_id, command.transfer_id, metadata.name,
        rwn::protocol::max_artifact_chunk_bytes);
    rwn::protocol::ArtifactManifestReply manifest{
        .accepted = true,
        .artifact_id = metadata.id,
        .transfer_id = command.transfer_id,
        .build_id = metadata.build_id,
        .source_revision = metadata.source_revision,
        .name = metadata.name,
        .sha256 = metadata.sha256,
        .size = metadata.size,
        .platform = metadata.platform,
        .architecture = metadata.architecture,
        .chunks = {},
        .reason_code = "artifact_ready",
    };
    manifest.chunks.reserve(plan.chunks.size());
    for (const auto& chunk : plan.chunks) {
        manifest.chunks.push_back({
            .index = static_cast<std::uint32_t>(chunk.index),
            .offset = chunk.offset,
            .size = static_cast<std::uint32_t>(chunk.size),
            .sha256 = chunk.sha256,
        });
    }
    rwn::protocol::validate_artifact_manifest_reply(manifest);
    send_frame(socket, rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::artifact_manifest,
        .correlation_id = envelope.correlation_id,
        .payload = rwn::protocol::encode_artifact_manifest_reply(manifest),
        .unknown_fields = {},
    }));
    const auto resume_envelope = rwn::protocol::decode(receive_frame(socket));
    if (resume_envelope.version != 1 ||
        resume_envelope.type != rwn::protocol::MessageType::artifact_resume ||
        resume_envelope.correlation_id != "resume-" + command.transfer_id ||
        !resume_envelope.unknown_fields.empty()) {
        throw std::invalid_argument("Build Worker artifact resume envelope is invalid");
    }
    const auto resume = rwn::protocol::decode_artifact_resume_command(
        resume_envelope.payload);
    if (resume.session_id != command.session_id ||
        resume.workspace_id != command.workspace_id ||
        resume.revision != command.revision ||
        resume.artifact_id != command.artifact_id ||
        resume.transfer_id != command.transfer_id) {
        throw std::invalid_argument("Build Worker artifact resume is not bound");
    }
    std::ifstream input(artifacts.object_path(command.artifact_id),
                        std::ios::binary);
    if (!input) throw std::runtime_error("Build Worker artifact open failed");
    for (const auto index : resume.missing_chunks) {
        if (index >= plan.chunks.size())
            throw std::invalid_argument("Build Worker artifact chunk is invalid");
        const auto& descriptor = plan.chunks[index];
        input.clear();
        input.seekg(static_cast<std::streamoff>(descriptor.offset));
        std::vector<std::byte> bytes(descriptor.size);
        input.read(reinterpret_cast<char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
        if (input.gcount() != static_cast<std::streamsize>(bytes.size()) ||
            rwn::core::sha256_hex(bytes) != descriptor.sha256) {
            throw std::runtime_error("Build Worker artifact chunk verification failed");
        }
        send_frame(socket, rwn::protocol::encode({
            .version = 1,
            .type = rwn::protocol::MessageType::artifact_chunk,
            .correlation_id = "chunk-" + command.transfer_id + "-" +
                std::to_string(index),
            .payload = rwn::protocol::encode_artifact_chunk_command({
                .session_id = command.session_id,
                .workspace_id = command.workspace_id,
                .revision = command.revision,
                .artifact_id = command.artifact_id,
                .transfer_id = command.transfer_id,
                .index = index,
                .bytes = std::move(bytes),
            }),
            .unknown_fields = {},
        }));
    }
}

int serve_once(const int argc, char** argv) {
    if (argc != 3 || std::string_view(argv[1]) != "serve-once") {
        std::cerr << "usage: rwn-build-worker serve-once "
                     "<absolute-worker-runtime.toml>\n";
        return 64;
    }
    rwn::platform::macos::require_process_identity(
        rwn::core::ProcessRole::build_worker);
    const auto runtime = rwn::core::load_build_worker_runtime_config(argv[2]);
    if (!std::filesystem::is_directory(runtime.socket_path.parent_path()) ||
        !std::filesystem::is_directory(runtime.evidence_root) ||
        !std::filesystem::is_directory(runtime.artifact_root) ||
        std::filesystem::exists(runtime.socket_path)) {
        throw std::invalid_argument(
            "Build Worker runtime directories or socket state are invalid");
    }
    const rwn::core::WorkspaceScope workspace_scope(runtime.workspace_root);
    for (const auto& protected_path : {
             runtime.workspace_config_file, runtime.state_root,
             runtime.evidence_root, runtime.artifact_root,
             runtime.socket_path.parent_path()}) {
        if (workspace_scope.contains_resolved(
                std::filesystem::weakly_canonical(protected_path))) {
            throw std::invalid_argument(
                "Build Worker protected path resolves inside workspace");
        }
    }
    const auto native = runtime.socket_path.string();
    sockaddr_un address{};
    if (native.size() >= sizeof(address.sun_path))
        throw std::length_error("Build Worker socket path is too long");
    Socket listener(::socket(AF_UNIX, SOCK_STREAM, 0));
    if (listener.get() < 0) throw std::runtime_error("Build Worker socket failed");
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, native.c_str(), native.size() + 1);
    SocketPath cleanup(runtime.socket_path);
    if (::bind(listener.get(), reinterpret_cast<sockaddr*>(&address),
               sizeof(address)) != 0) {
        throw std::runtime_error("Build Worker socket bind failed");
    }
    cleanup.bound();
    if (::chmod(runtime.socket_path.c_str(), 0660) != 0 ||
        ::listen(listener.get(), 1) != 0) {
        throw std::runtime_error("Build Worker socket listen failed");
    }
    std::cout << "product=rwn-build-worker state=listening socket="
              << runtime.socket_path.string() << '\n' << std::flush;
    pollfd ready{.fd = listener.get(), .events = POLLIN, .revents = 0};
    if (::poll(&ready, 1,
               static_cast<int>(runtime.accept_timeout.count() * 1000)) <= 0 ||
        (ready.revents & POLLIN) == 0) {
        throw std::runtime_error("Build Worker accept timed out");
    }
    Socket client(::accept(listener.get(), nullptr, nullptr));
    if (client.get() < 0) throw std::runtime_error("Build Worker accept failed");
    int no_sigpipe = 1;
    if (::setsockopt(client.get(), SOL_SOCKET, SO_NOSIGPIPE,
                     &no_sigpipe, sizeof(no_sigpipe)) != 0) {
        throw std::runtime_error("Build Worker socket signal guard failed");
    }
    uid_t peer_uid{}; gid_t peer_gid{};
    if (::getpeereid(client.get(), &peer_uid, &peer_gid) != 0 ||
        peer_uid != runtime.allowed_node_uid) {
        throw std::runtime_error("Build Worker caller identity is denied");
    }
    const auto envelope = rwn::protocol::decode(receive_frame(client.get()));
    if (envelope.version != 1 ||
        (envelope.type != rwn::protocol::MessageType::build_submit &&
         envelope.type != rwn::protocol::MessageType::artifact_manifest) ||
        envelope.correlation_id.empty() || !envelope.unknown_fields.empty()) {
        throw std::invalid_argument("Build Worker request envelope is invalid");
    }
    if (envelope.type == rwn::protocol::MessageType::artifact_manifest) {
        serve_artifact_request(client.get(), runtime, envelope);
        return 0;
    }
    const auto reply = execute_request(
        runtime, rwn::protocol::decode_build_submit_command(envelope.payload));
    send_frame(client.get(), rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::build_status,
        .correlation_id = envelope.correlation_id,
        .payload = rwn::protocol::encode_build_status_reply(reply),
        .unknown_fields = {},
    }));
    return 0;
}
#endif

}  // namespace

int main(const int argc, char** argv) {
    try {
#if defined(__APPLE__)
        if (argc > 1 && std::string_view(argv[1]) == "serve-once") {
            return serve_once(argc, argv);
        }
        if (argc > 1 && std::string_view(argv[1]) == "execute") {
            return execute_build(argc, argv);
        }
        return run_build(argc, argv);
#else
        static_cast<void>(argc);
        static_cast<void>(argv);
        const auto policy = rwn::core::default_process_policy(
            rwn::core::ProcessRole::build_worker);
        std::cout << "Remote Workspace build worker boundary ready; capabilities="
                  << policy.allowed_capabilities.size()
                  << "; execution=macOS-only\n";
        return 0;
#endif
    } catch (const std::exception& error) {
        std::cerr << "rwn-build-worker: " << error.what() << '\n';
        return 1;
    }
}
