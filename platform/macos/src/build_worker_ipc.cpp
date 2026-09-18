#include "rwn/platform/macos/build_worker_ipc.hpp"

#include "rwn/protocol/build_control.hpp"
#include "rwn/protocol/envelope.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace rwn::platform::macos {
namespace {

class Socket final {
public:
    explicit Socket(const int value) : value_(value) {}
    ~Socket() { if (value_ >= 0) static_cast<void>(::close(value_)); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    [[nodiscard]] int get() const noexcept { return value_; }
private:
    int value_{};
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

void send_frame(const int socket, const std::span<const std::byte> payload) {
    if (payload.empty() || payload.size() > rwn::protocol::max_payload_size + 4096U)
        throw std::length_error("Build Worker IPC frame size is invalid");
    auto size = htonl(static_cast<std::uint32_t>(payload.size()));
    transfer_all(socket, reinterpret_cast<std::byte*>(&size), sizeof(size), true);
    transfer_all(socket, const_cast<std::byte*>(payload.data()), payload.size(), true);
}

[[nodiscard]] std::vector<std::byte> receive_frame(const int socket) {
    std::uint32_t wire_size{};
    transfer_all(socket, reinterpret_cast<std::byte*>(&wire_size),
                 sizeof(wire_size), false);
    const auto size = ntohl(wire_size);
    if (size == 0 || size > rwn::protocol::max_payload_size + 4096U)
        throw std::length_error("Build Worker IPC frame size is invalid");
    std::vector<std::byte> payload(size);
    transfer_all(socket, payload.data(), payload.size(), false);
    return payload;
}

}  // namespace

rwn::core::BuildExecutionResult execute_build_worker_ipc(
    const std::filesystem::path& socket_path,
    const std::uint32_t expected_worker_uid,
    const rwn::core::BuildRequest& request,
    const std::chrono::seconds timeout) {
    if (!socket_path.is_absolute() || expected_worker_uid == 0 ||
        timeout <= std::chrono::seconds::zero() ||
        timeout > std::chrono::hours{24}) {
        throw std::invalid_argument("Build Worker IPC options are invalid");
    }
    const auto native = socket_path.string();
    sockaddr_un address{};
    if (native.size() >= sizeof(address.sun_path))
        throw std::length_error("Build Worker socket path is too long");
    Socket socket(::socket(AF_UNIX, SOCK_STREAM, 0));
    if (socket.get() < 0) throw std::runtime_error("Build Worker socket failed");
    int no_sigpipe = 1;
    if (::setsockopt(socket.get(), SOL_SOCKET, SO_NOSIGPIPE,
                     &no_sigpipe, sizeof(no_sigpipe)) != 0) {
        throw std::runtime_error("Build Worker socket signal guard failed");
    }
    timeval duration{};
    duration.tv_sec = static_cast<decltype(duration.tv_sec)>(timeout.count());
    if (::setsockopt(socket.get(), SOL_SOCKET, SO_RCVTIMEO,
                     &duration, sizeof(duration)) != 0 ||
        ::setsockopt(socket.get(), SOL_SOCKET, SO_SNDTIMEO,
                     &duration, sizeof(duration)) != 0) {
        throw std::runtime_error("Build Worker socket timeout setup failed");
    }
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, native.c_str(), native.size() + 1);
    if (::connect(socket.get(), reinterpret_cast<sockaddr*>(&address),
                  sizeof(address)) != 0) {
        throw std::runtime_error("Build Worker IPC connect failed");
    }
    uid_t peer_uid{}; gid_t peer_gid{};
    if (::getpeereid(socket.get(), &peer_uid, &peer_gid) != 0 ||
        peer_uid != expected_worker_uid) {
        throw std::runtime_error("Build Worker IPC peer identity is denied");
    }
    const auto correlation = "worker-" + request.id;
    send_frame(socket.get(), rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::build_submit,
        .correlation_id = correlation,
        .payload = rwn::protocol::encode_build_submit_command({
            .session_id = "node-local",
            .workspace_id = request.workspace_id,
            .revision = request.pinned_revision,
            .build_id = request.id,
            .profile = request.profile,
        }),
        .unknown_fields = {},
    }));
    const auto envelope = rwn::protocol::decode(receive_frame(socket.get()));
    if (envelope.version != 1 ||
        envelope.type != rwn::protocol::MessageType::build_status ||
        envelope.correlation_id != correlation ||
        !envelope.unknown_fields.empty()) {
        throw std::invalid_argument("Build Worker IPC reply envelope is invalid");
    }
    const auto reply = rwn::protocol::decode_build_status_reply(envelope.payload);
    if (!reply.accepted || reply.build_id != request.id ||
        reply.state == rwn::protocol::BuildWireState::rejected) {
        throw std::runtime_error("Build Worker rejected the fixed build request");
    }
    rwn::core::BuildEvidence evidence{
        .exit_code = reply.exit_code,
        .stdout_log = reply.stdout_log,
        .stderr_log = reply.stderr_log,
        .elapsed = std::chrono::milliseconds{reply.elapsed_ms},
        .timed_out = reply.timed_out,
        .cancelled = reply.cancelled,
        .stdout_truncated = reply.stdout_truncated,
        .stderr_truncated = reply.stderr_truncated,
    };
    if (rwn::core::build_evidence_sha256(request, evidence) !=
        reply.evidence_sha256) {
        throw std::runtime_error("Build Worker evidence binding is invalid");
    }
    return {.evidence = std::move(evidence),
            .artifact_ids = reply.artifact_ids};
}

ArtifactWorkerIpcSession::ArtifactWorkerIpcSession(
    const std::filesystem::path& socket_path,
    const std::uint32_t expected_worker_uid,
    const std::chrono::seconds timeout) {
    if (!socket_path.is_absolute() || expected_worker_uid == 0 ||
        timeout <= std::chrono::seconds::zero() ||
        timeout > std::chrono::hours{1}) {
        throw std::invalid_argument("Artifact Worker IPC options are invalid");
    }
    const auto native = socket_path.string();
    sockaddr_un address{};
    if (native.size() >= sizeof(address.sun_path))
        throw std::length_error("Build Worker socket path is too long");
    socket_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_ < 0) throw std::runtime_error("Build Worker socket failed");
    try {
        int no_sigpipe = 1;
        if (::setsockopt(socket_, SOL_SOCKET, SO_NOSIGPIPE,
                         &no_sigpipe, sizeof(no_sigpipe)) != 0) {
            throw std::runtime_error("Build Worker socket signal guard failed");
        }
        timeval duration{};
        duration.tv_sec = static_cast<decltype(duration.tv_sec)>(timeout.count());
        if (::setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO,
                         &duration, sizeof(duration)) != 0 ||
            ::setsockopt(socket_, SOL_SOCKET, SO_SNDTIMEO,
                         &duration, sizeof(duration)) != 0) {
            throw std::runtime_error("Build Worker socket timeout setup failed");
        }
        address.sun_family = AF_UNIX;
        std::memcpy(address.sun_path, native.c_str(), native.size() + 1);
        if (::connect(socket_, reinterpret_cast<sockaddr*>(&address),
                      sizeof(address)) != 0) {
            throw std::runtime_error("Build Worker IPC connect failed");
        }
        uid_t peer_uid{};
        gid_t peer_gid{};
        if (::getpeereid(socket_, &peer_uid, &peer_gid) != 0 ||
            peer_uid != expected_worker_uid) {
            throw std::runtime_error("Build Worker IPC peer identity is denied");
        }
    } catch (...) {
        static_cast<void>(::close(socket_));
        socket_ = -1;
        throw;
    }
}

ArtifactWorkerIpcSession::~ArtifactWorkerIpcSession() {
    if (socket_ >= 0) static_cast<void>(::close(socket_));
}

rwn::protocol::ArtifactManifestReply ArtifactWorkerIpcSession::prepare(
    const rwn::protocol::ArtifactFetchCommand& command) {
    const auto correlation = "artifact-" + command.transfer_id;
    send_frame(socket_, rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::artifact_manifest,
        .correlation_id = correlation,
        .payload = rwn::protocol::encode_artifact_fetch_command(command),
        .unknown_fields = {},
    }));
    const auto envelope = rwn::protocol::decode(receive_frame(socket_));
    if (envelope.version != 1 ||
        envelope.type != rwn::protocol::MessageType::artifact_manifest ||
        envelope.correlation_id != correlation ||
        !envelope.unknown_fields.empty()) {
        throw std::invalid_argument("Artifact Worker IPC manifest is invalid");
    }
    return rwn::protocol::decode_artifact_manifest_reply(envelope.payload);
}

void ArtifactWorkerIpcSession::request_chunks(
    const rwn::protocol::ArtifactResumeCommand& command) {
    send_frame(socket_, rwn::protocol::encode({
        .version = 1,
        .type = rwn::protocol::MessageType::artifact_resume,
        .correlation_id = "resume-" + command.transfer_id,
        .payload = rwn::protocol::encode_artifact_resume_command(command),
        .unknown_fields = {},
    }));
}

rwn::protocol::ArtifactChunkCommand ArtifactWorkerIpcSession::read_chunk() {
    const auto envelope = rwn::protocol::decode(receive_frame(socket_));
    if (envelope.version != 1 ||
        envelope.type != rwn::protocol::MessageType::artifact_chunk ||
        envelope.correlation_id.empty() || !envelope.unknown_fields.empty()) {
        throw std::invalid_argument("Artifact Worker IPC chunk is invalid");
    }
    const auto chunk = rwn::protocol::decode_artifact_chunk_command(
        envelope.payload);
    if (envelope.correlation_id != "chunk-" + chunk.transfer_id + "-" +
        std::to_string(chunk.index)) {
        throw std::invalid_argument("Artifact Worker IPC chunk is not bound");
    }
    return chunk;
}

}  // namespace rwn::platform::macos
