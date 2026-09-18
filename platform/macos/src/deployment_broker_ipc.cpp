#include "rwn/platform/macos/deployment_broker_ipc.hpp"

#include "rwn/core/content_hash.hpp"
#include "rwn/protocol/envelope.hpp"

#include <arpa/inet.h>
#include <cstring>
#include <span>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
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

void send_frame(const int socket, const std::span<const std::byte> payload) {
    if (payload.empty() || payload.size() > rwn::protocol::max_payload_size + 4096U)
        throw std::length_error("Deployment Broker IPC frame is invalid");
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
        throw std::length_error("Deployment Broker IPC frame is invalid");
    std::vector<std::byte> payload(size);
    transfer_all(socket, payload.data(), payload.size(), false);
    return payload;
}

}  // namespace

rwn::protocol::DeployStatusReply execute_deployment_broker_ipc(
    const std::filesystem::path& socket_path,
    const std::uint32_t expected_broker_uid,
    const rwn::protocol::DeploySubmitCommand& command,
    const std::chrono::seconds timeout) {
    if (!socket_path.is_absolute() || expected_broker_uid != 0 ||
        timeout <= std::chrono::seconds::zero() ||
        timeout > std::chrono::hours{1}) {
        throw std::invalid_argument("Deployment Broker IPC options are invalid");
    }
    rwn::protocol::validate_deploy_submit_command(command);
    const auto native = socket_path.string();
    sockaddr_un address{};
    if (native.size() >= sizeof(address.sun_path))
        throw std::length_error("Deployment Broker socket path is too long");
    Socket socket(::socket(AF_UNIX, SOCK_STREAM, 0));
    if (socket.get() < 0) throw std::runtime_error("Broker socket failed");
    int no_sigpipe = 1;
    if (::setsockopt(socket.get(), SOL_SOCKET, SO_NOSIGPIPE,
                     &no_sigpipe, sizeof(no_sigpipe)) != 0) {
        throw std::runtime_error("Broker socket signal guard failed");
    }
    timeval duration{};
    duration.tv_sec = static_cast<decltype(duration.tv_sec)>(timeout.count());
    if (::setsockopt(socket.get(), SOL_SOCKET, SO_RCVTIMEO,
                     &duration, sizeof(duration)) != 0 ||
        ::setsockopt(socket.get(), SOL_SOCKET, SO_SNDTIMEO,
                     &duration, sizeof(duration)) != 0) {
        throw std::runtime_error("Broker socket timeout setup failed");
    }
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, native.c_str(), native.size() + 1);
    if (::connect(socket.get(), reinterpret_cast<sockaddr*>(&address),
                  sizeof(address)) != 0) {
        throw std::runtime_error("Deployment Broker IPC connect failed");
    }
    uid_t peer_uid{};
    gid_t peer_gid{};
    if (::getpeereid(socket.get(), &peer_uid, &peer_gid) != 0 ||
        peer_uid != expected_broker_uid) {
        throw std::runtime_error("Deployment Broker peer identity is denied");
    }
    const auto correlation = "deploy-" + command.deployment_id;
    send_frame(socket.get(), rwn::protocol::encode({
        .version = 1, .type = rwn::protocol::MessageType::deploy_submit,
        .correlation_id = correlation,
        .payload = rwn::protocol::encode_deploy_submit_command(command),
        .unknown_fields = {},
    }));
    const auto envelope = rwn::protocol::decode(receive_frame(socket.get()));
    if (envelope.version != 1 ||
        envelope.type != rwn::protocol::MessageType::deploy_status ||
        envelope.correlation_id != correlation ||
        !envelope.unknown_fields.empty()) {
        throw std::invalid_argument("Deployment Broker IPC reply is invalid");
    }
    auto reply = rwn::protocol::decode_deploy_status_reply(envelope.payload);
    if (!reply.accepted || reply.deployment_id != command.deployment_id ||
        reply.artifact_id != command.artifact_id ||
        reply.source_revision != command.revision ||
        rwn::core::sha256_hex(
            rwn::protocol::encode_deploy_evidence_binding(reply)) !=
            reply.evidence_sha256) {
        throw std::invalid_argument("Deployment Broker evidence is not bound");
    }
    return reply;
}

}  // namespace rwn::platform::macos
