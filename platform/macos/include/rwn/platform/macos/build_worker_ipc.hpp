#pragma once

#include "rwn/core/build.hpp"
#include "rwn/protocol/build_control.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>

namespace rwn::platform::macos {

[[nodiscard]] rwn::core::BuildExecutionResult execute_build_worker_ipc(
    const std::filesystem::path& socket_path,
    std::uint32_t expected_worker_uid,
    const rwn::core::BuildRequest& request,
    std::chrono::seconds timeout);

class ArtifactWorkerIpcSession final {
public:
    ArtifactWorkerIpcSession(
        const std::filesystem::path& socket_path,
        std::uint32_t expected_worker_uid,
        std::chrono::seconds timeout);
    ~ArtifactWorkerIpcSession();
    ArtifactWorkerIpcSession(const ArtifactWorkerIpcSession&) = delete;
    ArtifactWorkerIpcSession& operator=(const ArtifactWorkerIpcSession&) = delete;

    [[nodiscard]] rwn::protocol::ArtifactManifestReply prepare(
        const rwn::protocol::ArtifactFetchCommand& command);
    void request_chunks(
        const rwn::protocol::ArtifactResumeCommand& command);
    [[nodiscard]] rwn::protocol::ArtifactChunkCommand read_chunk();

private:
    int socket_{-1};
};

}  // namespace rwn::platform::macos
