#pragma once

#include "rwn/protocol/build_control.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>

namespace rwn::platform::macos {

[[nodiscard]] rwn::protocol::DeployStatusReply execute_deployment_broker_ipc(
    const std::filesystem::path& socket_path,
    std::uint32_t expected_broker_uid,
    const rwn::protocol::DeploySubmitCommand& command,
    std::chrono::seconds timeout);

}  // namespace rwn::platform::macos
