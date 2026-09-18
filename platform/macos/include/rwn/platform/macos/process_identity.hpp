#pragma once

#include "rwn/core/process_isolation.hpp"

#include <string_view>

namespace rwn::platform::macos {

void require_process_identity(
    rwn::core::ProcessRole role,
    std::string_view build_worker_user = "remote-builder");

}  // namespace rwn::platform::macos
