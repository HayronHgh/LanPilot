#pragma once
#include <functional>
#include <vector>
#include <cstddef>
#include "rwn/core/cancellation.hpp"

namespace rwn::agent {

// Shared by the compatibility CLI and the canonical Mac application binary.
// Entering the application UI never invokes this endpoint implicitly.
int run(int argc, char** argv,
    const std::function<std::vector<std::byte>()>& native_client_status={},
    const std::vector<std::byte>& native_root={},core::CancellationToken credential_rollover={});

}  // namespace rwn::agent
