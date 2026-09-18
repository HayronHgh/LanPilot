#pragma once

#include "rwn/core/authorization.hpp"

#include <filesystem>
#include <string_view>

namespace rwn::core {

[[nodiscard]] Policy parse_policy(std::string_view contents);
[[nodiscard]] Policy load_policy_file(const std::filesystem::path& path);

}  // namespace rwn::core
