#pragma once

#include <filesystem>
#include <string_view>

namespace rwn::agent::macos {
// Requires the compiled publisher policy, fixed user install location and a
// valid Developer ID Application requirement. This does not claim notarization.
bool product_code_ready();
bool service_process_code_ready(unsigned pid);
bool publisher_policy_configured();
bool publisher_bundle_ready(const std::filesystem::path& bundle,std::string_view expected_version={});
}
