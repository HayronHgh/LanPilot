#include "rwn/platform/macos/process_identity.hpp"

#include <pwd.h>
#include <stdexcept>
#include <string_view>
#include <unistd.h>

namespace rwn::platform::macos {

void require_process_identity(
    const rwn::core::ProcessRole role,
    const std::string_view build_worker_user) {
    const auto effective_user = geteuid();
    const auto* account = getpwuid(effective_user);
    if (account == nullptr || account->pw_name == nullptr) {
        throw std::runtime_error("macOS process account could not be resolved");
    }
    const std::string_view user(account->pw_name);
    switch (role) {
        case rwn::core::ProcessRole::privileged_broker:
            if (effective_user != 0) {
                throw std::logic_error("privileged broker must run as root");
            }
            return;
        case rwn::core::ProcessRole::desktop_agent:
            if (effective_user == 0 || user == build_worker_user) {
                throw std::logic_error(
                    "desktop agent must run as the logged-in non-builder user");
            }
            return;
        case rwn::core::ProcessRole::build_worker:
            if (effective_user == 0 || user != build_worker_user) {
                throw std::logic_error(
                    "build worker must run as the dedicated non-root account");
            }
            return;
    }
    throw std::invalid_argument("unknown process role");
}

}  // namespace rwn::platform::macos
