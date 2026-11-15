#pragma once

#include "service_lifecycle.hpp"
#include <string>

namespace rwn::agent::macos {
struct ConfigurationInspection {
    bool configured{};
    bool legacy_owner{};
    bool requires_input{};
    std::string description;
};
// Inspection is read-only. Import writes create-new metadata only; no key,
// launchd, permission, trust or installed executable is changed.
ConfigurationInspection inspect_configuration();
bool import_legacy_configuration();
// Explicit foreground first-pairing setup only: creates/validates the single
// protected product directory; no key, trust, service or permission operation.
void prepare_enrollment_directory();
bool check_legacy_configuration();
bool legacy_service_present();
bool configured_service_verified();
int run_configured_service();
int configuration_store_fixture();
LoginResult activate_login_service();
LoginResult recover_login_service();
void authorize_configuration_identity();
std::string login_service_description();
int check_login_service_bundle();
} // namespace rwn::agent::macos
