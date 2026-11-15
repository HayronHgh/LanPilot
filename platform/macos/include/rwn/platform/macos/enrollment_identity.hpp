#pragma once
#include "rwn/core/enrollment_identity.hpp"
#include <Security/Security.h>
namespace rwn::platform::macos {
// Default keychain or an explicit locally opened keychain for isolated tests.
// No unlock/imported private key/default trust/search-list modification.
std::unique_ptr<core::enrollment::IdentityStore> enrollment_identity_store(SecKeychainRef local_keychain=nullptr);
// Stable app-owned reference for fresh native keys. Contains a bounded public
// leaf and closed local key reference, never a path or imported private key.
// Legacy opaque Keychain references continue through the existing loader.
bool is_enrollment_identity_reference(std::span<const std::byte>);
// Returns an owned (+1) identity; caller CFReleases it. Read-only, no unlock or
// new identity/key/certificate creation. Explicit fixture Keychain remains scoped.
SecIdentityRef load_enrollment_identity(std::span<const std::byte>,SecKeychainRef local_keychain=nullptr);
}
