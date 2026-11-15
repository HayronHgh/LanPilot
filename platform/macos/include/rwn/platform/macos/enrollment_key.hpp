#pragma once
#include "rwn/core/enrollment_key.hpp"
#include "rwn/core/enrollment_pairing.hpp"
#include <Security/Security.h>
namespace rwn::platform::macos {
// Default login keychain, or an explicit locally opened keychain for an isolated
// fixture. Holds a retain. No keychain creation, unlock, trust or UI automation.
std::unique_ptr<core::enrollment::KeyStore> enrollment_key_store(SecKeychainRef keychain=nullptr);
std::unique_ptr<core::enrollment::PairProofVerifier> enrollment_pairing_verifier();
}
