#pragma once
#include "rwn/core/enrollment_key.hpp"
#include "rwn/core/enrollment_pairing.hpp"
namespace rwn::platform::windows {
// Current user CNG software KSP; nonexportable signing keys. Does not create a
// key until create_new is called by the explicit local enrollment controller.
std::unique_ptr<core::enrollment::KeyStore> enrollment_key_store();
std::unique_ptr<core::enrollment::PairProofVerifier> enrollment_pairing_verifier();
}
