#pragma once
#include "rwn/core/pairing_consent.hpp"

namespace rwn::platform::macos {
// GUI/main thread only, explicitly invoked by the future pairing companion.
// Does not open a listener, create/import identity, persist trust or grant input.
// The caller owns the consent for the entire modal lifetime and cancels it on
// connection loss. Only local UI approval is written by this adapter.
[[nodiscard]] bool request_local_pairing_consent(rwn::core::PairingConsent& consent);
}
