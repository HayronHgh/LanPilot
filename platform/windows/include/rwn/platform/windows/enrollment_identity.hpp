#pragma once
#include "rwn/core/enrollment_identity.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
namespace rwn::platform::windows {
// Default CurrentUser/My, opened for mutation only after approval validation.
// Explicit locally owned stores support isolated native fixtures; never used
// as a remote-configurable trust/identity store selector. Roots stay in memory.
std::unique_ptr<core::enrollment::IdentityStore> enrollment_identity_store(HCERTSTORE local_store=nullptr);
}
