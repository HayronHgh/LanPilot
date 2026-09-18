#include "rwn/platform/windows/schannel_fallback.hpp"

#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#ifndef SCHANNEL_USE_BLACKLISTS
#define SCHANNEL_USE_BLACKLISTS
#endif

#include <windows.h>
#include <winternl.h>
#include <security.h>
#include <schannel.h>

#include <cstdint>

namespace rwn::platform::windows {
namespace {

[[nodiscard]] std::int32_t acquire_protocol_credentials(
    const DWORD protocol) noexcept {
    TLS_PARAMETERS parameters{};
    if (protocol != 0) {
        parameters.grbitDisabledProtocols =
            SP_PROT_X_CLIENTS & ~protocol;
    }

    SCH_CREDENTIALS credentials{};
    credentials.dwVersion = SCH_CREDENTIALS_VERSION;
    credentials.dwFlags =
        SCH_CRED_MANUAL_CRED_VALIDATION |
        SCH_CRED_NO_DEFAULT_CREDS |
        SCH_USE_STRONG_CRYPTO;
    if (protocol == SP_PROT_DTLS1_2_CLIENT) {
        credentials.dwFlags |= SCH_USE_DTLS_ONLY;
    }
    if (protocol != 0) {
        credentials.cTlsParameters = 1;
        credentials.pTlsParameters = &parameters;
    }
    CredHandle handle{};
    TimeStamp expiry{};
    const auto status = AcquireCredentialsHandleW(
        nullptr, const_cast<wchar_t*>(SCHANNEL_NAME_W),
        SECPKG_CRED_OUTBOUND, nullptr, &credentials,
        nullptr, nullptr, &handle, &expiry);
    if (status == SEC_E_OK) {
        static_cast<void>(FreeCredentialsHandle(&handle));
    }
    return static_cast<std::int32_t>(status);
}

}  // namespace

SchannelFallbackSupport probe_schannel_fallback_support() noexcept {
    SchannelFallbackSupport result{};
    result.default_status = acquire_protocol_credentials(0);
    result.tls13_status =
        acquire_protocol_credentials(SP_PROT_TLS1_3_CLIENT);
    result.dtls12_status =
        acquire_protocol_credentials(SP_PROT_DTLS1_2_CLIENT);
    result.default_client_credentials = result.default_status == SEC_E_OK;
    result.tls13_client_credentials = result.tls13_status == SEC_E_OK;
    result.dtls12_client_credentials = result.dtls12_status == SEC_E_OK;
    return result;
}

}  // namespace rwn::platform::windows
