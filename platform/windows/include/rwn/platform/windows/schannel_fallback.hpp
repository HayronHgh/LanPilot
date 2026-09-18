#pragma once

#include <cstdint>

namespace rwn::platform::windows {

struct SchannelFallbackSupport {
    bool default_client_credentials{};
    bool tls13_client_credentials{};
    bool dtls12_client_credentials{};
    std::int32_t default_status{};
    std::int32_t tls13_status{};
    std::int32_t dtls12_status{};

    [[nodiscard]] bool ready() const noexcept {
        return default_client_credentials && tls13_client_credentials &&
               dtls12_client_credentials;
    }
};

[[nodiscard]] SchannelFallbackSupport
probe_schannel_fallback_support() noexcept;

}  // namespace rwn::platform::windows
