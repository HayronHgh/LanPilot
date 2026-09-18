#include "rwn/platform/windows/schannel_fallback.hpp"

#include <iostream>

int main() {
    const auto support =
        rwn::platform::windows::probe_schannel_fallback_support();
    std::cout << "provider=schannel default_client_credentials="
              << (support.default_client_credentials ? 1 : 0)
              << " default_status=" << support.default_status
              << " tls13_client_credentials="
              << (support.tls13_client_credentials ? 1 : 0)
              << " tls13_status=" << support.tls13_status
              << " dtls12_client_credentials="
              << (support.dtls12_client_credentials ? 1 : 0)
              << " dtls12_status=" << support.dtls12_status << '\n';
    return support.ready() ? 0 : 1;
}
