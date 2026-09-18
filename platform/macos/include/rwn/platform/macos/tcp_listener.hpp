#pragma once
#include "rwn/transport/apple_network_contract.hpp"
#include "rwn/transport/tls_byte_channel.hpp"
#include "rwn/transport/channel_session.hpp"
#include <memory>
#include <string>

namespace rwn::platform::macos {
// CSPRNG identifier, not a capability or replacement for peer authentication.
[[nodiscard]] rwn::transport::ChannelSessionId new_tcp_session_id();
// Startup/onboarding ONLY, before worker threads or a listener exist. Signs a
// locally generated challenge and verifies it with the identity certificate.
// Never exports key/signature bytes or accepts caller-chosen signing material.
// Interactive mode may show native Keychain UI; caller must be local foreground.
void verify_local_tls_identity(const std::vector<std::byte>& persistent_reference,
                               bool allow_user_interaction);
// Read-only native trust probe, sharing the desktop listener's evaluator.
// Zero timestamp uses now; a nonzero Unix time affects this trust object only.
// No keychain identity, socket, OS clock change or network fetch is involved.
[[nodiscard]] bool probe_desktop_client_trust(
    const std::vector<std::byte>& certificate_der,
    const std::vector<std::byte>& root_der,
    const std::vector<std::byte>& ocsp_der,
    std::int64_t verify_unix_seconds = 0);
// Explicit bind address: loopback by default, never an implicit wildcard.
// Initial native listener supports exactly one paired client certificate.
class DedicatedTlsListener {
public:
    DedicatedTlsListener(rwn::transport::AppleNetworkServerOptions options,
                         std::string bind_address = "127.0.0.1",
                         std::vector<std::byte> exclusive_root_der = {},
                         std::vector<std::byte> client_ocsp_response_der = {});
    ~DedicatedTlsListener();
    DedicatedTlsListener(const DedicatedTlsListener&) = delete;
    DedicatedTlsListener& operator=(const DedicatedTlsListener&) = delete;
    [[nodiscard]] std::unique_ptr<rwn::transport::TlsByteChannel> accept(
        std::chrono::milliseconds timeout);
    // Null means ONLY no queued connection during this idle interval.
    // Once dequeued, authentication has its own bounded deadline; failures
    // throw. This permits a service to wait without restarting or extending
    // an unauthenticated client's handshake indefinitely.
    [[nodiscard]] std::unique_ptr<rwn::transport::TlsByteChannel> try_accept(
        std::chrono::milliseconds idle_timeout,
        std::chrono::milliseconds handshake_timeout);
    // Wakes an idle accept; accepted channels retain independent ownership.
    void cancel() noexcept;
    [[nodiscard]] std::uint16_t listen_port() const noexcept;
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace rwn::platform::macos
