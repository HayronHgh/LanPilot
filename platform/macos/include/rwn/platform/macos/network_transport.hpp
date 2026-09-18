#pragma once

#include "rwn/transport/apple_network_contract.hpp"
#include "rwn/transport/resilient_transport.hpp"

#include <chrono>
#include <cstdint>
#include <memory>

namespace rwn::platform::macos {

class NetworkFrameworkClientConnector final
    : public rwn::transport::TransportConnector {
public:
    explicit NetworkFrameworkClientConnector(
        rwn::transport::AppleNetworkClientOptions options);
    ~NetworkFrameworkClientConnector() override;

    NetworkFrameworkClientConnector(
        const NetworkFrameworkClientConnector&) = delete;
    NetworkFrameworkClientConnector& operator=(
        const NetworkFrameworkClientConnector&) = delete;
    NetworkFrameworkClientConnector(
        NetworkFrameworkClientConnector&&) noexcept;
    NetworkFrameworkClientConnector& operator=(
        NetworkFrameworkClientConnector&&) noexcept;

    [[nodiscard]] std::unique_ptr<rwn::transport::Transport> connect(
        rwn::transport::TransportMode mode,
        const rwn::transport::TransportEndpoint& endpoint,
        const rwn::transport::QuicTransportSettings& settings) override;
    [[nodiscard]] bool migrate(
        rwn::transport::Transport& transport,
        const rwn::transport::TransportEndpoint& endpoint) override;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

class NetworkFrameworkServerListener final {
public:
    NetworkFrameworkServerListener(
        rwn::transport::AppleNetworkServerOptions options,
        rwn::transport::QuicTransportSettings settings = {});
    ~NetworkFrameworkServerListener();

    NetworkFrameworkServerListener(
        const NetworkFrameworkServerListener&) = delete;
    NetworkFrameworkServerListener& operator=(
        const NetworkFrameworkServerListener&) = delete;
    NetworkFrameworkServerListener(
        NetworkFrameworkServerListener&&) noexcept;
    NetworkFrameworkServerListener& operator=(
        NetworkFrameworkServerListener&&) noexcept;

    [[nodiscard]] rwn::transport::AuthenticatedConnection accept(
        std::chrono::milliseconds timeout);
    [[nodiscard]] std::uint16_t listen_port() const noexcept;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace rwn::platform::macos
