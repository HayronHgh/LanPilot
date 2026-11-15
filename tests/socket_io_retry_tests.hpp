#pragma once
#include "rwn/platform/windows/socket_io_retry.hpp"
#include "test_support.hpp"
#include <array>
#include "rwn/desktop/session_reconnect.hpp"

inline void socket_retry_preserves_progress_and_deadline() {
    using rwn::platform::windows::detail::retry_nonblocking_socket_io;
    using rwn::test::require;
    using rwn::test::require_throws;
    std::size_t offset{}, operation{}, waits{}, errors{};
    constexpr std::array amounts{2, -1, -1, 3};
    constexpr std::array expected_offsets{0U, 2U, 2U, 2U};
    while (offset < 5) {
        const auto amount = retry_nonblocking_socket_io("test send", [&] {
            ++waits;
        }, [&] {
            require(offset == expected_offsets[operation], "partial write offset must survive retry");
            return amounts[operation++];
        }, [&] { return ++errors == 1 ? 10035 : 10004; });
        offset += static_cast<std::size_t>(amount);
    }
    require(offset == 5 && operation == 4 && waits == 4 && errors == 2,
            "would-block and interruption preserve exact bytes");
    unsigned attempts{};
    require_throws<std::runtime_error>([&] {
        retry_nonblocking_socket_io("test timeout", [&] {
            if (++attempts == 4) throw std::runtime_error("deadline reached");
        }, [] { return -1; }, [] { return 10035; });
    }, "persistent would-block must stop at caller deadline");
    require(attempts == 4, "deadline is not restarted on retries");
    require_throws<std::runtime_error>([] {
        retry_nonblocking_socket_io("test reset", [] {}, [] { return -1; }, [] { return 10054; });
    }, "connection reset remains fatal");
    require(retry_nonblocking_socket_io("test EOF", [] {}, [] { return 0; }, [] { return 10035; }) == 0,
            "EOF is returned once, not retried");
    require_throws<rwn::transport::TlsTransportInterrupted>([] {
        rwn::platform::windows::detail::throw_socket_error("reset",10054);
    },"socket reset is retryable only by a NEW authenticated session");
    bool retried_security{};
    try{rwn::platform::windows::detail::throw_socket_error("access denied",10013);}
    catch(const rwn::transport::TlsTransportInterrupted&){retried_security=true;}
    catch(const std::runtime_error&){}
    require(!retried_security,"access denial must not be a reconnect signal");
    using namespace std::chrono;
    using Policy=rwn::desktop::SessionReconnectPolicy;
    require(!rwn::core::CancellationToken{}.stop_possible(),"default token has no cancellation observer");
    rwn::core::CancellationSource connection_stop;
    require(connection_stop.token().stop_possible(),"native establishment has observable cancellation state");
    const auto start=Policy::Clock::time_point{};Policy policy;
    policy.connected(start);
    require(policy.interrupted(start+minutes{30})==seconds{1},"expiry reconnect starts fresh bounded window");
    policy.connected(start+minutes{30}+seconds{1});
    require(policy.interrupted(start+minutes{30}+seconds{2})==seconds{2},"short lived session cannot erase retry budget");
    for(unsigned i=0;i<4;++i)require(policy.interrupted(start+minutes{30}+seconds{3}).has_value(),"bounded retries available");
    require(!policy.interrupted(start+minutes{30}+seconds{4}),"attempt limit terminates background retries");
    policy.connected(start+minutes{31});
    require(policy.interrupted(start+minutes{32})==seconds{1},"stable session resets retry budget");
    require(!policy.interrupted(start+minutes{33}),"wall clock budget cannot be extended by polling");
}
