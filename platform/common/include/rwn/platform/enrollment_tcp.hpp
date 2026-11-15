#pragma once
#include "rwn/core/enrollment_setup.hpp"

namespace rwn::platform::enrollment {
inline constexpr std::uint16_t pairing_port=45444;
std::array<std::byte,4> parse_private_ipv4(std::string_view);
void secure_random(std::span<std::byte>);
class Listener {
public:
    virtual ~Listener()=default;
    virtual std::unique_ptr<core::enrollment::EnrollmentChannel> accept(std::chrono::milliseconds)=0;
    virtual std::uint16_t port()const=0;
};
// No wildcard/public address; no default listener. Native UI explicitly opens
// one bounded pairing window; caller closes Listener on timeout/cancellation.
std::unique_ptr<Listener> listen(std::array<std::byte,4>,std::uint16_t port);
std::unique_ptr<core::enrollment::EnrollmentChannel> connect(std::array<std::byte,4>,std::uint16_t,
    std::chrono::milliseconds,const std::atomic_bool& cancelled);
}
