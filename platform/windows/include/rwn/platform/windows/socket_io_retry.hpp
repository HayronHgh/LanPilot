#pragma once
#include <stdexcept>
#include <string>
#include <string_view>
#include <functional>
#include "rwn/transport/tls_byte_channel.hpp"
#include "rwn/core/cancellation.hpp"

namespace rwn::platform::windows::detail {
// Values are asserted against Winsock constants at the native call site.
inline constexpr int socket_would_block = 10035;
inline constexpr int socket_interrupted = 10004;
// Internal runtime probe, fixed loopback/ephemeral port only. No TLS identities,
// public listener, desktop access or input. Exercises the actual native helpers.
void probe_connection_cancellation(core::CancellationToken,const std::function<void()>& on_wait);

[[noreturn]] inline void throw_socket_error(std::string_view name,int error){
    const auto message=std::string(name)+" failed; wsa="+std::to_string(error);
    switch(error){
    case 10050: case 10051: case 10052: case 10053: case 10054:
    case 10058: case 10060: case 10061: case 10064: case 10065:
        throw rwn::transport::TlsTransportInterrupted(
            rwn::transport::TlsTransportInterrupted::Reason::unavailable,message);
    default:throw std::runtime_error(message);
    }
}

// wait_ready owns the original absolute deadline. Retrying cannot extend it.
// Only the successful byte count advances a caller's partial-write offset.
template<class Wait, class Operation, class LastError>
int retry_nonblocking_socket_io(std::string_view name, Wait wait_ready,
                                Operation operation, LastError last_error) {
    for (;;) {
        wait_ready();
        const int amount = operation();
        if (amount != -1) return amount; // Includes zero: caller handles EOF.
        const int error = last_error();
        if (error == socket_would_block || error == socket_interrupted) continue;
        throw_socket_error(name,error);
    }
}
} // namespace rwn::platform::windows::detail
