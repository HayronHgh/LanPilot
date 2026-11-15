#pragma once
#include "rwn/core/enrollment_status.hpp"
#include "rwn/core/cancellation.hpp"
#include <memory>
#include <string>

namespace rwn::agent::macos {
class NativeStatusService final {
public:
    // Null only for an opaque LEGACY identity. An LPI1 identity requires the
    // exact committed native enrollment; mismatch never disables verification.
    static std::shared_ptr<NativeStatusService> create(std::string bind,std::uint16_t desktop_port,
        core::enrollment::Bytes identity,core::Sha256Digest peer,core::enrollment::Bytes root);
    ~NativeStatusService();
    core::enrollment::Bytes client_ocsp();
    core::enrollment::Bytes server_identity()const;
    core::enrollment::Bytes root()const;
    core::Sha256Digest client_fingerprint()const;
    core::CancellationToken rollover_token()const;
private:
    class Impl;explicit NativeStatusService(std::unique_ptr<Impl>);
    std::unique_ptr<Impl> impl_;
};
}
