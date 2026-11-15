#pragma once
#include "rwn/platform/windows/schannel_transport.hpp"
namespace rwn::platform::windows {
// Schema-2 native profiles only. Fails closed on missing/mismatched native
// enrollment; legacy profiles never call this entry point.
SchannelFallbackClientOptions refresh_native_credentials(const SchannelFallbackClientOptions&,
    const transport::TransportEndpoint&,core::CancellationToken stop = {});
}
